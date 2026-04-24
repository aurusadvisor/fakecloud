//! Docker/Podman-based ECS task execution.
//!
//! Mirrors the Lambda `ContainerRuntime` approach (auto-detect CLI, forward
//! localhost → host.docker.internal) but scoped for ECS's different
//! lifecycle: tasks are ephemeral, so there is no warm-container pool. Each
//! `run_task` spawns a background tokio task that pulls the image, starts
//! the container, waits for exit, captures logs, and updates shared ECS
//! state in place.

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use parking_lot::RwLock;
use tokio::process::Command;

use crate::state::{LifecycleEvent, SharedEcsState};

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("container CLI not found (tried docker, podman)")]
    NoCli,
    #[error("image pull failed: {0}")]
    ImagePull(String),
    #[error("container start failed: {0}")]
    ContainerStart(String),
    #[error("docker wait failed: {0}")]
    Wait(String),
}

/// Docker/Podman executor for ECS tasks.
pub struct EcsRuntime {
    cli: String,
    host_ip: String,
    /// Tracks container IDs per task ID so `stop_task` can kill in-flight
    /// work without needing to block on the spawned executor future.
    containers: RwLock<std::collections::HashMap<String, String>>,
}

impl EcsRuntime {
    /// Auto-detect Docker or Podman. Returns `None` if neither is
    /// available. Honours `FAKECLOUD_CONTAINER_CLI` for explicit override.
    pub fn new() -> Option<Self> {
        let cli = if let Ok(cli) = std::env::var("FAKECLOUD_CONTAINER_CLI") {
            if cli_works(&cli) {
                cli
            } else {
                return None;
            }
        } else if cli_works("docker") {
            "docker".to_string()
        } else if cli_works("podman") {
            "podman".to_string()
        } else {
            return None;
        };
        let host_ip = if cfg!(target_os = "linux") {
            "172.17.0.1".to_string()
        } else {
            "host-gateway".to_string()
        };
        Some(Self {
            cli,
            host_ip,
            containers: RwLock::new(std::collections::HashMap::new()),
        })
    }

    pub fn cli_name(&self) -> &str {
        &self.cli
    }

    /// Spawn the task asynchronously. Returns immediately after transitioning
    /// the task to `PENDING`; the background task advances it to `RUNNING`
    /// once the container is created and to `STOPPED` once the container
    /// exits.
    pub fn run_task(self: Arc<Self>, state: SharedEcsState, task_id: String, account_id: String) {
        tokio::spawn(async move {
            if let Err(err) = self.run_task_inner(&state, &task_id, &account_id).await {
                tracing::warn!(%err, task = %task_id, "ecs task execution failed");
                finalize_failure(&state, &account_id, &task_id, &err.to_string());
            }
        });
    }

    async fn run_task_inner(
        &self,
        state: &SharedEcsState,
        task_id: &str,
        account_id: &str,
    ) -> Result<(), RuntimeError> {
        let (image, env, command, awslogs_container) = {
            let accounts = state.read();
            let s = accounts
                .get(account_id)
                .ok_or_else(|| RuntimeError::ContainerStart("account missing".into()))?;
            let task = s
                .tasks
                .get(task_id)
                .ok_or_else(|| RuntimeError::ContainerStart("task missing".into()))?;
            let container = task
                .containers
                .first()
                .ok_or_else(|| RuntimeError::ContainerStart("task has no containers".into()))?;
            let def = find_container_definition(s, &task.family, task.revision, &container.name);
            (
                container.image.clone(),
                def.as_ref()
                    .and_then(|d| d.get("environment").and_then(|v| v.as_array()).cloned())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|e| {
                                let k = e.get("name").and_then(|v| v.as_str())?;
                                let v = e.get("value").and_then(|v| v.as_str()).unwrap_or("");
                                Some((k.to_string(), v.to_string()))
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
                def.as_ref()
                    .and_then(|d| d.get("command").and_then(|v| v.as_array()).cloned())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default(),
                container.name.clone(),
            )
        };

        // Pull the image first so we can surface pull errors cleanly.
        mark_pull_started(state, account_id, task_id);
        let pull_out = Command::new(&self.cli)
            .args(["pull", &image])
            .output()
            .await
            .map_err(|e| RuntimeError::ImagePull(e.to_string()))?;
        if !pull_out.status.success() {
            let err = String::from_utf8_lossy(&pull_out.stderr).to_string();
            return Err(RuntimeError::ImagePull(err));
        }
        mark_pull_stopped(state, account_id, task_id);

        // Run the container detached so we can track its ID and wait
        // asynchronously. `-d` prints the container ID on stdout.
        let mut cmd = Command::new(&self.cli);
        cmd.args(["run", "-d"])
            .args(["--label", &format!("fakecloud-ecs-task={}", task_id)])
            .args([
                "--add-host",
                &format!("host.docker.internal:{}", self.host_ip),
            ]);
        for (k, v) in &env {
            let transformed = v
                .replace("http://127.0.0.1:", "http://host.docker.internal:")
                .replace("https://127.0.0.1:", "https://host.docker.internal:")
                .replace("http://localhost:", "http://host.docker.internal:")
                .replace("https://localhost:", "https://host.docker.internal:");
            cmd.arg("-e").arg(format!("{}={}", k, transformed));
        }
        cmd.arg(&image);
        for arg in &command {
            cmd.arg(arg);
        }
        let run_out = cmd
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStart(e.to_string()))?;
        if !run_out.status.success() {
            let err = String::from_utf8_lossy(&run_out.stderr).to_string();
            return Err(RuntimeError::ContainerStart(err));
        }
        let container_id = String::from_utf8_lossy(&run_out.stdout).trim().to_string();
        self.containers
            .write()
            .insert(task_id.to_string(), container_id.clone());
        mark_running(
            state,
            account_id,
            task_id,
            &container_id,
            &awslogs_container,
        );

        // Wait for the container to exit. `docker wait` blocks until exit
        // and prints the numeric exit code to stdout.
        let wait_out = Command::new(&self.cli)
            .args(["wait", &container_id])
            .output()
            .await
            .map_err(|e| RuntimeError::Wait(e.to_string()))?;
        if !wait_out.status.success() {
            // `docker wait` itself failed — treat this as a Wait error so
            // the task flips via `finalize_failure` rather than silently
            // claiming the container exited normally.
            let err = String::from_utf8_lossy(&wait_out.stderr).to_string();
            return Err(RuntimeError::Wait(err));
        }
        let exit_code: i64 = String::from_utf8_lossy(&wait_out.stdout)
            .trim()
            .parse()
            .unwrap_or(-1);

        // Capture combined stdout+stderr via `docker logs`.
        let logs_out = Command::new(&self.cli)
            .args(["logs", &container_id])
            .output()
            .await
            .map_err(|e| RuntimeError::Wait(e.to_string()))?;
        let mut captured = String::new();
        captured.push_str(&String::from_utf8_lossy(&logs_out.stdout));
        captured.push_str(&String::from_utf8_lossy(&logs_out.stderr));

        // Best-effort cleanup; failures here shouldn't keep the task from
        // transitioning to STOPPED.
        let _ = Command::new(&self.cli)
            .args(["rm", &container_id])
            .output()
            .await;
        self.containers.write().remove(task_id);

        finalize_stopped(
            state,
            account_id,
            task_id,
            exit_code,
            &captured,
            "EssentialContainerExited",
            None,
        );
        Ok(())
    }

    /// Kill the container behind a task (if any) with the configured stop
    /// timeout. Returns true if a container was killed. Called synchronously
    /// from `StopTask`; the wait loop in `run_task_inner` observes the
    /// exit and transitions the task to `STOPPED`.
    pub async fn stop_task(&self, task_id: &str, reason: &str) -> bool {
        let container_id = self.containers.read().get(task_id).cloned();
        let Some(id) = container_id else {
            return false;
        };
        // `docker stop` sends SIGTERM then SIGKILL after a timeout.
        let _ = Command::new(&self.cli)
            .args(["stop", "--time", "10", &id])
            .output()
            .await;
        tracing::info!(task = %task_id, reason = %reason, "ecs task stop requested");
        true
    }

    /// Kill every running container the runtime owns. Called on reset /
    /// shutdown so docker state matches fakecloud state after a fresh
    /// boot.
    pub async fn stop_all(&self) {
        let ids: Vec<String> = self.containers.read().values().cloned().collect();
        for id in ids {
            let _ = Command::new(&self.cli).args(["kill", &id]).output().await;
            let _ = Command::new(&self.cli).args(["rm", &id]).output().await;
        }
        self.containers.write().clear();
    }
}

fn cli_works(cli: &str) -> bool {
    std::process::Command::new(cli)
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn find_container_definition(
    state: &crate::state::EcsState,
    family: &str,
    revision: i32,
    name: &str,
) -> Option<serde_json::Value> {
    state
        .task_definitions
        .get(family)?
        .get(&revision)?
        .container_definitions
        .iter()
        .find(|c| c.get("name").and_then(|v| v.as_str()) == Some(name))
        .cloned()
}

fn mark_pull_started(state: &SharedEcsState, account_id: &str, task_id: &str) {
    let mut accounts = state.write();
    let Some(s) = accounts.get_mut(account_id) else {
        return;
    };
    let task_arn_cluster = s
        .tasks
        .get(task_id)
        .map(|t| (t.task_arn.clone(), t.cluster_arn.clone()));
    if let Some(task) = s.tasks.get_mut(task_id) {
        task.pull_started_at = Some(Utc::now());
    }
    if let Some((arn, cluster_arn)) = task_arn_cluster {
        s.push_event(LifecycleEvent {
            at: Utc::now(),
            event_type: "PullStarted".into(),
            task_arn: Some(arn),
            cluster_arn: Some(cluster_arn),
            last_status: Some("PENDING".into()),
            detail: serde_json::json!({}),
        });
    }
}

fn mark_pull_stopped(state: &SharedEcsState, account_id: &str, task_id: &str) {
    let mut accounts = state.write();
    let Some(s) = accounts.get_mut(account_id) else {
        return;
    };
    if let Some(task) = s.tasks.get_mut(task_id) {
        task.pull_stopped_at = Some(Utc::now());
    }
}

fn mark_running(
    state: &SharedEcsState,
    account_id: &str,
    task_id: &str,
    container_id: &str,
    container_name: &str,
) {
    let mut accounts = state.write();
    let Some(s) = accounts.get_mut(account_id) else {
        return;
    };
    let (arn, cluster_arn) = {
        let Some(task) = s.tasks.get_mut(task_id) else {
            return;
        };
        task.last_status = "RUNNING".into();
        task.connectivity = "CONNECTED".into();
        task.connectivity_at = Some(Utc::now());
        task.started_at = Some(Utc::now());
        if let Some(c) = task
            .containers
            .iter_mut()
            .find(|c| c.name == container_name)
        {
            c.runtime_id = Some(container_id.into());
            c.last_status = "RUNNING".into();
        }
        if let Some(cluster) = s.clusters.get_mut(&task.cluster_name) {
            cluster.running_tasks_count += 1;
            if cluster.pending_tasks_count > 0 {
                cluster.pending_tasks_count -= 1;
            }
        }
        (task.task_arn.clone(), task.cluster_arn.clone())
    };
    s.push_event(LifecycleEvent {
        at: Utc::now(),
        event_type: "TaskStateChange".into(),
        task_arn: Some(arn),
        cluster_arn: Some(cluster_arn),
        last_status: Some("RUNNING".into()),
        detail: serde_json::json!({}),
    });
}

fn finalize_stopped(
    state: &SharedEcsState,
    account_id: &str,
    task_id: &str,
    exit_code: i64,
    captured: &str,
    stop_code: &str,
    stopped_reason: Option<String>,
) {
    let mut accounts = state.write();
    let Some(s) = accounts.get_mut(account_id) else {
        return;
    };
    let (arn, cluster_arn) = {
        let Some(task) = s.tasks.get_mut(task_id) else {
            return;
        };
        task.last_status = "STOPPED".into();
        task.desired_status = "STOPPED".into();
        task.stopping_at = task.stopping_at.or(Some(Utc::now()));
        task.stopped_at = Some(Utc::now());
        task.stop_code = Some(stop_code.into());
        task.stopped_reason = stopped_reason.or(Some(format!("Exit code {}", exit_code)));
        task.captured_logs = captured.to_string();
        for c in task.containers.iter_mut() {
            c.last_status = "STOPPED".into();
            if c.exit_code.is_none() {
                c.exit_code = Some(exit_code);
            }
        }
        if let Some(cluster) = s.clusters.get_mut(&task.cluster_name) {
            if cluster.running_tasks_count > 0 {
                cluster.running_tasks_count -= 1;
            }
        }
        (task.task_arn.clone(), task.cluster_arn.clone())
    };
    s.push_event(LifecycleEvent {
        at: Utc::now(),
        event_type: "TaskStateChange".into(),
        task_arn: Some(arn),
        cluster_arn: Some(cluster_arn),
        last_status: Some("STOPPED".into()),
        detail: serde_json::json!({
            "exitCode": exit_code,
            "stopCode": stop_code,
        }),
    });
}

fn finalize_failure(state: &SharedEcsState, account_id: &str, task_id: &str, reason: &str) {
    let mut accounts = state.write();
    let Some(s) = accounts.get_mut(account_id) else {
        return;
    };
    let (arn, cluster_arn) = {
        let Some(task) = s.tasks.get_mut(task_id) else {
            return;
        };
        // Capture the prior status before we clobber it: if the task had
        // already reached RUNNING when execution failed (e.g. `docker wait`
        // blew up after the container started), we owe the cluster a
        // running-tasks decrement. Tasks that died before RUNNING only
        // ever incremented pendingTasksCount.
        let was_running = task.last_status == "RUNNING";
        task.last_status = "STOPPED".into();
        task.desired_status = "STOPPED".into();
        task.stopped_at = Some(Utc::now());
        task.stop_code = Some("TaskFailedToStart".into());
        task.stopped_reason = Some(reason.to_string());
        for c in task.containers.iter_mut() {
            c.last_status = "STOPPED".into();
            c.reason = Some(reason.to_string());
        }
        if let Some(cluster) = s.clusters.get_mut(&task.cluster_name) {
            if was_running {
                if cluster.running_tasks_count > 0 {
                    cluster.running_tasks_count -= 1;
                }
            } else if cluster.pending_tasks_count > 0 {
                cluster.pending_tasks_count -= 1;
            }
        }
        (task.task_arn.clone(), task.cluster_arn.clone())
    };
    s.push_event(LifecycleEvent {
        at: Utc::now(),
        event_type: "TaskFailedToStart".into(),
        task_arn: Some(arn),
        cluster_arn: Some(cluster_arn),
        last_status: Some("STOPPED".into()),
        detail: serde_json::json!({ "reason": reason }),
    });
}

/// Short helper for tests + snapshot code to sleep between state
/// transitions. Exposed on the crate boundary to keep test timing
/// centralized.
pub async fn sleep(duration: Duration) {
    tokio::time::sleep(duration).await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_works_for_known_missing_binary_is_false() {
        assert!(!cli_works("definitely-not-a-real-cli-binary-xyz"));
    }
}
