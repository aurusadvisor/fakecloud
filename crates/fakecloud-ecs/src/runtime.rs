//! Docker/Podman-based ECS task execution.
//!
//! Mirrors the Lambda `ContainerRuntime` approach (auto-detect CLI, forward
//! localhost → host.docker.internal) but scoped for ECS's different
//! lifecycle: tasks are ephemeral, so there is no warm-container pool. Each
//! `run_task` spawns a background tokio task that pulls the image, starts
//! the container, waits for exit, captures logs, and updates shared ECS
//! state in place.

use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use chrono::Utc;
use fakecloud_core::delivery::DeliveryBus;
use fakecloud_logs::ingest::{append_events, IngestEvent};
use fakecloud_logs::state::SharedLogsState;
use fakecloud_secretsmanager::state::SharedSecretsManagerState;
use fakecloud_ssm::state::SharedSsmState;
use parking_lot::RwLock;
use tempfile::TempDir;
use tokio::process::Command;

use crate::state::{LifecycleEvent, SharedEcsState, Task};

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
    /// Port the main fakecloud server bound to. Used to translate AWS
    /// ECR URIs (`<acct>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag>`) to
    /// the local OCI v2 endpoint (`127.0.0.1:<port>/<repo>:<tag>`) so
    /// tasks can pull images pushed to fakecloud's own ECR.
    server_port: u16,
    /// Isolated DOCKER_CONFIG dir pre-populated with Basic auth for
    /// `127.0.0.1:<port>`; keeps the host user's `~/.docker/config.json`
    /// untouched and lets `docker pull` succeed against fakecloud ECR
    /// without a prior `aws ecr get-login-password | docker login`.
    docker_config: Option<Arc<TempDir>>,
    /// Tracks container IDs per task ID so `stop_task` can kill in-flight
    /// work without needing to block on the spawned executor future.
    containers: RwLock<std::collections::HashMap<String, String>>,
    /// Cross-service delivery bus — emits `aws.ecs` EventBridge events
    /// on task state transitions when wired. `None` if the server started
    /// without EventBridge configured (or for unit tests).
    delivery_bus: Option<Arc<DeliveryBus>>,
    /// CloudWatch Logs state — when set, tasks whose container definition
    /// declares the `awslogs` log driver get their captured stdout/stderr
    /// forwarded to a log group/stream under this shared state.
    logs_state: Option<SharedLogsState>,
    /// SecretsManager state for resolving `containerDefinition.secrets[]`
    /// entries whose `valueFrom` is a SecretsManager ARN.
    secretsmanager_state: Option<SharedSecretsManagerState>,
    /// SSM Parameter Store state for resolving `secrets[]` entries whose
    /// `valueFrom` is an SSM parameter ARN.
    ssm_state: Option<SharedSsmState>,
}

impl EcsRuntime {
    /// Auto-detect Docker or Podman. Returns `None` if neither is
    /// available. Honours `FAKECLOUD_CONTAINER_CLI` for explicit override.
    /// `server_port` is the port the main fakecloud server bound to;
    /// needed to resolve AWS ECR URIs against the local OCI v2 registry.
    pub fn new(server_port: u16) -> Option<Self> {
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
        let docker_config = build_local_registry_docker_config(server_port).map(Arc::new);
        Some(Self {
            cli,
            host_ip,
            server_port,
            docker_config,
            containers: RwLock::new(std::collections::HashMap::new()),
            delivery_bus: None,
            logs_state: None,
            secretsmanager_state: None,
            ssm_state: None,
        })
    }

    /// Path suitable for `DOCKER_CONFIG`. `None` if the tempdir setup
    /// failed; in that case pulls fall back to the user's own config and
    /// will only work if they've already logged in.
    fn docker_config_path(&self) -> Option<PathBuf> {
        self.docker_config.as_ref().map(|d| d.path().to_path_buf())
    }

    /// Build a `Command` for the container CLI with `DOCKER_CONFIG` set
    /// to our isolated tempdir so fakecloud ECR auth works out of the box.
    fn cli_command(&self) -> Command {
        let mut cmd = Command::new(&self.cli);
        if let Some(p) = self.docker_config_path() {
            cmd.env("DOCKER_CONFIG", p);
        }
        cmd
    }

    pub fn cli_name(&self) -> &str {
        &self.cli
    }

    /// Wire EventBridge delivery so task state transitions emit
    /// `aws.ecs` / `ECS Task State Change` events.
    pub fn with_delivery_bus(mut self, bus: Arc<DeliveryBus>) -> Self {
        self.delivery_bus = Some(bus);
        self
    }

    /// Wire CloudWatch Logs state so tasks using the `awslogs` driver
    /// get their captured stdout/stderr forwarded.
    pub fn with_logs(mut self, logs: SharedLogsState) -> Self {
        self.logs_state = Some(logs);
        self
    }

    /// Wire SecretsManager state so `secrets[].valueFrom` entries
    /// pointing at SecretsManager ARNs resolve at task launch.
    pub fn with_secretsmanager(mut self, state: SharedSecretsManagerState) -> Self {
        self.secretsmanager_state = Some(state);
        self
    }

    /// Wire SSM state so `secrets[].valueFrom` entries pointing at
    /// Parameter Store ARNs resolve at task launch.
    pub fn with_ssm(mut self, state: SharedSsmState) -> Self {
        self.ssm_state = Some(state);
        self
    }

    /// Spawn the task asynchronously. Returns immediately after transitioning
    /// the task to `PENDING`; the background task advances it to `RUNNING`
    /// once the container is created and to `STOPPED` once the container
    /// exits.
    pub fn run_task(self: Arc<Self>, state: SharedEcsState, task_id: String, account_id: String) {
        let rt = self.clone();
        tokio::spawn(async move {
            if let Err(err) = rt.run_task_inner(&state, &task_id, &account_id).await {
                tracing::warn!(%err, task = %task_id, "ecs task execution failed");
                finalize_failure(&state, &account_id, &task_id, &err.to_string());
                rt.emit_state_change(
                    &state,
                    &account_id,
                    &task_id,
                    "STOPPED",
                    Some(("TaskFailedToStart", err.to_string())),
                );
            }
        });
    }

    async fn run_task_inner(
        &self,
        state: &SharedEcsState,
        task_id: &str,
        account_id: &str,
    ) -> Result<(), RuntimeError> {
        let (image, mut env, entry_point, command, awslogs_container, secrets_refs, has_task_role) = {
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
            let secrets = def
                .as_ref()
                .and_then(|d| d.get("secrets").and_then(|v| v.as_array()).cloned())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|e| {
                            let name = e.get("name").and_then(|v| v.as_str())?.to_string();
                            let value_from =
                                e.get("valueFrom").and_then(|v| v.as_str())?.to_string();
                            Some((name, value_from))
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let str_array = |key: &str| -> Vec<String> {
                def.as_ref()
                    .and_then(|d| d.get(key).and_then(|v| v.as_array()).cloned())
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            };
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
                str_array("entryPoint"),
                str_array("command"),
                container.name.clone(),
                secrets,
                task.task_role_arn.is_some(),
            )
        };

        // Resolve `containerDefinition.secrets[]` entries. Each entry is
        // `{name, valueFrom}`; `valueFrom` is either a SecretsManager
        // secret ARN (`arn:aws:secretsmanager:...:secret:name-AbCdEf`)
        // or an SSM parameter ARN (`arn:aws:ssm:...:parameter/name`).
        // Both are looked up synchronously against the in-process shared
        // state and appended as env vars. Failed lookups fail the task —
        // matching real ECS's "failed to retrieve secret" behaviour.
        for (name, value_from) in &secrets_refs {
            let resolved = self.resolve_secret(account_id, value_from);
            match resolved {
                Some(v) => env.push((name.clone(), v)),
                None => {
                    return Err(RuntimeError::ContainerStart(format!(
                        "failed to resolve secret {name} from {value_from}"
                    )))
                }
            }
        }

        // Inject `AWS_CONTAINER_CREDENTIALS_FULL_URI` when the task has
        // a `taskRoleArn`. AWS SDKs pick this up via the default
        // credential-provider chain. The endpoint runs on the main
        // fakecloud server; the container reaches it via
        // `host.docker.internal:<port>`.
        if has_task_role {
            env.push((
                "AWS_CONTAINER_CREDENTIALS_FULL_URI".into(),
                format!(
                    "http://host.docker.internal:{}/_fakecloud/ecs/creds/{}",
                    self.server_port, task_id
                ),
            ));
        }

        // Pull the image first so we can surface pull errors cleanly.
        // AWS private-ECR URIs (`<acct>.dkr.ecr.<region>.amazonaws.com/...`)
        // are translated to fakecloud's local OCI v2 endpoint; after
        // pulling the local URI we retag it to the AWS URI so the
        // container and task state carry the user-facing image reference.
        mark_pull_started(state, account_id, task_id);
        let local_pull_uri = fakecloud_core::ecr_uri::translate_to_local(&image, self.server_port);
        let pull_uri = local_pull_uri.as_deref().unwrap_or(&image);
        let pull_out = self
            .cli_command()
            .args(["pull", pull_uri])
            .output()
            .await
            .map_err(|e| RuntimeError::ImagePull(e.to_string()))?;
        if !pull_out.status.success() {
            let err = String::from_utf8_lossy(&pull_out.stderr).to_string();
            return Err(RuntimeError::ImagePull(err));
        }
        // Retag the local pull URI to the AWS URI so `docker run` finds
        // the image under the user-facing name. Digest-pinned refs can't
        // be `docker tag` targets, so we fall through and run under the
        // local URI in that case (cosmetic tradeoff — the task's image
        // field will show the 127.0.0.1 URI instead of the AWS digest).
        let run_image = if let Some(ref local_uri) = local_pull_uri {
            if fakecloud_core::ecr_uri::is_digest_ref(&image) {
                local_uri.clone()
            } else {
                let _ = self
                    .cli_command()
                    .args(["tag", local_uri, &image])
                    .output()
                    .await;
                image.clone()
            }
        } else {
            image.clone()
        };
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
        // `containerDefinition.entryPoint` overrides the image's ENTRYPOINT.
        // Docker CLI's `--entrypoint` only takes a single executable; any
        // additional entryPoint elements are appended as positional args
        // before the user-supplied `command[]`, which matches how docker
        // composes ENTRYPOINT + CMD at exec time.
        if let Some(first) = entry_point.first() {
            cmd.args(["--entrypoint", first]);
        }
        cmd.arg(&run_image);
        for arg in entry_point.iter().skip(1) {
            cmd.arg(arg);
        }
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
        self.emit_state_change(state, account_id, task_id, "RUNNING", None);

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

        // Forward logs BEFORE flipping the task to STOPPED so a client
        // that polls DescribeTasks and immediately queries DescribeLogStreams
        // can't observe the STOPPED transition before the awslogs group/stream
        // has been materialised.
        self.forward_awslogs_if_configured(state, account_id, task_id, &captured);
        finalize_stopped(
            state,
            account_id,
            task_id,
            exit_code,
            &captured,
            "EssentialContainerExited",
            None,
        );
        self.emit_state_change(
            state,
            account_id,
            task_id,
            "STOPPED",
            Some((
                "EssentialContainerExited",
                format!("Exit code {}", exit_code),
            )),
        );
        Ok(())
    }

    /// Resolve a `secrets[].valueFrom` reference to the actual secret
    /// payload. Supports SecretsManager secret ARNs and SSM parameter
    /// ARNs; returns `None` when the referenced state isn't wired or
    /// the lookup misses.
    fn resolve_secret(&self, account_id: &str, value_from: &str) -> Option<String> {
        if value_from.contains(":secret:") {
            let state = self.secretsmanager_state.as_ref()?;
            let accounts = state.read();
            let sm = accounts.get(account_id)?;
            // ARN shape: arn:aws:secretsmanager:<region>:<acct>:secret:<name>-<6char>
            // Stored key is the secret name (no suffix). Strip the
            // AWS-generated 6-char suffix when comparing.
            let arn_tail = value_from.rsplit(":secret:").next()?;
            let name = arn_tail
                .rsplit_once('-')
                .map(|(n, _)| n)
                .unwrap_or(arn_tail);
            let secret = sm.secrets.get(name).or_else(|| sm.secrets.get(arn_tail))?;
            let version_id = secret.current_version_id.as_ref()?;
            let v = secret.versions.get(version_id)?;
            return v.secret_string.clone();
        }
        if value_from.contains(":parameter") {
            let state = self.ssm_state.as_ref()?;
            let accounts = state.read();
            let ssm = accounts.get(account_id)?;
            // ARN shape: arn:aws:ssm:<region>:<acct>:parameter/<name>
            // Parameters are stored keyed by name (with leading slash)
            // or without, depending on how they were created. Try both.
            let after = value_from.rsplit(":parameter").next()?;
            let name_with_slash = after.trim_start_matches('/');
            return ssm
                .parameters
                .get(&format!("/{name_with_slash}"))
                .or_else(|| ssm.parameters.get(name_with_slash))
                .map(|p| p.value.clone());
        }
        None
    }

    /// Emit an `ECS Task State Change` EventBridge event. No-op when no
    /// delivery bus is wired. Matches AWS event shape so downstream
    /// rules can filter on `detail.lastStatus`, `detail.stopCode`, etc.
    fn emit_state_change(
        &self,
        state: &SharedEcsState,
        account_id: &str,
        task_id: &str,
        last_status: &str,
        stop: Option<(&str, String)>,
    ) {
        let Some(ref bus) = self.delivery_bus else {
            return;
        };
        let Some(task_view) = snapshot_task(state, account_id, task_id) else {
            return;
        };
        let mut detail = serde_json::json!({
            "taskArn": task_view.task_arn,
            "clusterArn": task_view.cluster_arn,
            "lastStatus": last_status,
            "desiredStatus": if last_status == "STOPPED" { "STOPPED" } else { "RUNNING" },
            "launchType": task_view.launch_type,
            "group": task_view.group,
            "taskDefinitionArn": task_view.task_definition_arn,
            "containers": task_view.containers,
        });
        if let Some((code, reason)) = stop {
            detail["stopCode"] = code.into();
            detail["stoppedReason"] = reason.into();
        }
        bus.put_event_to_eventbridge(
            "aws.ecs",
            "ECS Task State Change",
            &detail.to_string(),
            "default",
        );
    }

    /// Forward captured stdout/stderr to CloudWatch Logs when the task's
    /// container definition declares the `awslogs` log driver. No-op when
    /// logs_state isn't wired or the task has no awslogs config.
    fn forward_awslogs_if_configured(
        &self,
        state: &SharedEcsState,
        account_id: &str,
        task_id: &str,
        captured: &str,
    ) {
        let Some(ref logs) = self.logs_state else {
            return;
        };
        // Clone out of the read guard so we don't hold it across the logs
        // state write.
        let (cfg, task_region) = {
            let accounts = state.read();
            let Some(s) = accounts.get(account_id) else {
                return;
            };
            let Some(task) = s.tasks.get(task_id) else {
                return;
            };
            let Some(ref cfg) = task.awslogs else {
                return;
            };
            (cfg.clone(), s.region.clone())
        };
        if captured.is_empty() {
            return;
        }
        let now = Utc::now().timestamp_millis();
        let stream_name = cfg.stream_name(task_id);
        let events: Vec<IngestEvent> = captured
            .lines()
            .enumerate()
            .map(|(i, line)| IngestEvent {
                // Stagger within the same millisecond so CloudWatch's
                // chronological-order invariant holds without relying on
                // the host clock's resolution.
                timestamp_ms: now.saturating_add(i as i64),
                message: line.to_string(),
            })
            .collect();
        append_events(
            logs,
            account_id,
            &task_region,
            &cfg.group,
            &stream_name,
            &events,
        );
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

struct TaskSnapshot {
    task_arn: String,
    cluster_arn: String,
    launch_type: String,
    group: Option<String>,
    task_definition_arn: String,
    containers: serde_json::Value,
}

fn snapshot_task(state: &SharedEcsState, account_id: &str, task_id: &str) -> Option<TaskSnapshot> {
    let accounts = state.read();
    let s = accounts.get(account_id)?;
    let task = s.tasks.get(task_id)?;
    Some(TaskSnapshot {
        task_arn: task.task_arn.clone(),
        cluster_arn: task.cluster_arn.clone(),
        launch_type: task.launch_type.clone(),
        group: task.group.clone(),
        task_definition_arn: task.task_definition_arn.clone(),
        containers: serde_json::Value::Array(
            task.containers
                .iter()
                .map(|c| {
                    serde_json::json!({
                        "containerArn": c.container_arn,
                        "name": c.name,
                        "image": c.image,
                        "lastStatus": c.last_status,
                        "exitCode": c.exit_code,
                        "reason": c.reason,
                    })
                })
                .collect(),
        ),
    })
}

/// Unused silencer: keep `Task` in scope for future snapshot extensions.
#[allow(dead_code)]
fn _task_type_anchor(_t: &Task) {}

fn cli_works(cli: &str) -> bool {
    std::process::Command::new(cli)
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Build an isolated docker config directory with Basic auth for
/// fakecloud ECR at `127.0.0.1:<port>`. Lets `docker pull/push/tag`
/// work against the local OCI v2 registry without requiring the user
/// to run `aws ecr get-login-password | docker login` first.
fn build_local_registry_docker_config(server_port: u16) -> Option<TempDir> {
    let dir = TempDir::new().ok()?;
    let auth = base64::engine::general_purpose::STANDARD.encode("AWS:fakecloud-ecs-runtime");
    let config = serde_json::json!({
        "auths": {
            format!("127.0.0.1:{server_port}"): { "auth": auth },
        }
    });
    std::fs::write(dir.path().join("config.json"), config.to_string()).ok()?;
    Some(dir)
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

    #[test]
    fn aws_ecr_uris_translate_for_local_pull() {
        assert_eq!(
            fakecloud_core::ecr_uri::translate_to_local(
                "123456789012.dkr.ecr.us-east-1.amazonaws.com/app:latest",
                4566
            )
            .as_deref(),
            Some("127.0.0.1:4566/app:latest")
        );
    }
}
