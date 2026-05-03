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
use fakecloud_logs::SharedLogsState;
use fakecloud_secretsmanager::SharedSecretsManagerState;
use fakecloud_ssm::SharedSsmState;
use parking_lot::RwLock;
use tempfile::TempDir;
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
    /// Tracks per-task lists of `(container_name, docker_container_id)` so
    /// `stop_task` can kill every container backing a task — multi-container
    /// task definitions launch one docker container per `containerDefinitions`
    /// entry, all of which must be torn down on stop.
    containers: RwLock<std::collections::HashMap<String, Vec<(String, String)>>>,
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
                // Also surface on stderr so nextest's captured-output for a
                // failed E2E shows the reason instead of just "empty logs".
                eprintln!("[ecs] task {task_id} failed: {err}");
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
        // Build a per-container launch plan up-front so we hold the read
        // lock once. Each entry carries everything needed to compose a
        // `docker run` invocation for one container in the task.
        let plans = build_container_plans(state, account_id, task_id, self.server_port)?;
        if plans.is_empty() {
            return Err(RuntimeError::ContainerStart(
                "task has no containers".into(),
            ));
        }

        // Resolve secrets for each plan. Failures fail the whole task to
        // match real ECS's "failed to retrieve secret" behaviour — there's
        // no point starting a sidecar when the app container will fail.
        let mut resolved_plans: Vec<ResolvedContainerPlan> = Vec::with_capacity(plans.len());
        for plan in plans {
            let mut env = plan.env.clone();
            for (name, value_from) in &plan.secrets_refs {
                match self.resolve_secret(account_id, value_from) {
                    Some(v) => env.push((name.clone(), v)),
                    None => {
                        return Err(RuntimeError::ContainerStart(format!(
                            "failed to resolve secret {name} from {value_from}"
                        )));
                    }
                }
            }
            if plan.has_task_role {
                env.push((
                    "AWS_CONTAINER_CREDENTIALS_FULL_URI".into(),
                    format!(
                        "http://host.docker.internal:{}/_fakecloud/ecs/creds/{}",
                        self.server_port, task_id
                    ),
                ));
            }
            resolved_plans.push(ResolvedContainerPlan { plan, env });
        }

        // Pull every distinct image up-front so a second container's pull
        // failure surfaces before we leave the first container running.
        mark_pull_started(state, account_id, task_id);
        let mut run_images: Vec<String> = Vec::with_capacity(resolved_plans.len());
        for rp in &resolved_plans {
            let local_pull_uri =
                fakecloud_core::ecr_uri::translate_to_local(&rp.plan.image, self.server_port);
            let pull_uri = local_pull_uri.as_deref().unwrap_or(&rp.plan.image);
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
            // the image under the user-facing name. Digest-pinned refs
            // can't be `docker tag` targets, so we fall through and run
            // under the local URI in that case.
            let run_image = if let Some(ref local_uri) = local_pull_uri {
                if fakecloud_core::ecr_uri::is_digest_ref(&rp.plan.image) {
                    local_uri.clone()
                } else {
                    let _ = self
                        .cli_command()
                        .args(["tag", local_uri, &rp.plan.image])
                        .output()
                        .await;
                    rp.plan.image.clone()
                }
            } else {
                rp.plan.image.clone()
            };
            run_images.push(run_image);
        }
        mark_pull_stopped(state, account_id, task_id);

        // Launch every container detached. If any fails to start, kill the
        // ones we already started and bail — partial-launch state is harder
        // to reason about than a clean failure.
        let mut started: Vec<RunningContainer> = Vec::with_capacity(resolved_plans.len());
        for (rp, run_image) in resolved_plans.iter().zip(run_images.iter()) {
            let argv = build_run_argv(&rp.plan, &rp.env, task_id, &self.host_ip, run_image);
            let mut cmd = Command::new(&self.cli);
            cmd.args(&argv);
            let run_out = cmd.output().await.map_err(|e| {
                // Cleanup already-started containers on launch failure.
                self.cleanup_partial_start(&started);
                RuntimeError::ContainerStart(e.to_string())
            })?;
            if !run_out.status.success() {
                let err = String::from_utf8_lossy(&run_out.stderr).to_string();
                self.cleanup_partial_start(&started);
                return Err(RuntimeError::ContainerStart(err));
            }
            let container_id = String::from_utf8_lossy(&run_out.stdout).trim().to_string();
            started.push(RunningContainer {
                name: rp.plan.container_name.clone(),
                container_id,
                essential: rp.plan.essential,
                exit_code: None,
                network_bindings: network_bindings_for(&rp.plan),
            });
        }

        // Stash all (name, container_id) pairs so StopTask/stop_all can
        // reach every container backing this task.
        {
            let mut guard = self.containers.write();
            guard.insert(
                task_id.to_string(),
                started
                    .iter()
                    .map(|c| (c.name.clone(), c.container_id.clone()))
                    .collect(),
            );
        }
        mark_running_multi(state, account_id, task_id, &started);
        self.emit_state_change(state, account_id, task_id, "RUNNING", None);

        // Wait for the first essential container (or, if none are
        // essential, any container) to exit. ECS task lifetime is
        // bounded by the first essential exit, after which all remaining
        // containers are stopped.
        let wait_outcome = self.wait_for_task_exit(&started).await?;

        // Stop and reap any sidecars still running. Best-effort — failures
        // here shouldn't keep the task from transitioning to STOPPED.
        let mut final_containers = started.clone();
        for (i, rc) in started.iter().enumerate() {
            if Some(i) == wait_outcome.exited_index {
                final_containers[i].exit_code = Some(wait_outcome.exit_code);
                continue;
            }
            // Try to grab the exit code if the container already exited
            // on its own (non-essential exits don't stop the task), then
            // fall back to `docker stop` for stragglers.
            let inspect = Command::new(&self.cli)
                .args(["inspect", "-f", "{{.State.ExitCode}}", &rc.container_id])
                .output()
                .await;
            let still_running = match inspect {
                Ok(out) if out.status.success() => {
                    let s = String::from_utf8_lossy(&out.stdout).trim().to_string();
                    // `docker inspect` returns 0 for not-yet-exited
                    // containers, so we additionally check `State.Running`.
                    let running = Command::new(&self.cli)
                        .args(["inspect", "-f", "{{.State.Running}}", &rc.container_id])
                        .output()
                        .await
                        .map(|o| String::from_utf8_lossy(&o.stdout).trim() == "true")
                        .unwrap_or(false);
                    if !running {
                        if let Ok(code) = s.parse::<i64>() {
                            final_containers[i].exit_code = Some(code);
                        }
                    }
                    running
                }
                _ => false,
            };
            if still_running {
                let _ = Command::new(&self.cli)
                    .args(["stop", "--time", "10", &rc.container_id])
                    .output()
                    .await;
                let wait_out = Command::new(&self.cli)
                    .args(["wait", &rc.container_id])
                    .output()
                    .await;
                if let Ok(out) = wait_out {
                    let code: i64 = String::from_utf8_lossy(&out.stdout)
                        .trim()
                        .parse()
                        .unwrap_or(-1);
                    final_containers[i].exit_code = Some(code);
                }
            }
        }

        // Capture combined stdout+stderr from every container so the
        // introspection endpoint shows logs from sidecars too.
        let mut captured = String::new();
        for rc in &started {
            let logs_out = Command::new(&self.cli)
                .args(["logs", &rc.container_id])
                .output()
                .await
                .map_err(|e| RuntimeError::Wait(e.to_string()))?;
            captured.push_str(&format!("[{}] ", rc.name));
            captured.push_str(&String::from_utf8_lossy(&logs_out.stdout));
            captured.push_str(&String::from_utf8_lossy(&logs_out.stderr));
        }

        // Reap every container we own.
        for rc in &started {
            let _ = Command::new(&self.cli)
                .args(["rm", "-f", &rc.container_id])
                .output()
                .await;
        }
        self.containers.write().remove(task_id);

        // Forward logs BEFORE flipping the task to STOPPED so a client
        // that polls DescribeTasks and immediately queries
        // DescribeLogStreams can't observe the STOPPED transition before
        // the awslogs group/stream has been materialised.
        self.forward_awslogs_if_configured(state, account_id, task_id, &captured);
        let exit_code = wait_outcome.exit_code;
        finalize_stopped_multi(
            state,
            account_id,
            task_id,
            &final_containers,
            exit_code,
            &captured,
            wait_outcome.stop_code,
            None,
        );
        self.emit_state_change(
            state,
            account_id,
            task_id,
            "STOPPED",
            Some((wait_outcome.stop_code, format!("Exit code {}", exit_code))),
        );
        Ok(())
    }

    /// Wait for the task to reach a stop condition: any essential
    /// container exits, or every container exits when none are essential.
    /// Returns the index into `started` of the container whose exit
    /// determined the task lifetime, its exit code, and the stopCode.
    async fn wait_for_task_exit(
        &self,
        started: &[RunningContainer],
    ) -> Result<TaskExitOutcome, RuntimeError> {
        let any_essential = started.iter().any(|c| c.essential);
        let mut working: Vec<RunningContainer> = started.to_vec();
        let mut first_exited: Option<usize> = None;
        loop {
            for (i, rc) in started.iter().enumerate() {
                if working[i].exit_code.is_some() {
                    continue;
                }
                let inspect = Command::new(&self.cli)
                    .args(["inspect", "-f", "{{.State.Running}}", &rc.container_id])
                    .output()
                    .await;
                let running = match inspect {
                    Ok(out) if out.status.success() => {
                        String::from_utf8_lossy(&out.stdout).trim() == "true"
                    }
                    _ => false,
                };
                if running {
                    continue;
                }
                let wait_out = Command::new(&self.cli)
                    .args(["wait", &rc.container_id])
                    .output()
                    .await
                    .map_err(|e| RuntimeError::Wait(e.to_string()))?;
                if !wait_out.status.success() {
                    let err = String::from_utf8_lossy(&wait_out.stderr).to_string();
                    return Err(RuntimeError::Wait(err));
                }
                let exit_code: i64 = String::from_utf8_lossy(&wait_out.stdout)
                    .trim()
                    .parse()
                    .unwrap_or(-1);
                working[i].exit_code = Some(exit_code);
                if first_exited.is_none() && (rc.essential || !any_essential) {
                    first_exited = Some(i);
                }
            }
            if task_should_stop(&working) {
                let idx = first_exited
                    .or_else(|| working.iter().position(|c| c.exit_code.is_some()))
                    .unwrap_or(0);
                let exit_code = working[idx].exit_code.unwrap_or(-1);
                return Ok(TaskExitOutcome {
                    exited_index: Some(idx),
                    exit_code,
                    stop_code: if any_essential {
                        "EssentialContainerExited"
                    } else {
                        "TaskCompleted"
                    },
                });
            }
            sleep(Duration::from_millis(200)).await;
        }
    }

    /// Best-effort cleanup of containers we already started when a later
    /// container in the task failed to launch. Without this, half-launched
    /// tasks leak docker containers.
    fn cleanup_partial_start(&self, started: &[RunningContainer]) {
        let cli = self.cli.clone();
        let ids: Vec<String> = started.iter().map(|c| c.container_id.clone()).collect();
        tokio::spawn(async move {
            for id in ids {
                let _ = Command::new(&cli).args(["rm", "-f", &id]).output().await;
            }
        });
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

    /// Kill every container behind a task with the configured stop
    /// timeout. Returns true if at least one container was killed. Called
    /// synchronously from `StopTask`; the wait loop in `run_task_inner`
    /// observes the exits and transitions the task to `STOPPED`.
    pub async fn stop_task(&self, task_id: &str, reason: &str) -> bool {
        let containers = self.containers.read().get(task_id).cloned();
        let Some(list) = containers else {
            return false;
        };
        if list.is_empty() {
            return false;
        }
        // `docker stop` sends SIGTERM then SIGKILL after a timeout.
        for (_name, id) in &list {
            let _ = Command::new(&self.cli)
                .args(["stop", "--time", "10", id])
                .output()
                .await;
        }
        tracing::info!(task = %task_id, reason = %reason, "ecs task stop requested");
        true
    }

    /// Kill every running container the runtime owns. Called on reset /
    /// shutdown so docker state matches fakecloud state after a fresh
    /// boot.
    pub async fn stop_all(&self) {
        let ids: Vec<String> = self
            .containers
            .read()
            .values()
            .flat_map(|list| list.iter().map(|(_, id)| id.clone()))
            .collect();
        for id in ids {
            let _ = Command::new(&self.cli).args(["kill", &id]).output().await;
            let _ = Command::new(&self.cli).args(["rm", &id]).output().await;
        }
        self.containers.write().clear();
    }
}

/// Per-container launch plan derived from a task definition.
#[derive(Clone, Debug)]
pub(crate) struct ContainerPlan {
    pub(crate) container_name: String,
    pub(crate) image: String,
    pub(crate) env: Vec<(String, String)>,
    pub(crate) entry_point: Vec<String>,
    pub(crate) command: Vec<String>,
    pub(crate) secrets_refs: Vec<(String, String)>,
    pub(crate) essential: bool,
    pub(crate) has_task_role: bool,
    /// Port mappings parsed from the task definition. Each entry becomes
    /// a `--publish containerPort:hostPort/protocol` flag on the docker
    /// run command (except for `awsvpc`, where ports are exposed via the
    /// per-task ENI rather than the docker host's port table).
    pub(crate) port_mappings: Vec<PortMapping>,
    /// Task-level network mode propagated to every container plan so the
    /// argv builder can decide whether to emit `--publish` flags. Real
    /// ECS treats `awsvpc` as "container is on its own ENI"; the
    /// equivalent in fakecloud is "don't publish to the host".
    pub(crate) network_mode: Option<String>,
}

/// One entry in a container's `portMappings`. Mirrors the AWS shape so
/// [`build_run_argv`] and the `networkBindings` response can share the
/// same parsed representation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct PortMapping {
    pub container_port: u16,
    /// `0` (or unset in the source JSON) means "use the same value as
    /// containerPort" — host-mode default per AWS docs.
    pub host_port: u16,
    /// Lower-case `tcp` / `udp`. Defaults to `tcp` when omitted.
    pub protocol: String,
}

#[derive(Clone, Debug)]
struct ResolvedContainerPlan {
    plan: ContainerPlan,
    env: Vec<(String, String)>,
}

/// Result of waiting for a task's lifetime-determining container.
#[derive(Clone, Debug)]
struct TaskExitOutcome {
    /// Index into the started-containers list of the container whose exit
    /// closed out the task. `None` only in degenerate cases — kept as
    /// `Option` so `final_containers` indexing stays explicit.
    exited_index: Option<usize>,
    exit_code: i64,
    stop_code: &'static str,
}

/// Per-container record persisted on the task. Mirrors the AWS Container
/// shape but tracks the docker-side container id alongside ECS metadata.
#[derive(Clone, Debug)]
pub(crate) struct RunningContainer {
    pub(crate) name: String,
    pub(crate) container_id: String,
    pub(crate) essential: bool,
    pub(crate) exit_code: Option<i64>,
    /// Resolved `networkBindings` for DescribeTasks. Computed from the
    /// task definition's `portMappings` at launch and surfaced verbatim
    /// in the per-container response.
    pub(crate) network_bindings: Vec<serde_json::Value>,
}

/// Pure decision: does the current set of containers warrant stopping
/// the task? Returns true when any essential container has exited, or
/// when every container has exited (regardless of essential). Mirrors
/// AWS ECS task lifetime semantics.
pub(crate) fn task_should_stop(containers: &[RunningContainer]) -> bool {
    if containers.is_empty() {
        return true;
    }
    let any_essential_exited = containers
        .iter()
        .any(|c| c.essential && c.exit_code.is_some());
    if any_essential_exited {
        return true;
    }
    containers.iter().all(|c| c.exit_code.is_some())
}

fn build_container_plans(
    state: &SharedEcsState,
    account_id: &str,
    task_id: &str,
    _server_port: u16,
) -> Result<Vec<ContainerPlan>, RuntimeError> {
    let accounts = state.read();
    let s = accounts
        .get(account_id)
        .ok_or_else(|| RuntimeError::ContainerStart("account missing".into()))?;
    let task = s
        .tasks
        .get(task_id)
        .ok_or_else(|| RuntimeError::ContainerStart("task missing".into()))?;
    if task.containers.is_empty() {
        return Err(RuntimeError::ContainerStart(
            "task has no containers".into(),
        ));
    }
    let has_task_role = task.task_role_arn.is_some();
    let network_mode = s
        .task_definitions
        .get(&task.family)
        .and_then(|revs| revs.get(&task.revision))
        .and_then(|td| td.network_mode.clone());
    let mut plans = Vec::with_capacity(task.containers.len());
    for container in &task.containers {
        let def = find_container_definition(s, &task.family, task.revision, &container.name);
        let secrets_refs = def
            .as_ref()
            .and_then(|d| d.get("secrets").and_then(|v| v.as_array()).cloned())
            .map(|arr| {
                arr.iter()
                    .filter_map(|e| {
                        let name = e.get("name").and_then(|v| v.as_str())?.to_string();
                        let value_from = e.get("valueFrom").and_then(|v| v.as_str())?.to_string();
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
        let env = def
            .as_ref()
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
            .unwrap_or_default();
        let port_mappings = def
            .as_ref()
            .and_then(|d| d.get("portMappings").and_then(|v| v.as_array()).cloned())
            .map(|arr| {
                arr.iter()
                    .filter_map(parse_port_mapping)
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        plans.push(ContainerPlan {
            container_name: container.name.clone(),
            image: container.image.clone(),
            env,
            entry_point: str_array("entryPoint"),
            command: str_array("command"),
            secrets_refs,
            essential: container.essential,
            has_task_role,
            port_mappings,
            network_mode: network_mode.clone(),
        });
    }
    Ok(plans)
}

/// Test-only re-export of [`parse_port_mapping`] so sibling test modules
/// can lock in the default-port / default-protocol behaviour without us
/// widening the visibility of the parser itself.
#[cfg(test)]
pub(crate) fn __test_parse_port_mapping(value: &serde_json::Value) -> Option<PortMapping> {
    parse_port_mapping(value)
}

/// Parse a single `portMappings[]` entry. Returns `None` for entries
/// that are missing `containerPort` or have a value out of `u16` range.
/// Defaults: `hostPort` -> `containerPort`, `protocol` -> `tcp`.
fn parse_port_mapping(value: &serde_json::Value) -> Option<PortMapping> {
    let container_port = value
        .get("containerPort")
        .and_then(|v| v.as_i64())
        .filter(|n| (0..=u16::MAX as i64).contains(n))? as u16;
    let host_port_raw = value
        .get("hostPort")
        .and_then(|v| v.as_i64())
        .filter(|n| (0..=u16::MAX as i64).contains(n))
        .map(|n| n as u16)
        .unwrap_or(0);
    let host_port = if host_port_raw == 0 {
        container_port
    } else {
        host_port_raw
    };
    let protocol = value
        .get("protocol")
        .and_then(|v| v.as_str())
        .map(|s| s.to_ascii_lowercase())
        .unwrap_or_else(|| "tcp".to_string());
    Some(PortMapping {
        container_port,
        host_port,
        protocol,
    })
}

/// Build the docker `run` argv for a single container plan. Pure so unit
/// tests can assert on flag ordering / `--publish` translation without
/// shelling out. The returned vector is everything *after* the binary
/// name (i.e. starts with `run`, ends with the user-supplied command
/// args).
pub(crate) fn build_run_argv(
    plan: &ContainerPlan,
    env: &[(String, String)],
    task_id: &str,
    host_ip: &str,
    run_image: &str,
) -> Vec<String> {
    let mut argv: Vec<String> = Vec::new();
    argv.push("run".into());
    argv.push("-d".into());
    argv.push("--name".into());
    argv.push(format!("{}-{}", task_id, plan.container_name));
    argv.push("--label".into());
    argv.push(format!("fakecloud-ecs-task={}", task_id));
    argv.push("--label".into());
    argv.push(format!("fakecloud-ecs-container={}", plan.container_name));
    argv.push("--add-host".into());
    argv.push(format!("host.docker.internal:{}", host_ip));
    // `awsvpc` puts the container on a per-task ENI; emulating that on a
    // local docker host means *not* publishing to the host port table.
    // Bridge / host / default network modes still get `--publish`.
    let publish_ports = plan.network_mode.as_deref() != Some("awsvpc");
    if publish_ports {
        for pm in &plan.port_mappings {
            argv.push("--publish".into());
            argv.push(format!(
                "{}:{}/{}",
                pm.container_port, pm.host_port, pm.protocol
            ));
        }
    }
    for (k, v) in env {
        let transformed = v
            .replace("http://127.0.0.1:", "http://host.docker.internal:")
            .replace("https://127.0.0.1:", "https://host.docker.internal:")
            .replace("http://localhost:", "http://host.docker.internal:")
            .replace("https://localhost:", "https://host.docker.internal:");
        argv.push("-e".into());
        argv.push(format!("{}={}", k, transformed));
    }
    if let Some(first) = plan.entry_point.first() {
        argv.push("--entrypoint".into());
        argv.push(first.clone());
    }
    argv.push(run_image.to_string());
    for arg in plan.entry_point.iter().skip(1) {
        argv.push(arg.clone());
    }
    for arg in &plan.command {
        argv.push(arg.clone());
    }
    argv
}

/// Render `networkBindings` JSON for a launched container. Empty under
/// `awsvpc` (the equivalent info goes on the task's ENI attachments) and
/// for containers without `portMappings`.
pub(crate) fn network_bindings_for(plan: &ContainerPlan) -> Vec<serde_json::Value> {
    if plan.network_mode.as_deref() == Some("awsvpc") {
        return Vec::new();
    }
    plan.port_mappings
        .iter()
        .map(|pm| {
            serde_json::json!({
                "bindIP": "0.0.0.0",
                "containerPort": pm.container_port,
                "hostPort": pm.host_port,
                "protocol": pm.protocol,
            })
        })
        .collect()
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

pub(crate) fn mark_running_multi(
    state: &SharedEcsState,
    account_id: &str,
    task_id: &str,
    started: &[RunningContainer],
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
        for rc in started {
            if let Some(c) = task.containers.iter_mut().find(|c| c.name == rc.name) {
                c.runtime_id = Some(rc.container_id.clone());
                c.last_status = "RUNNING".into();
                c.network_bindings = rc.network_bindings.clone();
            }
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

#[allow(clippy::too_many_arguments)]
fn finalize_stopped_multi(
    state: &SharedEcsState,
    account_id: &str,
    task_id: &str,
    final_containers: &[RunningContainer],
    primary_exit_code: i64,
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
        task.stopped_reason = stopped_reason.or(Some(format!("Exit code {}", primary_exit_code)));
        task.captured_logs = captured.to_string();
        for c in task.containers.iter_mut() {
            c.last_status = "STOPPED".into();
            if c.exit_code.is_none() {
                let mapped = final_containers
                    .iter()
                    .find(|r| r.name == c.name)
                    .and_then(|r| r.exit_code);
                c.exit_code = mapped.or(Some(primary_exit_code));
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
            "exitCode": primary_exit_code,
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
        // Surface the failure reason on the /logs endpoint — without this,
        // a task that never reached RUNNING returns an empty log string,
        // leaving E2E assertions with no diagnostic.
        task.captured_logs = format!("[task failed to start]: {reason}");
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
    use crate::state::{EcsState, Task};
    use fakecloud_aws::arn::Arn;
    use fakecloud_core::multi_account::MultiAccountState;
    use parking_lot::RwLock;
    use std::sync::Arc;

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

    fn make_task(task_id: &str) -> Task {
        Task {
            task_arn: Arn::new(
                "ecs",
                "us-east-1",
                "000000000000",
                &format!("task/default/{task_id}"),
            )
            .to_string(),
            task_id: task_id.into(),
            cluster_arn: "arn:aws:ecs:us-east-1:000000000000:cluster/default".into(),
            cluster_name: "default".into(),
            task_definition_arn: "arn:aws:ecs:us-east-1:000000000000:task-definition/app:1".into(),
            family: "app".into(),
            revision: 1,
            capacity_provider_name: None,
            last_status: "PENDING".into(),
            desired_status: "RUNNING".into(),
            launch_type: "FARGATE".into(),
            platform_version: None,
            cpu: None,
            memory: None,
            containers: Vec::new(),
            overrides: serde_json::json!({}),
            started_by: None,
            group: None,
            connectivity: "CONNECTING".into(),
            stop_code: None,
            stopped_reason: None,
            created_at: Utc::now(),
            started_at: None,
            stopping_at: None,
            stopped_at: None,
            pull_started_at: None,
            pull_stopped_at: None,
            connectivity_at: None,
            started_by_ref_id: None,
            execution_role_arn: None,
            task_role_arn: None,
            tags: Vec::new(),
            awslogs: None,
            captured_logs: String::new(),
            protection: None,
        }
    }

    #[test]
    fn finalize_failure_writes_reason_into_captured_logs() {
        let mut accounts: MultiAccountState<EcsState> =
            MultiAccountState::new("000000000000", "us-east-1", "http://localhost:4566");
        let acct = accounts.get_or_create("000000000000");
        acct.tasks.insert("t1".into(), make_task("t1"));
        let state: SharedEcsState = Arc::new(RwLock::new(accounts));

        finalize_failure(
            &state,
            "000000000000",
            "t1",
            "failed to resolve secret DB_PASSWORD",
        );

        let accounts = state.read();
        let task = accounts
            .get("000000000000")
            .unwrap()
            .tasks
            .get("t1")
            .unwrap();
        assert_eq!(task.last_status, "STOPPED");
        assert_eq!(task.stop_code.as_deref(), Some("TaskFailedToStart"));
        assert!(
            task.captured_logs
                .contains("failed to resolve secret DB_PASSWORD"),
            "captured_logs missing reason: {:?}",
            task.captured_logs
        );
        assert!(
            task.captured_logs.starts_with("[task failed to start]:"),
            "captured_logs missing prefix: {:?}",
            task.captured_logs
        );
    }

    fn make_container(name: &str, essential: bool) -> crate::state::Container {
        crate::state::Container {
            container_arn: format!(
                "arn:aws:ecs:us-east-1:000000000000:container/default/abc/{name}"
            ),
            name: name.into(),
            image: "alpine".into(),
            task_arn: "arn:aws:ecs:us-east-1:000000000000:task/default/abc".into(),
            last_status: "RUNNING".into(),
            exit_code: None,
            reason: None,
            runtime_id: Some(format!("dockerid-{name}")),
            essential,
            cpu: None,
            memory: None,
            memory_reservation: None,
            network_bindings: Vec::new(),
            network_interfaces: Vec::new(),
            health_status: None,
            managed_agents: None,
        }
    }

    #[test]
    fn task_should_stop_when_essential_exits() {
        let containers = vec![
            RunningContainer {
                name: "app".into(),
                container_id: "id-app".into(),
                essential: true,
                exit_code: Some(0),
                network_bindings: Vec::new(),
            },
            RunningContainer {
                name: "sidecar".into(),
                container_id: "id-sc".into(),
                essential: false,
                exit_code: None,
                network_bindings: Vec::new(),
            },
        ];
        assert!(task_should_stop(&containers));
    }

    #[test]
    fn task_keeps_running_when_only_non_essential_exits() {
        let containers = vec![
            RunningContainer {
                name: "app".into(),
                container_id: "id-app".into(),
                essential: true,
                exit_code: None,
                network_bindings: Vec::new(),
            },
            RunningContainer {
                name: "sidecar".into(),
                container_id: "id-sc".into(),
                essential: false,
                exit_code: Some(0),
                network_bindings: Vec::new(),
            },
        ];
        assert!(!task_should_stop(&containers));
    }

    #[test]
    fn task_stops_when_all_non_essentials_exit() {
        let containers = vec![
            RunningContainer {
                name: "a".into(),
                container_id: "id-a".into(),
                essential: false,
                exit_code: Some(0),
                network_bindings: Vec::new(),
            },
            RunningContainer {
                name: "b".into(),
                container_id: "id-b".into(),
                essential: false,
                exit_code: Some(1),
                network_bindings: Vec::new(),
            },
        ];
        assert!(task_should_stop(&containers));
    }

    #[test]
    fn finalize_stopped_multi_assigns_per_container_exit_codes() {
        let mut accounts: MultiAccountState<EcsState> =
            MultiAccountState::new("000000000000", "us-east-1", "http://localhost:4566");
        let acct = accounts.get_or_create("000000000000");
        let mut t = make_task("t1");
        t.containers = vec![
            make_container("app", true),
            make_container("sidecar", false),
        ];
        acct.tasks.insert("t1".into(), t);
        let state: SharedEcsState = Arc::new(RwLock::new(accounts));

        let final_containers = vec![
            RunningContainer {
                name: "app".into(),
                container_id: "id-app".into(),
                essential: true,
                exit_code: Some(0),
                network_bindings: Vec::new(),
            },
            RunningContainer {
                name: "sidecar".into(),
                container_id: "id-sc".into(),
                essential: false,
                exit_code: Some(137),
                network_bindings: Vec::new(),
            },
        ];
        finalize_stopped_multi(
            &state,
            "000000000000",
            "t1",
            &final_containers,
            0,
            "captured",
            "EssentialContainerExited",
            None,
        );

        let accounts = state.read();
        let task = accounts
            .get("000000000000")
            .unwrap()
            .tasks
            .get("t1")
            .unwrap();
        assert_eq!(task.last_status, "STOPPED");
        assert_eq!(task.stop_code.as_deref(), Some("EssentialContainerExited"));
        let app = task.containers.iter().find(|c| c.name == "app").unwrap();
        let sc = task
            .containers
            .iter()
            .find(|c| c.name == "sidecar")
            .unwrap();
        assert_eq!(app.exit_code, Some(0));
        assert_eq!(sc.exit_code, Some(137));
        assert_eq!(app.last_status, "STOPPED");
        assert_eq!(sc.last_status, "STOPPED");
    }
}
