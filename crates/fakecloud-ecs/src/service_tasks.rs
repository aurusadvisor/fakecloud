// Auto-extracted from service.rs as part of carryover service.rs split.

#![allow(clippy::too_many_arguments)]

use chrono::Utc;
use serde_json::{json, Value};

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use super::*;

impl EcsService {
    pub(super) fn run_task(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let td_ref = req_str(&body, "taskDefinition")?;
        let cluster_ref = opt_str(&body, "cluster");
        let cluster_name = EcsState::resolve_cluster_name(cluster_ref);
        let launch_type = opt_str(&body, "launchType")
            .unwrap_or("FARGATE")
            .to_string();
        let count = body
            .get("count")
            .and_then(|v| v.as_i64())
            .filter(|n| (1..=10).contains(n))
            .unwrap_or(1) as usize;
        let group = opt_str(&body, "group").map(String::from);
        let started_by = opt_str(&body, "startedBy").map(String::from);
        let tags = parse_tags(&body);

        // PassRole trust check on any role overrides supplied via the
        // overrides.taskRoleArn / overrides.executionRoleArn fields.
        // The base task definition was already checked at Register time,
        // but RunTask can override either role and AWS re-validates the
        // trust policy on every call.
        if let Some(overrides) = body.get("overrides") {
            if let Some(role_arn) = opt_str(overrides, "taskRoleArn") {
                self.check_pass_role(&request.account_id, role_arn)?;
            }
            if let Some(role_arn) = opt_str(overrides, "executionRoleArn") {
                self.check_pass_role(&request.account_id, role_arn)?;
            }
        }

        let account = request.account_id.clone();
        let runtime = self.runtime.clone();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        let cluster_arn = state
            .clusters
            .get(&cluster_name)
            .map(|c| c.cluster_arn.clone())
            .unwrap_or_else(|| state.cluster_arn(&cluster_name));
        let (_, family, rev) = resolve_task_definition_ref(td_ref)?;
        let revisions = state
            .task_definitions
            .get(&family)
            .ok_or_else(|| task_definition_not_found(td_ref))?;
        let td = match rev {
            Some(n) => revisions
                .get(&n)
                .ok_or_else(|| task_definition_not_found(td_ref))?,
            None => latest_active_revision(revisions)
                .ok_or_else(|| task_definition_not_found(td_ref))?,
        };
        if td.status != "ACTIVE" {
            return Err(client_exception(format!(
                "Task definition {} is not ACTIVE",
                td.task_definition_arn
            )));
        }
        let td_arn = td.task_definition_arn.clone();
        let td_family = td.family.clone();
        let td_revision = td.revision;
        let td_cpu = td.cpu.clone();
        let td_memory = td.memory.clone();
        let td_task_role = td.task_role_arn.clone();
        let td_exec_role = td.execution_role_arn.clone();
        let td_containers = td.container_definitions.clone();

        let mut spawned_tasks: Vec<String> = Vec::new();
        let mut task_jsons: Vec<Value> = Vec::new();
        for _ in 0..count {
            let task_id = uuid::Uuid::new_v4().to_string().replace('-', "");
            let task_arn = state.task_arn(&cluster_name, &task_id);
            let containers: Vec<Container> = td_containers
                .iter()
                .map(|def| Container {
                    container_arn: format!(
                        "arn:aws:ecs:{}:{}:container/{}/{}/{}",
                        state.region,
                        state.account_id,
                        cluster_name,
                        task_id,
                        def.get("name").and_then(|v| v.as_str()).unwrap_or("app")
                    ),
                    name: def
                        .get("name")
                        .and_then(|v| v.as_str())
                        .unwrap_or("app")
                        .to_string(),
                    image: def
                        .get("image")
                        .and_then(|v| v.as_str())
                        .unwrap_or("")
                        .to_string(),
                    task_arn: task_arn.clone(),
                    last_status: "PENDING".into(),
                    exit_code: None,
                    reason: None,
                    runtime_id: None,
                    essential: def
                        .get("essential")
                        .and_then(|v| v.as_bool())
                        .unwrap_or(true),
                    cpu: def
                        .get("cpu")
                        .and_then(|v| v.as_i64())
                        .map(|n| n.to_string()),
                    memory: def
                        .get("memory")
                        .and_then(|v| v.as_i64())
                        .map(|n| n.to_string()),
                    memory_reservation: def
                        .get("memoryReservation")
                        .and_then(|v| v.as_i64())
                        .map(|n| n.to_string()),
                    network_bindings: Vec::new(),
                    network_interfaces: Vec::new(),
                    health_status: Some("UNKNOWN".to_string()),
                    managed_agents: None,
                })
                .collect();
            let awslogs = td_containers.iter().find_map(|def| {
                let name = def.get("name").and_then(|v| v.as_str())?.to_string();
                let log_cfg = def.get("logConfiguration")?;
                if log_cfg.get("logDriver").and_then(|v| v.as_str()) != Some("awslogs") {
                    return None;
                }
                let opts = log_cfg.get("options").and_then(|v| v.as_object())?;
                Some(AwsLogsConfig {
                    group: opts.get("awslogs-group").and_then(|v| v.as_str())?.into(),
                    stream_prefix: opts
                        .get("awslogs-stream-prefix")
                        .and_then(|v| v.as_str())
                        .map(String::from),
                    region: opts
                        .get("awslogs-region")
                        .and_then(|v| v.as_str())
                        .unwrap_or(&state.region)
                        .to_string(),
                    container_name: name,
                })
            });
            let capacity_provider_name = body
                .get("capacityProviderStrategy")
                .and_then(|v| v.as_array())
                .and_then(|arr| arr.first())
                .and_then(|item| item.get("capacityProvider"))
                .and_then(|v| v.as_str())
                .map(String::from);
            let task = Task {
                task_arn: task_arn.clone(),
                task_id: task_id.clone(),
                cluster_arn: cluster_arn.clone(),
                cluster_name: cluster_name.clone(),
                task_definition_arn: td_arn.clone(),
                family: td_family.clone(),
                revision: td_revision,
                capacity_provider_name,
                last_status: "PROVISIONING".into(),
                desired_status: "RUNNING".into(),
                launch_type: launch_type.clone(),
                platform_version: Some("1.4.0".into()),
                cpu: body
                    .get("overrides")
                    .and_then(|v| v.get("cpu"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .or_else(|| td_cpu.clone()),
                memory: body
                    .get("overrides")
                    .and_then(|v| v.get("memory"))
                    .and_then(|v| v.as_str())
                    .map(String::from)
                    .or_else(|| td_memory.clone()),
                containers,
                overrides: body.get("overrides").cloned().unwrap_or_else(|| json!({})),
                started_by: started_by.clone(),
                group: group.clone(),
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
                execution_role_arn: td_exec_role.clone(),
                task_role_arn: td_task_role.clone(),
                tags: tags.clone(),
                awslogs,
                captured_logs: String::new(),
                protection: None,
            };
            state.tasks.insert(task_id.clone(), task.clone());
            if let Some(cluster) = state.clusters.get_mut(&cluster_name) {
                cluster.pending_tasks_count += 1;
            }
            // Snapshot-in-progress: transition to PENDING synchronously so
            // callers that immediately DescribeTasks see movement. RUNNING /
            // STOPPED come later from the background runtime task.
            if let Some(t) = state.tasks.get_mut(&task_id) {
                t.last_status = "PENDING".into();
            }
            task_jsons.push(task_to_json(&task));
            spawned_tasks.push(task_id.clone());
        }
        drop(accounts);

        // Launch container execution outside the state lock.
        if let Some(rt) = runtime {
            for id in &spawned_tasks {
                rt.clone()
                    .run_task(self.state.clone(), id.clone(), account.clone());
            }
        } else {
            // No runtime available — fail fast so the task doesn't stay
            // PENDING forever. We incremented pending_tasks_count above;
            // decrement it here so the cluster counter doesn't drift and
            // block later DeleteCluster calls.
            let mut accounts = self.state.write();
            if let Some(state) = accounts.get_mut(&account) {
                let mut cluster_drains: Vec<String> = Vec::new();
                for id in &spawned_tasks {
                    if let Some(t) = state.tasks.get_mut(id) {
                        t.last_status = "STOPPED".into();
                        t.desired_status = "STOPPED".into();
                        t.stop_code = Some("TaskFailedToStart".into());
                        t.stopped_reason = Some(
                            "No container runtime available (docker/podman not installed)".into(),
                        );
                        t.stopped_at = Some(Utc::now());
                        for c in t.containers.iter_mut() {
                            c.last_status = "STOPPED".into();
                        }
                        cluster_drains.push(t.cluster_name.clone());
                    }
                }
                for name in cluster_drains {
                    if let Some(cluster) = state.clusters.get_mut(&name) {
                        if cluster.pending_tasks_count > 0 {
                            cluster.pending_tasks_count -= 1;
                        }
                    }
                }
            }
        }

        Ok(AwsResponse::ok_json(json!({
            "tasks": task_jsons,
            "failures": [],
        })))
    }

    pub(super) fn start_task(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        // StartTask targets explicit container instances. Our ECS emulator
        // has no concept of registered container instances yet (Batch 4);
        // fall through to the same semantics as RunTask so the API is
        // usable while the container-instance surface is pending.
        self.run_task(request)
    }

    pub(super) async fn stop_task(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let task_ref = req_str(&body, "task")?;
        let reason = opt_str(&body, "reason")
            .unwrap_or("UserInitiated")
            .to_string();
        let cluster_ref = opt_str(&body, "cluster");
        let _cluster_name = EcsState::resolve_cluster_name(cluster_ref);

        let (task_id, account, task_snapshot) = {
            let account = request.account_id.clone();
            let mut accounts = self.state.write();
            let state = accounts
                .get_mut(&account)
                .ok_or_else(|| task_not_found(task_ref))?;
            let task_id = resolve_task_id(state, task_ref)?;
            let task = state
                .tasks
                .get_mut(&task_id)
                .ok_or_else(|| task_not_found(task_ref))?;
            task.desired_status = "STOPPED".into();
            task.stopping_at = Some(Utc::now());
            task.stopped_reason = Some(reason.clone());
            task.stop_code = Some("UserInitiated".into());
            (task_id, account, task.clone())
        };
        if let Some(rt) = &self.runtime {
            rt.stop_task(&task_id, &reason).await;
        }
        let _ = account;
        Ok(AwsResponse::ok_json(json!({
            "task": task_to_json(&task_snapshot),
        })))
    }

    pub(super) fn describe_tasks(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let refs: Vec<String> = body
            .get("tasks")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let include_tags = body
            .get("include")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().any(|v| v.as_str() == Some("TAGS")))
            .unwrap_or(false);

        let account = request.account_id.clone();
        let accounts = self.state.read();
        let Some(state) = accounts.get(&account) else {
            return Ok(AwsResponse::ok_json(json!({
                "tasks": [],
                "failures": refs.iter().map(|r| json!({"arn": r, "reason": "MISSING"})).collect::<Vec<_>>(),
            })));
        };
        let mut found = Vec::new();
        let mut failures = Vec::new();
        for input in &refs {
            let task_id = task_id_from_ref(input);
            match state.tasks.get(&task_id) {
                Some(t) => {
                    let mut v = task_to_json(t);
                    if include_tags {
                        v.as_object_mut()
                            .unwrap()
                            .insert("tags".into(), tags_json(&t.tags));
                    }
                    found.push(v);
                }
                None => {
                    failures.push(json!({
                        "arn": input,
                        "reason": "MISSING",
                    }));
                }
            }
        }
        Ok(AwsResponse::ok_json(json!({
            "tasks": found,
            "failures": failures,
        })))
    }

    pub(super) fn list_tasks(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let cluster_ref = opt_str(&body, "cluster");
        let cluster_name = EcsState::resolve_cluster_name(cluster_ref);
        let family = opt_str(&body, "family");
        let status_filter = opt_str(&body, "desiredStatus");
        let started_by = opt_str(&body, "startedBy");
        let max_results = body
            .get("maxResults")
            .and_then(|v| v.as_i64())
            .filter(|n| (1..=100).contains(n))
            .map(|n| n as usize)
            .unwrap_or(100);
        let next_token = opt_str(&body, "nextToken").unwrap_or("");

        let account = request.account_id.clone();
        let accounts = self.state.read();
        let mut arns: Vec<String> = match accounts.get(&account) {
            Some(state) => state
                .tasks
                .values()
                .filter(|t| t.cluster_name == cluster_name)
                .filter(|t| family.is_none_or(|f| t.family == f))
                .filter(|t| status_filter.is_none_or(|s| t.desired_status == s))
                .filter(|t| started_by.is_none_or(|s| t.started_by.as_deref() == Some(s)))
                .map(|t| t.task_arn.clone())
                .collect(),
            None => Vec::new(),
        };
        arns.sort();
        let start = next_token.parse::<usize>().unwrap_or(0).min(arns.len());
        let end = (start + max_results).min(arns.len());
        let page = arns[start..end].to_vec();
        let mut out = json!({"taskArns": page});
        if end < arns.len() {
            out.as_object_mut()
                .unwrap()
                .insert("nextToken".into(), json!(end.to_string()));
        }
        Ok(AwsResponse::ok_json(out))
    }
}
