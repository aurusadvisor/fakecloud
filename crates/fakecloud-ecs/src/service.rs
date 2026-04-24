use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use http::StatusCode;
use serde_json::{json, Map, Value};
use tokio::sync::Mutex as AsyncMutex;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
use fakecloud_persistence::SnapshotStore;

use crate::state::{
    Cluster, EcsSnapshot, EcsState, SharedEcsState, TagEntry, TaskDefinition,
    ECS_SNAPSHOT_SCHEMA_VERSION,
};

const SUPPORTED_ACTIONS: &[&str] = &[
    "CreateCluster",
    "DescribeClusters",
    "DeleteCluster",
    "ListClusters",
    "UpdateCluster",
    "UpdateClusterSettings",
    "PutClusterCapacityProviders",
    "RegisterTaskDefinition",
    "DescribeTaskDefinition",
    "DeregisterTaskDefinition",
    "DeleteTaskDefinitions",
    "ListTaskDefinitions",
    "ListTaskDefinitionFamilies",
    "TagResource",
    "UntagResource",
    "ListTagsForResource",
    "PutAccountSetting",
    "PutAccountSettingDefault",
    "DeleteAccountSetting",
    "ListAccountSettings",
];

fn is_mutating(action: &str) -> bool {
    matches!(
        action,
        "CreateCluster"
            | "DeleteCluster"
            | "UpdateCluster"
            | "UpdateClusterSettings"
            | "PutClusterCapacityProviders"
            | "RegisterTaskDefinition"
            | "DeregisterTaskDefinition"
            | "DeleteTaskDefinitions"
            | "TagResource"
            | "UntagResource"
            | "PutAccountSetting"
            | "PutAccountSettingDefault"
            | "DeleteAccountSetting"
    )
}

pub struct EcsService {
    state: SharedEcsState,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    snapshot_lock: Arc<AsyncMutex<()>>,
}

impl EcsService {
    pub fn new(state: SharedEcsState) -> Self {
        Self {
            state,
            snapshot_store: None,
            snapshot_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    pub fn with_snapshot_store(mut self, store: Arc<dyn SnapshotStore>) -> Self {
        self.snapshot_store = Some(store);
        self
    }

    pub fn state_handle(&self) -> &SharedEcsState {
        &self.state
    }

    async fn save_snapshot(&self) {
        let Some(store) = self.snapshot_store.clone() else {
            return;
        };
        let _guard = self.snapshot_lock.lock().await;
        let snapshot = EcsSnapshot {
            schema_version: ECS_SNAPSHOT_SCHEMA_VERSION,
            accounts: Some(self.state.read().clone()),
        };
        let join = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let bytes = serde_json::to_vec(&snapshot)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            store.save(&bytes)
        })
        .await;
        match join {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(%err, "failed to write ecs snapshot"),
            Err(err) => tracing::error!(%err, "ecs snapshot task panicked"),
        }
    }
}

#[async_trait]
impl AwsService for EcsService {
    fn service_name(&self) -> &str {
        "ecs"
    }

    async fn handle(&self, request: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mutates = is_mutating(request.action.as_str());
        let result = match request.action.as_str() {
            "CreateCluster" => self.create_cluster(&request),
            "DescribeClusters" => self.describe_clusters(&request),
            "DeleteCluster" => self.delete_cluster(&request),
            "ListClusters" => self.list_clusters(&request),
            "UpdateCluster" => self.update_cluster(&request),
            "UpdateClusterSettings" => self.update_cluster_settings(&request),
            "PutClusterCapacityProviders" => self.put_cluster_capacity_providers(&request),
            "RegisterTaskDefinition" => self.register_task_definition(&request),
            "DescribeTaskDefinition" => self.describe_task_definition(&request),
            "DeregisterTaskDefinition" => self.deregister_task_definition(&request),
            "DeleteTaskDefinitions" => self.delete_task_definitions(&request),
            "ListTaskDefinitions" => self.list_task_definitions(&request),
            "ListTaskDefinitionFamilies" => self.list_task_definition_families(&request),
            "TagResource" => self.tag_resource(&request),
            "UntagResource" => self.untag_resource(&request),
            "ListTagsForResource" => self.list_tags_for_resource(&request),
            "PutAccountSetting" => self.put_account_setting(&request),
            "PutAccountSettingDefault" => self.put_account_setting_default(&request),
            "DeleteAccountSetting" => self.delete_account_setting(&request),
            "ListAccountSettings" => self.list_account_settings(&request),
            _ => Err(AwsServiceError::action_not_implemented(
                "ecs",
                &request.action,
            )),
        };
        if mutates && matches!(result.as_ref(), Ok(resp) if resp.status.is_success()) {
            self.save_snapshot().await;
        }
        result
    }

    fn supported_actions(&self) -> &[&str] {
        SUPPORTED_ACTIONS
    }
}

// -------- helpers --------

fn req_str<'a>(body: &'a Value, field: &str) -> Result<&'a str, AwsServiceError> {
    body.get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| client_exception(format!("Missing required field: {field}")))
}

fn opt_str<'a>(body: &'a Value, field: &str) -> Option<&'a str> {
    body.get(field).and_then(|v| v.as_str())
}

fn client_exception(message: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(StatusCode::BAD_REQUEST, "ClientException", message)
}

fn invalid_parameter(message: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "InvalidParameterException",
        message,
    )
}

fn cluster_not_found(name: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ClusterNotFoundException",
        format!("The referenced cluster was inactive: {name}"),
    )
}

fn cluster_contains_services() -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ClusterContainsServicesException",
        "The specified cluster still contains active services",
    )
}

fn cluster_contains_tasks() -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ClusterContainsTasksException",
        "The specified cluster still contains active tasks",
    )
}

fn task_definition_not_found(family_rev: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ClientException",
        format!("Unable to describe task definition: {family_rev}"),
    )
}

fn parse_tags(body: &Value) -> Vec<TagEntry> {
    body.get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| {
                    let k = t.get("key").and_then(|v| v.as_str())?;
                    let v = t.get("value").and_then(|v| v.as_str()).unwrap_or("");
                    Some(TagEntry {
                        key: k.to_string(),
                        value: v.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn tags_json(tags: &[TagEntry]) -> Value {
    Value::Array(
        tags.iter()
            .map(|t| json!({"key": t.key, "value": t.value}))
            .collect(),
    )
}

fn merge_tags(current: &mut Vec<TagEntry>, incoming: Vec<TagEntry>) {
    for new_tag in incoming {
        if let Some(existing) = current.iter_mut().find(|t| t.key == new_tag.key) {
            existing.value = new_tag.value;
        } else {
            current.push(new_tag);
        }
    }
}

fn cluster_to_json(cluster: &Cluster) -> Value {
    json!({
        "clusterArn": cluster.cluster_arn,
        "clusterName": cluster.cluster_name,
        "status": cluster.status,
        "registeredContainerInstancesCount": cluster.registered_container_instances_count,
        "runningTasksCount": cluster.running_tasks_count,
        "pendingTasksCount": cluster.pending_tasks_count,
        "activeServicesCount": cluster.active_services_count,
        "statistics": cluster.statistics,
        "tags": tags_json(&cluster.tags),
        "settings": cluster.settings,
        "configuration": cluster.configuration,
        "capacityProviders": cluster.capacity_providers,
        "defaultCapacityProviderStrategy": cluster.default_capacity_provider_strategy,
        "attachments": cluster.attachments,
        "attachmentsStatus": cluster.attachments_status,
        "serviceConnectDefaults": cluster.service_connect_defaults,
    })
}

fn task_definition_to_json(td: &TaskDefinition) -> Value {
    let mut map = Map::new();
    map.insert("taskDefinitionArn".into(), json!(td.task_definition_arn));
    map.insert("family".into(), json!(td.family));
    map.insert("revision".into(), json!(td.revision));
    map.insert("status".into(), json!(td.status));
    map.insert(
        "containerDefinitions".into(),
        Value::Array(td.container_definitions.clone()),
    );
    map.insert("compatibilities".into(), json!(td.compatibilities));
    map.insert(
        "requiresCompatibilities".into(),
        json!(td.requires_compatibilities),
    );
    map.insert("volumes".into(), Value::Array(td.volumes.clone()));
    map.insert(
        "placementConstraints".into(),
        Value::Array(td.placement_constraints.clone()),
    );
    map.insert(
        "requiresAttributes".into(),
        Value::Array(td.requires_attributes.clone()),
    );
    map.insert(
        "inferenceAccelerators".into(),
        Value::Array(td.inference_accelerators.clone()),
    );
    if let Some(ref x) = td.network_mode {
        map.insert("networkMode".into(), json!(x));
    }
    if let Some(ref x) = td.cpu {
        map.insert("cpu".into(), json!(x));
    }
    if let Some(ref x) = td.memory {
        map.insert("memory".into(), json!(x));
    }
    if let Some(ref x) = td.task_role_arn {
        map.insert("taskRoleArn".into(), json!(x));
    }
    if let Some(ref x) = td.execution_role_arn {
        map.insert("executionRoleArn".into(), json!(x));
    }
    if let Some(ref x) = td.pid_mode {
        map.insert("pidMode".into(), json!(x));
    }
    if let Some(ref x) = td.ipc_mode {
        map.insert("ipcMode".into(), json!(x));
    }
    if let Some(ref x) = td.proxy_configuration {
        map.insert("proxyConfiguration".into(), x.clone());
    }
    if let Some(ref x) = td.ephemeral_storage {
        map.insert("ephemeralStorage".into(), x.clone());
    }
    if let Some(ref x) = td.runtime_platform {
        map.insert("runtimePlatform".into(), x.clone());
    }
    if let Some(ref x) = td.registered_by {
        map.insert("registeredBy".into(), json!(x));
    }
    map.insert("registeredAt".into(), json!(td.registered_at.timestamp()));
    if let Some(ts) = td.deregistered_at {
        map.insert("deregisteredAt".into(), json!(ts.timestamp()));
    }
    if let Some(enabled) = td.enable_fault_injection {
        map.insert("enableFaultInjection".into(), json!(enabled));
    }
    Value::Object(map)
}

/// Decode an `arn:aws:ecs:<region>:<account>:<type>/<name>[:<rev>]` ARN
/// into `(account, resource_type, tail)`. For task definitions `tail` is
/// `family:revision`; for clusters it's `cluster_name`.
fn decode_ecs_arn(arn: &str) -> Result<(String, String, String), AwsServiceError> {
    let rest = arn
        .strip_prefix("arn:aws:ecs:")
        .ok_or_else(|| invalid_parameter(format!("Malformed ECS ARN: {arn}")))?;
    // Resource portion may itself contain a trailing `:<revision>`, so we
    // split at most three ways then treat the remainder as the resource.
    let mut parts = rest.splitn(3, ':');
    let _region = parts
        .next()
        .ok_or_else(|| invalid_parameter("Malformed ECS ARN"))?;
    let account = parts
        .next()
        .ok_or_else(|| invalid_parameter("Malformed ECS ARN"))?;
    let resource = parts
        .next()
        .ok_or_else(|| invalid_parameter("Malformed ECS ARN"))?;
    let (resource_type, tail) = resource
        .split_once('/')
        .ok_or_else(|| invalid_parameter("Malformed ECS ARN"))?;
    Ok((
        account.to_string(),
        resource_type.to_string(),
        tail.to_string(),
    ))
}

/// Parse a `family[:revision]` reference. Returns `(family, Some(rev))`
/// when a specific revision is requested, or `(family, None)` for the
/// latest-active shorthand.
fn parse_family_revision(input: &str) -> (String, Option<i32>) {
    if let Some((family, rev)) = input.rsplit_once(':') {
        if let Ok(n) = rev.parse::<i32>() {
            return (family.to_string(), Some(n));
        }
    }
    (input.to_string(), None)
}

/// Task-definition ARNs may appear as the full ARN or just `family:rev`.
/// Returns `(account, family, Some(rev))` where `account` is `None` for
/// the bare shorthand form.
fn resolve_task_definition_ref(
    input: &str,
) -> Result<(Option<String>, String, Option<i32>), AwsServiceError> {
    if input.starts_with("arn:aws:ecs:") {
        let (account, resource_type, tail) = decode_ecs_arn(input)?;
        if resource_type != "task-definition" {
            return Err(invalid_parameter(format!(
                "Expected task-definition ARN: {input}"
            )));
        }
        let (family, rev) = parse_family_revision(&tail);
        Ok((Some(account), family, rev))
    } else {
        let (family, rev) = parse_family_revision(input);
        Ok((None, family, rev))
    }
}

fn target_account_for_task_definition(request: &AwsRequest, td_ref: &str) -> String {
    if let Ok((Some(account), _, _)) = resolve_task_definition_ref(td_ref) {
        account
    } else {
        request.account_id.clone()
    }
}

fn target_account_for_cluster(request: &AwsRequest, cluster_ref: Option<&str>) -> String {
    if let Some(input) = cluster_ref {
        if input.starts_with("arn:aws:ecs:") {
            if let Ok((account, _, _)) = decode_ecs_arn(input) {
                return account;
            }
        }
    }
    request.account_id.clone()
}

fn latest_active_revision(
    revisions: &std::collections::BTreeMap<i32, TaskDefinition>,
) -> Option<&TaskDefinition> {
    revisions.values().rev().find(|td| td.status == "ACTIVE")
}

// -------- operations: clusters --------

impl EcsService {
    fn create_cluster(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let cluster_name = opt_str(&body, "clusterName")
            .unwrap_or("default")
            .to_string();
        let tags = parse_tags(&body);
        let settings: Vec<Value> = body
            .get("settings")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let configuration = body.get("configuration").cloned();
        let capacity_providers: Vec<String> = body
            .get("capacityProviders")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let default_strategy: Vec<Value> = body
            .get("defaultCapacityProviderStrategy")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let service_connect = body.get("serviceConnectDefaults").cloned();

        let account = request.account_id.clone();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        let arn = state.cluster_arn(&cluster_name);
        let mut cluster = Cluster::new(&cluster_name, arn);
        cluster.tags = tags;
        cluster.settings = settings;
        cluster.configuration = configuration;
        cluster.capacity_providers = capacity_providers;
        cluster.default_capacity_provider_strategy = default_strategy;
        cluster.service_connect_defaults = service_connect;
        // CreateCluster on an existing cluster is idempotent-ish — AWS
        // returns the existing cluster, potentially with merged settings.
        // We keep it simple and overwrite on recreate.
        state.clusters.insert(cluster_name.clone(), cluster.clone());

        Ok(AwsResponse::ok_json(json!({
            "cluster": cluster_to_json(&cluster),
        })))
    }

    fn describe_clusters(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let names: Vec<String> = body
            .get("clusters")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| EcsState::resolve_cluster_name(Some(s))))
                    .collect()
            })
            .unwrap_or_else(|| vec!["default".to_string()]);

        let account = request.account_id.clone();
        let accounts = self.state.read();
        let mut found = Vec::new();
        let mut failures = Vec::new();
        if let Some(state) = accounts.get(&account) {
            for name in &names {
                match state.clusters.get(name) {
                    Some(c) => found.push(cluster_to_json(c)),
                    None => failures.push(json!({
                        "arn": state.cluster_arn(name),
                        "reason": "MISSING",
                    })),
                }
            }
        } else {
            for name in &names {
                failures.push(json!({
                    "arn": format!(
                        "arn:aws:ecs:{}:{}:cluster/{}",
                        accounts.region(),
                        account,
                        name
                    ),
                    "reason": "MISSING",
                }));
            }
        }
        Ok(AwsResponse::ok_json(json!({
            "clusters": found,
            "failures": failures,
        })))
    }

    fn delete_cluster(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let cluster_ref = opt_str(&body, "cluster");
        let name = EcsState::resolve_cluster_name(cluster_ref);
        let account = target_account_for_cluster(request, cluster_ref);

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        let cluster = state
            .clusters
            .get_mut(&name)
            .ok_or_else(|| cluster_not_found(&name))?;
        if cluster.active_services_count > 0 {
            return Err(cluster_contains_services());
        }
        if cluster.running_tasks_count > 0 || cluster.pending_tasks_count > 0 {
            return Err(cluster_contains_tasks());
        }
        cluster.status = "INACTIVE".to_string();
        let snapshot = cluster.clone();
        // Real ECS keeps the cluster visible as INACTIVE for about an
        // hour before garbage-collecting it. We drop it immediately to
        // keep state bounded — callers that try to describe it by name
        // will get a MISSING failure, matching the long-tail behaviour.
        state.clusters.remove(&name);
        Ok(AwsResponse::ok_json(json!({
            "cluster": cluster_to_json(&snapshot),
        })))
    }

    fn list_clusters(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let max_results = body
            .get("maxResults")
            .and_then(|v| v.as_i64())
            .filter(|n| (1..=100).contains(n))
            .map(|n| n as usize)
            .unwrap_or(100);
        let next_token = opt_str(&body, "nextToken").unwrap_or("");

        let account = request.account_id.clone();
        let accounts = self.state.read();
        let arns: Vec<String> = match accounts.get(&account) {
            Some(state) => state
                .clusters
                .values()
                .map(|c| c.cluster_arn.clone())
                .collect(),
            None => Vec::new(),
        };
        let start = next_token.parse::<usize>().unwrap_or(0).min(arns.len());
        let end = (start + max_results).min(arns.len());
        let page = arns[start..end].to_vec();
        let next = if end < arns.len() {
            Some(end.to_string())
        } else {
            None
        };
        let mut out = json!({ "clusterArns": page });
        if let Some(n) = next {
            out.as_object_mut()
                .unwrap()
                .insert("nextToken".into(), json!(n));
        }
        Ok(AwsResponse::ok_json(out))
    }

    fn update_cluster(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let cluster_ref = req_str(&body, "cluster")?;
        let name = EcsState::resolve_cluster_name(Some(cluster_ref));
        let account = target_account_for_cluster(request, Some(cluster_ref));

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        let cluster = state
            .clusters
            .get_mut(&name)
            .ok_or_else(|| cluster_not_found(&name))?;
        if let Some(settings) = body.get("settings").and_then(|v| v.as_array()) {
            cluster.settings = settings.clone();
        }
        if let Some(cfg) = body.get("configuration") {
            cluster.configuration = Some(cfg.clone());
        }
        if let Some(sc) = body.get("serviceConnectDefaults") {
            cluster.service_connect_defaults = Some(sc.clone());
        }
        let snapshot = cluster.clone();
        Ok(AwsResponse::ok_json(json!({
            "cluster": cluster_to_json(&snapshot),
        })))
    }

    fn update_cluster_settings(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let cluster_ref = req_str(&body, "cluster")?;
        let name = EcsState::resolve_cluster_name(Some(cluster_ref));
        let account = target_account_for_cluster(request, Some(cluster_ref));
        let settings: Vec<Value> = body
            .get("settings")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        let cluster = state
            .clusters
            .get_mut(&name)
            .ok_or_else(|| cluster_not_found(&name))?;
        cluster.settings = settings;
        let snapshot = cluster.clone();
        Ok(AwsResponse::ok_json(json!({
            "cluster": cluster_to_json(&snapshot),
        })))
    }

    fn put_cluster_capacity_providers(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let cluster_ref = req_str(&body, "cluster")?;
        let name = EcsState::resolve_cluster_name(Some(cluster_ref));
        let account = target_account_for_cluster(request, Some(cluster_ref));
        let capacity_providers: Vec<String> = body
            .get("capacityProviders")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .ok_or_else(|| client_exception("Missing required field: capacityProviders"))?;
        let default_strategy: Vec<Value> = body
            .get("defaultCapacityProviderStrategy")
            .and_then(|v| v.as_array())
            .cloned()
            .ok_or_else(|| {
                client_exception("Missing required field: defaultCapacityProviderStrategy")
            })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        let cluster = state
            .clusters
            .get_mut(&name)
            .ok_or_else(|| cluster_not_found(&name))?;
        cluster.capacity_providers = capacity_providers;
        cluster.default_capacity_provider_strategy = default_strategy;
        let snapshot = cluster.clone();
        Ok(AwsResponse::ok_json(json!({
            "cluster": cluster_to_json(&snapshot),
        })))
    }
}

// -------- operations: task definitions --------

impl EcsService {
    fn register_task_definition(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let family = req_str(&body, "family")?.to_string();
        validate_family_name(&family)?;
        let container_definitions = body
            .get("containerDefinitions")
            .and_then(|v| v.as_array())
            .cloned()
            .ok_or_else(|| client_exception("Missing required field: containerDefinitions"))?;
        if container_definitions.is_empty() {
            return Err(client_exception(
                "Task definition must have at least one container",
            ));
        }
        for cd in &container_definitions {
            if cd
                .get("name")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .is_empty()
            {
                return Err(client_exception(
                    "Container definition is missing required field: name",
                ));
            }
            if cd
                .get("image")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .is_empty()
            {
                return Err(client_exception(
                    "Container definition is missing required field: image",
                ));
            }
        }
        let tags = parse_tags(&body);
        let requires_compatibilities: Vec<String> = body
            .get("requiresCompatibilities")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        // Compatibilities reflect what the task definition is compatible with.
        // We always claim EC2 and FARGATE since we execute via Docker either
        // way — callers with stricter requirements set `requiresCompatibilities`.
        let compatibilities = vec!["EC2".to_string(), "FARGATE".to_string()];

        let account = request.account_id.clone();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        let revision = state.allocate_revision(&family);
        let arn = state.task_definition_arn(&family, revision);
        let td = TaskDefinition {
            family: family.clone(),
            revision,
            task_definition_arn: arn,
            container_definitions,
            status: "ACTIVE".to_string(),
            task_role_arn: opt_str(&body, "taskRoleArn").map(String::from),
            execution_role_arn: opt_str(&body, "executionRoleArn").map(String::from),
            network_mode: opt_str(&body, "networkMode").map(String::from),
            requires_compatibilities,
            compatibilities,
            cpu: opt_str(&body, "cpu").map(String::from),
            memory: opt_str(&body, "memory").map(String::from),
            pid_mode: opt_str(&body, "pidMode").map(String::from),
            ipc_mode: opt_str(&body, "ipcMode").map(String::from),
            volumes: body
                .get("volumes")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default(),
            placement_constraints: body
                .get("placementConstraints")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default(),
            proxy_configuration: body.get("proxyConfiguration").cloned(),
            inference_accelerators: body
                .get("inferenceAccelerators")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default(),
            ephemeral_storage: body.get("ephemeralStorage").cloned(),
            runtime_platform: body.get("runtimePlatform").cloned(),
            requires_attributes: Vec::new(),
            registered_at: Utc::now(),
            registered_by: request
                .principal
                .as_ref()
                .map(|p| p.arn.clone())
                .or(Some(format!("arn:aws:iam::{}:root", state.account_id))),
            deregistered_at: None,
            tags: tags.clone(),
            enable_fault_injection: body.get("enableFaultInjection").and_then(|v| v.as_bool()),
        };
        let td_json = task_definition_to_json(&td);
        state
            .task_definitions
            .entry(family.clone())
            .or_default()
            .insert(revision, td);

        Ok(AwsResponse::ok_json(json!({
            "taskDefinition": td_json,
            "tags": tags_json(&tags),
        })))
    }

    fn describe_task_definition(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let td_ref = req_str(&body, "taskDefinition")?;
        let (_, family, rev) = resolve_task_definition_ref(td_ref)?;
        let include_tags = body
            .get("include")
            .and_then(|v| v.as_array())
            .map(|arr| arr.iter().any(|v| v.as_str() == Some("TAGS")))
            .unwrap_or(false);

        let account = target_account_for_task_definition(request, td_ref);
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| task_definition_not_found(td_ref))?;
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
        let mut out = json!({"taskDefinition": task_definition_to_json(td)});
        if include_tags {
            out.as_object_mut()
                .unwrap()
                .insert("tags".into(), tags_json(&td.tags));
        }
        Ok(AwsResponse::ok_json(out))
    }

    fn deregister_task_definition(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let td_ref = req_str(&body, "taskDefinition")?;
        let (_, family, rev) = resolve_task_definition_ref(td_ref)?;
        let rev =
            rev.ok_or_else(|| client_exception("taskDefinition must reference a revision"))?;

        let account = target_account_for_task_definition(request, td_ref);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        let revisions = state
            .task_definitions
            .get_mut(&family)
            .ok_or_else(|| task_definition_not_found(td_ref))?;
        let td = revisions
            .get_mut(&rev)
            .ok_or_else(|| task_definition_not_found(td_ref))?;
        td.status = "INACTIVE".to_string();
        td.deregistered_at = Some(Utc::now());
        let snapshot = td.clone();
        Ok(AwsResponse::ok_json(json!({
            "taskDefinition": task_definition_to_json(&snapshot),
        })))
    }

    fn delete_task_definitions(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let refs: Vec<String> = body
            .get("taskDefinitions")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .ok_or_else(|| client_exception("Missing required field: taskDefinitions"))?;
        if refs.is_empty() {
            return Err(client_exception("taskDefinitions must not be empty"));
        }

        let mut deleted = Vec::new();
        let mut failures = Vec::new();
        let account = request.account_id.clone();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        for input in refs {
            let parsed = match resolve_task_definition_ref(&input) {
                Ok((_, family, Some(rev))) => Some((family, rev)),
                Ok(_) => None,
                Err(_) => None,
            };
            let Some((family, rev)) = parsed else {
                failures.push(json!({
                    "arn": input,
                    "reason": "INVALID_REFERENCE",
                    "detail": "Expected family:revision or full task-definition ARN",
                }));
                continue;
            };
            let Some(revisions) = state.task_definitions.get_mut(&family) else {
                failures.push(json!({"arn": input, "reason": "MISSING"}));
                continue;
            };
            let Some(td) = revisions.get_mut(&rev) else {
                failures.push(json!({"arn": input, "reason": "MISSING"}));
                continue;
            };
            if td.status == "ACTIVE" {
                failures.push(json!({
                    "arn": td.task_definition_arn.clone(),
                    "reason": "MUST_BE_INACTIVE",
                    "detail": "Task definitions must be deregistered before they can be deleted",
                }));
                continue;
            }
            td.status = "DELETE_IN_PROGRESS".to_string();
            deleted.push(task_definition_to_json(td));
        }
        Ok(AwsResponse::ok_json(json!({
            "taskDefinitions": deleted,
            "failures": failures,
        })))
    }

    fn list_task_definitions(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let family_prefix = opt_str(&body, "familyPrefix");
        let status = opt_str(&body, "status").unwrap_or("ACTIVE");
        let sort = opt_str(&body, "sort").unwrap_or("ASC");
        let max_results = body
            .get("maxResults")
            .and_then(|v| v.as_i64())
            .filter(|n| (1..=100).contains(n))
            .map(|n| n as usize)
            .unwrap_or(100);
        let next_token = opt_str(&body, "nextToken").unwrap_or("");

        let account = request.account_id.clone();
        let accounts = self.state.read();
        let mut arns: Vec<String> = Vec::new();
        if let Some(state) = accounts.get(&account) {
            for (family, revisions) in &state.task_definitions {
                if let Some(prefix) = family_prefix {
                    if !family.starts_with(prefix) {
                        continue;
                    }
                }
                for td in revisions.values() {
                    if td.status == status {
                        arns.push(td.task_definition_arn.clone());
                    }
                }
            }
        }
        if sort == "DESC" {
            arns.sort();
            arns.reverse();
        } else {
            arns.sort();
        }
        let start = next_token.parse::<usize>().unwrap_or(0).min(arns.len());
        let end = (start + max_results).min(arns.len());
        let page = arns[start..end].to_vec();
        let mut out = json!({"taskDefinitionArns": page});
        if end < arns.len() {
            out.as_object_mut()
                .unwrap()
                .insert("nextToken".into(), json!(end.to_string()));
        }
        Ok(AwsResponse::ok_json(out))
    }

    fn list_task_definition_families(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let family_prefix = opt_str(&body, "familyPrefix");
        let status = opt_str(&body, "status").unwrap_or("ACTIVE");
        let max_results = body
            .get("maxResults")
            .and_then(|v| v.as_i64())
            .filter(|n| (1..=100).contains(n))
            .map(|n| n as usize)
            .unwrap_or(100);
        let next_token = opt_str(&body, "nextToken").unwrap_or("");

        let account = request.account_id.clone();
        let accounts = self.state.read();
        let mut families: Vec<String> = Vec::new();
        if let Some(state) = accounts.get(&account) {
            for (family, revisions) in &state.task_definitions {
                if let Some(prefix) = family_prefix {
                    if !family.starts_with(prefix) {
                        continue;
                    }
                }
                let matches_status = match status {
                    "ACTIVE" => revisions.values().any(|td| td.status == "ACTIVE"),
                    "INACTIVE" => revisions
                        .values()
                        .all(|td| td.status == "INACTIVE" || td.status == "DELETE_IN_PROGRESS"),
                    "ALL" => true,
                    _ => revisions.values().any(|td| td.status == status),
                };
                if matches_status {
                    families.push(family.clone());
                }
            }
        }
        families.sort();
        let start = next_token.parse::<usize>().unwrap_or(0).min(families.len());
        let end = (start + max_results).min(families.len());
        let page = families[start..end].to_vec();
        let mut out = json!({"families": page});
        if end < families.len() {
            out.as_object_mut()
                .unwrap()
                .insert("nextToken".into(), json!(end.to_string()));
        }
        Ok(AwsResponse::ok_json(out))
    }
}

fn validate_family_name(family: &str) -> Result<(), AwsServiceError> {
    if family.is_empty() || family.len() > 255 {
        return Err(invalid_parameter(
            "Task definition family must be 1-255 characters",
        ));
    }
    let ok = family
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-');
    if !ok {
        return Err(invalid_parameter(
            "Task definition family may only contain letters, numbers, hyphens, and underscores",
        ));
    }
    Ok(())
}

// -------- operations: tagging --------

impl EcsService {
    fn tag_resource(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let arn = req_str(&body, "resourceArn")?.to_string();
        let tags = parse_tags(&body);
        let (account, resource_type, tail) = decode_ecs_arn(&arn)?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        match resource_type.as_str() {
            "cluster" => {
                let cluster = state
                    .clusters
                    .get_mut(&tail)
                    .ok_or_else(|| resource_not_found(&arn))?;
                merge_tags(&mut cluster.tags, tags);
            }
            "task-definition" => {
                let (family, rev) = parse_family_revision(&tail);
                let rev = rev.ok_or_else(|| {
                    invalid_parameter("task-definition ARN must include revision")
                })?;
                let td = state
                    .task_definitions
                    .get_mut(&family)
                    .and_then(|m| m.get_mut(&rev))
                    .ok_or_else(|| resource_not_found(&arn))?;
                merge_tags(&mut td.tags, tags);
            }
            other => {
                return Err(invalid_parameter(format!(
                    "Tagging not yet supported for resource type: {other}"
                )));
            }
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn untag_resource(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let arn = req_str(&body, "resourceArn")?.to_string();
        let keys: Vec<String> = body
            .get("tagKeys")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let (account, resource_type, tail) = decode_ecs_arn(&arn)?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        match resource_type.as_str() {
            "cluster" => {
                let cluster = state
                    .clusters
                    .get_mut(&tail)
                    .ok_or_else(|| resource_not_found(&arn))?;
                cluster.tags.retain(|t| !keys.contains(&t.key));
            }
            "task-definition" => {
                let (family, rev) = parse_family_revision(&tail);
                let rev = rev.ok_or_else(|| {
                    invalid_parameter("task-definition ARN must include revision")
                })?;
                let td = state
                    .task_definitions
                    .get_mut(&family)
                    .and_then(|m| m.get_mut(&rev))
                    .ok_or_else(|| resource_not_found(&arn))?;
                td.tags.retain(|t| !keys.contains(&t.key));
            }
            other => {
                return Err(invalid_parameter(format!(
                    "Tagging not yet supported for resource type: {other}"
                )));
            }
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn list_tags_for_resource(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let arn = req_str(&body, "resourceArn")?.to_string();
        let (account, resource_type, tail) = decode_ecs_arn(&arn)?;
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| resource_not_found(&arn))?;
        let tags = match resource_type.as_str() {
            "cluster" => state
                .clusters
                .get(&tail)
                .map(|c| c.tags.clone())
                .ok_or_else(|| resource_not_found(&arn))?,
            "task-definition" => {
                let (family, rev) = parse_family_revision(&tail);
                let rev = rev.ok_or_else(|| {
                    invalid_parameter("task-definition ARN must include revision")
                })?;
                state
                    .task_definitions
                    .get(&family)
                    .and_then(|m| m.get(&rev))
                    .map(|td| td.tags.clone())
                    .ok_or_else(|| resource_not_found(&arn))?
            }
            other => {
                return Err(invalid_parameter(format!(
                    "ListTagsForResource not yet supported for resource type: {other}"
                )));
            }
        };
        Ok(AwsResponse::ok_json(json!({"tags": tags_json(&tags)})))
    }
}

fn resource_not_found(arn: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ClientException",
        format!("The referenced resource was not found: {arn}"),
    )
}

// -------- operations: account settings --------

impl EcsService {
    fn put_account_setting(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "name")?.to_string();
        let value = req_str(&body, "value")?.to_string();
        let principal_arn = opt_str(&body, "principalArn")
            .map(String::from)
            .or_else(|| request.principal.as_ref().map(|p| p.arn.clone()))
            .unwrap_or_else(|| format!("arn:aws:iam::{}:root", request.account_id));
        let account = request.account_id.clone();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        state
            .principal_account_settings
            .entry(principal_arn.clone())
            .or_default()
            .insert(name.clone(), value.clone());
        Ok(AwsResponse::ok_json(json!({
            "setting": {
                "name": name,
                "value": value,
                "principalArn": principal_arn,
            }
        })))
    }

    fn put_account_setting_default(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "name")?.to_string();
        let value = req_str(&body, "value")?.to_string();
        let account = request.account_id.clone();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        state
            .account_setting_defaults
            .insert(name.clone(), value.clone());
        Ok(AwsResponse::ok_json(json!({
            "setting": {
                "name": name,
                "value": value,
                "principalArn": format!("arn:aws:iam::{}:root", state.account_id),
            }
        })))
    }

    fn delete_account_setting(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "name")?.to_string();
        let principal_arn = opt_str(&body, "principalArn")
            .map(String::from)
            .or_else(|| request.principal.as_ref().map(|p| p.arn.clone()))
            .unwrap_or_else(|| format!("arn:aws:iam::{}:root", request.account_id));
        let account = request.account_id.clone();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        let removed_value = state
            .principal_account_settings
            .get_mut(&principal_arn)
            .and_then(|m| m.remove(&name));
        Ok(AwsResponse::ok_json(json!({
            "setting": {
                "name": name,
                "value": removed_value.unwrap_or_default(),
                "principalArn": principal_arn,
            }
        })))
    }

    fn list_account_settings(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name_filter = opt_str(&body, "name");
        let value_filter = opt_str(&body, "value");
        let principal_filter = opt_str(&body, "principalArn");
        let effective_only = body
            .get("effectiveSettings")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);

        let account = request.account_id.clone();
        let accounts = self.state.read();
        let Some(state) = accounts.get(&account) else {
            return Ok(AwsResponse::ok_json(json!({"settings": []})));
        };
        let root_arn = format!("arn:aws:iam::{}:root", state.account_id);
        let mut settings: Vec<Value> = Vec::new();

        if effective_only {
            // Merge principal overrides onto defaults, scoped to principal_filter
            // when supplied; otherwise use the caller's own principal.
            let principal = principal_filter
                .map(String::from)
                .or_else(|| request.principal.as_ref().map(|p| p.arn.clone()))
                .unwrap_or_else(|| root_arn.clone());
            let mut merged = state.account_setting_defaults.clone();
            if let Some(overrides) = state.principal_account_settings.get(&principal) {
                for (k, v) in overrides {
                    merged.insert(k.clone(), v.clone());
                }
            }
            for (k, v) in merged {
                if matches_filter(name_filter, &k) && matches_filter(value_filter, &v) {
                    settings.push(json!({
                        "name": k,
                        "value": v,
                        "principalArn": principal,
                    }));
                }
            }
        } else {
            // Raw listing: include defaults (under the root ARN) plus any
            // principal-specific settings.
            for (k, v) in &state.account_setting_defaults {
                if matches_filter(name_filter, k)
                    && matches_filter(value_filter, v)
                    && (principal_filter.is_none() || principal_filter == Some(root_arn.as_str()))
                {
                    settings.push(json!({
                        "name": k,
                        "value": v,
                        "principalArn": root_arn,
                    }));
                }
            }
            for (principal, entries) in &state.principal_account_settings {
                if principal_filter.is_some_and(|pf| pf != principal) {
                    continue;
                }
                for (k, v) in entries {
                    if matches_filter(name_filter, k) && matches_filter(value_filter, v) {
                        settings.push(json!({
                            "name": k,
                            "value": v,
                            "principalArn": principal,
                        }));
                    }
                }
            }
        }

        Ok(AwsResponse::ok_json(json!({"settings": settings})))
    }
}

fn matches_filter(filter: Option<&str>, value: &str) -> bool {
    filter.is_none_or(|f| f == value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_family_revision_with_revision() {
        assert_eq!(parse_family_revision("web:3"), ("web".to_string(), Some(3)));
    }

    #[test]
    fn parse_family_revision_without_revision() {
        assert_eq!(parse_family_revision("web"), ("web".to_string(), None));
    }

    #[test]
    fn parse_family_revision_non_numeric_treated_as_no_revision() {
        assert_eq!(
            parse_family_revision("web:latest"),
            ("web:latest".to_string(), None)
        );
    }

    #[test]
    fn decode_ecs_arn_cluster() {
        let (account, rtype, tail) =
            decode_ecs_arn("arn:aws:ecs:us-east-1:111122223333:cluster/prod").unwrap();
        assert_eq!(account, "111122223333");
        assert_eq!(rtype, "cluster");
        assert_eq!(tail, "prod");
    }

    #[test]
    fn decode_ecs_arn_task_definition() {
        let (account, rtype, tail) =
            decode_ecs_arn("arn:aws:ecs:us-east-1:111122223333:task-definition/web:5").unwrap();
        assert_eq!(account, "111122223333");
        assert_eq!(rtype, "task-definition");
        assert_eq!(tail, "web:5");
    }

    #[test]
    fn decode_ecs_arn_rejects_non_ecs() {
        assert!(decode_ecs_arn("arn:aws:s3:::bucket").is_err());
    }

    #[test]
    fn validate_family_name_accepts_hyphen_underscore() {
        assert!(validate_family_name("web_server-2").is_ok());
    }

    #[test]
    fn validate_family_name_rejects_empty() {
        assert!(validate_family_name("").is_err());
    }

    #[test]
    fn validate_family_name_rejects_slash() {
        assert!(validate_family_name("web/server").is_err());
    }

    #[test]
    fn resolve_task_definition_ref_bare_family() {
        let (account, family, rev) = resolve_task_definition_ref("web").unwrap();
        assert_eq!(account, None);
        assert_eq!(family, "web");
        assert_eq!(rev, None);
    }

    #[test]
    fn resolve_task_definition_ref_family_revision() {
        let (account, family, rev) = resolve_task_definition_ref("web:3").unwrap();
        assert_eq!(account, None);
        assert_eq!(family, "web");
        assert_eq!(rev, Some(3));
    }

    #[test]
    fn resolve_task_definition_ref_full_arn() {
        let (account, family, rev) =
            resolve_task_definition_ref("arn:aws:ecs:us-east-1:111122223333:task-definition/web:3")
                .unwrap();
        assert_eq!(account, Some("111122223333".to_string()));
        assert_eq!(family, "web");
        assert_eq!(rev, Some(3));
    }

    #[test]
    fn merge_tags_replaces_existing_value() {
        let mut current = vec![TagEntry {
            key: "env".into(),
            value: "dev".into(),
        }];
        merge_tags(
            &mut current,
            vec![TagEntry {
                key: "env".into(),
                value: "prod".into(),
            }],
        );
        assert_eq!(current.len(), 1);
        assert_eq!(current[0].value, "prod");
    }

    #[test]
    fn merge_tags_adds_new() {
        let mut current = vec![TagEntry {
            key: "env".into(),
            value: "dev".into(),
        }];
        merge_tags(
            &mut current,
            vec![TagEntry {
                key: "team".into(),
                value: "platform".into(),
            }],
        );
        assert_eq!(current.len(), 2);
    }

    #[test]
    fn parse_tags_reads_lowercase_keys() {
        let body = json!({
            "tags": [
                {"key": "env", "value": "prod"},
                {"key": "team", "value": "platform"},
            ]
        });
        let tags = parse_tags(&body);
        assert_eq!(tags.len(), 2);
        assert_eq!(tags[0].key, "env");
        assert_eq!(tags[0].value, "prod");
    }

    #[test]
    fn matches_filter_respects_none() {
        assert!(matches_filter(None, "anything"));
        assert!(matches_filter(Some("x"), "x"));
        assert!(!matches_filter(Some("x"), "y"));
    }
}
