use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub type SharedEcsState = Arc<RwLock<fakecloud_core::multi_account::MultiAccountState<EcsState>>>;

impl fakecloud_core::multi_account::AccountState for EcsState {
    fn new_for_account(account_id: &str, region: &str, _endpoint: &str) -> Self {
        Self::new(account_id, region)
    }
}

pub const ECS_SNAPSHOT_SCHEMA_VERSION: u32 = 2;

/// Top-level persisted ECS snapshot. Mirrors the multi-account snapshot
/// convention used by Kinesis/ECR/ElastiCache so `main.rs` can share the
/// load/save pattern.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcsSnapshot {
    pub schema_version: u32,
    pub accounts: Option<fakecloud_core::multi_account::MultiAccountState<EcsState>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EcsState {
    pub account_id: String,
    pub region: String,
    /// Cluster state keyed by cluster name.
    pub clusters: BTreeMap<String, Cluster>,
    /// Task definitions keyed by `family` -> `revision` -> definition.
    /// ECS revisions monotonically increase per-family regardless of
    /// deregistration, so we track the running counter separately.
    pub task_definitions: BTreeMap<String, BTreeMap<i32, TaskDefinition>>,
    /// Running revision counter per family. Grows monotonically even
    /// after task definitions are deregistered or deleted.
    pub next_revision: BTreeMap<String, i32>,
    /// Account-default settings (PutAccountSettingDefault). Keyed by
    /// setting name (e.g. `serviceLongArnFormat`).
    pub account_setting_defaults: BTreeMap<String, String>,
    /// Per-principal account settings (PutAccountSetting). Keyed by
    /// principal ARN, then setting name.
    pub principal_account_settings: BTreeMap<String, BTreeMap<String, String>>,
    /// Tasks keyed by task ID (the trailing segment of the task ARN).
    #[serde(default)]
    pub tasks: BTreeMap<String, Task>,
    /// Lifecycle event log for introspection. Bounded at 1024 entries
    /// (oldest dropped) so long-running servers don't grow unboundedly.
    #[serde(default)]
    pub events: Vec<LifecycleEvent>,
}

impl EcsState {
    pub fn new(account_id: &str, region: &str) -> Self {
        Self {
            account_id: account_id.to_string(),
            region: region.to_string(),
            clusters: BTreeMap::new(),
            task_definitions: BTreeMap::new(),
            next_revision: BTreeMap::new(),
            account_setting_defaults: BTreeMap::new(),
            principal_account_settings: BTreeMap::new(),
            tasks: BTreeMap::new(),
            events: Vec::new(),
        }
    }

    pub fn reset(&mut self) {
        self.clusters.clear();
        self.task_definitions.clear();
        self.next_revision.clear();
        self.account_setting_defaults.clear();
        self.principal_account_settings.clear();
        self.tasks.clear();
        self.events.clear();
    }

    pub fn task_arn(&self, cluster_name: &str, task_id: &str) -> String {
        format!(
            "arn:aws:ecs:{}:{}:task/{}/{}",
            self.region, self.account_id, cluster_name, task_id
        )
    }

    /// Append a lifecycle event, trimming the oldest when the cap is hit.
    pub fn push_event(&mut self, event: LifecycleEvent) {
        const MAX_EVENTS: usize = 1024;
        if self.events.len() >= MAX_EVENTS {
            self.events.drain(0..self.events.len() - MAX_EVENTS + 1);
        }
        self.events.push(event);
    }

    pub fn cluster_arn(&self, cluster_name: &str) -> String {
        format!(
            "arn:aws:ecs:{}:{}:cluster/{}",
            self.region, self.account_id, cluster_name
        )
    }

    pub fn task_definition_arn(&self, family: &str, revision: i32) -> String {
        format!(
            "arn:aws:ecs:{}:{}:task-definition/{}:{}",
            self.region, self.account_id, family, revision
        )
    }

    /// Given a user-supplied cluster reference (name or ARN), return the
    /// cluster name. Defaults to `"default"` when `None`/empty, matching
    /// the AWS CLI behaviour.
    pub fn resolve_cluster_name(input: Option<&str>) -> String {
        let raw = input.unwrap_or("").trim();
        if raw.is_empty() {
            return "default".to_string();
        }
        if let Some(name) = raw.rsplit_once('/').map(|(_, n)| n) {
            return name.to_string();
        }
        raw.to_string()
    }

    /// Bump and return the next revision number for a family. Never
    /// reused: monotonically increases even across deregistration.
    pub fn allocate_revision(&mut self, family: &str) -> i32 {
        let next = self.next_revision.entry(family.to_string()).or_insert(0);
        *next += 1;
        *next
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Cluster {
    pub cluster_name: String,
    pub cluster_arn: String,
    pub status: String,
    pub registered_container_instances_count: i32,
    pub running_tasks_count: i32,
    pub pending_tasks_count: i32,
    pub active_services_count: i32,
    #[serde(default)]
    pub statistics: Vec<Value>,
    #[serde(default)]
    pub tags: Vec<TagEntry>,
    #[serde(default)]
    pub settings: Vec<Value>,
    pub configuration: Option<Value>,
    #[serde(default)]
    pub capacity_providers: Vec<String>,
    #[serde(default)]
    pub default_capacity_provider_strategy: Vec<Value>,
    #[serde(default)]
    pub attachments: Vec<Value>,
    pub attachments_status: Option<String>,
    pub service_connect_defaults: Option<Value>,
    pub created_at: DateTime<Utc>,
}

impl Cluster {
    pub fn new(cluster_name: &str, cluster_arn: String) -> Self {
        Self {
            cluster_name: cluster_name.to_string(),
            cluster_arn,
            status: "ACTIVE".to_string(),
            registered_container_instances_count: 0,
            running_tasks_count: 0,
            pending_tasks_count: 0,
            active_services_count: 0,
            statistics: Vec::new(),
            tags: Vec::new(),
            settings: Vec::new(),
            configuration: None,
            capacity_providers: Vec::new(),
            default_capacity_provider_strategy: Vec::new(),
            attachments: Vec::new(),
            attachments_status: None,
            service_connect_defaults: None,
            created_at: Utc::now(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TagEntry {
    pub key: String,
    pub value: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TaskDefinition {
    pub family: String,
    pub revision: i32,
    pub task_definition_arn: String,
    /// Free-form container definitions preserved as the JSON the caller
    /// supplied. ECS accepts so many optional fields that round-tripping
    /// the raw JSON is simpler and more faithful than modeling a struct
    /// with hundreds of members per container.
    #[serde(default)]
    pub container_definitions: Vec<Value>,
    pub status: String,
    pub task_role_arn: Option<String>,
    pub execution_role_arn: Option<String>,
    pub network_mode: Option<String>,
    #[serde(default)]
    pub requires_compatibilities: Vec<String>,
    #[serde(default)]
    pub compatibilities: Vec<String>,
    pub cpu: Option<String>,
    pub memory: Option<String>,
    pub pid_mode: Option<String>,
    pub ipc_mode: Option<String>,
    #[serde(default)]
    pub volumes: Vec<Value>,
    #[serde(default)]
    pub placement_constraints: Vec<Value>,
    pub proxy_configuration: Option<Value>,
    #[serde(default)]
    pub inference_accelerators: Vec<Value>,
    pub ephemeral_storage: Option<Value>,
    pub runtime_platform: Option<Value>,
    #[serde(default)]
    pub requires_attributes: Vec<Value>,
    pub registered_at: DateTime<Utc>,
    pub registered_by: Option<String>,
    pub deregistered_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub tags: Vec<TagEntry>,
    pub enable_fault_injection: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Task {
    pub task_arn: String,
    pub task_id: String,
    pub cluster_arn: String,
    pub cluster_name: String,
    pub task_definition_arn: String,
    pub family: String,
    pub revision: i32,
    /// Current lifecycle state: PROVISIONING, PENDING, RUNNING,
    /// DEPROVISIONING, STOPPED.
    pub last_status: String,
    /// What the caller asked for: usually RUNNING, or STOPPED once
    /// `StopTask` / `StopService` hits.
    pub desired_status: String,
    pub launch_type: String,
    pub platform_version: Option<String>,
    pub cpu: Option<String>,
    pub memory: Option<String>,
    #[serde(default)]
    pub containers: Vec<Container>,
    #[serde(default)]
    pub overrides: Value,
    pub started_by: Option<String>,
    pub group: Option<String>,
    pub connectivity: String,
    pub stop_code: Option<String>,
    pub stopped_reason: Option<String>,
    pub created_at: DateTime<Utc>,
    pub started_at: Option<DateTime<Utc>>,
    pub stopping_at: Option<DateTime<Utc>>,
    pub stopped_at: Option<DateTime<Utc>>,
    pub pull_started_at: Option<DateTime<Utc>>,
    pub pull_stopped_at: Option<DateTime<Utc>>,
    pub connectivity_at: Option<DateTime<Utc>>,
    pub started_by_ref_id: Option<String>,
    pub execution_role_arn: Option<String>,
    pub task_role_arn: Option<String>,
    #[serde(default)]
    pub tags: Vec<TagEntry>,
    /// Log destination derived from the first container's awslogs driver.
    /// `None` when no awslogs driver is configured — captured stdout/stderr
    /// is still stored on the task for introspection.
    pub awslogs: Option<AwsLogsConfig>,
    /// Captured stdout/stderr from the container. Populated after the
    /// container exits. Kept here so the introspection endpoint can serve
    /// logs even when no awslogs driver is configured.
    #[serde(default)]
    pub captured_logs: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Container {
    pub container_arn: String,
    pub name: String,
    pub image: String,
    pub task_arn: String,
    pub last_status: String,
    pub exit_code: Option<i64>,
    pub reason: Option<String>,
    pub runtime_id: Option<String>,
    pub essential: bool,
    pub cpu: Option<String>,
    pub memory: Option<String>,
    pub memory_reservation: Option<String>,
    #[serde(default)]
    pub network_bindings: Vec<Value>,
    #[serde(default)]
    pub network_interfaces: Vec<Value>,
    pub health_status: Option<String>,
    pub managed_agents: Option<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AwsLogsConfig {
    pub group: String,
    pub stream_prefix: Option<String>,
    pub region: String,
    pub container_name: String,
}

impl AwsLogsConfig {
    pub fn stream_name(&self, task_id: &str) -> String {
        match &self.stream_prefix {
            Some(p) => format!("{}/{}/{}", p, self.container_name, task_id),
            None => format!("{}/{}", self.container_name, task_id),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LifecycleEvent {
    pub at: DateTime<Utc>,
    pub event_type: String,
    pub task_arn: Option<String>,
    pub cluster_arn: Option<String>,
    pub last_status: Option<String>,
    pub detail: Value,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolve_cluster_name_defaults_to_default() {
        assert_eq!(EcsState::resolve_cluster_name(None), "default");
        assert_eq!(EcsState::resolve_cluster_name(Some("")), "default");
        assert_eq!(EcsState::resolve_cluster_name(Some("   ")), "default");
    }

    #[test]
    fn resolve_cluster_name_strips_arn_prefix() {
        assert_eq!(
            EcsState::resolve_cluster_name(Some("arn:aws:ecs:us-east-1:111122223333:cluster/prod")),
            "prod"
        );
    }

    #[test]
    fn resolve_cluster_name_passes_through_name() {
        assert_eq!(EcsState::resolve_cluster_name(Some("prod")), "prod");
    }

    #[test]
    fn allocate_revision_monotonic() {
        let mut s = EcsState::new("111122223333", "us-east-1");
        assert_eq!(s.allocate_revision("web"), 1);
        assert_eq!(s.allocate_revision("web"), 2);
        assert_eq!(s.allocate_revision("worker"), 1);
        assert_eq!(s.allocate_revision("web"), 3);
    }

    #[test]
    fn cluster_arn_format() {
        let s = EcsState::new("111122223333", "us-east-1");
        assert_eq!(
            s.cluster_arn("prod"),
            "arn:aws:ecs:us-east-1:111122223333:cluster/prod"
        );
    }

    #[test]
    fn task_definition_arn_format() {
        let s = EcsState::new("111122223333", "us-east-1");
        assert_eq!(
            s.task_definition_arn("web", 3),
            "arn:aws:ecs:us-east-1:111122223333:task-definition/web:3"
        );
    }

    #[test]
    fn reset_clears_all() {
        let mut s = EcsState::new("111122223333", "us-east-1");
        s.clusters.insert(
            "prod".to_string(),
            Cluster::new("prod", s.cluster_arn("prod")),
        );
        s.allocate_revision("web");
        s.account_setting_defaults
            .insert("serviceLongArnFormat".into(), "enabled".into());
        s.reset();
        assert!(s.clusters.is_empty());
        assert!(s.next_revision.is_empty());
        assert!(s.account_setting_defaults.is_empty());
    }
}
