use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LambdaFunction {
    pub function_name: String,
    pub function_arn: String,
    pub runtime: String,
    pub role: String,
    pub handler: String,
    pub description: String,
    pub timeout: i64,
    pub memory_size: i64,
    pub code_sha256: String,
    pub code_size: i64,
    pub version: String,
    pub last_modified: DateTime<Utc>,
    pub tags: HashMap<String, String>,
    pub environment: HashMap<String, String>,
    pub architectures: Vec<String>,
    pub package_type: String,
    pub code_zip: Option<Vec<u8>>,
    /// Container image URI for `PackageType=Image` functions. Points at a
    /// private or public ECR image that the runtime pulls at invoke time.
    /// `None` for `PackageType=Zip`.
    #[serde(default)]
    pub image_uri: Option<String>,
    /// Resource-based policy attached to this function via
    /// `AddPermission`, serialized as a full JSON policy document
    /// (`{"Version":"2012-10-17","Statement":[...]}`). `None` means
    /// the function has no resource policy attached, matching the
    /// `ResourceNotFoundException` AWS returns from `GetPolicy` in
    /// that state. `AddPermission` lazily initializes this; every
    /// `RemovePermission` leaves at least `{"Statement":[]}` behind,
    /// matching AWS behavior.
    pub policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventSourceMapping {
    pub uuid: String,
    pub function_arn: String,
    pub event_source_arn: String,
    pub batch_size: i64,
    pub enabled: bool,
    pub state: String,
    pub last_modified: DateTime<Utc>,
}

/// A recorded Lambda invocation from cross-service delivery.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LambdaInvocation {
    pub function_arn: String,
    pub payload: String,
    pub timestamp: DateTime<Utc>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LambdaState {
    pub account_id: String,
    pub region: String,
    #[serde(default)]
    pub functions: HashMap<String, LambdaFunction>,
    #[serde(default)]
    pub event_source_mappings: HashMap<String, EventSourceMapping>,
    /// Recorded invocations from cross-service integrations — not persisted.
    #[serde(default, skip)]
    pub invocations: Vec<LambdaInvocation>,
    /// Per-function aliases keyed by `{function}:{alias}`.
    #[serde(default)]
    pub aliases: HashMap<String, FunctionAlias>,
    /// Published versions per function (function_name -> Vec<version>).
    #[serde(default)]
    pub function_versions: HashMap<String, Vec<String>>,
    /// Layers keyed by name.
    #[serde(default)]
    pub layers: HashMap<String, Layer>,
    /// Function URL configs keyed by function name.
    #[serde(default)]
    pub function_url_configs: HashMap<String, FunctionUrlConfig>,
    /// Reserved concurrency configs keyed by function name.
    #[serde(default)]
    pub function_concurrency: HashMap<String, i64>,
    /// Provisioned concurrency configs keyed by `{function}:{qualifier}`.
    #[serde(default)]
    pub provisioned_concurrency: HashMap<String, ProvisionedConcurrencyConfig>,
    /// Code signing configs keyed by id.
    #[serde(default)]
    pub code_signing_configs: HashMap<String, CodeSigningConfig>,
    /// Function-to-code-signing-config association keyed by function name.
    #[serde(default)]
    pub function_code_signing: HashMap<String, String>,
    /// Event invoke configs keyed by `{function}:{qualifier}`.
    #[serde(default)]
    pub event_invoke_configs: HashMap<String, EventInvokeConfig>,
    /// Runtime management configs keyed by `{function}:{qualifier}`.
    #[serde(default)]
    pub runtime_management: HashMap<String, RuntimeManagementConfig>,
    /// Scaling configs keyed by event source mapping uuid.
    #[serde(default)]
    pub scaling_configs: HashMap<String, FunctionScalingConfig>,
    /// Recursion configs keyed by function name.
    #[serde(default)]
    pub recursion_configs: HashMap<String, String>,
    /// Tags keyed by resource ARN.
    #[serde(default)]
    pub tags: HashMap<String, Vec<(String, String)>>,
    /// Capacity providers keyed by name.
    #[serde(default)]
    pub capacity_providers: HashMap<String, CapacityProvider>,
    /// Durable executions keyed by id.
    #[serde(default)]
    pub durable_executions: HashMap<String, DurableExecution>,
    /// Account settings (single per-account record).
    #[serde(default)]
    pub account_settings: Option<AccountSettings>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionAlias {
    pub alias_arn: String,
    pub name: String,
    pub function_version: String,
    pub description: String,
    pub revision_id: String,
    pub routing_config: Option<serde_json::Value>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Layer {
    pub layer_name: String,
    pub layer_arn: String,
    pub versions: Vec<LayerVersion>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LayerVersion {
    pub version: i64,
    pub layer_version_arn: String,
    pub description: String,
    pub created_date: DateTime<Utc>,
    pub compatible_runtimes: Vec<String>,
    pub license_info: String,
    pub policy: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionUrlConfig {
    pub function_arn: String,
    pub function_url: String,
    pub auth_type: String,
    pub cors: Option<serde_json::Value>,
    pub creation_time: DateTime<Utc>,
    pub last_modified_time: DateTime<Utc>,
    pub invoke_mode: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProvisionedConcurrencyConfig {
    pub requested: i64,
    pub allocated: i64,
    pub status: String,
    pub last_modified: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CodeSigningConfig {
    pub csc_id: String,
    pub csc_arn: String,
    pub description: String,
    pub allowed_publishers: Vec<String>,
    pub untrusted_artifact_action: String,
    pub last_modified: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventInvokeConfig {
    pub function_arn: String,
    pub maximum_event_age: i64,
    pub maximum_retry_attempts: i64,
    pub destination_config: serde_json::Value,
    pub last_modified: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RuntimeManagementConfig {
    pub update_runtime_on: String,
    pub runtime_version_arn: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionScalingConfig {
    pub maximum_concurrency: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityProvider {
    pub name: String,
    pub arn: String,
    pub status: String,
    pub created: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DurableExecution {
    pub id: String,
    pub function_arn: String,
    pub status: String,
    pub started: DateTime<Utc>,
    pub stopped: Option<DateTime<Utc>>,
    pub history: Vec<serde_json::Value>,
    pub state: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct AccountSettings {
    pub concurrent_executions: i64,
    pub code_size_zipped: i64,
    pub code_size_unzipped: i64,
    pub total_code_size: i64,
}

impl LambdaState {
    pub fn new(account_id: &str, region: &str) -> Self {
        Self {
            account_id: account_id.to_string(),
            region: region.to_string(),
            functions: HashMap::new(),
            event_source_mappings: HashMap::new(),
            invocations: Vec::new(),
            aliases: HashMap::new(),
            function_versions: HashMap::new(),
            layers: HashMap::new(),
            function_url_configs: HashMap::new(),
            function_concurrency: HashMap::new(),
            provisioned_concurrency: HashMap::new(),
            code_signing_configs: HashMap::new(),
            function_code_signing: HashMap::new(),
            event_invoke_configs: HashMap::new(),
            runtime_management: HashMap::new(),
            scaling_configs: HashMap::new(),
            recursion_configs: HashMap::new(),
            tags: HashMap::new(),
            capacity_providers: HashMap::new(),
            durable_executions: HashMap::new(),
            account_settings: None,
        }
    }

    pub fn reset(&mut self) {
        self.functions.clear();
        self.event_source_mappings.clear();
        self.invocations.clear();
        self.aliases.clear();
        self.function_versions.clear();
        self.layers.clear();
        self.function_url_configs.clear();
        self.function_concurrency.clear();
        self.provisioned_concurrency.clear();
        self.code_signing_configs.clear();
        self.function_code_signing.clear();
        self.event_invoke_configs.clear();
        self.runtime_management.clear();
        self.scaling_configs.clear();
        self.recursion_configs.clear();
        self.tags.clear();
        self.capacity_providers.clear();
        self.durable_executions.clear();
        self.account_settings = None;
    }
}

pub type SharedLambdaState =
    Arc<RwLock<fakecloud_core::multi_account::MultiAccountState<LambdaState>>>;

impl fakecloud_core::multi_account::AccountState for LambdaState {
    fn new_for_account(account_id: &str, region: &str, _endpoint: &str) -> Self {
        Self::new(account_id, region)
    }
}

pub const LAMBDA_SNAPSHOT_SCHEMA_VERSION: u32 = 2;

#[derive(Debug, Serialize, Deserialize)]
pub struct LambdaSnapshot {
    pub schema_version: u32,
    #[serde(default)]
    pub accounts: Option<fakecloud_core::multi_account::MultiAccountState<LambdaState>>,
    #[serde(default)]
    pub state: Option<LambdaState>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_has_empty_collections() {
        let state = LambdaState::new("123456789012", "us-east-1");
        assert_eq!(state.account_id, "123456789012");
        assert_eq!(state.region, "us-east-1");
        assert!(state.functions.is_empty());
        assert!(state.event_source_mappings.is_empty());
        assert!(state.invocations.is_empty());
    }

    #[test]
    fn reset_clears_collections() {
        let mut state = LambdaState::new("123456789012", "us-east-1");
        state.invocations.push(LambdaInvocation {
            function_arn: "arn".to_string(),
            payload: "p".to_string(),
            timestamp: Utc::now(),
            source: "s".to_string(),
        });
        state.reset();
        assert!(state.invocations.is_empty());
    }
}
