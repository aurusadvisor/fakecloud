use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

pub type SharedEcrState = Arc<RwLock<fakecloud_core::multi_account::MultiAccountState<EcrState>>>;

impl fakecloud_core::multi_account::AccountState for EcrState {
    fn new_for_account(account_id: &str, region: &str, _endpoint: &str) -> Self {
        Self::new(account_id, region)
    }
}

pub const ECR_SNAPSHOT_SCHEMA_VERSION: u32 = 1;

/// Top-level persisted ECR snapshot. The shape mirrors the convention
/// used by other multi-account services (Kinesis, ElastiCache) so the
/// `main.rs` loader can use the same branching pattern.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcrSnapshot {
    pub schema_version: u32,
    pub accounts: Option<fakecloud_core::multi_account::MultiAccountState<EcrState>>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct EcrState {
    pub account_id: String,
    pub region: String,
    /// Repository name -> repository.
    pub repositories: BTreeMap<String, Repository>,
    /// Registry-level policy JSON document. `None` until the caller
    /// sets one via `PutRegistryPolicy`.
    pub registry_policy: Option<String>,
    /// Registry-level scanning configuration. Defaults to `BASIC` per
    /// AWS behaviour; tracked here so `Get/PutRegistryScanningConfiguration`
    /// round-trips correctly.
    pub registry_scanning_configuration: RegistryScanningConfiguration,
    /// Registry-level replication configuration.
    pub replication_configuration: Option<ReplicationConfiguration>,
    /// Account setting flags keyed by setting name (e.g.,
    /// `BASIC_SCAN_TYPE_VERSION`, `REGISTRY_POLICY_SCOPE`).
    pub account_settings: HashMap<String, String>,
}

impl EcrState {
    pub fn new(account_id: &str, region: &str) -> Self {
        Self {
            account_id: account_id.to_string(),
            region: region.to_string(),
            repositories: BTreeMap::new(),
            registry_policy: None,
            registry_scanning_configuration: RegistryScanningConfiguration::default(),
            replication_configuration: None,
            account_settings: HashMap::new(),
        }
    }

    pub fn reset(&mut self) {
        self.repositories.clear();
        self.registry_policy = None;
        self.registry_scanning_configuration = RegistryScanningConfiguration::default();
        self.replication_configuration = None;
        self.account_settings.clear();
    }

    pub fn repository_arn(&self, repository_name: &str) -> String {
        format!(
            "arn:aws:ecr:{}:{}:repository/{}",
            self.region, self.account_id, repository_name
        )
    }

    pub fn registry_id(&self) -> &str {
        &self.account_id
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Repository {
    pub repository_name: String,
    pub repository_arn: String,
    pub registry_id: String,
    pub repository_uri: String,
    pub created_at: DateTime<Utc>,
    pub image_tag_mutability: String,
    pub image_scanning_configuration: ImageScanningConfiguration,
    pub encryption_configuration: EncryptionConfiguration,
    pub tags: BTreeMap<String, String>,
    /// Repository-level policy document JSON. `None` until the caller
    /// sets one via `SetRepositoryPolicy`.
    pub policy: Option<String>,
    /// Repository-level lifecycle policy document JSON.
    pub lifecycle_policy: Option<String>,
}

impl Repository {
    pub fn new(
        repository_name: &str,
        repository_arn: String,
        registry_id: &str,
        endpoint: &str,
    ) -> Self {
        // Strip scheme from endpoint for repositoryUri (docker requires host only).
        let host = endpoint
            .trim_start_matches("http://")
            .trim_start_matches("https://")
            .trim_end_matches('/')
            .to_string();
        Self {
            repository_name: repository_name.to_string(),
            repository_arn,
            registry_id: registry_id.to_string(),
            repository_uri: format!("{host}/{repository_name}"),
            created_at: Utc::now(),
            image_tag_mutability: "MUTABLE".to_string(),
            image_scanning_configuration: ImageScanningConfiguration::default(),
            encryption_configuration: EncryptionConfiguration::default(),
            tags: BTreeMap::new(),
            policy: None,
            lifecycle_policy: None,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct ImageScanningConfiguration {
    /// Whether images are scanned automatically on push. Defaults to `false`.
    pub scan_on_push: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EncryptionConfiguration {
    /// `AES256` or `KMS`.
    pub encryption_type: String,
    /// KMS key ARN when `encryption_type == "KMS"`.
    pub kms_key: Option<String>,
}

impl Default for EncryptionConfiguration {
    fn default() -> Self {
        Self {
            encryption_type: "AES256".to_string(),
            kms_key: None,
        }
    }
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct RegistryScanningConfiguration {
    /// `BASIC` or `ENHANCED`.
    pub scan_type: String,
    pub rules: Vec<RegistryScanningRule>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryScanningRule {
    pub scan_frequency: String,
    pub repository_filters: Vec<RepositoryFilter>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepositoryFilter {
    pub filter: String,
    pub filter_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplicationConfiguration {
    pub rules: Vec<ReplicationRule>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplicationRule {
    pub destinations: Vec<ReplicationDestination>,
    pub repository_filters: Vec<RepositoryFilter>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReplicationDestination {
    pub region: String,
    pub registry_id: String,
}
