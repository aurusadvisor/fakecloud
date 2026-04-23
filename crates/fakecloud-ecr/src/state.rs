use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub type SharedEcrState = Arc<RwLock<fakecloud_core::multi_account::MultiAccountState<EcrState>>>;

impl fakecloud_core::multi_account::AccountState for EcrState {
    fn new_for_account(account_id: &str, region: &str, _endpoint: &str) -> Self {
        Self::new(account_id, region)
    }
}

pub const ECR_SNAPSHOT_SCHEMA_VERSION: u32 = 3;

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
    /// Layer upload state machine keyed by `uploadId`. Each entry is
    /// tied to a specific repository.
    #[serde(default)]
    pub layer_uploads: BTreeMap<String, LayerUpload>,
    /// Pull-time update exclusions keyed by IAM principal ARN. These
    /// are registry-level per the Smithy model.
    #[serde(default)]
    pub pull_time_exclusions: BTreeMap<String, PullTimeExclusion>,
    /// Pull-through cache rules keyed by `ecrRepositoryPrefix`.
    #[serde(default)]
    pub pull_through_cache_rules: BTreeMap<String, PullThroughCacheRule>,
    /// Repository creation templates keyed by prefix.
    #[serde(default)]
    pub repository_creation_templates: BTreeMap<String, RepositoryCreationTemplate>,
    /// Registry-wide signing configuration.
    #[serde(default)]
    pub signing_configuration: Option<SigningConfiguration>,
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
            layer_uploads: BTreeMap::new(),
            pull_time_exclusions: BTreeMap::new(),
            pull_through_cache_rules: BTreeMap::new(),
            repository_creation_templates: BTreeMap::new(),
            signing_configuration: None,
        }
    }

    pub fn reset(&mut self) {
        self.repositories.clear();
        self.registry_policy = None;
        self.registry_scanning_configuration = RegistryScanningConfiguration::default();
        self.replication_configuration = None;
        self.account_settings.clear();
        self.layer_uploads.clear();
        self.pull_time_exclusions.clear();
        self.pull_through_cache_rules.clear();
        self.repository_creation_templates.clear();
        self.signing_configuration = None;
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
    /// Per-image scan findings, keyed by manifest digest.
    #[serde(default)]
    pub scan_findings: BTreeMap<String, ImageScanFindings>,
    /// Stored images keyed by manifest digest (sha256). One image can
    /// have many tags (via `image_tags`).
    #[serde(default)]
    pub images: BTreeMap<String, Image>,
    /// Tag name -> image digest. Multiple tags can point to the same
    /// digest.
    #[serde(default)]
    pub image_tags: BTreeMap<String, String>,
    /// Content-addressed layer blobs keyed by their sha256 digest
    /// (e.g. `sha256:deadbeef…`). Stored as base64 to keep JSON
    /// snapshots portable.
    #[serde(default)]
    pub layers: BTreeMap<String, Layer>,
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
            scan_findings: BTreeMap::new(),
            images: BTreeMap::new(),
            image_tags: BTreeMap::new(),
            layers: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PullTimeExclusion {
    pub principal_arn: String,
    pub registered_at: DateTime<Utc>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ImageScanFindings {
    pub image_digest: String,
    pub scan_status: String,
    pub scan_completed_at: Option<DateTime<Utc>>,
    pub vulnerability_source_updated_at: Option<DateTime<Utc>>,
    pub finding_severity_counts: BTreeMap<String, i64>,
    pub findings: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PullThroughCacheRule {
    pub ecr_repository_prefix: String,
    pub upstream_registry_url: String,
    pub upstream_registry: Option<String>,
    pub credential_arn: Option<String>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub custom_role_arn: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RepositoryCreationTemplate {
    pub prefix: String,
    pub description: Option<String>,
    pub image_tag_mutability: String,
    pub applied_for: Vec<String>,
    pub resource_tags: Vec<Value>,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub custom_role_arn: Option<String>,
    pub repository_policy: Option<String>,
    pub lifecycle_policy: Option<String>,
    pub encryption_configuration: Option<EncryptionConfiguration>,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct SigningConfiguration {
    pub rules: Vec<Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Image {
    pub image_digest: String,
    pub image_manifest: String,
    pub image_manifest_media_type: String,
    pub artifact_media_type: Option<String>,
    pub image_size_in_bytes: u64,
    pub image_pushed_at: DateTime<Utc>,
    pub last_recorded_pull_time: Option<DateTime<Utc>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Layer {
    pub digest: String,
    pub size: u64,
    /// Base64-encoded blob bytes. Kept in-process for Batch 2; Batch 3
    /// will move this to content-addressed disk storage for the OCI
    /// `/v2/` protocol.
    pub blob_b64: String,
    pub media_type: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LayerUpload {
    pub upload_id: String,
    pub repository_name: String,
    pub created_at: DateTime<Utc>,
    /// Accumulated blob bytes (base64). Each `UploadLayerPart` call
    /// appends to this and updates `last_byte_received`.
    pub blob_b64: String,
    pub last_byte_received: u64,
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RegistryScanningConfiguration {
    /// `BASIC` or `ENHANCED`.
    pub scan_type: String,
    pub rules: Vec<RegistryScanningRule>,
}

impl Default for RegistryScanningConfiguration {
    fn default() -> Self {
        Self {
            scan_type: "BASIC".to_string(),
            rules: Vec::new(),
        }
    }
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
