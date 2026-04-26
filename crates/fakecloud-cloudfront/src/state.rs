//! In-memory state for CloudFront resources.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::extras::{StoredAnycastIpList, StoredResourcePolicy, StoredTrustStore, StoredVpcOrigin};
use crate::fle::{
    StoredFieldLevelEncryption, StoredFieldLevelEncryptionProfile, StoredRealtimeLogConfig,
};
use crate::functions::{
    StoredFunction, StoredKeyGroup, StoredKeyValueStore, StoredMonitoringSubscription,
    StoredOriginAccessIdentity, StoredPublicKey,
};
use crate::model::{DistributionConfig, InvalidationBatch};
use crate::policies::{
    StoredCachePolicy, StoredContinuousDeploymentPolicy, StoredOriginAccessControl,
    StoredOriginRequestPolicy, StoredResponseHeadersPolicy,
};
use crate::streaming::StoredStreamingDistribution;

pub type SharedCloudFrontState = Arc<RwLock<CloudFrontAccounts>>;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct CloudFrontAccounts {
    pub accounts: HashMap<String, AccountState>,
}

impl CloudFrontAccounts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    pub fn entry(&mut self, account_id: &str) -> &mut AccountState {
        self.accounts.entry(account_id.to_string()).or_default()
    }

    pub fn get(&self, account_id: &str) -> Option<&AccountState> {
        self.accounts.get(account_id)
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AccountState {
    pub distributions: HashMap<String, StoredDistribution>,
    pub invalidations: HashMap<String, StoredInvalidation>,
    /// Tags keyed by ARN.
    pub tags: HashMap<String, Vec<Tag>>,
    pub origin_access_controls: HashMap<String, StoredOriginAccessControl>,
    pub cache_policies: HashMap<String, StoredCachePolicy>,
    pub origin_request_policies: HashMap<String, StoredOriginRequestPolicy>,
    pub response_headers_policies: HashMap<String, StoredResponseHeadersPolicy>,
    pub continuous_deployment_policies: HashMap<String, StoredContinuousDeploymentPolicy>,
    pub functions: HashMap<String, StoredFunction>,
    pub public_keys: HashMap<String, StoredPublicKey>,
    pub key_groups: HashMap<String, StoredKeyGroup>,
    pub key_value_stores: HashMap<String, StoredKeyValueStore>,
    pub origin_access_identities: HashMap<String, StoredOriginAccessIdentity>,
    /// Per-distribution monitoring subscription, keyed by distribution id.
    pub monitoring_subscriptions: HashMap<String, StoredMonitoringSubscription>,
    pub streaming_distributions: HashMap<String, StoredStreamingDistribution>,
    pub field_level_encryptions: HashMap<String, StoredFieldLevelEncryption>,
    pub field_level_encryption_profiles: HashMap<String, StoredFieldLevelEncryptionProfile>,
    /// Realtime log configs keyed by ARN.
    pub realtime_log_configs: HashMap<String, StoredRealtimeLogConfig>,
    pub vpc_origins: HashMap<String, StoredVpcOrigin>,
    pub anycast_ip_lists: HashMap<String, StoredAnycastIpList>,
    pub trust_stores: HashMap<String, StoredTrustStore>,
    /// Resource policies keyed by resource ARN.
    pub resource_policies: HashMap<String, StoredResourcePolicy>,
}

impl CloudFrontAccounts {
    /// Pre-seed the AWS-managed Cache, Origin Request, and Response
    /// Headers policies into the default account so callers that look
    /// them up by their well-known IDs (Terraform, CDK) get the same
    /// shape they get against AWS. The IDs and names mirror the AWS
    /// console output verbatim — the easiest way to keep tests source
    /// of truth.
    pub fn seed_managed_policies(&mut self, account_id: &str) {
        let account = self.entry(account_id);
        crate::policies::seed_managed(account);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredDistribution {
    pub id: String,
    pub arn: String,
    pub status: String,
    pub last_modified_time: DateTime<Utc>,
    pub domain_name: String,
    pub in_progress_invalidation_batches: u32,
    pub etag: String,
    pub config: DistributionConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredInvalidation {
    pub id: String,
    pub distribution_id: String,
    pub status: String,
    pub create_time: DateTime<Utc>,
    pub batch: InvalidationBatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Tag {
    pub key: String,
    pub value: Option<String>,
}
