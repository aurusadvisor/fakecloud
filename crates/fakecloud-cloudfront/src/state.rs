//! In-memory state for CloudFront resources.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::model::{DistributionConfig, InvalidationBatch};

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
