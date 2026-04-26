//! In-memory state for Route 53 resources.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

use crate::model::{HealthCheckConfig, HostedZoneFeatures, ResourceRecordSet, VPC};

pub type SharedRoute53State = Arc<RwLock<Route53Accounts>>;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct Route53Accounts {
    pub accounts: HashMap<String, AccountState>,
}

impl Route53Accounts {
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
    pub hosted_zones: HashMap<String, StoredHostedZone>,
    pub changes: HashMap<String, StoredChange>,
    pub health_checks: HashMap<String, StoredHealthCheck>,
    /// Keyed by `(traffic_policy_id, version)`. Each `CreateTrafficPolicyVersion`
    /// inserts a new entry alongside the existing versions.
    pub traffic_policies: HashMap<(String, i64), StoredTrafficPolicy>,
    pub traffic_policy_instances: HashMap<String, StoredTrafficPolicyInstance>,
    /// Per-zone DNSSEC `ServeSignature` status (SIGNING / NOT_SIGNING). Absent
    /// entries are treated as NOT_SIGNING.
    pub dnssec_status: HashMap<String, String>,
    /// Keyed by `(hosted_zone_id, ksk_name)`.
    pub key_signing_keys: HashMap<(String, String), StoredKeySigningKey>,
    pub query_logging_configs: HashMap<String, StoredQueryLoggingConfig>,
    pub cidr_collections: HashMap<String, StoredCidrCollection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredHostedZone {
    pub id: String,
    pub name: String,
    pub caller_reference: String,
    pub comment: Option<String>,
    pub private_zone: bool,
    pub features: Option<HostedZoneFeatures>,
    pub vpcs: Vec<VPC>,
    pub delegation_set_id: Option<String>,
    pub name_servers: Vec<String>,
    pub created_time: DateTime<Utc>,
    pub resource_record_sets: Vec<ResourceRecordSet>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredChange {
    pub id: String,
    pub status: String,
    pub submitted_at: DateTime<Utc>,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredHealthCheck {
    pub id: String,
    pub caller_reference: String,
    pub version: i64,
    pub config: HealthCheckConfig,
    pub created_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTrafficPolicy {
    pub id: String,
    pub version: i64,
    pub name: String,
    pub policy_type: String,
    pub document: String,
    pub comment: Option<String>,
    pub created_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTrafficPolicyInstance {
    pub id: String,
    pub hosted_zone_id: String,
    pub name: String,
    pub ttl: i64,
    pub state: String,
    pub message: String,
    pub traffic_policy_id: String,
    pub traffic_policy_version: i64,
    pub traffic_policy_type: String,
    pub created_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredKeySigningKey {
    pub hosted_zone_id: String,
    pub name: String,
    pub kms_arn: String,
    pub status: String,
    pub caller_reference: String,
    pub created_date: DateTime<Utc>,
    pub last_modified_date: DateTime<Utc>,
    pub key_tag: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredQueryLoggingConfig {
    pub id: String,
    pub hosted_zone_id: String,
    pub cloud_watch_logs_log_group_arn: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCidrCollection {
    pub id: String,
    pub name: String,
    pub arn: String,
    pub version: i64,
    pub caller_reference: String,
    /// Maps location name -> sorted list of CIDR blocks.
    pub locations: HashMap<String, Vec<String>>,
}
