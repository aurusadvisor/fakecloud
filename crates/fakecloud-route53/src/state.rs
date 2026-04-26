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
