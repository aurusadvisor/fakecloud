use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

pub type SharedGlueState = Arc<RwLock<GlueAccounts>>;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct GlueAccounts {
    pub accounts: BTreeMap<String, GlueState>,
}

impl GlueAccounts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_or_create(&mut self, account_id: &str, region: &str) -> &mut GlueState {
        self.accounts
            .entry(account_id.to_string())
            .or_insert_with(|| GlueState::new(account_id, region))
    }

    pub fn get(&self, account_id: &str) -> Option<&GlueState> {
        self.accounts.get(account_id)
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct GlueState {
    pub account_id: String,
    pub region: String,
    /// region -> database_name -> Database
    pub databases: BTreeMap<String, BTreeMap<String, Database>>,
}

impl GlueState {
    pub fn new(account_id: &str, region: &str) -> Self {
        Self {
            account_id: account_id.to_string(),
            region: region.to_string(),
            databases: BTreeMap::new(),
        }
    }

    pub fn dbs_in(&self, region: &str) -> Option<&BTreeMap<String, Database>> {
        self.databases.get(region)
    }

    pub fn dbs_in_mut(&mut self, region: &str) -> &mut BTreeMap<String, Database> {
        self.databases.entry(region.to_string()).or_default()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Database {
    pub name: String,
    pub description: Option<String>,
    pub location_uri: Option<String>,
    pub parameters: BTreeMap<String, String>,
    pub created_at: DateTime<Utc>,
    pub catalog_id: String,
    /// Tables keyed by name.
    pub tables: BTreeMap<String, Table>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Table {
    pub name: String,
    pub database_name: String,
    pub description: Option<String>,
    pub owner: Option<String>,
    pub create_time: DateTime<Utc>,
    pub update_time: DateTime<Utc>,
    pub last_access_time: Option<DateTime<Utc>>,
    pub retention: i64,
    pub storage_descriptor: Option<StorageDescriptor>,
    pub partition_keys: Vec<Column>,
    pub view_original_text: Option<String>,
    pub view_expanded_text: Option<String>,
    pub table_type: Option<String>,
    pub parameters: BTreeMap<String, String>,
    /// Partitions keyed by joined partition values ("v1/v2").
    pub partitions: BTreeMap<String, Partition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Partition {
    pub values: Vec<String>,
    pub database_name: String,
    pub table_name: String,
    pub create_time: DateTime<Utc>,
    pub last_access_time: Option<DateTime<Utc>>,
    pub storage_descriptor: Option<StorageDescriptor>,
    pub parameters: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct StorageDescriptor {
    pub columns: Vec<Column>,
    pub location: Option<String>,
    pub input_format: Option<String>,
    pub output_format: Option<String>,
    pub compressed: Option<bool>,
    pub serde_info: Option<SerdeInfo>,
    pub parameters: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Column {
    pub name: String,
    pub column_type: String,
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerdeInfo {
    pub name: Option<String>,
    pub serialization_library: Option<String>,
    pub parameters: BTreeMap<String, String>,
}
