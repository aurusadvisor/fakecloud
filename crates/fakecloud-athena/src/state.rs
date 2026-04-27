//! In-memory state for Athena.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use serde_json::Value;

pub type SharedAthenaState = Arc<RwLock<AthenaAccounts>>;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AthenaAccounts {
    pub accounts: HashMap<String, AccountState>,
}

impl AthenaAccounts {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AccountState {
    pub work_groups: HashMap<String, WorkGroup>,
    pub data_catalogs: HashMap<String, DataCatalog>,
    pub named_queries: HashMap<String, NamedQuery>,
    pub prepared_statements: HashMap<(String, String), PreparedStatement>,
    pub query_executions: HashMap<String, QueryExecution>,
    pub notebooks: HashMap<String, Notebook>,
    pub sessions: HashMap<String, Session>,
    pub calculations: HashMap<String, Calculation>,
    pub capacity_reservations: HashMap<String, CapacityReservation>,
    pub capacity_assignment_config: Option<CapacityAssignmentConfiguration>,
    pub tags: HashMap<String, HashMap<String, String>>,
    pub initialized: bool,
}

impl AccountState {
    /// Seed the default `primary` workgroup the first time the account is touched
    /// — Athena always exposes a primary workgroup that callers expect to exist.
    pub fn ensure_initialized(&mut self) {
        if self.initialized {
            return;
        }
        self.initialized = true;
        let primary = WorkGroup {
            name: "primary".to_string(),
            state: "ENABLED".to_string(),
            description: Some("default primary workgroup".to_string()),
            configuration: Some(default_workgroup_configuration()),
            creation_time: Utc::now(),
            engine_version: Some("AUTO".to_string()),
        };
        self.work_groups.insert("primary".to_string(), primary);

        let default_catalog = DataCatalog {
            name: "AwsDataCatalog".to_string(),
            description: Some("Default AWS data catalog".to_string()),
            cat_type: "GLUE".to_string(),
            parameters: HashMap::new(),
            status: "CREATE_COMPLETE".to_string(),
            connection_type: None,
            error: None,
        };
        self.data_catalogs
            .insert("AwsDataCatalog".to_string(), default_catalog);
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WorkGroup {
    pub name: String,
    pub state: String,
    pub description: Option<String>,
    pub configuration: Option<Value>,
    pub creation_time: DateTime<Utc>,
    pub engine_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataCatalog {
    pub name: String,
    pub description: Option<String>,
    pub cat_type: String,
    pub parameters: HashMap<String, String>,
    pub status: String,
    pub connection_type: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NamedQuery {
    pub named_query_id: String,
    pub name: String,
    pub description: Option<String>,
    pub database: String,
    pub query_string: String,
    pub work_group: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PreparedStatement {
    pub statement_name: String,
    pub work_group_name: String,
    pub query_statement: String,
    pub description: Option<String>,
    pub last_modified_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct QueryExecution {
    pub query_execution_id: String,
    pub query: String,
    pub statement_type: String,
    pub work_group: String,
    pub state: String,
    pub state_change_reason: Option<String>,
    pub submission_time: DateTime<Utc>,
    pub completion_time: Option<DateTime<Utc>>,
    pub query_execution_context: Option<Value>,
    pub result_configuration: Option<Value>,
    pub engine_version: Option<Value>,
    pub data_scanned_bytes: i64,
    pub engine_execution_time_ms: i64,
    pub query_planning_time_ms: i64,
    pub total_execution_time_ms: i64,
    pub result_rows: Vec<Vec<String>>,
    pub result_columns: Vec<(String, String)>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notebook {
    pub notebook_id: String,
    pub name: String,
    pub work_group: String,
    pub creation_time: DateTime<Utc>,
    pub last_modified_time: DateTime<Utc>,
    pub payload: String,
    pub notebook_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub work_group: String,
    pub description: Option<String>,
    pub engine_version: Option<String>,
    pub state: String,
    pub start_date_time: DateTime<Utc>,
    pub end_date_time: Option<DateTime<Utc>>,
    pub idle_since_date_time: Option<DateTime<Utc>>,
    pub configuration: Option<Value>,
    pub notebook_version: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Calculation {
    pub calculation_execution_id: String,
    pub session_id: String,
    pub description: Option<String>,
    pub state: String,
    pub state_change_reason: Option<String>,
    pub working_directory: Option<String>,
    pub code_block: Option<String>,
    pub submission_date_time: DateTime<Utc>,
    pub completion_date_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityReservation {
    pub name: String,
    pub status: String,
    pub target_dpus: i32,
    pub allocated_dpus: i32,
    pub creation_time: DateTime<Utc>,
    pub last_allocation: Option<DateTime<Utc>>,
    pub last_successful_allocation_time: Option<DateTime<Utc>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CapacityAssignmentConfiguration {
    pub capacity_reservation_name: String,
    pub capacity_assignments: Vec<Value>,
}

fn default_workgroup_configuration() -> Value {
    serde_json::json!({
        "ResultConfiguration": {},
        "EnforceWorkGroupConfiguration": false,
        "PublishCloudWatchMetricsEnabled": false,
        "RequesterPaysEnabled": false,
        "EngineVersion": {"SelectedEngineVersion": "AUTO", "EffectiveEngineVersion": "Athena engine version 3"},
    })
}
