use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

pub type SharedBedrockAgentRuntimeState = Arc<RwLock<BedrockAgentRuntimeAccounts>>;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BedrockAgentRuntimeAccounts {
    pub accounts: BTreeMap<String, BedrockAgentRuntimeState>,
}

impl BedrockAgentRuntimeAccounts {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn get_or_create(&mut self, account_id: &str) -> &mut BedrockAgentRuntimeState {
        self.accounts
            .entry(account_id.to_string())
            .or_insert_with(|| BedrockAgentRuntimeState::new(account_id))
    }

    pub fn reset(&mut self) {
        self.accounts.clear();
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct BedrockAgentRuntimeState {
    pub account_id: String,
    pub invocations: Vec<InvocationRecord>,
    pub sessions: BTreeMap<String, Session>,
    pub flow_executions: BTreeMap<String, FlowExecution>,
}

impl BedrockAgentRuntimeState {
    pub fn new(account_id: &str) -> Self {
        Self {
            account_id: account_id.to_string(),
            invocations: Vec::new(),
            sessions: BTreeMap::new(),
            flow_executions: BTreeMap::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InvocationRecord {
    pub invocation_id: String,
    pub agent_id: Option<String>,
    pub flow_id: Option<String>,
    pub input: String,
    pub output: String,
    pub timestamp: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FlowExecution {
    pub execution_id: String,
    pub flow_id: String,
    pub status: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}
