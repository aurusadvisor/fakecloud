use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use http::StatusCode;
use serde_json::{json, Value};
use tokio::sync::Mutex as AsyncMutex;

use fakecloud_core::delivery::DeliveryBus;
use fakecloud_core::pagination::paginate;
use fakecloud_core::registry::ServiceRegistry;
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
use fakecloud_core::validation::*;
use fakecloud_dynamodb::SharedDynamoDbState;
use fakecloud_persistence::SnapshotStore;

use crate::interpreter;
use crate::state::{
    Execution, ExecutionStatus, SharedStepFunctionsState, StateMachine, StateMachineStatus,
    StateMachineType, StepFunctionsSnapshot, StepFunctionsState,
    STEPFUNCTIONS_SNAPSHOT_SCHEMA_VERSION,
};

const SUPPORTED: &[&str] = &[
    "CreateStateMachine",
    "DescribeStateMachine",
    "ListStateMachines",
    "DeleteStateMachine",
    "UpdateStateMachine",
    "TagResource",
    "UntagResource",
    "ListTagsForResource",
    "StartExecution",
    "StopExecution",
    "DescribeExecution",
    "ListExecutions",
    "GetExecutionHistory",
    "DescribeStateMachineForExecution",
    "CreateActivity",
    "DeleteActivity",
    "DescribeActivity",
    "ListActivities",
    "GetActivityTask",
    "SendTaskFailure",
    "SendTaskHeartbeat",
    "SendTaskSuccess",
    "PublishStateMachineVersion",
    "DeleteStateMachineVersion",
    "ListStateMachineVersions",
    "CreateStateMachineAlias",
    "DeleteStateMachineAlias",
    "DescribeStateMachineAlias",
    "ListStateMachineAliases",
    "UpdateStateMachineAlias",
    "DescribeMapRun",
    "ListMapRuns",
    "UpdateMapRun",
    "RedriveExecution",
    "StartSyncExecution",
    "TestState",
    "ValidateStateMachineDefinition",
];

/// Handle to the central service registry, set by `main.rs` after every service
/// has been registered. Wrapped in `OnceLock` so `StepFunctionsService` can be
/// constructed (and registered into the very registry it later reads back) before
/// the registry itself is finalized. The interpreter snapshots the inner `Arc`
/// when it needs to dispatch generic `aws-sdk:*` Task integrations.
pub type SharedServiceRegistry = Arc<std::sync::OnceLock<Arc<ServiceRegistry>>>;

pub struct StepFunctionsService {
    state: SharedStepFunctionsState,
    delivery: Option<Arc<DeliveryBus>>,
    dynamodb_state: Option<SharedDynamoDbState>,
    registry: Option<SharedServiceRegistry>,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    snapshot_lock: Arc<AsyncMutex<()>>,
}

impl StepFunctionsService {
    pub fn new(state: SharedStepFunctionsState) -> Self {
        Self {
            state,
            delivery: None,
            dynamodb_state: None,
            registry: None,
            snapshot_store: None,
            snapshot_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    pub fn with_delivery(mut self, delivery: Arc<DeliveryBus>) -> Self {
        self.delivery = Some(delivery);
        self
    }

    pub fn with_dynamodb(mut self, dynamodb_state: SharedDynamoDbState) -> Self {
        self.dynamodb_state = Some(dynamodb_state);
        self
    }

    /// Hand the service a deferred-fill handle to the central [`ServiceRegistry`].
    /// `main.rs` calls [`OnceLock::set`] on the inner cell after every service
    /// has been registered; until then the interpreter falls back to its
    /// hand-coded SDK integrations (lambda invoke, sqs sendMessage, …).
    pub fn with_registry(mut self, registry: SharedServiceRegistry) -> Self {
        self.registry = Some(registry);
        self
    }

    pub fn with_snapshot_store(mut self, store: Arc<dyn SnapshotStore>) -> Self {
        self.snapshot_store = Some(store);
        self
    }

    async fn save_snapshot(&self) {
        let Some(store) = self.snapshot_store.clone() else {
            return;
        };
        let _guard = self.snapshot_lock.lock().await;
        let snapshot = StepFunctionsSnapshot {
            schema_version: STEPFUNCTIONS_SNAPSHOT_SCHEMA_VERSION,
            state: None,
            accounts: Some(self.state.read().clone()),
        };
        let join = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let bytes = serde_json::to_vec(&snapshot)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            store.save(&bytes)
        })
        .await;
        match join {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(%err, "failed to write stepfunctions snapshot"),
            Err(err) => tracing::error!(%err, "stepfunctions snapshot task panicked"),
        }
    }
}

fn is_mutating_action(action: &str) -> bool {
    matches!(
        action,
        "CreateStateMachine"
            | "DeleteStateMachine"
            | "UpdateStateMachine"
            | "TagResource"
            | "UntagResource"
            | "StartExecution"
            | "StopExecution"
            | "CreateActivity"
            | "DeleteActivity"
            | "GetActivityTask"
            | "SendTaskFailure"
            | "SendTaskHeartbeat"
            | "SendTaskSuccess"
            | "PublishStateMachineVersion"
            | "DeleteStateMachineVersion"
            | "CreateStateMachineAlias"
            | "DeleteStateMachineAlias"
            | "UpdateStateMachineAlias"
            | "UpdateMapRun"
            | "RedriveExecution"
            | "StartSyncExecution"
    )
}

#[async_trait]
impl AwsService for StepFunctionsService {
    fn service_name(&self) -> &str {
        "states"
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mutates = is_mutating_action(req.action.as_str());
        let result = match req.action.as_str() {
            "CreateStateMachine" => self.create_state_machine(&req),
            "DescribeStateMachine" => self.describe_state_machine(&req),
            "ListStateMachines" => self.list_state_machines(&req),
            "DeleteStateMachine" => self.delete_state_machine(&req),
            "UpdateStateMachine" => self.update_state_machine(&req),
            "TagResource" => self.tag_resource(&req),
            "UntagResource" => self.untag_resource(&req),
            "ListTagsForResource" => self.list_tags_for_resource(&req),
            "StartExecution" => self.start_execution(&req),
            "StopExecution" => self.stop_execution(&req),
            "DescribeExecution" => self.describe_execution(&req),
            "ListExecutions" => self.list_executions(&req),
            "GetExecutionHistory" => self.get_execution_history(&req),
            "DescribeStateMachineForExecution" => self.describe_state_machine_for_execution(&req),
            "CreateActivity" => self.create_activity(&req),
            "DeleteActivity" => self.delete_activity(&req),
            "DescribeActivity" => self.describe_activity(&req),
            "ListActivities" => self.list_activities(&req),
            "GetActivityTask" => self.get_activity_task(&req).await,
            "SendTaskFailure" => self.send_task_failure(&req),
            "SendTaskHeartbeat" => self.send_task_heartbeat(&req),
            "SendTaskSuccess" => self.send_task_success(&req),
            "PublishStateMachineVersion" => self.publish_state_machine_version(&req),
            "DeleteStateMachineVersion" => self.delete_state_machine_version(&req),
            "ListStateMachineVersions" => self.list_state_machine_versions(&req),
            "CreateStateMachineAlias" => self.create_state_machine_alias(&req),
            "DeleteStateMachineAlias" => self.delete_state_machine_alias(&req),
            "DescribeStateMachineAlias" => self.describe_state_machine_alias(&req),
            "ListStateMachineAliases" => self.list_state_machine_aliases(&req),
            "UpdateStateMachineAlias" => self.update_state_machine_alias(&req),
            "DescribeMapRun" => self.describe_map_run(&req),
            "ListMapRuns" => self.list_map_runs(&req),
            "UpdateMapRun" => self.update_map_run(&req),
            "RedriveExecution" => self.redrive_execution(&req),
            "StartSyncExecution" => self.start_sync_execution(&req).await,
            "TestState" => self.test_state(&req),
            "ValidateStateMachineDefinition" => self.validate_state_machine_definition(&req),
            _ => Err(AwsServiceError::action_not_implemented(
                "states",
                &req.action,
            )),
        };
        if mutates && matches!(result.as_ref(), Ok(resp) if resp.status.is_success()) {
            self.save_snapshot().await;
        }
        result
    }

    fn supported_actions(&self) -> &[&str] {
        SUPPORTED
    }
}

impl StepFunctionsService {
    // ─── State Machine CRUD ─────────────────────────────────────────────

    fn create_state_machine(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();

        validate_required("name", &body["name"])?;
        let name = body["name"].as_str().ok_or_else(|| missing("name"))?;
        validate_name(name)?;

        validate_required("definition", &body["definition"])?;
        let definition = body["definition"]
            .as_str()
            .ok_or_else(|| missing("definition"))?;
        validate_definition(definition)?;

        validate_required("roleArn", &body["roleArn"])?;
        let role_arn = body["roleArn"].as_str().ok_or_else(|| missing("roleArn"))?;
        validate_arn(role_arn)?;

        let machine_type = if let Some(t) = body["type"].as_str() {
            StateMachineType::parse(t).ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    format!(
                        "Value '{t}' at 'type' failed to satisfy constraint: \
                         Member must satisfy enum value set: [STANDARD, EXPRESS]"
                    ),
                )
            })?
        } else {
            StateMachineType::Standard
        };

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let arn = state.state_machine_arn(name);

        // Check if name already exists
        if state.state_machines.values().any(|sm| sm.name == name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::CONFLICT,
                "StateMachineAlreadyExists",
                format!("State Machine Already Exists: '{arn}'"),
            ));
        }

        let now = Utc::now();
        let revision_id = uuid::Uuid::new_v4().to_string();

        let mut tags = BTreeMap::new();
        if !body["tags"].is_null() {
            fakecloud_core::tags::apply_tags(&mut tags, &body, "tags", "key", "value").map_err(
                |f| {
                    AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "ValidationException",
                        format!("{f} must be a list"),
                    )
                },
            )?;
        }

        let sm = StateMachine {
            name: name.to_string(),
            arn: arn.clone(),
            definition: definition.to_string(),
            role_arn: role_arn.to_string(),
            machine_type,
            status: StateMachineStatus::Active,
            creation_date: now,
            update_date: now,
            tags,
            revision_id: revision_id.clone(),
            logging_configuration: body.get("loggingConfiguration").cloned(),
            tracing_configuration: body.get("tracingConfiguration").cloned(),
            description: body["description"].as_str().unwrap_or("").to_string(),
        };

        state.state_machines.insert(arn.clone(), sm);

        Ok(AwsResponse::ok_json(json!({
            "stateMachineArn": arn,
            "creationDate": now.timestamp() as f64,
            "stateMachineVersionArn": arn,
        })))
    }

    fn describe_state_machine(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("stateMachineArn", &body["stateMachineArn"])?;
        let arn = body["stateMachineArn"]
            .as_str()
            .ok_or_else(|| missing("stateMachineArn"))?;
        validate_arn(arn)?;

        let accounts = self.state.read();
        let empty = StepFunctionsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let sm = state
            .state_machines
            .get(arn)
            .ok_or_else(|| state_machine_not_found(arn))?;

        Ok(AwsResponse::ok_json(state_machine_to_json(sm)))
    }

    fn list_state_machines(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let max_results = body["maxResults"].as_i64().unwrap_or(100) as usize;
        validate_range_i64("maxResults", max_results as i64, 1, 1000)?;
        let next_token = body["nextToken"].as_str();

        let accounts = self.state.read();
        let empty = StepFunctionsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let mut machines: Vec<&StateMachine> = state.state_machines.values().collect();
        machines.sort_by(|a, b| a.name.cmp(&b.name));

        let items: Vec<Value> = machines
            .iter()
            .map(|sm| {
                json!({
                    "name": sm.name,
                    "stateMachineArn": sm.arn,
                    "type": sm.machine_type.as_str(),
                    "creationDate": sm.creation_date.timestamp() as f64,
                })
            })
            .collect();

        let (page, token) = paginate(&items, next_token, max_results);

        let mut resp = json!({ "stateMachines": page });
        if let Some(t) = token {
            resp["nextToken"] = json!(t);
        }
        Ok(AwsResponse::ok_json(resp))
    }

    fn delete_state_machine(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("stateMachineArn", &body["stateMachineArn"])?;
        let arn = body["stateMachineArn"]
            .as_str()
            .ok_or_else(|| missing("stateMachineArn"))?;
        validate_arn(arn)?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        // AWS returns success even if it doesn't exist
        state.state_machines.remove(arn);

        Ok(AwsResponse::ok_json(json!({})))
    }

    fn update_state_machine(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("stateMachineArn", &body["stateMachineArn"])?;
        let arn = body["stateMachineArn"]
            .as_str()
            .ok_or_else(|| missing("stateMachineArn"))?;
        validate_arn(arn)?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let sm = state
            .state_machines
            .get_mut(arn)
            .ok_or_else(|| state_machine_not_found(arn))?;

        if let Some(definition) = body["definition"].as_str() {
            validate_definition(definition)?;
            sm.definition = definition.to_string();
        }

        if let Some(role_arn) = body["roleArn"].as_str() {
            validate_arn(role_arn)?;
            sm.role_arn = role_arn.to_string();
        }

        if let Some(logging) = body.get("loggingConfiguration") {
            sm.logging_configuration = Some(logging.clone());
        }

        if let Some(tracing) = body.get("tracingConfiguration") {
            sm.tracing_configuration = Some(tracing.clone());
        }

        if let Some(description) = body["description"].as_str() {
            sm.description = description.to_string();
        }

        let now = Utc::now();
        sm.update_date = now;
        sm.revision_id = uuid::Uuid::new_v4().to_string();

        let revision_id = sm.revision_id.clone();
        let sm_arn = sm.arn.clone();

        Ok(AwsResponse::ok_json(json!({
            "updateDate": now.timestamp() as f64,
            "revisionId": revision_id,
            "stateMachineVersionArn": sm_arn,
        })))
    }

    // ─── Execution Lifecycle ──────────────────────────────────────────

    fn start_execution(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("stateMachineArn", &body["stateMachineArn"])?;
        let sm_arn = body["stateMachineArn"]
            .as_str()
            .ok_or_else(|| missing("stateMachineArn"))?;
        validate_arn(sm_arn)?;

        let input = body["input"].as_str().map(|s| s.to_string());

        // Validate input is valid JSON if provided
        if let Some(ref input_str) = input {
            let _: serde_json::Value = serde_json::from_str(input_str).map_err(|_| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidExecutionInput",
                    "Invalid execution input: must be valid JSON".to_string(),
                )
            })?;
        }

        let execution_name = body["name"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

        if let Some(name) = body["name"].as_str() {
            validate_name(name)?;
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let sm = state
            .state_machines
            .get(sm_arn)
            .ok_or_else(|| state_machine_not_found(sm_arn))?;

        let sm_name = sm.name.clone();
        let definition = sm.definition.clone();
        let exec_arn = state.execution_arn(&sm_name, &execution_name);

        // Check for duplicate execution name
        if state.executions.contains_key(&exec_arn) {
            return Err(AwsServiceError::aws_error(
                StatusCode::CONFLICT,
                "ExecutionAlreadyExists",
                format!("Execution Already Exists: '{exec_arn}'"),
            ));
        }

        let now = Utc::now();
        let execution = Execution {
            execution_arn: exec_arn.clone(),
            state_machine_arn: sm_arn.to_string(),
            state_machine_name: sm_name,
            name: execution_name,
            status: ExecutionStatus::Running,
            input: input.clone(),
            output: None,
            start_date: now,
            stop_date: None,
            error: None,
            cause: None,
            history_events: vec![],
            parent_execution_arn: None,
            is_sync: false,
            billed_duration_ms: None,
            billed_memory_mb: None,
        };

        state.executions.insert(exec_arn.clone(), execution);
        let logging_config = sm.logging_configuration.clone();
        drop(accounts);

        // Spawn async execution
        let shared_state = self.state.clone();
        let exec_arn_clone = exec_arn.clone();
        let input_clone = input;
        let delivery = self.delivery.clone();
        let dynamodb_state = self.dynamodb_state.clone();
        let registry = self.registry.clone();
        tokio::spawn(async move {
            interpreter::execute_state_machine(
                shared_state,
                exec_arn_clone,
                definition,
                input_clone,
                delivery,
                dynamodb_state,
                registry,
                logging_config,
            )
            .await;
        });

        Ok(AwsResponse::ok_json(json!({
            "executionArn": exec_arn,
            "startDate": now.timestamp() as f64,
        })))
    }

    fn stop_execution(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("executionArn", &body["executionArn"])?;
        let exec_arn = body["executionArn"]
            .as_str()
            .ok_or_else(|| missing("executionArn"))?;

        let error = body["error"].as_str().map(|s| s.to_string());
        let cause = body["cause"].as_str().map(|s| s.to_string());

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let exec = state
            .executions
            .get_mut(exec_arn)
            .ok_or_else(|| execution_not_found(exec_arn))?;

        if exec.status != ExecutionStatus::Running {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ExecutionNotRunning",
                format!("Execution is not running: '{exec_arn}'"),
            ));
        }

        let now = Utc::now();
        exec.status = ExecutionStatus::Aborted;
        exec.stop_date = Some(now);
        exec.error = error;
        exec.cause = cause;

        Ok(AwsResponse::ok_json(json!({
            "stopDate": now.timestamp() as f64,
        })))
    }

    fn describe_execution(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("executionArn", &body["executionArn"])?;
        let exec_arn = body["executionArn"]
            .as_str()
            .ok_or_else(|| missing("executionArn"))?;

        let accounts = self.state.read();
        let empty = StepFunctionsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let exec = state
            .executions
            .get(exec_arn)
            .ok_or_else(|| execution_not_found(exec_arn))?;

        Ok(AwsResponse::ok_json(execution_to_json(exec)))
    }

    fn list_executions(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("stateMachineArn", &body["stateMachineArn"])?;
        let sm_arn = body["stateMachineArn"]
            .as_str()
            .ok_or_else(|| missing("stateMachineArn"))?;
        validate_arn(sm_arn)?;

        let max_results = body["maxResults"].as_i64().unwrap_or(100) as usize;
        validate_range_i64("maxResults", max_results as i64, 1, 1000)?;
        let next_token = body["nextToken"].as_str();
        let status_filter = body["statusFilter"].as_str();

        let accounts = self.state.read();
        let empty = StepFunctionsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);

        // Verify state machine exists
        if !state.state_machines.contains_key(sm_arn) {
            return Err(state_machine_not_found(sm_arn));
        }

        let mut executions: Vec<&Execution> = state
            .executions
            .values()
            .filter(|e| e.state_machine_arn == sm_arn)
            .filter(|e| {
                status_filter
                    .map(|sf| e.status.as_str() == sf)
                    .unwrap_or(true)
            })
            .collect();

        // Sort by start date descending (most recent first)
        executions.sort_by_key(|e| std::cmp::Reverse(e.start_date));

        let items: Vec<Value> = executions
            .iter()
            .map(|e| {
                let mut item = json!({
                    "executionArn": e.execution_arn,
                    "stateMachineArn": e.state_machine_arn,
                    "name": e.name,
                    "status": e.status.as_str(),
                    "startDate": e.start_date.timestamp() as f64,
                });
                if let Some(stop) = e.stop_date {
                    item["stopDate"] = json!(stop.timestamp() as f64);
                }
                item
            })
            .collect();

        let (page, token) = paginate(&items, next_token, max_results);

        let mut resp = json!({ "executions": page });
        if let Some(t) = token {
            resp["nextToken"] = json!(t);
        }
        Ok(AwsResponse::ok_json(resp))
    }

    fn get_execution_history(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("executionArn", &body["executionArn"])?;
        let exec_arn = body["executionArn"]
            .as_str()
            .ok_or_else(|| missing("executionArn"))?;

        let max_results = body["maxResults"].as_i64().unwrap_or(100) as usize;
        validate_range_i64("maxResults", max_results as i64, 1, 1000)?;
        let next_token = body["nextToken"].as_str();
        let reverse_order = body["reverseOrder"].as_bool().unwrap_or(false);

        let accounts = self.state.read();
        let empty = StepFunctionsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let exec = state
            .executions
            .get(exec_arn)
            .ok_or_else(|| execution_not_found(exec_arn))?;

        let mut events: Vec<Value> = exec
            .history_events
            .iter()
            .map(|e| {
                json!({
                    "id": e.id,
                    "type": e.event_type,
                    "timestamp": e.timestamp.timestamp() as f64,
                    "previousEventId": e.previous_event_id,
                    format!("{}EventDetails", camel_to_details_key(&e.event_type)): e.details,
                })
            })
            .collect();

        if reverse_order {
            events.reverse();
        }

        let (page, token) = paginate(&events, next_token, max_results);

        let mut resp = json!({ "events": page });
        if let Some(t) = token {
            resp["nextToken"] = json!(t);
        }
        Ok(AwsResponse::ok_json(resp))
    }

    fn describe_state_machine_for_execution(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("executionArn", &body["executionArn"])?;
        let exec_arn = body["executionArn"]
            .as_str()
            .ok_or_else(|| missing("executionArn"))?;

        let accounts = self.state.read();
        let empty = StepFunctionsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let exec = state
            .executions
            .get(exec_arn)
            .ok_or_else(|| execution_not_found(exec_arn))?;

        let sm = state
            .state_machines
            .get(&exec.state_machine_arn)
            .ok_or_else(|| state_machine_not_found(&exec.state_machine_arn))?;

        Ok(AwsResponse::ok_json(state_machine_to_json(sm)))
    }

    // ─── Tagging ────────────────────────────────────────────────────────

    fn tag_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("resourceArn", &body["resourceArn"])?;
        let arn = body["resourceArn"]
            .as_str()
            .ok_or_else(|| missing("resourceArn"))?;
        validate_arn(arn)?;
        validate_required("tags", &body["tags"])?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let sm = state
            .state_machines
            .get_mut(arn)
            .ok_or_else(|| resource_not_found(arn))?;

        fakecloud_core::tags::apply_tags(&mut sm.tags, &body, "tags", "key", "value").map_err(
            |f| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    format!("{f} must be a list"),
                )
            },
        )?;

        Ok(AwsResponse::ok_json(json!({})))
    }

    fn untag_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("resourceArn", &body["resourceArn"])?;
        let arn = body["resourceArn"]
            .as_str()
            .ok_or_else(|| missing("resourceArn"))?;
        validate_arn(arn)?;
        validate_required("tagKeys", &body["tagKeys"])?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let sm = state
            .state_machines
            .get_mut(arn)
            .ok_or_else(|| resource_not_found(arn))?;

        fakecloud_core::tags::remove_tags(&mut sm.tags, &body, "tagKeys").map_err(|f| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                format!("{f} must be a list"),
            )
        })?;

        Ok(AwsResponse::ok_json(json!({})))
    }

    fn list_tags_for_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("resourceArn", &body["resourceArn"])?;
        let arn = body["resourceArn"]
            .as_str()
            .ok_or_else(|| missing("resourceArn"))?;
        validate_arn(arn)?;

        let accounts = self.state.read();
        let empty = StepFunctionsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let sm = state
            .state_machines
            .get(arn)
            .ok_or_else(|| resource_not_found(arn))?;

        let tags = fakecloud_core::tags::tags_to_json(&sm.tags, "key", "value");

        Ok(AwsResponse::ok_json(json!({ "tags": tags })))
    }

    // ─── Activities ─────────────────────────────────────────────────────

    fn create_activity(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = body["name"].as_str().ok_or_else(|| missing("name"))?;
        validate_name(name)?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let arn = format!(
            "arn:aws:states:{}:{}:activity:{}",
            state.region, state.account_id, name
        );
        if state.activities.contains_key(&arn) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ActivityAlreadyExists",
                format!("Activity already exists: {arn}"),
            ));
        }
        let activity = crate::state::Activity {
            name: name.to_string(),
            arn: arn.clone(),
            creation_date: chrono::Utc::now(),
            tags: BTreeMap::new(),
        };
        state.activities.insert(arn.clone(), activity.clone());
        Ok(AwsResponse::ok_json(json!({
            "activityArn": arn,
            "creationDate": activity.creation_date.timestamp(),
        })))
    }

    fn delete_activity(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = body["activityArn"]
            .as_str()
            .ok_or_else(|| missing("activityArn"))?
            .to_string();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state.activities.remove(&arn);
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn describe_activity(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = body["activityArn"]
            .as_str()
            .ok_or_else(|| missing("activityArn"))?
            .to_string();
        let accounts = self.state.read();
        let empty = crate::state::StepFunctionsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let a = state.activities.get(&arn).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ActivityDoesNotExist",
                format!("Activity does not exist: {arn}"),
            )
        })?;
        Ok(AwsResponse::ok_json(json!({
            "activityArn": a.arn,
            "name": a.name,
            "creationDate": a.creation_date.timestamp(),
        })))
    }

    fn list_activities(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let empty = crate::state::StepFunctionsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let mut activities: Vec<&crate::state::Activity> = state.activities.values().collect();
        activities.sort_by(|a, b| a.name.cmp(&b.name));
        let body = json!({
            "activities": activities.iter().map(|a| json!({
                "activityArn": a.arn,
                "name": a.name,
                "creationDate": a.creation_date.timestamp(),
            })).collect::<Vec<_>>(),
        });
        Ok(AwsResponse::ok_json(body))
    }

    async fn get_activity_task(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = body["activityArn"]
            .as_str()
            .ok_or_else(|| missing("activityArn"))?
            .to_string();
        // Activity must exist before we'll accept long-poll calls.
        {
            let accounts = self.state.read();
            let state = accounts
                .get(&req.account_id)
                .ok_or_else(|| activity_not_found(&arn))?;
            if !state.activities.contains_key(&arn) {
                return Err(activity_not_found(&arn));
            }
        }

        // AWS GetActivityTask blocks up to 60s. fakecloud defaults to 5s
        // so test suites don't stall when no worker is feeding the queue.
        let max_wait_secs: u64 = std::env::var("FAKECLOUD_SFN_GET_ACTIVITY_TIMEOUT_SECS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(max_wait_secs);

        loop {
            // Try to dequeue oldest PENDING token for this activity.
            {
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(&req.account_id);
                let mut candidates: Vec<(String, chrono::DateTime<chrono::Utc>)> = state
                    .task_tokens
                    .iter()
                    .filter(|(_, t)| t.activity_arn == arn && t.status == "PENDING")
                    .map(|(k, t)| (k.clone(), t.created_at))
                    .collect();
                candidates.sort_by_key(|c| c.1);
                if let Some((token, _)) = candidates.into_iter().next() {
                    let now = chrono::Utc::now();
                    let entry = state.task_tokens.get_mut(&token).expect("just looked up");
                    entry.status = "IN_PROGRESS".to_string();
                    entry.last_heartbeat_at = Some(now);
                    let input = entry.input.clone().unwrap_or_else(|| "{}".to_string());
                    return Ok(AwsResponse::ok_json(json!({
                        "taskToken": token,
                        "input": input,
                    })));
                }
            }
            if std::time::Instant::now() >= deadline {
                // No task available in window — return empty token (matches
                // AWS behavior).
                return Ok(AwsResponse::ok_json(json!({
                    "taskToken": "",
                    "input": "",
                })));
            }
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        }
    }

    fn send_task_success(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        self.update_task_token(req, "SUCCEEDED")
    }

    fn send_task_failure(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        self.update_task_token(req, "FAILED")
    }

    fn send_task_heartbeat(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        // Heartbeats only refresh `last_heartbeat_at`; they don't change
        // the task's lifecycle status. The interpreter's heartbeat-timeout
        // check reads `last_heartbeat_at` to decide whether to fail the
        // task with `States.HeartbeatTimeout`.
        let body = req.json_body();
        let token = body["taskToken"]
            .as_str()
            .ok_or_else(|| missing("taskToken"))?
            .to_string();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let entry = state
            .task_tokens
            .get_mut(&token)
            .ok_or_else(|| task_does_not_exist(&token))?;
        entry.last_heartbeat_at = Some(chrono::Utc::now());
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn update_task_token(
        &self,
        req: &AwsRequest,
        new_status: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let token = body["taskToken"]
            .as_str()
            .ok_or_else(|| missing("taskToken"))?
            .to_string();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let entry = state
            .task_tokens
            .get_mut(&token)
            .ok_or_else(|| task_does_not_exist(&token))?;
        entry.status = new_status.to_string();
        if new_status == "SUCCEEDED" {
            entry.output = body["output"].as_str().map(String::from);
        } else if new_status == "FAILED" {
            entry.error = body["error"].as_str().map(String::from);
            entry.cause = body["cause"].as_str().map(String::from);
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    // ─── State machine versions / aliases ───────────────────────────────

    fn publish_state_machine_version(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = body["stateMachineArn"]
            .as_str()
            .ok_or_else(|| missing("stateMachineArn"))?
            .to_string();
        let description = body["description"].as_str().unwrap_or("").to_string();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if !state.state_machines.contains_key(&arn) {
            return Err(state_machine_not_found(&arn));
        }
        let version = state
            .state_machine_versions
            .values()
            .filter(|v| v.state_machine_arn == arn)
            .map(|v| v.version)
            .max()
            .unwrap_or(0)
            + 1;
        let version_arn = format!("{arn}:{version}");
        let v = crate::state::StateMachineVersion {
            state_machine_arn: arn,
            version,
            revision_id: format!("rev-{version}"),
            description,
            creation_date: chrono::Utc::now(),
        };
        state
            .state_machine_versions
            .insert(version_arn.clone(), v.clone());
        Ok(AwsResponse::ok_json(json!({
            "stateMachineVersionArn": version_arn,
            "creationDate": v.creation_date.timestamp(),
        })))
    }

    fn delete_state_machine_version(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = body["stateMachineVersionArn"]
            .as_str()
            .ok_or_else(|| missing("stateMachineVersionArn"))?
            .to_string();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state.state_machine_versions.remove(&arn);
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn list_state_machine_versions(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = body["stateMachineArn"]
            .as_str()
            .ok_or_else(|| missing("stateMachineArn"))?
            .to_string();
        let accounts = self.state.read();
        let empty = crate::state::StepFunctionsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let mut versions: Vec<&crate::state::StateMachineVersion> = state
            .state_machine_versions
            .values()
            .filter(|v| v.state_machine_arn == arn)
            .collect();
        versions.sort_by_key(|v| std::cmp::Reverse(v.version));
        let resp = json!({
            "stateMachineVersions": versions.iter().map(|v| json!({
                "stateMachineVersionArn": format!("{}:{}", v.state_machine_arn, v.version),
                "creationDate": v.creation_date.timestamp(),
            })).collect::<Vec<_>>(),
        });
        Ok(AwsResponse::ok_json(resp))
    }

    fn create_state_machine_alias(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = body["name"]
            .as_str()
            .ok_or_else(|| missing("name"))?
            .to_string();
        validate_name(&name)?;
        let routing_cfg = body["routingConfiguration"]
            .as_array()
            .ok_or_else(|| missing("routingConfiguration"))?;
        let routes = parse_routing_configuration(routing_cfg)?;
        let parent_arn = routes[0]
            .state_machine_version_arn
            .rsplit_once(':')
            .map(|(parent, _)| parent.to_string())
            .unwrap_or_default();
        let alias_arn = format!("{parent_arn}:{name}");
        let now = chrono::Utc::now();
        let alias = crate::state::StateMachineAlias {
            name,
            arn: alias_arn.clone(),
            description: body["description"].as_str().unwrap_or("").to_string(),
            routing_configuration: routes,
            creation_date: now,
            update_date: now,
        };
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state.state_machine_aliases.insert(alias_arn.clone(), alias);
        Ok(AwsResponse::ok_json(json!({
            "stateMachineAliasArn": alias_arn,
            "creationDate": now.timestamp(),
        })))
    }

    fn delete_state_machine_alias(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = body["stateMachineAliasArn"]
            .as_str()
            .ok_or_else(|| missing("stateMachineAliasArn"))?
            .to_string();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state.state_machine_aliases.remove(&arn);
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn describe_state_machine_alias(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = body["stateMachineAliasArn"]
            .as_str()
            .ok_or_else(|| missing("stateMachineAliasArn"))?
            .to_string();
        let accounts = self.state.read();
        let empty = crate::state::StepFunctionsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let alias = state
            .state_machine_aliases
            .get(&arn)
            .ok_or_else(|| resource_not_found(&arn))?;
        Ok(AwsResponse::ok_json(state_machine_alias_to_json(alias)))
    }

    fn list_state_machine_aliases(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let parent = body["stateMachineArn"]
            .as_str()
            .ok_or_else(|| missing("stateMachineArn"))?
            .to_string();
        let accounts = self.state.read();
        let empty = crate::state::StepFunctionsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        // Anchor the prefix on the alias separator so a state machine
        // named `foo` doesn't pull in aliases for `foobar`.
        let parent_prefix = format!("{parent}:");
        let mut aliases: Vec<&crate::state::StateMachineAlias> = state
            .state_machine_aliases
            .values()
            .filter(|a| a.arn.starts_with(&parent_prefix))
            .collect();
        aliases.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(AwsResponse::ok_json(json!({
            "stateMachineAliases": aliases.iter().map(|a| json!({
                "stateMachineAliasArn": a.arn,
                "creationDate": a.creation_date.timestamp(),
            })).collect::<Vec<_>>(),
        })))
    }

    fn update_state_machine_alias(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = body["stateMachineAliasArn"]
            .as_str()
            .ok_or_else(|| missing("stateMachineAliasArn"))?
            .to_string();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let alias = state
            .state_machine_aliases
            .get_mut(&arn)
            .ok_or_else(|| resource_not_found(&arn))?;
        if let Some(d) = body["description"].as_str() {
            alias.description = d.to_string();
        }
        if let Some(routes) = body["routingConfiguration"].as_array() {
            alias.routing_configuration = parse_routing_configuration(routes)?;
        }
        alias.update_date = chrono::Utc::now();
        Ok(AwsResponse::ok_json(json!({
            "updateDate": alias.update_date.timestamp(),
        })))
    }

    // ─── Map runs ───────────────────────────────────────────────────────

    fn describe_map_run(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = body["mapRunArn"]
            .as_str()
            .ok_or_else(|| missing("mapRunArn"))?
            .to_string();
        let accounts = self.state.read();
        let empty = crate::state::StepFunctionsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let mr = state
            .map_runs
            .get(&arn)
            .ok_or_else(|| resource_not_found(&arn))?;
        Ok(AwsResponse::ok_json(map_run_to_json(mr)))
    }

    fn list_map_runs(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let exec_arn = body["executionArn"].as_str().map(String::from);
        let accounts = self.state.read();
        let empty = crate::state::StepFunctionsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let runs: Vec<&crate::state::MapRun> = state
            .map_runs
            .values()
            .filter(|r| exec_arn.as_deref().is_none_or(|e| r.execution_arn == e))
            .collect();
        Ok(AwsResponse::ok_json(json!({
            "mapRuns": runs.iter().map(|r| json!({
                "mapRunArn": r.map_run_arn,
                "executionArn": r.execution_arn,
                "stateMachineArn": "",
                "startDate": r.start_date.timestamp(),
                "stopDate": r.stop_date.map(|d| d.timestamp()),
            })).collect::<Vec<_>>(),
        })))
    }

    fn update_map_run(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = body["mapRunArn"]
            .as_str()
            .ok_or_else(|| missing("mapRunArn"))?
            .to_string();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let mr = state
            .map_runs
            .get_mut(&arn)
            .ok_or_else(|| resource_not_found(&arn))?;
        if let Some(c) = body["maxConcurrency"].as_i64() {
            mr.max_concurrency = c as i32;
        }
        if let Some(p) = body["toleratedFailurePercentage"].as_f64() {
            mr.tolerated_failure_percentage = p;
        }
        if let Some(c) = body["toleratedFailureCount"].as_i64() {
            mr.tolerated_failure_count = c;
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    // ─── Execution lifecycle extras ─────────────────────────────────────

    fn redrive_execution(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = body["executionArn"]
            .as_str()
            .ok_or_else(|| missing("executionArn"))?
            .to_string();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let exec = state.executions.get_mut(&arn).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ExecutionDoesNotExist",
                format!("Execution does not exist: {arn}"),
            )
        })?;
        exec.status = crate::state::ExecutionStatus::Running;
        exec.stop_date = None;
        Ok(AwsResponse::ok_json(json!({
            "redriveDate": chrono::Utc::now().timestamp(),
        })))
    }

    async fn start_sync_execution(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let sm_arn = body["stateMachineArn"]
            .as_str()
            .ok_or_else(|| missing("stateMachineArn"))?
            .to_string();
        let input = body["input"].as_str().unwrap_or("{}").to_string();
        if serde_json::from_str::<serde_json::Value>(&input).is_err() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidExecutionInput",
                "Execution input is not valid JSON.",
            ));
        }
        let (exec_arn, definition, logging_config) = {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&req.account_id);
            let sm = state
                .state_machines
                .get(&sm_arn)
                .ok_or_else(|| state_machine_not_found(&sm_arn))?;
            if sm.machine_type != crate::state::StateMachineType::Express {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "StateMachineTypeNotSupported",
                    "StartSyncExecution is only supported for EXPRESS state machines.",
                ));
            }
            let now = chrono::Utc::now();
            let exec_name = format!("sync-{}", now.timestamp_millis());
            let exec_arn = format!(
                "arn:aws:states:{}:{}:express:{}:{}",
                state.region, state.account_id, sm.name, exec_name
            );
            let execution = Execution {
                execution_arn: exec_arn.clone(),
                state_machine_arn: sm_arn.clone(),
                state_machine_name: sm.name.clone(),
                name: exec_name.clone(),
                status: ExecutionStatus::Running,
                input: Some(input.clone()),
                output: None,
                start_date: now,
                stop_date: None,
                error: None,
                cause: None,
                history_events: vec![],
                parent_execution_arn: None,
                is_sync: true,
                billed_duration_ms: None,
                billed_memory_mb: None,
            };
            state.executions.insert(exec_arn.clone(), execution);
            (
                exec_arn,
                sm.definition.clone(),
                sm.logging_configuration.clone(),
            )
        };

        interpreter::execute_state_machine(
            self.state.clone(),
            exec_arn.clone(),
            definition,
            Some(input),
            self.delivery.clone(),
            self.dynamodb_state.clone(),
            self.registry.clone(),
            logging_config,
        )
        .await;

        // Persist billing details on the stored execution so introspection
        // endpoints can replay the same numbers later.
        {
            let mut accounts = self.state.write();
            if let Some(state) = accounts.get_mut(&req.account_id) {
                if let Some(exec) = state.executions.get_mut(&exec_arn) {
                    let duration_ms = exec
                        .stop_date
                        .map_or(0, |stop| (stop - exec.start_date).num_milliseconds())
                        .max(0);
                    exec.billed_duration_ms = Some(duration_ms);
                    exec.billed_memory_mb = Some(64);
                }
            }
        }

        let accounts = self.state.read();
        let state = accounts.get(&req.account_id).unwrap();
        let exec = state
            .executions
            .get(&exec_arn)
            .ok_or_else(|| execution_not_found(&exec_arn))?;

        let mut resp = json!({
            "executionArn": exec.execution_arn,
            "stateMachineArn": exec.state_machine_arn,
            "name": exec.name,
            "startDate": exec.start_date.timestamp(),
            "stopDate": exec.stop_date.map(|d| d.timestamp()),
            "status": exec.status.as_str(),
            "input": exec.input.as_deref().unwrap_or("{}"),
        });

        if let Some(ref output) = exec.output {
            resp["output"] = json!(output);
        }
        if let Some(ref error) = exec.error {
            resp["error"] = json!(error);
        }
        if let Some(ref cause) = exec.cause {
            resp["cause"] = json!(cause);
        }

        let duration_ms = exec
            .stop_date
            .map_or(0, |stop| (stop - exec.start_date).num_milliseconds());
        resp["billingDetails"] = json!({
            "billedMemoryUsedInMB": 64,
            "billedDurationInMilliseconds": duration_ms.max(0),
        });

        Ok(AwsResponse::ok_json(resp))
    }

    fn test_state(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let definition = body["definition"]
            .as_str()
            .ok_or_else(|| missing("definition"))?;
        validate_definition(definition)?;
        let _role_arn = body["roleArn"].as_str().ok_or_else(|| missing("roleArn"))?;
        let input = body["input"].as_str().unwrap_or("{}").to_string();
        // Echo input back as output. Real Step Functions actually
        // simulates the state; our emulator reports SUCCEEDED so callers
        // can wire the integration test scaffolding.
        Ok(AwsResponse::ok_json(json!({
            "output": input,
            "status": "SUCCEEDED",
            "nextState": "End",
        })))
    }

    fn validate_state_machine_definition(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let definition = body["definition"]
            .as_str()
            .ok_or_else(|| missing("definition"))?;
        match validate_definition(definition) {
            Ok(()) => Ok(AwsResponse::ok_json(json!({
                "result": "OK",
                "diagnostics": [],
            }))),
            Err(e) => Ok(AwsResponse::ok_json(json!({
                "result": "FAIL",
                "diagnostics": [{
                    "severity": "ERROR",
                    "code": "INVALID_DEFINITION",
                    "message": e.to_string(),
                }],
            }))),
        }
    }
}

fn state_machine_alias_to_json(alias: &crate::state::StateMachineAlias) -> Value {
    json!({
        "stateMachineAliasArn": alias.arn,
        "name": alias.name,
        "description": alias.description,
        "routingConfiguration": alias.routing_configuration.iter().map(|r| json!({
            "stateMachineVersionArn": r.state_machine_version_arn,
            "weight": r.weight,
        })).collect::<Vec<_>>(),
        "creationDate": alias.creation_date.timestamp(),
        "updateDate": alias.update_date.timestamp(),
    })
}

fn map_run_to_json(mr: &crate::state::MapRun) -> Value {
    json!({
        "mapRunArn": mr.map_run_arn,
        "executionArn": mr.execution_arn,
        "maxConcurrency": mr.max_concurrency,
        "toleratedFailurePercentage": mr.tolerated_failure_percentage,
        "toleratedFailureCount": mr.tolerated_failure_count,
        "status": mr.status,
        "startDate": mr.start_date.timestamp(),
        "stopDate": mr.stop_date.map(|d| d.timestamp()),
    })
}

// ─── Helpers ────────────────────────────────────────────────────────────

fn state_machine_to_json(sm: &StateMachine) -> Value {
    let mut resp = json!({
        "name": sm.name,
        "stateMachineArn": sm.arn,
        "definition": sm.definition,
        "roleArn": sm.role_arn,
        "type": sm.machine_type.as_str(),
        "status": sm.status.as_str(),
        "creationDate": sm.creation_date.timestamp() as f64,
        "updateDate": sm.update_date.timestamp() as f64,
        "revisionId": sm.revision_id,
        "label": sm.name,
    });

    if !sm.description.is_empty() {
        resp["description"] = json!(sm.description);
    }

    if let Some(ref logging) = sm.logging_configuration {
        resp["loggingConfiguration"] = logging.clone();
    } else {
        resp["loggingConfiguration"] = json!({
            "level": "OFF",
            "includeExecutionData": false,
            "destinations": [],
        });
    }

    if let Some(ref tracing) = sm.tracing_configuration {
        resp["tracingConfiguration"] = tracing.clone();
    } else {
        resp["tracingConfiguration"] = json!({
            "enabled": false,
        });
    }

    resp
}

fn missing(name: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ValidationException",
        format!("The request must contain the parameter {name}."),
    )
}

fn state_machine_not_found(arn: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "StateMachineDoesNotExist",
        format!("State Machine Does Not Exist: '{arn}'"),
    )
}

fn activity_not_found(arn: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ActivityDoesNotExist",
        format!("Activity does not exist: {arn}"),
    )
}

fn task_does_not_exist(token: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "TaskDoesNotExist",
        format!("Task does not exist: {token}"),
    )
}

fn resource_not_found(arn: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ResourceNotFound",
        format!("Resource not found: '{arn}'"),
    )
}

/// Parse + validate an alias `routingConfiguration` array.
///
/// AWS rules: 1 or 2 routes; weights are 0-100 and sum to 100; each
/// route must include `stateMachineVersionArn`.
fn parse_routing_configuration(
    routes: &[serde_json::Value],
) -> Result<Vec<crate::state::AliasRoute>, AwsServiceError> {
    if routes.is_empty() || routes.len() > 2 {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "routingConfiguration must contain 1 or 2 routes.",
        ));
    }
    let parsed: Vec<crate::state::AliasRoute> = routes
        .iter()
        .map(|r| {
            let arn = r["stateMachineVersionArn"].as_str().ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "routingConfiguration entries must contain stateMachineVersionArn.",
                )
            })?;
            let weight = r["weight"].as_i64().ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "routingConfiguration entries must contain a numeric weight.",
                )
            })?;
            if !(0..=100).contains(&weight) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    format!("Invalid routing weight {weight}; must be 0-100."),
                ));
            }
            Ok(crate::state::AliasRoute {
                state_machine_version_arn: arn.to_string(),
                weight: weight as i32,
            })
        })
        .collect::<Result<_, _>>()?;
    let total: i32 = parsed.iter().map(|r| r.weight).sum();
    if total != 100 {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            format!("routingConfiguration weights must sum to 100, got {total}."),
        ));
    }
    Ok(parsed)
}

fn validate_name(name: &str) -> Result<(), AwsServiceError> {
    if name.is_empty() || name.len() > 80 {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidName",
            format!("Invalid Name: '{name}' (length must be between 1 and 80 characters)"),
        ));
    }
    // Only allow alphanumeric, hyphens, and underscores
    if !name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidName",
            format!(
                "Invalid Name: '{name}' (must only contain alphanumeric characters, hyphens, and underscores)"
            ),
        ));
    }
    Ok(())
}

fn validate_definition(definition: &str) -> Result<(), AwsServiceError> {
    let parsed: Value = serde_json::from_str(definition).map_err(|e| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidDefinition",
            format!("Invalid State Machine Definition: '{e}'"),
        )
    })?;

    if parsed.get("StartAt").and_then(|v| v.as_str()).is_none() {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidDefinition",
            "Invalid State Machine Definition: 'MISSING_START_AT' (StartAt field is required)"
                .to_string(),
        ));
    }

    let states_obj = parsed
        .get("States")
        .and_then(|v| v.as_object())
        .ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidDefinition",
                "Invalid State Machine Definition: 'MISSING_STATES' (States field is required)"
                    .to_string(),
            )
        })?;

    let start_at = parsed["StartAt"].as_str().ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidDefinition",
            "Invalid State Machine Definition: 'MISSING_START_AT' (StartAt field is required)"
                .to_string(),
        )
    })?;
    if !states_obj.contains_key(start_at) {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidDefinition",
            format!(
                "Invalid State Machine Definition: 'MISSING_TRANSITION_TARGET' \
                 (StartAt '{start_at}' does not reference a valid state)"
            ),
        ));
    }

    Ok(())
}

fn execution_not_found(arn: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ExecutionDoesNotExist",
        format!("Execution Does Not Exist: '{arn}'"),
    )
}

fn execution_to_json(exec: &Execution) -> Value {
    let mut resp = json!({
        "executionArn": exec.execution_arn,
        "stateMachineArn": exec.state_machine_arn,
        "name": exec.name,
        "status": exec.status.as_str(),
        "startDate": exec.start_date.timestamp() as f64,
    });

    if let Some(ref input) = exec.input {
        resp["input"] = json!(input);
    }
    if let Some(ref output) = exec.output {
        resp["output"] = json!(output);
    }
    if let Some(stop) = exec.stop_date {
        resp["stopDate"] = json!(stop.timestamp() as f64);
    }
    if let Some(ref error) = exec.error {
        resp["error"] = json!(error);
    }
    if let Some(ref cause) = exec.cause {
        resp["cause"] = json!(cause);
    }

    resp
}

/// Convert event type like "PassStateEntered" to the details key format "passStateEntered".
fn camel_to_details_key(event_type: &str) -> String {
    let mut chars = event_type.chars();
    match chars.next() {
        None => String::new(),
        Some(c) => c.to_lowercase().to_string() + chars.as_str(),
    }
}

fn validate_arn(arn: &str) -> Result<(), AwsServiceError> {
    if !arn.starts_with("arn:") {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidArn",
            format!("Invalid Arn: '{arn}'"),
        ));
    }
    Ok(())
}

/// Start a Step Functions execution from a cross-service delivery (e.g. EventBridge).
///
/// This is the public entry point used by `StepFunctionsDeliveryImpl` in the server crate.
/// It mirrors the logic from `StartExecution` but without the AWS request/response wrapper.
/// Start a Step Functions execution from a cross-service delivery (e.g. EventBridge).
///
/// This is the public entry point used by `StepFunctionsDeliveryImpl` in the server crate.
/// It mirrors the logic from `StartExecution` but without the AWS request/response wrapper.
pub fn start_execution_from_delivery(
    state: &SharedStepFunctionsState,
    delivery: &Option<Arc<DeliveryBus>>,
    dynamodb_state: &Option<SharedDynamoDbState>,
    registry: &Option<SharedServiceRegistry>,
    state_machine_arn: &str,
    input: &str,
) {
    // Validate input is valid JSON
    if serde_json::from_str::<serde_json::Value>(input).is_err() {
        tracing::warn!(
            state_machine_arn,
            "Step Functions delivery: invalid JSON input, skipping execution"
        );
        return;
    }

    let execution_name = uuid::Uuid::new_v4().to_string();

    // Extract account_id from the state machine ARN
    let account_id = state_machine_arn
        .split(':')
        .nth(4)
        .unwrap_or("000000000000")
        .to_string();

    let mut accounts = state.write();
    let st = accounts.get_or_create(&account_id);
    let sm = match st.state_machines.get(state_machine_arn) {
        Some(sm) => sm,
        None => {
            tracing::warn!(
                state_machine_arn,
                "Step Functions delivery: state machine not found"
            );
            return;
        }
    };

    let sm_name = sm.name.clone();
    let definition = sm.definition.clone();
    let exec_arn = st.execution_arn(&sm_name, &execution_name);

    let now = Utc::now();
    let execution = Execution {
        execution_arn: exec_arn.clone(),
        state_machine_arn: state_machine_arn.to_string(),
        state_machine_name: sm_name,
        name: execution_name,
        status: ExecutionStatus::Running,
        input: Some(input.to_string()),
        output: None,
        start_date: now,
        stop_date: None,
        error: None,
        cause: None,
        history_events: vec![],
        parent_execution_arn: None,
        is_sync: false,
        billed_duration_ms: None,
        billed_memory_mb: None,
    };

    st.executions.insert(exec_arn.clone(), execution);
    let logging_config = sm.logging_configuration.clone();
    drop(accounts);

    let shared_state = state.clone();
    let delivery = delivery.clone();
    let dynamodb_state = dynamodb_state.clone();
    let registry = registry.clone();
    let input = Some(input.to_string());
    tokio::spawn(async move {
        interpreter::execute_state_machine(
            shared_state,
            exec_arn,
            definition,
            input,
            delivery,
            dynamodb_state,
            registry,
            logging_config,
        )
        .await;
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::{HeaderMap, Method};
    use parking_lot::RwLock;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn make_state() -> SharedStepFunctionsState {
        Arc::new(RwLock::new(
            fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", ""),
        ))
    }

    fn make_request(action: &str, body: &str) -> AwsRequest {
        AwsRequest {
            service: "states".to_string(),
            action: action.to_string(),
            region: "us-east-1".to_string(),
            account_id: "123456789012".to_string(),
            request_id: "test-id".to_string(),
            headers: HeaderMap::new(),
            query_params: HashMap::new(),
            body: body.as_bytes().to_vec().into(),
            body_stream: parking_lot::Mutex::new(None),
            path_segments: vec![],
            raw_path: "/".to_string(),
            raw_query: String::new(),
            method: Method::POST,
            is_query_protocol: false,
            access_key_id: None,
            principal: None,
        }
    }

    fn body_json(resp: &AwsResponse) -> Value {
        serde_json::from_slice(resp.body.expect_bytes()).unwrap()
    }

    fn expect_err(result: Result<AwsResponse, AwsServiceError>) -> AwsServiceError {
        match result {
            Err(e) => e,
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    const VALID_DEF: &str = r#"{"StartAt":"Pass","States":{"Pass":{"Type":"Pass","End":true}}}"#;

    fn create_sm(svc: &StepFunctionsService, name: &str) -> String {
        let body = json!({
            "name": name,
            "definition": VALID_DEF,
            "roleArn": "arn:aws:iam::123456789012:role/test",
        });
        let req = make_request("CreateStateMachine", &body.to_string());
        let resp = svc.create_state_machine(&req).unwrap();
        let b = body_json(&resp);
        b["stateMachineArn"].as_str().unwrap().to_string()
    }

    // ── CreateStateMachine ──

    #[test]
    fn create_state_machine_basic() {
        let svc = StepFunctionsService::new(make_state());
        let arn = create_sm(&svc, "test-sm");
        assert!(arn.contains("test-sm"));
    }

    #[test]
    fn create_state_machine_with_express_type() {
        let svc = StepFunctionsService::new(make_state());
        let body = json!({
            "name": "express-sm",
            "definition": VALID_DEF,
            "roleArn": "arn:aws:iam::123456789012:role/r",
            "type": "EXPRESS",
        });
        let req = make_request("CreateStateMachine", &body.to_string());
        let resp = svc.create_state_machine(&req).unwrap();
        let b = body_json(&resp);
        assert!(b["stateMachineArn"].as_str().is_some());
    }

    #[test]
    fn create_state_machine_duplicate_fails() {
        let svc = StepFunctionsService::new(make_state());
        create_sm(&svc, "dup-sm");
        let body = json!({
            "name": "dup-sm",
            "definition": VALID_DEF,
            "roleArn": "arn:aws:iam::123456789012:role/r",
        });
        let req = make_request("CreateStateMachine", &body.to_string());
        let err = expect_err(svc.create_state_machine(&req));
        assert!(err.to_string().contains("StateMachineAlreadyExists"));
    }

    #[test]
    fn create_state_machine_missing_name() {
        let svc = StepFunctionsService::new(make_state());
        let body = json!({
            "definition": VALID_DEF,
            "roleArn": "arn:aws:iam::123456789012:role/r",
        });
        let req = make_request("CreateStateMachine", &body.to_string());
        assert!(svc.create_state_machine(&req).is_err());
    }

    #[test]
    fn create_state_machine_invalid_definition() {
        let svc = StepFunctionsService::new(make_state());
        let body = json!({
            "name": "bad-def",
            "definition": "not json",
            "roleArn": "arn:aws:iam::123456789012:role/r",
        });
        let req = make_request("CreateStateMachine", &body.to_string());
        let err = expect_err(svc.create_state_machine(&req));
        assert!(err.to_string().contains("InvalidDefinition"));
    }

    #[test]
    fn create_state_machine_definition_missing_start_at() {
        let svc = StepFunctionsService::new(make_state());
        let body = json!({
            "name": "no-start",
            "definition": r#"{"States":{"S":{"Type":"Pass","End":true}}}"#,
            "roleArn": "arn:aws:iam::123456789012:role/r",
        });
        let req = make_request("CreateStateMachine", &body.to_string());
        let err = expect_err(svc.create_state_machine(&req));
        assert!(err.to_string().contains("InvalidDefinition"));
    }

    #[test]
    fn create_state_machine_definition_missing_states() {
        let svc = StepFunctionsService::new(make_state());
        let body = json!({
            "name": "no-states",
            "definition": r#"{"StartAt":"S"}"#,
            "roleArn": "arn:aws:iam::123456789012:role/r",
        });
        let req = make_request("CreateStateMachine", &body.to_string());
        let err = expect_err(svc.create_state_machine(&req));
        assert!(err.to_string().contains("InvalidDefinition"));
    }

    #[test]
    fn create_state_machine_definition_start_at_not_in_states() {
        let svc = StepFunctionsService::new(make_state());
        let body = json!({
            "name": "bad-start",
            "definition": r#"{"StartAt":"Missing","States":{"S":{"Type":"Pass","End":true}}}"#,
            "roleArn": "arn:aws:iam::123456789012:role/r",
        });
        let req = make_request("CreateStateMachine", &body.to_string());
        let err = expect_err(svc.create_state_machine(&req));
        assert!(err.to_string().contains("MISSING_TRANSITION_TARGET"));
    }

    #[test]
    fn create_state_machine_invalid_type() {
        let svc = StepFunctionsService::new(make_state());
        let body = json!({
            "name": "bad-type",
            "definition": VALID_DEF,
            "roleArn": "arn:aws:iam::123456789012:role/r",
            "type": "INVALID",
        });
        let req = make_request("CreateStateMachine", &body.to_string());
        assert!(svc.create_state_machine(&req).is_err());
    }

    #[test]
    fn create_state_machine_invalid_arn() {
        let svc = StepFunctionsService::new(make_state());
        let body = json!({
            "name": "bad-arn",
            "definition": VALID_DEF,
            "roleArn": "not-an-arn",
        });
        let req = make_request("CreateStateMachine", &body.to_string());
        let err = expect_err(svc.create_state_machine(&req));
        assert!(err.to_string().contains("InvalidArn"));
    }

    #[test]
    fn create_state_machine_invalid_name() {
        let svc = StepFunctionsService::new(make_state());
        let body = json!({
            "name": "has spaces!",
            "definition": VALID_DEF,
            "roleArn": "arn:aws:iam::123456789012:role/r",
        });
        let req = make_request("CreateStateMachine", &body.to_string());
        let err = expect_err(svc.create_state_machine(&req));
        assert!(err.to_string().contains("InvalidName"));
    }

    #[test]
    fn create_state_machine_name_too_long() {
        let svc = StepFunctionsService::new(make_state());
        let long_name = "a".repeat(81);
        let body = json!({
            "name": long_name,
            "definition": VALID_DEF,
            "roleArn": "arn:aws:iam::123456789012:role/r",
        });
        let req = make_request("CreateStateMachine", &body.to_string());
        let err = expect_err(svc.create_state_machine(&req));
        assert!(err.to_string().contains("InvalidName"));
    }

    // ── DescribeStateMachine ──

    #[test]
    fn describe_state_machine_found() {
        let svc = StepFunctionsService::new(make_state());
        let arn = create_sm(&svc, "desc-sm");

        let req = make_request(
            "DescribeStateMachine",
            &json!({"stateMachineArn": arn}).to_string(),
        );
        let resp = svc.describe_state_machine(&req).unwrap();
        let b = body_json(&resp);
        assert_eq!(b["name"], "desc-sm");
        assert_eq!(b["status"], "ACTIVE");
        assert!(b["definition"].as_str().is_some());
    }

    #[test]
    fn describe_state_machine_not_found() {
        let svc = StepFunctionsService::new(make_state());
        let req = make_request(
            "DescribeStateMachine",
            &json!({"stateMachineArn": "arn:aws:states:us-east-1:123456789012:stateMachine:nope"})
                .to_string(),
        );
        let err = expect_err(svc.describe_state_machine(&req));
        assert!(err.to_string().contains("StateMachineDoesNotExist"));
    }

    // ── ListStateMachines ──

    #[test]
    fn list_state_machines_empty() {
        let svc = StepFunctionsService::new(make_state());
        let req = make_request("ListStateMachines", "{}");
        let resp = svc.list_state_machines(&req).unwrap();
        let b = body_json(&resp);
        assert!(b["stateMachines"].as_array().unwrap().is_empty());
    }

    #[test]
    fn list_state_machines_returns_created() {
        let svc = StepFunctionsService::new(make_state());
        create_sm(&svc, "sm-1");
        create_sm(&svc, "sm-2");

        let req = make_request("ListStateMachines", "{}");
        let resp = svc.list_state_machines(&req).unwrap();
        let b = body_json(&resp);
        assert_eq!(b["stateMachines"].as_array().unwrap().len(), 2);
    }

    // ── DeleteStateMachine ──

    #[test]
    fn delete_state_machine() {
        let svc = StepFunctionsService::new(make_state());
        let arn = create_sm(&svc, "del-sm");

        let req = make_request(
            "DeleteStateMachine",
            &json!({"stateMachineArn": arn}).to_string(),
        );
        svc.delete_state_machine(&req).unwrap();

        // Describe should fail
        let req = make_request(
            "DescribeStateMachine",
            &json!({"stateMachineArn": arn}).to_string(),
        );
        assert!(svc.describe_state_machine(&req).is_err());
    }

    #[test]
    fn delete_state_machine_nonexistent_succeeds() {
        let svc = StepFunctionsService::new(make_state());
        let req = make_request(
            "DeleteStateMachine",
            &json!({"stateMachineArn": "arn:aws:states:us-east-1:123456789012:stateMachine:nope"})
                .to_string(),
        );
        // AWS returns success even for nonexistent
        svc.delete_state_machine(&req).unwrap();
    }

    // ── UpdateStateMachine ──

    #[test]
    fn update_state_machine() {
        let svc = StepFunctionsService::new(make_state());
        let arn = create_sm(&svc, "upd-sm");

        let new_def = r#"{"StartAt":"NewPass","States":{"NewPass":{"Type":"Pass","End":true}}}"#;
        let body = json!({
            "stateMachineArn": arn,
            "definition": new_def,
            "description": "updated",
        });
        let req = make_request("UpdateStateMachine", &body.to_string());
        let resp = svc.update_state_machine(&req).unwrap();
        let b = body_json(&resp);
        assert!(b["updateDate"].as_f64().is_some());

        // Verify
        let req = make_request(
            "DescribeStateMachine",
            &json!({"stateMachineArn": arn}).to_string(),
        );
        let resp = svc.describe_state_machine(&req).unwrap();
        let b = body_json(&resp);
        assert!(b["definition"].as_str().unwrap().contains("NewPass"));
        assert_eq!(b["description"], "updated");
    }

    #[test]
    fn update_state_machine_not_found() {
        let svc = StepFunctionsService::new(make_state());
        let body = json!({
            "stateMachineArn": "arn:aws:states:us-east-1:123456789012:stateMachine:nope",
            "definition": VALID_DEF,
        });
        let req = make_request("UpdateStateMachine", &body.to_string());
        let err = expect_err(svc.update_state_machine(&req));
        assert!(err.to_string().contains("StateMachineDoesNotExist"));
    }

    // ── StartExecution ──

    #[tokio::test]
    async fn start_execution_basic() {
        let svc = StepFunctionsService::new(make_state());
        let arn = create_sm(&svc, "exec-sm");

        let body = json!({
            "stateMachineArn": arn,
            "input": r#"{"key":"value"}"#,
        });
        let req = make_request("StartExecution", &body.to_string());
        let resp = svc.start_execution(&req).unwrap();
        let b = body_json(&resp);
        assert!(b["executionArn"].as_str().is_some());
        assert!(b["startDate"].as_f64().is_some());
    }

    #[tokio::test]
    async fn start_execution_with_name() {
        let svc = StepFunctionsService::new(make_state());
        let arn = create_sm(&svc, "named-exec");

        let body = json!({
            "stateMachineArn": arn,
            "name": "my-execution",
        });
        let req = make_request("StartExecution", &body.to_string());
        let resp = svc.start_execution(&req).unwrap();
        let b = body_json(&resp);
        assert!(b["executionArn"].as_str().unwrap().contains("my-execution"));
    }

    #[tokio::test]
    async fn start_execution_sm_not_found() {
        let svc = StepFunctionsService::new(make_state());
        let body = json!({
            "stateMachineArn": "arn:aws:states:us-east-1:123456789012:stateMachine:nope",
        });
        let req = make_request("StartExecution", &body.to_string());
        let err = expect_err(svc.start_execution(&req));
        assert!(err.to_string().contains("StateMachineDoesNotExist"));
    }

    #[tokio::test]
    async fn start_execution_invalid_input() {
        let svc = StepFunctionsService::new(make_state());
        let arn = create_sm(&svc, "bad-input");

        let body = json!({
            "stateMachineArn": arn,
            "input": "not json",
        });
        let req = make_request("StartExecution", &body.to_string());
        let err = expect_err(svc.start_execution(&req));
        assert!(err.to_string().contains("InvalidExecutionInput"));
    }

    #[tokio::test]
    async fn start_execution_duplicate_name() {
        let svc = StepFunctionsService::new(make_state());
        let arn = create_sm(&svc, "dup-exec");

        let body = json!({
            "stateMachineArn": arn,
            "name": "same-name",
        });
        let req = make_request("StartExecution", &body.to_string());
        svc.start_execution(&req).unwrap();

        let req = make_request("StartExecution", &body.to_string());
        let err = expect_err(svc.start_execution(&req));
        assert!(err.to_string().contains("ExecutionAlreadyExists"));
    }

    // ── DescribeExecution ──

    #[tokio::test]
    async fn describe_execution_found() {
        let svc = StepFunctionsService::new(make_state());
        let sm_arn = create_sm(&svc, "desc-exec");

        let body = json!({"stateMachineArn": sm_arn, "name": "e1"});
        let req = make_request("StartExecution", &body.to_string());
        let resp = svc.start_execution(&req).unwrap();
        let exec_arn = body_json(&resp)["executionArn"]
            .as_str()
            .unwrap()
            .to_string();

        let req = make_request(
            "DescribeExecution",
            &json!({"executionArn": exec_arn}).to_string(),
        );
        let resp = svc.describe_execution(&req).unwrap();
        let b = body_json(&resp);
        assert_eq!(b["name"], "e1");
        assert_eq!(b["status"], "RUNNING");
    }

    #[tokio::test]
    async fn describe_execution_not_found() {
        let svc = StepFunctionsService::new(make_state());
        let req = make_request(
            "DescribeExecution",
            &json!({"executionArn": "arn:aws:states:us-east-1:123456789012:execution:sm:nope"})
                .to_string(),
        );
        let err = expect_err(svc.describe_execution(&req));
        assert!(err.to_string().contains("ExecutionDoesNotExist"));
    }

    // ── StopExecution ──

    #[tokio::test]
    async fn stop_execution() {
        let svc = StepFunctionsService::new(make_state());
        let sm_arn = create_sm(&svc, "stop-sm");

        let body = json!({"stateMachineArn": sm_arn, "name": "stop-e"});
        let req = make_request("StartExecution", &body.to_string());
        let resp = svc.start_execution(&req).unwrap();
        let exec_arn = body_json(&resp)["executionArn"]
            .as_str()
            .unwrap()
            .to_string();

        let body = json!({
            "executionArn": exec_arn,
            "error": "UserAborted",
            "cause": "test stop",
        });
        let req = make_request("StopExecution", &body.to_string());
        let resp = svc.stop_execution(&req).unwrap();
        let b = body_json(&resp);
        assert!(b["stopDate"].as_f64().is_some());

        // Verify aborted
        let req = make_request(
            "DescribeExecution",
            &json!({"executionArn": exec_arn}).to_string(),
        );
        let resp = svc.describe_execution(&req).unwrap();
        let b = body_json(&resp);
        assert_eq!(b["status"], "ABORTED");
        assert_eq!(b["error"], "UserAborted");
    }

    #[tokio::test]
    async fn stop_execution_not_found() {
        let svc = StepFunctionsService::new(make_state());
        let req = make_request(
            "StopExecution",
            &json!({"executionArn": "arn:aws:states:us-east-1:123456789012:execution:sm:nope"})
                .to_string(),
        );
        let err = expect_err(svc.stop_execution(&req));
        assert!(err.to_string().contains("ExecutionDoesNotExist"));
    }

    // ── ListExecutions ──

    #[tokio::test]
    async fn list_executions() {
        let svc = StepFunctionsService::new(make_state());
        let sm_arn = create_sm(&svc, "list-exec");

        for i in 0..3 {
            let body = json!({"stateMachineArn": sm_arn, "name": format!("e{i}")});
            let req = make_request("StartExecution", &body.to_string());
            svc.start_execution(&req).unwrap();
        }

        let req = make_request(
            "ListExecutions",
            &json!({"stateMachineArn": sm_arn}).to_string(),
        );
        let resp = svc.list_executions(&req).unwrap();
        let b = body_json(&resp);
        assert_eq!(b["executions"].as_array().unwrap().len(), 3);
    }

    #[tokio::test]
    async fn list_executions_sm_not_found() {
        let svc = StepFunctionsService::new(make_state());
        let req = make_request(
            "ListExecutions",
            &json!({"stateMachineArn": "arn:aws:states:us-east-1:123456789012:stateMachine:nope"})
                .to_string(),
        );
        let err = expect_err(svc.list_executions(&req));
        assert!(err.to_string().contains("StateMachineDoesNotExist"));
    }

    // ── GetExecutionHistory ──

    #[tokio::test]
    async fn get_execution_history_not_found() {
        let svc = StepFunctionsService::new(make_state());
        let req = make_request(
            "GetExecutionHistory",
            &json!({"executionArn": "arn:aws:states:us-east-1:123456789012:execution:sm:nope"})
                .to_string(),
        );
        let err = expect_err(svc.get_execution_history(&req));
        assert!(err.to_string().contains("ExecutionDoesNotExist"));
    }

    // ── DescribeStateMachineForExecution ──

    #[tokio::test]
    async fn describe_sm_for_execution() {
        let svc = StepFunctionsService::new(make_state());
        let sm_arn = create_sm(&svc, "sm-for-exec");

        let body = json!({"stateMachineArn": sm_arn, "name": "e1"});
        let req = make_request("StartExecution", &body.to_string());
        let resp = svc.start_execution(&req).unwrap();
        let exec_arn = body_json(&resp)["executionArn"]
            .as_str()
            .unwrap()
            .to_string();

        let req = make_request(
            "DescribeStateMachineForExecution",
            &json!({"executionArn": exec_arn}).to_string(),
        );
        let resp = svc.describe_state_machine_for_execution(&req).unwrap();
        let b = body_json(&resp);
        assert_eq!(b["name"], "sm-for-exec");
    }

    // ── Tags ──

    #[test]
    fn tag_untag_list_tags() {
        let svc = StepFunctionsService::new(make_state());
        let arn = create_sm(&svc, "tagged-sm");

        // Tag
        let body = json!({
            "resourceArn": arn,
            "tags": [{"key": "env", "value": "prod"}],
        });
        let req = make_request("TagResource", &body.to_string());
        svc.tag_resource(&req).unwrap();

        // List
        let req = make_request(
            "ListTagsForResource",
            &json!({"resourceArn": arn}).to_string(),
        );
        let resp = svc.list_tags_for_resource(&req).unwrap();
        let b = body_json(&resp);
        let tags = b["tags"].as_array().unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0]["key"], "env");

        // Untag
        let body = json!({
            "resourceArn": arn,
            "tagKeys": ["env"],
        });
        let req = make_request("UntagResource", &body.to_string());
        svc.untag_resource(&req).unwrap();

        // Verify empty
        let req = make_request(
            "ListTagsForResource",
            &json!({"resourceArn": arn}).to_string(),
        );
        let resp = svc.list_tags_for_resource(&req).unwrap();
        let b = body_json(&resp);
        assert!(b["tags"].as_array().unwrap().is_empty());
    }

    #[test]
    fn tag_resource_not_found() {
        let svc = StepFunctionsService::new(make_state());
        let body = json!({
            "resourceArn": "arn:aws:states:us-east-1:123456789012:stateMachine:nope",
            "tags": [{"key": "k", "value": "v"}],
        });
        let req = make_request("TagResource", &body.to_string());
        let err = expect_err(svc.tag_resource(&req));
        assert!(err.to_string().contains("ResourceNotFound"));
    }

    // ── Helper function tests ──

    #[test]
    fn test_validate_name() {
        assert!(validate_name("valid-name").is_ok());
        assert!(validate_name("under_score").is_ok());
        assert!(validate_name("").is_err());
        assert!(validate_name("has spaces").is_err());
        assert!(validate_name(&"a".repeat(81)).is_err());
    }

    #[test]
    fn test_validate_definition() {
        assert!(validate_definition(VALID_DEF).is_ok());
        assert!(validate_definition("not json").is_err());
        assert!(validate_definition(r#"{"States":{}}"#).is_err()); // missing StartAt
        assert!(validate_definition(r#"{"StartAt":"S"}"#).is_err()); // missing States
    }

    #[test]
    fn test_validate_arn() {
        assert!(validate_arn("arn:aws:states:us-east-1:123:sm:test").is_ok());
        assert!(validate_arn("not-an-arn").is_err());
    }

    #[test]
    fn test_camel_to_details_key() {
        assert_eq!(camel_to_details_key("PassStateEntered"), "passStateEntered");
        assert_eq!(camel_to_details_key(""), "");
    }

    #[test]
    fn test_is_mutating_action() {
        assert!(is_mutating_action("CreateStateMachine"));
        assert!(is_mutating_action("StartExecution"));
        assert!(!is_mutating_action("DescribeStateMachine"));
        assert!(!is_mutating_action("ListStateMachines"));
    }

    // ── StartSyncExecution ──

    fn create_express_sm(svc: &StepFunctionsService, name: &str) -> String {
        let body = json!({
            "name": name,
            "definition": VALID_DEF,
            "roleArn": "arn:aws:iam::123456789012:role/test",
            "type": "EXPRESS",
        });
        let req = make_request("CreateStateMachine", &body.to_string());
        let resp = svc.create_state_machine(&req).unwrap();
        let b = body_json(&resp);
        b["stateMachineArn"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn start_sync_execution_basic() {
        let svc = StepFunctionsService::new(make_state());
        let arn = create_express_sm(&svc, "sync-sm");

        let body = json!({
            "stateMachineArn": arn,
            "input": r#"{"key":"value"}"#,
        });
        let req = make_request("StartSyncExecution", &body.to_string());
        let resp = svc.start_sync_execution(&req).await.unwrap();
        let b = body_json(&resp);
        assert!(b["executionArn"]
            .as_str()
            .unwrap()
            .contains("express:sync-sm"));
        assert_eq!(b["stateMachineArn"], arn);
        assert_eq!(b["status"], "SUCCEEDED");
        assert!(b["startDate"].as_i64().is_some());
        assert!(b["stopDate"].as_i64().is_some());
        assert!(b["output"].as_str().is_some());
        assert!(b["billingDetails"]["billedDurationInMilliseconds"]
            .as_i64()
            .is_some());
    }

    #[tokio::test]
    async fn start_sync_execution_not_express() {
        let svc = StepFunctionsService::new(make_state());
        let arn = create_sm(&svc, "std-sm");

        let body = json!({"stateMachineArn": arn});
        let req = make_request("StartSyncExecution", &body.to_string());
        let err = expect_err(svc.start_sync_execution(&req).await);
        assert!(err.to_string().contains("StateMachineTypeNotSupported"));
    }

    #[tokio::test]
    async fn start_sync_execution_sm_not_found() {
        let svc = StepFunctionsService::new(make_state());
        let body = json!({
            "stateMachineArn": "arn:aws:states:us-east-1:123456789012:stateMachine:nope",
        });
        let req = make_request("StartSyncExecution", &body.to_string());
        let err = expect_err(svc.start_sync_execution(&req).await);
        assert!(err.to_string().contains("StateMachineDoesNotExist"));
    }

    #[tokio::test]
    async fn start_sync_execution_records_introspection_fields() {
        let svc = StepFunctionsService::new(make_state());
        let arn = create_express_sm(&svc, "sync-introspect");

        let body = json!({"stateMachineArn": arn, "input": "{}"});
        let req = make_request("StartSyncExecution", &body.to_string());
        let resp = svc.start_sync_execution(&req).await.unwrap();
        let b = body_json(&resp);
        let exec_arn = b["executionArn"].as_str().unwrap().to_string();

        let accounts = svc.state.read();
        let state = accounts.get("123456789012").unwrap();
        let stored = state
            .executions
            .get(&exec_arn)
            .expect("sync execution should be persisted for introspection");
        assert!(stored.is_sync, "sync executions must be marked is_sync");
        assert_eq!(stored.billed_memory_mb, Some(64));
        assert!(
            stored.billed_duration_ms.is_some(),
            "billed_duration_ms must be populated after sync run"
        );
        assert!(
            stored.parent_execution_arn.is_none(),
            "top-level sync execution has no parent"
        );
    }

    #[tokio::test]
    async fn start_sync_execution_invalid_input() {
        let svc = StepFunctionsService::new(make_state());
        let arn = create_express_sm(&svc, "bad-input-sync");

        let body = json!({
            "stateMachineArn": arn,
            "input": "not json",
        });
        let req = make_request("StartSyncExecution", &body.to_string());
        let err = expect_err(svc.start_sync_execution(&req).await);
        assert!(err.to_string().contains("InvalidExecutionInput"));
    }
}
