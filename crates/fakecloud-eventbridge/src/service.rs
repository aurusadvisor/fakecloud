use async_trait::async_trait;
use chrono::{DateTime, Utc};
use http::StatusCode;
use serde_json::{json, Value};

use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;

use tokio::sync::Mutex as AsyncMutex;

use fakecloud_aws::arn::Arn;
use fakecloud_core::delivery::DeliveryBus;
use fakecloud_core::pagination::paginate;
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
use fakecloud_core::validation::*;
use fakecloud_persistence::SnapshotStore;

use fakecloud_lambda::runtime::ContainerRuntime;
use fakecloud_lambda::state::{LambdaInvocation, SharedLambdaState};
use fakecloud_logs::state::SharedLogsState;

use crate::state::{
    ApiDestination, Archive, Connection, Endpoint, EventBridgeSnapshot, EventBridgeState, EventBus,
    EventRule, EventTarget, PartnerEventSource, PutEvent, Replay, SharedEventBridgeState,
    EVENTBRIDGE_SNAPSHOT_SCHEMA_VERSION,
};

pub struct EventBridgeService {
    state: SharedEventBridgeState,
    delivery: Arc<DeliveryBus>,
    lambda_state: Option<SharedLambdaState>,
    logs_state: Option<SharedLogsState>,
    container_runtime: Option<Arc<ContainerRuntime>>,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    snapshot_lock: Arc<AsyncMutex<()>>,
}

impl EventBridgeService {
    pub fn new(state: SharedEventBridgeState, delivery: Arc<DeliveryBus>) -> Self {
        Self {
            state,
            delivery,
            lambda_state: None,
            logs_state: None,
            container_runtime: None,
            snapshot_store: None,
            snapshot_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    pub fn with_lambda(mut self, lambda_state: SharedLambdaState) -> Self {
        self.lambda_state = Some(lambda_state);
        self
    }

    pub fn with_logs(mut self, logs_state: SharedLogsState) -> Self {
        self.logs_state = Some(logs_state);
        self
    }

    pub fn with_runtime(mut self, runtime: Arc<ContainerRuntime>) -> Self {
        self.container_runtime = Some(runtime);
        self
    }

    pub fn with_snapshot_store(mut self, store: Arc<dyn SnapshotStore>) -> Self {
        self.snapshot_store = Some(store);
        self
    }

    /// Persist current state as a snapshot. Held across the
    /// clone-serialize-write sequence to prevent stale-last writes,
    /// with serde + file I/O offloaded to the blocking pool.
    async fn save_snapshot(&self) {
        let Some(store) = self.snapshot_store.clone() else {
            return;
        };
        let _guard = self.snapshot_lock.lock().await;
        let snapshot = EventBridgeSnapshot {
            schema_version: EVENTBRIDGE_SNAPSHOT_SCHEMA_VERSION,
            accounts: Some(self.state.read().clone()),
            state: None,
        };
        let join = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let bytes = serde_json::to_vec(&snapshot)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            store.save(&bytes)
        })
        .await;
        match join {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(%err, "failed to write eventbridge snapshot"),
            Err(err) => tracing::error!(%err, "eventbridge snapshot task panicked"),
        }
    }
}

#[async_trait]
impl AwsService for EventBridgeService {
    fn service_name(&self) -> &str {
        "events"
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mutates = is_mutating_action(req.action.as_str());
        let result = match req.action.as_str() {
            "CreateEventBus" => self.create_event_bus(&req),
            "DeleteEventBus" => self.delete_event_bus(&req),
            "ListEventBuses" => self.list_event_buses(&req),
            "DescribeEventBus" => self.describe_event_bus(&req),
            "PutRule" => self.put_rule(&req),
            "DeleteRule" => self.delete_rule(&req),
            "ListRules" => self.list_rules(&req),
            "DescribeRule" => self.describe_rule(&req),
            "EnableRule" => self.enable_rule(&req),
            "DisableRule" => self.disable_rule(&req),
            "PutTargets" => self.put_targets(&req),
            "RemoveTargets" => self.remove_targets(&req),
            "ListTargetsByRule" => self.list_targets_by_rule(&req),
            "ListRuleNamesByTarget" => self.list_rule_names_by_target(&req),
            "PutEvents" => self.put_events(&req),
            "PutPermission" => self.put_permission(&req),
            "RemovePermission" => self.remove_permission(&req),
            "TagResource" => self.tag_resource(&req),
            "UntagResource" => self.untag_resource(&req),
            "ListTagsForResource" => self.list_tags_for_resource(&req),
            "CreateArchive" => self.create_archive(&req),
            "DescribeArchive" => self.describe_archive(&req),
            "ListArchives" => self.list_archives(&req),
            "UpdateArchive" => self.update_archive(&req),
            "DeleteArchive" => self.delete_archive(&req),
            "CreateConnection" => self.create_connection(&req),
            "DescribeConnection" => self.describe_connection(&req),
            "ListConnections" => self.list_connections(&req),
            "UpdateConnection" => self.update_connection(&req),
            "DeleteConnection" => self.delete_connection(&req),
            "CreateApiDestination" => self.create_api_destination(&req),
            "DescribeApiDestination" => self.describe_api_destination(&req),
            "ListApiDestinations" => self.list_api_destinations(&req),
            "UpdateApiDestination" => self.update_api_destination(&req),
            "DeleteApiDestination" => self.delete_api_destination(&req),
            "StartReplay" => self.start_replay(&req),
            "DescribeReplay" => self.describe_replay(&req),
            "ListReplays" => self.list_replays(&req),
            "CancelReplay" => self.cancel_replay(&req),
            "CreatePartnerEventSource" => self.create_partner_event_source(&req),
            "DeletePartnerEventSource" => self.delete_partner_event_source(&req),
            "DescribePartnerEventSource" => self.describe_partner_event_source(&req),
            "ListPartnerEventSources" => self.list_partner_event_sources(&req),
            "ListPartnerEventSourceAccounts" => self.list_partner_event_source_accounts(&req),
            "ActivateEventSource" => self.activate_event_source(&req),
            "DeactivateEventSource" => self.deactivate_event_source(&req),
            "DescribeEventSource" => self.describe_event_source(&req),
            "ListEventSources" => self.list_event_sources(&req),
            "PutPartnerEvents" => self.put_partner_events(&req),
            "TestEventPattern" => self.test_event_pattern(&req),
            "UpdateEventBus" => self.update_event_bus(&req),
            "CreateEndpoint" => self.create_endpoint(&req),
            "DeleteEndpoint" => self.delete_endpoint(&req),
            "DescribeEndpoint" => self.describe_endpoint(&req),
            "ListEndpoints" => self.list_endpoints(&req),
            "UpdateEndpoint" => self.update_endpoint(&req),
            "DeauthorizeConnection" => self.deauthorize_connection(&req),
            _ => Err(AwsServiceError::action_not_implemented(
                "events",
                &req.action,
            )),
        };
        if mutates && matches!(result.as_ref(), Ok(resp) if resp.status.is_success()) {
            self.save_snapshot().await;
        }
        result
    }

    fn supported_actions(&self) -> &[&str] {
        &[
            "CreateEventBus",
            "DeleteEventBus",
            "ListEventBuses",
            "DescribeEventBus",
            "PutRule",
            "DeleteRule",
            "ListRules",
            "DescribeRule",
            "EnableRule",
            "DisableRule",
            "PutTargets",
            "RemoveTargets",
            "ListTargetsByRule",
            "ListRuleNamesByTarget",
            "PutEvents",
            "PutPermission",
            "RemovePermission",
            "TagResource",
            "UntagResource",
            "ListTagsForResource",
            "CreateArchive",
            "DescribeArchive",
            "ListArchives",
            "UpdateArchive",
            "DeleteArchive",
            "CreateConnection",
            "DescribeConnection",
            "ListConnections",
            "UpdateConnection",
            "DeleteConnection",
            "CreateApiDestination",
            "DescribeApiDestination",
            "ListApiDestinations",
            "UpdateApiDestination",
            "DeleteApiDestination",
            "StartReplay",
            "DescribeReplay",
            "ListReplays",
            "CancelReplay",
            "CreatePartnerEventSource",
            "DeletePartnerEventSource",
            "DescribePartnerEventSource",
            "ListPartnerEventSources",
            "ListPartnerEventSourceAccounts",
            "ActivateEventSource",
            "DeactivateEventSource",
            "DescribeEventSource",
            "ListEventSources",
            "PutPartnerEvents",
            "TestEventPattern",
            "UpdateEventBus",
            "CreateEndpoint",
            "DeleteEndpoint",
            "DescribeEndpoint",
            "ListEndpoints",
            "UpdateEndpoint",
            "DeauthorizeConnection",
        ]
    }
}

// ─── Event Bus Operations ───────────────────────────────────────────
impl EventBridgeService {
    fn create_event_bus(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"]
            .as_str()
            .ok_or_else(|| missing("Name"))?
            .to_string();
        validate_string_length("name", &name, 1, 256)?;
        validate_optional_string_length(
            "eventSourceName",
            body["EventSourceName"].as_str(),
            1,
            256,
        )?;
        validate_optional_string_length("description", body["Description"].as_str(), 0, 512)?;
        validate_optional_string_length(
            "kmsKeyIdentifier",
            body["KmsKeyIdentifier"].as_str(),
            0,
            2048,
        )?;

        // Validate name doesn't contain '/' (unless partner bus)
        if name.contains('/') && !name.starts_with("aws.partner/") {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "Event bus name must not contain '/'.",
            ));
        }

        // Partner event bus validation
        if name.starts_with("aws.partner/") {
            let event_source = body["EventSourceName"].as_str().unwrap_or("");
            let accounts_r = self.state.read();
            let empty_r = EventBridgeState::new(&req.account_id, &req.region);
            let state_r = accounts_r.get(&req.account_id).unwrap_or(&empty_r);
            let has_source = state_r.partner_event_sources.contains_key(event_source);
            drop(accounts_r);
            if !has_source {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ResourceNotFoundException",
                    format!("Event source {event_source} does not exist."),
                ));
            }
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        if state.buses.contains_key(&name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceAlreadyExistsException",
                format!("Event bus {name} already exists."),
            ));
        }

        let arn = format!(
            "arn:aws:events:{}:{}:event-bus/{}",
            req.region, state.account_id, name
        );
        let now = Utc::now();
        let description = body["Description"].as_str().map(|s| s.to_string());
        let kms_key_identifier = body["KmsKeyIdentifier"].as_str().map(|s| s.to_string());
        let dead_letter_config = body.get("DeadLetterConfig").cloned();

        let tags = parse_tags(&body);

        let bus = EventBus {
            name: name.clone(),
            arn: arn.clone(),
            tags,
            policy: None,
            description,
            kms_key_identifier,
            dead_letter_config,
            creation_time: now,
            last_modified_time: now,
        };
        state.buses.insert(name, bus);

        Ok(AwsResponse::ok_json(json!({ "EventBusArn": arn })))
    }

    fn delete_event_bus(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;
        validate_string_length("name", name, 1, 256)?;

        if name == "default" {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                format!("Cannot delete event bus {name}."),
            ));
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state.buses.remove(name);
        state.rules.retain(|k, _| k.0 != name);

        Ok(AwsResponse::ok_json(json!({})))
    }

    fn list_event_buses(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_optional_string_length("namePrefix", body["NamePrefix"].as_str(), 1, 256)?;
        validate_optional_string_length("nextToken", body["NextToken"].as_str(), 1, 2048)?;
        validate_optional_range_i64("limit", body["Limit"].as_i64(), 1, 100)?;
        let name_prefix = body["NamePrefix"].as_str();
        let limit = body["Limit"].as_i64().unwrap_or(100) as usize;
        if let Some(t) = body["NextToken"].as_str() {
            t.parse::<usize>().map_err(|_| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidNextTokenException",
                    format!("Invalid NextToken value: '{t}'"),
                )
            })?;
        }

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let filtered: Vec<&_> = state
            .buses
            .values()
            .filter(|b| match name_prefix {
                Some(prefix) => b.name.starts_with(prefix),
                None => true,
            })
            .collect();

        let (page, next_token) = paginate(&filtered, body["NextToken"].as_str(), limit);
        let buses: Vec<Value> = page
            .iter()
            .map(|b| json!({ "Name": b.name, "Arn": b.arn }))
            .collect();
        let mut resp = json!({ "EventBuses": buses });
        if let Some(token) = next_token {
            resp["NextToken"] = json!(token);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    fn describe_event_bus(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_optional_string_length("name", body["Name"].as_str(), 1, 1600)?;
        let name = body["Name"].as_str().unwrap_or("default");

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let bus = state.buses.get(name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Event bus {name} does not exist."),
            )
        })?;

        let mut resp = json!({
            "Name": bus.name,
            "Arn": bus.arn,
            "CreationTime": bus.creation_time.timestamp() as f64,
            "LastModifiedTime": bus.last_modified_time.timestamp() as f64,
        });

        if let Some(ref policy) = bus.policy {
            resp["Policy"] = Value::String(serde_json::to_string(policy).unwrap());
        }
        if let Some(ref desc) = bus.description {
            resp["Description"] = json!(desc);
        }
        if let Some(ref kms) = bus.kms_key_identifier {
            resp["KmsKeyIdentifier"] = json!(kms);
        }
        if let Some(ref dlc) = bus.dead_letter_config {
            resp["DeadLetterConfig"] = dlc.clone();
        }

        Ok(AwsResponse::ok_json(resp))
    }

    // ─── Permission Operations ──────────────────────────────────────────

    fn put_permission(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_optional_string_length("eventBusName", body["EventBusName"].as_str(), 1, 256)?;
        validate_optional_string_length("action", body["Action"].as_str(), 1, 64)?;
        validate_optional_string_length("principal", body["Principal"].as_str(), 1, 12)?;
        validate_optional_string_length("statementId", body["StatementId"].as_str(), 1, 64)?;
        let event_bus_name = body["EventBusName"].as_str().unwrap_or("default");

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        let bus = state.buses.get_mut(event_bus_name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Event bus {event_bus_name} does not exist."),
            )
        })?;

        // Check if Policy is provided (new-style)
        if let Some(policy_str) = body["Policy"].as_str() {
            if let Ok(policy) = serde_json::from_str::<Value>(policy_str) {
                bus.policy = Some(policy);
                return Ok(AwsResponse::ok_json(json!({})));
            }
        }

        // Old-style: Action, Principal, StatementId
        let action = body["Action"].as_str().unwrap_or("");
        let principal = body["Principal"].as_str().unwrap_or("");
        let statement_id = body["StatementId"].as_str().unwrap_or("");

        // Validate action
        if action != "events:PutEvents" {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "Provided value in parameter 'action' is not supported.",
            ));
        }

        let statement = json!({
            "Sid": statement_id,
            "Effect": "Allow",
            "Principal": { "AWS": Arn::global("iam", principal, "root").to_string() },
            "Action": action,
            "Resource": bus.arn,
        });

        let policy = bus.policy.get_or_insert_with(|| {
            json!({
                "Version": "2012-10-17",
                "Statement": [],
            })
        });

        if let Some(stmts) = policy["Statement"].as_array_mut() {
            stmts.push(statement);
        }

        Ok(AwsResponse::ok_json(json!({})))
    }

    fn remove_permission(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_optional_string_length("statementId", body["StatementId"].as_str(), 1, 64)?;
        validate_optional_string_length("eventBusName", body["EventBusName"].as_str(), 1, 256)?;
        let event_bus_name = body["EventBusName"].as_str().unwrap_or("default");
        let statement_id = body["StatementId"].as_str().unwrap_or("");
        let remove_all = body["RemoveAllPermissions"].as_bool().unwrap_or(false);

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        let bus = state.buses.get_mut(event_bus_name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Event bus {event_bus_name} does not exist."),
            )
        })?;

        if remove_all {
            bus.policy = None;
            return Ok(AwsResponse::ok_json(json!({})));
        }

        let policy = bus.policy.as_mut().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                "EventBus does not have a policy.",
            )
        })?;

        if let Some(stmts) = policy["Statement"].as_array_mut() {
            let before = stmts.len();
            stmts.retain(|s| s["Sid"].as_str() != Some(statement_id));
            if stmts.len() == before {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ResourceNotFoundException",
                    "Statement with the provided id does not exist.",
                ));
            }
            if stmts.is_empty() {
                bus.policy = None;
            }
        }

        Ok(AwsResponse::ok_json(json!({})))
    }

    // ─── Rule Operations ────────────────────────────────────────────────

    fn put_rule(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"]
            .as_str()
            .ok_or_else(|| missing("Name"))?
            .to_string();
        validate_string_length("name", &name, 1, 64)?;
        validate_optional_string_length("eventBusName", body["EventBusName"].as_str(), 1, 1600)?;
        validate_optional_string_length(
            "scheduleExpression",
            body["ScheduleExpression"].as_str(),
            0,
            256,
        )?;
        validate_optional_string_length("eventPattern", body["EventPattern"].as_str(), 0, 4096)?;
        validate_optional_enum(
            "state",
            body["State"].as_str(),
            &[
                "ENABLED",
                "DISABLED",
                "ENABLED_WITH_ALL_CLOUDTRAIL_MANAGEMENT_EVENTS",
            ],
        )?;
        validate_optional_string_length("description", body["Description"].as_str(), 0, 512)?;
        validate_optional_string_length("roleArn", body["RoleArn"].as_str(), 1, 1600)?;

        let raw_bus = body["EventBusName"]
            .as_str()
            .unwrap_or("default")
            .to_string();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let event_bus_name = state.resolve_bus_name(&raw_bus);

        let event_pattern = body["EventPattern"].as_str().and_then(|s| {
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        });
        let schedule_expression = body["ScheduleExpression"].as_str().and_then(|s| {
            if s.is_empty() {
                None
            } else {
                Some(s.to_string())
            }
        });
        let description = body["Description"].as_str().map(|s| s.to_string());
        let role_arn = body["RoleArn"].as_str().map(|s| s.to_string());
        let rule_state = body["State"].as_str().unwrap_or("ENABLED").to_string();

        // Validate: schedule expressions only on default bus
        if schedule_expression.is_some() && event_bus_name != "default" {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "ScheduleExpression is supported only on the default event bus.",
            ));
        }

        if !state.buses.contains_key(&event_bus_name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Event bus {event_bus_name} does not exist."),
            ));
        }

        let arn = if event_bus_name == "default" {
            format!(
                "arn:aws:events:{}:{}:rule/{}",
                req.region, state.account_id, name
            )
        } else {
            format!(
                "arn:aws:events:{}:{}:rule/{}/{}",
                req.region, state.account_id, event_bus_name, name
            )
        };

        let key = (event_bus_name.clone(), name.clone());
        let targets = state
            .rules
            .get(&key)
            .map(|r| r.targets.clone())
            .unwrap_or_default();

        let tags = parse_tags(&body);

        let rule = EventRule {
            name: name.clone(),
            arn: arn.clone(),
            event_bus_name,
            event_pattern,
            schedule_expression,
            state: rule_state,
            description,
            role_arn,
            managed_by: None,
            created_by: None,
            targets,
            tags,
            last_fired: None,
        };

        state.rules.insert(key, rule);
        Ok(AwsResponse::ok_json(json!({ "RuleArn": arn })))
    }

    fn delete_rule(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;
        validate_string_length("name", name, 1, 64)?;
        validate_optional_string_length("eventBusName", body["EventBusName"].as_str(), 1, 1600)?;
        let event_bus_name = body["EventBusName"].as_str().unwrap_or("default");

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let bus_name = state.resolve_bus_name(event_bus_name);
        let key = (bus_name, name.to_string());

        // Check if rule has targets
        if let Some(rule) = state.rules.get(&key) {
            if !rule.targets.is_empty() {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "Rule can't be deleted since it has targets.",
                ));
            }
        }

        state.rules.remove(&key);
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn list_rules(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_optional_string_length("namePrefix", body["NamePrefix"].as_str(), 1, 64)?;
        validate_optional_string_length("eventBusName", body["EventBusName"].as_str(), 1, 1600)?;
        validate_optional_string_length("nextToken", body["NextToken"].as_str(), 1, 2048)?;
        validate_optional_range_i64("limit", body["Limit"].as_i64(), 1, 100)?;
        let event_bus_name = body["EventBusName"].as_str().unwrap_or("default");
        let name_prefix = body["NamePrefix"].as_str();
        let limit = body["Limit"].as_u64().map(|n| n as usize);
        let next_token = body["NextToken"].as_str();

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let bus_name = state.resolve_bus_name(event_bus_name);

        let mut rules: Vec<&EventRule> = state
            .rules
            .values()
            .filter(|r| r.event_bus_name == bus_name)
            .filter(|r| match name_prefix {
                Some(prefix) => r.name.starts_with(prefix),
                None => true,
            })
            .collect();
        rules.sort_by(|a, b| a.name.cmp(&b.name));

        // Pagination
        let start = next_token
            .and_then(|t| t.parse::<usize>().ok())
            .unwrap_or(0)
            .min(rules.len());
        let rules_slice = &rules[start..];

        let (page, new_next_token) = if let Some(lim) = limit {
            if rules_slice.len() > lim {
                (&rules_slice[..lim], Some((start + lim).to_string()))
            } else {
                (rules_slice, None)
            }
        } else {
            (rules_slice, None)
        };

        let rules_json: Vec<Value> = page
            .iter()
            .map(|r| {
                let mut obj = json!({
                    "Name": r.name,
                    "Arn": r.arn,
                    "EventBusName": r.event_bus_name,
                    "State": r.state,
                });
                if let Some(ref desc) = r.description {
                    obj["Description"] = json!(desc);
                }
                if let Some(ref ep) = r.event_pattern {
                    obj["EventPattern"] = json!(ep);
                }
                if let Some(ref se) = r.schedule_expression {
                    obj["ScheduleExpression"] = json!(se);
                }
                if let Some(ref mb) = r.managed_by {
                    obj["ManagedBy"] = json!(mb);
                }
                obj
            })
            .collect();

        let mut resp = json!({ "Rules": rules_json });
        if let Some(token) = new_next_token {
            resp["NextToken"] = json!(token);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    fn describe_rule(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;
        validate_string_length("name", name, 1, 64)?;
        validate_optional_string_length("eventBusName", body["EventBusName"].as_str(), 1, 1600)?;
        let event_bus_name = body["EventBusName"].as_str().unwrap_or("default");

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let bus_name = state.resolve_bus_name(event_bus_name);
        let key = (bus_name.clone(), name.to_string());

        let rule = state.rules.get(&key).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Rule {name} does not exist."),
            )
        })?;

        let mut resp = json!({
            "Name": rule.name,
            "Arn": rule.arn,
            "EventBusName": rule.event_bus_name,
            "State": rule.state,
        });

        if let Some(ref desc) = rule.description {
            resp["Description"] = json!(desc);
        }
        if let Some(ref ep) = rule.event_pattern {
            resp["EventPattern"] = json!(ep);
        }
        if let Some(ref se) = rule.schedule_expression {
            resp["ScheduleExpression"] = json!(se);
        }
        if let Some(ref role) = rule.role_arn {
            resp["RoleArn"] = json!(role);
        }
        if let Some(ref mb) = rule.managed_by {
            resp["ManagedBy"] = json!(mb);
        }
        if let Some(ref cb) = rule.created_by {
            resp["CreatedBy"] = json!(cb);
        }
        // If non-default bus, set CreatedBy to account_id
        if rule.event_bus_name != "default" && rule.created_by.is_none() {
            resp["CreatedBy"] = json!(state.account_id);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    fn enable_rule(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;
        validate_string_length("name", name, 1, 64)?;
        validate_optional_string_length("eventBusName", body["EventBusName"].as_str(), 1, 1600)?;
        let event_bus_name = body["EventBusName"].as_str().unwrap_or("default");

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let bus_name = state.resolve_bus_name(event_bus_name);
        let key = (bus_name, name.to_string());

        let rule = state.rules.get_mut(&key).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Rule {name} does not exist."),
            )
        })?;

        rule.state = "ENABLED".to_string();
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn disable_rule(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;
        validate_string_length("name", name, 1, 64)?;
        validate_optional_string_length("eventBusName", body["EventBusName"].as_str(), 1, 1600)?;
        let event_bus_name = body["EventBusName"].as_str().unwrap_or("default");

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let bus_name = state.resolve_bus_name(event_bus_name);
        let key = (bus_name, name.to_string());

        let rule = state.rules.get_mut(&key).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Rule {name} does not exist."),
            )
        })?;

        rule.state = "DISABLED".to_string();
        Ok(AwsResponse::ok_json(json!({})))
    }

    // ─── Target Operations ──────────────────────────────────────────────

    fn put_targets(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Rule", &body["Rule"])?;
        let rule_name = body["Rule"].as_str().ok_or_else(|| missing("Rule"))?;
        validate_string_length("rule", rule_name, 1, 64)?;
        validate_optional_string_length("eventBusName", body["EventBusName"].as_str(), 1, 1600)?;
        validate_required("Targets", &body["Targets"])?;
        let event_bus_name = body["EventBusName"].as_str().unwrap_or("default");
        let targets = body["Targets"]
            .as_array()
            .ok_or_else(|| missing("Targets"))?;

        // Validate targets - check for FIFO SQS without SqsParameters
        for target in targets {
            let target_id = target["Id"].as_str().unwrap_or("");
            let target_arn = target["Arn"].as_str().unwrap_or("");

            if target_arn.ends_with(".fifo") && target.get("SqsParameters").is_none() {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    format!(
                        "Parameter(s) SqsParameters must be specified for target: {target_id}."
                    ),
                ));
            }

            // Validate ARN format
            if !target_arn.starts_with("arn:") {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    format!(
                        "Parameter {target_arn} is not valid. Reason: Provided Arn is not in correct format."
                    ),
                ));
            }
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let bus_name = state.resolve_bus_name(event_bus_name);
        let key = (bus_name.clone(), rule_name.to_string());

        let rule = state.rules.get_mut(&key).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Rule {rule_name} does not exist on EventBus {bus_name}."),
            )
        })?;

        for target in targets {
            let et = parse_target(target);
            // Remove existing target with same ID
            rule.targets.retain(|t| t.id != et.id);
            rule.targets.push(et);
        }

        Ok(AwsResponse::ok_json(json!({
            "FailedEntryCount": 0,
            "FailedEntries": [],
        })))
    }

    fn remove_targets(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Rule", &body["Rule"])?;
        let rule_name = body["Rule"].as_str().ok_or_else(|| missing("Rule"))?;
        validate_string_length("rule", rule_name, 1, 64)?;
        validate_optional_string_length("eventBusName", body["EventBusName"].as_str(), 1, 1600)?;
        validate_required("Ids", &body["Ids"])?;
        let event_bus_name = body["EventBusName"].as_str().unwrap_or("default");
        let ids = body["Ids"].as_array().ok_or_else(|| missing("Ids"))?;

        let target_ids: Vec<String> = ids
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let bus_name = state.resolve_bus_name(event_bus_name);
        let key = (bus_name.clone(), rule_name.to_string());

        let rule = state.rules.get_mut(&key).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Rule {rule_name} does not exist on EventBus {bus_name}."),
            )
        })?;

        rule.targets.retain(|t| !target_ids.contains(&t.id));

        Ok(AwsResponse::ok_json(json!({
            "FailedEntryCount": 0,
            "FailedEntries": [],
        })))
    }

    fn list_targets_by_rule(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Rule", &body["Rule"])?;
        let rule_name = body["Rule"].as_str().ok_or_else(|| missing("Rule"))?;
        validate_string_length("rule", rule_name, 1, 64)?;
        validate_optional_string_length("eventBusName", body["EventBusName"].as_str(), 1, 1600)?;
        validate_optional_string_length("nextToken", body["NextToken"].as_str(), 1, 2048)?;
        validate_optional_range_i64("limit", body["Limit"].as_i64(), 1, 100)?;
        let event_bus_name = body["EventBusName"].as_str().unwrap_or("default");
        let limit = body["Limit"].as_u64().map(|n| n as usize);
        let next_token = body["NextToken"].as_str();

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let bus_name = state.resolve_bus_name(event_bus_name);
        let key = (bus_name, rule_name.to_string());

        let rule = state.rules.get(&key).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Rule {rule_name} does not exist."),
            )
        })?;

        let all_targets = &rule.targets;
        let start = next_token
            .and_then(|t| t.parse::<usize>().ok())
            .unwrap_or(0)
            .min(all_targets.len());
        let slice = &all_targets[start..];

        let (page, new_next_token) = if let Some(lim) = limit {
            if slice.len() > lim {
                (&slice[..lim], Some((start + lim).to_string()))
            } else {
                (slice, None)
            }
        } else {
            (slice, None)
        };

        let targets: Vec<Value> = page.iter().map(target_to_json).collect();

        let mut resp = json!({ "Targets": targets });
        if let Some(token) = new_next_token {
            resp["NextToken"] = json!(token);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    fn list_rule_names_by_target(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("TargetArn", &body["TargetArn"])?;
        let target_arn = body["TargetArn"]
            .as_str()
            .ok_or_else(|| missing("TargetArn"))?;
        validate_string_length("targetArn", target_arn, 1, 1600)?;
        validate_optional_string_length("eventBusName", body["EventBusName"].as_str(), 1, 1600)?;
        validate_optional_string_length("nextToken", body["NextToken"].as_str(), 1, 2048)?;
        validate_optional_range_i64("limit", body["Limit"].as_i64(), 1, 100)?;
        let event_bus_name = body["EventBusName"].as_str().unwrap_or("default");
        let limit = body["Limit"].as_u64().map(|n| n as usize);
        let next_token = body["NextToken"].as_str();

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let bus_name = state.resolve_bus_name(event_bus_name);

        // Deduplicate rule names
        let mut rule_names: Vec<String> = Vec::new();
        for rule in state.rules.values() {
            if rule.event_bus_name == bus_name
                && rule.targets.iter().any(|t| t.arn == target_arn)
                && !rule_names.contains(&rule.name)
            {
                rule_names.push(rule.name.clone());
            }
        }
        rule_names.sort();

        let start = next_token
            .and_then(|t| t.parse::<usize>().ok())
            .unwrap_or(0)
            .min(rule_names.len());
        let slice = &rule_names[start..];

        let (page, new_next_token) = if let Some(lim) = limit {
            if slice.len() > lim {
                (&slice[..lim], Some((start + lim).to_string()))
            } else {
                (slice, None)
            }
        } else {
            (slice, None)
        };

        let mut resp = json!({ "RuleNames": page });
        if let Some(token) = new_next_token {
            resp["NextToken"] = json!(token);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    // ─── Partner Event Sources ────────────���───────────────────────────

    fn create_partner_event_source(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"]
            .as_str()
            .ok_or_else(|| missing("Name"))?
            .to_string();
        validate_string_length("name", &name, 1, 256)?;
        validate_required("Account", &body["Account"])?;
        let account = body["Account"]
            .as_str()
            .ok_or_else(|| missing("Account"))?
            .to_string();
        validate_string_length("account", &account, 12, 12)?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if state.partner_event_sources.contains_key(&name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::CONFLICT,
                "ResourceAlreadyExistsException",
                format!("Partner event source {name} already exists."),
            ));
        }
        let arn = format!(
            "arn:aws:events:{}::event-source/aws.partner/{}",
            state.region, name
        );
        let now = Utc::now();
        let ps = PartnerEventSource {
            name: name.clone(),
            arn: arn.clone(),
            account,
            creation_time: now,
            expiration_time: None,
            state: "ACTIVE".to_string(),
        };
        state.partner_event_sources.insert(name.clone(), ps);

        Ok(AwsResponse::ok_json(json!({ "EventSourceArn": arn })))
    }

    fn delete_partner_event_source(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"]
            .as_str()
            .ok_or_else(|| missing("Name"))?
            .to_string();
        validate_required("Account", &body["Account"])?;
        let account = body["Account"]
            .as_str()
            .ok_or_else(|| missing("Account"))?
            .to_string();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        match state.partner_event_sources.get(&name) {
            Some(ps) if ps.account == account => {
                state.partner_event_sources.remove(&name);
            }
            Some(_) => {
                return Err(AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "ResourceNotFoundException",
                    format!("Partner event source {name} does not exist for account {account}."),
                ));
            }
            None => {
                return Err(AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "ResourceNotFoundException",
                    format!("Partner event source {name} does not exist."),
                ));
            }
        }

        Ok(AwsResponse::ok_json(json!({})))
    }

    fn describe_partner_event_source(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"]
            .as_str()
            .ok_or_else(|| missing("Name"))?
            .to_string();
        validate_string_length("name", &name, 1, 256)?;

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let ps = state.partner_event_sources.get(&name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!("Partner event source {name} does not exist."),
            )
        })?;

        Ok(AwsResponse::ok_json(json!({
            "Arn": ps.arn,
            "Name": ps.name,
        })))
    }

    fn list_partner_event_sources(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("namePrefix", &body["NamePrefix"])?;
        let name_prefix = body["NamePrefix"]
            .as_str()
            .ok_or_else(|| missing("NamePrefix"))?;
        validate_string_length("namePrefix", name_prefix, 1, 256)?;
        validate_optional_range_i64("limit", body["Limit"].as_i64(), 1, 100)?;
        validate_optional_string_length("nextToken", body["NextToken"].as_str(), 1, 2048)?;
        let limit = body["Limit"].as_i64().unwrap_or(100) as usize;

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let all: Vec<Value> = state
            .partner_event_sources
            .values()
            .filter(|ps| ps.name.starts_with(name_prefix))
            .map(|ps| {
                json!({
                    "Arn": ps.arn,
                    "Name": ps.name,
                })
            })
            .collect();

        let (sources, next_token) = paginate(&all, body["NextToken"].as_str(), limit);
        let mut resp = json!({ "PartnerEventSources": sources });
        if let Some(token) = next_token {
            resp["NextToken"] = json!(token);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    fn list_partner_event_source_accounts(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("EventSourceName", &body["EventSourceName"])?;
        let event_source_name = body["EventSourceName"]
            .as_str()
            .ok_or_else(|| missing("EventSourceName"))?;
        validate_string_length("eventSourceName", event_source_name, 1, 256)?;
        validate_optional_range_i64("limit", body["Limit"].as_i64(), 1, 100)?;
        validate_optional_string_length("nextToken", body["NextToken"].as_str(), 1, 2048)?;

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let accounts: Vec<Value> = state
            .partner_event_sources
            .values()
            .filter(|ps| ps.name == event_source_name)
            .map(|ps| json!({ "Account": ps.account }))
            .collect();

        Ok(AwsResponse::ok_json(json!({
            "PartnerEventSourceAccounts": accounts
        })))
    }

    fn activate_event_source(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"]
            .as_str()
            .ok_or_else(|| missing("Name"))?
            .to_string();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let ps = state.partner_event_sources.get_mut(&name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!("Event source {name} does not exist."),
            )
        })?;
        ps.state = "ACTIVE".to_string();

        Ok(AwsResponse::ok_json(json!({})))
    }

    fn deactivate_event_source(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"]
            .as_str()
            .ok_or_else(|| missing("Name"))?
            .to_string();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let ps = state.partner_event_sources.get_mut(&name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!("Event source {name} does not exist."),
            )
        })?;
        ps.state = "INACTIVE".to_string();

        Ok(AwsResponse::ok_json(json!({})))
    }

    fn describe_event_source(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"]
            .as_str()
            .ok_or_else(|| missing("Name"))?
            .to_string();

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let ps = state.partner_event_sources.get(&name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!("Event source {name} does not exist."),
            )
        })?;

        Ok(AwsResponse::ok_json(json!({
            "Arn": ps.arn,
            "Name": ps.name,
            "CreatedBy": ps.account,
            "CreationTime": ps.creation_time.timestamp() as f64,
            "State": ps.state,
        })))
    }

    fn list_event_sources(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_optional_string_length("namePrefix", body["NamePrefix"].as_str(), 1, 256)?;
        validate_optional_range_i64("limit", body["Limit"].as_i64(), 1, 100)?;
        validate_optional_string_length("nextToken", body["NextToken"].as_str(), 1, 2048)?;
        let name_prefix = body["NamePrefix"].as_str();
        let limit = body["Limit"].as_i64().unwrap_or(100) as usize;

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let all: Vec<Value> = state
            .partner_event_sources
            .values()
            .filter(|ps| match name_prefix {
                Some(prefix) => ps.name.starts_with(prefix),
                None => true,
            })
            .map(|ps| {
                json!({
                    "Arn": ps.arn,
                    "Name": ps.name,
                    "CreatedBy": ps.account,
                    "CreationTime": ps.creation_time.timestamp() as f64,
                    "State": ps.state,
                })
            })
            .collect();

        let (sources, next_token) = paginate(&all, body["NextToken"].as_str(), limit);
        let mut resp = json!({ "EventSources": sources });
        if let Some(token) = next_token {
            resp["NextToken"] = json!(token);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    fn put_partner_events(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Entries", &body["Entries"])?;
        let entries = body["Entries"]
            .as_array()
            .ok_or_else(|| missing("Entries"))?;

        let mut result_entries = Vec::new();
        for _entry in entries {
            let event_id = uuid::Uuid::new_v4().to_string();
            result_entries.push(json!({ "EventId": event_id }));
        }

        Ok(AwsResponse::ok_json(json!({
            "FailedEntryCount": 0,
            "Entries": result_entries,
        })))
    }

    // ─── TestEventPattern ────────────────────────────────────────────────

    fn test_event_pattern(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("EventPattern", &body["EventPattern"])?;
        validate_required("Event", &body["Event"])?;
        let event_pattern = body["EventPattern"]
            .as_str()
            .ok_or_else(|| missing("EventPattern"))?;
        let event_str = body["Event"].as_str().ok_or_else(|| missing("Event"))?;

        // Parse the event JSON
        let event: Value = serde_json::from_str(event_str).map_err(|_| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidEventPatternException",
                "Event is not valid JSON.",
            )
        })?;

        // Parse the pattern JSON
        let _pattern: Value = serde_json::from_str(event_pattern).map_err(|_| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidEventPatternException",
                "Event pattern is not valid JSON.",
            )
        })?;

        let source = event["source"].as_str().unwrap_or("");
        let detail_type = event["detail-type"].as_str().unwrap_or("");
        let detail = event
            .get("detail")
            .map(|v| serde_json::to_string(v).unwrap_or_default())
            .unwrap_or_else(|| "{}".to_string());
        let account = event["account"].as_str().unwrap_or("");
        let region = event["region"].as_str().unwrap_or("");
        let resources: Vec<String> = event["resources"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let result = matches_pattern(
            Some(event_pattern),
            source,
            detail_type,
            &detail,
            account,
            region,
            &resources,
        );

        Ok(AwsResponse::ok_json(json!({ "Result": result })))
    }

    // ─── UpdateEventBus ─────────────────────────────────────────────────

    fn update_event_bus(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_optional_string_length("description", body["Description"].as_str(), 0, 512)?;
        validate_optional_string_length(
            "kmsKeyIdentifier",
            body["KmsKeyIdentifier"].as_str(),
            0,
            2048,
        )?;
        let name = body["Name"].as_str().unwrap_or("default");

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let bus = state.buses.get_mut(name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Event bus {name} does not exist."),
            )
        })?;

        if let Some(desc) = body["Description"].as_str() {
            bus.description = Some(desc.to_string());
        }
        if let Some(kms) = body["KmsKeyIdentifier"].as_str() {
            bus.kms_key_identifier = Some(kms.to_string());
        }
        if let Some(dlc) = body.get("DeadLetterConfig") {
            bus.dead_letter_config = Some(dlc.clone());
        }
        bus.last_modified_time = Utc::now();

        let arn = bus.arn.clone();
        let bus_name = bus.name.clone();

        Ok(AwsResponse::ok_json(json!({
            "Arn": arn,
            "Name": bus_name,
        })))
    }

    // ─── Endpoint Operations ────────────────────────────────────────────

    fn create_endpoint(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"]
            .as_str()
            .ok_or_else(|| missing("Name"))?
            .to_string();
        validate_string_length("name", &name, 1, 64)?;
        validate_required("RoutingConfig", &body["RoutingConfig"])?;
        validate_required("EventBuses", &body["EventBuses"])?;

        let description = body["Description"].as_str().map(|s| s.to_string());
        let routing_config = body["RoutingConfig"].clone();
        let replication_config = body.get("ReplicationConfig").cloned();
        let event_buses = body["EventBuses"].as_array().cloned().unwrap_or_default();
        let role_arn = body["RoleArn"].as_str().map(|s| s.to_string());

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if state.endpoints.contains_key(&name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::CONFLICT,
                "ResourceAlreadyExistsException",
                format!("Endpoint {name} already exists."),
            ));
        }

        let endpoint_id = format!("{}.abc123", name);
        let arn = format!(
            "arn:aws:events:{}:{}:endpoint/{}",
            req.region, state.account_id, name
        );
        let endpoint_url = format!(
            "https://{}.endpoint.events.{}.amazonaws.com",
            endpoint_id, req.region
        );
        let now = Utc::now();

        let endpoint = Endpoint {
            name: name.clone(),
            arn: arn.clone(),
            endpoint_id: endpoint_id.clone(),
            endpoint_url: Some(endpoint_url),
            description,
            routing_config: routing_config.clone(),
            replication_config: replication_config.clone(),
            event_buses: event_buses.clone(),
            role_arn: role_arn.clone(),
            state: "ACTIVE".to_string(),
            creation_time: now,
            last_modified_time: now,
        };
        state.endpoints.insert(name.clone(), endpoint);

        let mut resp = json!({
            "Name": name,
            "Arn": arn,
            "State": "ACTIVE",
            "RoutingConfig": routing_config,
            "EventBuses": event_buses,
        });
        if let Some(ref rc) = replication_config {
            resp["ReplicationConfig"] = rc.clone();
        }
        if let Some(ref ra) = role_arn {
            resp["RoleArn"] = json!(ra);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    fn delete_endpoint(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state.endpoints.remove(name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Endpoint '{name}' does not exist."),
            )
        })?;

        Ok(AwsResponse::ok_json(json!({})))
    }

    fn describe_endpoint(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let ep = state.endpoints.get(name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Endpoint '{name}' does not exist."),
            )
        })?;

        let mut resp = json!({
            "Name": ep.name,
            "Arn": ep.arn,
            "EndpointId": ep.endpoint_id,
            "State": ep.state,
            "RoutingConfig": ep.routing_config,
            "EventBuses": ep.event_buses,
            "CreationTime": ep.creation_time.timestamp() as f64,
            "LastModifiedTime": ep.last_modified_time.timestamp() as f64,
        });
        if let Some(ref url) = ep.endpoint_url {
            resp["EndpointUrl"] = json!(url);
        }
        if let Some(ref desc) = ep.description {
            resp["Description"] = json!(desc);
        }
        if let Some(ref rc) = ep.replication_config {
            resp["ReplicationConfig"] = rc.clone();
        }
        if let Some(ref ra) = ep.role_arn {
            resp["RoleArn"] = json!(ra);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    fn list_endpoints(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_optional_string_length("namePrefix", body["NamePrefix"].as_str(), 1, 64)?;
        validate_optional_string_length("homeRegion", body["HomeRegion"].as_str(), 9, 20)?;
        validate_optional_string_length("nextToken", body["NextToken"].as_str(), 1, 2048)?;
        validate_optional_range_i64("maxResults", body["MaxResults"].as_i64(), 1, 100)?;
        let name_prefix = body["NamePrefix"].as_str();
        let limit = body["MaxResults"].as_i64().unwrap_or(100) as usize;

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let all: Vec<Value> = state
            .endpoints
            .values()
            .filter(|ep| match name_prefix {
                Some(prefix) => ep.name.starts_with(prefix),
                None => true,
            })
            .map(|ep| {
                let mut obj = json!({
                    "Name": ep.name,
                    "Arn": ep.arn,
                    "EndpointId": ep.endpoint_id,
                    "State": ep.state,
                    "RoutingConfig": ep.routing_config,
                    "EventBuses": ep.event_buses,
                    "CreationTime": ep.creation_time.timestamp() as f64,
                    "LastModifiedTime": ep.last_modified_time.timestamp() as f64,
                });
                if let Some(ref url) = ep.endpoint_url {
                    obj["EndpointUrl"] = json!(url);
                }
                obj
            })
            .collect();

        let (endpoints, next_token) = paginate(&all, body["NextToken"].as_str(), limit);
        let mut resp = json!({ "Endpoints": endpoints });
        if let Some(token) = next_token {
            resp["NextToken"] = json!(token);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    fn update_endpoint(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let ep = state.endpoints.get_mut(name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Endpoint '{name}' does not exist."),
            )
        })?;

        if let Some(desc) = body["Description"].as_str() {
            ep.description = Some(desc.to_string());
        }
        if !body["RoutingConfig"].is_null() {
            ep.routing_config = body["RoutingConfig"].clone();
        }
        if let Some(rc) = body.get("ReplicationConfig") {
            ep.replication_config = Some(rc.clone());
        }
        if let Some(buses) = body["EventBuses"].as_array() {
            ep.event_buses = buses.clone();
        }
        if let Some(ra) = body["RoleArn"].as_str() {
            ep.role_arn = Some(ra.to_string());
        }
        ep.last_modified_time = Utc::now();

        let resp = json!({
            "Name": ep.name,
            "Arn": ep.arn,
            "EndpointId": ep.endpoint_id,
            "State": ep.state,
            "RoutingConfig": ep.routing_config,
            "EventBuses": ep.event_buses,
        });

        Ok(AwsResponse::ok_json(resp))
    }

    // ─── DeauthorizeConnection ──────────────────────────────────────────

    fn deauthorize_connection(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;
        validate_string_length("name", name, 1, 64)?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let conn = state.connections.get_mut(name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Connection '{name}' does not exist."),
            )
        })?;

        conn.connection_state = "DEAUTHORIZING".to_string();
        conn.last_modified_time = Utc::now();

        let resp = json!({
            "ConnectionArn": conn.arn,
            "ConnectionState": conn.connection_state,
            "CreationTime": conn.creation_time.timestamp() as f64,
            "LastModifiedTime": conn.last_modified_time.timestamp() as f64,
            "LastAuthorizedTime": conn.last_authorized_time.timestamp() as f64,
        });

        Ok(AwsResponse::ok_json(resp))
    }

    // ─── PutEvents ──────────────────────────────────────────────────────

    fn put_events(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Entries", &body["Entries"])?;
        validate_optional_string_length("endpointId", body["EndpointId"].as_str(), 1, 50)?;
        let entries = body["Entries"]
            .as_array()
            .ok_or_else(|| missing("Entries"))?;

        // Validate entries count
        if entries.is_empty() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "1 validation error detected: Value '[PutEventsRequestEntry]' at 'entries' failed to satisfy constraint: Member must have length greater than or equal to 1",
            ));
        }
        if entries.len() > 10 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "1 validation error detected: Value '[PutEventsRequestEntry]' at 'entries' failed to satisfy constraint: Member must have length less than or equal to 10",
            ));
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let mut result_entries = Vec::new();
        let mut events_to_deliver = Vec::new();
        let mut failed_count = 0;

        for entry in entries {
            let source = entry["Source"].as_str().unwrap_or("").to_string();
            let detail_type = entry["DetailType"].as_str().unwrap_or("").to_string();
            let detail = entry["Detail"].as_str().unwrap_or("").to_string();

            if let Err(error) = validate_put_events_entry(&source, &detail_type, &detail) {
                failed_count += 1;
                result_entries.push(error);
                continue;
            }

            let event_id = uuid::Uuid::new_v4().to_string();
            let raw_bus = entry["EventBusName"]
                .as_str()
                .unwrap_or("default")
                .to_string();
            let event_bus_name = state.resolve_bus_name(&raw_bus);
            let time = parse_put_events_time(&entry["Time"]);
            let resources: Vec<String> = entry["Resources"]
                .as_array()
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default();

            let event = PutEvent {
                event_id: event_id.clone(),
                source: source.clone(),
                detail_type: detail_type.clone(),
                detail: detail.clone(),
                event_bus_name: event_bus_name.clone(),
                time,
                resources: resources.clone(),
            };

            archive_matching_event(
                state,
                &event,
                &event_bus_name,
                &source,
                &detail_type,
                &detail,
                &req.account_id,
                &req.region,
                &resources,
            );

            state.events.push(event);

            // Find matching rules and their targets
            let matching_targets: Vec<EventTarget> = state
                .rules
                .values()
                .filter(|r| {
                    r.event_bus_name == event_bus_name
                        && r.state == "ENABLED"
                        && matches_pattern(
                            r.event_pattern.as_deref(),
                            &source,
                            &detail_type,
                            &detail,
                            &req.account_id,
                            &req.region,
                            &resources,
                        )
                })
                .flat_map(|r| r.targets.clone())
                .collect();

            if !matching_targets.is_empty() {
                events_to_deliver.push((
                    event_id.clone(),
                    source,
                    detail_type,
                    detail,
                    time,
                    resources,
                    matching_targets,
                ));
            }

            result_entries.push(json!({ "EventId": event_id }));
        }

        // Drop the lock before delivering
        drop(accounts);

        // Deliver to targets
        for (event_id, source, detail_type, detail, time, resources, targets) in events_to_deliver {
            let detail_value: Value = serde_json::from_str(&detail).unwrap_or(json!({}));
            let event_json = json!({
                "version": "0",
                "id": event_id,
                "source": source,
                "account": req.account_id,
                "detail-type": detail_type,
                "detail": detail_value,
                "time": time.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                "region": req.region,
                "resources": resources,
            });
            let event_str = event_json.to_string();

            for target in targets {
                let arn = &target.arn;
                // Compute the message body, applying InputTransformer if present
                let body_str = if let Some(ref transformer) = target.input_transformer {
                    apply_input_transformer(transformer, &event_json)
                } else if let Some(ref input) = target.input {
                    input.clone()
                } else if let Some(ref input_path) = target.input_path {
                    resolve_json_path(&event_json, input_path)
                        .map(|v| v.to_string())
                        .unwrap_or_else(|| event_str.clone())
                } else {
                    event_str.clone()
                };

                if arn.contains(":sqs:") {
                    // Extract FIFO parameters (MessageGroupId)
                    let group_id = target
                        .sqs_parameters
                        .as_ref()
                        .and_then(|p| p["MessageGroupId"].as_str())
                        .map(|s| s.to_string());
                    if group_id.is_some() {
                        // FIFO queue: send with group ID but no dedup ID.
                        // Queues with content-based dedup will auto-generate one;
                        // queues without it will reject the message.
                        self.delivery.send_to_sqs_with_attrs(
                            arn,
                            &body_str,
                            &HashMap::new(),
                            group_id.as_deref(),
                            None,
                        );
                    } else {
                        self.delivery.send_to_sqs(arn, &body_str, &HashMap::new());
                    }
                } else if arn.contains(":sns:") {
                    self.delivery
                        .publish_to_sns(arn, &body_str, Some(&detail_type));
                } else if arn.contains(":lambda:") {
                    tracing::info!(
                        function_arn = %arn,
                        payload = %body_str,
                        "EventBridge delivering to Lambda function"
                    );
                    let now = Utc::now();
                    let mut accounts = self.state.write();
                    let state = accounts.get_or_create(&req.account_id);
                    state
                        .lambda_invocations
                        .push(crate::state::LambdaInvocation {
                            function_arn: arn.clone(),
                            payload: body_str.clone(),
                            timestamp: now,
                        });
                    drop(accounts);
                    // Record in Lambda state for cross-service visibility
                    if let Some(ref ls) = self.lambda_state {
                        ls.write().default_mut().invocations.push(LambdaInvocation {
                            function_arn: arn.clone(),
                            payload: body_str.clone(),
                            timestamp: now,
                            source: "aws:events".to_string(),
                        });
                    }
                    // Actually invoke the Lambda function if a container runtime is available
                    invoke_lambda_async(
                        &self.container_runtime,
                        &self.lambda_state,
                        arn,
                        &body_str,
                    );
                } else if arn.contains(":logs:") {
                    tracing::info!(
                        log_group_arn = %arn,
                        payload = %body_str,
                        "EventBridge delivering to CloudWatch Logs"
                    );
                    let now = Utc::now();
                    let mut accounts = self.state.write();
                    let state = accounts.get_or_create(&req.account_id);
                    state.log_deliveries.push(crate::state::LogDelivery {
                        log_group_arn: arn.clone(),
                        payload: body_str.clone(),
                        timestamp: now,
                    });
                    drop(accounts);
                    // Write event to CloudWatch Logs state
                    if let Some(ref log_state) = self.logs_state {
                        deliver_to_logs(log_state, arn, &body_str, now);
                    }
                } else if arn.contains(":kinesis:") {
                    tracing::info!(
                        stream_arn = %arn,
                        "EventBridge delivering to Kinesis stream"
                    );
                    // Use event ID as partition key for even distribution
                    self.delivery.send_to_kinesis(arn, &body_str, &event_id);
                } else if arn.contains(":states:") {
                    tracing::info!(
                        state_machine_arn = %arn,
                        "EventBridge delivering to Step Functions"
                    );
                    self.delivery.start_stepfunctions_execution(arn, &body_str);
                    let mut accounts = self.state.write();
                    let state = accounts.get_or_create(&req.account_id);
                    state
                        .step_function_executions
                        .push(crate::state::StepFunctionExecution {
                            state_machine_arn: arn.clone(),
                            payload: body_str.clone(),
                            timestamp: Utc::now(),
                        });
                } else if arn.contains(":api-destination/") {
                    // ApiDestination target: look up destination + connection, then POST
                    let accounts = self.state.read();
                    let empty = EventBridgeState::new(&req.account_id, &req.region);
                    let state = accounts.get(&req.account_id).unwrap_or(&empty);
                    let dest = state.api_destinations.values().find(|d| d.arn == *arn);
                    if let Some(dest) = dest {
                        let url = dest.invocation_endpoint.clone();
                        let method = dest.http_method.clone();
                        let conn = state
                            .connections
                            .values()
                            .find(|c| c.arn == dest.connection_arn)
                            .cloned();
                        drop(accounts);

                        let payload = body_str.clone();
                        tokio::spawn(async move {
                            let client = reqwest::Client::new();
                            let mut req_builder = match method.as_str() {
                                "GET" => client.get(&url),
                                "PUT" => client.put(&url),
                                "DELETE" => client.delete(&url),
                                "PATCH" => client.patch(&url),
                                "HEAD" => client.head(&url),
                                _ => client.post(&url),
                            };
                            req_builder = req_builder.header("Content-Type", "application/json");

                            // Apply auth from connection
                            if let Some(conn) = conn {
                                req_builder = apply_connection_auth(req_builder, &conn);
                            }

                            let result = req_builder.body(payload).send().await;
                            if let Err(e) = result {
                                tracing::warn!(
                                    endpoint = %url,
                                    error = %e,
                                    "EventBridge ApiDestination delivery failed"
                                );
                            }
                        });
                    }
                } else if arn.starts_with("https://") || arn.starts_with("http://") {
                    // HTTP target — fire-and-forget POST
                    let url = arn.clone();
                    let payload = body_str.clone();
                    tokio::spawn(async move {
                        let client = reqwest::Client::new();
                        let result = client
                            .post(&url)
                            .header("Content-Type", "application/json")
                            .body(payload)
                            .send()
                            .await;
                        if let Err(e) = result {
                            tracing::warn!(
                                endpoint = %url,
                                error = %e,
                                "EventBridge HTTP target delivery failed"
                            );
                        }
                    });
                }
            }
        }

        let resp = json!({
            "FailedEntryCount": failed_count,
            "Entries": result_entries,
        });

        Ok(AwsResponse::ok_json(resp))
    }

    // ─── Tagging ────────────────────────────────────────────────────────

    fn tag_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("ResourceARN", &body["ResourceARN"])?;
        let arn = body["ResourceARN"]
            .as_str()
            .ok_or_else(|| missing("ResourceARN"))?;
        validate_string_length("resourceARN", arn, 1, 1600)?;
        validate_required("Tags", &body["Tags"])?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let tag_map = find_tags_mut(state, arn)?;

        fakecloud_core::tags::apply_tags(tag_map, &body, "Tags", "Key", "Value").map_err(|f| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                format!("{f} must be a list"),
            )
        })?;

        Ok(AwsResponse::ok_json(json!({})))
    }

    fn untag_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("ResourceARN", &body["ResourceARN"])?;
        let arn = body["ResourceARN"]
            .as_str()
            .ok_or_else(|| missing("ResourceARN"))?;
        validate_string_length("resourceARN", arn, 1, 1600)?;
        validate_required("TagKeys", &body["TagKeys"])?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let tag_map = find_tags_mut(state, arn)?;

        fakecloud_core::tags::remove_tags(tag_map, &body, "TagKeys").map_err(|f| {
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
        validate_required("ResourceARN", &body["ResourceARN"])?;
        let arn = body["ResourceARN"]
            .as_str()
            .ok_or_else(|| missing("ResourceARN"))?;
        validate_string_length("resourceARN", arn, 1, 1600)?;

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let tag_map = find_tags(state, arn)?;

        let tags = fakecloud_core::tags::tags_to_json(tag_map, "Key", "Value");

        Ok(AwsResponse::ok_json(json!({ "Tags": tags })))
    }

    // ─── Archive Operations ─────────────────────────────────────────────

    fn create_archive(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("ArchiveName", &body["ArchiveName"])?;
        let name = body["ArchiveName"]
            .as_str()
            .ok_or_else(|| missing("ArchiveName"))?
            .to_string();
        validate_string_length("archiveName", &name, 1, 48)?;
        validate_required("EventSourceArn", &body["EventSourceArn"])?;
        let event_source_arn = body["EventSourceArn"]
            .as_str()
            .ok_or_else(|| missing("EventSourceArn"))?
            .to_string();
        validate_string_length("eventSourceArn", &event_source_arn, 1, 1600)?;
        validate_optional_string_length("description", body["Description"].as_str(), 0, 512)?;
        validate_optional_string_length("eventPattern", body["EventPattern"].as_str(), 0, 4096)?;
        if let Some(rd) = body["RetentionDays"].as_i64() {
            validate_range_i64("retentionDays", rd, 0, i64::MAX)?;
        }
        let description = body["Description"].as_str().map(|s| s.to_string());
        let event_pattern = body["EventPattern"].as_str().map(|s| s.to_string());
        let retention_days = body["RetentionDays"].as_i64().unwrap_or(0);

        // Validate event pattern if provided
        if let Some(ref pattern) = event_pattern {
            validate_event_pattern(pattern)?;
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        // Validate event bus exists
        let bus_name = state.resolve_bus_name(&event_source_arn);
        if !state.buses.contains_key(&bus_name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Event bus {bus_name} does not exist."),
            ));
        }

        // Check duplicate
        if state.archives.contains_key(&name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceAlreadyExistsException",
                format!("Archive {name} already exists."),
            ));
        }

        let now = Utc::now();
        let arn = format!(
            "arn:aws:events:{}:{}:archive/{}",
            req.region, state.account_id, name
        );

        let archive = Archive {
            name: name.clone(),
            arn: arn.clone(),
            event_source_arn: event_source_arn.clone(),
            description,
            event_pattern: event_pattern.clone(),
            retention_days,
            state: "ENABLED".to_string(),
            creation_time: now,
            event_count: 0,
            size_bytes: 0,
            events: Vec::new(),
        };
        state.archives.insert(name.clone(), archive);

        // Create the archive rule
        let rule_name = format!("Events-Archive-{name}");
        let rule_arn = format!(
            "arn:aws:events:{}:{}:rule/{}",
            req.region, state.account_id, rule_name
        );
        // Merge archive event pattern with replay-name filter
        let rule_event_pattern = {
            let mut merged = if let Some(ref ep) = event_pattern {
                serde_json::from_str::<Value>(ep).unwrap_or_else(|_| json!({}))
            } else {
                json!({})
            };
            if let Some(obj) = merged.as_object_mut() {
                obj.insert("replay-name".to_string(), json!([{"exists": false}]));
            }
            serde_json::to_string(&merged).unwrap_or_default()
        };

        // Build the archive target with InputTransformer
        let archive_target = EventTarget {
            id: name.clone(),
            arn: Arn::new("events", &req.region, "", "").to_string(),
            input: None,
            input_path: None,
            input_transformer: Some(json!({
                "InputPathsMap": {},
                "InputTemplate": format!(
                    "{{\"archive-arn\": \"{}\", \"event\": <aws.events.event.json>, \"ingestion-time\": <aws.events.event.ingestion-time>}}",
                    arn
                )
            })),
            sqs_parameters: None,
        };

        let archive_rule = EventRule {
            name: rule_name.clone(),
            arn: rule_arn,
            event_bus_name: bus_name.clone(),
            event_pattern: Some(rule_event_pattern),
            schedule_expression: None,
            state: "ENABLED".to_string(),
            description: None,
            role_arn: None,
            managed_by: Some("prod.vhs.events.aws.internal".to_string()),
            created_by: Some(state.account_id.clone()),
            targets: vec![archive_target],
            tags: BTreeMap::new(),
            last_fired: None,
        };
        let key = (bus_name, rule_name);
        state.rules.insert(key, archive_rule);

        Ok(AwsResponse::ok_json(json!({
            "ArchiveArn": arn,
            "CreationTime": now.timestamp() as f64,
            "State": "ENABLED",
        })))
    }

    fn describe_archive(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("ArchiveName", &body["ArchiveName"])?;
        let name = body["ArchiveName"]
            .as_str()
            .ok_or_else(|| missing("ArchiveName"))?;
        validate_string_length("archiveName", name, 1, 48)?;

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let archive = state.archives.get(name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Archive {name} does not exist."),
            )
        })?;

        let mut resp = json!({
            "ArchiveArn": archive.arn,
            "ArchiveName": archive.name,
            "CreationTime": archive.creation_time.timestamp() as f64,
            "EventCount": archive.event_count,
            "EventSourceArn": archive.event_source_arn,
            "RetentionDays": archive.retention_days,
            "SizeBytes": archive.size_bytes,
            "State": archive.state,
        });
        if let Some(ref desc) = archive.description {
            resp["Description"] = json!(desc);
        }
        if let Some(ref ep) = archive.event_pattern {
            resp["EventPattern"] = json!(ep);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    fn list_archives(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_optional_string_length("namePrefix", body["NamePrefix"].as_str(), 1, 48)?;
        validate_optional_string_length(
            "eventSourceArn",
            body["EventSourceArn"].as_str(),
            1,
            1600,
        )?;
        validate_optional_string_length("nextToken", body["NextToken"].as_str(), 1, 2048)?;
        validate_optional_range_i64("limit", body["Limit"].as_i64(), 1, 100)?;
        let name_prefix = body["NamePrefix"].as_str();
        let source_arn = body["EventSourceArn"].as_str();
        let archive_state = body["State"].as_str();

        // Validate at most one filter
        let filter_count = [
            name_prefix.is_some(),
            source_arn.is_some(),
            archive_state.is_some(),
        ]
        .iter()
        .filter(|&&x| x)
        .count();
        if filter_count > 1 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "At most one filter is allowed for ListArchives. Use either : State, EventSourceArn, or NamePrefix.",
            ));
        }

        // Validate state
        if let Some(s) = archive_state {
            let valid = [
                "ENABLED",
                "DISABLED",
                "CREATING",
                "UPDATING",
                "CREATE_FAILED",
                "UPDATE_FAILED",
            ];
            if !valid.contains(&s) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    format!(
                        "1 validation error detected: Value '{}' at 'state' failed to satisfy constraint: Member must satisfy enum value set: [ENABLED, DISABLED, CREATING, UPDATING, CREATE_FAILED, UPDATE_FAILED]",
                        s
                    ),
                ));
            }
        }

        let limit = body["Limit"].as_i64().unwrap_or(100) as usize;

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let all: Vec<Value> = state
            .archives
            .values()
            .filter(|a| {
                if let Some(prefix) = name_prefix {
                    a.name.starts_with(prefix)
                } else if let Some(arn) = source_arn {
                    a.event_source_arn == arn
                } else if let Some(s) = archive_state {
                    a.state == s
                } else {
                    true
                }
            })
            .map(|a| {
                json!({
                    "ArchiveName": a.name,
                    "CreationTime": a.creation_time.timestamp() as f64,
                    "EventCount": a.event_count,
                    "EventSourceArn": a.event_source_arn,
                    "RetentionDays": a.retention_days,
                    "SizeBytes": a.size_bytes,
                    "State": a.state,
                })
            })
            .collect();

        let (archives, next_token) = paginate(&all, body["NextToken"].as_str(), limit);
        let mut resp = json!({ "Archives": archives });
        if let Some(token) = next_token {
            resp["NextToken"] = json!(token);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    fn update_archive(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("ArchiveName", &body["ArchiveName"])?;
        let name = body["ArchiveName"]
            .as_str()
            .ok_or_else(|| missing("ArchiveName"))?;
        validate_string_length("archiveName", name, 1, 48)?;
        validate_optional_string_length("description", body["Description"].as_str(), 0, 512)?;
        validate_optional_string_length("eventPattern", body["EventPattern"].as_str(), 0, 4096)?;
        if let Some(rd) = body["RetentionDays"].as_i64() {
            validate_range_i64("retentionDays", rd, 0, i64::MAX)?;
        }

        // Validate event pattern if provided
        if let Some(pattern) = body["EventPattern"].as_str() {
            validate_event_pattern(pattern)?;
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let archive = state.archives.get_mut(name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Archive {name} does not exist."),
            )
        })?;

        if let Some(desc) = body["Description"].as_str() {
            archive.description = Some(desc.to_string());
        }
        if let Some(pattern) = body["EventPattern"].as_str() {
            archive.event_pattern = Some(pattern.to_string());
        }
        if let Some(days) = body["RetentionDays"].as_i64() {
            archive.retention_days = days;
        }

        Ok(AwsResponse::ok_json(json!({
            "ArchiveArn": archive.arn,
            "CreationTime": archive.creation_time.timestamp() as f64,
            "State": archive.state,
        })))
    }

    fn delete_archive(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("ArchiveName", &body["ArchiveName"])?;
        let name = body["ArchiveName"]
            .as_str()
            .ok_or_else(|| missing("ArchiveName"))?;
        validate_string_length("archiveName", name, 1, 48)?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if !state.archives.contains_key(name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Archive {name} does not exist."),
            ));
        }

        state.archives.remove(name);

        // Remove the archive rule
        let rule_name = format!("Events-Archive-{name}");
        state.rules.retain(|k, _| k.1 != rule_name);

        Ok(AwsResponse::ok_json(json!({})))
    }

    // ─── Connection Operations ──────────────────────────────────────────

    fn create_connection(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"]
            .as_str()
            .ok_or_else(|| missing("Name"))?
            .to_string();
        validate_string_length("name", &name, 1, 64)?;
        validate_optional_string_length("description", body["Description"].as_str(), 0, 512)?;
        validate_required("AuthorizationType", &body["AuthorizationType"])?;
        let description = body["Description"].as_str().map(|s| s.to_string());
        let auth_type = body["AuthorizationType"]
            .as_str()
            .ok_or_else(|| missing("AuthorizationType"))?
            .to_string();
        validate_enum(
            "authorizationType",
            &auth_type,
            &["BASIC", "OAUTH_CLIENT_CREDENTIALS", "API_KEY"],
        )?;
        validate_optional_string_length(
            "kmsKeyIdentifier",
            body["KmsKeyIdentifier"].as_str(),
            0,
            2048,
        )?;
        validate_required("AuthParameters", &body["AuthParameters"])?;
        let auth_params = body["AuthParameters"].clone();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let now = Utc::now();
        let conn_uuid = uuid::Uuid::new_v4();
        let arn = format!(
            "arn:aws:events:{}:{}:connection/{}/{}",
            req.region, state.account_id, name, conn_uuid
        );
        let secret_arn = format!(
            "arn:aws:secretsmanager:{}:{}:secret:events!connection/{}/{}",
            req.region, state.account_id, name, conn_uuid
        );

        let conn = Connection {
            name: name.clone(),
            arn: arn.clone(),
            description,
            authorization_type: auth_type.clone(),
            auth_parameters: auth_params,
            connection_state: "AUTHORIZED".to_string(),
            secret_arn: secret_arn.clone(),
            creation_time: now,
            last_modified_time: now,
            last_authorized_time: now,
        };
        state.connections.insert(name, conn);

        Ok(AwsResponse::ok_json(json!({
            "ConnectionArn": arn,
            "ConnectionState": "AUTHORIZED",
            "CreationTime": now.timestamp() as f64,
            "LastModifiedTime": now.timestamp() as f64,
        })))
    }

    fn describe_connection(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;
        validate_string_length("name", name, 1, 64)?;

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let conn = state.connections.get(name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Connection '{name}' does not exist."),
            )
        })?;

        // Build auth parameters response - strip secrets
        let auth_params_response =
            build_auth_params_response(&conn.authorization_type, &conn.auth_parameters);

        let mut resp = json!({
            "ConnectionArn": conn.arn,
            "Name": conn.name,
            "AuthorizationType": conn.authorization_type,
            "AuthParameters": auth_params_response,
            "ConnectionState": conn.connection_state,
            "SecretArn": conn.secret_arn,
            "CreationTime": conn.creation_time.timestamp() as f64,
            "LastModifiedTime": conn.last_modified_time.timestamp() as f64,
            "LastAuthorizedTime": conn.last_authorized_time.timestamp() as f64,
        });
        if let Some(ref desc) = conn.description {
            resp["Description"] = json!(desc);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    fn list_connections(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_optional_string_length("namePrefix", body["NamePrefix"].as_str(), 1, 64)?;
        validate_optional_enum(
            "connectionState",
            body["ConnectionState"].as_str(),
            &[
                "CREATING",
                "UPDATING",
                "DELETING",
                "AUTHORIZED",
                "DEAUTHORIZED",
                "AUTHORIZING",
                "DEAUTHORIZING",
                "ACTIVE",
                "FAILED_CONNECTIVITY",
            ],
        )?;
        validate_optional_string_length("nextToken", body["NextToken"].as_str(), 1, 2048)?;
        validate_optional_range_i64("limit", body["Limit"].as_i64(), 1, 100)?;

        let name_prefix = body["NamePrefix"].as_str();
        let connection_state = body["ConnectionState"].as_str();
        let limit = body["Limit"].as_i64().unwrap_or(100) as usize;

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let all: Vec<Value> = state
            .connections
            .values()
            .filter(|c| {
                if let Some(prefix) = name_prefix {
                    if !c.name.starts_with(prefix) {
                        return false;
                    }
                }
                if let Some(cs) = connection_state {
                    if c.connection_state != cs {
                        return false;
                    }
                }
                true
            })
            .map(|c| {
                json!({
                    "ConnectionArn": c.arn,
                    "Name": c.name,
                    "AuthorizationType": c.authorization_type,
                    "ConnectionState": c.connection_state,
                    "CreationTime": c.creation_time.timestamp() as f64,
                    "LastModifiedTime": c.last_modified_time.timestamp() as f64,
                    "LastAuthorizedTime": c.last_authorized_time.timestamp() as f64,
                })
            })
            .collect();

        let (conns, next_token) = paginate(&all, body["NextToken"].as_str(), limit);
        let mut resp = json!({ "Connections": conns });
        if let Some(token) = next_token {
            resp["NextToken"] = json!(token);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    fn update_connection(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;
        validate_string_length("name", name, 1, 64)?;
        validate_optional_string_length("description", body["Description"].as_str(), 0, 512)?;
        validate_optional_enum(
            "authorizationType",
            body["AuthorizationType"].as_str(),
            &["BASIC", "OAUTH_CLIENT_CREDENTIALS", "API_KEY"],
        )?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let conn = state.connections.get_mut(name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Connection '{name}' does not exist."),
            )
        })?;

        if let Some(desc) = body["Description"].as_str() {
            conn.description = Some(desc.to_string());
        }
        if let Some(auth_type) = body["AuthorizationType"].as_str() {
            conn.authorization_type = auth_type.to_string();
        }
        if body.get("AuthParameters").is_some() {
            conn.auth_parameters = body["AuthParameters"].clone();
        }
        conn.last_modified_time = Utc::now();

        Ok(AwsResponse::ok_json(json!({
            "ConnectionArn": conn.arn,
            "ConnectionState": conn.connection_state,
            "CreationTime": conn.creation_time.timestamp() as f64,
            "LastModifiedTime": conn.last_modified_time.timestamp() as f64,
            "LastAuthorizedTime": conn.last_authorized_time.timestamp() as f64,
        })))
    }

    fn delete_connection(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;
        validate_string_length("name", name, 1, 64)?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let conn = state.connections.remove(name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Connection '{name}' does not exist."),
            )
        })?;

        Ok(AwsResponse::ok_json(json!({
            "ConnectionArn": conn.arn,
            "ConnectionState": conn.connection_state,
            "CreationTime": conn.creation_time.timestamp() as f64,
            "LastModifiedTime": conn.last_modified_time.timestamp() as f64,
            "LastAuthorizedTime": conn.last_authorized_time.timestamp() as f64,
        })))
    }

    // ─── API Destination Operations ─────────────────────────────────────

    fn create_api_destination(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"]
            .as_str()
            .ok_or_else(|| missing("Name"))?
            .to_string();
        validate_string_length("name", &name, 1, 64)?;
        validate_optional_string_length("description", body["Description"].as_str(), 0, 512)?;
        validate_required("ConnectionArn", &body["ConnectionArn"])?;
        let description = body["Description"].as_str().map(|s| s.to_string());
        let connection_arn = body["ConnectionArn"]
            .as_str()
            .ok_or_else(|| missing("ConnectionArn"))?
            .to_string();
        validate_string_length("connectionArn", &connection_arn, 1, 1600)?;
        validate_required("InvocationEndpoint", &body["InvocationEndpoint"])?;
        let endpoint = body["InvocationEndpoint"]
            .as_str()
            .ok_or_else(|| missing("InvocationEndpoint"))?
            .to_string();
        validate_string_length("invocationEndpoint", &endpoint, 1, 2048)?;
        validate_required("HttpMethod", &body["HttpMethod"])?;
        let http_method = body["HttpMethod"]
            .as_str()
            .ok_or_else(|| missing("HttpMethod"))?
            .to_string();
        validate_enum(
            "httpMethod",
            &http_method,
            &["POST", "GET", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE"],
        )?;
        let rate_limit = body["InvocationRateLimitPerSecond"].as_i64();
        if let Some(r) = rate_limit {
            validate_range_i64("invocationRateLimitPerSecond", r, 1, i64::MAX)?;
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let now = Utc::now();
        let dest_uuid = uuid::Uuid::new_v4();
        let arn = format!(
            "arn:aws:events:{}:{}:api-destination/{}/{}",
            req.region, state.account_id, name, dest_uuid
        );

        let dest = ApiDestination {
            name: name.clone(),
            arn: arn.clone(),
            description,
            connection_arn,
            invocation_endpoint: endpoint,
            http_method,
            invocation_rate_limit_per_second: rate_limit,
            state: "ACTIVE".to_string(),
            creation_time: now,
            last_modified_time: now,
        };
        state.api_destinations.insert(name, dest);

        Ok(AwsResponse::ok_json(json!({
            "ApiDestinationArn": arn,
            "ApiDestinationState": "ACTIVE",
            "CreationTime": now.timestamp() as f64,
            "LastModifiedTime": now.timestamp() as f64,
        })))
    }

    fn describe_api_destination(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;
        validate_string_length("name", name, 1, 64)?;

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let dest = state.api_destinations.get(name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("An api-destination '{name}' does not exist."),
            )
        })?;

        let mut resp = json!({
            "ApiDestinationArn": dest.arn,
            "Name": dest.name,
            "ConnectionArn": dest.connection_arn,
            "InvocationEndpoint": dest.invocation_endpoint,
            "HttpMethod": dest.http_method,
            "ApiDestinationState": dest.state,
            "CreationTime": dest.creation_time.timestamp() as f64,
            "LastModifiedTime": dest.last_modified_time.timestamp() as f64,
        });
        if let Some(ref desc) = dest.description {
            resp["Description"] = json!(desc);
        }
        if let Some(rate) = dest.invocation_rate_limit_per_second {
            resp["InvocationRateLimitPerSecond"] = json!(rate);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    fn list_api_destinations(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_optional_string_length("namePrefix", body["NamePrefix"].as_str(), 1, 64)?;
        validate_optional_string_length("connectionArn", body["ConnectionArn"].as_str(), 1, 1600)?;
        validate_optional_string_length("nextToken", body["NextToken"].as_str(), 1, 2048)?;
        validate_optional_range_i64("limit", body["Limit"].as_i64(), 1, 100)?;

        let name_prefix = body["NamePrefix"].as_str();
        let connection_arn = body["ConnectionArn"].as_str();
        let limit = body["Limit"].as_i64().unwrap_or(100) as usize;

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let all: Vec<Value> = state
            .api_destinations
            .values()
            .filter(|d| {
                if let Some(prefix) = name_prefix {
                    if !d.name.starts_with(prefix) {
                        return false;
                    }
                }
                if let Some(arn) = connection_arn {
                    if d.connection_arn != arn {
                        return false;
                    }
                }
                true
            })
            .map(|d| {
                let mut obj = json!({
                    "ApiDestinationArn": d.arn,
                    "Name": d.name,
                    "ConnectionArn": d.connection_arn,
                    "InvocationEndpoint": d.invocation_endpoint,
                    "HttpMethod": d.http_method,
                    "ApiDestinationState": d.state,
                    "CreationTime": d.creation_time.timestamp() as f64,
                    "LastModifiedTime": d.last_modified_time.timestamp() as f64,
                });
                if let Some(rate) = d.invocation_rate_limit_per_second {
                    obj["InvocationRateLimitPerSecond"] = json!(rate);
                }
                obj
            })
            .collect();

        let (dests, next_token) = paginate(&all, body["NextToken"].as_str(), limit);
        let mut resp = json!({ "ApiDestinations": dests });
        if let Some(token) = next_token {
            resp["NextToken"] = json!(token);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    fn update_api_destination(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;
        validate_string_length("name", name, 1, 64)?;
        validate_optional_string_length("description", body["Description"].as_str(), 0, 512)?;
        validate_optional_string_length("connectionArn", body["ConnectionArn"].as_str(), 1, 1600)?;
        validate_optional_string_length(
            "invocationEndpoint",
            body["InvocationEndpoint"].as_str(),
            1,
            2048,
        )?;
        validate_optional_enum(
            "httpMethod",
            body["HttpMethod"].as_str(),
            &["POST", "GET", "HEAD", "OPTIONS", "PUT", "PATCH", "DELETE"],
        )?;
        if let Some(r) = body["InvocationRateLimitPerSecond"].as_i64() {
            validate_range_i64("invocationRateLimitPerSecond", r, 1, i64::MAX)?;
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let dest = state.api_destinations.get_mut(name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("An api-destination '{name}' does not exist."),
            )
        })?;

        if let Some(desc) = body["Description"].as_str() {
            dest.description = Some(desc.to_string());
        }
        if let Some(endpoint) = body["InvocationEndpoint"].as_str() {
            dest.invocation_endpoint = endpoint.to_string();
        }
        if let Some(method) = body["HttpMethod"].as_str() {
            dest.http_method = method.to_string();
        }
        if let Some(rate) = body["InvocationRateLimitPerSecond"].as_i64() {
            dest.invocation_rate_limit_per_second = Some(rate);
        }
        if let Some(conn) = body["ConnectionArn"].as_str() {
            dest.connection_arn = conn.to_string();
        }
        dest.last_modified_time = Utc::now();

        Ok(AwsResponse::ok_json(json!({
            "ApiDestinationArn": dest.arn,
            "ApiDestinationState": dest.state,
            "CreationTime": dest.creation_time.timestamp() as f64,
            "LastModifiedTime": dest.last_modified_time.timestamp() as f64,
        })))
    }

    fn delete_api_destination(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("Name", &body["Name"])?;
        let name = body["Name"].as_str().ok_or_else(|| missing("Name"))?;
        validate_string_length("name", name, 1, 64)?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if !state.api_destinations.contains_key(name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("An api-destination '{name}' does not exist."),
            ));
        }
        state.api_destinations.remove(name);

        Ok(AwsResponse::ok_json(json!({})))
    }

    // ─── Replay Operations ──────────────────────────────────────────────

    fn start_replay(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let input = StartReplayInput::from_body(&req.json_body())?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        // Validate event bus + archive, in the order the real service validates them.
        let bus_name = state.resolve_bus_name(&input.destination_arn);
        if !state.buses.contains_key(&bus_name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Event bus {bus_name} does not exist."),
            ));
        }

        let archive_name = input
            .event_source_arn
            .rsplit_once("archive/")
            .map(|(_, n)| n.to_string())
            .unwrap_or_default();
        let archive = state.archives.get(&archive_name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                format!(
                    "Parameter EventSourceArn is not valid. Reason: Archive {archive_name} does not exist."
                ),
            )
        })?;
        let archive_bus = state.resolve_bus_name(&archive.event_source_arn);
        if archive_bus != bus_name {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "Parameter Destination.Arn is not valid. Reason: Cross event bus replay is not permitted.",
            ));
        }

        if input.event_end_time <= input.event_start_time {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "Parameter EventEndTime is not valid. Reason: EventStartTime must be before EventEndTime.",
            ));
        }

        if state.replays.contains_key(&input.name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceAlreadyExistsException",
                format!("Replay {} already exists.", input.name),
            ));
        }

        let now = Utc::now();
        let arn = format!(
            "arn:aws:events:{}:{}:replay/{}",
            req.region, state.account_id, input.name
        );

        let events_to_deliver = collect_replay_events_with_targets(
            state,
            &archive_name,
            &bus_name,
            input.event_start_time,
            input.event_end_time,
            &req.account_id,
            &req.region,
        );

        let replay = Replay {
            name: input.name.clone(),
            arn: arn.clone(),
            description: input.description,
            event_source_arn: input.event_source_arn,
            destination: input.destination,
            event_start_time: input.event_start_time,
            event_end_time: input.event_end_time,
            state: "COMPLETED".to_string(),
            replay_start_time: now,
            replay_end_time: Some(now),
        };
        state.replays.insert(input.name, replay);

        drop(accounts);

        for (event, targets) in events_to_deliver {
            let detail_value: Value = serde_json::from_str(&event.detail).unwrap_or(json!({}));
            let event_json = json!({
                "version": "0",
                "id": event.event_id,
                "source": event.source,
                "account": req.account_id,
                "detail-type": event.detail_type,
                "detail": detail_value,
                "time": event.time.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                "region": req.region,
                "resources": event.resources,
                "replay-name": arn,
            });
            let event_str = event_json.to_string();

            for target in targets {
                self.deliver_replay_event_to_target(
                    &target,
                    &event,
                    &event_json,
                    &event_str,
                    &req.account_id,
                );
            }
        }

        Ok(AwsResponse::ok_json(json!({
            "ReplayArn": arn,
            "ReplayStartTime": now.timestamp() as f64,
            "State": "STARTING",
        })))
    }

    fn deliver_replay_event_to_target(
        &self,
        target: &EventTarget,
        event: &PutEvent,
        event_json: &Value,
        event_str: &str,
        account_id: &str,
    ) {
        let target_arn = &target.arn;
        let body_str = if let Some(ref transformer) = target.input_transformer {
            apply_input_transformer(transformer, event_json)
        } else if let Some(ref input) = target.input {
            input.clone()
        } else if let Some(ref input_path) = target.input_path {
            resolve_json_path(event_json, input_path)
                .map(|v| v.to_string())
                .unwrap_or_else(|| event_str.to_string())
        } else {
            event_str.to_string()
        };

        if target_arn.contains(":sqs:") {
            let group_id = target
                .sqs_parameters
                .as_ref()
                .and_then(|p| p["MessageGroupId"].as_str())
                .map(|s| s.to_string());
            if group_id.is_some() {
                self.delivery.send_to_sqs_with_attrs(
                    target_arn,
                    &body_str,
                    &HashMap::new(),
                    group_id.as_deref(),
                    None,
                );
            } else {
                self.delivery
                    .send_to_sqs(target_arn, &body_str, &HashMap::new());
            }
        } else if target_arn.contains(":sns:") {
            self.delivery
                .publish_to_sns(target_arn, &body_str, Some(&event.detail_type));
        } else if target_arn.contains(":lambda:") {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(account_id);
            state
                .lambda_invocations
                .push(crate::state::LambdaInvocation {
                    function_arn: target_arn.clone(),
                    payload: body_str.clone(),
                    timestamp: Utc::now(),
                });
            drop(accounts);
            if let Some(ref ls) = self.lambda_state {
                ls.write()
                    .get_or_create(account_id)
                    .invocations
                    .push(LambdaInvocation {
                        function_arn: target_arn.clone(),
                        payload: body_str.clone(),
                        timestamp: Utc::now(),
                        source: "aws:events".to_string(),
                    });
            }
            invoke_lambda_async(
                &self.container_runtime,
                &self.lambda_state,
                target_arn,
                &body_str,
            );
        } else if target_arn.contains(":logs:") {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(account_id);
            state.log_deliveries.push(crate::state::LogDelivery {
                log_group_arn: target_arn.clone(),
                payload: body_str.clone(),
                timestamp: Utc::now(),
            });
            drop(accounts);
            if let Some(ref log_state) = self.logs_state {
                deliver_to_logs(log_state, target_arn, &body_str, Utc::now());
            }
        } else if target_arn.contains(":states:") {
            self.delivery
                .start_stepfunctions_execution(target_arn, &body_str);
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(account_id);
            state
                .step_function_executions
                .push(crate::state::StepFunctionExecution {
                    state_machine_arn: target_arn.clone(),
                    payload: body_str.clone(),
                    timestamp: Utc::now(),
                });
        } else if target_arn.starts_with("https://") || target_arn.starts_with("http://") {
            let url = target_arn.clone();
            let payload = body_str.clone();
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                let _ = client
                    .post(&url)
                    .header("Content-Type", "application/json")
                    .body(payload)
                    .send()
                    .await;
            });
        }
    }

    fn describe_replay(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("ReplayName", &body["ReplayName"])?;
        let name = body["ReplayName"]
            .as_str()
            .ok_or_else(|| missing("ReplayName"))?;
        validate_string_length("replayName", name, 1, 64)?;

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let replay = state.replays.get(name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Replay {name} does not exist."),
            )
        })?;

        let mut resp = json!({
            "Destination": replay.destination,
            "EventSourceArn": replay.event_source_arn,
            "EventStartTime": replay.event_start_time.timestamp() as f64,
            "EventEndTime": replay.event_end_time.timestamp() as f64,
            "ReplayArn": replay.arn,
            "ReplayName": replay.name,
            "ReplayStartTime": replay.replay_start_time.timestamp() as f64,
            "State": replay.state,
        });
        if let Some(ref desc) = replay.description {
            resp["Description"] = json!(desc);
        }
        if let Some(ref end) = replay.replay_end_time {
            resp["ReplayEndTime"] = json!(end.timestamp() as f64);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    fn list_replays(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_optional_string_length("namePrefix", body["NamePrefix"].as_str(), 1, 64)?;
        validate_optional_string_length(
            "eventSourceArn",
            body["EventSourceArn"].as_str(),
            1,
            1600,
        )?;
        validate_optional_string_length("nextToken", body["NextToken"].as_str(), 1, 2048)?;
        validate_optional_range_i64("limit", body["Limit"].as_i64(), 1, 100)?;
        let name_prefix = body["NamePrefix"].as_str();
        let source_arn = body["EventSourceArn"].as_str();
        let replay_state = body["State"].as_str();

        // Validate at most one filter
        let filter_count = [
            name_prefix.is_some(),
            source_arn.is_some(),
            replay_state.is_some(),
        ]
        .iter()
        .filter(|&&x| x)
        .count();
        if filter_count > 1 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "At most one filter is allowed for ListReplays. Use either : State, EventSourceArn, or NamePrefix.",
            ));
        }

        // Validate state
        if let Some(s) = replay_state {
            let valid = [
                "CANCELLED",
                "CANCELLING",
                "COMPLETED",
                "FAILED",
                "RUNNING",
                "STARTING",
            ];
            if !valid.contains(&s) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    format!(
                        "1 validation error detected: Value '{}' at 'state' failed to satisfy constraint: Member must satisfy enum value set: [CANCELLED, CANCELLING, COMPLETED, FAILED, RUNNING, STARTING]",
                        s
                    ),
                ));
            }
        }

        let limit = body["Limit"].as_i64().unwrap_or(100) as usize;

        let accounts = self.state.read();
        let empty = EventBridgeState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let all: Vec<Value> = state
            .replays
            .values()
            .filter(|r| {
                if let Some(prefix) = name_prefix {
                    r.name.starts_with(prefix)
                } else if let Some(arn) = source_arn {
                    r.event_source_arn == arn
                } else if let Some(s) = replay_state {
                    r.state == s
                } else {
                    true
                }
            })
            .map(|r| {
                let mut obj = json!({
                    "EventSourceArn": r.event_source_arn,
                    "EventStartTime": r.event_start_time.timestamp() as f64,
                    "EventEndTime": r.event_end_time.timestamp() as f64,
                    "ReplayName": r.name,
                    "ReplayStartTime": r.replay_start_time.timestamp() as f64,
                    "State": r.state,
                });
                if let Some(ref end) = r.replay_end_time {
                    obj["ReplayEndTime"] = json!(end.timestamp() as f64);
                }
                obj
            })
            .collect();

        let (replays, next_token) = paginate(&all, body["NextToken"].as_str(), limit);
        let mut resp = json!({ "Replays": replays });
        if let Some(token) = next_token {
            resp["NextToken"] = json!(token);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    fn cancel_replay(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_required("ReplayName", &body["ReplayName"])?;
        let name = body["ReplayName"]
            .as_str()
            .ok_or_else(|| missing("ReplayName"))?;
        validate_string_length("replayName", name, 1, 64)?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let replay = state.replays.get_mut(name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                format!("Replay {name} does not exist."),
            )
        })?;

        // Can only cancel STARTING or RUNNING replays (or COMPLETED in our mock)
        if replay.state == "CANCELLED" || replay.state == "CANCELLING" {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "IllegalStatusException",
                format!("Replay {name} is not in a valid state for this operation."),
            ));
        }

        let arn = replay.arn.clone();
        replay.state = "CANCELLED".to_string();

        Ok(AwsResponse::ok_json(json!({
            "ReplayArn": arn,
            "State": "CANCELLING",
        })))
    }
}

// ─── Tag Lookup Helpers ─────────────────────────────────────────────────

// ─── Event Pattern Validation ────────────────────────────────────────

// ─── Connection Auth Params Response Builder ────────────────────────

// ─── Event Pattern Matching ─────────────────────────────────────────

/// Parsed + validated inputs for `StartReplay`.
struct StartReplayInput {
    name: String,
    description: Option<String>,
    event_source_arn: String,
    destination: Value,
    destination_arn: String,
    event_start_time: DateTime<Utc>,
    event_end_time: DateTime<Utc>,
}

impl StartReplayInput {
    fn from_body(body: &Value) -> Result<Self, AwsServiceError> {
        validate_required("ReplayName", &body["ReplayName"])?;
        let name = body["ReplayName"]
            .as_str()
            .ok_or_else(|| missing("ReplayName"))?
            .to_string();
        validate_string_length("replayName", &name, 1, 64)?;
        validate_optional_string_length("description", body["Description"].as_str(), 0, 512)?;
        validate_required("EventSourceArn", &body["EventSourceArn"])?;
        let description = body["Description"].as_str().map(|s| s.to_string());
        let event_source_arn = body["EventSourceArn"]
            .as_str()
            .ok_or_else(|| missing("EventSourceArn"))?
            .to_string();
        validate_string_length("eventSourceArn", &event_source_arn, 1, 1600)?;
        validate_required("EventStartTime", &body["EventStartTime"])?;
        validate_required("EventEndTime", &body["EventEndTime"])?;
        validate_required("Destination", &body["Destination"])?;
        let destination = body["Destination"].clone();

        let event_start_time = body["EventStartTime"]
            .as_f64()
            .and_then(|f| DateTime::from_timestamp(f as i64, 0))
            .unwrap_or_else(Utc::now);
        let event_end_time = body["EventEndTime"]
            .as_f64()
            .and_then(|f| DateTime::from_timestamp(f as i64, 0))
            .unwrap_or_else(Utc::now);

        let destination_arn = destination["Arn"].as_str().unwrap_or("").to_string();
        if !destination_arn.contains(":event-bus/") {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "Parameter Destination.Arn is not valid. Reason: Must contain an event bus ARN.",
            ));
        }

        Ok(Self {
            name,
            description,
            event_source_arn,
            destination,
            destination_arn,
            event_start_time,
            event_end_time,
        })
    }
}

#[path = "helpers.rs"]
mod helpers;
pub(crate) use helpers::*;

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
