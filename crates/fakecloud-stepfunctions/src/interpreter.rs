use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use serde_json::{json, Value};
use tracing::{debug, warn};

use fakecloud_aws::arn::Arn;
use fakecloud_core::delivery::DeliveryBus;
use fakecloud_dynamodb::state::SharedDynamoDbState;

use crate::choice::evaluate_choice;
use crate::error_handling::{find_catcher, should_retry};
use crate::io_processing::{apply_input_path, apply_output_path, apply_result_path};
use crate::state::{ExecutionStatus, HistoryEvent, SharedStepFunctionsState};

/// Execute a state machine definition with the given input.
/// Updates the execution record in shared state as it progresses.
pub async fn execute_state_machine(
    state: SharedStepFunctionsState,
    execution_arn: String,
    definition: String,
    input: Option<String>,
    delivery: Option<Arc<DeliveryBus>>,
    dynamodb_state: Option<SharedDynamoDbState>,
) {
    let def: Value = match serde_json::from_str(&definition) {
        Ok(v) => v,
        Err(e) => {
            fail_execution(
                &state,
                &execution_arn,
                "States.Runtime",
                &format!("Failed to parse definition: {e}"),
            );
            return;
        }
    };

    let raw_input: Value = input
        .as_deref()
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or(json!({}));

    // Record ExecutionStarted event
    add_event(
        &state,
        &execution_arn,
        "ExecutionStarted",
        0,
        json!({
            "input": serde_json::to_string(&raw_input).expect("serde_json::Value serialization is infallible"),
            "roleArn": "arn:aws:iam::123456789012:role/execution-role"
        }),
    );

    // Run the state machine inside an inner tokio::spawn so that any panic
    // bubbles up as a JoinError instead of tearing down the caller. Without
    // this the panic propagates through the outer spawn in `start_execution`
    // which leaves the execution stuck in Running and leaks the panic to
    // tokio's default hook.
    let def_owned = def;
    let state_clone = state.clone();
    let execution_arn_clone = execution_arn.clone();
    let delivery_clone = delivery.clone();
    let dynamodb_state_clone = dynamodb_state.clone();
    let handle = tokio::spawn(async move {
        run_states(
            &def_owned,
            raw_input,
            &delivery_clone,
            &dynamodb_state_clone,
            &state_clone,
            &execution_arn_clone,
        )
        .await
    });

    match handle.await {
        Ok(Ok(output)) => {
            succeed_execution(&state, &execution_arn, &output);
        }
        Ok(Err((error, cause))) => {
            fail_execution(&state, &execution_arn, &error, &cause);
        }
        Err(join_err) => {
            let msg = if join_err.is_panic() {
                let payload = join_err.into_panic();
                if let Some(s) = payload.downcast_ref::<String>() {
                    s.clone()
                } else if let Some(s) = payload.downcast_ref::<&'static str>() {
                    (*s).to_string()
                } else {
                    "execution task panicked".to_string()
                }
            } else {
                format!("execution task cancelled: {join_err}")
            };
            tracing::error!(
                execution_arn = %execution_arn,
                panic = %msg,
                "Step Functions execution panicked"
            );
            fail_execution(&state, &execution_arn, "States.Runtime", &msg);
        }
    }
}

type StatesResult<'a> = std::pin::Pin<
    Box<dyn std::future::Future<Output = Result<Value, (String, String)>> + Send + 'a>,
>;

/// Result of executing a single state in the state machine.
pub(crate) enum Advance {
    /// Continue to the given state with the given input.
    Next(String, Value),
    /// Terminate the state machine with the given output.
    End(Value),
    /// Fail the state machine with the given error and cause.
    Fail(String, String),
}

async fn run_wait_state(
    name: &str,
    state_def: &Value,
    input: Value,
    shared_state: &SharedStepFunctionsState,
    execution_arn: &str,
) -> Advance {
    let entered_event_id = add_event(
        shared_state,
        execution_arn,
        "WaitStateEntered",
        0,
        json!({
            "name": name,
            "input": serde_json::to_string(&input).expect("serde_json::Value serialization is infallible"),
        }),
    );

    execute_wait_state(state_def, &input).await;

    add_event(
        shared_state,
        execution_arn,
        "WaitStateExited",
        entered_event_id,
        json!({
            "name": name,
            "output": serde_json::to_string(&input).expect("serde_json::Value serialization is infallible"),
        }),
    );

    advance_from_next(state_def, input)
}

#[allow(clippy::too_many_arguments)]
async fn run_task_state(
    name: &str,
    state_def: &Value,
    input: Value,
    delivery: &Option<Arc<DeliveryBus>>,
    dynamodb_state: &Option<SharedDynamoDbState>,
    shared_state: &SharedStepFunctionsState,
    execution_arn: &str,
) -> Advance {
    let entered_event_id = add_event(
        shared_state,
        execution_arn,
        "TaskStateEntered",
        0,
        json!({
            "name": name,
            "input": serde_json::to_string(&input).expect("serde_json::Value serialization is infallible"),
        }),
    );

    let result = execute_task_state(
        state_def,
        &input,
        delivery,
        dynamodb_state,
        shared_state,
        execution_arn,
        entered_event_id,
    )
    .await;

    match result {
        Ok(output) => {
            add_event(
                shared_state,
                execution_arn,
                "TaskStateExited",
                entered_event_id,
                json!({
                    "name": name,
                    "output": serde_json::to_string(&output).expect("serde_json::Value serialization is infallible"),
                }),
            );
            advance_from_next(state_def, output)
        }
        Err((error, cause)) => advance_from_error(state_def, &input, error, cause),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_parallel_state(
    name: &str,
    state_def: &Value,
    input: Value,
    delivery: &Option<Arc<DeliveryBus>>,
    dynamodb_state: &Option<SharedDynamoDbState>,
    shared_state: &SharedStepFunctionsState,
    execution_arn: &str,
) -> Advance {
    let entered_event_id = add_event(
        shared_state,
        execution_arn,
        "ParallelStateEntered",
        0,
        json!({
            "name": name,
            "input": serde_json::to_string(&input).expect("serde_json::Value serialization is infallible"),
        }),
    );

    let result = execute_parallel_state(
        state_def,
        &input,
        delivery,
        dynamodb_state,
        shared_state,
        execution_arn,
    )
    .await;

    match result {
        Ok(output) => {
            add_event(
                shared_state,
                execution_arn,
                "ParallelStateExited",
                entered_event_id,
                json!({
                    "name": name,
                    "output": serde_json::to_string(&output).expect("serde_json::Value serialization is infallible"),
                }),
            );
            advance_from_next(state_def, output)
        }
        Err((error, cause)) => advance_from_error(state_def, &input, error, cause),
    }
}

#[allow(clippy::too_many_arguments)]
async fn run_map_state(
    name: &str,
    state_def: &Value,
    input: Value,
    delivery: &Option<Arc<DeliveryBus>>,
    dynamodb_state: &Option<SharedDynamoDbState>,
    shared_state: &SharedStepFunctionsState,
    execution_arn: &str,
) -> Advance {
    let entered_event_id = add_event(
        shared_state,
        execution_arn,
        "MapStateEntered",
        0,
        json!({
            "name": name,
            "input": serde_json::to_string(&input).expect("serde_json::Value serialization is infallible"),
        }),
    );

    let result = execute_map_state(
        state_def,
        &input,
        delivery,
        dynamodb_state,
        shared_state,
        execution_arn,
    )
    .await;

    match result {
        Ok(output) => {
            add_event(
                shared_state,
                execution_arn,
                "MapStateExited",
                entered_event_id,
                json!({
                    "name": name,
                    "output": serde_json::to_string(&output).expect("serde_json::Value serialization is infallible"),
                }),
            );
            advance_from_next(state_def, output)
        }
        Err((error, cause)) => advance_from_error(state_def, &input, error, cause),
    }
}

/// Execute a Wait state: pause execution for a specified duration or until a timestamp.
async fn execute_wait_state(state_def: &Value, input: &Value) {
    if let Some(seconds) = state_def["Seconds"].as_u64() {
        tokio::time::sleep(tokio::time::Duration::from_secs(seconds)).await;
        return;
    }

    if let Some(path) = state_def["SecondsPath"].as_str() {
        let val = crate::io_processing::resolve_path(input, path);
        if let Some(seconds) = val.as_u64() {
            tokio::time::sleep(tokio::time::Duration::from_secs(seconds)).await;
        }
        return;
    }

    if let Some(ts_str) = state_def["Timestamp"].as_str() {
        if let Ok(target) = chrono::DateTime::parse_from_rfc3339(ts_str) {
            let now = Utc::now();
            let target_utc = target.with_timezone(&chrono::Utc);
            if target_utc > now {
                let duration = (target_utc - now).to_std().unwrap_or_default();
                tokio::time::sleep(duration).await;
            }
        }
        return;
    }

    if let Some(path) = state_def["TimestampPath"].as_str() {
        let val = crate::io_processing::resolve_path(input, path);
        if let Some(ts_str) = val.as_str() {
            if let Ok(target) = chrono::DateTime::parse_from_rfc3339(ts_str) {
                let now = Utc::now();
                let target_utc = target.with_timezone(&chrono::Utc);
                if target_utc > now {
                    let duration = (target_utc - now).to_std().unwrap_or_default();
                    tokio::time::sleep(duration).await;
                }
            }
        }
        return;
    }

    warn!(
        "Wait state has no valid Seconds, SecondsPath, Timestamp, or TimestampPath — skipping wait"
    );
}

/// Execute a Task state: invoke the resource (Lambda, SQS, SNS, EventBridge, DynamoDB),
/// apply I/O processing, handle Retry.
async fn execute_task_state(
    state_def: &Value,
    input: &Value,
    delivery: &Option<Arc<DeliveryBus>>,
    dynamodb_state: &Option<SharedDynamoDbState>,
    shared_state: &SharedStepFunctionsState,
    execution_arn: &str,
    entered_event_id: i64,
) -> Result<Value, (String, String)> {
    let resource = state_def["Resource"].as_str().unwrap_or("").to_string();

    let input_path = state_def["InputPath"].as_str();
    let result_path = state_def["ResultPath"].as_str();
    let output_path = state_def["OutputPath"].as_str();

    let effective_input = if input_path == Some("null") {
        json!({})
    } else {
        apply_input_path(input, input_path)
    };

    let task_input = if let Some(params) = state_def.get("Parameters") {
        apply_parameters(params, &effective_input)
    } else {
        effective_input
    };

    let retriers = state_def["Retry"].as_array().cloned().unwrap_or_default();
    let timeout_seconds = state_def["TimeoutSeconds"].as_u64();
    let heartbeat_seconds = state_def["HeartbeatSeconds"].as_u64();
    let mut attempt = 0u32;

    loop {
        add_event(
            shared_state,
            execution_arn,
            "TaskScheduled",
            entered_event_id,
            json!({
                "resource": resource,
                "region": "us-east-1",
                "parameters": serde_json::to_string(&task_input).expect("serde_json::Value serialization is infallible"),
            }),
        );

        add_event(
            shared_state,
            execution_arn,
            "TaskStarted",
            entered_event_id,
            json!({ "resource": resource }),
        );

        let invoke_result = invoke_resource(
            &resource,
            &task_input,
            delivery,
            dynamodb_state,
            timeout_seconds,
            heartbeat_seconds,
            shared_state,
        )
        .await;

        match invoke_result {
            Ok(result) => {
                add_event(
                    shared_state,
                    execution_arn,
                    "TaskSucceeded",
                    entered_event_id,
                    json!({
                        "resource": resource,
                        "output": serde_json::to_string(&result).expect("serde_json::Value serialization is infallible"),
                    }),
                );

                let selected = if let Some(selector) = state_def.get("ResultSelector") {
                    apply_parameters(selector, &result)
                } else {
                    result
                };

                let after_result = if result_path == Some("null") {
                    input.clone()
                } else {
                    apply_result_path(input, &selected, result_path)
                };

                let output = if output_path == Some("null") {
                    json!({})
                } else {
                    apply_output_path(&after_result, output_path)
                };

                return Ok(output);
            }
            Err((error, cause)) => {
                add_event(
                    shared_state,
                    execution_arn,
                    "TaskFailed",
                    entered_event_id,
                    json!({ "error": error, "cause": cause }),
                );

                if let Some(delay_ms) = should_retry(&retriers, &error, attempt) {
                    attempt += 1;
                    let actual_delay = delay_ms.min(5000);
                    tokio::time::sleep(tokio::time::Duration::from_millis(actual_delay)).await;
                    continue;
                }

                return Err((error, cause));
            }
        }
    }
}

/// Execute a Parallel state: run all branches concurrently, collect results into an array.
async fn execute_parallel_state(
    state_def: &Value,
    input: &Value,
    delivery: &Option<Arc<DeliveryBus>>,
    dynamodb_state: &Option<SharedDynamoDbState>,
    shared_state: &SharedStepFunctionsState,
    execution_arn: &str,
) -> Result<Value, (String, String)> {
    let input_path = state_def["InputPath"].as_str();
    let result_path = state_def["ResultPath"].as_str();
    let output_path = state_def["OutputPath"].as_str();

    let effective_input = if input_path == Some("null") {
        json!({})
    } else {
        apply_input_path(input, input_path)
    };

    let branches = state_def["Branches"]
        .as_array()
        .cloned()
        .unwrap_or_default();

    if branches.is_empty() {
        return Err((
            "States.Runtime".to_string(),
            "Parallel state has no Branches".to_string(),
        ));
    }

    // Spawn all branches concurrently
    let mut handles = Vec::new();
    for branch_def in &branches {
        let branch = branch_def.clone();
        let branch_input = effective_input.clone();
        let delivery = delivery.clone();
        let ddb = dynamodb_state.clone();
        let state = shared_state.clone();
        let arn = execution_arn.to_string();

        handles.push(tokio::spawn(async move {
            run_states(&branch, branch_input, &delivery, &ddb, &state, &arn).await
        }));
    }

    // Collect results in order
    let mut results = Vec::with_capacity(handles.len());
    for handle in handles {
        let result = handle.await.map_err(|e| {
            (
                "States.Runtime".to_string(),
                format!("Branch execution panicked: {e}"),
            )
        })??;
        results.push(result);
    }

    let branch_output = Value::Array(results);

    // Apply ResultSelector if present
    let selected = if let Some(selector) = state_def.get("ResultSelector") {
        apply_parameters(selector, &branch_output)
    } else {
        branch_output
    };

    // Apply ResultPath
    let after_result = if result_path == Some("null") {
        input.clone()
    } else {
        apply_result_path(input, &selected, result_path)
    };

    // Apply OutputPath
    let output = if output_path == Some("null") {
        json!({})
    } else {
        apply_output_path(&after_result, output_path)
    };

    Ok(output)
}

/// Execute a Map state: iterate over an array and run a sub-state machine per item.
async fn execute_map_state(
    state_def: &Value,
    input: &Value,
    delivery: &Option<Arc<DeliveryBus>>,
    dynamodb_state: &Option<SharedDynamoDbState>,
    shared_state: &SharedStepFunctionsState,
    execution_arn: &str,
) -> Result<Value, (String, String)> {
    let input_path = state_def["InputPath"].as_str();
    let result_path = state_def["ResultPath"].as_str();
    let output_path = state_def["OutputPath"].as_str();

    let effective_input = if input_path == Some("null") {
        json!({})
    } else {
        apply_input_path(input, input_path)
    };

    // Get the items to iterate over
    let items_path = state_def["ItemsPath"].as_str().unwrap_or("$");
    let items_value = crate::io_processing::resolve_path(&effective_input, items_path);
    let items = items_value.as_array().cloned().unwrap_or_default();

    // Get the iterator definition (ItemProcessor or Iterator for backwards compat)
    let iterator_def = state_def
        .get("ItemProcessor")
        .or_else(|| state_def.get("Iterator"))
        .cloned()
        .ok_or_else(|| {
            (
                "States.Runtime".to_string(),
                "Map state has no ItemProcessor or Iterator".to_string(),
            )
        })?;

    let max_concurrency = state_def["MaxConcurrency"].as_u64().unwrap_or(0);
    let effective_concurrency = if max_concurrency == 0 {
        40
    } else {
        max_concurrency as usize
    };

    let semaphore = Arc::new(tokio::sync::Semaphore::new(effective_concurrency));

    // Process all items
    let mut handles = Vec::new();
    for (index, item) in items.into_iter().enumerate() {
        let iter_def = iterator_def.clone();
        let delivery = delivery.clone();
        let ddb = dynamodb_state.clone();
        let state = shared_state.clone();
        let arn = execution_arn.to_string();
        let sem = semaphore.clone();

        // Apply ItemSelector if present
        let item_input = if let Some(selector) = state_def.get("ItemSelector") {
            let mut ctx = serde_json::Map::new();
            ctx.insert("value".to_string(), item.clone());
            ctx.insert("index".to_string(), json!(index));
            apply_parameters(selector, &Value::Object(ctx))
        } else {
            item
        };

        add_event(
            shared_state,
            execution_arn,
            "MapIterationStarted",
            0,
            json!({ "index": index }),
        );

        handles.push(tokio::spawn(async move {
            let _permit = sem
                .acquire()
                .await
                .map_err(|_| ("States.Runtime".to_string(), "Semaphore closed".to_string()))?;
            let result = run_states(&iter_def, item_input, &delivery, &ddb, &state, &arn).await;
            Ok::<(usize, Result<Value, (String, String)>), (String, String)>((index, result))
        }));
    }

    // Collect results in order
    let mut results: Vec<(usize, Value)> = Vec::with_capacity(handles.len());
    for handle in handles {
        let (index, result) = handle.await.map_err(|e| {
            (
                "States.Runtime".to_string(),
                format!("Map iteration panicked: {e}"),
            )
        })??;

        match result {
            Ok(output) => {
                add_event(
                    shared_state,
                    execution_arn,
                    "MapIterationSucceeded",
                    0,
                    json!({ "index": index }),
                );
                results.push((index, output));
            }
            Err((error, cause)) => {
                add_event(
                    shared_state,
                    execution_arn,
                    "MapIterationFailed",
                    0,
                    json!({ "index": index, "error": error }),
                );
                return Err((error, cause));
            }
        }
    }

    // Sort by index to maintain order
    results.sort_by_key(|(i, _)| *i);
    let map_output = Value::Array(results.into_iter().map(|(_, v)| v).collect());

    // Apply ResultSelector if present
    let selected = if let Some(selector) = state_def.get("ResultSelector") {
        apply_parameters(selector, &map_output)
    } else {
        map_output
    };

    // Apply ResultPath
    let after_result = if result_path == Some("null") {
        input.clone()
    } else {
        apply_result_path(input, &selected, result_path)
    };

    // Apply OutputPath
    let output = if output_path == Some("null") {
        json!({})
    } else {
        apply_output_path(&after_result, output_path)
    };

    Ok(output)
}

/// Invoke a resource (Lambda function or SDK integration).
#[allow(clippy::too_many_arguments)]
async fn invoke_resource(
    resource: &str,
    input: &Value,
    delivery: &Option<Arc<DeliveryBus>>,
    dynamodb_state: &Option<SharedDynamoDbState>,
    timeout_seconds: Option<u64>,
    heartbeat_seconds: Option<u64>,
    shared_state: &SharedStepFunctionsState,
) -> Result<Value, (String, String)> {
    // Direct activity ARN: arn:aws:states:<region>:<account>:activity:<name>
    if resource.contains(":states:") && resource.contains(":activity:") {
        return invoke_activity(
            resource,
            input,
            shared_state,
            timeout_seconds,
            heartbeat_seconds,
        )
        .await;
    }

    // Direct Lambda ARN: arn:aws:lambda:<region>:<account>:function:<name>
    if resource.contains(":lambda:") && resource.contains(":function:") {
        return invoke_lambda_direct(resource, input, delivery, timeout_seconds).await;
    }

    // SDK integration patterns: arn:aws:states:::<service>:<action>
    if resource.starts_with("arn:aws:states:::lambda:invoke") {
        let function_name = input["FunctionName"].as_str().unwrap_or("");
        let payload = if let Some(p) = input.get("Payload") {
            p.clone()
        } else {
            input.clone()
        };
        return invoke_lambda_direct(function_name, &payload, delivery, timeout_seconds).await;
    }

    if resource.starts_with("arn:aws:states:::sqs:sendMessage") {
        return invoke_sqs_send_message(input, delivery);
    }

    if resource.starts_with("arn:aws:states:::sns:publish") {
        return invoke_sns_publish(input, delivery);
    }

    if resource.starts_with("arn:aws:states:::events:putEvents") {
        return invoke_eventbridge_put_events(input, delivery);
    }

    if resource.starts_with("arn:aws:states:::dynamodb:getItem") {
        return invoke_dynamodb_get_item(input, dynamodb_state);
    }

    if resource.starts_with("arn:aws:states:::dynamodb:putItem") {
        return invoke_dynamodb_put_item(input, dynamodb_state);
    }

    if resource.starts_with("arn:aws:states:::dynamodb:deleteItem") {
        return invoke_dynamodb_delete_item(input, dynamodb_state);
    }

    if resource.starts_with("arn:aws:states:::dynamodb:updateItem") {
        return invoke_dynamodb_update_item(input, dynamodb_state);
    }

    Err((
        "States.TaskFailed".to_string(),
        format!("Unsupported resource: {resource}"),
    ))
}

#[derive(Clone, Copy)]
pub(crate) enum UpdateClause {
    Set,
    Remove,
    Add,
    Delete,
}

/// Invoke a Lambda function directly via DeliveryBus.
async fn invoke_lambda_direct(
    function_arn: &str,
    input: &Value,
    delivery: &Option<Arc<DeliveryBus>>,
    timeout_seconds: Option<u64>,
) -> Result<Value, (String, String)> {
    let delivery = delivery.as_ref().ok_or_else(|| {
        (
            "States.TaskFailed".to_string(),
            "No delivery bus configured for Lambda invocation".to_string(),
        )
    })?;

    let payload =
        serde_json::to_string(input).expect("serde_json::Value serialization is infallible");

    let invoke_future = delivery.invoke_lambda(function_arn, &payload);

    let result = if let Some(timeout) = timeout_seconds {
        match tokio::time::timeout(tokio::time::Duration::from_secs(timeout), invoke_future).await {
            Ok(r) => r,
            Err(_) => {
                return Err((
                    "States.Timeout".to_string(),
                    format!("Task timed out after {timeout} seconds"),
                ));
            }
        }
    } else {
        invoke_future.await
    };

    match result {
        Some(Ok(bytes)) => {
            let response_str = String::from_utf8_lossy(&bytes);
            let value: Value =
                serde_json::from_str(&response_str).unwrap_or(json!(response_str.to_string()));
            Ok(value)
        }
        Some(Err(e)) => Err(("States.TaskFailed".to_string(), e)),
        None => {
            // No runtime available — return empty result
            Ok(json!({}))
        }
    }
}

/// Invoke an activity worker. Inserts a `PENDING` token into shared state
/// so a worker can claim it via `GetActivityTask`, then polls until the
/// worker calls `SendTaskSuccess` / `SendTaskFailure` or the heartbeat /
/// timeout windows expire.
async fn invoke_activity(
    activity_arn: &str,
    input: &Value,
    shared_state: &SharedStepFunctionsState,
    timeout_seconds: Option<u64>,
    heartbeat_seconds: Option<u64>,
) -> Result<Value, (String, String)> {
    use crate::state::TaskTokenState;

    // Activity must exist (look up across accounts via ARN segment).
    let activity_account = activity_arn.split(':').nth(4).unwrap_or("").to_string();
    {
        let accounts = shared_state.read();
        let exists = accounts
            .get(&activity_account)
            .map(|s| s.activities.contains_key(activity_arn))
            .unwrap_or(false);
        if !exists {
            return Err((
                "States.TaskFailed".to_string(),
                format!("Activity does not exist: {activity_arn}"),
            ));
        }
    }

    let token = format!(
        "FCToken-{}-{}",
        chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0),
        uuid::Uuid::new_v4().simple(),
    );
    let now = chrono::Utc::now();
    let input_str =
        serde_json::to_string(input).expect("serde_json::Value serialization is infallible");
    {
        let mut accounts = shared_state.write();
        let state = accounts.get_or_create(&activity_account);
        state.task_tokens.insert(
            token.clone(),
            TaskTokenState {
                activity_arn: activity_arn.to_string(),
                status: "PENDING".to_string(),
                output: None,
                error: None,
                cause: None,
                input: Some(input_str),
                created_at: now,
                last_heartbeat_at: None,
                heartbeat_seconds: heartbeat_seconds.map(|s| s as i64),
                timeout_seconds: timeout_seconds.map(|s| s as i64),
            },
        );
    }

    // Poll for completion. Default poll cadence 200ms; 1 hour absolute
    // ceiling so a stuck activity can't block the interpreter forever
    // when no TimeoutSeconds is set on the Task state.
    let absolute_deadline =
        std::time::Instant::now() + std::time::Duration::from_secs(timeout_seconds.unwrap_or(3600));
    loop {
        let now_ts = chrono::Utc::now();
        let snapshot = {
            let accounts = shared_state.read();
            accounts
                .get(&activity_account)
                .and_then(|s| s.task_tokens.get(&token).cloned())
        };
        let Some(entry) = snapshot else {
            return Err((
                "States.TaskFailed".to_string(),
                "Activity task token disappeared".to_string(),
            ));
        };
        match entry.status.as_str() {
            "SUCCEEDED" => {
                cleanup_token(shared_state, &activity_account, &token);
                let output = entry.output.unwrap_or_else(|| "{}".to_string());
                let value: Value = serde_json::from_str(&output).unwrap_or(Value::String(output));
                return Ok(value);
            }
            "FAILED" => {
                cleanup_token(shared_state, &activity_account, &token);
                return Err((
                    entry
                        .error
                        .unwrap_or_else(|| "States.TaskFailed".to_string()),
                    entry.cause.unwrap_or_default(),
                ));
            }
            _ => {}
        }
        // Heartbeat timeout: only enforced once a worker has picked up the
        // task (status == IN_PROGRESS) and a heartbeat window is set.
        if entry.status == "IN_PROGRESS" {
            if let Some(hb) = entry.heartbeat_seconds {
                let last = entry.last_heartbeat_at.unwrap_or(entry.created_at);
                if (now_ts - last).num_seconds() > hb {
                    cleanup_token(shared_state, &activity_account, &token);
                    return Err((
                        "States.HeartbeatTimeout".to_string(),
                        format!("Activity worker missed heartbeat ({hb}s window)"),
                    ));
                }
            }
        }
        if std::time::Instant::now() >= absolute_deadline {
            cleanup_token(shared_state, &activity_account, &token);
            let secs = timeout_seconds.unwrap_or(3600);
            return Err((
                "States.Timeout".to_string(),
                format!("Activity timed out after {secs} seconds"),
            ));
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
}

pub(crate) enum NextState {
    Name(String),
    End,
    Error(String),
}

#[path = "interpreter_helpers.rs"]
mod interpreter_helpers;
pub(crate) use interpreter_helpers::*;

#[cfg(test)]
#[path = "interpreter_tests.rs"]
mod tests;
