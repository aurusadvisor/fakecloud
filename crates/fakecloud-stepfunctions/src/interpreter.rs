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

/// Core execution loop: runs through states in a definition and returns the output.
/// Used by the top-level executor, Parallel branches, and Map iterations.
fn run_states<'a>(
    def: &'a Value,
    input: Value,
    delivery: &'a Option<Arc<DeliveryBus>>,
    dynamodb_state: &'a Option<SharedDynamoDbState>,
    shared_state: &'a SharedStepFunctionsState,
    execution_arn: &'a str,
) -> StatesResult<'a> {
    Box::pin(async move {
        let start_at = def["StartAt"]
            .as_str()
            .ok_or_else(|| {
                (
                    "States.Runtime".to_string(),
                    "Missing StartAt in definition".to_string(),
                )
            })?
            .to_string();

        let states = def.get("States").ok_or_else(|| {
            (
                "States.Runtime".to_string(),
                "Missing States in definition".to_string(),
            )
        })?;

        let mut current_state = start_at;
        let mut effective_input = input;
        let mut iteration = 0;
        let max_iterations = 500;

        loop {
            iteration += 1;
            if iteration > max_iterations {
                return Err((
                    "States.Runtime".to_string(),
                    "Maximum number of state transitions exceeded".to_string(),
                ));
            }

            let state_def = states.get(&current_state).cloned().ok_or_else(|| {
                (
                    "States.Runtime".to_string(),
                    format!("State '{current_state}' not found in definition"),
                )
            })?;

            let state_type = state_def["Type"]
                .as_str()
                .ok_or_else(|| {
                    (
                        "States.Runtime".to_string(),
                        format!("State '{current_state}' missing Type field"),
                    )
                })?
                .to_string();

            debug!(
                execution_arn = %execution_arn,
                state = %current_state,
                state_type = %state_type,
                "Executing state"
            );

            let advance = match state_type.as_str() {
                "Pass" => run_pass_state(
                    &current_state,
                    &state_def,
                    effective_input,
                    shared_state,
                    execution_arn,
                ),
                "Succeed" => run_succeed_state(
                    &current_state,
                    &state_def,
                    effective_input,
                    shared_state,
                    execution_arn,
                ),
                "Fail" => run_fail_state(
                    &current_state,
                    &state_def,
                    effective_input,
                    shared_state,
                    execution_arn,
                ),
                "Choice" => run_choice_state(
                    &current_state,
                    &state_def,
                    effective_input,
                    shared_state,
                    execution_arn,
                ),
                "Wait" => {
                    run_wait_state(
                        &current_state,
                        &state_def,
                        effective_input,
                        shared_state,
                        execution_arn,
                    )
                    .await
                }
                "Task" => {
                    run_task_state(
                        &current_state,
                        &state_def,
                        effective_input,
                        delivery,
                        dynamodb_state,
                        shared_state,
                        execution_arn,
                    )
                    .await
                }
                "Parallel" => {
                    run_parallel_state(
                        &current_state,
                        &state_def,
                        effective_input,
                        delivery,
                        dynamodb_state,
                        shared_state,
                        execution_arn,
                    )
                    .await
                }
                "Map" => {
                    run_map_state(
                        &current_state,
                        &state_def,
                        effective_input,
                        delivery,
                        dynamodb_state,
                        shared_state,
                        execution_arn,
                    )
                    .await
                }
                other => Advance::Fail(
                    "States.Runtime".to_string(),
                    format!("Unsupported state type: '{other}'"),
                ),
            };

            match advance {
                Advance::Next(next, new_input) => {
                    effective_input = new_input;
                    current_state = next;
                }
                Advance::End(output) => return Ok(output),
                Advance::Fail(error, cause) => return Err((error, cause)),
            }
        }
    })
}

/// Result of executing a single state in the state machine.
enum Advance {
    /// Continue to the given state with the given input.
    Next(String, Value),
    /// Terminate the state machine with the given output.
    End(Value),
    /// Fail the state machine with the given error and cause.
    Fail(String, String),
}

fn advance_from_next(state_def: &Value, input: Value) -> Advance {
    match next_state(state_def) {
        NextState::Name(next) => Advance::Next(next, input),
        NextState::End => Advance::End(input),
        NextState::Error(msg) => Advance::Fail("States.Runtime".to_string(), msg),
    }
}

fn advance_from_error(state_def: &Value, input: &Value, error: String, cause: String) -> Advance {
    match apply_state_catcher(state_def, input, &error, &cause) {
        Some((next, new_input)) => Advance::Next(next, new_input),
        None => Advance::Fail(error, cause),
    }
}

fn run_pass_state(
    name: &str,
    state_def: &Value,
    input: Value,
    shared_state: &SharedStepFunctionsState,
    execution_arn: &str,
) -> Advance {
    let entered_event_id = add_event(
        shared_state,
        execution_arn,
        "PassStateEntered",
        0,
        json!({
            "name": name,
            "input": serde_json::to_string(&input).expect("serde_json::Value serialization is infallible"),
        }),
    );

    let result = execute_pass_state(state_def, &input);

    add_event(
        shared_state,
        execution_arn,
        "PassStateExited",
        entered_event_id,
        json!({
            "name": name,
            "output": serde_json::to_string(&result).expect("serde_json::Value serialization is infallible"),
        }),
    );

    advance_from_next(state_def, result)
}

fn run_succeed_state(
    name: &str,
    state_def: &Value,
    input: Value,
    shared_state: &SharedStepFunctionsState,
    execution_arn: &str,
) -> Advance {
    add_event(
        shared_state,
        execution_arn,
        "SucceedStateEntered",
        0,
        json!({
            "name": name,
            "input": serde_json::to_string(&input).expect("serde_json::Value serialization is infallible"),
        }),
    );

    let input_path = state_def["InputPath"].as_str();
    let output_path = state_def["OutputPath"].as_str();

    let processed = if input_path == Some("null") {
        json!({})
    } else {
        apply_input_path(&input, input_path)
    };

    let output = if output_path == Some("null") {
        json!({})
    } else {
        apply_output_path(&processed, output_path)
    };

    add_event(
        shared_state,
        execution_arn,
        "SucceedStateExited",
        0,
        json!({
            "name": name,
            "output": serde_json::to_string(&output).expect("serde_json::Value serialization is infallible"),
        }),
    );

    Advance::End(output)
}

fn run_fail_state(
    name: &str,
    state_def: &Value,
    input: Value,
    shared_state: &SharedStepFunctionsState,
    execution_arn: &str,
) -> Advance {
    let error = state_def["Error"]
        .as_str()
        .unwrap_or("States.Fail")
        .to_string();
    let cause = state_def["Cause"].as_str().unwrap_or("").to_string();

    add_event(
        shared_state,
        execution_arn,
        "FailStateEntered",
        0,
        json!({
            "name": name,
            "input": serde_json::to_string(&input).expect("serde_json::Value serialization is infallible"),
        }),
    );

    Advance::Fail(error, cause)
}

fn run_choice_state(
    name: &str,
    state_def: &Value,
    input: Value,
    shared_state: &SharedStepFunctionsState,
    execution_arn: &str,
) -> Advance {
    let entered_event_id = add_event(
        shared_state,
        execution_arn,
        "ChoiceStateEntered",
        0,
        json!({
            "name": name,
            "input": serde_json::to_string(&input).expect("serde_json::Value serialization is infallible"),
        }),
    );

    let input_path = state_def["InputPath"].as_str();
    let processed_input = if input_path == Some("null") {
        json!({})
    } else {
        apply_input_path(&input, input_path)
    };

    match evaluate_choice(state_def, &processed_input) {
        Some(next) => {
            add_event(
                shared_state,
                execution_arn,
                "ChoiceStateExited",
                entered_event_id,
                json!({
                    "name": name,
                    "output": serde_json::to_string(&input).expect("serde_json::Value serialization is infallible"),
                }),
            );
            Advance::Next(next, input)
        }
        None => Advance::Fail(
            "States.NoChoiceMatched".to_string(),
            format!("No choice rule matched and no Default in state '{name}'"),
        ),
    }
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

/// Execute a Pass state: apply InputPath, use Result if present, apply ResultPath and OutputPath.
fn execute_pass_state(state_def: &Value, input: &Value) -> Value {
    let input_path = state_def["InputPath"].as_str();
    let result_path = state_def["ResultPath"].as_str();
    let output_path = state_def["OutputPath"].as_str();

    let effective_input = if input_path == Some("null") {
        json!({})
    } else {
        apply_input_path(input, input_path)
    };

    let result = if let Some(r) = state_def.get("Result") {
        r.clone()
    } else {
        effective_input.clone()
    };

    let after_result = if result_path == Some("null") {
        input.clone()
    } else {
        apply_result_path(input, &result, result_path)
    };

    if output_path == Some("null") {
        json!({})
    } else {
        apply_output_path(&after_result, output_path)
    }
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

/// Send a message to an SQS queue via DeliveryBus.
fn invoke_sqs_send_message(
    input: &Value,
    delivery: &Option<Arc<DeliveryBus>>,
) -> Result<Value, (String, String)> {
    let delivery = delivery.as_ref().ok_or_else(|| {
        (
            "States.TaskFailed".to_string(),
            "No delivery bus configured for SQS".to_string(),
        )
    })?;

    let queue_url = input["QueueUrl"].as_str().ok_or_else(|| {
        (
            "States.TaskFailed".to_string(),
            "Missing QueueUrl in SQS sendMessage parameters".to_string(),
        )
    })?;

    let message_body = input["MessageBody"]
        .as_str()
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            // If MessageBody is not a string, serialize the value
            serde_json::to_string(&input["MessageBody"])
                .expect("serde_json::Value serialization is infallible")
        });

    // Convert QueueUrl to ARN format for the delivery bus
    // QueueUrl format: http://.../<account>/<queue-name>
    // ARN format: arn:aws:sqs:<region>:<account>:<queue-name>
    let queue_arn = queue_url_to_arn(queue_url);

    delivery.send_to_sqs(&queue_arn, &message_body, &HashMap::new());

    Ok(json!({
        "MessageId": uuid::Uuid::new_v4().to_string(),
        "MD5OfMessageBody": md5_hex(&message_body),
    }))
}

/// Publish a message to an SNS topic via DeliveryBus.
fn invoke_sns_publish(
    input: &Value,
    delivery: &Option<Arc<DeliveryBus>>,
) -> Result<Value, (String, String)> {
    let delivery = delivery.as_ref().ok_or_else(|| {
        (
            "States.TaskFailed".to_string(),
            "No delivery bus configured for SNS".to_string(),
        )
    })?;

    let topic_arn = input["TopicArn"].as_str().ok_or_else(|| {
        (
            "States.TaskFailed".to_string(),
            "Missing TopicArn in SNS publish parameters".to_string(),
        )
    })?;

    let message = input["Message"]
        .as_str()
        .map(|s| s.to_string())
        .unwrap_or_else(|| {
            serde_json::to_string(&input["Message"])
                .expect("serde_json::Value serialization is infallible")
        });

    let subject = input["Subject"].as_str();

    delivery.publish_to_sns(topic_arn, &message, subject);

    Ok(json!({
        "MessageId": uuid::Uuid::new_v4().to_string(),
    }))
}

/// Put events onto an EventBridge bus via DeliveryBus.
fn invoke_eventbridge_put_events(
    input: &Value,
    delivery: &Option<Arc<DeliveryBus>>,
) -> Result<Value, (String, String)> {
    let delivery = delivery.as_ref().ok_or_else(|| {
        (
            "States.TaskFailed".to_string(),
            "No delivery bus configured for EventBridge".to_string(),
        )
    })?;

    let entries = input["Entries"]
        .as_array()
        .ok_or_else(|| {
            (
                "States.TaskFailed".to_string(),
                "Missing Entries in EventBridge putEvents parameters".to_string(),
            )
        })?
        .clone();

    let mut event_ids = Vec::new();
    for entry in &entries {
        let source = entry["Source"].as_str().unwrap_or("aws.stepfunctions");
        let detail_type = entry["DetailType"].as_str().unwrap_or("StepFunctionsEvent");
        let detail = entry["Detail"]
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                serde_json::to_string(&entry["Detail"])
                    .expect("serde_json::Value serialization is infallible")
            });
        let bus_name = entry["EventBusName"].as_str().unwrap_or("default");

        delivery.put_event_to_eventbridge(source, detail_type, &detail, bus_name);
        event_ids.push(uuid::Uuid::new_v4().to_string());
    }

    Ok(json!({
        "Entries": event_ids.iter().map(|id| json!({"EventId": id})).collect::<Vec<_>>(),
        "FailedEntryCount": 0,
    }))
}

/// Get an item from DynamoDB via direct state access.
fn invoke_dynamodb_get_item(
    input: &Value,
    dynamodb_state: &Option<SharedDynamoDbState>,
) -> Result<Value, (String, String)> {
    let ddb = dynamodb_state.as_ref().ok_or_else(|| {
        (
            "States.TaskFailed".to_string(),
            "No DynamoDB state configured".to_string(),
        )
    })?;

    let table_name = input["TableName"].as_str().ok_or_else(|| {
        (
            "States.TaskFailed".to_string(),
            "Missing TableName in DynamoDB getItem parameters".to_string(),
        )
    })?;

    let key = input
        .get("Key")
        .and_then(|k| k.as_object())
        .ok_or_else(|| {
            (
                "States.TaskFailed".to_string(),
                "Missing Key in DynamoDB getItem parameters".to_string(),
            )
        })?;

    let key_map: HashMap<String, Value> = key.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

    let __mas = ddb.read();
    let state = __mas.default_ref();
    let table = state.tables.get(table_name).ok_or_else(|| {
        (
            "States.TaskFailed".to_string(),
            format!("Table '{table_name}' not found"),
        )
    })?;

    let item = table
        .find_item_index(&key_map)
        .map(|idx| table.items[idx].clone());

    match item {
        Some(item_map) => {
            let item_value: serde_json::Map<String, Value> = item_map.into_iter().collect();
            Ok(json!({ "Item": item_value }))
        }
        None => Ok(json!({})),
    }
}

/// Put an item into DynamoDB via direct state access.
fn invoke_dynamodb_put_item(
    input: &Value,
    dynamodb_state: &Option<SharedDynamoDbState>,
) -> Result<Value, (String, String)> {
    let ddb = dynamodb_state.as_ref().ok_or_else(|| {
        (
            "States.TaskFailed".to_string(),
            "No DynamoDB state configured".to_string(),
        )
    })?;

    let table_name = input["TableName"].as_str().ok_or_else(|| {
        (
            "States.TaskFailed".to_string(),
            "Missing TableName in DynamoDB putItem parameters".to_string(),
        )
    })?;

    let item = input
        .get("Item")
        .and_then(|i| i.as_object())
        .ok_or_else(|| {
            (
                "States.TaskFailed".to_string(),
                "Missing Item in DynamoDB putItem parameters".to_string(),
            )
        })?;

    let item_map: HashMap<String, Value> =
        item.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

    let mut __mas = ddb.write();
    let state = __mas.default_mut();
    let table = state.tables.get_mut(table_name).ok_or_else(|| {
        (
            "States.TaskFailed".to_string(),
            format!("Table '{table_name}' not found"),
        )
    })?;

    // Replace existing item with same key, or insert new
    if let Some(idx) = table.find_item_index(&item_map) {
        table.items[idx] = item_map;
    } else {
        table.items.push(item_map);
    }

    Ok(json!({}))
}

/// Delete an item from DynamoDB via direct state access.
fn invoke_dynamodb_delete_item(
    input: &Value,
    dynamodb_state: &Option<SharedDynamoDbState>,
) -> Result<Value, (String, String)> {
    let ddb = dynamodb_state.as_ref().ok_or_else(|| {
        (
            "States.TaskFailed".to_string(),
            "No DynamoDB state configured".to_string(),
        )
    })?;

    let table_name = input["TableName"].as_str().ok_or_else(|| {
        (
            "States.TaskFailed".to_string(),
            "Missing TableName in DynamoDB deleteItem parameters".to_string(),
        )
    })?;

    let key = input
        .get("Key")
        .and_then(|k| k.as_object())
        .ok_or_else(|| {
            (
                "States.TaskFailed".to_string(),
                "Missing Key in DynamoDB deleteItem parameters".to_string(),
            )
        })?;

    let key_map: HashMap<String, Value> = key.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

    let mut __mas = ddb.write();
    let state = __mas.default_mut();
    let table = state.tables.get_mut(table_name).ok_or_else(|| {
        (
            "States.TaskFailed".to_string(),
            format!("Table '{table_name}' not found"),
        )
    })?;

    if let Some(idx) = table.find_item_index(&key_map) {
        table.items.remove(idx);
    }

    Ok(json!({}))
}

/// Update an item in DynamoDB via direct state access. Honors UpdateExpression
/// SET (with `=`, `+`, `-`, `if_not_exists`), REMOVE, ADD (numeric), and
/// DELETE (set elements). Creates the item from `Key` plus the expression
/// when no matching item exists, mirroring DynamoDB upsert semantics.
fn invoke_dynamodb_update_item(
    input: &Value,
    dynamodb_state: &Option<SharedDynamoDbState>,
) -> Result<Value, (String, String)> {
    let ddb = dynamodb_state.as_ref().ok_or_else(|| {
        (
            "States.TaskFailed".to_string(),
            "No DynamoDB state configured".to_string(),
        )
    })?;

    let table_name = input["TableName"].as_str().ok_or_else(|| {
        (
            "States.TaskFailed".to_string(),
            "Missing TableName in DynamoDB updateItem parameters".to_string(),
        )
    })?;

    let key = input
        .get("Key")
        .and_then(|k| k.as_object())
        .ok_or_else(|| {
            (
                "States.TaskFailed".to_string(),
                "Missing Key in DynamoDB updateItem parameters".to_string(),
            )
        })?;

    let key_map: HashMap<String, Value> = key.iter().map(|(k, v)| (k.clone(), v.clone())).collect();

    let mut __mas = ddb.write();
    let state = __mas.default_mut();
    let table = state.tables.get_mut(table_name).ok_or_else(|| {
        (
            "States.TaskFailed".to_string(),
            format!("Table '{table_name}' not found"),
        )
    })?;

    // Parse UpdateExpression to apply SET operations
    if let Some(update_expr) = input["UpdateExpression"].as_str() {
        let attr_values = input
            .get("ExpressionAttributeValues")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();
        let attr_names = input
            .get("ExpressionAttributeNames")
            .and_then(|v| v.as_object())
            .cloned()
            .unwrap_or_default();

        if let Some(idx) = table.find_item_index(&key_map) {
            apply_update_expression(
                &mut table.items[idx],
                update_expr,
                &attr_values,
                &attr_names,
            );
        } else {
            // Create new item with key + update expression values
            let mut new_item = key_map;
            apply_update_expression(&mut new_item, update_expr, &attr_values, &attr_names);
            table.items.push(new_item);
        }
    }

    Ok(json!({}))
}

/// Apply a simple SET UpdateExpression to an item.
fn apply_update_expression(
    item: &mut HashMap<String, Value>,
    expr: &str,
    attr_values: &serde_json::Map<String, Value>,
    attr_names: &serde_json::Map<String, Value>,
) {
    // DynamoDB UpdateExpression has up to four clauses: SET, REMOVE, ADD, DELETE.
    // The clauses are separated by whitespace; we tokenize by walking the string
    // and switching mode whenever we hit a keyword, then split the body of each
    // clause on commas.
    let clauses = split_update_clauses(expr);
    for (clause, body) in clauses {
        match clause {
            UpdateClause::Set => apply_set(item, &body, attr_values, attr_names),
            UpdateClause::Remove => apply_remove(item, &body, attr_names),
            UpdateClause::Add => apply_add(item, &body, attr_values, attr_names),
            UpdateClause::Delete => apply_delete(item, &body, attr_values, attr_names),
        }
    }
}

#[derive(Clone, Copy)]
enum UpdateClause {
    Set,
    Remove,
    Add,
    Delete,
}

fn split_update_clauses(expr: &str) -> Vec<(UpdateClause, String)> {
    let mut out = Vec::new();
    let mut current: Option<UpdateClause> = None;
    let mut buf = String::new();
    for token in expr.split_whitespace() {
        let upper = token.to_ascii_uppercase();
        let next_clause = match upper.as_str() {
            "SET" => Some(UpdateClause::Set),
            "REMOVE" => Some(UpdateClause::Remove),
            "ADD" => Some(UpdateClause::Add),
            "DELETE" => Some(UpdateClause::Delete),
            _ => None,
        };
        if let Some(nc) = next_clause {
            if let Some(prev) = current.take() {
                out.push((prev, buf.trim().to_string()));
                buf.clear();
            }
            current = Some(nc);
        } else if current.is_some() {
            if !buf.is_empty() {
                buf.push(' ');
            }
            buf.push_str(token);
        }
    }
    if let Some(c) = current {
        out.push((c, buf.trim().to_string()));
    }
    out
}

fn resolve_attr_name(token: &str, attr_names: &serde_json::Map<String, Value>) -> String {
    if token.starts_with('#') {
        attr_names
            .get(token)
            .and_then(|v| v.as_str())
            .unwrap_or(token)
            .to_string()
    } else {
        token.to_string()
    }
}

fn apply_set(
    item: &mut HashMap<String, Value>,
    body: &str,
    attr_values: &serde_json::Map<String, Value>,
    attr_names: &serde_json::Map<String, Value>,
) {
    for assignment in split_top_commas(body) {
        let Some((lhs, rhs)) = assignment.split_once('=') else {
            continue;
        };
        let attr_name = resolve_attr_name(lhs.trim(), attr_names);
        let value = evaluate_set_rhs(rhs.trim(), &attr_name, item, attr_values, attr_names);
        if let Some(v) = value {
            item.insert(attr_name, v);
        }
    }
}

fn evaluate_set_rhs(
    rhs: &str,
    attr_name: &str,
    item: &HashMap<String, Value>,
    attr_values: &serde_json::Map<String, Value>,
    attr_names: &serde_json::Map<String, Value>,
) -> Option<Value> {
    // if_not_exists(path, :val)
    if let Some(args) = rhs
        .strip_prefix("if_not_exists(")
        .and_then(|s| s.strip_suffix(')'))
    {
        let parts: Vec<&str> = args.splitn(2, ',').collect();
        if parts.len() == 2 {
            let path = resolve_attr_name(parts[0].trim(), attr_names);
            if item.contains_key(&path) {
                return item.get(&path).cloned();
            }
            return resolve_value(parts[1].trim(), attr_values);
        }
        return None;
    }
    // path + :inc / path - :dec — DynamoDB stores numbers as {"N":"<str>"}.
    for op in ['+', '-'] {
        if let Some((left, right)) = split_top_op(rhs, op) {
            let left = left.trim();
            let right = right.trim();
            let left_val = if left.starts_with(':') {
                resolve_value(left, attr_values)
            } else {
                let name = resolve_attr_name(left, attr_names);
                item.get(&name).cloned()
            };
            let right_val = if right.starts_with(':') {
                resolve_value(right, attr_values)
            } else {
                let name = resolve_attr_name(right, attr_names);
                item.get(&name).cloned()
            };
            return arithmetic(left_val.as_ref(), op, right_val.as_ref());
        }
    }
    // bare value or attribute reference
    if rhs.starts_with(':') {
        return resolve_value(rhs, attr_values);
    }
    if rhs.starts_with('#') {
        let _ = attr_name;
        let name = resolve_attr_name(rhs, attr_names);
        return item.get(&name).cloned();
    }
    None
}

fn arithmetic(left: Option<&Value>, op: char, right: Option<&Value>) -> Option<Value> {
    let lf = number_from_dynamo(left?)?;
    let rf = number_from_dynamo(right?)?;
    let out = match op {
        '+' => lf + rf,
        '-' => lf - rf,
        _ => return None,
    };
    Some(json!({ "N": format_number(out) }))
}

fn number_from_dynamo(v: &Value) -> Option<f64> {
    v.get("N")?.as_str()?.parse().ok()
}

fn format_number(n: f64) -> String {
    // i64::MAX is 2^63-1 which is not exactly representable in f64; `i64::MAX as f64`
    // rounds up to 2^63, and casting 2^63 back to i64 saturates. Use an exclusive upper
    // bound so we never hand `n as i64` a value it can't faithfully represent.
    if n.fract() == 0.0 && n.is_finite() && n >= i64::MIN as f64 && n < i64::MAX as f64 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

fn resolve_value(token: &str, attr_values: &serde_json::Map<String, Value>) -> Option<Value> {
    attr_values.get(token).cloned()
}

fn apply_remove(
    item: &mut HashMap<String, Value>,
    body: &str,
    attr_names: &serde_json::Map<String, Value>,
) {
    for path in split_top_commas(body) {
        let name = resolve_attr_name(path.trim(), attr_names);
        item.remove(&name);
    }
}

fn apply_add(
    item: &mut HashMap<String, Value>,
    body: &str,
    attr_values: &serde_json::Map<String, Value>,
    attr_names: &serde_json::Map<String, Value>,
) {
    // ADD #path :inc — numeric increment, with the value initialized to :inc when
    // the attribute is absent. Set union (NS/SS/BS) is not implemented; ADD on a
    // non-numeric attribute is a no-op.
    for clause in split_top_commas(body) {
        let mut parts = clause.split_whitespace();
        let Some(path) = parts.next() else { continue };
        let Some(value_ref) = parts.next() else {
            continue;
        };
        let attr_name = resolve_attr_name(path, attr_names);
        let Some(delta) = resolve_value(value_ref, attr_values) else {
            continue;
        };
        let current = item.get(&attr_name).cloned();
        let next = match (current.as_ref(), &delta) {
            (None, _) => delta.clone(),
            (Some(cur), _) => arithmetic(Some(cur), '+', Some(&delta)).unwrap_or(delta.clone()),
        };
        item.insert(attr_name, next);
    }
}

fn apply_delete(
    item: &mut HashMap<String, Value>,
    body: &str,
    attr_values: &serde_json::Map<String, Value>,
    attr_names: &serde_json::Map<String, Value>,
) {
    // DELETE #path :elements — remove each element of the set value from the
    // attribute's set. Drops the attribute when the resulting set is empty.
    for clause in split_top_commas(body) {
        let mut parts = clause.split_whitespace();
        let Some(path) = parts.next() else { continue };
        let Some(value_ref) = parts.next() else {
            continue;
        };
        let attr_name = resolve_attr_name(path, attr_names);
        let Some(elements) = resolve_value(value_ref, attr_values) else {
            continue;
        };
        let Some(current) = item.get_mut(&attr_name) else {
            continue;
        };
        for set_kind in ["SS", "NS", "BS"] {
            if let (Some(cur_arr), Some(rem_arr)) = (
                current.get_mut(set_kind).and_then(|v| v.as_array_mut()),
                elements.get(set_kind).and_then(|v| v.as_array()),
            ) {
                let to_remove: std::collections::HashSet<String> = rem_arr
                    .iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect();
                cur_arr.retain(|v| !v.as_str().is_some_and(|s| to_remove.contains(s)));
                if cur_arr.is_empty() {
                    item.remove(&attr_name);
                }
                break;
            }
        }
    }
}

fn split_top_commas(s: &str) -> Vec<String> {
    // Splits on `,` while respecting paren depth (so commas inside
    // `if_not_exists(a, :b)` don't split the assignment).
    let mut out = Vec::new();
    let mut depth = 0i32;
    let mut buf = String::new();
    for c in s.chars() {
        match c {
            '(' => {
                depth += 1;
                buf.push(c);
            }
            ')' => {
                depth -= 1;
                buf.push(c);
            }
            ',' if depth == 0 => {
                out.push(std::mem::take(&mut buf).trim().to_string());
            }
            _ => buf.push(c),
        }
    }
    if !buf.trim().is_empty() {
        out.push(buf.trim().to_string());
    }
    out
}

fn split_top_op(s: &str, op: char) -> Option<(&str, &str)> {
    let mut depth = 0i32;
    for (i, c) in s.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            c if c == op && depth == 0 && i > 0 => {
                return Some((&s[..i], &s[i + c.len_utf8()..]));
            }
            _ => {}
        }
    }
    None
}

/// Convert an SQS queue URL to an ARN.
/// QueueUrl format: http://localhost:4566/123456789012/my-queue
fn queue_url_to_arn(url: &str) -> String {
    let parts: Vec<&str> = url.rsplitn(3, '/').collect();
    if parts.len() >= 2 {
        let queue_name = parts[0];
        let account_id = parts[1];
        Arn::new("sqs", "us-east-1", account_id, queue_name).to_string()
    } else {
        url.to_string()
    }
}

/// Compute MD5 hex digest for SQS message response format.
fn md5_hex(data: &str) -> String {
    use md5::Digest;
    let result = md5::Md5::digest(data.as_bytes());
    format!("{result:032x}")
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

fn cleanup_token(shared_state: &SharedStepFunctionsState, account_id: &str, token: &str) {
    let mut accounts = shared_state.write();
    if let Some(state) = accounts.get_mut(account_id) {
        state.task_tokens.remove(token);
    }
}

/// Apply Parameters template: keys ending with .$ are treated as JsonPath references.
fn apply_parameters(template: &Value, input: &Value) -> Value {
    match template {
        Value::Object(map) => {
            let mut result = serde_json::Map::new();
            for (key, value) in map {
                if let Some(stripped) = key.strip_suffix(".$") {
                    if let Some(path) = value.as_str() {
                        result.insert(
                            stripped.to_string(),
                            crate::io_processing::resolve_path(input, path),
                        );
                    }
                } else {
                    result.insert(key.clone(), apply_parameters(value, input));
                }
            }
            Value::Object(result)
        }
        Value::Array(arr) => Value::Array(arr.iter().map(|v| apply_parameters(v, input)).collect()),
        other => other.clone(),
    }
}

enum NextState {
    Name(String),
    End,
    Error(String),
}

fn next_state(state_def: &Value) -> NextState {
    if state_def["End"].as_bool() == Some(true) {
        return NextState::End;
    }
    match state_def["Next"].as_str() {
        Some(next) => NextState::Name(next.to_string()),
        None => NextState::Error("State has neither 'End' nor 'Next' field".to_string()),
    }
}

/// Find the first `Catch` clause on `state_def` that matches `error` and
/// apply its `ResultPath` to produce the state to transition to and the
/// new effective input. Returns None when no catcher applies, in which
/// case the error should propagate up.
fn apply_state_catcher(
    state_def: &Value,
    effective_input: &Value,
    error: &str,
    cause: &str,
) -> Option<(String, Value)> {
    let catchers = state_def["Catch"].as_array().cloned().unwrap_or_default();
    let (next, result_path) = find_catcher(&catchers, error)?;
    let error_output = json!({
        "Error": error,
        "Cause": cause,
    });
    let new_input = apply_result_path(effective_input, &error_output, result_path.as_deref());
    Some((next, new_input))
}

/// Extract account ID from an execution ARN (`arn:aws:states:region:account_id:...`).
fn account_id_from_arn(arn: &str) -> &str {
    arn.split(':').nth(4).unwrap_or("000000000000")
}

fn add_event(
    state: &SharedStepFunctionsState,
    execution_arn: &str,
    event_type: &str,
    previous_event_id: i64,
    details: Value,
) -> i64 {
    let account_id = account_id_from_arn(execution_arn).to_string();
    let mut accounts = state.write();
    let s = accounts.get_or_create(&account_id);
    if let Some(exec) = s.executions.get_mut(execution_arn) {
        let id = exec.history_events.len() as i64 + 1;
        exec.history_events.push(HistoryEvent {
            id,
            event_type: event_type.to_string(),
            timestamp: Utc::now(),
            previous_event_id,
            details,
        });
        id
    } else {
        0
    }
}

fn succeed_execution(state: &SharedStepFunctionsState, execution_arn: &str, output: &Value) {
    let account_id = account_id_from_arn(execution_arn).to_string();
    // Check terminal status before recording events to avoid inconsistent history
    {
        let accounts = state.read();
        if let Some(s) = accounts.get(&account_id) {
            if let Some(exec) = s.executions.get(execution_arn) {
                if exec.status != ExecutionStatus::Running {
                    return;
                }
            }
        }
    }

    let output_str =
        serde_json::to_string(output).expect("serde_json::Value serialization is infallible");

    add_event(
        state,
        execution_arn,
        "ExecutionSucceeded",
        0,
        json!({ "output": output_str }),
    );

    let mut accounts = state.write();
    let s = accounts.get_or_create(&account_id);
    if let Some(exec) = s.executions.get_mut(execution_arn) {
        exec.status = ExecutionStatus::Succeeded;
        exec.output = Some(output_str);
        exec.stop_date = Some(Utc::now());
    }
}

fn fail_execution(state: &SharedStepFunctionsState, execution_arn: &str, error: &str, cause: &str) {
    let account_id = account_id_from_arn(execution_arn).to_string();
    // Check terminal status before recording events to avoid inconsistent history
    {
        let accounts = state.read();
        if let Some(s) = accounts.get(&account_id) {
            if let Some(exec) = s.executions.get(execution_arn) {
                if exec.status != ExecutionStatus::Running {
                    return;
                }
            }
        }
    }

    add_event(
        state,
        execution_arn,
        "ExecutionFailed",
        0,
        json!({ "error": error, "cause": cause }),
    );

    let mut accounts = state.write();
    let s = accounts.get_or_create(&account_id);
    if let Some(exec) = s.executions.get_mut(execution_arn) {
        exec.status = ExecutionStatus::Failed;
        exec.error = Some(error.to_string());
        exec.cause = Some(cause.to_string());
        exec.stop_date = Some(Utc::now());
    }
}

#[cfg(test)]
#[path = "interpreter_tests.rs"]
mod tests;
