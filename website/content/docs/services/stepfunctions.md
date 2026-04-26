+++
title = "Step Functions"
description = "Full ASL interpreter, cross-service task integrations, execution history."
weight = 19
+++

fakecloud implements **37 of 37** Step Functions operations at 100% Smithy conformance, including a **full ASL (Amazon States Language) interpreter**.

## Supported features

- **State machines** — CRUD, versions, aliases, tags
- **Executions** — StartExecution, StartSyncExecution, StopExecution, DescribeExecution, GetExecutionHistory
- **ASL states** — Pass, Task, Choice, Wait, Parallel, Map, Succeed, Fail
- **Retry and Catch** — full retry logic with exponential backoff, catch clauses with error filters
- **JSONPath and JSONata** — both query languages for state input/output
- **Task integrations** — Lambda (invoke, invoke.waitForTaskToken), SQS (sendMessage), SNS (publish), EventBridge (putEvents), DynamoDB (getItem/putItem/updateItem/deleteItem)
- **Map state** — parallel item processing with concurrency control
- **Parallel state** — concurrent branch execution
- **Activities** — real worker pool. A `Task` state with an activity ARN inserts a pending task; `GetActivityTask` long-polls (up to `FAKECLOUD_SFN_GET_ACTIVITY_TIMEOUT_SECS`, default 5s) for the next pending task; `SendTaskSuccess` / `SendTaskFailure` resolve the workflow. `HeartbeatSeconds` and `TimeoutSeconds` are enforced.
- **State machine execution history** — full event log per execution
- **Error handling** — states.ALL, states.TaskFailed, custom error names

## Protocol

JSON protocol. `X-Amz-Target` header, JSON body, JSON responses.

## Introspection

- `GET /_fakecloud/stepfunctions/executions` — list all executions with status, input, output, and timestamps
- `POST /_fakecloud/stepfunctions/enqueue-activity-task` — directly insert a pending activity task (skipping a state-machine execution). Body: `{"activityArn": "...", "input": "{}", "heartbeatSeconds": 60, "timeoutSeconds": 300}`. Returns `{"taskToken": "..."}`. Useful for testing worker pool clients without authoring a full ASL workflow.

## Cross-service delivery

- **Step Functions -> Lambda / SQS / SNS / EventBridge / DynamoDB** — Task states invoke functions, send messages, publish events, and read/write items

## Why this matters

Most emulators stub Step Functions or support a tiny subset of the ASL spec. fakecloud runs the full interpreter — your state machine definitions execute with real branching, retries, catches, and task integrations. This lets you test orchestration logic end-to-end without touching real AWS.

## Source

- [`crates/fakecloud-stepfunctions`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-stepfunctions)
- [AWS Step Functions API reference](https://docs.aws.amazon.com/step-functions/latest/apireference/Welcome.html)
- [Amazon States Language spec](https://states-language.net/spec.html)
