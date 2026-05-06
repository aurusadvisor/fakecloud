+++
title = "Introspection endpoints"
description = "Every /_fakecloud/* endpoint for test assertions, simulation, and state control."
weight = 3
+++

fakecloud exposes `/_fakecloud/*` endpoints for testing behaviors that AWS runs asynchronously (TTL expiration, scheduled rotation, lifecycle, etc.) and for asserting on state from within tests. The first-party SDKs wrap these into ergonomic helpers — see [SDK setup](/docs/getting-started/sdk-setup/) — but the raw endpoints are documented here as the source of truth.

## Health

| Endpoint                  | Method | Description |
| ------------------------- | ------ | ----------- |
| `/_fakecloud/health`      | GET    | Returns `{"status":"ok","version":"<version>","services":[...]}`. Lists every service fakecloud is serving. |

```sh
curl http://localhost:4566/_fakecloud/health
```

```json
{
  "status": "ok",
  "version": "0.10.0",
  "services": [
    "apigatewayv2", "bedrock", "cloudformation", "cognito-idp",
    "dynamodb", "elasticache", "events", "iam", "kinesis", "kms",
    "lambda", "logs", "rds", "s3", "secretsmanager", "ses", "sns",
    "sqs", "ssm", "states", "sts"
  ]
}
```

## Reset

| Endpoint                      | Method | Description |
| ----------------------------- | ------ | ----------- |
| `/_fakecloud/reset`           | POST   | Reset all state across all services. |
| `/_fakecloud/reset/{service}` | POST   | Reset only the specified service. Returns `{"reset":"<service>"}`. |

## Lambda

| Endpoint                                          | Method | Description |
| ------------------------------------------------- | ------ | ----------- |
| `/_fakecloud/lambda/invocations`                  | GET    | List all Lambda invocations. |
| `/_fakecloud/lambda/warm-containers`              | GET    | List warm Lambda containers. |
| `/_fakecloud/lambda/{function-name}/evict-container` | POST | Force a cold start on the next invoke. |

## SQS

| Endpoint                                    | Method | Description |
| ------------------------------------------- | ------ | ----------- |
| `/_fakecloud/sqs/messages`                  | GET    | List all SQS messages across queues. |
| `/_fakecloud/sqs/expiration-processor/tick` | POST   | Expire SQS messages past retention. |
| `/_fakecloud/sqs/{queue_name}/force-dlq`    | POST   | Force-move messages exceeding `maxReceiveCount` to DLQ. |

## SNS

| Endpoint                                | Method | Description |
| --------------------------------------- | ------ | ----------- |
| `/_fakecloud/sns/messages`              | GET    | List all published SNS messages. |
| `/_fakecloud/sns/pending-confirmations` | GET    | List subscriptions pending confirmation. |
| `/_fakecloud/sns/confirm-subscription`  | POST   | Force-confirm a subscription. Body: `{"subscriptionArn":"..."}`. |

## EventBridge

| Endpoint                       | Method | Description |
| ------------------------------ | ------ | ----------- |
| `/_fakecloud/events/history`   | GET    | List all EventBridge events and deliveries. |
| `/_fakecloud/events/fire-rule` | POST   | Fire an EventBridge rule manually. Body: `{"busName":"...","ruleName":"..."}`. |

## S3

| Endpoint                                    | Method | Description |
| ------------------------------------------- | ------ | ----------- |
| `/_fakecloud/s3/notifications`              | GET    | List S3 notification events. |
| `/_fakecloud/s3/lifecycle-processor/tick`   | POST   | Run one S3 lifecycle tick. Returns counts. |

## DynamoDB

| Endpoint                                     | Method | Description |
| -------------------------------------------- | ------ | ----------- |
| `/_fakecloud/dynamodb/ttl-processor/tick`    | POST   | Expire items whose TTL attribute is in the past. |

## Application Auto Scaling

| Endpoint                                     | Method | Description |
| -------------------------------------------- | ------ | ----------- |
| `/_fakecloud/application-autoscaling/tick`   | POST   | Force the watcher to evaluate every scaling policy now. Returns `{ "applied": <int> }` — the count of policies that applied a capacity change this tick. |

## Secrets Manager

| Endpoint                                              | Method | Description |
| ----------------------------------------------------- | ------ | ----------- |
| `/_fakecloud/secretsmanager/rotation-scheduler/tick`  | POST   | Rotate secrets whose rotation schedule is due. |

## SSM

| Endpoint                                              | Method | Description |
| ----------------------------------------------------- | ------ | ----------- |
| `/_fakecloud/ssm/commands/{command_id}/status`        | POST   | Force a `SendCommand` to a specific status. Body: `{"accountId":"...", "status":"Failed"}`. |
| `/_fakecloud/ssm/commands/{command_id}/fail`          | POST   | Fail one (or all) command invocations. Body: `{"accountId":"?", "instanceId":"?", "statusDetails":"?", "standardErrorContent":"?"}`. Returns `{"updatedInvocations":N}`. |

`SendCommand` runs through `Pending` -> `InProgress` -> `Success` automatically over ~2 seconds. The `/fail` endpoint lets tests inject a non-zero exit at any point — by default it stamps every invocation, or pass `instanceId` to target one. `statusDetails` overrides the friendly status string (e.g. `"Script exited with code 7"`); `standardErrorContent` is exposed via `GetCommandInvocation`.

## SES

| Endpoint                   | Method | Description |
| -------------------------- | ------ | ----------- |
| `/_fakecloud/ses/emails`   | GET    | List all sent SES emails. |
| `/_fakecloud/ses/inbound`  | POST   | Simulate receiving an inbound email. Evaluates receipt rules and executes actions. |

## Cognito

| Endpoint                                                      | Method | Description |
| ------------------------------------------------------------- | ------ | ----------- |
| `/_fakecloud/cognito/confirmation-codes`                      | GET    | List all pending confirmation codes. |
| `/_fakecloud/cognito/confirmation-codes/{pool_id}/{username}` | GET    | Codes for a specific user. |
| `/_fakecloud/cognito/confirm-user`                            | POST   | Force-confirm a user. |
| `/_fakecloud/cognito/tokens`                                  | GET    | List all active tokens (without exposing strings). |
| `/_fakecloud/cognito/expire-tokens`                           | POST   | Expire tokens for a pool/user. |
| `/_fakecloud/cognito/auth-events`                             | GET    | List auth events (signup, signin, failures). |
| `/_fakecloud/cognito/authorization-codes`                     | POST   | Mint a single-use OAuth2 authorization code for the `authorization_code` grant. Test-only equivalent of `/oauth2/authorize`. |

## Step Functions

| Endpoint                               | Method | Description |
| -------------------------------------- | ------ | ----------- |
| `/_fakecloud/stepfunctions/executions` | GET    | List executions with status, input, output, timestamps. |

## API Gateway v2

| Endpoint                              | Method | Description |
| ------------------------------------- | ------ | ----------- |
| `/_fakecloud/apigatewayv2/requests`   | GET    | List all HTTP API requests received. |
| `/_fakecloud/apigatewayv2/connections` | GET   | List live WebSocket connections (id, api, stage, timestamps, source IP). |

## RDS

| Endpoint                    | Method | Description |
| --------------------------- | ------ | ----------- |
| `/_fakecloud/rds/instances` | GET    | List fakecloud-managed DB instances with runtime metadata (container id, host port). |

## Bedrock

| Endpoint                                                | Method        | Description |
| ------------------------------------------------------- | ------------- | ----------- |
| `/_fakecloud/bedrock/invocations`                       | GET           | List runtime invocations. Each entry has `modelId`, `input`, `output`, `timestamp`, `error`. |
| `/_fakecloud/bedrock/models/{model_id}/response`        | POST          | Set a single custom response for a model (all calls). |
| `/_fakecloud/bedrock/models/{model_id}/responses`       | POST / DELETE | Set or clear prompt-conditional response rules. See the [Bedrock testing guide](/docs/guides/testing-bedrock/). |
| `/_fakecloud/bedrock/faults`                            | POST / GET / DELETE | Queue, list, or clear fault-injection rules (`ThrottlingException`, `ModelTimeoutException`, etc.). |

See the [Bedrock testing guide](/docs/guides/testing-bedrock/) for the full test loop using these endpoints.
