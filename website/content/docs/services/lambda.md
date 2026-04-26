+++
title = "Lambda"
description = "Real code execution in Docker containers across 23 runtimes. Event source mappings, warm container reuse."
weight = 5
+++

fakecloud implements **85 of 85** Lambda operations at 100% Smithy conformance. Unlike most emulators, **Lambda functions actually execute** — fakecloud runs your code inside real Docker containers.

## Supported features

- **Function CRUD** — create, update, delete, list, get
- **Real code execution** — functions run in Docker containers with the official AWS Lambda runtime images
- **23 runtimes** — Node.js (16/18/20/22/24), Python (3.8/3.9/3.10/3.11/3.12/3.13/3.14), Java (11/17/21/25), Go (1.x), Ruby (3.3/3.4), .NET (8/10), `provided.al2`, `provided.al2023`
- **Event source mappings** — SQS, Kinesis, DynamoDB Streams polling loops with **`FilterCriteria`** (EventBridge-style JSON pattern, exists/prefix/suffix/equals-ignore-case/anything-but/numeric operators, SQS body decode), **`StartingPosition`** (`TRIM_HORIZON` / `LATEST` / `AT_TIMESTAMP` for Kinesis, `TRIM_HORIZON` / `LATEST` for DDB Streams), **`MaximumBatchingWindowInSeconds`** (SQS), and **`FunctionResponseTypes=[ReportBatchItemFailures]`** for SQS partial-batch failure semantics
- **Layers** — create, publish, attach to functions
- **Environment variables** — passed to the container
- **Aliases and versions** — publish, point aliases at versions
- **Concurrency controls** — reserved concurrency (recorded, not enforced)
- **Warm container reuse** — subsequent invocations of the same function reuse the container
- **Async invoke destinations** — `OnSuccess` / `OnFailure` routes the invocation result to SQS, SNS, EventBridge, or another Lambda by ARN scheme; record matches the AWS destinations schema (`requestContext`, `requestPayload`, `responseContext`, `responsePayload`)
- **`InvocationType` honored** — `Event` returns 202 and runs in the background, `RequestResponse` blocks for the result, `DryRun` validates without executing

## Protocol

REST. Path-based routing for invoke operations, JSON for control plane.

## Introspection

- `GET /_fakecloud/lambda/invocations` — list all Lambda invocations with input/output/errors
- `GET /_fakecloud/lambda/warm-containers` — list currently warm containers
- `POST /_fakecloud/lambda/{function-name}/evict-container` — force a cold start on the next invoke

## Event source mapping example: FilterCriteria + partial batch failure

```typescript
import { LambdaClient, CreateEventSourceMappingCommand } from "@aws-sdk/client-lambda";

await new LambdaClient({ endpoint: "http://localhost:4566" }).send(
  new CreateEventSourceMappingCommand({
    FunctionName: "process-orders",
    EventSourceArn: "arn:aws:sqs:us-east-1:000000000000:orders",
    BatchSize: 10,
    MaximumBatchingWindowInSeconds: 5,
    // Only deliver paid orders.
    FilterCriteria: {
      Filters: [{ Pattern: '{"body": {"status": ["paid"]}}' }],
    },
    // Opt into partial-batch failure: Lambda returns
    // {"batchItemFailures":[{"itemIdentifier":"<msgId>"}]}
    // and only those messages stay on the queue for retry.
    FunctionResponseTypes: ["ReportBatchItemFailures"],
  })
);
```

## Cross-service triggers

Lambda is a target for most event-producing services:

- **SQS -> Lambda** — Event source mapping polls the queue
- **Kinesis -> Lambda** — Event source mapping polls shards
- **DynamoDB Streams -> Lambda** — Event source mapping polls stream records
- **S3 -> Lambda** — Bucket notifications
- **SNS -> Lambda** — Topic subscriptions
- **EventBridge -> Lambda** — Rule targets
- **API Gateway v2 -> Lambda** — HTTP API proxy integration
- **Cognito -> Lambda** — Triggers (pre-signup, post-confirmation, pre/post-auth, custom message, token generation, migration, custom auth challenge)
- **Secrets Manager -> Lambda** — Rotation (all 4 steps)
- **CloudFormation -> Lambda** — Custom resources via `ServiceToken`
- **SES Inbound -> Lambda** — Receipt rule actions
- **Step Functions -> Lambda** — Task state integrations
- **CloudWatch Logs -> Lambda** — Subscription filters

## Gotchas

- **Requires a Docker socket.** Lambda needs access to `/var/run/docker.sock` to start and stop containers. Only use in environments you trust — Docker socket access is effectively host-level privilege.
- **First invocation of a runtime pulls the image.** Expect a slower first run while the Lambda runtime image downloads. Subsequent invocations are fast.
- **Cold vs. warm containers.** fakecloud reuses containers between invocations for the same function. Force a cold start via `/_fakecloud/lambda/{name}/evict-container`.

## Source

- [`crates/fakecloud-lambda`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-lambda)
- [AWS Lambda API reference](https://docs.aws.amazon.com/lambda/latest/api/welcome.html)
