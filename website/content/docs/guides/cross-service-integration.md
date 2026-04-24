+++
title = "Cross-service integration tests"
description = "fakecloud actually executes the wiring between services. Here's every supported integration."
weight = 2
+++

The hardest bugs in AWS applications live in the wiring between services. A Lambda that's supposed to trigger on S3 uploads but doesn't. An EventBridge rule that fires but delivers to the wrong target. A Step Functions state machine that waits forever because the Lambda integration is shaped wrong.

Mocks can't catch those bugs. They test each service in isolation, and the wiring between them is exactly where the bugs hide.

fakecloud actually executes the cross-service wiring. When an EventBridge rule matches, it really delivers to the target. When an SES receipt rule evaluates, it really invokes the Lambda. When an S3 object is uploaded, it really publishes the notification. Tests that exercise end-to-end behavior work the same way they would against real AWS.

## Supported integrations

**Messaging and eventing:**

- **SNS -> SQS / Lambda / HTTP** — Fan-out delivery to all subscription types.
- **S3 -> SNS / SQS / Lambda / EventBridge** — Bucket notifications on object create/delete.
- **EventBridge -> SNS / SQS / Lambda / Logs / Kinesis / Step Functions / HTTP** — Rules deliver to targets on schedule or event match, including API Destinations.
- **SQS -> Lambda** — Event source mapping polls queues and invokes functions.
- **Kinesis -> Lambda** — Event source mapping polls shards and invokes functions.
- **DynamoDB Streams -> Lambda** — Event source mapping polls stream records and invokes.
- **DynamoDB -> Kinesis** — Table changes stream to Kinesis Data Streams.
- **CloudWatch Logs -> Lambda / Kinesis / SQS** — Subscription filters deliver log events.
- **Lambda async destinations -> SQS / SNS / EventBridge / Lambda** — `InvocationType=Event` invocations route their result through `OnSuccess` / `OnFailure` using AWS's standard destinations record schema.

**Identity and auth:**

- **Cognito -> Lambda** — All 12 triggers: PreSignUp, PostConfirmation, PreAuthentication, PostAuthentication, CustomMessage, PreTokenGeneration, UserMigration, DefineAuthChallenge, CreateAuthChallenge, VerifyAuthChallengeResponse, CustomEmailSender, CustomSMSSender.
- **Cognito -> SES** — Verification emails for SignUp / ResendConfirmationCode / ForgotPassword / GetUserAttributeVerificationCode dispatch through SES (CustomEmailSender Lambda takes precedence when configured).
- **Cognito -> SNS** — SMS verification codes dispatch through SNS as `sms_messages` (CustomSMSSender Lambda takes precedence when configured).

**Email:**

- **SES -> SNS / EventBridge** — Email event fanout (send, delivery, bounce, complaint) via configured event destinations.
- **SES Inbound -> S3 / SNS / Lambda** — Receipt rules evaluate inbound email and execute S3, SNS, and Lambda actions for real.

**Orchestration and APIs:**

- **Step Functions -> Lambda / SQS / SNS / EventBridge / DynamoDB** — Task states invoke Lambda, send SQS messages, publish to SNS topics, put EventBridge events, and read/write DynamoDB items.
- **API Gateway v2 -> Lambda** — HTTP API routes invoke Lambda functions with proxy integration v2.0 format.

**Infrastructure:**

- **CloudFormation -> Lambda / SNS** — Custom resources invoke via `ServiceToken`, stack events notify via `NotificationARNs`.
- **Secrets Manager -> Lambda** — Rotation invokes Lambda for all 4 steps.
- **S3 Lifecycle** — Background expiration and storage class transitions.
- **EventBridge Scheduler** — Cron and rate-based rules fire on schedule.
- **RDS -> EventBridge** — DB instance and snapshot lifecycle ops (create, modify, delete, reboot, start, stop, snapshot create/delete, restore) emit `aws.rds` events that match the AWS event schema.
- **ECS -> EventBridge** — Task state transitions emit `ECS Task State Change` events on the default bus.

## Testing a cross-service flow

The pattern is the same for all of them: configure the wiring via the normal AWS SDK, trigger the upstream event, then assert on the downstream state via the fakecloud SDK.

Example — S3 upload triggers Lambda via an event source:

```typescript
import { FakeCloud } from "fakecloud";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";

const fc = new FakeCloud();

// (assume bucket, Lambda, and notification config already created via SDK)

await new S3Client({ endpoint: "http://localhost:4566", /* ... */ }).send(
  new PutObjectCommand({ Bucket: "my-bucket", Key: "uploads/hello.txt", Body: "hi" })
);

// Lambda really ran. Assert on its invocations.
const { invocations } = await fc.lambda.getInvocations();
expect(invocations).toHaveLength(1);
expect(invocations[0].event.Records[0].s3.object.key).toBe("uploads/hello.txt");
```

No mocks. The S3 upload actually triggered the notification, which actually invoked the Lambda, which actually ran and recorded its invocation — all in the same fakecloud process. If any step of that wiring is broken in your code, the test fails the same way it would against real AWS.

## What doesn't exist yet

If you need a cross-service integration that isn't in the list above, [open an issue](https://github.com/faiscadev/fakecloud/issues). The ones that exist were driven by real user needs, and the list keeps growing.
