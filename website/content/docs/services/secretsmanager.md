+++
title = "Secrets Manager"
description = "Secrets, versioning, rotation via Lambda, replication."
weight = 10
+++

fakecloud implements **23 of 23** Secrets Manager operations at 100% Smithy conformance.

## Supported features

- **Secrets** — CRUD, tags, resource-based policies
- **Versioning** — stages (AWSCURRENT, AWSPREVIOUS, AWSPENDING), version IDs, explicit version retrieval
- **Soft delete** — DeleteSecret with recovery window, RestoreSecret
- **Rotation** — RotateSecret invokes a Lambda function through all 4 steps (createSecret, setSecret, testSecret, finishSecret)
- **Automatic rotation scheduling** — via `/_fakecloud/secretsmanager/rotation-scheduler/tick`
- **Replication** — replica regions tracked in state, not actually replicated
- **Random password generation** — GetRandomPassword with full character class support
- **Real KMS encryption** — when `KmsKeyId` is set on a secret, `CreateSecret` / `PutSecretValue` call `kms:GenerateDataKey` and `GetSecretValue` calls `kms:Decrypt` with the AWS-shaped encryption context `{aws:secretsmanager:secretArn: <arn>}`. The `aws/secretsmanager` AWS-managed key auto-provisions on first use. All KMS calls land in `/_fakecloud/kms/usage` so test code can assert encryption ran.

## Protocol

JSON protocol. `X-Amz-Target` header, JSON body, JSON responses.

## Introspection

- `POST /_fakecloud/secretsmanager/rotation-scheduler/tick` — trigger rotation for secrets whose schedule is due
- `GET /_fakecloud/kms/usage` — list every KMS call triggered by service-side encryption (Secrets Manager, and the rest of the services as the KMS hook rolls out), with operation, service principal, key ARN, and encryption context

## Cross-service delivery

- **Secrets Manager -> Lambda** — Rotation invokes the configured Lambda for all 4 rotation steps
- **Secrets Manager -> KMS** — Encrypt on Create / PutSecretValue, Decrypt on GetSecretValue when `KmsKeyId` is set

## Source

- [`crates/fakecloud-secretsmanager`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-secretsmanager)
- [AWS Secrets Manager API reference](https://docs.aws.amazon.com/secretsmanager/latest/apireference/Welcome.html)
