+++
title = "SSM"
description = "Parameters, documents, commands, maintenance windows, associations, patch baselines."
weight = 9
+++

fakecloud implements **146 of 146** SSM operations at 100% Smithy conformance.

## Supported features

- **Parameter Store** — String, StringList, SecureString parameters; tiers; labels; versions; history
- **Documents** — CRUD, versions, tags, permissions, sharing
- **Commands** — RunCommand, command history, invocation status, output
- **Maintenance windows** — CRUD, task execution, target registration
- **Associations** — CRUD, execution history, compliance
- **Patch baselines** — CRUD, baseline registration, patch groups
- **Inventory** — entries, schemas, deletion
- **Automation** — executions, step management, signal handling
- **OpsItems** — CRUD, related items, comments, summaries
- **Resource Data Sync** — CRUD with S3 destinations
- **Service settings** — get, reset, update

## Protocol

JSON protocol. `X-Amz-Target` header, JSON body, JSON responses.

## SecureString encryption

SecureString parameters are encrypted through the KMS hook on `PutParameter`
and decrypted on `GetParameter` / `GetParameters` / `GetParametersByPath` when
the caller passes `WithDecryption=true`. The default `alias/aws/ssm`
AWS-managed key is auto-provisioned on first use; passing an explicit `KeyId`
routes encryption through that key instead. KMS calls land in
`/_fakecloud/kms/usage` with the `PARAMETER_ARN` encryption context, so tests
can assert that a parameter's plaintext is never persisted.

## Source

- [`crates/fakecloud-ssm`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-ssm)
- [AWS Systems Manager API reference](https://docs.aws.amazon.com/systems-manager/latest/APIReference/Welcome.html)
