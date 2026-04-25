+++
title = "IAM"
description = "Users, roles, policies, groups, instance profiles, OIDC/SAML providers."
weight = 7
+++

fakecloud implements **176 of 176** IAM operations at 100% Smithy conformance.

## Supported features

- **Users** — CRUD, access keys, login profiles, signing certificates, SSH public keys, service-specific credentials, MFA devices
- **Roles** — CRUD, inline policies, managed policies, trust relationships, instance profile relationships
- **Groups** — CRUD, user membership, inline and managed policies
- **Policies** — managed policies, policy versions, attachment, simulation (recorded)
- **Instance profiles** — CRUD, role attachment
- **OIDC providers** — CRUD, client IDs, thumbprints
- **SAML providers** — CRUD, metadata documents
- **Account management** — aliases, password policy, summary
- **Tags** — on users, roles, policies, and policy versions
- **Service-linked roles** — CRUD with service name validation
- **PassRole trust enforcement** — when a role ARN is passed to Lambda (`CreateFunction`) or ECS (`RegisterTaskDefinition`, `RunTask` overrides), the role's `AssumeRolePolicyDocument` is checked against the calling service's principal (`lambda.amazonaws.com`, `ecs-tasks.amazonaws.com`). Roles whose trust policy doesn't allow the principal are rejected with `InvalidParameterValueException` / `InvalidParameterException`, matching real AWS

## PassRole trust policy example

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {"Service": "lambda.amazonaws.com"},
    "Action": "sts:AssumeRole"
  }]
}
```

For ECS, replace `lambda.amazonaws.com` with `ecs-tasks.amazonaws.com`. Multiple service principals can be granted in one statement using `"Service": ["lambda.amazonaws.com", "ecs-tasks.amazonaws.com"]`.

## Protocol

Query protocol. Form-encoded body, `Action` parameter, XML responses.

## Gotchas

- **Policies are stored and optionally evaluated.** By default fakecloud records IAM policies without evaluating them. Set `FAKECLOUD_IAM=strict` (or `soft` for log-only) to turn on policy evaluation — Allow/Deny with Deny precedence, Action/Resource wildcards, user/group/role inline and managed policies, `Condition` blocks with all 28 AWS operators and global + service-specific keys, resource-based policies for S3 bucket, SNS topic, Lambda function, and KMS key policies with AWS's cross-account combining semantics, full `Principal` / `NotPrincipal` matching, permission boundaries (`PutUserPermissionsBoundary` / `PutRolePermissionsBoundary`), session policies passed to `AssumeRole` / `AssumeRoleWithWebIdentity` / `AssumeRoleWithSAML` / `GetFederationToken`, ABAC tag conditions (`aws:ResourceTag`, `aws:RequestTag`, `aws:TagKeys`, `aws:PrincipalTag`) on S3, SQS, SNS, and IAM resources, and Organizations SCPs (Service Control Policies) ceiling enforcement across multi-account setups. See [SigV4 verification and IAM enforcement](@/docs/reference/security.md) for the full scope.
- **SigV4 verification is opt-in.** By default fakecloud parses signatures for routing but doesn't verify them. Set `FAKECLOUD_VERIFY_SIGV4=true` to turn on cryptographic verification with the standard ±15-minute clock skew window. The reserved `test`/`test` root-bypass convention always passes, matching LocalStack.

## Source

- [`crates/fakecloud-iam`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-iam)
- [AWS IAM API reference](https://docs.aws.amazon.com/IAM/latest/APIReference/welcome.html)
