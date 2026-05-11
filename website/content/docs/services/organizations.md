+++
title = "Organizations"
description = "AWS Organizations control plane — accounts, OUs, SCPs, tag policies, handshakes, delegated administrators. Real SCP enforcement across services."
weight = 31
+++

fakecloud implements **55 of 55** AWS Organizations operations at 100% Smithy conformance. SCPs (Service Control Policies) are **really enforced** as a permission ceiling across every IAM-evaluated service.

## Supported features

- **Organization lifecycle** — `CreateOrganization`, `DescribeOrganization`, `DeleteOrganization`, `EnableAllFeatures`. The management account is the only caller allowed to mutate org state, matching AWS.
- **Accounts**
  - `CreateAccount` / `CreateGovCloudAccount` run a **real async lifecycle**: the call returns immediately with a `CreateAccountStatus` whose `State` starts `IN_PROGRESS`, then transitions to `SUCCEEDED` after the background task provisions the member account, attaches the default IAM admin role (`OrganizationAccountAccessRole`), and assigns the account to the requested OU (or to the root). `DescribeCreateAccountStatus` and `ListCreateAccountStatus` reflect the real status.
  - `CloseAccount` moves the account to `SUSPENDED` and blocks subsequent control-plane calls from that account ID — the management account is protected and cannot be closed.
  - `RemoveAccountFromOrganization` detaches a member account from the org; subsequent describes flip to `NotFound`, mirroring AWS's behaviour where the account becomes a standalone payer.
  - `DescribeAccount`, `ListAccounts`, `ListAccountsForParent` paginate the directory.
  - `InviteAccountToOrganization` + `AcceptHandshake` / `DeclineHandshake` / `CancelHandshake` / `DescribeHandshake` + `ListHandshakesForAccount` / `ListHandshakesForOrganization` run the real handshake state machine — only the invited account can accept/decline, only the inviter can cancel, and expired handshakes flip to `EXPIRED`.
- **Organizational Units** — `CreateOrganizationalUnit`, `UpdateOrganizationalUnit`, `DeleteOrganizationalUnit`, `DescribeOrganizationalUnit`, `ListOrganizationalUnitsForParent`, `ListChildren`, `ListParents`, `ListRoots`, `MoveAccount`. The hierarchy is enforced — non-empty OUs cannot be deleted, and `MoveAccount` validates both source and destination parents.
- **Policies** — `CreatePolicy`, `UpdatePolicy`, `DeletePolicy`, `DescribePolicy`, `ListPolicies`, `ListPoliciesForTarget`, `ListTargetsForPolicy`, `AttachPolicy`, `DetachPolicy`, `EnablePolicyType`, `DisablePolicyType`, `DescribeEffectivePolicy`. All four AWS policy types are accepted: `SERVICE_CONTROL_POLICY`, `TAG_POLICY`, `BACKUP_POLICY`, `AISERVICES_OPT_OUT_POLICY`. Policy documents are JSON-validated on create/update — malformed content is rejected with `MalformedPolicyDocumentException`.
- **Resource policies** — `PutResourcePolicy`, `DescribeResourcePolicy`, `DeleteResourcePolicy` for the org-wide delegation policy.
- **Service access** — `EnableAWSServiceAccess`, `DisableAWSServiceAccess`, `ListAWSServiceAccessForOrganization`, `RegisterDelegatedAdministrator`, `DeregisterDelegatedAdministrator`, `ListDelegatedAdministrators`, `ListDelegatedServicesForAccount`. Delegated-admin registration is gated on the service having `EnableAWSServiceAccess` first, matching AWS error ordering.
- **Tagging** — `TagResource`, `UntagResource`, `ListTagsForResource` on accounts, OUs, roots, and policies.

## SCP enforcement

Service Control Policies aren't just stored — they're a real permission ceiling. When `FAKECLOUD_IAM=strict` is on, every IAM evaluation walks up from the calling account's parent OU(s) through the root, collects the SCPs that apply at each level, and intersects them with the identity-based policy decision. The semantics match AWS:

- Same-target SCPs are **unioned** (multiple SCPs attached to the same OU/account can each grant a subset).
- Cross-level SCPs are **intersected** (a permission must be allowed at every level — root, parent OU, account — to survive).
- The management account and service-linked roles are exempt, just like AWS.
- An explicit `Deny` at any level wins.

This means a parent OU with `Deny: s3:DeleteBucket` actually blocks the call in a member account even when the member's IAM policy grants `s3:*`. The same machinery enforces TAG_POLICY constraints on `TagResource` calls when strict mode is on.

## Protocol

JSON 1.1. `X-Amz-Target: AWSOrganizationsV20161128.<Action>`.

## Bootstrap

Because Organizations sits above IAM, fakecloud exposes
`POST /_fakecloud/iam/create-admin` to seed a management-account admin
without needing existing credentials. Once the management account is
bootstrapped, the rest of the org lifecycle uses normal SigV4'd
calls.

## Smoke test

```sh
fakecloud &

# Bootstrap a management-account admin.
curl -fsS -X POST http://localhost:4566/_fakecloud/iam/create-admin \
  -H 'content-type: application/json' \
  -d '{"AccountId":"123456789012"}'

aws --endpoint-url http://localhost:4566 organizations create-organization \
  --feature-set ALL

aws --endpoint-url http://localhost:4566 organizations create-account \
  --email dev@example.com --account-name Dev

aws --endpoint-url http://localhost:4566 organizations list-create-account-status \
  --states SUCCEEDED IN_PROGRESS

aws --endpoint-url http://localhost:4566 organizations create-policy \
  --type SERVICE_CONTROL_POLICY \
  --name DenyBucketDelete \
  --description "block deletes" \
  --content '{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}]}'
```

## Gotchas

- **Management account only.** Mutating calls (`CreateAccount`, `AttachPolicy`, `EnableAWSServiceAccess`, etc.) must originate from the management account. Calls from member accounts return `AccessDeniedException`, matching AWS.
- **SCP enforcement is opt-in.** SCPs are stored and `DescribeEffectivePolicy` works in all modes, but enforcement only kicks in under `FAKECLOUD_IAM=strict` (or `soft` for log-only). See [SigV4 verification and IAM enforcement](@/docs/reference/security.md).
- **CreateAccount is async.** The state moves through `IN_PROGRESS` -> `SUCCEEDED` over a short interval; tests should poll `DescribeCreateAccountStatus` rather than assume the account is usable immediately.

## Source

- [`crates/fakecloud-organizations`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-organizations)
- [AWS Organizations API reference](https://docs.aws.amazon.com/organizations/latest/APIReference/Welcome.html)
