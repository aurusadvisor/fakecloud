+++
title = "CloudFormation"
description = "Template parsing, resource provisioning, stack management, custom resources."
weight = 13
+++

fakecloud implements **90 of 90** CloudFormation operations at 100% Smithy conformance.

## Supported features

- **Stacks** — CreateStack, UpdateStack, DeleteStack, DescribeStacks
- **Template parsing** — JSON and YAML, parameters, mappings, conditions, outputs
- **Resource provisioning** — creates underlying resources in other fakecloud services (S3 buckets, SQS queues, Lambda functions, etc.) where supported
- **Cross-stack exports / imports** — `Outputs.*.Export.Name` registers entries in an account-wide exports registry; `Fn::ImportValue` substitutes them at provision time. Unknown export names fail the create/update with a `ValidationError` ("No export named X found"), and `DeleteStack` blocks while another live stack still imports an export.
- **`ListExports` / `ListImports`** — read directly from the exports registry / reverse-ref map; export name uniqueness is enforced across the account.
- **Change sets** — CreateChangeSet, DescribeChangeSet, ExecuteChangeSet
- **Stack sets** — CRUD, instance management, operation tracking
- **Stack events** — real event generation during create/update/delete
- **Stack resources** — ListStackResources, DescribeStackResource
- **Custom resources** — invoke Lambda functions via `ServiceToken`
- **Notifications** — notify SNS via `NotificationARNs` on stack events
- **Drift detection** — CRUD (always reports IN_SYNC)
- **Type registry** — Hooks and resource types (recorded)

## Protocol

Query protocol. Form-encoded body, `Action` parameter, XML responses.

## Cross-service delivery

- **CloudFormation -> Lambda** — Custom resources invoke via `ServiceToken`
- **CloudFormation -> SNS** — Stack events notify configured topics via `NotificationARNs`

## Gotchas

- **Not every resource type provisions something.** Common types (AWS::S3::Bucket, AWS::SQS::Queue, AWS::Lambda::Function) create real resources in fakecloud. Less common types are recorded but don't create backing state. If your stack references a resource type that isn't backed, your code will still see it as provisioned, but dependent operations may fail.

## Source

- [`crates/fakecloud-cloudformation`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-cloudformation)
- [AWS CloudFormation API reference](https://docs.aws.amazon.com/AWSCloudFormation/latest/APIReference/Welcome.html)
