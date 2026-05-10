+++
title = "Parity matrix"
description = "Service-by-service behavior parity: what is real, what is synthesized, and what is not yet implemented."
weight = 1
+++

fakecloud implements **33 AWS services** with **2,422 operations**. Every operation passes [Smithy conformance](https://github.com/faiscadev/fakecloud/blob/main/conformance-baseline.json) validation, meaning request/response shapes, field names, and error codes match AWS exactly. Behavior parity varies by service — some run real infrastructure (Postgres, Redis, Docker containers), some run a real control plane but return synthesized data for complex queries, and a few have control-plane-only coverage with no data-plane enforcement.

| Service | Ops | Protocol | Control plane | Data plane | Known limitations |
| --- | --- | --- | --- | --- | --- |
| [S3](@/docs/services/s3.md) | 107 | REST-XML | Full | Full | Object Lambda, S3 Select, access points, and multi-region access points are control-plane only. Object Lock compliance mode is enforced on single-object delete but not yet on batch delete. |
| [SQS](@/docs/services/sqs.md) | 23 | JSON 1.1 (Query) | Full | Full | — |
| [SNS](@/docs/services/sns.md) | 42 | JSON 1.1 (Query) | Full | Full | — |
| [EventBridge](@/docs/services/eventbridge.md) | 57 | JSON 1.1 | Full | Full | — |
| [EventBridge Scheduler](@/docs/services/scheduler.md) | 12 | JSON 1.1 | Full | Full | — |
| [Lambda](@/docs/services/lambda.md) | 85 | REST-JSON | Full | Full | Reserved concurrency is recorded but not yet enforced at invoke time. Provisioned concurrency is a roadmap item. |
| [DynamoDB](@/docs/services/dynamodb.md) | 57 | JSON 1.1 | Full | Full | — |
| [IAM](@/docs/services/iam.md) | 176 | JSON 1.1 (Query) | Full | Full | — |
| [STS](@/docs/services/sts.md) | 11 | JSON 1.1 (Query) | Full | Full | — |
| [SSM](@/docs/services/ssm.md) | 146 | JSON 1.1 | Full | Partial | `StartSession` returns a clear 501 with documentation pointer rather than opening a real websocket. Session Manager data plane is not implemented. |
| [Secrets Manager](@/docs/services/secretsmanager.md) | 23 | JSON 1.1 | Full | Full | — |
| [CloudWatch Logs](@/docs/services/logs.md) | 113 | JSON 1.1 | Full | Partial | `StartLiveTail`, `GetLogObject`, and `GetLogFields` return shape-correct stub responses. Log event export to S3 and Firehose is real. Metric filters extract metrics from ingested logs. |
| [KMS](@/docs/services/kms.md) | 53 | JSON 1.1 | Full | Full | — |
| [CloudFormation](@/docs/services/cloudformation.md) | 90 | JSON 1.1 (Query) | Full | Full | Custom resources execute real Lambda-backed custom resource providers. |
| [SES](@/docs/services/ses.md) | 110 | JSON 1.1 | Full | Full | v2 sending + v1 inbound receipt rules are both real. DKIM signing is real. Bounce simulator addresses are available for testing. SMTP credential issuance is implemented via IAM service-specific credentials, and an opt-in SMTP submission listener (`FAKECLOUD_SES_SMTP_PORT`) accepts mail authenticated with those credentials. |
| [Cognito User Pools](@/docs/services/cognito.md) | 122 | JSON 1.1 | Full | Full | Real RSA-2048 RS256 JWT signing. JWKS + OIDC discovery endpoints serve real JWKs. `/oauth2/token`, `/oauth2/authorize`, `/oauth2/userInfo`, and `/oauth2/revoke` are all implemented. Refresh token rotation is supported when enabled. |
| [Cognito Identity](@/docs/services/cognito.md) | 20 | JSON 1.1 | Full | Full | Identity pools, federated identities, developer identities, and real STS-style credential issuance are implemented. |
| [Kinesis](@/docs/services/kinesis.md) | 39 | JSON 1.1 | Full | Full | — |
| [RDS](@/docs/services/rds.md) | 163 | JSON 1.1 (Query) | Full | Full | Real Postgres, MySQL, MariaDB, Oracle, SQL Server, and Db2 via Docker. PostgreSQL `aws_lambda` + `aws_s3` extensions and Aurora-compatible MySQL/MariaDB `mysql.lambda_async`/`mysql.lambda_sync` invoke fakecloud Lambda and import/export S3 objects from SQL. |
| [ElastiCache](@/docs/services/elasticache.md) | 75 | JSON 1.1 (Query) | Full | Full | Real Redis, Valkey, and Memcached via Docker. |
| [Step Functions](@/docs/services/stepfunctions.md) | 37 | JSON 1.1 | Full | Full | Full ASL interpreter with `.sync` wait patterns, `waitForTaskToken`, and generic `aws-sdk:*` integrations. |
| [API Gateway v1](@/docs/services/apigateway.md) | 124 | REST-JSON | Full | Partial | Authorizer enforcement (TOKEN/REQUEST/COGNITO_USER_POOLS) is implemented. Request validators, VTL templates, AWS direct service integrations, and VPC_LINK data plane are partially implemented or stubbed. |
| [API Gateway v2](@/docs/services/apigatewayv2.md) | 103 | JSON 1.1 | Full | Partial | WebSocket support (`$connect`/`$disconnect`/`$default`) is implemented. JWT and Lambda authorizer enforcement, AWS service integrations, and access log delivery are partially implemented or stubbed. |
| [Bedrock](@/docs/services/bedrock.md) | 101 | JSON 1.1 | Full | Partial | Control plane (guardrails, custom models, jobs, inference profiles) is fully implemented. Runtime (`InvokeModel`, `Converse`, streaming) runs in echo / configurable-response mode with real token counting and fault injection, not real model inference. |
| [Bedrock Runtime](@/docs/services/bedrock.md) | 10 | JSON 1.1 | Full | Partial | Same as Bedrock runtime notes above. |
| [ECR](@/docs/services/ecr.md) | 58 | JSON 1.1 | Full | Full | OCI v2 push/pull is real. Lifecycle policy evaluation, image scanning, pull-through cache, registry templates, and cosign signature verification are all implemented. |
| [ECS](@/docs/services/ecs.md) | 60 | JSON 1.1 (Query) | Full | Full | Real Fargate-style task execution via Docker, services with rolling deployments, task sets, container instances, capacity providers, and ECS Exec. Multi-container tasks, volume mounts, health checks, and `dependsOn` ordering are all implemented. |
| [ELBv2](@/docs/services/elbv2.md) | 51 | JSON 1.1 (Query) | Full | Partial | Control plane (ALB/NLB/GWLB CRUD, target groups, listeners, rules, mTLS trust stores) is fully implemented. An in-process HTTP data plane for ALBs handles rule matching, forwarding, fixed-response, redirect, and sticky sessions. WAFv2 inspection is wired into the ALB data plane. NLB and GWLB data planes are not implemented. |
| [CloudFront](@/docs/services/cloudfront.md) | 147 | REST-XML | Full | Partial | Control plane is fully implemented (distributions, policies, functions, key value stores, etc.). CloudFront Functions can be tested via `TestFunction`. There is no actual CDN edge network — distributions do not serve traffic from edge locations. |
| [Route 53](@/docs/services/route53.md) | 71 | REST-XML | Full | Partial | Control plane is fully implemented (hosted zones, RRsets, health checks, DNSSEC, traffic policies, etc.). `TestDNSAnswer` resolves routing policies and alias targets using fakecloud state. A real DNS server on UDP/TCP 53 is not implemented by default. |
| [WAFv2](@/docs/services/wafv2.md) | 55 | JSON 1.1 | Full | Control-only | Control plane is fully implemented (WebACLs, rule groups, IP sets, regex patterns, API keys, managed rules, logging). WAFv2 inspection is wired into the ELBv2 ALB data plane and API Gateway v1+v2 data planes, but CloudFront and AppSync associations are stored only. Rate-based rules and CAPTCHA/Challenge actions are not enforced against real traffic. |
| [Application Auto Scaling](@/docs/services/application-autoscaling.md) | 14 | JSON 1.1 | Full | Partial | Control plane is fully implemented (scalable targets, step/target-tracking/predictive policies, scheduled actions). Scaling actions fire and update the target service (`UpdateService` for ECS, `UpdateTable` for DynamoDB, etc.), but the actual metric-driven alarm loop is synthesized. |
| [Athena](@/docs/services/athena.md) | 70 | JSON 1.1 | Full | Control-only | Control plane is fully implemented. `StartQueryExecution` synthesizes a `SUCCEEDED` execution with a single-row `["1"]` result. fakecloud is not a SQL engine. |
| [ACM](@/docs/services/acm.md) | 17 | JSON 1.1 | Full | Partial | Control plane is fully implemented. Certificates are self-signed (`rcgen`) or imported PEM. DNS validation is auto-promoted after a configurable delay; there is no real CA or DNS validation pipeline. EMAIL validation stays `PENDING_VALIDATION` until approved via the admin endpoint. |
| [CloudWatch (Metrics & Alarms)](@/docs/services/cloudformation.md) | 7 | JSON 1.1 (Query) | Full | Partial | `PutMetricData`, `GetMetricStatistics`, `GetMetricData`, `ListMetrics`, `PutMetricAlarm`, `DescribeAlarms`, and `DeleteAlarms` are implemented. Alarm threshold transitions trigger SNS/AppAS/EC2 actions. Metrics are stored in memory and do not persist across server restarts. |

## Reading the matrix

* **Control plane** — the APIs that create, configure, and manage resources (e.g., `CreateBucket`, `PutRolePolicy`, `CreateFunction`). fakecloud implements 100% of the control plane for every service listed above.
* **Data plane** — the APIs that process, store, or move actual data (e.g., `GetObject`, `InvokeModel`, `AssumeRole`, `SendMessage`). A service marked **Full** has a real data plane. A service marked **Partial** has some real data-plane operations and some synthesized / stubbed ones. A service marked **Control-only** has no data-plane implementation.
* **Known limitations** — specific gaps that are intentionally synthesized or not yet implemented. These are usually outside the Smithy conformance boundary (the shape is correct, but the behavior is simplified). If a limitation is important for your use case, open an issue or check the [service-specific docs](@/docs/services/_index.md) for workarounds.

## What "100% conformance" means

fakecloud validates every implemented operation against AWS's own Smithy models using a generated test suite with **59,000+ variants**. This guarantees that field names, types, required/optional flags, error codes, and HTTP signatures are identical to AWS. It does *not* guarantee that every operation behaves exactly like AWS in all edge cases — that is what the **Data plane** and **Known limitations** columns describe.

If you need a service that is not listed above, the issue tracker and [roadmap](https://github.com/faiscadev/fakecloud#roadmap) are the best places to request it.
