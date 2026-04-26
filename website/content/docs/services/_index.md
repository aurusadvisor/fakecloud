+++
title = "Services"
description = "Every AWS service fakecloud implements, with operation counts and notable features."
sort_by = "weight"
weight = 3
template = "docs.html"
page_template = "docs-page.html"
+++

fakecloud implements 28 AWS services with 2,141 total operations, all at 100% Smithy conformance. Per-service feature matrices and gotchas live on individual service pages — use the sidebar to navigate.

| Service                | Ops | Notes                                                                  |
| ---------------------- | --- | ---------------------------------------------------------------------- |
| S3                     | 107 | Versioning, lifecycle, notifications, multipart, replication, website, **real SSE-KMS encrypt/decrypt** |
| SQS                    |  23 | FIFO, DLQs, long polling, batch, **real KMS encrypt/decrypt on `KmsMasterKeyId` queues** |
| SNS                    |  42 | Fan-out to SQS/Lambda/HTTP, filter policies, **KMS audit-trail on `KmsMasterKeyId` topics** |
| EventBridge            |  57 | Pattern matching, schedules, archives, replay, API destinations        |
| EventBridge Scheduler  |  12 | at/rate/cron, SQS targets, DLQ routing, one-shot self-delete           |
| Lambda                 |  85 | Real Docker, 13 runtimes, ESM with FilterCriteria + partial-batch failure |
| DynamoDB               |  57 | Transactions, PartiQL, backups, global tables, streams, **KMS audit-trail on SSE-KMS tables** |
| IAM                    | 176 | Users, roles, policies, groups, OIDC/SAML, **PassRole trust enforcement** |
| STS                    |  11 | AssumeRole, session tokens, federation                                 |
| SSM                    | 146 | Parameters, documents, commands, maintenance, patch baselines, **SecureString -> real KMS encrypt/decrypt** |
| Secrets Manager        |  23 | Versioning, rotation via Lambda, replication, **real KMS encrypt/decrypt** |
| CloudWatch Logs        | 113 | Groups, streams, subscription filters, query language                  |
| KMS                    |  53 | Encryption, aliases, grants, real ECDH, key import, **cross-service hook** |
| CloudFormation         |  90 | Template parsing, resource provisioning, custom resources              |
| SES (v2 + v1 inbound)  | 110 | Sending, templates, DKIM, **real receipt rule execution**              |
| Cognito User Pools     | 122 | Pools, clients, MFA, identity providers, full auth flows; verification email -> SES, SMS -> SNS, all 12 Lambda triggers |
| Kinesis                |  39 | Streams, records, shard iterators, retention                           |
| RDS                    | 163 | Real Postgres, MySQL, MariaDB, Oracle, SQL Server, Db2 via Docker; lifecycle ops emit `aws.rds` EventBridge events |
| ElastiCache            |  75 | Real Redis, Valkey, Memcached via Docker                                |
| Step Functions         |  37 | Full ASL interpreter, Lambda/SQS/SNS/EventBridge/DynamoDB tasks        |
| API Gateway v1         | 124 | REST APIs, resources, methods, integrations (`MOCK`/`HTTP`/`HTTP_PROXY`/`AWS_PROXY` Lambda), deployments, stages, API keys, usage plans, authorizers, models, request validators, VPC links, domain names, base path mappings, client certs, gateway responses, docs, tags |
| API Gateway v2         | 103 | HTTP APIs, routes, integrations, stages, deployments, authorizers, domains, models, VPC links, routing rules, developer portals, CORS, tags |
| Bedrock                | 101 | Foundation models, guardrails, custom models, invocation/eval jobs    |
| Bedrock Runtime        |  10 | InvokeModel, Converse, streaming, configurable responses, fault inject |
| ECR                    |  58 | Full API — OCI v2 push/pull, lifecycle eval, scanning, pull-through cache, registry templates, real cosign signature verification |
| ECS                    |  60 | Full API — clusters, real Fargate-style task execution via Docker, services + rolling deployments, task sets, container instances, ECS Exec, awslogs -> Logs, secrets injection, task role credentials |
| Elastic Load Balancing v2 |  51 | Full control plane — ALB/NLB/GWLB CRUD, target groups + targets + real health probes, listeners + rules + certificates, attributes, capacity reservations, **mTLS trust stores + revocations**, resource policies, SSL policies, tags. **In-process HTTP data plane for ALBs** — per-LB TCP bind, rule matching, forward / fixed-response / redirect, sticky sessions |
| CloudFront                |  93 | Distributions (full CRUD + ETag/If-Match concurrency + WithTags + copy + by-X listings), invalidations, web ACL associate/disassociate, alias associate, tags. Origin Access Controls + Cache/Origin Request/Response Headers/Continuous Deployment policies. **CloudFront Functions (incl. Publish/Test), Public Keys, Key Groups, Key Value Stores, Origin Access Identities (legacy), Monitoring Subscriptions** — full CRUD. Full `DistributionConfig` round-trip incl. origins, cache behaviors, custom error responses, viewer certificates, geo restrictions |

Detailed per-service pages are coming. If you need specifics on a service today, the conformance baseline at [`conformance-baseline.json`](https://github.com/faiscadev/fakecloud/blob/main/conformance-baseline.json) lists every operation fakecloud handles, and the AWS Smithy models in [`aws-models/`](https://github.com/faiscadev/fakecloud/tree/main/aws-models) are the authoritative source of truth.
