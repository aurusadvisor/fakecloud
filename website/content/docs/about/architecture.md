+++
title = "Architecture"
description = "How fakecloud is structured as a Cargo workspace and how it dispatches AWS requests."
weight = 1
+++

fakecloud is a single Rust binary built from a Cargo workspace. Each AWS service lives in its own crate; a small core crate handles request dispatch and shared types.

## Workspace layout

| Crate                      | Purpose                                                                  |
| -------------------------- | ------------------------------------------------------------------------ |
| `fakecloud`                | Binary entry point (clap CLI, Axum HTTP server)                          |
| `fakecloud-core`           | `AwsService` trait, service registry, request dispatch, protocol parsing |
| `fakecloud-aws`            | Shared AWS types (ARNs, error builders, SigV4 parser)                    |
| `fakecloud-sqs`            | SQS                                                                      |
| `fakecloud-sns`            | SNS with delivery to SQS/Lambda/HTTP                                     |
| `fakecloud-eventbridge`    | EventBridge with scheduler                                               |
| `fakecloud-iam`            | IAM and STS                                                              |
| `fakecloud-ssm`            | SSM Parameter Store                                                      |
| `fakecloud-dynamodb`       | DynamoDB                                                                 |
| `fakecloud-lambda`         | Lambda with Docker-based execution                                       |
| `fakecloud-secretsmanager` | Secrets Manager                                                          |
| `fakecloud-s3`             | S3                                                                       |
| `fakecloud-logs`           | CloudWatch Logs                                                          |
| `fakecloud-kms`            | KMS                                                                      |
| `fakecloud-cloudformation` | CloudFormation                                                           |
| `fakecloud-ses`            | SES (v2 REST + v1 inbound Query)                                         |
| `fakecloud-cognito`        | Cognito User Pools                                                       |
| `fakecloud-kinesis`        | Kinesis                                                                  |
| `fakecloud-rds`            | RDS with Docker-backed database execution                                |
| `fakecloud-elasticache`    | ElastiCache with Docker-backed Redis/Valkey/Memcached                    |
| `fakecloud-bedrock`        | Bedrock + Bedrock Runtime                                                |
| `fakecloud-bedrock-agent`  | Bedrock Agents control plane                                             |
| `fakecloud-bedrock-agent-runtime` | Bedrock Agents runtime (InvokeAgent, RetrieveAndGenerate)         |
| `fakecloud-apigateway`     | API Gateway v1 (REST APIs)                                               |
| `fakecloud-apigatewayv2`   | API Gateway v2 (HTTP APIs + WebSocket)                                   |
| `fakecloud-ecr`            | Elastic Container Registry (OCI v2 push/pull)                            |
| `fakecloud-ecs`            | Elastic Container Service (Docker-backed task execution)                 |
| `fakecloud-elbv2`          | Elastic Load Balancing v2 (ALB/NLB/GWLB, in-process HTTP data plane)     |
| `fakecloud-cloudfront`     | CloudFront                                                               |
| `fakecloud-route53`        | Route 53 (hosted zones, RRsets, DNSSEC, traffic policies)                |
| `fakecloud-acm`            | AWS Certificate Manager                                                  |
| `fakecloud-wafv2`          | WAFv2 (wired into ALB and API Gateway data planes)                       |
| `fakecloud-athena`         | Athena (control plane + synthesized query results)                       |
| `fakecloud-application-autoscaling` | Application Auto Scaling                                        |
| `fakecloud-organizations`  | AWS Organizations + Service Control Policies                             |
| `fakecloud-firehose`       | Kinesis Data Firehose (real S3 destination delivery)                     |
| `fakecloud-glue`           | Glue Data Catalog + Job control plane                                    |
| `fakecloud-stepfunctions`  | Step Functions (ASL interpreter)                                         |
| `fakecloud-sdk`            | Rust SDK for `/_fakecloud/*` introspection endpoints                     |
| `fakecloud-e2e`            | End-to-end tests using `aws-sdk-rust`                                    |
| `fakecloud-conformance`    | Smithy-driven conformance harness                                        |

## Protocol handling

AWS services use several different wire protocols. fakecloud dispatches incoming requests to the right service based on a combination of headers, URL paths, and form parameters.

- **Query protocol** (SQS, SNS, IAM, STS, CloudFormation, SES v1, RDS, ElastiCache): form-encoded body, `Action` parameter, XML responses.
- **JSON protocol** (SSM, EventBridge, DynamoDB, Secrets Manager, CloudWatch Logs, KMS, Cognito User Pools, Kinesis, Step Functions): JSON body, `X-Amz-Target` header, JSON responses.
- **REST protocol** (S3, Lambda, SES v2, Bedrock, Bedrock Runtime, API Gateway v2): HTTP method + path-based routing, XML or JSON responses depending on service.
- **SES v1 inbound** uses Query protocol for receipt rule and filter operations.

SigV4 signatures are parsed to help route requests to the right service but are never validated.

## Why this structure

The workspace split keeps each service isolated — its types, logic, tests, and storage all live in one crate. The core crate is intentionally small: just enough to parse protocols, route requests, and hand off to services. This keeps compile times reasonable as services grow and makes it easy to reason about per-service behavior.
