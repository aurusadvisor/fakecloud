+++
title = "Free LocalStack alternatives in 2026: fakecloud, MiniStack, floci, Moto"
date = 2026-04-22
description = "Four free, open-source alternatives to LocalStack Community: fakecloud, MiniStack, floci, and Moto. What each is architecturally, how they position, and how to pick by fit."

[extra]
author = "Lucas Vieira"
+++

LocalStack's Community Edition went proprietary in March 2026. Since then a few free, open-source alternatives have surfaced or gained momentum. This post covers the four that keep coming up — fakecloud, MiniStack, floci, and Moto — and what each one is, architecturally.

Upfront disclosure: I maintain fakecloud. Bias declared. What this post avoids: a head-to-head scorecard with numbers I haven't personally measured on all four. That kind of comparison gets out of date in days and reads as marketing when the numbers are favorable to the author. Instead: what each project is, the design choices it's made, and how to think about the fit.

## The architectural split that matters

Two ways to emulate AWS for tests:

**1. In-process library that patches the SDK.** Import a library, decorate your test, library intercepts SDK calls inside your test process. Moto works this way. Fast, no external process, trivial Python setup. Does not speak the AWS wire protocol. Cannot run real Lambda code, real databases, or real Redis.

**2. Real HTTP server speaking the AWS wire protocol.** Separate process on port 4566. SDK points at it via `endpoint_url`. LocalStack, MiniStack, floci, and fakecloud all work this way. Any AWS SDK in any language works. Cross-service wiring runs server-side.

If your tests are "does my Python function call boto3 correctly," Moto. If your tests are "does my whole system actually work end-to-end," HTTP server.

## Two approaches among the HTTP servers

Among the HTTP emulators there's another split that matters, especially for AI-assisted dev and real integration tests:

**Breadth-first:** ship a large catalog of AWS services fast, with partial/surface coverage on each — enough to accept the common calls and return plausible shapes. Good when your tests lean lightly on many services.

**Depth-first:** ship fewer services but at 100% behavioral parity, with real code execution, real stateful backends, and real cross-service wire-ups. Good when your tests actually exercise cross-service flows, or when you want an AI coding agent to be able to rely on the emulator behaving like AWS.

These are philosophies, not rankings. Different workloads prefer different ones.

## fakecloud

**What it is:** single static binary written in Rust, ~19 MB. Speaks the AWS wire protocol on port 4566. No account, no token, no paid tier. AGPL-3.0.

**Approach:** depth-first.

**Explicit goal:** 100% of AWS services, each at 100% behavioral conformance with 100% of cross-service integrations. Services are added one at a time; a service lands when it passes the full Smithy-model test variants and the cross-service wire-ups that matter for it — not when the API surface looks filled in. The roadmap is driven by real-project demand.

**What it covers today:** 23 services, 1,680 operations: S3, SQS, SNS, DynamoDB, Lambda, IAM, STS, KMS, Secrets Manager, SSM, CloudWatch Logs, CloudFormation, EventBridge, EventBridge Scheduler, SES (v2 + v1 inbound), Cognito User Pools, Kinesis, RDS, ElastiCache, Step Functions, API Gateway v2, Bedrock, Bedrock Runtime.

**Distinctive choices driven by the depth-first goal:**
- Real Lambda execution across 13 runtimes in Docker containers — your function code runs, not a stub.
- Real stateful backends: RDS runs real PostgreSQL/MySQL/MariaDB via Docker; ElastiCache runs real Redis/Valkey.
- Cross-service wiring that actually fires: EventBridge -> Step Functions, S3 -> Lambda, SES inbound -> S3/SNS/Lambda, 15+ more integrations.
- Multi-account, SCPs, ABAC, permission boundaries, session policies, KMS key policies, bucket policies — full Allow/Deny/NotPrincipal semantics.
- First-party test-assertion SDKs in TypeScript, Python, Go, PHP, Java, Rust.
- Conformance validated on every commit against 54,000+ Smithy-generated test variants, plus the upstream `hashicorp/terraform-provider-aws` `TestAcc*` suites.

**Source:** [github.com/faiscadev/fakecloud](https://github.com/faiscadev/fakecloud)

## MiniStack

A free LocalStack alternative that surfaced during the March 2026 paywall window. Check the repo for current service coverage, architecture, and approach — the project moves quickly, so numbers in any blog post will be stale within weeks. Evaluate on your test suite's actual needs.

## floci

Another free LocalStack alternative from the same window. Landing page publishes performance claims — verify them against the version you'd actually run before relying on the numbers. Evaluate on your test suite's actual needs.

## Moto

Longest-lived open-source AWS mocking project. Python library, in-process, patches `boto3`. Broad service surface at varying depth. Excellent for Python unit tests where you want boto3 to respond plausibly inside your test process. Not usable from other languages, does not run Lambda code, does not talk to Terraform/CDK deploys.

**Source:** [github.com/getmoto/moto](https://github.com/getmoto/moto)

## LocalStack Pro (for completeness)

Paid tier, mature catalog, commercial support, proprietary license. Fits teams OK with proprietary and per-seat pricing who need the whole LocalStack catalog.

## How to pick

Avoid the temptation to pick by "which has more services." All four of the HTTP emulators (fakecloud, MiniStack, floci, LocalStack Pro) are moving targets; service counts change week to week. The durable questions are:

1. **Do your tests exercise cross-service flows?** (S3 triggers Lambda, EventBridge routes to Step Functions, SES inbound writes to S3, etc.) If yes, depth-first matters more than breadth. The emulator needs to actually *wire* those flows, not just accept each call in isolation.
2. **Do you need real code execution?** (Does your Lambda function actually run, or do you just need a response shape?) fakecloud runs Lambda code in real Docker runtimes; some alternatives return synthetic responses.
3. **Do you need real stateful backends?** (Does your Postgres schema matter? Your Redis data structures?) fakecloud runs real PostgreSQL/MySQL/MariaDB/Redis/Valkey; alternatives vary.
4. **What language are your tests?** Moto is Python-only. Everything else is language-agnostic over HTTP.
5. **How much of AWS does your test mix actually hit?** Open your test suite. Count unique AWS services called. That number is almost always smaller than "total AWS services" and is the only count that matters.

Run your real test suite against each option you're considering. That's the only benchmark that applies to your codebase.

## Links

- fakecloud: [github.com/faiscadev/fakecloud](https://github.com/faiscadev/fakecloud)
- Moto: [github.com/getmoto/moto](https://github.com/getmoto/moto)
- LocalStack: [localstack.cloud](https://localstack.cloud)
- fakecloud install options: [fakecloud.dev/docs/getting-started](/docs/getting-started/)
- fakecloud migration guide: [Migrating from LocalStack to fakecloud](/blog/migrate-from-localstack/)
