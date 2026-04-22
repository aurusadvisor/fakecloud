+++
title = "Free LocalStack alternatives in 2026: fakecloud, MiniStack, floci, Moto"
date = 2026-04-22
description = "Four free, open-source alternatives to LocalStack Community: fakecloud, MiniStack, floci, and Moto. What each is good at, how they differ in approach, and which to pick."

[extra]
author = "Lucas Vieira"
+++

LocalStack's Community Edition went proprietary in March 2026. Since then, a few free, open-source alternatives have surfaced or gained momentum. This post covers the four that keep coming up — fakecloud, MiniStack, floci, and Moto — and explains where each one actually fits.

Some upfront disclosure: I maintain fakecloud. I am not going to pretend I don't have a bias. What I will do is describe each project by what it architecturally is, what it sets out to do, and where the fit lines sit. If you are shopping for a LocalStack replacement, that framing is more useful than a fake head-to-head benchmark.

## TL;DR — pick by workload

- **Python unit tests that mock boto3 in-process:** Moto.
- **Multi-language integration tests, real HTTP, real Lambda execution, real RDS/Redis:** fakecloud.
- **Wanted a Docker-based LocalStack Community replacement, same operating model:** MiniStack or floci. (Or fakecloud, which also runs as a Docker image.)
- **You need full LocalStack service catalog and don't mind paying:** LocalStack Pro.

The rest of this post explains the differences.

## The architectural split that matters

There are two fundamentally different ways to emulate AWS for tests:

**1. In-process library that patches the SDK.** You import a library, decorate your test, and the library intercepts SDK calls inside your test process. Moto works this way. It's very fast, has no external process, and is trivial to set up for Python. It does not actually speak the AWS wire protocol, and it cannot run real Lambda code, real databases, or real Redis. It is for unit-ish tests.

**2. Real HTTP server that speaks the AWS wire protocol.** You run a separate process that listens on a port (usually 4566). Your SDK points at it via `endpoint_url`. LocalStack, MiniStack, floci, and fakecloud all work this way. Because it's a real HTTP server, any AWS SDK in any language works against it, and cross-service wiring (EventBridge -> Lambda, S3 -> SNS) runs server-side.

If your tests are "does my Python function call boto3 correctly," Moto is probably what you want. If your tests are "does my whole system actually work end-to-end against AWS-shaped infrastructure," you want an HTTP server.

## fakecloud

**What it is:** single static binary written in Rust, ships as ~19 MB. Speaks the AWS wire protocol on port 4566. No account, no token, no paid tier. AGPL-3.0.

**What it covers:** 23 services, 1,680 operations, 100% conformance per implemented service, validated on every commit against AWS's own Smithy models (54,000+ generated test variants). Full list: S3, SQS, SNS, DynamoDB, Lambda, IAM, STS, KMS, Secrets Manager, SSM, CloudWatch Logs, CloudFormation, EventBridge, EventBridge Scheduler, SES (v2 + v1 inbound), Cognito User Pools, Kinesis, RDS, ElastiCache, Step Functions, API Gateway v2, Bedrock, Bedrock Runtime.

**Distinctive choices:**
- Real Lambda execution across 13 runtimes in Docker containers. Not a stub — your function code runs.
- Real stateful services. RDS runs real PostgreSQL/MySQL/MariaDB via Docker. ElastiCache runs real Redis/Valkey.
- Cross-service wiring is wired end-to-end. EventBridge -> Step Functions, S3 -> Lambda, SES inbound -> S3/SNS/Lambda, 15+ more integrations that actually fire.
- Multi-account, SCPs, ABAC, permission boundaries, session policies, KMS key policies, bucket policies — all with the Allow/Deny/NotPrincipal semantics AWS uses.
- First-party test-assertion SDKs in TypeScript, Python, Go, PHP, Java, Rust. Assert that an email was sent, an SNS was published, a Lambda was invoked, without raw HTTP.
- CI runs upstream `hashicorp/terraform-provider-aws` `TestAcc*` suites against fakecloud to catch provider-level drift.

**Where it fits:** integration tests and local development in any language. If you used LocalStack Community with Lambda, Cognito, SES v2, RDS, or ElastiCache and hit the paywall, fakecloud covers those.

**Where it doesn't fit:** EC2, ECS, ECR, CloudFront, AppSync, Athena, Glue, SageMaker — not implemented yet. If you need any of those, it's not the tool for you today.

**Source:** [github.com/faiscadev/fakecloud](https://github.com/faiscadev/fakecloud)

## MiniStack

**What it is:** a newer project that surfaced during the March 2026 LocalStack paywall window. Positions itself as a free LocalStack alternative. Check the repo for current service coverage and architecture details — the project is moving quickly and anything I write here will be outdated fast.

**Where it fits:** if you want the LocalStack operating model — a Docker image you pull and run — and are looking for a free alternative, MiniStack is one of the options worth evaluating against fakecloud on your specific service mix. If your test suite leans heavily on services MiniStack supports, it may be the easier drop-in for your team.

**Where to check fit:** compare the supported-services list in their README to your actual SDK calls. That's the only comparison that matters for your codebase.

**Source:** check GitHub for the current repo and README.

## floci

**What it is:** another newer free LocalStack alternative that appeared in the same window. The landing page publishes performance claims (startup time, memory, SDK-test pass rate); verify them against the version you'd actually run before relying on the numbers.

**Where it fits:** same category as MiniStack. If you want a free Docker-image-based LocalStack replacement, floci is on the shortlist. Evaluate against your service mix.

**Source:** check GitHub / floci.io for the current repo.

## Moto

**What it is:** the longest-lived open-source AWS mocking project. Python library, in-process, patches `boto3` inside your test. 100+ services covered at varying depth.

**Where it fits:** Python unit tests where you want to assert that your code calls boto3 the right way and handles boto3 responses the right way. Moto is great at this and has years of maturity.

**Where it doesn't fit:** any language other than Python. Any integration test that needs real cross-service wiring. Any test that needs Lambda to actually execute your code. Any test against Terraform or CDK deploys — Moto is in-process, so external tooling can't talk to it.

**Source:** [github.com/getmoto/moto](https://github.com/getmoto/moto)

## LocalStack Pro (for completeness)

**What it is:** the paid tier of the project that dropped Community Edition. Has the most mature service catalog, commercial support, and a track record.

**Where it fits:** teams that need the full LocalStack service catalog, are comfortable with a proprietary license, and are OK paying per-seat pricing.

**Where it doesn't fit:** teams who want an open-source license, who don't want an account/token gate, or who need a service like Bedrock that LocalStack doesn't implement.

## The non-dodge honest recommendation

If you were on LocalStack Community for integration testing, the likely fit order is:

1. **Try fakecloud first** if your service mix includes Lambda, Cognito, SES v2, RDS, ElastiCache, API Gateway v2, or Bedrock — these are where fakecloud does the most that LocalStack Community no longer does (or never did).
2. **Try MiniStack or floci** if fakecloud doesn't have a service you depend on. Their catalogs may overlap differently with yours.
3. **Add Moto** if you have Python unit tests that are happy with in-process mocking — Moto and fakecloud are complementary, not competitive, for different test tiers.
4. **Pay for LocalStack Pro** if none of the above cover what you need and you're OK with the commercial terms.

The honest test for any of these: run your actual test suite against each. Every team's mix of services, SDKs, and test patterns is different, and the only benchmark that matters is whether your tests pass.

## Links

- fakecloud: [github.com/faiscadev/fakecloud](https://github.com/faiscadev/fakecloud)
- Moto: [github.com/getmoto/moto](https://github.com/getmoto/moto)
- LocalStack: [localstack.cloud](https://localstack.cloud)
- fakecloud install options: [fakecloud.dev/docs/getting-started](/docs/getting-started/)
- fakecloud migration guide: [Migrating from LocalStack to fakecloud](/blog/migrate-from-localstack/)
