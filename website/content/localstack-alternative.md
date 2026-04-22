+++
title = "Free, open-source LocalStack alternative"
description = "fakecloud is a free, open-source local AWS emulator: 23 services, 1,680 operations, 100% conformance, 6 test-assertion SDKs. No account, no token, no paid tier. Drop-in replacement for LocalStack Community."
template = "page.html"
+++

LocalStack replaced its open-source Community Edition with a proprietary image in March 2026. Running `localstack:latest` now requires an account and an auth token, and several previously-free services (RDS, ElastiCache, Cognito User Pools, SES v2, API Gateway v2, ECS/ECR) moved behind a paywall.

**fakecloud is a free, open-source replacement.** Single static binary, no account, no token, no paid tier, AGPL-3.0.

```sh
curl -fsSL https://raw.githubusercontent.com/faiscadev/fakecloud/main/install.sh | bash
fakecloud
```

Point any AWS SDK or CLI at `http://localhost:4566` with dummy credentials. That is the whole setup.

## What fakecloud gives you

- **23 AWS services.** S3, SQS, SNS, DynamoDB, Lambda, IAM, STS, KMS, Secrets Manager, SSM, CloudWatch Logs, CloudFormation, EventBridge, EventBridge Scheduler, SES (v2 + v1 inbound), Cognito User Pools, Kinesis, RDS, ElastiCache, Step Functions, API Gateway v2, Bedrock, Bedrock Runtime.
- **1,680 API operations. 100% conformance** per implemented service, validated against AWS's own Smithy models on every commit (54,000+ generated test variants).
- **Tested against upstream Terraform acceptance tests.** CI runs `hashicorp/terraform-provider-aws` `TestAcc*` suites against fakecloud, catching waiter and field-presence drift that pure SDK tests miss.
- **Real Lambda execution.** 13 runtimes in Docker containers. Not a mock, not a stub. Node, Python, Java, Go, .NET, Ruby, custom runtimes.
- **Real stateful services.** RDS runs real PostgreSQL/MySQL/MariaDB. ElastiCache runs real Redis/Valkey. Your Lambda talking to RDS is talking to a real Postgres.
- **Real cross-service wiring.** EventBridge -> Step Functions, S3 -> Lambda, SES inbound -> S3/SNS/Lambda, 15+ more end-to-end integrations.
- **Fast.** ~500ms startup. ~10 MiB idle memory. ~19 MB binary. No Docker required to run fakecloud itself.
- **Test-assertion SDKs** for TypeScript, Python, Go, PHP, Java, and Rust. Assert that an email was sent, an SNS message published, a Lambda invoked, without writing raw HTTP.
- **Multi-account, SCPs, ABAC.** Cross-account delivery on SQS/SNS/Lambda/S3/EventBridge/Step Functions. STS trust policies with `sts:ExternalId`, session tags, permission boundaries, and session policies all enforced.
- **IAM, KMS key policies, bucket policies, SCPs.** Opt-in strict enforcement with the full Allow/Deny/NotPrincipal semantics AWS uses.

## fakecloud vs LocalStack Community (post-March 2026)

| Feature | fakecloud | LocalStack Community |
|---|---|---|
| License | AGPL-3.0 (open source) | Proprietary |
| Account / auth token | Not required | Required |
| Free for commercial use | Yes | No |
| Docker required | No (single binary) | Yes |
| Startup | ~500ms | ~3s |
| Idle memory | ~10 MiB | ~150 MiB |
| Install size | ~19 MB binary | ~1 GB image |
| Conformance methodology | Smithy-model-validated, 54k+ test variants | Not published |
| Test-assertion SDKs | TypeScript, Python, Go, PHP, Java, Rust | Python, Java |
| Cognito User Pools | 122 operations | [Paid only](https://docs.localstack.cloud/references/licensing/) |
| SES v2 | 110 operations, full send + templates + DKIM | [Paid only](https://docs.localstack.cloud/references/licensing/) |
| SES inbound email | Real receipt rule action execution | [Stored but never executed](https://docs.localstack.cloud/user-guide/aws/ses/) |
| RDS | 163 ops, real PostgreSQL/MySQL/MariaDB via Docker | [Paid only](https://docs.localstack.cloud/references/licensing/) |
| ElastiCache | 75 ops, real Redis/Valkey via Docker | [Paid only](https://docs.localstack.cloud/references/licensing/) |
| API Gateway v2 | 28 ops, HTTP APIs + JWT/Lambda authorizers | [Paid only](https://docs.localstack.cloud/references/licensing/) |
| Bedrock | 111 ops (control plane + runtime) | Not available |

Performance numbers measured on Apple M1 via `time fakecloud`, `ps -o rss`, `ls -lh`. LocalStack numbers from a fresh `localstack start` on the same hardware.

## Migrating from LocalStack

Most projects can migrate by changing one thing: the container image (or the install command), plus the port if it differs. The endpoint URL, dummy credentials, and SDK wiring all stay the same.

```yaml
# docker-compose.yml — before (LocalStack Community)
services:
  localstack:
    image: localstack/localstack:latest  # now requires auth token
    ports:
      - "4566:4566"

# docker-compose.yml — after (fakecloud)
services:
  fakecloud:
    image: ghcr.io/faiscadev/fakecloud:latest
    ports:
      - "4566:4566"
```

For CI without Docker:

```yaml
- run: curl -fsSL https://raw.githubusercontent.com/faiscadev/fakecloud/main/install.sh | bash
- run: fakecloud &
- run: sleep 1 && aws --endpoint-url http://localhost:4566 s3 ls  # verify
```

Full migration guide: [Migrating from LocalStack to fakecloud](/blog/migrate-from-localstack/).

## FAQ

**Is fakecloud a drop-in replacement for LocalStack Community?**

For integration testing and local development against the services fakecloud supports, yes. Your AWS SDK code, CLI commands, Terraform configs, and CDK apps work unchanged — you only switch the endpoint URL (already `http://localhost:4566`) and the process you run.

**Is fakecloud free for commercial use?**

Yes. AGPL-3.0. Using fakecloud as a dev/test dependency has zero AGPL implications for your application or your production code. The copyleft clause only kicks in if you modify fakecloud itself and redistribute it as a network service.

**How is fakecloud different from Moto?**

Moto is a Python library that patches boto3 inside a test process. fakecloud is a real HTTP server that listens on port 4566 and speaks the AWS wire protocol. That means fakecloud works with any language and any SDK (Go, Java, Node, Rust, PHP), and it exercises real cross-service wiring (EventBridge -> Lambda, S3 -> SNS, etc) because the services are running in the same process. Moto doesn't execute Lambda code; fakecloud runs Lambda in real Docker containers across 13 runtimes.

**How is fakecloud different from SAM Local / serverless-offline?**

SAM Local and serverless-offline only run Lambda (and a limited HTTP/API Gateway surface in front of it). fakecloud runs Lambda plus 22 other services, with real cross-service integrations. If your function calls SQS, fans out over SNS, or reads from DynamoDB, fakecloud has those services wired up.

**Does fakecloud run on CI?**

Yes. Single binary, ~19 MB, ~500ms startup. Common patterns: install-and-run as a background step in GitHub Actions / GitLab CI / CircleCI, or pull `ghcr.io/faiscadev/fakecloud:latest` as a service container. See [integration testing AWS in CI](/blog/integration-testing-aws-in-ci/) for copy-paste configs.

**Which services are implemented at 100% conformance?**

Every service listed above. Conformance means: for every operation exposed by AWS's Smithy model, fakecloud accepts every documented input shape and returns the documented output shape, with every field AWS returns. Validated on every commit against 54,000+ generated test variants.

**What's not implemented?**

EC2, ECS, ECR, CloudFront, SQS extended client encryption, AppSync, Athena, Glue, SageMaker. If you need one of these, open an issue — the roadmap is driven by real-project demand.

**Is this a fork of LocalStack?**

No. fakecloud is written from scratch in Rust. No LocalStack code was used. LocalStack is written in Python; fakecloud is written in Rust and ships as a single binary.

## Get started

- **Install:** `curl -fsSL https://raw.githubusercontent.com/faiscadev/fakecloud/main/install.sh | bash`
- **Docker:** `docker run --rm -p 4566:4566 ghcr.io/faiscadev/fakecloud`
- **Cargo:** `cargo install fakecloud`
- **Repo:** [github.com/faiscadev/fakecloud](https://github.com/faiscadev/fakecloud)
- **Docs:** [fakecloud.dev/docs](/docs/)
- **Issues:** [github.com/faiscadev/fakecloud/issues](https://github.com/faiscadev/fakecloud/issues)

If fakecloud behaves differently from real AWS, that's a bug — open an issue and it gets fixed.
