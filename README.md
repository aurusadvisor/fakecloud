<p align="center">
  <strong>fakecloud</strong><br>
  <em>Local AWS cloud emulator. Free forever.</em>
</p>

<p align="center">
  <a href="https://github.com/faiscadev/fakecloud/actions"><img src="https://img.shields.io/github/actions/workflow/status/faiscadev/fakecloud/ci.yml?branch=main&label=CI" alt="CI"></a>
  <a href="https://codecov.io/gh/faiscadev/fakecloud"><img src="https://img.shields.io/codecov/c/github/faiscadev/fakecloud?label=coverage" alt="Coverage"></a>
  <a href="https://github.com/faiscadev/fakecloud/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-AGPL--3.0-blue" alt="License"></a>
  <a href="https://github.com/faiscadev/fakecloud/pkgs/container/fakecloud"><img src="https://img.shields.io/badge/ghcr.io-fakecloud-blue?logo=docker" alt="GHCR"></a>
  <a href="https://crates.io/crates/fakecloud"><img src="https://img.shields.io/crates/v/fakecloud" alt="crates.io"></a>
  <a href="https://fakecloud.dev"><img src="https://img.shields.io/badge/docs-fakecloud.dev-green" alt="Docs"></a>
</p>

---

fakecloud is a free, open-source local AWS emulator for integration testing and local development. Single binary, no account, no auth token, no paid tier. Point your AWS SDK at `http://localhost:4566` and it works.

In March 2026, LocalStack replaced its open-source Community Edition with a proprietary image that requires an account and auth token. fakecloud exists so teams can keep a fully local AWS testing workflow without one.

## Quick start

```sh
curl -fsSL https://raw.githubusercontent.com/faiscadev/fakecloud/main/install.sh | bash
fakecloud
```

Then point any AWS SDK or CLI at `http://localhost:4566` with dummy credentials:

```sh
aws --endpoint-url http://localhost:4566 sqs create-queue --queue-name my-queue
```

Other install options (Cargo, Docker, Docker Compose, source) are documented at [fakecloud.dev/docs/getting-started](https://fakecloud.dev/docs/getting-started).

## Why fakecloud

- **Free, forever.** AGPL-3.0, no paid tier, no account, no token.
- **100% conformance** per implemented service. Every operation validated against AWS's own Smithy models — 59,000+ generated test variants on every commit.
- **Tested against upstream Terraform acceptance tests.** CI runs `hashicorp/terraform-provider-aws` `TestAcc*` suites against fakecloud. Catches waiter/field-presence/drift bugs that pure SDK tests miss.
- **Real cross-service wiring.** EventBridge -> Step Functions, S3 -> Lambda, SES inbound -> S3/SNS/Lambda, and 15+ more integrations actually execute end-to-end.
- **Real infrastructure for stateful services.** Lambda runs in Docker containers (13 runtimes). RDS runs real Postgres/MySQL/MariaDB. ElastiCache runs real Redis/Valkey.
- **Single binary.** ~19 MB, ~10 MiB idle memory, ~500ms startup. No Docker required to run fakecloud itself (only to exercise the services that need real containers).
- **Bedrock, the whole surface.** 111 operations across runtime + full control plane: `InvokeModel`/`Converse` (with streaming), guardrails (real content evaluation + PII detection), custom model jobs, model import, inference profiles, provisioned throughput, async batch via S3, prompt management, agreements, automated reasoning. Configurable responses per prompt + fault injection for deterministic Bedrock tests. LocalStack's Ultimate-tier Bedrock covers 4 ops backed by Ollama; fakecloud is free and covers the full Bedrock shape. See [`/bedrock-emulator/`](https://fakecloud.dev/bedrock-emulator/).
- **First-party test SDKs** for TypeScript, Python, Go, PHP, Java, and Rust. Assert on what your code called without writing raw HTTP.
- **Opt-in SigV4 verification and IAM enforcement.** Off by default so tests just work; turn on `--verify-sigv4` for real cryptographic signature checking and `--iam soft|strict` for identity-policy evaluation (Allow/Deny with Deny precedence, Action/Resource wildcards, user/group/role policies, `Condition` blocks with all 28 AWS operators against global keys like `aws:username` / `aws:SourceIp` / `aws:CurrentTime`, plus resource-based policies for S3 bucket, SNS topic, and Lambda function policies with AWS's cross-account combining semantics) across IAM, STS, SQS, SNS, and S3. See [the security docs](https://fakecloud.dev/docs/reference/security/).
- **LocalStack and real-AWS URL compatibility.** Both `*.localhost.localstack.cloud` and `*.amazonaws.com` Host headers decode to service + region for routing, including every S3 virtual-hosted variant (`<bucket>.s3.<region>.…`, legacy `<bucket>.s3.amazonaws.com` with implicit `us-east-1`, and the older dash-separated `<bucket>.s3-<region>.amazonaws.com`). Persisted queue URLs, presigned URLs, webhook targets, and dev scripts from either system replay against fakecloud unchanged.

## Supported services

26 services, 1,849 operations, 100% conformance per implemented service.

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
| RDS                    | 163 | Real Postgres, MySQL, MariaDB via Docker; lifecycle ops emit `aws.rds` EventBridge events |
| ElastiCache            |  75 | Real Redis, Valkey via Docker                                          |
| Step Functions         |  37 | Full ASL interpreter, Lambda/SQS/SNS/EventBridge/DynamoDB tasks        |
| API Gateway v2         |  28 | HTTP APIs, Lambda proxy, JWT/Lambda authorizers, CORS                  |
| Bedrock                | 101 | Foundation models, guardrails, custom models, invocation/eval jobs    |
| Bedrock Runtime        |  10 | InvokeModel, Converse, streaming, configurable responses, fault inject |
| ECR                    |  58 | Full API — OCI v2 push/pull, lifecycle, scanning, registry, pull-through |
| ECS                    |  60 | **Full API** — clusters, task definitions, real task execution, services + rolling deployments, container instances, capacity providers, task sets, ECS Exec |
| Elastic Load Balancing v2 |  51 | ALB/NLB/GWLB CRUD: load balancers, target groups + targets + health, **listeners + rules + certificates**, LB/listener/target-group attributes, capacity reservations, **mTLS trust stores + revocations**, SSL policies, resource policies, tags |

Per-service docs and feature matrices: [fakecloud.dev/docs/services](https://fakecloud.dev/docs/services).

## Common use cases

| What you want to do                        | Command                                                                        |
| ------------------------------------------ | ------------------------------------------------------------------------------ |
| **Test Lambda locally**                    | `fakecloud` then `aws --endpoint-url http://localhost:4566 lambda invoke …`    |
| **Mock DynamoDB in tests**                 | `fakecloud` then point boto3/aws-sdk at `http://localhost:4566`                |
| **Local S3 for integration tests**         | `fakecloud` then use any S3 SDK with `endpoint_url=http://localhost:4566`      |
| **Fake AWS server for tests**              | `fakecloud` — single binary on port 4566, any AWS SDK works                    |
| **Replace LocalStack in CI**               | `curl … install.sh`, then `fakecloud &` as a background step                   |
| **Terraform local dev**                    | Point the `aws` provider `endpoints` block at `http://localhost:4566`          |
| **CDK local testing**                      | `cdklocal deploy --endpoint-url http://localhost:4566`                         |
| **Moto equivalent for Go/Java/Node**       | `fakecloud` — real HTTP server, every AWS SDK works, no language lock-in       |
| **Integration test AWS in GitHub Actions** | Install or pull `ghcr.io/faiscadev/fakecloud`, run as service container        |

Full guides: [fakecloud.dev/docs/guides](https://fakecloud.dev/docs/guides).

## Compared to LocalStack Community

| Feature             | fakecloud                                          | LocalStack Community (post-March 2026)                                         |
| ------------------- | -------------------------------------------------- | ------------------------------------------------------------------------------ |
| License             | AGPL-3.0                                           | Proprietary                                                                    |
| Auth required       | No                                                 | Yes (account + token)                                                          |
| Commercial use      | Free                                               | Paid plans only                                                                |
| Docker required     | No (standalone binary)                             | Yes                                                                            |
| Startup time        | ~500ms                                             | ~3s                                                                            |
| Idle memory         | ~10 MiB                                            | ~150 MiB                                                                       |
| Install size        | ~19 MB binary                                      | ~1 GB Docker image                                                             |
| Test assertion SDKs | TypeScript, Python, Go, PHP, Java, Rust            | Python, Java                                                                   |
| Cognito User Pools  | 122 operations                                     | [Paid only](https://docs.localstack.cloud/references/licensing/)               |
| SES v2              | Full send + templates + DKIM + suppression         | [Paid only](https://docs.localstack.cloud/references/licensing/)               |
| SES inbound email   | Real receipt rule action execution                 | [Stored but never executed](https://docs.localstack.cloud/user-guide/aws/ses/) |
| RDS                 | 163 operations, PostgreSQL/MySQL/MariaDB via Docker | [Paid only](https://docs.localstack.cloud/references/licensing/)               |
| ElastiCache         | 75 operations, Redis and Valkey via Docker         | [Paid only](https://docs.localstack.cloud/references/licensing/)               |
| API Gateway v2      | 28 operations, full HTTP API support               | [Paid only](https://docs.localstack.cloud/references/licensing/)               |
| Bedrock             | 111 operations (control plane + runtime)           | Not available                                                                  |
| ECR                 | 58 operations, real `docker push`/`pull` via OCI v2 | [Paid only](https://docs.localstack.cloud/references/licensing/)              |
| ECS                 | **60 operations — full API** incl. real task execution, services, task sets, capacity providers | [Paid only](https://docs.localstack.cloud/references/licensing/)               |
| Elastic Load Balancing v2 | **51 operations** ALB/NLB/GWLB incl. mTLS trust stores, capacity reservations, attributes, resource policies | [Paid only](https://docs.localstack.cloud/references/licensing/)               |

> Performance numbers measured on Apple M1 via `time fakecloud`, `ps -o rss`, `ls -lh`.

## First-party SDKs

Normal AWS SDKs handle your application code. fakecloud's own SDKs let your tests assert on what happened — sent emails, SNS messages, Lambda invocations, Bedrock calls, and more.

| Language   | Install                                         |
| ---------- | ----------------------------------------------- |
| TypeScript | `npm install fakecloud`                         |
| Python     | `pip install fakecloud`                         |
| Go         | `go get github.com/faiscadev/fakecloud/sdks/go` |
| PHP        | `composer require fakecloud/fakecloud`          |
| Java       | `dev.fakecloud:fakecloud` (Maven Central)       |
| Rust       | `cargo add fakecloud-sdk`                       |

```ts
import { FakeCloud } from "fakecloud";

const fc = new FakeCloud();

// Your app sends through the normal AWS SDK.
// Your test asserts the side effect directly.
const { emails } = await fc.ses.getEmails();
expect(emails).toHaveLength(1);

await fc.reset();
```

Full SDK reference for all six languages: [fakecloud.dev/docs/sdks](https://fakecloud.dev/docs/sdks).

## Use with AI coding tools

Add one of these snippets to your project so AI coding assistants (Claude Code, Cursor, GitHub Copilot) automatically use fakecloud for AWS integration tests.

<details>
<summary><strong>Claude Code</strong> — add to <code>CLAUDE.md</code></summary>

```markdown
## AWS Testing

For integration tests, use fakecloud as a local AWS emulator.

- Install: `curl -fsSL https://raw.githubusercontent.com/faiscadev/fakecloud/main/install.sh | bash`
- Run: `fakecloud` (listens on http://localhost:4566)
- Configure AWS SDK endpoint to http://localhost:4566 with dummy credentials (access_key=test, secret_key=test)
- Docs: https://fakecloud.dev/llms.txt
```

</details>

<details>
<summary><strong>Cursor</strong> — add to <code>.cursor/rules</code></summary>

```
For AWS integration tests, use fakecloud (local AWS emulator) at http://localhost:4566.
Install: curl -fsSL https://raw.githubusercontent.com/faiscadev/fakecloud/main/install.sh | bash
Run: fakecloud
Use dummy credentials (access_key=test, secret_key=test).
Docs: https://fakecloud.dev/llms.txt
```

</details>

<details>
<summary><strong>GitHub Copilot</strong> — add to <code>.github/copilot-instructions.md</code></summary>

```markdown
## AWS Testing

Use fakecloud as a local AWS emulator for integration tests.

- Run: `fakecloud` (listens on http://localhost:4566)
- Configure endpoint_url to http://localhost:4566 with dummy credentials
- Docs: https://fakecloud.dev/llms.txt
```

</details>

## Docs and guides

- **[fakecloud.dev](https://fakecloud.dev)** — website
- **[Getting started](https://fakecloud.dev/docs/getting-started)** — install, first test, SDK setup
- **[Guides](https://fakecloud.dev/docs/guides)** — in-depth how-tos (testing Bedrock, cross-service integration, CI setup)
- **[Reference](https://fakecloud.dev/docs/reference)** — configuration, introspection endpoints, persistence
- **[Blog](https://fakecloud.dev/blog)** — essays and hot takes on testing, AWS, and AI-assisted development

## Contributing

Contributions welcome. Fork, branch, write tests, open a PR.

- Conventional commits (`feat:`, `fix:`, `chore:`, `test:`, `refactor:`)
- E2E tests for every new action
- `cargo test --workspace && cargo clippy --workspace -- -D warnings && cargo fmt --check`

See [CONTRIBUTING.md](CONTRIBUTING.md) for more.

## License

fakecloud is free and open-source, licensed under [AGPL-3.0-or-later](https://www.gnu.org/licenses/agpl-3.0.html). Using fakecloud as a dev/test dependency has zero AGPL implications for your application — the copyleft clause only applies if you modify and redistribute fakecloud itself as a network service.

---

<p align="center">
  Part of the <a href="https://faisca.dev">faisca</a> project family | <a href="https://fakecloud.dev">fakecloud.dev</a>
</p>
