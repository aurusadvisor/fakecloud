+++
title = "Local ECS for integration tests"
description = "Run local Amazon ECS for tests with fakecloud. Full 60-operation API, real Fargate-style task execution via Docker, rolling deployments, ECS Exec. Free, AGPL-3.0."
template = "page.html"
+++

Need local ECS for integration tests? Use [fakecloud](https://github.com/faiscadev/fakecloud).

```sh
curl -fsSL https://raw.githubusercontent.com/faiscadev/fakecloud/main/install.sh | bash
fakecloud
```

Point your AWS SDK at `http://localhost:4566`. Tasks really run — `RunTask` shells out to `docker pull` + `docker run`, captures the exit code, and forwards stdout/stderr to fakecloud CloudWatch Logs when the container declares `logDriver=awslogs`.

## Why fakecloud for ECS

- **Full API — 60 operations at 100% conformance.** Clusters, task definitions, tasks, services, service deployments, task sets, container instances, attributes, capacity providers, task protection, ECS Exec, and the agent-side `Submit*` / `DiscoverPollEndpoint` surface.
- **Real Fargate-style task execution.** `RunTask` does `docker pull <image>` -> `docker run -d` -> `docker wait` (blocks on exit) -> `docker logs` (captures stdout/stderr) -> `docker rm`. Exit code lands on `containers[].exitCode`; `pullStartedAt` / `pullStoppedAt` timestamps are recorded the way real ECS does.
- **Services with rolling deployments.** `CreateService` spawns tasks to match `desiredCount` and tags each with `startedBy=ecs-svc/<name>`. `UpdateService` flips the previous PRIMARY deployment to `ACTIVE`, creates a new PRIMARY for the target revision, and drains old tasks while new ones come up. `minimumHealthyPercent` / `maximumPercent` and the deployment circuit breaker are honored.
- **ECS Exec.** `ExecuteCommand` proxies to `docker exec` against the running container so `aws ecs execute-command --interactive` shells in.
- **awslogs -> CloudWatch Logs.** Container definitions with `logDriver=awslogs` get their captured output forwarded to fakecloud Logs, with `awslogs-create-group=true` and `<prefix>/<container-name>/<task-id>` stream naming honored end-to-end.
- **Task role credentials.** Tasks with a `taskRoleArn` get `AWS_CONTAINER_CREDENTIALS_FULL_URI` injected, pointing at a fakecloud IMDS-format endpoint. AWS SDKs inside the container pick this up via the default credential-provider chain — `aws sts get-caller-identity` works from inside the container.
- **Secrets injection.** Container `secrets[]` ARNs (Secrets Manager + SSM Parameter Store) resolve at task launch and inject as environment variables before `docker run`. Missing values fail the task with `stopCode=TaskFailedToStart` matching real ECS.
- **Pulling from local ECR.** AWS-private ECR URIs (`<account>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag>`) resolve to fakecloud's local OCI v2 endpoint. Push to the local registry, run the task, get the image — no external pulls.
- **EventBridge events.** Task state transitions emit `aws.ecs` / `ECS Task State Change` events on the default bus so EB rules can fan out to SQS / SNS / Lambda / Step Functions.

## Smoke test (5 commands)

```sh
# Start fakecloud.
fakecloud &

# Create a cluster + register a task definition.
aws --endpoint-url http://localhost:4566 ecs create-cluster --cluster-name demo
aws --endpoint-url http://localhost:4566 ecs register-task-definition \
  --family hello \
  --container-definitions '[{"name":"app","image":"busybox:latest","essential":true,"command":["echo","hello from ecs"]}]'

# Run it. The container actually executes.
aws --endpoint-url http://localhost:4566 ecs run-task --cluster demo --task-definition hello

# Inspect captured output.
curl http://localhost:4566/_fakecloud/ecs/tasks
```

## Assert on what was run (first-party SDKs)

```typescript
import { FakeCloud } from "fakecloud";

const fc = new FakeCloud();
const { tasks } = await fc.ecs.getTasks({ cluster: "demo" });
const { logs, exitCode } = await fc.ecs.getTaskLogs(tasks[0].taskArn);

expect(exitCode).toBe(0);
expect(logs).toContain("hello from ecs");
```

Same API in Python, Go, Java, PHP, and Rust. See [the SDKs page](/docs/sdks) for per-language examples.

## What about LocalStack?

LocalStack's ECS support is paid-only since the March 2026 Community switch. fakecloud is free, AGPL-3.0, and ships the full 60-operation API plus real container execution.

## Read the docs

- [ECS service page](/docs/services/ecs/) — full operation list, introspection endpoints, awslogs / secrets / task-role wiring.
- [Cross-service integration guide](/docs/guides/cross-service-integration/) — every ECR / ECS / Logs / Secrets / SSM / EventBridge wiring fakecloud actually executes.
- [`crates/fakecloud-ecs`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-ecs) source.
