+++
title = "ECS"
description = "Elastic Container Service — clusters, task definitions, (later) real Fargate-style task execution via Docker, services, and rolling deployments."
weight = 22
+++

fakecloud implements Amazon Elastic Container Service (ECS) with full API coverage. 60 operations, shipped across four batches.

**Status: all four batches shipped — full API.** Covers clusters, task definitions, real Fargate-style task execution, services with rolling deployments, task sets, container instances, capacity providers, attributes, task protection, ECS Exec, and the agent-side `Submit*` / `DiscoverPollEndpoint` surface.

## Supported today (full API)

- **Clusters** — `CreateCluster`, `DescribeClusters`, `DeleteCluster`, `ListClusters`, `UpdateCluster`, `UpdateClusterSettings`, `PutClusterCapacityProviders`
- **Task definitions** — `RegisterTaskDefinition`, `DescribeTaskDefinition`, `DeregisterTaskDefinition`, `DeleteTaskDefinitions`, `ListTaskDefinitions`, `ListTaskDefinitionFamilies`
- **Tasks** — `RunTask`, `StartTask`, `StopTask`, `DescribeTasks`, `ListTasks` with real Fargate-style execution via Docker/Podman
- **Services** — `CreateService`, `UpdateService`, `DeleteService`, `DescribeServices`, `ListServices`, `ListServicesByNamespace` with desired-count enforcement and rolling deployments
- **Service deployments** — `StopServiceDeployment`, `ListServiceDeployments`, `DescribeServiceDeployments`, `DescribeServiceRevisions`
- **Task sets** — `CreateTaskSet`, `UpdateTaskSet`, `DeleteTaskSet`, `DescribeTaskSets`, `UpdateServicePrimaryTaskSet` (EXTERNAL deployment controller)
- **Container instances** — `RegisterContainerInstance`, `DeregisterContainerInstance`, `DescribeContainerInstances`, `ListContainerInstances`, `UpdateContainerAgent`, `UpdateContainerInstancesState`
- **Attributes** — `PutAttributes`, `DeleteAttributes`, `ListAttributes`
- **Capacity providers** — `CreateCapacityProvider`, `DeleteCapacityProvider`, `DescribeCapacityProviders`, `UpdateCapacityProvider`
- **Task protection** — `GetTaskProtection`, `UpdateTaskProtection`
- **ECS Exec** — `ExecuteCommand` proxies to `docker exec` against the task's running container
- **Agent surface** — `SubmitContainerStateChange`, `SubmitTaskStateChange`, `SubmitAttachmentStateChanges`, `DiscoverPollEndpoint`
- **Tagging** — `TagResource`, `UntagResource`, `ListTagsForResource` (clusters and task definitions)
- **Account settings** — `PutAccountSetting`, `PutAccountSettingDefault`, `DeleteAccountSetting`, `ListAccountSettings`

### Services + rolling deployments (Batch 3)

`CreateService` spawns tasks to match `desiredCount` under the service, tagging each with `startedBy=ecs-svc/<name>` so the tasks reconcile back to the service. `UpdateService` supports two independent mutations:

- **Scale** — set a new `desiredCount`. The service spawns additional tasks when scaling up and flips excess tasks to `desiredStatus=STOPPED` (runtime kill on the container) when scaling down.
- **Rolling deployment** — pass a new `taskDefinition`. The service marks the previous PRIMARY deployment as `ACTIVE`, creates a new `PRIMARY` deployment for the target revision, and drains tasks on the old task definition while new ones come up. Deployment circuit breaker + `minimumHealthyPercent` / `maximumPercent` are honoured in `deploymentConfiguration`.

`DeleteService` refuses while `desiredCount > 0` unless `force=true`; the forced path scales to 0 and stops every running task under the service before removing it.

Task-definition families track revisions monotonically; `DeleteTaskDefinitions` requires `DeregisterTaskDefinition` first (real AWS behaviour), and the result flips status to `DELETE_IN_PROGRESS`.

## Task execution (Batch 2)

`RunTask` records the task synchronously and kicks off a background docker execution per spawned task:

1. `docker pull <image>` (timestamps captured on the task: `pullStartedAt` / `pullStoppedAt`)
2. `docker run -d <image>` (container ID recorded on the task's container)
3. `docker wait <id>` (blocks on container exit; exit code → `containers[].exitCode`)
4. `docker logs <id>` (captured stdout/stderr stored on the task + exposed via the introspection endpoint)
5. `docker rm <id>` (cleanup)

Environment variables from the task definition are forwarded with `localhost` / `127.0.0.1` rewritten to `host.docker.internal` so containers reach fakecloud itself the same way Lambda does.

Without a container runtime (docker/podman missing), `RunTask` still returns tasks but they immediately transition to `STOPPED` with `stopCode=TaskFailedToStart`. This keeps the API surface shape-correct so tests on CI agents without Docker can still drive the control-plane surface.

### Pulling from fakecloud ECR

Tasks that reference AWS private-ECR URIs (`<account>.dkr.ecr.<region>.amazonaws.com/<repo>:<tag>`) are resolved against fakecloud's own OCI v2 endpoint. The runtime pulls from `127.0.0.1:<port>/<repo>:<tag>`, retags to the AWS URI, and runs the container under the user-visible image name. On Linux this is transparent because the docker daemon auto-treats `127.0.0.1` as an insecure registry. On Docker Desktop for macOS or Windows, the daemon runs in a VM and `127.0.0.1` maps to the VM itself, not the host — for full fidelity there, add `127.0.0.0/8` to Docker Desktop's insecure-registries and ensure fakecloud is reachable from the VM (e.g. via `host.docker.internal` forwarding).

Same resolution path applies to Lambda functions deployed with `PackageType=Image`: `Code.ImageUri` pointing at a fakecloud ECR URI is pulled and run on invoke.

### awslogs -> CloudWatch Logs

Container definitions that declare the `awslogs` log driver get their captured stdout/stderr forwarded to fakecloud's CloudWatch Logs service:

```json
"logConfiguration": {
  "logDriver": "awslogs",
  "options": {
    "awslogs-group": "/ecs/my-service",
    "awslogs-stream-prefix": "app",
    "awslogs-region": "us-east-1",
    "awslogs-create-group": "true"
  }
}
```

The runtime creates the log group on demand when `awslogs-create-group=true`, creates a stream named `<prefix>/<container-name>/<task-id>`, and appends one `LogEvent` per captured line. The usual fakecloud-logs API (`DescribeLogStreams`, `GetLogEvents`, subscription filters) then sees the container's output with no additional wiring.

### EventBridge task state change events

Task state transitions fire `aws.ecs` / `ECS Task State Change` events on the default EventBridge bus. Event `detail` carries the task ARN, cluster ARN, last status, stop code / reason on STOPPED, and a summary of each container including exit code. Rules matching `source: aws.ecs` receive these events and can route to SQS, SNS, Lambda, Step Functions — the standard target fan-out.

### Task role credentials

Tasks registered with a `taskRoleArn` get `AWS_CONTAINER_CREDENTIALS_FULL_URI` injected into every container. The URL points at a fakecloud-local endpoint — `http://host.docker.internal:<port>/_fakecloud/ecs/creds/<task-id>` — that returns IMDS-format credentials:

```json
{
  "AccessKeyId": "ASIA...",
  "SecretAccessKey": "...",
  "Token": "...",
  "Expiration": "2026-04-24T12:00:00Z",
  "RoleArn": "arn:aws:iam::123456789012:role/app-task-role"
}
```

AWS SDKs pick this up via the default credential-provider chain, so `aws sts get-caller-identity` (and any other SDK call) from inside the container works out of the box. fakecloud's STS accepts any `AccessKeyId`, so no pre-registration of the role is needed.

### Secrets injection

Container definitions can pull secrets from SecretsManager or SSM Parameter Store via the standard `secrets[]` field:

```json
"secrets": [
  { "name": "DB_PASSWORD", "valueFrom": "arn:aws:secretsmanager:us-east-1:123456789012:secret:db-password-AbCdEf" },
  { "name": "API_KEY",     "valueFrom": "arn:aws:ssm:us-east-1:123456789012:parameter/app/api-key" }
]
```

The runtime resolves both kinds of ARN synchronously against the in-process state and injects the values as environment variables before `docker run`. A missing secret or parameter fails the task with `stopCode=TaskFailedToStart`, matching real ECS's "failed to retrieve secret" behaviour.

## Protocol

JSON protocol over `POST /`, with `X-Amz-Target: AmazonEC2ContainerServiceV20141113.<Action>`. Request + response bodies are JSON; tags use lowercase `key` / `value` (matches AWS SDK serialization).

## Introspection

Endpoints bypass the public AWS API so tests can assert deterministic state without pagination or role-assumption noise.

| Endpoint | Method | Purpose |
|---|---|---|
| `/_fakecloud/ecs/clusters` | GET | Dump every cluster across all accounts |
| `/_fakecloud/ecs/tasks` | GET | Dump every task; filter with `?cluster=` / `?status=` |
| `/_fakecloud/ecs/tasks/{taskId}` | GET | Single-task deep detail |
| `/_fakecloud/ecs/tasks/{taskId}/logs` | GET | Captured docker stdout/stderr + exit code |
| `/_fakecloud/ecs/tasks/{taskId}/force-stop` | POST | SIGTERM + SIGKILL the running container |
| `/_fakecloud/ecs/tasks/{taskId}/mark-failed` | POST | Flip to STOPPED without killing the container (inject exit code + reason) |
| `/_fakecloud/ecs/events` | GET | Replay the lifecycle event log |

All endpoints are sorted deterministically (by ARN for clusters/tasks, by timestamp for events) so test assertions don't flake on map iteration order.

### Clusters dump

```json
{
  "clusters": [
    {
      "clusterName": "prod",
      "clusterArn": "arn:aws:ecs:us-east-1:111122223333:cluster/prod",
      "status": "ACTIVE",
      "runningTasksCount": 0,
      "pendingTasksCount": 0,
      "activeServicesCount": 0,
      "registeredContainerInstancesCount": 0,
      "capacityProviders": ["FARGATE"],
      "tags": [{"key": "env", "value": "prod"}],
      "createdAt": "2026-04-23T23:00:00+00:00"
    }
  ]
}
```

## SDK usage (testing helper)

The fakecloud client SDKs ship typed wrappers for every introspection endpoint. Use them instead of poking `/_fakecloud/*` paths by hand.

```go
// Go
clusters, _ := fakecloud.New("http://localhost:4566").ECS().GetClusters(ctx)
```

```python
# Python
async with FakeCloud() as fc:
    clusters = await fc.ecs.get_clusters()
```

```typescript
// TypeScript
const fc = new FakeCloud();
const { clusters } = await fc.ecs.getClusters();
```

```rust
// Rust
let fc = FakeCloud::new("http://localhost:4566");
let clusters = fc.ecs().get_clusters().await?;
```

## Roadmap

- **Batch 4** — Container instances, attributes, capacity providers, task protection, ECS Exec (`ExecuteCommand` via `docker exec`), task sets (EXTERNAL deployment controller), snapshot/restore of in-flight tasks, IAM task-role credential injection via `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI`, EventBridge `ECS Task State Change` events, awslogs-driver CloudWatch Logs streaming.

## Source

- [`crates/fakecloud-ecs`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-ecs)
- [AWS ECS API reference](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/Welcome.html)
