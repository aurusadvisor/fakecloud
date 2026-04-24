+++
title = "ECS"
description = "Elastic Container Service — clusters, task definitions, (later) real Fargate-style task execution via Docker, services, and rolling deployments."
weight = 22
+++

fakecloud implements Amazon Elastic Container Service (ECS) with a four-batch roadmap. This page tracks what's shipped.

**Status: Batch 1 shipped — control-plane CRUD.** Subsequent batches add real task execution (Batch 2), services + rolling deployments (Batch 3), and completeness (Batch 4: container instances, capacity providers, task protection, `ExecuteCommand`).

## Supported today (Batch 1)

- **Clusters** — `CreateCluster`, `DescribeClusters`, `DeleteCluster`, `ListClusters`, `UpdateCluster`, `UpdateClusterSettings`, `PutClusterCapacityProviders`
- **Task definitions** — `RegisterTaskDefinition`, `DescribeTaskDefinition`, `DeregisterTaskDefinition`, `DeleteTaskDefinitions`, `ListTaskDefinitions`, `ListTaskDefinitionFamilies`
- **Tagging** — `TagResource`, `UntagResource`, `ListTagsForResource` (clusters and task definitions)
- **Account settings** — `PutAccountSetting`, `PutAccountSettingDefault`, `DeleteAccountSetting`, `ListAccountSettings`
- **Introspection endpoint** — `GET /_fakecloud/ecs/clusters` dumps every cluster across every account, bypassing the public API

Task-definition families track revisions monotonically; `DeleteTaskDefinitions` requires `DeregisterTaskDefinition` first (real AWS behaviour), and the result flips status to `DELETE_IN_PROGRESS`.

## Protocol

JSON protocol over `POST /`, with `X-Amz-Target: AmazonEC2ContainerServiceV20141113.<Action>`. Request + response bodies are JSON; tags use lowercase `key` / `value` (matches AWS SDK serialization).

## Introspection

```text
GET /_fakecloud/ecs/clusters
```

Returns every cluster fakecloud has recorded, sorted by cluster ARN. Useful for asserting deterministic state in tests without dealing with public-API pagination.

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

- **Batch 2** — `RunTask`, `StartTask`, `StopTask`, `DescribeTasks`, `ListTasks`: real Fargate-style container execution via Docker, ECR image pull, awslogs driver wiring to CloudWatch Logs, EventBridge `ECS Task State Change` events
- **Batch 3** — `CreateService`, `UpdateService`, rolling deployments with `minimumHealthyPercent`/`maximumPercent`, `CreateTaskSet`/`UpdateTaskSet` (EXTERNAL deployment controller), deployment circuit breaker
- **Batch 4** — Container instances, attributes, capacity providers, task protection, ECS Exec (`ExecuteCommand` via `docker exec`), snapshot/restore of in-flight tasks

## Source

- [`crates/fakecloud-ecs`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-ecs)
- [AWS ECS API reference](https://docs.aws.amazon.com/AmazonECS/latest/APIReference/Welcome.html)
