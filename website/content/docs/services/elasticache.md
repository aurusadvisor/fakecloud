+++
title = "ElastiCache"
description = "Real Redis, Valkey, and Memcached clusters via Docker. Replication groups, snapshots, user/group management."
weight = 18
+++

fakecloud implements **75 of 75** ElastiCache operations at 100% Smithy conformance. Cache clusters run in **real Docker containers** — your code connects to a real Redis, Valkey, or Memcached instance.

## Supported features

- **Cache clusters** — CreateCacheCluster, ModifyCacheCluster, DeleteCacheCluster, DescribeCacheClusters
- **Real engines via Docker** — Redis, Valkey, Memcached
- **Replication groups** — CreateReplicationGroup with primary/replica topology (Redis/Valkey only — matches AWS)
- **Global replication groups** — cross-region global datastores (CRUD)
- **Serverless caches** — CreateServerlessCache, ModifyServerlessCache (Redis/Valkey only — matches AWS)
- **Snapshots** — CreateSnapshot, CopySnapshot, DeleteSnapshot, RestoreReplicationGroupFromSnapshot
- **Serverless cache snapshots** — CRUD
- **Subnet groups** — CRUD
- **Users and user groups** — IAM-integrated auth
- **Parameter groups** — CRUD (default groups for redis7, valkey8, memcached1.6)
- **Security groups** — cache security group CRUD
- **Failover** — TestFailover, TestMigration
- **Tagging** — AddTagsToResource, RemoveTagsFromResource
- **Engine versions** — DescribeCacheEngineVersions

## Protocol

Query protocol. Form-encoded body, `Action` parameter, XML responses.

## How the Docker integration works

When you call `CreateCacheCluster` (or `CreateReplicationGroup` for Redis/Valkey topologies), fakecloud starts a real Docker container running the corresponding official image (`redis:7-alpine`, `valkey:8-alpine`, or `memcached:1.6-alpine`) and reports the mapped host port. Your application connects with a normal Redis or Memcached client.

## Gotchas

- **Requires a Docker socket.** ElastiCache needs access to `/var/run/docker.sock`.
- **First use pulls the image.** Expect a slower first run while the Redis/Valkey/Memcached image downloads.
- **Memcached is cache-cluster only.** AWS does not support replication groups or serverless caches for Memcached, and neither does fakecloud. Use `CreateCacheCluster` with `Engine=memcached`.

## Source

- [`crates/fakecloud-elasticache`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-elasticache)
- [AWS ElastiCache API reference](https://docs.aws.amazon.com/AmazonElastiCache/latest/APIReference/Welcome.html)
