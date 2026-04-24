+++
title = "RDS"
description = "Real PostgreSQL, MySQL, and MariaDB instances via Docker. Snapshots, read replicas, parameter groups."
weight = 17
+++

fakecloud implements **163 of 163** RDS operations at 100% Smithy conformance. DB instances run in **real Docker containers** — your code connects to a real database, not a mock.

## Supported features

- **DB instances** — CreateDBInstance, ModifyDBInstance, DeleteDBInstance, DescribeDBInstances, RebootDBInstance
- **Real engines via Docker** — PostgreSQL, MySQL, MariaDB
- **Snapshots** — automated and manual, CreateDBSnapshot, RestoreDBInstanceFromDBSnapshot, CopyDBSnapshot, DeleteDBSnapshot
- **Read replicas** — CreateDBInstanceReadReplica, PromoteReadReplica
- **Parameter groups** — DBParameterGroup and DBClusterParameterGroup CRUD, parameter management
- **Option groups** — CRUD
- **Subnet groups** — CRUD
- **DB clusters** — Aurora-style clusters (limited engine support)
- **Events** — DescribeEvents, DescribeEventCategories, DescribeEventSubscriptions
- **Engine discovery** — DescribeDBEngineVersions with real engine metadata
- **Tagging** — AddTagsToResource, RemoveTagsFromResource
- **Dump and restore** — MySQL and MariaDB database dumps for snapshot/restore flows
- **License models** — tracking
- **EventBridge events** — lifecycle ops emit `aws.rds` events on the `default` bus, deliverable to SQS, SNS, Lambda, etc. via standard EB rules

## EventBridge integration

Lifecycle ops emit events matching the AWS event schema (`source: "aws.rds"`, detail-type per source kind):

| Operation                       | EventID         | Source type        | Categories            |
|---------------------------------|-----------------|--------------------|-----------------------|
| `CreateDBInstance`              | RDS-EVENT-0005  | DB_INSTANCE        | creation              |
| `DeleteDBInstance`              | RDS-EVENT-0003  | DB_INSTANCE        | deletion              |
| `ModifyDBInstance`              | RDS-EVENT-0014  | DB_INSTANCE        | configuration change  |
| `RebootDBInstance`              | RDS-EVENT-0006  | DB_INSTANCE        | availability          |
| `StartDBInstance`               | RDS-EVENT-0088  | DB_INSTANCE        | notification          |
| `StopDBInstance`                | RDS-EVENT-0089  | DB_INSTANCE        | notification          |
| `CreateDBInstanceReadReplica`   | RDS-EVENT-0005  | DB_INSTANCE        | creation, read replica|
| `RestoreDBInstanceFromDBSnapshot` | RDS-EVENT-0043 | DB_INSTANCE       | creation              |
| `CreateDBSnapshot`              | RDS-EVENT-0042  | DB_SNAPSHOT        | creation              |
| `DeleteDBSnapshot`              | RDS-EVENT-0041  | DB_SNAPSHOT        | deletion              |

Match with an EventBridge rule pattern like:

```json
{ "source": ["aws.rds"], "detail-type": ["RDS DB Instance Event"] }
```

## Protocol

Query protocol. Form-encoded body, `Action` parameter, XML responses.

## Introspection

- `GET /_fakecloud/rds/instances` — list fakecloud-managed DB instances with runtime metadata (container id, host port)

## How the Docker integration works

When you call `CreateDBInstance` for PostgreSQL/MySQL/MariaDB, fakecloud starts a real Docker container running the official image for that engine and version, waits for it to be ready, and reports the mapped host port. Your application connects to that port like it would connect to any database.

`DeleteDBInstance` stops and removes the container. `RebootDBInstance` restarts it. Snapshots serialize the DB state so it can be restored into a fresh container.

## Gotchas

- **Requires a Docker socket.** RDS needs access to `/var/run/docker.sock` to start and stop containers.
- **First use pulls the image.** Expect a slower first run while the database image downloads.
- **Aurora is partially supported.** Aurora-specific features (Global Database, Serverless v2, I/O-optimized) are recorded but don't affect the real container.
- **Some engines not supported via Docker.** Oracle, SQL Server, and Db2 are recorded in state (CRUD operations work) but don't run real databases.

## Source

- [`crates/fakecloud-rds`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-rds)
- [AWS RDS API reference](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/Welcome.html)
