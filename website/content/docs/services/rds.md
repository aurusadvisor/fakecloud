+++
title = "RDS"
description = "Real PostgreSQL, MySQL, MariaDB, Oracle, SQL Server, and Db2 instances via Docker. Snapshots, read replicas, parameter groups."
weight = 17
+++

fakecloud implements **163 of 163** RDS operations at 100% Smithy conformance. DB instances run in **real Docker containers** — your code connects to a real database, not a mock.

## Supported features

- **DB instances** — CreateDBInstance, ModifyDBInstance, DeleteDBInstance, DescribeDBInstances, RebootDBInstance
- **Real engines via Docker** — PostgreSQL, MySQL, MariaDB, Oracle (gvenzl/oracle-free), SQL Server (mssql/server Express), Db2 (db2_community)
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

When you call `CreateDBInstance` for PostgreSQL/MySQL/MariaDB/Oracle/SQL Server/Db2, fakecloud starts a real Docker container running the upstream image for that engine and version, waits for it to be ready, and reports the mapped host port. Your application connects to that port like it would connect to any database.

`DeleteDBInstance` stops and removes the container. `RebootDBInstance` restarts it. Snapshots serialize the DB state so it can be restored into a fresh container.

### Engine -> image map

| Engine | Image | Port | Wait probe |
|--------|-------|------|------------|
| `postgres` | `postgres:<major>-alpine` | 5432 | `tokio-postgres` ping |
| `mysql` | `mysql:<major>` | 3306 | `mysql_async` ping |
| `mariadb` | `mariadb:<major>` | 3306 | `mysql_async` ping |
| `oracle-ee` / `oracle-se2` (+`-cdb`) | `gvenzl/oracle-free:23-slim` | 1521 | log marker `DATABASE IS READY TO USE!` + TCP probe |
| `sqlserver-ee` / `-se` / `-ex` / `-web` | `mcr.microsoft.com/mssql/server:2022-latest` | 1433 | log marker `SQL Server is now ready for client connections` + TCP probe |
| `db2-se` / `db2-ae` | `icr.io/db2_community/db2:latest` | 50000 | log marker `Setup has completed` + TCP probe |

The Oracle / SQL Server / Db2 images are large (1-3 GB) and take 30-300 s to first-boot. fakecloud passes the engine-specific license-acceptance environment variables (`ACCEPT_EULA`, `LICENSE`) automatically. Db2 launches with `--privileged` because the container needs it to set kernel parameters during startup.

## Gotchas

- **Requires a Docker socket.** RDS needs access to `/var/run/docker.sock` to start and stop containers.
- **First use pulls the image.** Expect a slower first run while the database image downloads. Heavy engines (Oracle/SQL Server/Db2) can pull 1-3 GB on first use.
- **Aurora is partially supported.** Aurora-specific features (Global Database, Serverless v2, I/O-optimized) are recorded but don't affect the real container.
- **Db2 needs `--privileged`.** fakecloud sets it automatically; the host must allow privileged containers.
- **Heavy-engine boot is slow.** Oracle takes 30-90 s to first-boot, Db2 30-60 s, SQL Server ~30 s. Factor this into test budgets.

## Source

- [`crates/fakecloud-rds`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-rds)
- [AWS RDS API reference](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/Welcome.html)
