+++
title = "Glue"
description = "AWS Glue Data Catalog (databases, tables, partitions) + Jobs/JobRuns control plane. JSON 1.1 protocol."
weight = 31
+++

fakecloud implements AWS Glue's JSON 1.1 control plane covering the **Data Catalog** (databases, tables, partitions) and **Jobs** (job CRUD + JobRun lifecycle), 26 operations total. The Data Catalog is the same store Athena reads through: tables created here surface immediately under `AwsDataCatalog` for Athena's `ListDatabases` / `GetTableMetadata` paths.

**Status: control-plane parity. The Glue ETL runtime does not execute Spark / Python Shell scripts — JobRuns transition through `STARTING -> RUNNING -> SUCCEEDED` for control-plane testing only.**

## Supported today

- **Databases** — `CreateDatabase` / `GetDatabase` / `UpdateDatabase` / `DeleteDatabase` / `GetDatabases`. Per-account namespace, name-uniqueness enforcement, parameter passthrough.
- **Tables** — `CreateTable` / `GetTable` / `UpdateTable` / `DeleteTable` / `GetTables`. Full `StorageDescriptor` round-trip: columns + types, location, input/output format, SerDe info, partition keys, table parameters, view text, table type. Tables are looked up by `(catalogId, databaseName, name)`.
- **Partitions** — `CreatePartition` / `BatchCreatePartition` / `BatchGetPartition` / `GetPartition` / `UpdatePartition` / `DeletePartition` / `GetPartitions`.
  - **`GetPartitions` Expression pruning** — the `Expression` filter is parsed and evaluated against partition values server-side. Supports `=` / `!=` / `<>` / `<` / `<=` / `>` / `>=` / `IN` / `BETWEEN` / `LIKE` / `IS NULL` / `IS NOT NULL`, plus `AND` / `OR` / `NOT` combinators and parentheses. Type-aware comparison for `string`, `int`, `bigint`, `date`, `timestamp`. Unparseable expressions return `InvalidInputException`, matching real Glue.
- **Jobs** — `CreateJob` / `GetJob` / `GetJobs` / `ListJobs` / `UpdateJob` / `DeleteJob`. Full round-trip on `Command` (name + script location + python version + runtime), `DefaultArguments`, `Connections`, `MaxRetries`, `Timeout`, `MaxCapacity`, `WorkerType`, `NumberOfWorkers`, `GlueVersion`, `ExecutionProperty`, `NotificationProperty`.
- **JobRuns** — `StartJobRun` / `GetJobRun` / `GetJobRuns`. Runs are assigned a JobRunId, accept `Arguments` overrides, capture `Timeout` / `MaxCapacity` / `WorkerType` / `NumberOfWorkers`, and step through `STARTING -> RUNNING -> SUCCEEDED` with `StartedOn` / `CompletedOn` / `ExecutionTime` populated.

## Athena integration

The same Data Catalog state powers Athena's catalog reads:

- `glue:CreateDatabase` -> visible in `athena:ListDatabases` under `AwsDataCatalog`.
- `glue:CreateTable` -> visible in `athena:GetTableMetadata` / `athena:ListTableMetadata`.
- Column types and partition keys round-trip end-to-end, so Athena's `DESCRIBE` / `SHOW TABLES` return the schema you registered through Glue.

See the [Athena docs](/docs/services/athena/) for the minimal SQL evaluator that runs over this catalog.

## Smoke test

```sh
fakecloud &

aws --endpoint-url http://localhost:4566 glue create-database \
  --database-input Name=analytics

aws --endpoint-url http://localhost:4566 glue create-table \
  --database-name analytics \
  --table-input 'Name=events,PartitionKeys=[{Name=dt,Type=string}],StorageDescriptor={Columns=[{Name=id,Type=string}],Location=s3://my-bucket/events/}'

# Register a few partitions, then prune them server-side.
for d in 2026-05-09 2026-05-10 2026-05-11; do
  aws --endpoint-url http://localhost:4566 glue create-partition \
    --database-name analytics --table-name events \
    --partition-input Values=$d,StorageDescriptor={Location=s3://my-bucket/events/dt=$d/}
done

aws --endpoint-url http://localhost:4566 glue get-partitions \
  --database-name analytics --table-name events \
  --expression "dt >= '2026-05-10'"

# Job + JobRun control plane.
aws --endpoint-url http://localhost:4566 glue create-job \
  --name daily-rollup \
  --role arn:aws:iam::000000000000:role/glue \
  --command Name=glueetl,ScriptLocation=s3://my-bucket/scripts/rollup.py,PythonVersion=3 \
  --glue-version 4.0

RUN_ID=$(aws --endpoint-url http://localhost:4566 glue start-job-run \
  --job-name daily-rollup --query 'JobRunId' --output text)

aws --endpoint-url http://localhost:4566 glue get-job-run \
  --job-name daily-rollup --run-id $RUN_ID
```

## Introspection

Two IAM-bypass admin endpoints expose Glue state so test assertions don't have to round-trip through the AWS SDK:

- `GET /_fakecloud/glue/jobs` — every Glue Job recorded by `CreateJob`, across every account. Returns `name`, `role`, `command`, `defaultArguments`, capacity / retry / timeout / worker fields, `createdOn`, `lastModifiedOn`.
- `GET /_fakecloud/glue/job-runs` — every `JobRun` recorded by `StartJobRun`. Returns `id`, `jobName`, `attempt`, `startedOn`, `completedOn`, `jobRunState`, `arguments`, `executionTime`. Accepts `?job_name=foo` to filter to a single job.

All first-party SDKs ship a `glue` sub-client wrapping these endpoints (`getJobs()`, `getJobRuns(jobName?)`). See [`reference/introspection`](/docs/reference/introspection/) for the full endpoint catalog.

## Caveats

The ETL runtime is not implemented. `StartJobRun` does not fetch your script from S3, does not spin up a Spark / Python Shell worker, and does not produce any output. Runs land in `SUCCEEDED` immediately. Use real Glue for actual ETL execution; use fakecloud for testing the job-orchestration and catalog-management code paths around it.

Crawlers, connections, triggers, workflows, dev endpoints, ML transforms, blueprints, schema registry, and data quality APIs are not implemented. The Data Catalog is the same store Athena reads through, so registered tables stay exactly what you wrote with `CreateTable` / `CreatePartition`.

## Source

- [`crates/fakecloud-glue`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-glue)
- [AWS Glue API reference](https://docs.aws.amazon.com/glue/latest/webapi/Welcome.html)
