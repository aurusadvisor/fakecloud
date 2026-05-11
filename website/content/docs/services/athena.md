+++
title = "Athena"
description = "AWS Athena — workgroups, data catalogs, named queries, prepared statements, query executions, notebooks, sessions, capacity reservations. JSON 1.1 protocol with a minimal SQL evaluator that reads Glue tables."
weight = 30
+++

fakecloud implements AWS Athena's full JSON 1.1 control plane: 70 operations covering workgroups, data catalogs, named queries, prepared statements, query executions, notebooks, sessions + calculations, capacity reservations, tagging, and read-only catalog lookups. 100% Smithy conformance.

**Status: 100% control-plane coverage. A minimal SQL evaluator handles `SELECT` / `SHOW DATABASES` / `SHOW TABLES` / `DESCRIBE` and parameter substitution against Glue Data Catalog state; complex queries (joins, aggregations, window functions, Parquet/ORC scans) intentionally fall back to a synthesized single-row result.**

## Supported today

- **Workgroups** — `CreateWorkGroup` / `GetWorkGroup` / `ListWorkGroups` / `UpdateWorkGroup` / `DeleteWorkGroup`. The `primary` workgroup is auto-seeded the first time an account is touched. `DeleteWorkGroup` rejects `primary` and refuses workgroups with attached query executions / named queries unless `RecursiveDeleteOption=true`.
- **Data catalogs** — `CreateDataCatalog` / `GetDataCatalog` / `ListDataCatalogs` / `UpdateDataCatalog` / `DeleteDataCatalog`. `AwsDataCatalog` (GLUE type) is auto-seeded and rejected on delete. Supports `LAMBDA` / `GLUE` / `HIVE` / `FEDERATED` types.
- **Catalog reads back the real Glue state** — `ListDatabases` and `GetTableMetadata` (and `ListTableMetadata`) on the `AwsDataCatalog` catalog read from the Glue Data Catalog service: databases and tables created via `glue:CreateDatabase` / `glue:CreateTable` show up immediately. Column types, partition keys, storage descriptors, and table parameters round-trip end-to-end.
- **Named queries** — `CreateNamedQuery` / `GetNamedQuery` / `ListNamedQueries` / `BatchGetNamedQuery` / `UpdateNamedQuery` / `DeleteNamedQuery`. Stored against a workgroup; named query IDs are UUID v4. `StartQueryExecution` accepts `NamedQueryId` and resolves the stored SQL.
- **Prepared statements** — `CreatePreparedStatement` / `GetPreparedStatement` / `ListPreparedStatements` / `BatchGetPreparedStatement` / `UpdatePreparedStatement` / `DeletePreparedStatement`. Keyed by `(workgroup, statement_name)`. `StartQueryExecution` with `ExecutionParameters` performs positional `?` substitution against the prepared SQL.
- **Query executions** — `StartQueryExecution` runs through the minimal evaluator:
  - `SELECT col1, col2 FROM db.table WHERE col = 'literal' LIMIT N` projects from Glue table metadata that has rows registered (via the introspection endpoint or partition writes).
  - `SHOW DATABASES` / `SHOW TABLES IN db` enumerate Glue catalog state.
  - `DESCRIBE db.table` returns the column schema.
  - Unknown / complex statements (joins, aggregates, subqueries) succeed with a single-row `[["1"]]` result so callers can still exercise polling / pagination wiring.

  `StopQueryExecution` flips the state to `CANCELLED`. `BatchGetQueryExecution` returns hits + misses. `GetQueryRuntimeStatistics` returns shape-correct empty stats.
- **Notebooks** — `CreateNotebook` / `ImportNotebook` / `ExportNotebook` / `GetNotebookMetadata` / `ListNotebookMetadata` / `UpdateNotebook` / `UpdateNotebookMetadata` / `DeleteNotebook` / `CreatePresignedNotebookUrl`. Notebooks are stored against a workgroup; payload round-trips verbatim.
- **Sessions + calculations** — `StartSession` / `GetSession` / `GetSessionStatus` / `GetSessionEndpoint` / `ListSessions` / `ListNotebookSessions` / `TerminateSession`. `StartCalculationExecution` / `StopCalculationExecution` / `GetCalculationExecution` / `GetCalculationExecutionCode` / `GetCalculationExecutionStatus` / `ListCalculationExecutions`. Sessions transition through `CREATING -> IDLE -> TERMINATED`; calculations land in `COMPLETED` immediately.
- **Capacity reservations** — `CreateCapacityReservation` / `GetCapacityReservation` / `ListCapacityReservations` / `UpdateCapacityReservation` / `CancelCapacityReservation` / `DeleteCapacityReservation`. `PutCapacityAssignmentConfiguration` / `GetCapacityAssignmentConfiguration` for routing workgroups to reservations.
- **Tags** — `TagResource` / `UntagResource` / `ListTagsForResource`. Keyed by ARN across workgroup / datacatalog / capacity-reservation resources.
- **Read-only catalog** — `ListEngineVersions` returns the AUTO + Athena engine version 2/3 catalog. `ListApplicationDPUSizes` returns the standard application coordinator + executor DPU options. `ListExecutors` / `GetResourceDashboard` return shape-correct empty windows.

## Smoke test

```sh
fakecloud &

# `primary` workgroup and `AwsDataCatalog` are seeded automatically.
aws --endpoint-url http://localhost:4566 athena list-work-groups
aws --endpoint-url http://localhost:4566 athena list-data-catalogs

# Register a Glue database + table, then query it through Athena.
aws --endpoint-url http://localhost:4566 glue create-database \
  --database-input Name=analytics
aws --endpoint-url http://localhost:4566 glue create-table \
  --database-name analytics \
  --table-input 'Name=events,StorageDescriptor={Columns=[{Name=id,Type=string},{Name=ts,Type=string}],Location=s3://my-bucket/events/}'

aws --endpoint-url http://localhost:4566 athena start-query-execution \
  --query-string "SHOW TABLES IN analytics" \
  --work-group primary \
  --result-configuration OutputLocation=s3://my-bucket/results/

# Prepared statement with parameter substitution.
aws --endpoint-url http://localhost:4566 athena create-prepared-statement \
  --statement-name latest-event \
  --work-group primary \
  --query-statement "SELECT id FROM analytics.events WHERE id = ?"

aws --endpoint-url http://localhost:4566 athena start-query-execution \
  --query-string "EXECUTE latest-event" \
  --work-group primary \
  --execution-parameters "'abc-123'" \
  --result-configuration OutputLocation=s3://my-bucket/results/
```

## Caveats

The Athena query path is a deliberately minimal SQL evaluator built for control-plane and SDK testing — not an analytics engine. It is happy to answer schema / catalog questions and trivial single-table `SELECT`s, but it does not implement:

- Joins, subqueries, CTEs, set operations (`UNION` / `INTERSECT` / `EXCEPT`).
- Aggregations or window functions (`GROUP BY`, `COUNT`, `SUM`, `OVER (...)`).
- Parquet / ORC / Avro / JSON file scans from S3. The evaluator does not read object data.
- Type coercion beyond literal `string` / `bigint` / `boolean` comparisons.

Any statement outside the supported subset still succeeds with a synthesized single-row `[["1"]]` result so test fixtures keep working. If you need real query execution, run real Athena.

Capacity reservations are stored verbatim; `allocated_dpus` mirrors `target_dpus` immediately on create (real Athena ramps over minutes). Sessions and calculations transition to their terminal state synchronously rather than over the real Athena warm-up window.

The managed engine version catalog (`ListEngineVersions`) is a static seed: `AUTO`, `Athena engine version 2`, `Athena engine version 3`. New engine versions shipped by AWS will not appear until the seed is updated.

## Source

- [`crates/fakecloud-athena`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-athena)
- [AWS Athena API reference](https://docs.aws.amazon.com/athena/latest/APIReference/Welcome.html)
