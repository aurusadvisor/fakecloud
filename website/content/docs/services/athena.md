+++
title = "Athena"
description = "AWS Athena — workgroups, data catalogs, named queries, prepared statements, query executions, notebooks, sessions, capacity reservations. JSON 1.1 protocol."
weight = 30
+++

fakecloud implements AWS Athena's full JSON 1.1 control plane: 70 operations covering workgroups, data catalogs, named queries, prepared statements, query executions, notebooks, sessions + calculations, capacity reservations, tagging, and read-only catalog lookups. 100% Smithy conformance.

**Status: 100% control-plane coverage. Queries always SUCCEED with a synthesized single-row result — fakecloud is not a SQL engine.**

## Supported today

- **Workgroups** — `CreateWorkGroup` / `GetWorkGroup` / `ListWorkGroups` / `UpdateWorkGroup` / `DeleteWorkGroup`. The `primary` workgroup is auto-seeded the first time an account is touched. `DeleteWorkGroup` rejects `primary` and refuses workgroups with attached query executions / named queries unless `RecursiveDeleteOption=true`.
- **Data catalogs** — `CreateDataCatalog` / `GetDataCatalog` / `ListDataCatalogs` / `UpdateDataCatalog` / `DeleteDataCatalog`. `AwsDataCatalog` (GLUE type) is auto-seeded and rejected on delete. Supports `LAMBDA` / `GLUE` / `HIVE` / `FEDERATED` types. `GetDatabase` / `ListDatabases` / `GetTableMetadata` / `ListTableMetadata` return shape-correct empty catalog responses.
- **Named queries** — `CreateNamedQuery` / `GetNamedQuery` / `ListNamedQueries` / `BatchGetNamedQuery` / `UpdateNamedQuery` / `DeleteNamedQuery`. Stored against a workgroup; named query IDs are UUID v4.
- **Prepared statements** — `CreatePreparedStatement` / `GetPreparedStatement` / `ListPreparedStatements` / `BatchGetPreparedStatement` / `UpdatePreparedStatement` / `DeletePreparedStatement`. Keyed by `(workgroup, statement_name)` so the same name can exist in different workgroups.
- **Query executions** — `StartQueryExecution` synthesizes a `SUCCEEDED` execution with a single-row `[["1"]]` result (1 byte scanned, 1 ms execution time) so callers can immediately fetch via `GetQueryResults` without waiting on a poll loop. Statement type (`DML` / `DDL` / `UTILITY`) is inferred from the leading SQL keyword. `StopQueryExecution` flips the state to `CANCELLED`. `BatchGetQueryExecution` returns hits + misses. `GetQueryRuntimeStatistics` returns shape-correct empty stats.
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

# Run a query — returns immediately with a single-row result.
QID=$(aws --endpoint-url http://localhost:4566 athena start-query-execution \
  --query-string "SELECT 1" \
  --work-group primary \
  --query-execution-context Database=default \
  --result-configuration OutputLocation=s3://my-bucket/results/ \
  --query 'QueryExecutionId' --output text)

aws --endpoint-url http://localhost:4566 athena get-query-execution \
  --query-execution-id $QID

aws --endpoint-url http://localhost:4566 athena get-query-results \
  --query-execution-id $QID

# Save a named query for reuse.
aws --endpoint-url http://localhost:4566 athena create-named-query \
  --name daily-count \
  --database default \
  --query-string "SELECT count(*) FROM events" \
  --work-group primary
```

## Caveats

fakecloud does not parse or execute SQL. Every `StartQueryExecution` call returns a `SUCCEEDED` execution with a synthesized one-row result containing the literal `"1"`. Real Athena runs against Glue + S3 + Presto/Trino; fakecloud does not. This is enough to exercise SDK wiring, polling logic, IAM policy paths, and result-pagination handling, but it is not a SQL engine.

`GetDatabase`, `ListDatabases`, `GetTableMetadata`, and `ListTableMetadata` return shape-correct responses with no actual catalog data. Real Athena reads these from Glue / Hive Metastore — fakecloud does not currently surface Glue catalog state through Athena.

Capacity reservations are stored verbatim; `allocated_dpus` mirrors `target_dpus` immediately on create (real Athena ramps over minutes). Sessions and calculations transition to their terminal state synchronously rather than over the real Athena warm-up window.

The managed engine version catalog (`ListEngineVersions`) is a static seed: `AUTO`, `Athena engine version 2`, `Athena engine version 3`. New engine versions shipped by AWS will not appear until the seed is updated.
