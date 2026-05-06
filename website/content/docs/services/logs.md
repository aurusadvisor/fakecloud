+++
title = "CloudWatch Logs"
description = "Log groups, streams, filtering, subscriptions, queries, anomaly detection."
weight = 11
+++

fakecloud implements **113 of 113** CloudWatch Logs operations at 100% Smithy conformance.

## Supported features

- **Log groups** — CRUD, retention, tags, KMS association, data protection
- **Log streams** — CRUD, log events, sequence token management
- **Log events** — PutLogEvents, GetLogEvents, FilterLogEvents
- **Subscription filters** — delivery to Lambda, Kinesis, SQS
- **Query language** — StartQuery, GetQueryResults with full Insights query syntax
- **Metric filters** — CRUD, extraction patterns
- **Resource policies** — CRUD
- **Export tasks** — S3 exports (recorded)
- **Destinations** — cross-account destinations
- **Anomaly detectors** — CRUD, training state, configuration
- **Log deliveries** — CRUD for enhanced metrics/logs delivery
- **Transformers** — log transformation configurations

## Protocol

JSON protocol. `X-Amz-Target` header, JSON body, JSON responses.

## Cross-service delivery

- **CloudWatch Logs -> Lambda / Kinesis / SQS** — Subscription filters deliver log events

## Gotchas

- **Anomaly detection is managed but doesn't run.** You can create, update, list, and delete anomaly detectors — they all conform to AWS — but no actual anomaly analysis happens. `ListAnomalies` returns an empty list. If your code depends on detections, fake them another way.

## Limitations

- `StartLiveTail`, `GetLogObject`, and `GetLogFields` return shape-correct stub responses. No real streaming tail or structured log-object indexing is implemented.
- Anomaly detection is managed but does not run. You can create, update, list, and delete anomaly detectors, but `ListAnomalies` always returns an empty list.

## Source

- [`crates/fakecloud-logs`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-logs)
- [AWS CloudWatch Logs API reference](https://docs.aws.amazon.com/AmazonCloudWatchLogs/latest/APIReference/Welcome.html)
