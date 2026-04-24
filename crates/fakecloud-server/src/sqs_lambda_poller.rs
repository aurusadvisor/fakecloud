//! Background poller that bridges SQS -> Lambda event source mappings.
//!
//! Periodically checks Lambda state for enabled event source mappings
//! pointing to SQS queues, polls those queues for messages, and either
//! invokes the Lambda function via the container runtime (when available)
//! or records the invocation in Lambda state.
//!
//! Honors:
//! - `FilterCriteria` — non-matching messages are dropped (acked).
//! - `FunctionResponseTypes=[ReportBatchItemFailures]` — when the
//!   Lambda response body is `{"batchItemFailures":[{"itemIdentifier":"<id>"}]}`,
//!   only acked message ids are removed; failed ids are made visible
//!   again so the queue can redeliver.
//! - `MaximumBatchingWindowInSeconds` — once a partial batch is
//!   observed, the poller waits up to N seconds for it to fill before
//!   invoking the Lambda. Once `BatchSize` is reached or the window
//!   expires, the batch is dispatched.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use serde_json::{json, Value};

use fakecloud_core::delivery::LambdaDelivery;
use fakecloud_lambda::filter::FilterSet;
use fakecloud_lambda::state::{LambdaInvocation, SharedLambdaState};
use fakecloud_sqs::state::SharedSqsState;

#[derive(Clone)]
struct Mapping {
    uuid: String,
    function_arn: String,
    queue_arn: String,
    batch_size: i64,
    filter: FilterSet,
    report_batch_item_failures: bool,
    max_batching_window_seconds: i64,
}

/// Per-mapping batching window state. Tracks the timestamp of the
/// first observed message after the most recent invoke so the poller
/// can hold a partial batch open for `max_batching_window_seconds`.
#[derive(Default)]
struct BatchingState {
    window_started_at: HashMap<String, DateTime<Utc>>,
}

/// SQS -> Lambda event source mapping poller.
pub struct SqsLambdaPoller {
    sqs_state: SharedSqsState,
    lambda_state: SharedLambdaState,
    lambda_delivery: Option<Arc<dyn LambdaDelivery>>,
}

impl SqsLambdaPoller {
    pub fn new(sqs_state: SharedSqsState, lambda_state: SharedLambdaState) -> Self {
        Self {
            sqs_state,
            lambda_state,
            lambda_delivery: None,
        }
    }

    pub fn with_lambda_delivery(mut self, delivery: Arc<dyn LambdaDelivery>) -> Self {
        self.lambda_delivery = Some(delivery);
        self
    }

    pub async fn run(self) {
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        let mut batching = BatchingState::default();
        loop {
            interval.tick().await;
            self.poll(&mut batching).await;
        }
    }

    async fn poll(&self, batching: &mut BatchingState) {
        let mappings: Vec<Mapping> = {
            let lambda_accounts = self.lambda_state.read();
            lambda_accounts
                .iter()
                .flat_map(|(_, lambda)| {
                    lambda
                        .event_source_mappings
                        .values()
                        .filter(|m| m.enabled && m.event_source_arn.contains(":sqs:"))
                        .map(|m| Mapping {
                            uuid: m.uuid.clone(),
                            function_arn: m.function_arn.clone(),
                            queue_arn: m.event_source_arn.clone(),
                            batch_size: m.batch_size,
                            filter: FilterSet::from_strings(m.filter_patterns.iter()),
                            report_batch_item_failures: m
                                .function_response_types
                                .iter()
                                .any(|s| s == "ReportBatchItemFailures"),
                            max_batching_window_seconds: m
                                .maximum_batching_window_in_seconds
                                .unwrap_or(0),
                        })
                        .collect::<Vec<_>>()
                })
                .collect()
        };

        if mappings.is_empty() {
            return;
        }

        let now = Utc::now();

        for mapping in mappings {
            self.process_mapping(&mapping, batching, now).await;
        }
    }

    async fn process_mapping(
        &self,
        mapping: &Mapping,
        batching: &mut BatchingState,
        now: DateTime<Utc>,
    ) {
        // Pull up to BatchSize visible messages without removing them
        // from the queue yet. Removal happens after the Lambda response
        // is observed so partial-batch failure semantics work.
        let messages = {
            let mut sqs_mas = self.sqs_state.write();
            let default_acct = sqs_mas.default_account_id().to_string();
            let acct = mapping.queue_arn.split(':').nth(4).unwrap_or(&default_acct);
            let sqs = sqs_mas.get_or_create(acct);
            let queue = sqs.queues.values_mut().find(|q| q.arn == mapping.queue_arn);
            let queue = match queue {
                Some(q) => q,
                None => return,
            };

            let mut batch = Vec::new();
            let limit = mapping.batch_size.min(10) as usize;

            for msg in queue.messages.iter() {
                if batch.len() >= limit {
                    break;
                }
                if let Some(vis) = msg.visible_at {
                    if vis > now {
                        continue;
                    }
                }
                batch.push(msg.clone());
            }

            batch
        };

        if messages.is_empty() {
            batching.window_started_at.remove(&mapping.uuid);
            return;
        }

        // Honor MaximumBatchingWindowInSeconds: hold a partial batch
        // open until the window expires, then dispatch what we have.
        // A full batch dispatches immediately regardless.
        let limit = mapping.batch_size.min(10) as usize;
        if mapping.max_batching_window_seconds > 0 && messages.len() < limit {
            let window_start = batching
                .window_started_at
                .entry(mapping.uuid.clone())
                .or_insert(now);
            let elapsed = now.signed_duration_since(*window_start).num_seconds();
            if elapsed < mapping.max_batching_window_seconds {
                return;
            }
        }
        batching.window_started_at.remove(&mapping.uuid);

        // Build SQS-shaped event records, filter, then mark visible-at
        // for failures (or remove for successes) on the SQS side.
        let records: Vec<Value> = messages
            .iter()
            .map(|msg| {
                json!({
                    "messageId": msg.message_id,
                    "receiptHandle": msg.receipt_handle,
                    "body": msg.body,
                    "attributes": {
                        "ApproximateReceiveCount": msg.receive_count.to_string(),
                        "SentTimestamp": msg.sent_timestamp.to_string(),
                    },
                    "md5OfBody": msg.md5_of_body,
                    "eventSource": "aws:sqs",
                    "eventSourceARN": mapping.queue_arn,
                })
            })
            .collect();

        let (matched_records, dropped_ids): (Vec<Value>, Vec<String>) = if mapping.filter.is_empty()
        {
            (records, Vec::new())
        } else {
            let mut matched = Vec::new();
            let mut dropped = Vec::new();
            for (rec, msg) in records.into_iter().zip(messages.iter()) {
                if mapping.filter.matches(&rec) {
                    matched.push(rec);
                } else {
                    dropped.push(msg.message_id.clone());
                }
            }
            (matched, dropped)
        };

        // Drop filtered-out messages — AWS treats them as acked so the
        // queue stops redelivering them.
        if !dropped_ids.is_empty() {
            let mut sqs_mas = self.sqs_state.write();
            let default_acct = sqs_mas.default_account_id().to_string();
            let acct = mapping.queue_arn.split(':').nth(4).unwrap_or(&default_acct);
            let sqs = sqs_mas.get_or_create(acct);
            if let Some(queue) = sqs.queues.values_mut().find(|q| q.arn == mapping.queue_arn) {
                queue
                    .messages
                    .retain(|m| !dropped_ids.contains(&m.message_id));
            }
        }

        if matched_records.is_empty() {
            return;
        }

        let payload = json!({ "Records": &matched_records }).to_string();

        tracing::debug!(
            function_arn = %mapping.function_arn,
            queue_arn = %mapping.queue_arn,
            message_count = matched_records.len(),
            dropped_by_filter = dropped_ids.len(),
            "SQS->Lambda: delivering messages to function"
        );

        let invoke_result = if let Some(ref delivery) = self.lambda_delivery {
            Some(
                delivery
                    .invoke_lambda(&mapping.function_arn, &payload)
                    .await,
            )
        } else {
            None
        };

        let matched_msg_ids: Vec<String> = matched_records
            .iter()
            .filter_map(|r| {
                r.get("messageId")
                    .and_then(|v| v.as_str())
                    .map(String::from)
            })
            .collect();

        let (acked_ids, failed_ids) = match &invoke_result {
            Some(Ok(body)) if mapping.report_batch_item_failures => {
                split_batch_failures(body, &matched_msg_ids)
            }
            Some(Ok(_)) => (matched_msg_ids.clone(), Vec::new()),
            Some(Err(err)) => {
                tracing::warn!(
                    function_arn = %mapping.function_arn,
                    error = %err,
                    "SQS->Lambda: function invocation failed; messages will be retried"
                );
                (Vec::new(), matched_msg_ids.clone())
            }
            None => (matched_msg_ids.clone(), Vec::new()),
        };

        if !acked_ids.is_empty() || !failed_ids.is_empty() {
            let mut sqs_mas = self.sqs_state.write();
            let default_acct = sqs_mas.default_account_id().to_string();
            let acct = mapping.queue_arn.split(':').nth(4).unwrap_or(&default_acct);
            let sqs = sqs_mas.get_or_create(acct);
            if let Some(queue) = sqs.queues.values_mut().find(|q| q.arn == mapping.queue_arn) {
                queue
                    .messages
                    .retain(|m| !acked_ids.contains(&m.message_id));
                // Failed messages stay; bump receive_count and clear
                // any pending visibility timeout so the queue
                // immediately considers them again on the next poll.
                for msg in queue.messages.iter_mut() {
                    if failed_ids.contains(&msg.message_id) {
                        msg.receive_count = msg.receive_count.saturating_add(1);
                        msg.visible_at = None;
                    }
                }
            }
        }

        let fn_account = mapping.function_arn.split(':').nth(4).unwrap_or("");
        let mut lambda_accounts = self.lambda_state.write();
        let lambda = lambda_accounts.get_or_create(fn_account);
        lambda.invocations.push(LambdaInvocation {
            function_arn: mapping.function_arn.clone(),
            payload,
            timestamp: now,
            source: "aws:sqs".to_string(),
        });
    }
}

/// Parse the Lambda response body as `{"batchItemFailures":[...]}`. Any
/// id that appears in the failures list is reported as failed; the
/// rest are acked. If the body doesn't decode or contains an empty
/// failures list, the entire batch is acked.
fn split_batch_failures(body: &[u8], batch_ids: &[String]) -> (Vec<String>, Vec<String>) {
    let parsed: Value = match serde_json::from_slice(body) {
        Ok(v) => v,
        Err(_) => return (batch_ids.to_vec(), Vec::new()),
    };
    let failures: Vec<String> = parsed
        .get("batchItemFailures")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|f| {
                    f.get("itemIdentifier")
                        .and_then(|v| v.as_str())
                        .map(String::from)
                })
                .collect()
        })
        .unwrap_or_default();
    if failures.is_empty() {
        return (batch_ids.to_vec(), Vec::new());
    }
    let acked = batch_ids
        .iter()
        .filter(|id| !failures.contains(id))
        .cloned()
        .collect();
    (acked, failures)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn batch_failures_parse() {
        let body = br#"{"batchItemFailures":[{"itemIdentifier":"a"},{"itemIdentifier":"c"}]}"#;
        let (acked, failed) =
            split_batch_failures(body, &["a".into(), "b".into(), "c".into(), "d".into()]);
        assert_eq!(acked, vec!["b".to_string(), "d".to_string()]);
        assert_eq!(failed, vec!["a".to_string(), "c".to_string()]);
    }

    #[test]
    fn batch_failures_empty_list_acks_all() {
        let body = br#"{"batchItemFailures":[]}"#;
        let (acked, failed) = split_batch_failures(body, &["a".into(), "b".into()]);
        assert_eq!(acked, vec!["a".to_string(), "b".to_string()]);
        assert!(failed.is_empty());
    }

    #[test]
    fn batch_failures_no_field_acks_all() {
        let body = br#"{"ok":true}"#;
        let (acked, failed) = split_batch_failures(body, &["a".into(), "b".into()]);
        assert_eq!(acked, vec!["a".to_string(), "b".to_string()]);
        assert!(failed.is_empty());
    }
}
