//! Target delivery + DLQ routing for fired schedules.
//!
//! Scheduler's firing contract: every enabled schedule whose expression
//! matches the current tick has its `Target.Input` body delivered to
//! `Target.Arn`. If delivery fails (target queue missing, etc.) and
//! `Target.DeadLetterConfig.Arn` is set, we route the original input +
//! failure metadata headers to the DLQ so tests can observe the
//! failure. No retry policy is modeled in Batch 2 — every fire is a
//! single attempt.

use std::collections::HashMap;
use std::sync::Arc;

use fakecloud_core::delivery::{DeliveryBus, SqsDeliveryError, SqsMessageAttribute};

use crate::state::Schedule;

/// Attempt to deliver a fired schedule's target. Returns `Ok(())` when
/// the target accepted the message (or the target type is a fire-and-
/// forget SNS/Lambda/SFN that we don't currently validate). Returns
/// `Err` only for SQS-shaped targets where the queue doesn't exist —
/// that's the specific signal Scheduler's DLQ routing needs.
pub fn deliver_target(bus: &Arc<DeliveryBus>, schedule: &Schedule) -> Result<(), SqsDeliveryError> {
    let arn = &schedule.target.arn;
    let body = schedule.target.input.as_deref().unwrap_or("{}");

    if arn.contains(":sqs:") {
        let attrs = HashMap::new();
        let group_id = schedule
            .target
            .sqs_parameters
            .as_ref()
            .and_then(|s| s.message_group_id.as_deref());
        // FIFO queues without content-based dedup reject messages
        // lacking a dedup ID; AWS Scheduler synthesizes one per fire
        // so the message survives regardless of the queue's dedup
        // policy. Use the schedule ARN + fire timestamp so the same
        // schedule can fire repeatedly without being deduplicated.
        let dedup_id = fifo_dedup_id(arn, &schedule.arn);
        return bus.try_send_to_sqs_with_attrs(arn, body, &attrs, group_id, dedup_id.as_deref());
    }

    if arn.contains(":sns:") {
        bus.publish_to_sns(arn, body, None);
        return Ok(());
    }

    if arn.contains(":lambda:") {
        // Fire-and-forget async invocation. A proper implementation
        // would await the future, but DeliveryBus::invoke_lambda is
        // async and we're called from the synchronous tick loop.
        let bus = bus.clone();
        let arn = arn.clone();
        let body = body.to_string();
        tokio::spawn(async move {
            let _ = bus.invoke_lambda(&arn, &body).await;
        });
        return Ok(());
    }

    if arn.contains(":states:") {
        bus.start_stepfunctions_execution(arn, body);
        return Ok(());
    }

    if arn.contains(":events:") {
        let bus_name = event_bus_name_from_arn(arn);
        let target_account = account_id_from_arn(arn);
        match target_account {
            Some(account) => bus.put_event_to_eventbridge_for_account(
                "aws.scheduler",
                "Scheduled Event",
                body,
                &bus_name,
                &account,
            ),
            None => {
                bus.put_event_to_eventbridge("aws.scheduler", "Scheduled Event", body, &bus_name)
            }
        }
        return Ok(());
    }

    if arn.contains(":kinesis:") {
        // KinesisParameters.PartitionKey carries the per-record key per
        // AWS contract; fall back to the schedule name so the put never
        // fails on a missing key.
        let partition_key = schedule
            .target
            .kinesis_parameters
            .as_ref()
            .and_then(|p| p.get("PartitionKey").and_then(|v| v.as_str()))
            .unwrap_or(&schedule.name)
            .to_string();
        bus.send_to_kinesis(arn, body, &partition_key);
        return Ok(());
    }

    // Unsupported target type — log and succeed so we don't push it to
    // DLQ (DLQ is for deliverable-target failures, not unknown targets).
    tracing::warn!(target_arn = %arn, schedule = %schedule.name, "scheduler: unsupported target type, skipping");
    Ok(())
}

/// Route a failed delivery to the schedule's DLQ, if one is
/// configured. Metadata headers mirror AWS's format so tests can
/// assert on `X-Amz-Scheduler-Attempt` etc.
pub fn route_to_dlq(
    bus: &Arc<DeliveryBus>,
    schedule: &Schedule,
    error_code: &str,
    error_message: &str,
) {
    let dlq_arn = match schedule
        .target
        .dead_letter_config
        .as_ref()
        .and_then(|d| d.arn.as_ref())
    {
        Some(arn) => arn.clone(),
        None => return,
    };

    let mut attrs: HashMap<String, SqsMessageAttribute> = HashMap::new();
    attrs.insert("X-Amz-Scheduler-Attempt".to_string(), string_attr("1"));
    attrs.insert(
        "X-Amz-Scheduler-Schedule-Arn".to_string(),
        string_attr(&schedule.arn),
    );
    attrs.insert(
        "X-Amz-Scheduler-Target-Arn".to_string(),
        string_attr(&schedule.target.arn),
    );
    attrs.insert(
        "X-Amz-Scheduler-Error-Code".to_string(),
        string_attr(error_code),
    );
    attrs.insert(
        "X-Amz-Scheduler-Error-Message".to_string(),
        string_attr(error_message),
    );
    attrs.insert(
        "X-Amz-Scheduler-Group".to_string(),
        string_attr(&schedule.group_name),
    );

    let body = schedule.target.input.as_deref().unwrap_or("{}");
    let dedup_id = fifo_dedup_id(&dlq_arn, &schedule.arn);
    // FIFO DLQs need a MessageGroupId; use the schedule name so each
    // schedule's DLQ messages fall in its own ordered stream.
    let group_id = dedup_id.as_ref().map(|_| schedule.name.clone());
    if let Err(err) = bus.try_send_to_sqs_with_attrs(
        &dlq_arn,
        body,
        &attrs,
        group_id.as_deref(),
        dedup_id.as_deref(),
    ) {
        tracing::error!(
            schedule = %schedule.name,
            dlq = %dlq_arn,
            %err,
            "scheduler: DLQ delivery failed — message dropped"
        );
    } else {
        tracing::info!(
            schedule = %schedule.name,
            dlq = %dlq_arn,
            %error_code,
            "scheduler: delivery failed, routed to DLQ"
        );
    }
}

/// Build a dedup ID for FIFO queues. Returns `Some(...)` only when
/// the target queue name ends in `.fifo`; standard queues ignore
/// dedup IDs so we skip the allocation. SQS caps MessageDeduplicationId
/// at 128 chars, so we use a bare UUID (36 chars) rather than
/// concatenating the schedule ARN — schedule ARNs can themselves reach
/// ~150 chars and would push combined IDs over the limit.
fn fifo_dedup_id(queue_arn: &str, _schedule_arn: &str) -> Option<String> {
    if !queue_arn.ends_with(".fifo") {
        return None;
    }
    Some(uuid::Uuid::new_v4().to_string())
}

/// Extract the account-id segment from any AWS ARN. Returns `None` when
/// the ARN is malformed or omits the account (some service ARNs do).
fn account_id_from_arn(arn: &str) -> Option<String> {
    let account = arn.split(':').nth(4)?;
    if account.is_empty() {
        None
    } else {
        Some(account.to_string())
    }
}

/// Extract the EventBridge bus name from a `:events:` target ARN.
/// Two shapes are accepted:
/// - `arn:aws:events:<region>:<account>:event-bus/<name>`
/// - `arn:aws:events:<region>:<account>:bus/<name>` (legacy / alias)
///
/// Returns `"default"` only when the ARN names the default bus or is
/// malformed; never as a silent fallback for a custom bus name.
fn event_bus_name_from_arn(arn: &str) -> String {
    let resource = match arn.split(':').nth(5) {
        Some(r) => r,
        None => return "default".to_string(),
    };
    let name = resource
        .strip_prefix("event-bus/")
        .or_else(|| resource.strip_prefix("bus/"))
        .unwrap_or("default");
    if name.is_empty() {
        "default".to_string()
    } else {
        name.to_string()
    }
}

fn string_attr(v: &str) -> SqsMessageAttribute {
    SqsMessageAttribute {
        data_type: "String".to_string(),
        string_value: Some(v.to_string()),
        binary_value: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{DeadLetterConfig, FlexibleTimeWindow, Schedule, Target};
    use chrono::Utc;
    use std::collections::HashMap;
    use std::sync::Mutex;

    type RecordedCall = (String, String, HashMap<String, SqsMessageAttribute>);

    struct Recorder {
        calls: Mutex<Vec<RecordedCall>>,
        fail_arn: Option<String>,
    }

    impl fakecloud_core::delivery::SqsDelivery for Recorder {
        fn deliver_to_queue(&self, _arn: &str, _body: &str, _attrs: &HashMap<String, String>) {}

        fn try_deliver_to_queue_with_attrs(
            &self,
            queue_arn: &str,
            message_body: &str,
            message_attributes: &HashMap<String, SqsMessageAttribute>,
            _group: Option<&str>,
            _dedup: Option<&str>,
        ) -> Result<(), SqsDeliveryError> {
            if Some(queue_arn.to_string()) == self.fail_arn {
                return Err(SqsDeliveryError::QueueNotFound(queue_arn.to_string()));
            }
            self.calls.lock().unwrap().push((
                queue_arn.to_string(),
                message_body.to_string(),
                message_attributes.clone(),
            ));
            Ok(())
        }
    }

    fn make_schedule(target_arn: &str, dlq: Option<&str>, input: Option<&str>) -> Schedule {
        Schedule {
            arn: "arn:aws:scheduler:us-east-1:1:schedule/default/t".to_string(),
            name: "t".to_string(),
            group_name: "default".to_string(),
            schedule_expression: "rate(1 minute)".to_string(),
            schedule_expression_timezone: None,
            start_date: None,
            end_date: None,
            description: None,
            state: "ENABLED".to_string(),
            kms_key_arn: None,
            action_after_completion: "NONE".to_string(),
            flexible_time_window: FlexibleTimeWindow::default(),
            target: Target {
                arn: target_arn.to_string(),
                role_arn: "arn:aws:iam::1:role/s".to_string(),
                input: input.map(String::from),
                dead_letter_config: dlq.map(|arn| DeadLetterConfig {
                    arn: Some(arn.to_string()),
                }),
                retry_policy: None,
                sqs_parameters: None,
                ecs_parameters: None,
                eventbridge_parameters: None,
                kinesis_parameters: None,
                sagemaker_pipeline_parameters: None,
            },
            creation_date: Utc::now(),
            last_modification_date: Utc::now(),
            last_fired: None,
        }
    }

    #[test]
    fn deliver_target_sqs_success() {
        let recorder = Arc::new(Recorder {
            calls: Mutex::new(Vec::new()),
            fail_arn: None,
        });
        let bus = Arc::new(DeliveryBus::new().with_sqs(recorder.clone()));
        let sched = make_schedule("arn:aws:sqs:us-east-1:1:dest", None, Some(r#"{"v":1}"#));
        let result = deliver_target(&bus, &sched);
        assert!(result.is_ok());
        let calls = recorder.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].1, r#"{"v":1}"#);
    }

    #[test]
    fn deliver_target_kinesis_uses_kinesis_parameters_partition_key() {
        struct KinesisRec(Mutex<Vec<(String, String, String)>>);
        impl fakecloud_core::delivery::KinesisDelivery for KinesisRec {
            fn put_record(&self, stream_arn: &str, data: &str, partition_key: &str) {
                self.0.lock().unwrap().push((
                    stream_arn.to_string(),
                    data.to_string(),
                    partition_key.to_string(),
                ));
            }
        }
        let kinesis = Arc::new(KinesisRec(Mutex::new(Vec::new())));
        let bus = Arc::new(DeliveryBus::new().with_kinesis(kinesis.clone()));
        let mut sched = make_schedule(
            "arn:aws:kinesis:us-east-1:1:stream/orders",
            None,
            Some(r#"{"order":42}"#),
        );
        sched.target.kinesis_parameters = Some(serde_json::json!({"PartitionKey": "tenant-7"}));
        let result = deliver_target(&bus, &sched);
        assert!(result.is_ok());
        let calls = kinesis.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "arn:aws:kinesis:us-east-1:1:stream/orders");
        assert_eq!(calls[0].1, r#"{"order":42}"#);
        assert_eq!(calls[0].2, "tenant-7");
    }

    #[test]
    fn deliver_target_kinesis_falls_back_to_schedule_name_for_partition_key() {
        struct KinesisRec(Mutex<Vec<(String, String, String)>>);
        impl fakecloud_core::delivery::KinesisDelivery for KinesisRec {
            fn put_record(&self, stream_arn: &str, data: &str, partition_key: &str) {
                self.0.lock().unwrap().push((
                    stream_arn.to_string(),
                    data.to_string(),
                    partition_key.to_string(),
                ));
            }
        }
        let kinesis = Arc::new(KinesisRec(Mutex::new(Vec::new())));
        let bus = Arc::new(DeliveryBus::new().with_kinesis(kinesis.clone()));
        let sched = make_schedule(
            "arn:aws:kinesis:us-east-1:1:stream/orders",
            None,
            Some(r#"{"v":1}"#),
        );
        let result = deliver_target(&bus, &sched);
        assert!(result.is_ok());
        let calls = kinesis.0.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].2, "t");
    }

    #[test]
    fn deliver_target_sqs_missing_queue_returns_err() {
        let recorder = Arc::new(Recorder {
            calls: Mutex::new(Vec::new()),
            fail_arn: Some("arn:aws:sqs:us-east-1:1:missing".to_string()),
        });
        let bus = Arc::new(DeliveryBus::new().with_sqs(recorder.clone()));
        let sched = make_schedule("arn:aws:sqs:us-east-1:1:missing", None, None);
        let result = deliver_target(&bus, &sched);
        assert!(matches!(result, Err(SqsDeliveryError::QueueNotFound(_))));
    }

    #[test]
    fn route_to_dlq_includes_metadata_headers() {
        let recorder = Arc::new(Recorder {
            calls: Mutex::new(Vec::new()),
            fail_arn: None,
        });
        let bus = Arc::new(DeliveryBus::new().with_sqs(recorder.clone()));
        let sched = make_schedule(
            "arn:aws:sqs:us-east-1:1:main",
            Some("arn:aws:sqs:us-east-1:1:dlq"),
            Some(r#"{"original":true}"#),
        );
        route_to_dlq(&bus, &sched, "QueueNotFound", "queue missing");
        let calls = recorder.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        let (arn, body, attrs) = &calls[0];
        assert_eq!(arn, "arn:aws:sqs:us-east-1:1:dlq");
        assert_eq!(body, r#"{"original":true}"#);
        assert_eq!(
            attrs
                .get("X-Amz-Scheduler-Attempt")
                .and_then(|a| a.string_value.as_deref()),
            Some("1")
        );
        assert_eq!(
            attrs
                .get("X-Amz-Scheduler-Error-Code")
                .and_then(|a| a.string_value.as_deref()),
            Some("QueueNotFound")
        );
        assert_eq!(
            attrs
                .get("X-Amz-Scheduler-Schedule-Arn")
                .and_then(|a| a.string_value.as_deref()),
            Some("arn:aws:scheduler:us-east-1:1:schedule/default/t")
        );
    }

    #[test]
    fn route_to_dlq_without_config_is_noop() {
        let recorder = Arc::new(Recorder {
            calls: Mutex::new(Vec::new()),
            fail_arn: None,
        });
        let bus = Arc::new(DeliveryBus::new().with_sqs(recorder.clone()));
        let sched = make_schedule("arn:aws:sqs:us-east-1:1:main", None, None);
        route_to_dlq(&bus, &sched, "X", "y");
        assert!(recorder.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn fifo_dedup_id_generated_for_fifo_queue() {
        let id = fifo_dedup_id("arn:aws:sqs:us-east-1:1:q.fifo", "arn:sched/a");
        assert!(id.is_some());
        let s = id.unwrap();
        // SQS caps MessageDeduplicationId at 128 chars.
        assert!(s.len() <= 128);
        // Two fires must not collide.
        let id2 = fifo_dedup_id("arn:aws:sqs:us-east-1:1:q.fifo", "arn:sched/a").unwrap();
        assert_ne!(s, id2);
    }

    #[test]
    fn fifo_dedup_id_stays_under_128_char_limit_for_long_arns() {
        let long_arn = format!(
            "arn:aws:scheduler:us-east-1:123456789012:schedule/{}/{}",
            "g".repeat(64),
            "s".repeat(64)
        );
        let id = fifo_dedup_id("arn:aws:sqs:us-east-1:1:q.fifo", &long_arn).unwrap();
        assert!(id.len() <= 128, "got {} chars", id.len());
    }

    #[test]
    fn fifo_dedup_id_skipped_for_standard_queue() {
        let id = fifo_dedup_id("arn:aws:sqs:us-east-1:1:standard", "arn:sched/a");
        assert!(id.is_none());
    }

    #[test]
    fn event_bus_name_from_arn_custom() {
        assert_eq!(
            event_bus_name_from_arn("arn:aws:events:us-east-1:1:event-bus/my-bus"),
            "my-bus"
        );
    }

    #[test]
    fn event_bus_name_from_arn_default_fallback() {
        assert_eq!(
            event_bus_name_from_arn("arn:aws:events:us-east-1:1:event-bus/default"),
            "default"
        );
        assert_eq!(event_bus_name_from_arn("arn:malformed"), "default");
    }

    #[test]
    fn deliver_target_sqs_cross_account_routes_by_arn_account() {
        // The SQS target points to account 999988887777 even though the
        // schedule lives in account 1. Account-aware SQS routing is the
        // SqsDelivery impl's responsibility — at this layer we just verify
        // the ARN is forwarded unchanged to the bus, so a real impl can
        // route it to the right account's state.
        let recorder = Arc::new(Recorder {
            calls: Mutex::new(Vec::new()),
            fail_arn: None,
        });
        let bus = Arc::new(DeliveryBus::new().with_sqs(recorder.clone()));
        let sched = make_schedule(
            "arn:aws:sqs:us-east-1:999988887777:cross-q",
            None,
            Some(r#"{"v":1}"#),
        );
        assert!(deliver_target(&bus, &sched).is_ok());
        let calls = recorder.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "arn:aws:sqs:us-east-1:999988887777:cross-q");
    }

    #[test]
    fn account_id_from_arn_extracts_account_segment() {
        assert_eq!(
            account_id_from_arn("arn:aws:events:us-east-1:111122223333:event-bus/main"),
            Some("111122223333".to_string())
        );
        assert_eq!(
            account_id_from_arn("arn:aws:events:us-east-1::event-bus/x"),
            None
        );
        assert_eq!(account_id_from_arn("arn:malformed"), None);
    }

    #[test]
    fn deliver_target_unknown_arn_is_ok() {
        let recorder = Arc::new(Recorder {
            calls: Mutex::new(Vec::new()),
            fail_arn: None,
        });
        let bus = Arc::new(DeliveryBus::new().with_sqs(recorder.clone()));
        let sched = make_schedule("arn:aws:ec2:us-east-1:1:instance/foo", None, None);
        assert!(deliver_target(&bus, &sched).is_ok());
        assert!(recorder.calls.lock().unwrap().is_empty());
    }
}
