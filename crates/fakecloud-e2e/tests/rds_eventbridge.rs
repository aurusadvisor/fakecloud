//! RDS lifecycle ops emit `aws.rds` events on the default EventBridge
//! bus, deliverable to rule targets. Start/StopDBInstance take the no-
//! runtime path so the test runs on every CI shard.

mod helpers;

use aws_sdk_eventbridge::types::Target;
use aws_sdk_sqs::types::QueueAttributeName;
use helpers::TestServer;

#[tokio::test]
async fn rds_start_db_instance_emits_eventbridge_event() {
    let server = TestServer::start().await;
    let rds = server.rds_client().await;
    let eb = server.eventbridge_client().await;
    let sqs = server.sqs_client().await;

    let q = sqs
        .create_queue()
        .queue_name("rds-events-target")
        .send()
        .await
        .unwrap();
    let queue_url = q.queue_url().unwrap().to_string();
    let q_attrs = sqs
        .get_queue_attributes()
        .queue_url(&queue_url)
        .attribute_names(QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap();
    let queue_arn = q_attrs
        .attributes()
        .unwrap()
        .get(&QueueAttributeName::QueueArn)
        .unwrap()
        .to_string();

    eb.put_rule()
        .name("rds-instance-events")
        .event_pattern(
            serde_json::json!({
                "source": ["aws.rds"],
                "detail-type": ["RDS DB Instance Event"]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    eb.put_targets()
        .rule("rds-instance-events")
        .targets(
            Target::builder()
                .id("sqs-target")
                .arn(&queue_arn)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    rds.start_db_instance()
        .db_instance_identifier("my-db")
        .send()
        .await
        .unwrap();

    let mut saw_start = false;
    for _ in 0..20 {
        let recv = sqs
            .receive_message()
            .queue_url(&queue_url)
            .max_number_of_messages(10)
            .wait_time_seconds(1)
            .send()
            .await
            .unwrap();
        for m in recv.messages() {
            let Some(body) = m.body() else { continue };
            let Ok(ev) = serde_json::from_str::<serde_json::Value>(body) else {
                continue;
            };
            if ev.get("source").and_then(|v| v.as_str()) != Some("aws.rds") {
                continue;
            }
            let detail = ev.get("detail").cloned().unwrap_or(ev.clone());
            if detail.get("EventID").and_then(|v| v.as_str()) == Some("RDS-EVENT-0088")
                && detail.get("SourceIdentifier").and_then(|v| v.as_str()) == Some("my-db")
                && detail.get("SourceType").and_then(|v| v.as_str()) == Some("DB_INSTANCE")
            {
                saw_start = true;
            }
        }
        if saw_start {
            break;
        }
    }
    assert!(
        saw_start,
        "expected RDS-EVENT-0088 aws.rds event for my-db on SQS target"
    );
}

#[tokio::test]
async fn rds_stop_db_instance_emits_eventbridge_event() {
    let server = TestServer::start().await;
    let rds = server.rds_client().await;
    let eb = server.eventbridge_client().await;
    let sqs = server.sqs_client().await;

    let q = sqs
        .create_queue()
        .queue_name("rds-stop-events-target")
        .send()
        .await
        .unwrap();
    let queue_url = q.queue_url().unwrap().to_string();
    let q_attrs = sqs
        .get_queue_attributes()
        .queue_url(&queue_url)
        .attribute_names(QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap();
    let queue_arn = q_attrs
        .attributes()
        .unwrap()
        .get(&QueueAttributeName::QueueArn)
        .unwrap()
        .to_string();

    eb.put_rule()
        .name("rds-stop-events")
        .event_pattern(serde_json::json!({"source": ["aws.rds"]}).to_string())
        .send()
        .await
        .unwrap();
    eb.put_targets()
        .rule("rds-stop-events")
        .targets(
            Target::builder()
                .id("sqs-target")
                .arn(&queue_arn)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    rds.stop_db_instance()
        .db_instance_identifier("prod-db")
        .send()
        .await
        .unwrap();

    let mut saw_stop = false;
    for _ in 0..20 {
        let recv = sqs
            .receive_message()
            .queue_url(&queue_url)
            .max_number_of_messages(10)
            .wait_time_seconds(1)
            .send()
            .await
            .unwrap();
        for m in recv.messages() {
            let Some(body) = m.body() else { continue };
            let Ok(ev) = serde_json::from_str::<serde_json::Value>(body) else {
                continue;
            };
            let detail = ev.get("detail").cloned().unwrap_or(ev.clone());
            if detail.get("EventID").and_then(|v| v.as_str()) == Some("RDS-EVENT-0089")
                && detail.get("SourceIdentifier").and_then(|v| v.as_str()) == Some("prod-db")
            {
                saw_stop = true;
            }
        }
        if saw_stop {
            break;
        }
    }
    assert!(saw_stop, "expected RDS-EVENT-0089 event for prod-db");
}

#[tokio::test]
async fn rds_event_delivers_to_sns_target() {
    let server = TestServer::start().await;
    let rds = server.rds_client().await;
    let eb = server.eventbridge_client().await;
    let sns = server.sns_client().await;
    let sqs = server.sqs_client().await;

    let topic = sns
        .create_topic()
        .name("rds-events-topic")
        .send()
        .await
        .unwrap();
    let topic_arn = topic.topic_arn().unwrap().to_string();

    // Subscribe an SQS queue to the topic so we can assert on delivery.
    let q = sqs
        .create_queue()
        .queue_name("rds-events-via-sns")
        .send()
        .await
        .unwrap();
    let queue_url = q.queue_url().unwrap().to_string();
    let q_attrs = sqs
        .get_queue_attributes()
        .queue_url(&queue_url)
        .attribute_names(QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap();
    let queue_arn = q_attrs
        .attributes()
        .unwrap()
        .get(&QueueAttributeName::QueueArn)
        .unwrap()
        .to_string();
    sns.subscribe()
        .topic_arn(&topic_arn)
        .protocol("sqs")
        .endpoint(&queue_arn)
        .send()
        .await
        .unwrap();

    eb.put_rule()
        .name("rds-events-sns")
        .event_pattern(serde_json::json!({"source": ["aws.rds"]}).to_string())
        .send()
        .await
        .unwrap();
    eb.put_targets()
        .rule("rds-events-sns")
        .targets(
            Target::builder()
                .id("sns-target")
                .arn(&topic_arn)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    rds.start_db_instance()
        .db_instance_identifier("sns-db")
        .send()
        .await
        .unwrap();

    let mut saw = false;
    for _ in 0..20 {
        let recv = sqs
            .receive_message()
            .queue_url(&queue_url)
            .max_number_of_messages(10)
            .wait_time_seconds(1)
            .send()
            .await
            .unwrap();
        for m in recv.messages() {
            let Some(body) = m.body() else { continue };
            // SNS wraps deliveries: {Type:"Notification", Message: "<original-event-json>"}
            let env: serde_json::Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let inner_str = env.get("Message").and_then(|v| v.as_str()).unwrap_or("");
            let inner: serde_json::Value =
                serde_json::from_str(inner_str).unwrap_or(serde_json::Value::Null);
            let detail = inner.get("detail").cloned().unwrap_or(inner.clone());
            if detail.get("EventID").and_then(|v| v.as_str()) == Some("RDS-EVENT-0088")
                && detail.get("SourceIdentifier").and_then(|v| v.as_str()) == Some("sns-db")
            {
                saw = true;
            }
        }
        if saw {
            break;
        }
    }
    assert!(saw, "expected RDS event delivered through SNS target");
}
