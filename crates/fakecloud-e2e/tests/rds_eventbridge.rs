//! RDS lifecycle ops emit `aws.rds` events on the default EventBridge
//! bus, deliverable to rule targets. Start/StopDBInstance now drive
//! real container lifecycle (see #1338) so these tests need Docker to
//! create the instance before toggling it.

mod helpers;

use aws_sdk_eventbridge::types::Target;
use aws_sdk_sqs::types::QueueAttributeName;
use helpers::TestServer;

fn docker_available() -> bool {
    std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn require_docker_or_skip(test: &str) -> bool {
    if docker_available() {
        return true;
    }
    if std::env::var("CI").is_ok() {
        panic!("docker is required for {test} in CI");
    }
    eprintln!("Skipping {test}: docker not available");
    false
}

async fn create_running_db(rds: &aws_sdk_rds::Client, id: &str) {
    rds.create_db_instance()
        .db_instance_identifier(id)
        .allocated_storage(20)
        .db_instance_class("db.t3.micro")
        .engine("postgres")
        .engine_version("16.3")
        .master_username("admin")
        .master_user_password("secret123")
        .db_name("appdb")
        .send()
        .await
        .unwrap();
    let _ = helpers::wait_for_db_available(rds, id, 240).await;
}

#[tokio::test]
async fn rds_start_db_instance_emits_eventbridge_event() {
    if !require_docker_or_skip("rds_start_db_instance_emits_eventbridge_event") {
        return;
    }
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

    create_running_db(&rds, "my-db").await;
    rds.stop_db_instance()
        .db_instance_identifier("my-db")
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
    if !require_docker_or_skip("rds_stop_db_instance_emits_eventbridge_event") {
        return;
    }
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

    create_running_db(&rds, "prod-db").await;
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
    if !require_docker_or_skip("rds_event_delivers_to_sns_target") {
        return;
    }
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

    create_running_db(&rds, "sns-db").await;
    rds.stop_db_instance()
        .db_instance_identifier("sns-db")
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
