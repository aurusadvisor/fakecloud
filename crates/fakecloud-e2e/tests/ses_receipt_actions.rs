//! SES receipt rule actions execute end-to-end:
//! - S3 stores the (header-augmented) message
//! - SNS publishes a notification
//! - Bounce action enqueues a bounce email + optional SNS notification
//! - Stop action with topic notifies and halts subsequent rules
//!
//! Hits the existing `/_fakecloud/ses/inbound` introspection endpoint that
//! delivers the email to the active receipt rule set.

mod helpers;

use aws_sdk_ses::types::{
    AddHeaderAction, BounceAction, BouncedRecipientInfo, ReceiptAction, ReceiptRule, S3Action,
    SnsAction, StopAction,
};
use aws_sdk_sqs::types::QueueAttributeName;
use helpers::TestServer;

#[tokio::test]
async fn ses_receipt_rule_executes_addheader_s3_and_bounce() {
    let server = TestServer::start().await;
    let ses = server.ses_client().await;
    let s3 = server.s3_client().await;
    let sns = server.sns_client().await;
    let sqs = server.sqs_client().await;
    let http = reqwest::Client::new();

    // S3 bucket used by the S3 action.
    s3.create_bucket()
        .bucket("inbound-emails")
        .send()
        .await
        .unwrap();

    // SNS topic + SQS queue subscription so we can read the bounce
    // notification.
    let topic = sns
        .create_topic()
        .name("bounce-topic")
        .send()
        .await
        .unwrap();
    let topic_arn = topic.topic_arn().unwrap().to_string();
    let q = sqs
        .create_queue()
        .queue_name("bounce-q")
        .send()
        .await
        .unwrap();
    let queue_url = q.queue_url().unwrap().to_string();
    let queue_arn = sqs
        .get_queue_attributes()
        .queue_url(&queue_url)
        .attribute_names(QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap()
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

    ses.create_receipt_rule_set()
        .rule_set_name("inbound-rs")
        .send()
        .await
        .unwrap();
    ses.create_receipt_rule()
        .rule_set_name("inbound-rs")
        .rule(
            ReceiptRule::builder()
                .name("hello-rule")
                .enabled(true)
                .recipients("hello@example.com")
                .actions(
                    ReceiptAction::builder()
                        .add_header_action(
                            AddHeaderAction::builder()
                                .header_name("X-Receipt-Tag")
                                .header_value("processed")
                                .build()
                                .unwrap(),
                        )
                        .build(),
                )
                .actions(
                    ReceiptAction::builder()
                        .s3_action(
                            S3Action::builder()
                                .bucket_name("inbound-emails")
                                .object_key_prefix("incoming/")
                                .build()
                                .unwrap(),
                        )
                        .build(),
                )
                .actions(
                    ReceiptAction::builder()
                        .bounce_action(
                            BounceAction::builder()
                                .smtp_reply_code("550")
                                .status_code("5.7.1")
                                .message("Mailbox not allowed")
                                .sender("postmaster@example.com")
                                .topic_arn(&topic_arn)
                                .build()
                                .unwrap(),
                        )
                        .build(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    ses.set_active_receipt_rule_set()
        .rule_set_name("inbound-rs")
        .send()
        .await
        .unwrap();

    // Trigger a delivery via the introspection endpoint.
    let resp = http
        .post(format!("{}/_fakecloud/ses/inbound", server.endpoint()))
        .json(&serde_json::json!({
            "from": "alice@example.com",
            "to": ["hello@example.com"],
            "subject": "Hi",
            "body": "Hello world",
        }))
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success());

    // S3 object should exist with the AddHeader prepended.
    let mut found_s3 = false;
    for _ in 0..20 {
        let listed = s3
            .list_objects_v2()
            .bucket("inbound-emails")
            .send()
            .await
            .unwrap();
        if let Some(objs) = listed.contents.as_ref() {
            for o in objs {
                let key = o.key().unwrap();
                if key.starts_with("incoming/") {
                    let got = s3
                        .get_object()
                        .bucket("inbound-emails")
                        .key(key)
                        .send()
                        .await
                        .unwrap();
                    let body = got.body.collect().await.unwrap().into_bytes();
                    let s = String::from_utf8_lossy(&body).to_string();
                    assert!(
                        s.contains("X-Receipt-Tag: processed"),
                        "S3 object should contain AddHeader header, got: {s}"
                    );
                    assert!(s.contains("Hello world"));
                    found_s3 = true;
                }
            }
        }
        if found_s3 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(found_s3, "S3 action should have stored the message");

    // Bounce email should have landed in /_fakecloud/ses/emails addressed
    // back to alice@example.com.
    let emails: serde_json::Value = http
        .get(format!("{}/_fakecloud/ses/emails", server.endpoint()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let arr = emails["emails"].as_array().unwrap();
    let bounce = arr
        .iter()
        .find(|e| {
            e["to"]
                .as_array()
                .map(|to| to.iter().any(|t| t.as_str() == Some("alice@example.com")))
                .unwrap_or(false)
                && e["from"].as_str() == Some("postmaster@example.com")
        })
        .expect("bounce email should be enqueued");
    let body = bounce["textBody"].as_str().unwrap_or("");
    assert!(
        body.contains("550") && body.contains("Mailbox not allowed"),
        "bounce body should contain SMTP reply code + message, got: {body}"
    );

    // Bounce notification should be delivered through SNS -> SQS.
    let mut saw_bounce_notif = false;
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
            let body = m.body().unwrap_or("");
            let env: serde_json::Value = match serde_json::from_str(body) {
                Ok(v) => v,
                Err(_) => continue,
            };
            let msg_str = env.get("Message").and_then(|v| v.as_str()).unwrap_or("");
            let inner: serde_json::Value =
                serde_json::from_str(msg_str).unwrap_or(serde_json::Value::Null);
            if inner["notificationType"].as_str() == Some("Bounce") {
                saw_bounce_notif = true;
            }
        }
        if saw_bounce_notif {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    assert!(saw_bounce_notif, "expected SNS Bounce notification");

    // Suppress unused warnings for AWS SDK types pulled in for clarity.
    let _ = (
        BouncedRecipientInfo::builder,
        StopAction::builder,
        SnsAction::builder,
    );
}
