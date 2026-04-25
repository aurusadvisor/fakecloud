//! SQS encrypted queue + KMS hook end-to-end:
//! - SendMessage on a queue with KmsMasterKeyId triggers
//!   `kms:GenerateDataKey` with the queue-arn encryption context
//! - ReceiveMessage decrypts via `kms:Decrypt` and returns the original
//!   plaintext body
//! - Both calls land in `/_fakecloud/kms/usage`

mod helpers;

use helpers::TestServer;

#[tokio::test]
async fn sqs_send_receive_encrypted_round_trips_through_kms() {
    let server = TestServer::start().await;
    let sqs = server.sqs_client().await;
    let http = reqwest::Client::new();

    let queue = sqs
        .create_queue()
        .queue_name("encrypted")
        .attributes(
            aws_sdk_sqs::types::QueueAttributeName::KmsMasterKeyId,
            "alias/aws/sqs",
        )
        .send()
        .await
        .unwrap();
    let queue_url = queue.queue_url().unwrap().to_string();

    sqs.send_message()
        .queue_url(&queue_url)
        .message_body("payload-42")
        .send()
        .await
        .unwrap();

    let got = sqs
        .receive_message()
        .queue_url(&queue_url)
        .max_number_of_messages(1)
        .send()
        .await
        .unwrap();
    let msgs = got.messages();
    assert_eq!(msgs.len(), 1, "expected one message back");
    assert_eq!(
        msgs[0].body(),
        Some("payload-42"),
        "ReceiveMessage must return decrypted plaintext"
    );

    let usage: serde_json::Value = http
        .get(format!("{}/_fakecloud/kms/usage", server.endpoint()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let records = usage["records"].as_array().expect("records array");
    let sqs_records: Vec<&serde_json::Value> = records
        .iter()
        .filter(|r| r["servicePrincipal"].as_str() == Some("sqs.amazonaws.com"))
        .collect();
    assert!(
        sqs_records.iter().any(|r| {
            r["operation"].as_str() == Some("GenerateDataKey")
                && r["encryptionContext"]["aws:sqs:arn"].as_str().is_some()
        }),
        "expected GenerateDataKey bound to queue arn, got: {sqs_records:?}"
    );
    assert!(
        sqs_records.iter().any(|r| {
            r["operation"].as_str() == Some("Decrypt")
                && r["encryptionContext"]["aws:sqs:arn"].as_str().is_some()
        }),
        "expected Decrypt bound to queue arn, got: {sqs_records:?}"
    );
}

#[tokio::test]
async fn sqs_unencrypted_queue_does_not_record_kms_usage() {
    let server = TestServer::start().await;
    let sqs = server.sqs_client().await;
    let http = reqwest::Client::new();

    let queue = sqs.create_queue().queue_name("plain").send().await.unwrap();
    let queue_url = queue.queue_url().unwrap().to_string();
    sqs.send_message()
        .queue_url(&queue_url)
        .message_body("plain")
        .send()
        .await
        .unwrap();

    let usage: serde_json::Value = http
        .get(format!("{}/_fakecloud/kms/usage", server.endpoint()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let records = usage["records"].as_array().expect("records array");
    assert!(
        !records
            .iter()
            .any(|r| r["servicePrincipal"].as_str() == Some("sqs.amazonaws.com")),
        "queue without KmsMasterKeyId must not record KMS usage, got: {records:?}"
    );
}
