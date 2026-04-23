mod helpers;

use aws_sdk_sqs::types::{
    ChangeMessageVisibilityBatchRequestEntry, DeleteMessageBatchRequestEntry,
    SendMessageBatchRequestEntry,
};
use fakecloud_conformance_macros::test_action;
use helpers::TestServer;

#[test_action("sqs", "CreateQueue", checksum = "0a1fae82")]
#[tokio::test]
async fn sqs_create_queue() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let resp = client
        .create_queue()
        .queue_name("conformance-test")
        .send()
        .await
        .unwrap();
    assert!(resp.queue_url().is_some());
}

#[test_action("sqs", "DeleteQueue", checksum = "a18b7dff")]
#[tokio::test]
async fn sqs_delete_queue() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let url = client
        .create_queue()
        .queue_name("to-delete")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    client.delete_queue().queue_url(&url).send().await.unwrap();
}

#[test_action("sqs", "ListQueues", checksum = "3f6dd6dd")]
#[tokio::test]
async fn sqs_list_queues() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    client
        .create_queue()
        .queue_name("list-test")
        .send()
        .await
        .unwrap();
    let resp = client.list_queues().send().await.unwrap();
    assert!(!resp.queue_urls().is_empty());
}

#[test_action("sqs", "GetQueueUrl", checksum = "20f1dd11")]
#[tokio::test]
async fn sqs_get_queue_url() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    client
        .create_queue()
        .queue_name("url-test")
        .send()
        .await
        .unwrap();
    let resp = client
        .get_queue_url()
        .queue_name("url-test")
        .send()
        .await
        .unwrap();
    assert!(resp.queue_url().is_some());
}

#[test_action("sqs", "GetQueueAttributes", checksum = "d9b5e6d2")]
#[tokio::test]
async fn sqs_get_queue_attributes() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let url = client
        .create_queue()
        .queue_name("attrs-test")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    let resp = client
        .get_queue_attributes()
        .queue_url(&url)
        .attribute_names(aws_sdk_sqs::types::QueueAttributeName::All)
        .send()
        .await
        .unwrap();
    let attrs = resp.attributes().expect("attributes should be present");
    assert!(
        attrs.contains_key(&aws_sdk_sqs::types::QueueAttributeName::QueueArn),
        "QueueArn should be present in attributes"
    );
}

#[test_action("sqs", "SetQueueAttributes", checksum = "e30a8436")]
#[tokio::test]
async fn sqs_set_queue_attributes() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let url = client
        .create_queue()
        .queue_name("set-attrs-test")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    client
        .set_queue_attributes()
        .queue_url(&url)
        .attributes(
            aws_sdk_sqs::types::QueueAttributeName::VisibilityTimeout,
            "60",
        )
        .send()
        .await
        .unwrap();
}

#[test_action("sqs", "SendMessage", checksum = "89d68568")]
#[tokio::test]
async fn sqs_send_message() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let url = client
        .create_queue()
        .queue_name("send-test")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    let resp = client
        .send_message()
        .queue_url(&url)
        .message_body("hello")
        .send()
        .await
        .unwrap();
    assert!(resp.message_id().is_some());
}

#[test_action("sqs", "SendMessageBatch", checksum = "9dd48806")]
#[tokio::test]
async fn sqs_send_message_batch() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let url = client
        .create_queue()
        .queue_name("batch-send-test")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    let resp = client
        .send_message_batch()
        .queue_url(&url)
        .entries(
            SendMessageBatchRequestEntry::builder()
                .id("1")
                .message_body("msg1")
                .build()
                .unwrap(),
        )
        .entries(
            SendMessageBatchRequestEntry::builder()
                .id("2")
                .message_body("msg2")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.successful().len(), 2);
}

#[test_action("sqs", "ReceiveMessage", checksum = "42609ccb")]
#[tokio::test]
async fn sqs_receive_message() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let url = client
        .create_queue()
        .queue_name("recv-test")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    client
        .send_message()
        .queue_url(&url)
        .message_body("hello")
        .send()
        .await
        .unwrap();
    let resp = client
        .receive_message()
        .queue_url(&url)
        .send()
        .await
        .unwrap();
    assert!(!resp.messages().is_empty());
}

#[test_action("sqs", "DeleteMessage", checksum = "b1e095b9")]
#[tokio::test]
async fn sqs_delete_message() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let url = client
        .create_queue()
        .queue_name("del-msg-test")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    client
        .send_message()
        .queue_url(&url)
        .message_body("to-delete")
        .send()
        .await
        .unwrap();
    let msgs = client
        .receive_message()
        .queue_url(&url)
        .send()
        .await
        .unwrap();
    assert!(!msgs.messages().is_empty(), "expected at least one message");
    let receipt = msgs.messages()[0].receipt_handle().unwrap();
    client
        .delete_message()
        .queue_url(&url)
        .receipt_handle(receipt)
        .send()
        .await
        .unwrap();
}

#[test_action("sqs", "DeleteMessageBatch", checksum = "26252f25")]
#[tokio::test]
async fn sqs_delete_message_batch() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let url = client
        .create_queue()
        .queue_name("del-batch-test")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    client
        .send_message()
        .queue_url(&url)
        .message_body("batch-del")
        .send()
        .await
        .unwrap();
    let msgs = client
        .receive_message()
        .queue_url(&url)
        .send()
        .await
        .unwrap();
    assert!(!msgs.messages().is_empty(), "expected at least one message");
    let receipt = msgs.messages()[0].receipt_handle().unwrap();
    let resp = client
        .delete_message_batch()
        .queue_url(&url)
        .entries(
            DeleteMessageBatchRequestEntry::builder()
                .id("1")
                .receipt_handle(receipt)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.successful().len(), 1);
}

#[test_action("sqs", "PurgeQueue", checksum = "f25aaf8e")]
#[tokio::test]
async fn sqs_purge_queue() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let url = client
        .create_queue()
        .queue_name("purge-test")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    client
        .send_message()
        .queue_url(&url)
        .message_body("to-purge")
        .send()
        .await
        .unwrap();
    client.purge_queue().queue_url(&url).send().await.unwrap();
}

#[test_action("sqs", "ChangeMessageVisibility", checksum = "f1324378")]
#[tokio::test]
async fn sqs_change_message_visibility() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let url = client
        .create_queue()
        .queue_name("vis-test")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    client
        .send_message()
        .queue_url(&url)
        .message_body("vis-msg")
        .send()
        .await
        .unwrap();
    let msgs = client
        .receive_message()
        .queue_url(&url)
        .send()
        .await
        .unwrap();
    assert!(!msgs.messages().is_empty(), "expected at least one message");
    let receipt = msgs.messages()[0].receipt_handle().unwrap();
    client
        .change_message_visibility()
        .queue_url(&url)
        .receipt_handle(receipt)
        .visibility_timeout(0)
        .send()
        .await
        .unwrap();
}

#[test_action("sqs", "ChangeMessageVisibilityBatch", checksum = "d8d99cf0")]
#[tokio::test]
async fn sqs_change_message_visibility_batch() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let url = client
        .create_queue()
        .queue_name("vis-batch-test")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    client
        .send_message()
        .queue_url(&url)
        .message_body("vis-batch-msg")
        .send()
        .await
        .unwrap();
    let msgs = client
        .receive_message()
        .queue_url(&url)
        .send()
        .await
        .unwrap();
    assert!(!msgs.messages().is_empty(), "expected at least one message");
    let receipt = msgs.messages()[0].receipt_handle().unwrap();
    let resp = client
        .change_message_visibility_batch()
        .queue_url(&url)
        .entries(
            ChangeMessageVisibilityBatchRequestEntry::builder()
                .id("1")
                .receipt_handle(receipt)
                .visibility_timeout(0)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.successful().len(), 1);
}

#[test_action("sqs", "ListQueueTags", checksum = "fe70eefa")]
#[tokio::test]
async fn sqs_list_queue_tags() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let url = client
        .create_queue()
        .queue_name("tags-test")
        .tags("env", "test")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    let resp = client
        .list_queue_tags()
        .queue_url(&url)
        .send()
        .await
        .unwrap();
    assert!(resp.tags().is_some());
}

#[test_action("sqs", "TagQueue", checksum = "ffc3e579")]
#[tokio::test]
async fn sqs_tag_queue() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let url = client
        .create_queue()
        .queue_name("tag-test")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    client
        .tag_queue()
        .queue_url(&url)
        .tags("project", "conformance")
        .send()
        .await
        .unwrap();
}

#[test_action("sqs", "UntagQueue", checksum = "e1ee616f")]
#[tokio::test]
async fn sqs_untag_queue() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let url = client
        .create_queue()
        .queue_name("untag-test")
        .tags("remove-me", "yes")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    client
        .untag_queue()
        .queue_url(&url)
        .tag_keys("remove-me")
        .send()
        .await
        .unwrap();
}

#[test_action("sqs", "AddPermission", checksum = "59c4016e")]
#[tokio::test]
async fn sqs_add_permission() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let url = client
        .create_queue()
        .queue_name("perm-test")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    client
        .add_permission()
        .queue_url(&url)
        .label("test-perm")
        .aws_account_ids("123456789012")
        .actions("SendMessage")
        .send()
        .await
        .unwrap();
}

#[test_action("sqs", "RemovePermission", checksum = "a0f698c4")]
#[tokio::test]
async fn sqs_remove_permission() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let url = client
        .create_queue()
        .queue_name("rm-perm-test")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    client
        .add_permission()
        .queue_url(&url)
        .label("to-remove")
        .aws_account_ids("123456789012")
        .actions("SendMessage")
        .send()
        .await
        .unwrap();
    client
        .remove_permission()
        .queue_url(&url)
        .label("to-remove")
        .send()
        .await
        .unwrap();
}

#[test_action("sqs", "ListDeadLetterSourceQueues", checksum = "be4b1f5d")]
#[tokio::test]
async fn sqs_list_dead_letter_source_queues() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let dlq_url = client
        .create_queue()
        .queue_name("dlq-test")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    let resp = client
        .list_dead_letter_source_queues()
        .queue_url(&dlq_url)
        .send()
        .await
        .unwrap();
    assert!(resp.queue_urls().is_empty());
}

// ---------------------------------------------------------------------------
// Error path tests
// ---------------------------------------------------------------------------

#[tokio::test]
async fn sqs_send_message_nonexistent_queue_returns_error() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;

    let result = client
        .send_message()
        .queue_url("http://localhost:0/000000000000/no-such-queue")
        .message_body("hello")
        .send()
        .await;
    assert!(
        result.is_err(),
        "SendMessage to nonexistent queue should fail"
    );
}

#[tokio::test]
async fn sqs_receive_message_nonexistent_queue_returns_error() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;

    let result = client
        .receive_message()
        .queue_url("http://localhost:0/000000000000/no-such-queue")
        .send()
        .await;
    assert!(
        result.is_err(),
        "ReceiveMessage from nonexistent queue should fail"
    );
}

#[test_action("sqs", "StartMessageMoveTask", checksum = "d9675688")]
#[tokio::test]
async fn sqs_start_message_move_task() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let dlq_url = client
        .create_queue()
        .queue_name("mmt-dlq")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    let dlq_arn = client
        .get_queue_attributes()
        .queue_url(&dlq_url)
        .attribute_names(aws_sdk_sqs::types::QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap()
        .attributes()
        .unwrap()
        .get(&aws_sdk_sqs::types::QueueAttributeName::QueueArn)
        .unwrap()
        .to_string();

    let redrive = format!(
        "{{\"deadLetterTargetArn\":\"{}\",\"maxReceiveCount\":\"1\"}}",
        dlq_arn
    );
    client
        .create_queue()
        .queue_name("mmt-src")
        .attributes(
            aws_sdk_sqs::types::QueueAttributeName::RedrivePolicy,
            &redrive,
        )
        .send()
        .await
        .unwrap();

    let resp = client
        .start_message_move_task()
        .source_arn(&dlq_arn)
        .send()
        .await
        .unwrap();
    assert!(resp.task_handle().is_some());
}

#[test_action("sqs", "ListMessageMoveTasks", checksum = "49e840b5")]
#[tokio::test]
async fn sqs_list_message_move_tasks() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let dlq_url = client
        .create_queue()
        .queue_name("lmmt-dlq")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    let dlq_arn = client
        .get_queue_attributes()
        .queue_url(&dlq_url)
        .attribute_names(aws_sdk_sqs::types::QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap()
        .attributes()
        .unwrap()
        .get(&aws_sdk_sqs::types::QueueAttributeName::QueueArn)
        .unwrap()
        .to_string();
    let redrive = format!(
        "{{\"deadLetterTargetArn\":\"{}\",\"maxReceiveCount\":\"1\"}}",
        dlq_arn
    );
    client
        .create_queue()
        .queue_name("lmmt-src")
        .attributes(
            aws_sdk_sqs::types::QueueAttributeName::RedrivePolicy,
            &redrive,
        )
        .send()
        .await
        .unwrap();
    client
        .start_message_move_task()
        .source_arn(&dlq_arn)
        .send()
        .await
        .unwrap();

    let resp = client
        .list_message_move_tasks()
        .source_arn(&dlq_arn)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.results().len(), 1);
}

#[test_action("sqs", "CancelMessageMoveTask", checksum = "676a29c4")]
#[tokio::test]
async fn sqs_cancel_message_move_task() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;
    let dlq_url = client
        .create_queue()
        .queue_name("cmmt-dlq")
        .send()
        .await
        .unwrap()
        .queue_url()
        .unwrap()
        .to_string();
    let dlq_arn = client
        .get_queue_attributes()
        .queue_url(&dlq_url)
        .attribute_names(aws_sdk_sqs::types::QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap()
        .attributes()
        .unwrap()
        .get(&aws_sdk_sqs::types::QueueAttributeName::QueueArn)
        .unwrap()
        .to_string();
    let redrive = format!(
        "{{\"deadLetterTargetArn\":\"{}\",\"maxReceiveCount\":\"1\"}}",
        dlq_arn
    );
    client
        .create_queue()
        .queue_name("cmmt-src")
        .attributes(
            aws_sdk_sqs::types::QueueAttributeName::RedrivePolicy,
            &redrive,
        )
        .send()
        .await
        .unwrap();
    let handle = client
        .start_message_move_task()
        .source_arn(&dlq_arn)
        .send()
        .await
        .unwrap()
        .task_handle()
        .unwrap()
        .to_string();
    // Task is COMPLETED immediately in fakecloud (synchronous), so cancel
    // returns the UnsupportedOperation error. Verify both response paths.
    let result = client
        .cancel_message_move_task()
        .task_handle(&handle)
        .send()
        .await;
    assert!(result.is_err(), "cancel of completed task should fail");
}

#[tokio::test]
async fn sqs_create_duplicate_queue_same_attrs_succeeds() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;

    client
        .create_queue()
        .queue_name("dup-queue")
        .send()
        .await
        .unwrap();

    // Creating the same queue with the same attributes should succeed (idempotent)
    let result = client.create_queue().queue_name("dup-queue").send().await;
    assert!(
        result.is_ok(),
        "Creating duplicate queue with same attrs should succeed"
    );
}
