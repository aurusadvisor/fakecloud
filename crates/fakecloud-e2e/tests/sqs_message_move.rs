mod helpers;

use std::collections::HashMap;
use std::time::Duration;

use aws_sdk_sqs::types::QueueAttributeName;
use helpers::TestServer;

async fn create_dlq_pair(client: &aws_sdk_sqs::Client, name_prefix: &str) -> (String, String) {
    let dlq = client
        .create_queue()
        .queue_name(format!("{name_prefix}-dlq"))
        .send()
        .await
        .unwrap();
    let dlq_url = dlq.queue_url().unwrap().to_string();

    let attrs = client
        .get_queue_attributes()
        .queue_url(&dlq_url)
        .attribute_names(QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap();
    let dlq_arn = attrs
        .attributes()
        .and_then(|m| m.get(&QueueAttributeName::QueueArn))
        .unwrap()
        .to_string();

    let mut redrive = HashMap::new();
    redrive.insert(
        QueueAttributeName::RedrivePolicy,
        format!("{{\"deadLetterTargetArn\":\"{dlq_arn}\",\"maxReceiveCount\":\"3\"}}",),
    );
    let src = client
        .create_queue()
        .queue_name(format!("{name_prefix}-src"))
        .set_attributes(Some(redrive))
        .send()
        .await
        .unwrap();
    let src_url = src.queue_url().unwrap().to_string();

    (dlq_url, src_url)
}

#[tokio::test]
async fn rate_limited_move_progresses_and_completes() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;

    let (dlq_url, src_url) = create_dlq_pair(&client, "ratelimit").await;

    // Seed DLQ with 5 messages
    for i in 0..5 {
        client
            .send_message()
            .queue_url(&dlq_url)
            .message_body(format!("msg-{i}"))
            .send()
            .await
            .unwrap();
    }

    let dlq_arn = client
        .get_queue_attributes()
        .queue_url(&dlq_url)
        .attribute_names(QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap()
        .attributes()
        .and_then(|m| m.get(&QueueAttributeName::QueueArn))
        .unwrap()
        .to_string();

    let src_arn = client
        .get_queue_attributes()
        .queue_url(&src_url)
        .attribute_names(QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap()
        .attributes()
        .and_then(|m| m.get(&QueueAttributeName::QueueArn))
        .unwrap()
        .to_string();

    // 50/sec rate -> 5 messages drain in ~100ms but task is observable as Running first.
    let resp = client
        .start_message_move_task()
        .source_arn(&dlq_arn)
        .destination_arn(&src_arn)
        .max_number_of_messages_per_second(50)
        .send()
        .await
        .unwrap();
    assert!(resp.task_handle().is_some());

    // Wait until completion (poll up to 5s)
    let mut final_status = None;
    for _ in 0..50 {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let list = client
            .list_message_move_tasks()
            .source_arn(&dlq_arn)
            .max_results(10)
            .send()
            .await
            .unwrap();
        let tasks = list.results();
        if let Some(t) = tasks.first() {
            let status = t.status().unwrap().to_string();
            if status == "COMPLETED" {
                final_status = Some(status);
                break;
            }
        }
    }
    assert_eq!(final_status.as_deref(), Some("COMPLETED"));

    // Source DLQ drained
    let attrs = client
        .get_queue_attributes()
        .queue_url(&dlq_url)
        .attribute_names(QueueAttributeName::ApproximateNumberOfMessages)
        .send()
        .await
        .unwrap();
    let dlq_count: i32 = attrs
        .attributes()
        .and_then(|m| m.get(&QueueAttributeName::ApproximateNumberOfMessages))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(dlq_count, 0);

    // Destination has messages
    let attrs = client
        .get_queue_attributes()
        .queue_url(&src_url)
        .attribute_names(QueueAttributeName::ApproximateNumberOfMessages)
        .send()
        .await
        .unwrap();
    let src_count: i32 = attrs
        .attributes()
        .and_then(|m| m.get(&QueueAttributeName::ApproximateNumberOfMessages))
        .unwrap()
        .parse()
        .unwrap();
    assert_eq!(src_count, 5);
}

#[tokio::test]
async fn cancel_message_move_task_stops_in_flight_mover() {
    let server = TestServer::start().await;
    let client = server.sqs_client().await;

    let (dlq_url, src_url) = create_dlq_pair(&client, "cancel").await;

    // Seed DLQ with 100 messages
    for i in 0..100 {
        client
            .send_message()
            .queue_url(&dlq_url)
            .message_body(format!("msg-{i}"))
            .send()
            .await
            .unwrap();
    }

    let dlq_arn = client
        .get_queue_attributes()
        .queue_url(&dlq_url)
        .attribute_names(QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap()
        .attributes()
        .and_then(|m| m.get(&QueueAttributeName::QueueArn))
        .unwrap()
        .to_string();

    let src_arn = client
        .get_queue_attributes()
        .queue_url(&src_url)
        .attribute_names(QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap()
        .attributes()
        .and_then(|m| m.get(&QueueAttributeName::QueueArn))
        .unwrap()
        .to_string();

    // Slow rate (5/sec) so cancellation lands mid-flight.
    let resp = client
        .start_message_move_task()
        .source_arn(&dlq_arn)
        .destination_arn(&src_arn)
        .max_number_of_messages_per_second(5)
        .send()
        .await
        .unwrap();
    let handle = resp.task_handle().unwrap().to_string();

    // Wait briefly to let some moves happen.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let cancel = client
        .cancel_message_move_task()
        .task_handle(&handle)
        .send()
        .await
        .unwrap();
    assert!(cancel.approximate_number_of_messages_moved() > 0);

    // Wait briefly for mover to observe cancel and exit.
    tokio::time::sleep(Duration::from_millis(500)).await;

    let list = client
        .list_message_move_tasks()
        .source_arn(&dlq_arn)
        .max_results(10)
        .send()
        .await
        .unwrap();
    let task = list.results().first().unwrap();
    let status = task.status().unwrap().to_string();
    assert!(
        status == "CANCELLED" || status == "CANCELLING",
        "expected CANCELLED/CANCELLING, got {status}"
    );

    // DLQ still has messages (we didn't drain them all)
    let attrs = client
        .get_queue_attributes()
        .queue_url(&dlq_url)
        .attribute_names(QueueAttributeName::ApproximateNumberOfMessages)
        .send()
        .await
        .unwrap();
    let remaining: i32 = attrs
        .attributes()
        .and_then(|m| m.get(&QueueAttributeName::ApproximateNumberOfMessages))
        .unwrap()
        .parse()
        .unwrap();
    assert!(remaining > 0, "expected leftover messages in DLQ");
}
