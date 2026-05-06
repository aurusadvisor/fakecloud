mod helpers;

use helpers::TestServer;
use serde_json::{json, Value};
use tokio::time::{sleep, Duration};

async fn wait_for_execution(
    client: &aws_sdk_sfn::Client,
    arn: &str,
) -> aws_sdk_sfn::operation::describe_execution::DescribeExecutionOutput {
    for _ in 0..400 {
        sleep(Duration::from_millis(50)).await;
        let desc = client
            .describe_execution()
            .execution_arn(arn)
            .send()
            .await
            .unwrap();
        if desc.status().as_str() != "RUNNING" {
            return desc;
        }
    }
    panic!("Execution did not complete in time: {arn}");
}

#[tokio::test]
async fn sfn_wait_for_task_token_sqs_send_message() {
    let server = TestServer::start().await;
    let sfn = server.sfn_client().await;
    let sqs = server.sqs_client().await;

    // Create a queue to receive the token.
    let queue = sqs
        .create_queue()
        .queue_name("task-token-queue")
        .send()
        .await
        .unwrap();
    let queue_url = queue.queue_url().unwrap();

    let definition = json!({
        "StartAt": "SendToken",
        "States": {
            "SendToken": {
                "Type": "Task",
                "Resource": "arn:aws:states:::sqs:sendMessage.waitForTaskToken",
                "Parameters": {
                    "QueueUrl": queue_url,
                    "MessageBody.$": "$$.Task.Token"
                },
                "End": true
            }
        }
    });

    let created = sfn
        .create_state_machine()
        .name("token-sm")
        .definition(definition.to_string())
        .role_arn("arn:aws:iam::123456789012:role/sfn-role")
        .send()
        .await
        .unwrap();

    let started = sfn
        .start_execution()
        .state_machine_arn(created.state_machine_arn())
        .send()
        .await
        .unwrap();

    // Poll SQS for the message containing the task token.
    let mut token: Option<String> = None;
    for _ in 0..100 {
        let recv = sqs
            .receive_message()
            .queue_url(queue_url)
            .max_number_of_messages(1)
            .send()
            .await
            .unwrap();
        let messages = recv.messages();
        if let Some(m) = messages.first() {
            if let Some(body) = m.body() {
                token = Some(body.to_string());
                // Delete the message so the queue is clean.
                if let Some(receipt) = m.receipt_handle() {
                    let _ = sqs
                        .delete_message()
                        .queue_url(queue_url)
                        .receipt_handle(receipt)
                        .send()
                        .await;
                }
                break;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }

    let token = token.expect("task token should have been sent to SQS");
    assert!(
        token.starts_with("FCToken-"),
        "token should start with FCToken- prefix"
    );

    // Send task success with a custom output.
    let expected_output = json!({"result": "ok"});
    sfn.send_task_success()
        .task_token(&token)
        .output(expected_output.to_string())
        .send()
        .await
        .unwrap();

    let desc = wait_for_execution(&sfn, started.execution_arn()).await;
    assert_eq!(
        desc.status().as_str(),
        "SUCCEEDED",
        "execution should succeed; output={:?}, cause={:?}",
        desc.output(),
        desc.cause(),
    );

    let output: Value = serde_json::from_str(desc.output().expect("output")).unwrap();
    assert_eq!(
        output, expected_output,
        "output should match SendTaskSuccess payload"
    );
}

#[tokio::test]
async fn sfn_wait_for_task_token_send_task_failure() {
    let server = TestServer::start().await;
    let sfn = server.sfn_client().await;
    let sqs = server.sqs_client().await;

    let queue = sqs
        .create_queue()
        .queue_name("token-fail-queue")
        .send()
        .await
        .unwrap();
    let queue_url = queue.queue_url().unwrap();

    let definition = json!({
        "StartAt": "SendToken",
        "States": {
            "SendToken": {
                "Type": "Task",
                "Resource": "arn:aws:states:::sqs:sendMessage.waitForTaskToken",
                "Parameters": {
                    "QueueUrl": queue_url,
                    "MessageBody.$": "$$.Task.Token"
                },
                "End": true
            }
        }
    });

    let created = sfn
        .create_state_machine()
        .name("token-fail-sm")
        .definition(definition.to_string())
        .role_arn("arn:aws:iam::123456789012:role/sfn-role")
        .send()
        .await
        .unwrap();

    let started = sfn
        .start_execution()
        .state_machine_arn(created.state_machine_arn())
        .send()
        .await
        .unwrap();

    let mut token: Option<String> = None;
    for _ in 0..100 {
        let recv = sqs
            .receive_message()
            .queue_url(queue_url)
            .max_number_of_messages(1)
            .send()
            .await
            .unwrap();
        let messages = recv.messages();
        if let Some(m) = messages.first() {
            if let Some(body) = m.body() {
                token = Some(body.to_string());
                if let Some(receipt) = m.receipt_handle() {
                    let _ = sqs
                        .delete_message()
                        .queue_url(queue_url)
                        .receipt_handle(receipt)
                        .send()
                        .await;
                }
                break;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }

    let token = token.expect("task token should have been sent to SQS");

    sfn.send_task_failure()
        .task_token(&token)
        .error("CustomError")
        .cause("worker failed")
        .send()
        .await
        .unwrap();

    let desc = wait_for_execution(&sfn, started.execution_arn()).await;
    assert_eq!(desc.status().as_str(), "FAILED");
    assert_eq!(desc.error(), Some("CustomError"));
    assert_eq!(desc.cause(), Some("worker failed"));
}

#[tokio::test]
async fn sfn_wait_for_task_token_heartbeat_resets_timeout() {
    let server = TestServer::start().await;
    let sfn = server.sfn_client().await;
    let sqs = server.sqs_client().await;

    let queue = sqs
        .create_queue()
        .queue_name("token-hb-queue")
        .send()
        .await
        .unwrap();
    let queue_url = queue.queue_url().unwrap();

    let definition = json!({
        "StartAt": "SendToken",
        "States": {
            "SendToken": {
                "Type": "Task",
                "Resource": "arn:aws:states:::sqs:sendMessage.waitForTaskToken",
                "Parameters": {
                    "QueueUrl": queue_url,
                    "MessageBody.$": "$$.Task.Token"
                },
                "HeartbeatSeconds": 2,
                "End": true
            }
        }
    });

    let created = sfn
        .create_state_machine()
        .name("token-hb-sm")
        .definition(definition.to_string())
        .role_arn("arn:aws:iam::123456789012:role/sfn-role")
        .send()
        .await
        .unwrap();

    let started = sfn
        .start_execution()
        .state_machine_arn(created.state_machine_arn())
        .send()
        .await
        .unwrap();

    let mut token: Option<String> = None;
    for _ in 0..100 {
        let recv = sqs
            .receive_message()
            .queue_url(queue_url)
            .max_number_of_messages(1)
            .send()
            .await
            .unwrap();
        let messages = recv.messages();
        if let Some(m) = messages.first() {
            if let Some(body) = m.body() {
                token = Some(body.to_string());
                if let Some(receipt) = m.receipt_handle() {
                    let _ = sqs
                        .delete_message()
                        .queue_url(queue_url)
                        .receipt_handle(receipt)
                        .send()
                        .await;
                }
                break;
            }
        }
        sleep(Duration::from_millis(50)).await;
    }

    let token = token.expect("task token should have been sent to SQS");

    // Send heartbeat to keep the task alive.
    sfn.send_task_heartbeat()
        .task_token(&token)
        .send()
        .await
        .unwrap();

    sleep(Duration::from_secs(1)).await;

    // Send another heartbeat.
    sfn.send_task_heartbeat()
        .task_token(&token)
        .send()
        .await
        .unwrap();

    // Complete the task.
    sfn.send_task_success()
        .task_token(&token)
        .output(json!({"done": true}).to_string())
        .send()
        .await
        .unwrap();

    let desc = wait_for_execution(&sfn, started.execution_arn()).await;
    assert_eq!(desc.status().as_str(), "SUCCEEDED");
}
