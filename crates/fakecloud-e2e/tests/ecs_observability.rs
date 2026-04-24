//! ECS observability integrations:
//! - `awslogs` driver forwards captured stdout/stderr to CloudWatch Logs
//! - Task state transitions emit `aws.ecs` / "ECS Task State Change"
//!   events on EventBridge, deliverable to the usual rule targets
//!
//! Gated on docker availability the same way the Lambda invoke tests
//! are: required in CI, skipped otherwise so local dev without docker
//! still passes.

mod helpers;

use std::collections::HashMap;
use std::time::Duration;

use aws_sdk_ecs::types::{
    ContainerDefinition, KeyValuePair, LogConfiguration as EcsLogConfig, LogDriver,
};
use aws_sdk_eventbridge::types::{PutEventsRequestEntry, Target};
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
    eprintln!("skipping {test}: docker is not available");
    false
}

async fn wait_for_task_stopped(
    ecs: &aws_sdk_ecs::Client,
    cluster: &str,
    arn: &str,
) -> aws_sdk_ecs::types::Task {
    for _ in 0..120 {
        let desc = ecs
            .describe_tasks()
            .cluster(cluster)
            .tasks(arn)
            .send()
            .await
            .expect("describe_tasks");
        let t = &desc.tasks()[0];
        if t.last_status() == Some("STOPPED") {
            return t.clone();
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("task {arn} never reached STOPPED");
}

fn awslogs_config(group: &str, stream_prefix: &str, region: &str) -> EcsLogConfig {
    let mut options: HashMap<String, String> = HashMap::new();
    options.insert("awslogs-group".into(), group.into());
    options.insert("awslogs-stream-prefix".into(), stream_prefix.into());
    options.insert("awslogs-region".into(), region.into());
    options.insert("awslogs-create-group".into(), "true".into());
    EcsLogConfig::builder()
        .log_driver(LogDriver::Awslogs)
        .set_options(Some(options))
        .build()
        .expect("build log config")
}

/// Task with `awslogs` log driver: captured stdout shows up in the log
/// group/stream that fakecloud-logs exposes via `GetLogEvents`.
#[tokio::test]
async fn ecs_task_awslogs_forwards_to_cloudwatch() {
    if !require_docker_or_skip("ecs_task_awslogs_forwards_to_cloudwatch") {
        return;
    }
    let server = TestServer::start().await;
    let ecs = server.ecs_client().await;
    let logs = server.logs_client().await;

    ecs.create_cluster()
        .cluster_name("awslogs-cluster")
        .send()
        .await
        .unwrap();

    let log_cfg = awslogs_config("/fakecloud/ecs/awslogs-test", "fc", "us-east-1");
    ecs.register_task_definition()
        .family("awslogs-family")
        .container_definitions(
            ContainerDefinition::builder()
                .name("app")
                .image("public.ecr.aws/docker/library/alpine:3.20")
                .essential(true)
                .command("sh")
                .command("-c")
                .command("echo hello-from-awslogs && echo second-line")
                .log_configuration(log_cfg)
                .build(),
        )
        .send()
        .await
        .unwrap();

    let run = ecs
        .run_task()
        .cluster("awslogs-cluster")
        .task_definition("awslogs-family")
        .send()
        .await
        .unwrap();
    let arn = run.tasks()[0].task_arn().unwrap().to_string();
    let _ = wait_for_task_stopped(&ecs, "awslogs-cluster", &arn).await;

    // Introspect what fakecloud-logs received.
    let streams = logs
        .describe_log_streams()
        .log_group_name("/fakecloud/ecs/awslogs-test")
        .send()
        .await
        .expect("describe_log_streams");
    let names: Vec<&str> = streams
        .log_streams()
        .iter()
        .filter_map(|s| s.log_stream_name())
        .collect();
    assert!(
        names.iter().any(|n| n.starts_with("fc/app/")),
        "expected awslogs stream; got {names:?}"
    );
    let stream = names[0];

    let events = logs
        .get_log_events()
        .log_group_name("/fakecloud/ecs/awslogs-test")
        .log_stream_name(stream)
        .send()
        .await
        .expect("get_log_events");
    let messages: Vec<&str> = events.events().iter().filter_map(|e| e.message()).collect();
    assert!(
        messages.iter().any(|m| m.contains("hello-from-awslogs")),
        "expected container stdout in CW Logs; got {messages:?}"
    );
}

/// Task state transitions fire `ECS Task State Change` events on the
/// default EventBridge bus. An SQS rule target receives the events, and
/// we assert that the task's RUNNING -> STOPPED transitions show up.
#[tokio::test]
async fn ecs_task_state_change_emits_eventbridge() {
    if !require_docker_or_skip("ecs_task_state_change_emits_eventbridge") {
        return;
    }
    let server = TestServer::start().await;
    let ecs = server.ecs_client().await;
    let eb = server.eventbridge_client().await;
    let sqs = server.sqs_client().await;

    let q = sqs
        .create_queue()
        .queue_name("ecs-state-change-target")
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
        .name("ecs-state-change")
        .event_pattern(
            serde_json::json!({
                "source": ["aws.ecs"],
                "detail-type": ["ECS Task State Change"]
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    eb.put_targets()
        .rule("ecs-state-change")
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

    // Sanity-check the wiring by putting one event directly on the bus.
    eb.put_events()
        .entries(
            PutEventsRequestEntry::builder()
                .source("aws.ecs")
                .detail_type("ECS Task State Change")
                .detail(r#"{"test": "sanity"}"#)
                .build(),
        )
        .send()
        .await
        .unwrap();

    ecs.create_cluster()
        .cluster_name("eb-cluster")
        .send()
        .await
        .unwrap();
    ecs.register_task_definition()
        .family("eb-family")
        .container_definitions(
            ContainerDefinition::builder()
                .name("app")
                .image("public.ecr.aws/docker/library/alpine:3.20")
                .essential(true)
                .command("sh")
                .command("-c")
                .command("exit 0")
                .environment(
                    KeyValuePair::builder()
                        .name("T")
                        .value("state-change")
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();

    let run = ecs
        .run_task()
        .cluster("eb-cluster")
        .task_definition("eb-family")
        .send()
        .await
        .unwrap();
    let arn = run.tasks()[0].task_arn().unwrap().to_string();
    let _ = wait_for_task_stopped(&ecs, "eb-cluster", &arn).await;

    // Poll the SQS queue for messages — sanity entry + at least one task
    // state-change event with lastStatus=STOPPED for our task.
    let mut saw_stopped_for_task = false;
    for _ in 0..30 {
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
            // EventBridge delivery wraps the detail in the event envelope.
            let detail = ev.get("detail").cloned().unwrap_or(ev.clone());
            let matches_task = detail
                .get("taskArn")
                .and_then(|v| v.as_str())
                .map(|s| s == arn)
                .unwrap_or(false);
            let stopped = detail
                .get("lastStatus")
                .and_then(|v| v.as_str())
                .map(|s| s == "STOPPED")
                .unwrap_or(false);
            if matches_task && stopped {
                saw_stopped_for_task = true;
                break;
            }
        }
        if saw_stopped_for_task {
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        saw_stopped_for_task,
        "expected an ECS Task State Change STOPPED event for our task on SQS"
    );
}
