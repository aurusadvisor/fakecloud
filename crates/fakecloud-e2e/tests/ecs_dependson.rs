//! ECS `containerDefinitions[].dependsOn` ordering. Two scenarios:
//!
//! 1. `START` condition: container B depends on container A reaching
//!    `START`. fakecloud must wait for A to be running (or have already
//!    exited) before launching B. We assert ordering by polling
//!    DescribeTasks: B's lastStatus must never be `RUNNING` while A is
//!    still `PENDING`.
//!
//! 2. Cycle rejection: a `dependsOn[]` graph with a cycle (A -> B,
//!    B -> A) is rejected at RegisterTaskDefinition time with a
//!    ClientException, matching real ECS.

mod helpers;

use std::time::Duration;

use aws_sdk_ecs::types::{ContainerCondition, ContainerDefinition, ContainerDependency};
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

/// Container B (`dependsOn` A with condition=START) must not reach
/// RUNNING before container A. We poll DescribeTasks throughout the
/// task's lifetime and assert B is never observed as RUNNING while A
/// is still PENDING.
#[tokio::test]
async fn ecs_task_depends_on_start_orders_launches() {
    if !require_docker_or_skip("ecs_task_depends_on_start_orders_launches") {
        return;
    }
    let server = TestServer::start().await;
    let ecs = server.ecs_client().await;

    ecs.create_cluster()
        .cluster_name("dep-cluster")
        .send()
        .await
        .unwrap();

    // A: sleeps for 4s so it's still running when B starts. B depends
    // on A reaching START. Without dependsOn ordering, both containers
    // would launch back-to-back with no inter-container wait.
    let dep_b_on_a = ContainerDependency::builder()
        .container_name("a")
        .condition(ContainerCondition::Start)
        .build()
        .expect("dep");

    ecs.register_task_definition()
        .family("dep-family")
        .container_definitions(
            ContainerDefinition::builder()
                .name("a")
                .image("public.ecr.aws/docker/library/alpine:3.20")
                .essential(false)
                .command("sh")
                .command("-c")
                .command("sleep 4")
                .build(),
        )
        .container_definitions(
            ContainerDefinition::builder()
                .name("b")
                .image("public.ecr.aws/docker/library/alpine:3.20")
                .essential(true)
                .command("sh")
                .command("-c")
                .command("sleep 2")
                .depends_on(dep_b_on_a)
                .build(),
        )
        .send()
        .await
        .unwrap();

    let run = ecs
        .run_task()
        .cluster("dep-cluster")
        .task_definition("dep-family")
        .send()
        .await
        .expect("run_task");
    let arn = run.tasks()[0].task_arn().unwrap().to_string();

    // Poll DescribeTasks while the task progresses. We assert the
    // ordering invariant on every observation: B reaching RUNNING while
    // A is still PENDING means dependsOn ordering wasn't honoured.
    let mut both_running_seen = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(60);
    while std::time::Instant::now() < deadline {
        let desc = ecs
            .describe_tasks()
            .cluster("dep-cluster")
            .tasks(&arn)
            .send()
            .await
            .expect("describe_tasks");
        let task = &desc.tasks()[0];
        let a_status = task
            .containers()
            .iter()
            .find(|c| c.name() == Some("a"))
            .and_then(|c| c.last_status())
            .unwrap_or("");
        let b_status = task
            .containers()
            .iter()
            .find(|c| c.name() == Some("b"))
            .and_then(|c| c.last_status())
            .unwrap_or("");
        assert!(
            !(b_status == "RUNNING" && a_status == "PENDING"),
            "B reached RUNNING while A was still PENDING (dependsOn ordering broken)",
        );
        if a_status == "RUNNING" && b_status == "RUNNING" {
            both_running_seen = true;
            break;
        }
        if task.last_status() == Some("STOPPED") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert!(
        both_running_seen,
        "task never had both containers RUNNING simultaneously before deadline (arn={arn})",
    );

    let _ = ecs
        .stop_task()
        .cluster("dep-cluster")
        .task(&arn)
        .reason("e2e-cleanup")
        .send()
        .await;
}

/// A task definition with a cyclic dependsOn graph (A depends on B,
/// B depends on A) must be rejected at RegisterTaskDefinition with a
/// ClientException. Real ECS does this; without the check, the runtime
/// would deadlock at launch waiting on each side of the cycle.
#[tokio::test]
async fn ecs_task_depends_on_cycle_is_rejected() {
    // No docker dependency — this is a register-time validation test.
    let server = TestServer::start().await;
    let ecs = server.ecs_client().await;

    let dep_a_on_b = ContainerDependency::builder()
        .container_name("b")
        .condition(ContainerCondition::Start)
        .build()
        .expect("dep");
    let dep_b_on_a = ContainerDependency::builder()
        .container_name("a")
        .condition(ContainerCondition::Start)
        .build()
        .expect("dep");

    let err = ecs
        .register_task_definition()
        .family("dep-cycle-family")
        .container_definitions(
            ContainerDefinition::builder()
                .name("a")
                .image("public.ecr.aws/docker/library/alpine:3.20")
                .essential(true)
                .depends_on(dep_a_on_b)
                .build(),
        )
        .container_definitions(
            ContainerDefinition::builder()
                .name("b")
                .image("public.ecr.aws/docker/library/alpine:3.20")
                .essential(true)
                .depends_on(dep_b_on_a)
                .build(),
        )
        .send()
        .await
        .expect_err("expected cyclic dependsOn to be rejected");

    let msg = format!("{:?}", err);
    assert!(
        msg.contains("cyclic") || msg.contains("ClientException"),
        "expected cycle error, got: {msg}",
    );
}
