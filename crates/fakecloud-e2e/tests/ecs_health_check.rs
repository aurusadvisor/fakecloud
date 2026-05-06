//! ECS container `healthCheck` translates into docker `--health-*`
//! flags so `docker inspect .State.Health.Status` reflects the probe
//! result. fakecloud polls that status while the task runs and surfaces
//! the mapped value (`HEALTHY|UNHEALTHY|UNKNOWN`) on DescribeTasks.
//!
//! Gated on docker availability the same way other ECS-runtime tests
//! are: required in CI, skipped otherwise.

mod helpers;

use std::time::Duration;

use aws_sdk_ecs::types::{ContainerDefinition, HealthCheck};
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

/// A long-running container with a healthCheck that always succeeds
/// (`CMD-SHELL true`) should report `healthStatus=HEALTHY` on DescribeTasks
/// once docker has run the probe at least once.
#[tokio::test]
async fn ecs_task_health_check_reports_healthy() {
    if !require_docker_or_skip("ecs_task_health_check_reports_healthy") {
        return;
    }
    let server = TestServer::start().await;
    let ecs = server.ecs_client().await;

    ecs.create_cluster()
        .cluster_name("hc-cluster")
        .send()
        .await
        .unwrap();

    // sleep keeps the container alive long enough for the probe to land
    // before the task exits. interval=1s + retries=1 means docker should
    // produce a healthy verdict within ~2-3s of the container starting.
    let hc = HealthCheck::builder()
        .command("CMD-SHELL")
        .command("true")
        .interval(1)
        .timeout(2)
        .retries(1)
        .start_period(0)
        .build()
        .expect("build healthcheck");

    ecs.register_task_definition()
        .family("hc-family")
        .container_definitions(
            ContainerDefinition::builder()
                .name("app")
                .image("public.ecr.aws/docker/library/alpine:3.20")
                .essential(true)
                .command("sh")
                .command("-c")
                .command("sleep 20")
                .health_check(hc)
                .build(),
        )
        .send()
        .await
        .unwrap();

    let run = ecs
        .run_task()
        .cluster("hc-cluster")
        .task_definition("hc-family")
        .send()
        .await
        .expect("run_task");
    let arn = run.tasks()[0].task_arn().unwrap().to_string();

    // Poll DescribeTasks until the container's healthStatus is HEALTHY
    // or we hit a generous deadline. Real docker can take a few seconds
    // to run the first probe + report a transition out of `starting`.
    let mut got_healthy = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    while std::time::Instant::now() < deadline {
        let desc = ecs
            .describe_tasks()
            .cluster("hc-cluster")
            .tasks(&arn)
            .send()
            .await
            .expect("describe_tasks");
        let task = &desc.tasks()[0];
        let container_health = task
            .containers()
            .iter()
            .find(|c| c.name() == Some("app"))
            .and_then(|c| c.health_status())
            .map(|s| s.as_str().to_string());
        if container_health.as_deref() == Some("HEALTHY") {
            // Task-level healthStatus should aggregate to HEALTHY too
            // since the only essential container is healthy.
            assert_eq!(
                task.health_status().map(|s| s.as_str()),
                Some("HEALTHY"),
                "task healthStatus should aggregate to HEALTHY",
            );
            got_healthy = true;
            break;
        }
        if task.last_status() == Some("STOPPED") {
            panic!(
                "task stopped before reporting HEALTHY (last container_health={:?})",
                container_health
            );
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        got_healthy,
        "task never reported HEALTHY before deadline (arn={arn})",
    );

    // Tidy: stop the task so the suite doesn't leave a sleeper running.
    let _ = ecs
        .stop_task()
        .cluster("hc-cluster")
        .task(&arn)
        .reason("e2e-cleanup")
        .send()
        .await;
}

/// A container whose probe always fails (`CMD-SHELL false`) should
/// transition to `healthStatus=UNHEALTHY` once docker has retried the
/// probe enough times. We don't assert task-level lifecycle (ECS would
/// kill an unhealthy essential container, but that's a separate
/// behaviour from health surfacing).
#[tokio::test]
async fn ecs_task_health_check_reports_unhealthy() {
    if !require_docker_or_skip("ecs_task_health_check_reports_unhealthy") {
        return;
    }
    let server = TestServer::start().await;
    let ecs = server.ecs_client().await;

    ecs.create_cluster()
        .cluster_name("hc-unhealthy-cluster")
        .send()
        .await
        .unwrap();

    let hc = HealthCheck::builder()
        .command("CMD-SHELL")
        .command("false")
        .interval(1)
        .timeout(1)
        .retries(1)
        .start_period(0)
        .build()
        .expect("build healthcheck");

    ecs.register_task_definition()
        .family("hc-unhealthy-family")
        .container_definitions(
            ContainerDefinition::builder()
                .name("app")
                .image("public.ecr.aws/docker/library/alpine:3.20")
                .essential(true)
                .command("sh")
                .command("-c")
                .command("sleep 30")
                .health_check(hc)
                .build(),
        )
        .send()
        .await
        .unwrap();

    let run = ecs
        .run_task()
        .cluster("hc-unhealthy-cluster")
        .task_definition("hc-unhealthy-family")
        .send()
        .await
        .expect("run_task");
    let arn = run.tasks()[0].task_arn().unwrap().to_string();

    let mut got_unhealthy = false;
    let deadline = std::time::Instant::now() + Duration::from_secs(45);
    while std::time::Instant::now() < deadline {
        let desc = ecs
            .describe_tasks()
            .cluster("hc-unhealthy-cluster")
            .tasks(&arn)
            .send()
            .await
            .expect("describe_tasks");
        let task = &desc.tasks()[0];
        let container_health = task
            .containers()
            .iter()
            .find(|c| c.name() == Some("app"))
            .and_then(|c| c.health_status())
            .map(|s| s.as_str().to_string());
        if container_health.as_deref() == Some("UNHEALTHY") {
            assert_eq!(
                task.health_status().map(|s| s.as_str()),
                Some("UNHEALTHY"),
                "task healthStatus should aggregate to UNHEALTHY",
            );
            got_unhealthy = true;
            break;
        }
        if task.last_status() == Some("STOPPED") {
            // The container may have been killed externally; bail.
            break;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    assert!(
        got_unhealthy,
        "task never reported UNHEALTHY before deadline (arn={arn})",
    );

    let _ = ecs
        .stop_task()
        .cluster("hc-unhealthy-cluster")
        .task(&arn)
        .reason("e2e-cleanup")
        .send()
        .await;
}
