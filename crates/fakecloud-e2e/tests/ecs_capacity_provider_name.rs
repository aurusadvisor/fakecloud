//! Verify Task.capacityProviderName surfaces in DescribeTasks when the
//! task was launched via a capacity-provider strategy. AWS exposes the
//! resolved capacity provider on the task itself; SDK clients (CDK,
//! terraform) match on this field to assert tasks ended up where
//! intended.

mod helpers;

use aws_sdk_ecs::types::{CapacityProviderStrategyItem, ContainerDefinition};
use helpers::TestServer;

#[tokio::test]
async fn run_task_emits_capacity_provider_name_on_task() {
    let server = TestServer::start().await;
    let ecs = server.ecs_client().await;

    ecs.create_cluster()
        .cluster_name("cp-cluster")
        .capacity_providers("FARGATE_SPOT")
        .send()
        .await
        .unwrap();
    ecs.register_task_definition()
        .family("cp-family")
        .container_definitions(
            ContainerDefinition::builder()
                .name("app")
                .image("public.ecr.aws/docker/library/alpine:3.20")
                .essential(true)
                .command("true")
                .build(),
        )
        .send()
        .await
        .unwrap();

    let run = ecs
        .run_task()
        .cluster("cp-cluster")
        .task_definition("cp-family")
        .capacity_provider_strategy(
            CapacityProviderStrategyItem::builder()
                .capacity_provider("FARGATE_SPOT")
                .weight(1)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("run_task");

    let task = &run.tasks()[0];
    assert_eq!(
        task.capacity_provider_name(),
        Some("FARGATE_SPOT"),
        "Task should carry the strategy's resolved capacityProviderName"
    );
}

#[tokio::test]
async fn run_task_without_strategy_omits_capacity_provider_name() {
    let server = TestServer::start().await;
    let ecs = server.ecs_client().await;

    ecs.create_cluster()
        .cluster_name("plain-cluster")
        .send()
        .await
        .unwrap();
    ecs.register_task_definition()
        .family("plain-family")
        .container_definitions(
            ContainerDefinition::builder()
                .name("app")
                .image("public.ecr.aws/docker/library/alpine:3.20")
                .essential(true)
                .command("true")
                .build(),
        )
        .send()
        .await
        .unwrap();

    let run = ecs
        .run_task()
        .cluster("plain-cluster")
        .task_definition("plain-family")
        .send()
        .await
        .expect("run_task");

    let task = &run.tasks()[0];
    assert!(
        task.capacity_provider_name().is_none(),
        "RunTask without a CP strategy should not populate capacityProviderName"
    );
}
