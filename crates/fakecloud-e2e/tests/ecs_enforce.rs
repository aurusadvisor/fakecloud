//! Verify ECS-side enforcement gates that until O15 only stored fields:
//!
//! 1. ExecuteCommand must reject when the target task did not opt in
//!    via `enableExecuteCommand` at RunTask / Service-create time.
//! 2. `propagateTags=TASK_DEFINITION` on a service must copy the task
//!    definition's tags onto every task the service spawns; clients
//!    can read them back via `ListTagsForResource`.
//! 3. `UpdateService` scale-down must skip tasks marked with
//!    `protectFromScaleIn` via `UpdateTaskProtection` and pick an
//!    unprotected task instead.

mod helpers;

use aws_sdk_ecs::types::{ContainerDefinition, PropagateTags, Tag, TaskField};
use helpers::TestServer;

async fn bootstrap(client: &aws_sdk_ecs::Client, cluster: &str, family: &str, tags: Vec<Tag>) {
    client
        .create_cluster()
        .cluster_name(cluster)
        .send()
        .await
        .unwrap();
    let mut td = client
        .register_task_definition()
        .family(family)
        .container_definitions(
            ContainerDefinition::builder()
                .name("app")
                .image("public.ecr.aws/library/alpine:latest")
                .essential(true)
                .build(),
        );
    for t in tags {
        td = td.tags(t);
    }
    td.send().await.unwrap();
}

#[tokio::test]
async fn execute_command_rejected_when_service_did_not_enable_it() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    bootstrap(&client, "exec-off", "exec-off-td", vec![]).await;

    client
        .create_service()
        .cluster("exec-off")
        .service_name("web")
        .task_definition("exec-off-td")
        .desired_count(1)
        // enable_execute_command intentionally omitted (default = false).
        .send()
        .await
        .expect("create_service");

    let tasks = client
        .list_tasks()
        .cluster("exec-off")
        .send()
        .await
        .expect("list_tasks");
    let task_arn = tasks.task_arns().first().expect("one task").clone();

    let err = client
        .execute_command()
        .cluster("exec-off")
        .task(&task_arn)
        .command("/bin/sh -c 'echo hi'")
        .interactive(false)
        .send()
        .await
        .expect_err("ExecuteCommand should be rejected");

    let msg = format!("{err:?}");
    assert!(
        msg.contains("InvalidParameterException")
            || msg.contains("execute command was not enabled"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
async fn execute_command_allowed_when_service_enabled_it() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    bootstrap(&client, "exec-on", "exec-on-td", vec![]).await;

    client
        .create_service()
        .cluster("exec-on")
        .service_name("web")
        .task_definition("exec-on-td")
        .desired_count(1)
        .enable_execute_command(true)
        .send()
        .await
        .expect("create_service");

    let tasks = client
        .list_tasks()
        .cluster("exec-on")
        .send()
        .await
        .expect("list_tasks");
    let task_arn = tasks.task_arns().first().expect("one task").clone();

    // ExecuteCommand returns a session shape. We don't assert the
    // session contents (docker exec may or may not be available in
    // CI), only that the gate didn't reject the call.
    let resp = client
        .execute_command()
        .cluster("exec-on")
        .task(&task_arn)
        .command("/bin/sh -c 'true'")
        .interactive(false)
        .send()
        .await;
    // In CI without docker, the runtime may surface a docker-exec
    // failure; the gate itself must not return InvalidParameterException.
    if let Err(err) = resp {
        let msg = format!("{err:?}");
        assert!(
            !msg.contains("InvalidParameterException"),
            "ExecuteCommand should not be gated when service enabled it: {msg}"
        );
    }

    // Surface check: DescribeTasks should report enableExecuteCommand=true.
    let described = client
        .describe_tasks()
        .cluster("exec-on")
        .tasks(&task_arn)
        .send()
        .await
        .expect("describe_tasks");
    let task = described.tasks().first().expect("task present");
    assert!(task.enable_execute_command());
}

#[tokio::test]
async fn propagate_tags_task_definition_copies_td_tags_onto_tasks() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    let td_tags = vec![
        Tag::builder().key("Project").value("alpha").build(),
        Tag::builder().key("Env").value("test").build(),
    ];
    bootstrap(&client, "tag-cluster", "tag-td", td_tags.clone()).await;

    client
        .create_service()
        .cluster("tag-cluster")
        .service_name("web")
        .task_definition("tag-td")
        .desired_count(1)
        .propagate_tags(PropagateTags::TaskDefinition)
        .send()
        .await
        .expect("create_service");

    let listed = client
        .list_tasks()
        .cluster("tag-cluster")
        .send()
        .await
        .expect("list_tasks");
    let task_arn = listed.task_arns().first().expect("one task").clone();

    let described = client
        .describe_tasks()
        .cluster("tag-cluster")
        .tasks(&task_arn)
        .include(TaskField::Tags)
        .send()
        .await
        .expect("describe_tasks");
    let task = described.tasks().first().expect("task present");
    let tag_keys: Vec<_> = task.tags().iter().filter_map(|t| t.key()).collect();
    assert!(
        tag_keys.contains(&"Project") && tag_keys.contains(&"Env"),
        "propagateTags=TASK_DEFINITION should copy TD tags onto tasks; got {tag_keys:?}"
    );

    // ListTagsForResource on the task ARN must surface them too.
    let lt = client
        .list_tags_for_resource()
        .resource_arn(&task_arn)
        .send()
        .await
        .expect("list_tags_for_resource");
    let lt_keys: Vec<_> = lt.tags().iter().filter_map(|t| t.key()).collect();
    assert!(
        lt_keys.contains(&"Project") && lt_keys.contains(&"Env"),
        "ListTagsForResource on the task should reflect propagated TD tags; got {lt_keys:?}"
    );
}

#[tokio::test]
async fn propagate_tags_service_copies_service_tags_onto_tasks() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    bootstrap(&client, "svc-tag-cluster", "svc-tag-td", vec![]).await;

    client
        .create_service()
        .cluster("svc-tag-cluster")
        .service_name("web")
        .task_definition("svc-tag-td")
        .desired_count(1)
        .propagate_tags(PropagateTags::Service)
        .tags(Tag::builder().key("Owner").value("platform").build())
        .send()
        .await
        .expect("create_service");

    let listed = client
        .list_tasks()
        .cluster("svc-tag-cluster")
        .send()
        .await
        .expect("list_tasks");
    let task_arn = listed.task_arns().first().expect("one task").clone();

    let described = client
        .describe_tasks()
        .cluster("svc-tag-cluster")
        .tasks(&task_arn)
        .include(TaskField::Tags)
        .send()
        .await
        .expect("describe_tasks");
    let task = described.tasks().first().expect("task present");
    let tag_keys: Vec<_> = task.tags().iter().filter_map(|t| t.key()).collect();
    assert!(
        tag_keys.contains(&"Owner"),
        "propagateTags=SERVICE should copy Service tags onto tasks; got {tag_keys:?}"
    );
}

#[tokio::test]
async fn update_service_scale_in_skips_protected_tasks() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    bootstrap(&client, "prot-cluster", "prot-td", vec![]).await;

    client
        .create_service()
        .cluster("prot-cluster")
        .service_name("web")
        .task_definition("prot-td")
        .desired_count(2)
        .send()
        .await
        .expect("create_service");

    let listed = client
        .list_tasks()
        .cluster("prot-cluster")
        .send()
        .await
        .expect("list_tasks");
    let task_arns: Vec<String> = listed.task_arns().to_vec();
    assert_eq!(task_arns.len(), 2, "service should have spawned 2 tasks");
    let protected_arn = &task_arns[1];

    client
        .update_task_protection()
        .cluster("prot-cluster")
        .tasks(protected_arn)
        .protection_enabled(true)
        .send()
        .await
        .expect("update_task_protection");

    client
        .update_service()
        .cluster("prot-cluster")
        .service("web")
        .desired_count(1)
        .send()
        .await
        .expect("update_service down");

    // The protected task must still exist (RUNNING/PENDING — not STOPPED).
    let described = client
        .describe_tasks()
        .cluster("prot-cluster")
        .tasks(protected_arn)
        .send()
        .await
        .expect("describe_tasks");
    let task = described.tasks().first().expect("protected task present");
    assert_ne!(
        task.last_status(),
        Some("STOPPED"),
        "protected task must survive scale-in; got last_status={:?}",
        task.last_status()
    );
    assert_ne!(
        task.desired_status(),
        Some("STOPPED"),
        "protected task desired_status must not flip to STOPPED on scale-in; got {:?}",
        task.desired_status()
    );
}
