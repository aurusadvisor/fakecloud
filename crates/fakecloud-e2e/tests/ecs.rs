//! ECS Batch 1: control-plane CRUD for clusters, task definitions,
//! tagging, account settings. Execution (RunTask/CreateService/...) is
//! covered in subsequent batches.

mod helpers;

use aws_sdk_ecs::types::{ContainerDefinition, Tag};
use helpers::TestServer;

#[tokio::test]
async fn create_describe_list_delete_cluster() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;

    let created = client
        .create_cluster()
        .cluster_name("batch1-cluster")
        .send()
        .await
        .expect("create_cluster");
    let cluster = created.cluster().expect("cluster");
    assert_eq!(cluster.cluster_name(), Some("batch1-cluster"));
    assert_eq!(cluster.status(), Some("ACTIVE"));
    let arn = cluster.cluster_arn().unwrap().to_string();
    assert!(arn.ends_with(":cluster/batch1-cluster"), "arn={arn}");

    let described = client
        .describe_clusters()
        .clusters("batch1-cluster")
        .send()
        .await
        .expect("describe_clusters");
    assert_eq!(described.clusters().len(), 1);
    assert!(described.failures().is_empty());

    let described_by_arn = client
        .describe_clusters()
        .clusters(arn.clone())
        .send()
        .await
        .expect("describe_clusters by ARN");
    assert_eq!(described_by_arn.clusters().len(), 1);

    let listed = client.list_clusters().send().await.expect("list_clusters");
    assert!(listed
        .cluster_arns()
        .iter()
        .any(|a| a.ends_with(":cluster/batch1-cluster")));

    let deleted = client
        .delete_cluster()
        .cluster("batch1-cluster")
        .send()
        .await
        .expect("delete_cluster");
    assert_eq!(deleted.cluster().and_then(|c| c.status()), Some("INACTIVE"));

    // Describe after delete returns a MISSING failure, not an error.
    let after = client
        .describe_clusters()
        .clusters("batch1-cluster")
        .send()
        .await
        .expect("describe after delete");
    assert!(after.clusters().is_empty());
    assert_eq!(after.failures().len(), 1);
    assert_eq!(after.failures()[0].reason(), Some("MISSING"));
}

#[tokio::test]
async fn describe_missing_cluster_returns_failure() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    let resp = client
        .describe_clusters()
        .clusters("nonexistent")
        .send()
        .await
        .expect("describe_clusters");
    assert!(resp.clusters().is_empty());
    assert_eq!(resp.failures().len(), 1);
    assert_eq!(resp.failures()[0].reason(), Some("MISSING"));
}

#[tokio::test]
async fn create_cluster_with_tags_and_capacity_providers() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;

    let created = client
        .create_cluster()
        .cluster_name("tagged")
        .tags(Tag::builder().key("env").value("prod").build())
        .tags(Tag::builder().key("team").value("platform").build())
        .capacity_providers("FARGATE")
        .capacity_providers("FARGATE_SPOT")
        .send()
        .await
        .expect("create_cluster with tags");
    let cluster = created.cluster().unwrap();
    assert_eq!(cluster.tags().len(), 2);
    assert_eq!(cluster.capacity_providers().len(), 2);

    let listed_tags = client
        .list_tags_for_resource()
        .resource_arn(cluster.cluster_arn().unwrap())
        .send()
        .await
        .expect("list_tags_for_resource");
    assert_eq!(listed_tags.tags().len(), 2);
}

#[tokio::test]
async fn register_describe_deregister_task_definition() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;

    let registered = client
        .register_task_definition()
        .family("batch1-td")
        .container_definitions(
            ContainerDefinition::builder()
                .name("app")
                .image("public.ecr.aws/library/alpine:latest")
                .essential(true)
                .build(),
        )
        .send()
        .await
        .expect("register_task_definition");
    let td = registered.task_definition().unwrap();
    assert_eq!(td.family(), Some("batch1-td"));
    assert_eq!(td.revision(), 1);
    assert_eq!(td.status().unwrap().as_str(), "ACTIVE");
    let arn = td.task_definition_arn().unwrap().to_string();
    assert!(arn.ends_with(":task-definition/batch1-td:1"));

    // Second registration bumps revision.
    let registered_v2 = client
        .register_task_definition()
        .family("batch1-td")
        .container_definitions(
            ContainerDefinition::builder()
                .name("app")
                .image("public.ecr.aws/library/alpine:3.19")
                .essential(true)
                .build(),
        )
        .send()
        .await
        .expect("register_task_definition v2");
    assert_eq!(registered_v2.task_definition().unwrap().revision(), 2);

    // DescribeTaskDefinition with family shorthand returns the latest ACTIVE.
    let described = client
        .describe_task_definition()
        .task_definition("batch1-td")
        .send()
        .await
        .expect("describe_task_definition latest");
    assert_eq!(described.task_definition().unwrap().revision(), 2);

    // DescribeTaskDefinition with family:revision returns that revision.
    let described_v1 = client
        .describe_task_definition()
        .task_definition("batch1-td:1")
        .send()
        .await
        .expect("describe_task_definition v1");
    assert_eq!(described_v1.task_definition().unwrap().revision(), 1);

    // Deregister flips status to INACTIVE and sets deregisteredAt.
    let deregistered = client
        .deregister_task_definition()
        .task_definition("batch1-td:2")
        .send()
        .await
        .expect("deregister_task_definition");
    assert_eq!(
        deregistered
            .task_definition()
            .and_then(|t| t.status())
            .map(|s| s.as_str()),
        Some("INACTIVE")
    );
}

#[tokio::test]
async fn list_task_definitions_and_families() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;

    for family in ["api", "worker", "cron"] {
        client
            .register_task_definition()
            .family(family)
            .container_definitions(
                ContainerDefinition::builder()
                    .name("app")
                    .image("public.ecr.aws/library/alpine:latest")
                    .essential(true)
                    .build(),
            )
            .send()
            .await
            .unwrap();
    }

    let defs = client
        .list_task_definitions()
        .send()
        .await
        .expect("list_task_definitions");
    assert_eq!(defs.task_definition_arns().len(), 3);

    let families = client
        .list_task_definition_families()
        .send()
        .await
        .expect("list_task_definition_families");
    assert_eq!(families.families().len(), 3);

    // familyPrefix filter.
    let filtered = client
        .list_task_definition_families()
        .family_prefix("wo")
        .send()
        .await
        .expect("list_task_definition_families filtered");
    assert_eq!(filtered.families(), &["worker".to_string()]);
}

#[tokio::test]
async fn delete_task_definitions_requires_inactive() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;

    client
        .register_task_definition()
        .family("to-delete")
        .container_definitions(
            ContainerDefinition::builder()
                .name("app")
                .image("public.ecr.aws/library/alpine:latest")
                .essential(true)
                .build(),
        )
        .send()
        .await
        .unwrap();

    let attempt = client
        .delete_task_definitions()
        .task_definitions("to-delete:1")
        .send()
        .await
        .expect("delete_task_definitions active");
    assert!(attempt.task_definitions().is_empty());
    assert_eq!(attempt.failures().len(), 1);
    assert_eq!(attempt.failures()[0].reason(), Some("MUST_BE_INACTIVE"));

    client
        .deregister_task_definition()
        .task_definition("to-delete:1")
        .send()
        .await
        .unwrap();

    let deleted = client
        .delete_task_definitions()
        .task_definitions("to-delete:1")
        .send()
        .await
        .expect("delete_task_definitions inactive");
    assert_eq!(deleted.task_definitions().len(), 1);
    assert!(deleted.failures().is_empty());
    assert_eq!(
        deleted.task_definitions()[0].status().unwrap().as_str(),
        "DELETE_IN_PROGRESS"
    );
}

#[tokio::test]
async fn tag_untag_cluster_and_task_definition() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;

    let cluster = client
        .create_cluster()
        .cluster_name("tagme")
        .send()
        .await
        .unwrap()
        .cluster()
        .unwrap()
        .clone();

    client
        .tag_resource()
        .resource_arn(cluster.cluster_arn().unwrap())
        .tags(Tag::builder().key("env").value("staging").build())
        .tags(Tag::builder().key("team").value("platform").build())
        .send()
        .await
        .unwrap();

    let tags = client
        .list_tags_for_resource()
        .resource_arn(cluster.cluster_arn().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(tags.tags().len(), 2);

    client
        .untag_resource()
        .resource_arn(cluster.cluster_arn().unwrap())
        .tag_keys("team")
        .send()
        .await
        .unwrap();

    let after = client
        .list_tags_for_resource()
        .resource_arn(cluster.cluster_arn().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(after.tags().len(), 1);
    assert_eq!(after.tags()[0].key(), Some("env"));
}

#[tokio::test]
async fn put_and_list_account_settings() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;

    client
        .put_account_setting_default()
        .name("taskLongArnFormat".into())
        .value("enabled")
        .send()
        .await
        .expect("put_account_setting_default");

    let listed = client
        .list_account_settings()
        .effective_settings(true)
        .send()
        .await
        .expect("list_account_settings effective");
    assert!(listed
        .settings()
        .iter()
        .any(|s| s.name().map(|n| n.as_str()) == Some("taskLongArnFormat")));
}

#[tokio::test]
async fn list_clusters_with_out_of_range_next_token_is_not_a_panic() {
    // Regression: an attacker-controlled or stale nextToken pointing past
    // the end of the list must not panic the server.
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    client
        .create_cluster()
        .cluster_name("only")
        .send()
        .await
        .unwrap();
    let resp = client
        .list_clusters()
        .next_token("9999")
        .send()
        .await
        .expect("list_clusters with OOR token");
    assert!(resp.cluster_arns().is_empty());
    assert!(resp.next_token().is_none());
}

#[tokio::test]
async fn delete_cluster_with_tasks_fails() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;

    // Introspection endpoint sanity check — Batch 1 ships the /clusters dump.
    client
        .create_cluster()
        .cluster_name("introspected")
        .send()
        .await
        .unwrap();

    let body: serde_json::Value =
        reqwest::get(format!("{}/_fakecloud/ecs/clusters", server.endpoint()))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    let arr = body.get("clusters").and_then(|v| v.as_array()).unwrap();
    assert!(arr
        .iter()
        .any(|c| c.get("clusterName").and_then(|v| v.as_str()) == Some("introspected")));
}
