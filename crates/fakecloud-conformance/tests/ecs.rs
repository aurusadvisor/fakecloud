//! ECS Batch 1 conformance tests: each `#[test_action]` pairs a real AWS
//! SDK call with the Smithy shape checksum. If AWS rev-bumps the ECS
//! model the checksum goes stale and the build fails loudly.

mod helpers;

use aws_sdk_ecs::types::{ContainerDefinition, Tag};
use fakecloud_conformance_macros::test_action;
use helpers::TestServer;

#[test_action("ecs", "CreateCluster", checksum = "cb27e04e")]
#[tokio::test]
async fn ecs_create_cluster() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    let resp = client
        .create_cluster()
        .cluster_name("confo-create")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.cluster().unwrap().cluster_name(), Some("confo-create"));
}

#[test_action("ecs", "DescribeClusters", checksum = "df3a48bc")]
#[tokio::test]
async fn ecs_describe_clusters() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    client
        .create_cluster()
        .cluster_name("confo-describe")
        .send()
        .await
        .unwrap();
    let resp = client
        .describe_clusters()
        .clusters("confo-describe")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.clusters().len(), 1);
}

#[test_action("ecs", "DeleteCluster", checksum = "00faf628")]
#[tokio::test]
async fn ecs_delete_cluster() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    client
        .create_cluster()
        .cluster_name("confo-delete")
        .send()
        .await
        .unwrap();
    client
        .delete_cluster()
        .cluster("confo-delete")
        .send()
        .await
        .unwrap();
}

#[test_action("ecs", "ListClusters", checksum = "cf37c170")]
#[tokio::test]
async fn ecs_list_clusters() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    client
        .create_cluster()
        .cluster_name("confo-list")
        .send()
        .await
        .unwrap();
    let resp = client.list_clusters().send().await.unwrap();
    assert!(!resp.cluster_arns().is_empty());
}

#[test_action("ecs", "UpdateCluster", checksum = "c38335f1")]
#[tokio::test]
async fn ecs_update_cluster() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    client
        .create_cluster()
        .cluster_name("confo-update")
        .send()
        .await
        .unwrap();
    let resp = client
        .update_cluster()
        .cluster("confo-update")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.cluster().and_then(|c| c.cluster_name()),
        Some("confo-update")
    );
}

#[test_action("ecs", "UpdateClusterSettings", checksum = "f0e11ce7")]
#[tokio::test]
async fn ecs_update_cluster_settings() {
    use aws_sdk_ecs::types::{ClusterSetting, ClusterSettingName};
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    client
        .create_cluster()
        .cluster_name("confo-settings")
        .send()
        .await
        .unwrap();
    let resp = client
        .update_cluster_settings()
        .cluster("confo-settings")
        .settings(
            ClusterSetting::builder()
                .name(ClusterSettingName::ContainerInsights)
                .value("enabled")
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert!(resp.cluster().is_some());
}

#[test_action("ecs", "PutClusterCapacityProviders", checksum = "11ce7106")]
#[tokio::test]
async fn ecs_put_cluster_capacity_providers() {
    use aws_sdk_ecs::types::CapacityProviderStrategyItem;
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    client
        .create_cluster()
        .cluster_name("confo-cp")
        .send()
        .await
        .unwrap();
    let resp = client
        .put_cluster_capacity_providers()
        .cluster("confo-cp")
        .capacity_providers("FARGATE")
        .default_capacity_provider_strategy(
            CapacityProviderStrategyItem::builder()
                .capacity_provider("FARGATE")
                .weight(1)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert!(resp.cluster().is_some());
}

#[test_action("ecs", "RegisterTaskDefinition", checksum = "dcbae024")]
#[tokio::test]
async fn ecs_register_task_definition() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    let resp = client
        .register_task_definition()
        .family("confo-td")
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
    assert_eq!(resp.task_definition().unwrap().family(), Some("confo-td"));
}

#[test_action("ecs", "DescribeTaskDefinition", checksum = "6b7e9ff5")]
#[tokio::test]
async fn ecs_describe_task_definition() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    client
        .register_task_definition()
        .family("confo-desc-td")
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
    let resp = client
        .describe_task_definition()
        .task_definition("confo-desc-td")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.task_definition().and_then(|t| t.family()),
        Some("confo-desc-td")
    );
}

#[test_action("ecs", "DeregisterTaskDefinition", checksum = "0c55a26a")]
#[tokio::test]
async fn ecs_deregister_task_definition() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    client
        .register_task_definition()
        .family("confo-dereg")
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
    let resp = client
        .deregister_task_definition()
        .task_definition("confo-dereg:1")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.task_definition()
            .and_then(|t| t.status())
            .map(|s| s.as_str()),
        Some("INACTIVE")
    );
}

#[test_action("ecs", "DeleteTaskDefinitions", checksum = "ad0b6663")]
#[tokio::test]
async fn ecs_delete_task_definitions() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    client
        .register_task_definition()
        .family("confo-del-td")
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
    client
        .deregister_task_definition()
        .task_definition("confo-del-td:1")
        .send()
        .await
        .unwrap();
    let resp = client
        .delete_task_definitions()
        .task_definitions("confo-del-td:1")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.task_definitions().len(), 1);
}

#[test_action("ecs", "ListTaskDefinitions", checksum = "bbbbb9b3")]
#[tokio::test]
async fn ecs_list_task_definitions() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    client
        .register_task_definition()
        .family("confo-list-td")
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
    let resp = client.list_task_definitions().send().await.unwrap();
    assert!(!resp.task_definition_arns().is_empty());
}

#[test_action("ecs", "ListTaskDefinitionFamilies", checksum = "ca148fca")]
#[tokio::test]
async fn ecs_list_task_definition_families() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    client
        .register_task_definition()
        .family("confo-family")
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
    let resp = client.list_task_definition_families().send().await.unwrap();
    assert!(resp.families().iter().any(|f| f == "confo-family"));
}

#[test_action("ecs", "TagResource", checksum = "fbc4b89a")]
#[tokio::test]
async fn ecs_tag_resource() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    let cluster = client
        .create_cluster()
        .cluster_name("confo-tag")
        .send()
        .await
        .unwrap()
        .cluster()
        .unwrap()
        .clone();
    client
        .tag_resource()
        .resource_arn(cluster.cluster_arn().unwrap())
        .tags(Tag::builder().key("env").value("prod").build())
        .send()
        .await
        .unwrap();
}

#[test_action("ecs", "UntagResource", checksum = "0cff3b01")]
#[tokio::test]
async fn ecs_untag_resource() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    let cluster = client
        .create_cluster()
        .cluster_name("confo-untag")
        .send()
        .await
        .unwrap()
        .cluster()
        .unwrap()
        .clone();
    client
        .tag_resource()
        .resource_arn(cluster.cluster_arn().unwrap())
        .tags(Tag::builder().key("env").value("prod").build())
        .send()
        .await
        .unwrap();
    client
        .untag_resource()
        .resource_arn(cluster.cluster_arn().unwrap())
        .tag_keys("env")
        .send()
        .await
        .unwrap();
}

#[test_action("ecs", "ListTagsForResource", checksum = "2ad51d6a")]
#[tokio::test]
async fn ecs_list_tags_for_resource() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    let cluster = client
        .create_cluster()
        .cluster_name("confo-listtags")
        .tags(Tag::builder().key("env").value("dev").build())
        .send()
        .await
        .unwrap()
        .cluster()
        .unwrap()
        .clone();
    let resp = client
        .list_tags_for_resource()
        .resource_arn(cluster.cluster_arn().unwrap())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.tags().len(), 1);
}

#[test_action("ecs", "PutAccountSetting", checksum = "ef8a7f7b")]
#[tokio::test]
async fn ecs_put_account_setting() {
    use aws_sdk_ecs::types::SettingName;
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    let resp = client
        .put_account_setting()
        .name(SettingName::TaskLongArnFormat)
        .value("enabled")
        .send()
        .await
        .unwrap();
    assert!(resp.setting().is_some());
}

#[test_action("ecs", "PutAccountSettingDefault", checksum = "dc08dc2d")]
#[tokio::test]
async fn ecs_put_account_setting_default() {
    use aws_sdk_ecs::types::SettingName;
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    let resp = client
        .put_account_setting_default()
        .name(SettingName::ServiceLongArnFormat)
        .value("enabled")
        .send()
        .await
        .unwrap();
    assert!(resp.setting().is_some());
}

#[test_action("ecs", "DeleteAccountSetting", checksum = "6f293917")]
#[tokio::test]
async fn ecs_delete_account_setting() {
    use aws_sdk_ecs::types::SettingName;
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    client
        .put_account_setting()
        .name(SettingName::TaskLongArnFormat)
        .value("enabled")
        .send()
        .await
        .unwrap();
    let resp = client
        .delete_account_setting()
        .name(SettingName::TaskLongArnFormat)
        .send()
        .await
        .unwrap();
    assert!(resp.setting().is_some());
}

#[test_action("ecs", "ListAccountSettings", checksum = "96955ca3")]
#[tokio::test]
async fn ecs_list_account_settings() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    let resp = client
        .list_account_settings()
        .effective_settings(true)
        .send()
        .await
        .unwrap();
    // New account has no defaults set; the call should succeed with an
    // empty-or-populated settings list.
    let _ = resp.settings().len();
}

// ── Batch 2: task lifecycle ────────────────────────────────────────

async fn register_conformance_task_def(client: &aws_sdk_ecs::Client, family: &str) {
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

#[test_action("ecs", "RunTask", checksum = "f0ae3fb6")]
#[tokio::test]
async fn ecs_run_task() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    client
        .create_cluster()
        .cluster_name("confo-run")
        .send()
        .await
        .unwrap();
    register_conformance_task_def(&client, "confo-run-td").await;
    let resp = client
        .run_task()
        .cluster("confo-run")
        .task_definition("confo-run-td")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.tasks().len(), 1);
    assert!(resp.failures().is_empty());
}

#[test_action("ecs", "StartTask", checksum = "75d41d3b")]
#[tokio::test]
async fn ecs_start_task() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    client
        .create_cluster()
        .cluster_name("confo-start")
        .send()
        .await
        .unwrap();
    register_conformance_task_def(&client, "confo-start-td").await;
    let resp = client
        .start_task()
        .cluster("confo-start")
        .task_definition("confo-start-td")
        .container_instances("ci-placeholder")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.tasks().len(), 1);
}

#[test_action("ecs", "DescribeTasks", checksum = "84135240")]
#[tokio::test]
async fn ecs_describe_tasks() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    client
        .create_cluster()
        .cluster_name("confo-desc")
        .send()
        .await
        .unwrap();
    register_conformance_task_def(&client, "confo-desc-td").await;
    let run = client
        .run_task()
        .cluster("confo-desc")
        .task_definition("confo-desc-td")
        .send()
        .await
        .unwrap();
    let arn = run.tasks()[0].task_arn().unwrap().to_string();
    let described = client
        .describe_tasks()
        .cluster("confo-desc")
        .tasks(arn)
        .send()
        .await
        .unwrap();
    assert_eq!(described.tasks().len(), 1);
}

#[test_action("ecs", "ListTasks", checksum = "5e257f00")]
#[tokio::test]
async fn ecs_list_tasks() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    client
        .create_cluster()
        .cluster_name("confo-list-t")
        .send()
        .await
        .unwrap();
    register_conformance_task_def(&client, "confo-list-t-td").await;
    client
        .run_task()
        .cluster("confo-list-t")
        .task_definition("confo-list-t-td")
        .send()
        .await
        .unwrap();
    let resp = client
        .list_tasks()
        .cluster("confo-list-t")
        .send()
        .await
        .unwrap();
    assert!(!resp.task_arns().is_empty());
}

#[test_action("ecs", "StopTask", checksum = "b4f8ca9a")]
#[tokio::test]
async fn ecs_stop_task() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    client
        .create_cluster()
        .cluster_name("confo-stop")
        .send()
        .await
        .unwrap();
    register_conformance_task_def(&client, "confo-stop-td").await;
    let run = client
        .run_task()
        .cluster("confo-stop")
        .task_definition("confo-stop-td")
        .send()
        .await
        .unwrap();
    let arn = run.tasks()[0].task_arn().unwrap().to_string();
    let resp = client
        .stop_task()
        .cluster("confo-stop")
        .task(arn)
        .reason("test")
        .send()
        .await
        .unwrap();
    assert!(resp.task().is_some());
}

// ── Batch 3: services ──────────────────────────────────────────────

async fn bootstrap_service_fixtures(client: &aws_sdk_ecs::Client, cluster: &str, family: &str) {
    client
        .create_cluster()
        .cluster_name(cluster)
        .send()
        .await
        .unwrap();
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

#[test_action("ecs", "CreateService", checksum = "15a6dbd5")]
#[tokio::test]
async fn ecs_create_service() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    bootstrap_service_fixtures(&client, "confo-svc", "confo-svc-td").await;
    let resp = client
        .create_service()
        .cluster("confo-svc")
        .service_name("svc-a")
        .task_definition("confo-svc-td")
        .desired_count(1)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.service().unwrap().service_name(), Some("svc-a"));
}

#[test_action("ecs", "DescribeServices", checksum = "ca07d4ee")]
#[tokio::test]
async fn ecs_describe_services() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    bootstrap_service_fixtures(&client, "confo-svc-desc", "confo-svc-desc-td").await;
    client
        .create_service()
        .cluster("confo-svc-desc")
        .service_name("svc-d")
        .task_definition("confo-svc-desc-td")
        .send()
        .await
        .unwrap();
    let resp = client
        .describe_services()
        .cluster("confo-svc-desc")
        .services("svc-d")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.services().len(), 1);
}

#[test_action("ecs", "ListServices", checksum = "4bc85a42")]
#[tokio::test]
async fn ecs_list_services() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    bootstrap_service_fixtures(&client, "confo-svc-list", "confo-svc-list-td").await;
    client
        .create_service()
        .cluster("confo-svc-list")
        .service_name("svc-l")
        .task_definition("confo-svc-list-td")
        .send()
        .await
        .unwrap();
    let resp = client
        .list_services()
        .cluster("confo-svc-list")
        .send()
        .await
        .unwrap();
    assert!(!resp.service_arns().is_empty());
}

#[test_action("ecs", "ListServicesByNamespace", checksum = "13f69425")]
#[tokio::test]
async fn ecs_list_services_by_namespace() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    let resp = client
        .list_services_by_namespace()
        .namespace("arn:aws:servicediscovery:us-east-1:111122223333:namespace/ns-1")
        .send()
        .await
        .unwrap();
    let _ = resp.service_arns().len();
}

#[test_action("ecs", "UpdateService", checksum = "c1482ff6")]
#[tokio::test]
async fn ecs_update_service() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    bootstrap_service_fixtures(&client, "confo-svc-up", "confo-svc-up-td").await;
    client
        .create_service()
        .cluster("confo-svc-up")
        .service_name("svc-u")
        .task_definition("confo-svc-up-td")
        .desired_count(1)
        .send()
        .await
        .unwrap();
    let resp = client
        .update_service()
        .cluster("confo-svc-up")
        .service("svc-u")
        .desired_count(2)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.service().unwrap().desired_count(), 2);
}

#[test_action("ecs", "DeleteService", checksum = "d4f5fbe7")]
#[tokio::test]
async fn ecs_delete_service() {
    let server = TestServer::start().await;
    let client = server.ecs_client().await;
    bootstrap_service_fixtures(&client, "confo-svc-del", "confo-svc-del-td").await;
    client
        .create_service()
        .cluster("confo-svc-del")
        .service_name("svc-del")
        .task_definition("confo-svc-del-td")
        .desired_count(0)
        .send()
        .await
        .unwrap();
    let resp = client
        .delete_service()
        .cluster("confo-svc-del")
        .service("svc-del")
        .send()
        .await
        .unwrap();
    assert!(resp.service().is_some());
}
