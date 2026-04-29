//! ECS account-setting ARN format enforcement. Covers the
//! `serviceLongArnFormat` / `taskLongArnFormat` /
//! `containerInstanceLongArnFormat` flags which switch ECS between
//! long-form (cluster segment included) and short-form ARNs.
//!
//! AWS has mandated long-form since Jan 2020 but the settings still
//! exist for backward-compat. Tests that rely on short ARNs shouldn't
//! be silently broken just because fakecloud ignored the setting.

mod helpers;

use aws_sdk_ecs::types::{ContainerDefinition, SettingName};
use helpers::TestServer;

async fn register_noop_task_def(client: &aws_sdk_ecs::Client, family: &str) {
    client
        .register_task_definition()
        .family(family)
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
}

#[tokio::test]
async fn task_long_arn_format_disabled_uses_short_arn() {
    let server = TestServer::start().await;
    let ecs = server.ecs_client().await;

    ecs.put_account_setting_default()
        .name(SettingName::TaskLongArnFormat)
        .value("disabled")
        .send()
        .await
        .expect("put_account_setting_default");

    ecs.create_cluster()
        .cluster_name("short-arn-cluster")
        .send()
        .await
        .unwrap();
    register_noop_task_def(&ecs, "short-arn-family").await;

    let run = ecs
        .run_task()
        .cluster("short-arn-cluster")
        .task_definition("short-arn-family")
        .send()
        .await
        .expect("run_task");
    let arn = run.tasks()[0].task_arn().unwrap().to_string();
    // Short form: `arn:aws:ecs:<region>:<acct>:task/<id>` — no cluster.
    assert!(
        arn.contains(":task/") && !arn.contains(":task/short-arn-cluster/"),
        "expected short-form task ARN, got {arn}"
    );
    let tail = arn.rsplit(":task/").next().unwrap();
    assert!(
        !tail.contains('/'),
        "short ARN tail should be a single id, got {tail}"
    );
}

#[tokio::test]
async fn service_long_arn_format_disabled_uses_short_arn() {
    let server = TestServer::start().await;
    let ecs = server.ecs_client().await;

    ecs.put_account_setting_default()
        .name(SettingName::ServiceLongArnFormat)
        .value("disabled")
        .send()
        .await
        .unwrap();

    ecs.create_cluster()
        .cluster_name("svc-arn-cluster")
        .send()
        .await
        .unwrap();
    register_noop_task_def(&ecs, "svc-arn-family").await;

    let created = ecs
        .create_service()
        .cluster("svc-arn-cluster")
        .service_name("short-svc")
        .task_definition("svc-arn-family")
        .desired_count(0)
        .send()
        .await
        .unwrap();
    let arn = created
        .service()
        .unwrap()
        .service_arn()
        .unwrap()
        .to_string();
    assert!(
        arn.contains(":service/short-svc") && !arn.contains(":service/svc-arn-cluster/"),
        "expected short-form service ARN, got {arn}"
    );
}

#[tokio::test]
async fn long_format_is_the_default() {
    // No account-setting touch — default long ARNs expected.
    let server = TestServer::start().await;
    let ecs = server.ecs_client().await;
    ecs.create_cluster()
        .cluster_name("default-long")
        .send()
        .await
        .unwrap();
    register_noop_task_def(&ecs, "default-long-family").await;
    let run = ecs
        .run_task()
        .cluster("default-long")
        .task_definition("default-long-family")
        .send()
        .await
        .unwrap();
    let arn = run.tasks()[0].task_arn().unwrap().to_string();
    assert!(
        arn.contains(":task/default-long/"),
        "expected long-form task ARN by default, got {arn}"
    );
}

#[tokio::test]
async fn account_setting_default_list_reflects_writes() {
    let server = TestServer::start().await;
    let ecs = server.ecs_client().await;
    ecs.put_account_setting_default()
        .name(SettingName::TaskLongArnFormat)
        .value("disabled")
        .send()
        .await
        .unwrap();
    let resp = ecs
        .list_account_settings()
        .effective_settings(true)
        .send()
        .await
        .unwrap();
    let found = resp
        .settings()
        .iter()
        .find(|s| s.name() == Some(&SettingName::TaskLongArnFormat))
        .expect("taskLongArnFormat in effective settings");
    assert_eq!(found.value(), Some("disabled"));
}
