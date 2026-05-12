//! ECS container metadata endpoint (O12).
//!
//! Verifies that `/_fakecloud/ecs/v4/{task_id}` and `/_fakecloud/ecs/v3/{task_id}`
//! return the expected metadata JSON after a task is created.

mod helpers;

use aws_sdk_ecs::types::ContainerDefinition;
use helpers::TestServer;

#[tokio::test]
async fn ecs_metadata_endpoint_v3_v4() {
    let server = TestServer::start().await;
    let ecs = server.ecs_client().await;

    ecs.create_cluster()
        .cluster_name("meta-cluster")
        .send()
        .await
        .expect("create_cluster");

    ecs.register_task_definition()
        .family("meta-family")
        .container_definitions(
            ContainerDefinition::builder()
                .name("app")
                .image("alpine")
                .essential(true)
                .build(),
        )
        .send()
        .await
        .expect("register_task_definition");

    let run = ecs
        .run_task()
        .cluster("meta-cluster")
        .task_definition("meta-family")
        .send()
        .await
        .expect("run_task");
    let arn = run.tasks()[0].task_arn().unwrap().to_string();
    let task_id = arn.rsplit('/').next().unwrap();

    let v4: serde_json::Value = reqwest::get(format!(
        "{}/_fakecloud/ecs/v4/{}",
        server.endpoint(),
        task_id
    ))
    .await
    .expect("v4 request")
    .json()
    .await
    .expect("v4 json");

    assert_eq!(
        v4.get("Cluster").and_then(|v| v.as_str()),
        Some("meta-cluster")
    );
    assert_eq!(
        v4.get("TaskARN").and_then(|v| v.as_str()),
        Some(arn.as_str())
    );
    assert_eq!(
        v4.get("Family").and_then(|v| v.as_str()),
        Some("meta-family")
    );
    assert!(
        v4.get("DesiredStatus").and_then(|v| v.as_str()).is_some(),
        "v4 should include DesiredStatus"
    );
    assert!(
        v4.get("Containers").and_then(|v| v.as_array()).is_some(),
        "v4 should include Containers array"
    );

    let v3: serde_json::Value = reqwest::get(format!(
        "{}/_fakecloud/ecs/v3/{}",
        server.endpoint(),
        task_id
    ))
    .await
    .expect("v3 request")
    .json()
    .await
    .expect("v3 json");

    assert_eq!(
        v3.get("Cluster").and_then(|v| v.as_str()),
        Some("meta-cluster")
    );
    assert_eq!(
        v3.get("TaskARN").and_then(|v| v.as_str()),
        Some(arn.as_str())
    );
    assert_eq!(
        v3.get("Family").and_then(|v| v.as_str()),
        Some("meta-family")
    );
    assert!(
        v3.get("Containers").and_then(|v| v.as_array()).is_some(),
        "v3 should include Containers array"
    );

    let not_found = reqwest::get(format!(
        "{}/_fakecloud/ecs/v4/nonexistent-task-id",
        server.endpoint()
    ))
    .await
    .expect("not_found request");
    assert_eq!(not_found.status(), 404);
}

/// I11: `/_fakecloud/ecs/metadata/{task_arn}` returns the aggregated v4 dump
/// keyed by full (URL-encoded) task ARN. This is the assertion-friendly path
/// tests reach for after holding a RunTask response.
#[tokio::test]
async fn ecs_introspection_metadata_by_arn() {
    let server = TestServer::start().await;
    let ecs = server.ecs_client().await;

    ecs.create_cluster()
        .cluster_name("intro-meta-cluster")
        .send()
        .await
        .expect("create_cluster");

    ecs.register_task_definition()
        .family("intro-meta-family")
        .container_definitions(
            ContainerDefinition::builder()
                .name("app")
                .image("alpine:3.19")
                .essential(true)
                .build(),
        )
        .send()
        .await
        .expect("register_task_definition");

    let run = ecs
        .run_task()
        .cluster("intro-meta-cluster")
        .task_definition("intro-meta-family")
        .send()
        .await
        .expect("run_task");
    let arn = run.tasks()[0].task_arn().unwrap().to_string();

    // Minimal percent-encoding sufficient for an ECS task ARN
    // (`arn:aws:ecs:...:task/<cluster>/<id>`).
    let encoded = arn.replace(':', "%3A").replace('/', "%2F");
    let resp = reqwest::get(format!(
        "{}/_fakecloud/ecs/metadata/{}",
        server.endpoint(),
        encoded
    ))
    .await
    .expect("metadata request");
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.expect("metadata json");

    let task = body.get("task").expect("task field");
    assert_eq!(
        task.get("cluster").and_then(|v| v.as_str()),
        Some("intro-meta-cluster")
    );
    assert_eq!(
        task.get("taskArn").and_then(|v| v.as_str()),
        Some(arn.as_str())
    );
    assert_eq!(
        task.get("family").and_then(|v| v.as_str()),
        Some("intro-meta-family")
    );
    assert!(task.get("revision").and_then(|v| v.as_i64()).is_some());
    assert!(task.get("desiredStatus").and_then(|v| v.as_str()).is_some());
    assert!(task.get("knownStatus").and_then(|v| v.as_str()).is_some());
    assert!(task.get("launchType").and_then(|v| v.as_str()).is_some());
    assert!(task
        .get("availabilityZone")
        .and_then(|v| v.as_str())
        .is_some());
    let containers = task
        .get("containers")
        .and_then(|v| v.as_array())
        .expect("containers array");
    assert_eq!(containers.len(), 1);
    let c0 = &containers[0];
    assert_eq!(c0.get("name").and_then(|v| v.as_str()), Some("app"));
    assert_eq!(
        c0.get("image").and_then(|v| v.as_str()),
        Some("alpine:3.19")
    );
    assert!(c0.get("limits").is_some());
    assert!(c0.get("ports").and_then(|v| v.as_array()).is_some());
    assert!(c0.get("labels").is_some());

    let not_found = reqwest::get(format!(
        "{}/_fakecloud/ecs/metadata/arn%3Aaws%3Aecs%3Aus-east-1%3A000000000000%3Atask%2Fnope%2Fnope",
        server.endpoint()
    ))
    .await
    .expect("nf request");
    assert_eq!(not_found.status(), 404);
}
