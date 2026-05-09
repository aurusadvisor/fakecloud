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
