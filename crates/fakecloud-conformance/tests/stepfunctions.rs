mod helpers;

use aws_sdk_sfn::types::Tag;
use fakecloud_conformance_macros::test_action;
use helpers::TestServer;
use tokio::time::{sleep, Duration};

fn simple_definition() -> String {
    serde_json::json!({
        "StartAt": "Hello",
        "States": {
            "Hello": {
                "Type": "Pass",
                "Result": "Hello, World!",
                "End": true
            }
        }
    })
    .to_string()
}

#[test_action("sfn", "CreateStateMachine", checksum = "cad1ea0f")]
#[tokio::test]
async fn sfn_create_state_machine() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;

    let resp = client
        .create_state_machine()
        .name("conf-sm")
        .definition(simple_definition())
        .role_arn("arn:aws:iam::123456789012:role/test-role")
        .send()
        .await
        .unwrap();
    assert!(resp.state_machine_arn().contains("stateMachine:conf-sm"));
}

#[test_action("sfn", "DescribeStateMachine", checksum = "e9ff62d1")]
#[tokio::test]
async fn sfn_describe_state_machine() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;

    let create = client
        .create_state_machine()
        .name("conf-describe")
        .definition(simple_definition())
        .role_arn("arn:aws:iam::123456789012:role/test-role")
        .send()
        .await
        .unwrap();

    let resp = client
        .describe_state_machine()
        .state_machine_arn(create.state_machine_arn())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.name(), "conf-describe");
    assert_eq!(resp.status().unwrap().as_str(), "ACTIVE");
    assert_eq!(resp.r#type().as_str(), "STANDARD");
}

#[test_action("sfn", "ListStateMachines", checksum = "3d392fe1")]
#[tokio::test]
async fn sfn_list_state_machines() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;

    client
        .create_state_machine()
        .name("conf-list")
        .definition(simple_definition())
        .role_arn("arn:aws:iam::123456789012:role/test-role")
        .send()
        .await
        .unwrap();

    let resp = client.list_state_machines().send().await.unwrap();
    assert!(!resp.state_machines().is_empty());
}

#[test_action("sfn", "DeleteStateMachine", checksum = "286b2d42")]
#[tokio::test]
async fn sfn_delete_state_machine() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;

    let create = client
        .create_state_machine()
        .name("conf-delete")
        .definition(simple_definition())
        .role_arn("arn:aws:iam::123456789012:role/test-role")
        .send()
        .await
        .unwrap();

    client
        .delete_state_machine()
        .state_machine_arn(create.state_machine_arn())
        .send()
        .await
        .unwrap();

    let err = client
        .describe_state_machine()
        .state_machine_arn(create.state_machine_arn())
        .send()
        .await;
    assert!(err.is_err());
}

#[test_action("sfn", "UpdateStateMachine", checksum = "a9b06b6a")]
#[tokio::test]
async fn sfn_update_state_machine() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;

    let create = client
        .create_state_machine()
        .name("conf-update")
        .definition(simple_definition())
        .role_arn("arn:aws:iam::123456789012:role/test-role")
        .send()
        .await
        .unwrap();

    let resp = client
        .update_state_machine()
        .state_machine_arn(create.state_machine_arn())
        .role_arn("arn:aws:iam::123456789012:role/new-role")
        .send()
        .await
        .unwrap();
    let _ = resp.update_date();

    let describe = client
        .describe_state_machine()
        .state_machine_arn(create.state_machine_arn())
        .send()
        .await
        .unwrap();
    assert_eq!(
        describe.role_arn(),
        "arn:aws:iam::123456789012:role/new-role"
    );
}

#[test_action("sfn", "TagResource", checksum = "047e5817")]
#[tokio::test]
async fn sfn_tag_resource() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;

    let create = client
        .create_state_machine()
        .name("conf-tag")
        .definition(simple_definition())
        .role_arn("arn:aws:iam::123456789012:role/test-role")
        .send()
        .await
        .unwrap();

    client
        .tag_resource()
        .resource_arn(create.state_machine_arn())
        .tags(Tag::builder().key("env").value("test").build())
        .send()
        .await
        .unwrap();

    let tags = client
        .list_tags_for_resource()
        .resource_arn(create.state_machine_arn())
        .send()
        .await
        .unwrap();
    assert_eq!(tags.tags().len(), 1);
}

#[test_action("sfn", "UntagResource", checksum = "56aea886")]
#[tokio::test]
async fn sfn_untag_resource() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;

    let create = client
        .create_state_machine()
        .name("conf-untag")
        .definition(simple_definition())
        .role_arn("arn:aws:iam::123456789012:role/test-role")
        .send()
        .await
        .unwrap();

    client
        .tag_resource()
        .resource_arn(create.state_machine_arn())
        .tags(Tag::builder().key("env").value("test").build())
        .tags(Tag::builder().key("team").value("eng").build())
        .send()
        .await
        .unwrap();

    client
        .untag_resource()
        .resource_arn(create.state_machine_arn())
        .tag_keys("env")
        .send()
        .await
        .unwrap();

    let tags = client
        .list_tags_for_resource()
        .resource_arn(create.state_machine_arn())
        .send()
        .await
        .unwrap();
    assert_eq!(tags.tags().len(), 1);
    assert_eq!(tags.tags()[0].key(), Some("team"));
}

#[test_action("sfn", "ListTagsForResource", checksum = "b98da062")]
#[tokio::test]
async fn sfn_list_tags_for_resource() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;

    let create = client
        .create_state_machine()
        .name("conf-list-tags")
        .definition(simple_definition())
        .role_arn("arn:aws:iam::123456789012:role/test-role")
        .send()
        .await
        .unwrap();

    // No tags initially
    let tags = client
        .list_tags_for_resource()
        .resource_arn(create.state_machine_arn())
        .send()
        .await
        .unwrap();
    assert!(tags.tags().is_empty());
}

// ─── Execution Lifecycle Conformance Tests ──────────────────────────

async fn wait_for_execution(client: &aws_sdk_sfn::Client, arn: &str) {
    for _ in 0..50 {
        sleep(Duration::from_millis(50)).await;
        let desc = client
            .describe_execution()
            .execution_arn(arn)
            .send()
            .await
            .unwrap();
        if desc.status().as_str() != "RUNNING" {
            return;
        }
    }
    panic!("Execution did not complete in time");
}

#[test_action("sfn", "StartExecution", checksum = "6ec509e4")]
#[tokio::test]
async fn sfn_start_execution() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;

    let create = client
        .create_state_machine()
        .name("conf-start-exec")
        .definition(simple_definition())
        .role_arn("arn:aws:iam::123456789012:role/test-role")
        .send()
        .await
        .unwrap();

    let resp = client
        .start_execution()
        .state_machine_arn(create.state_machine_arn())
        .input(r#"{}"#)
        .send()
        .await
        .unwrap();
    assert!(resp.execution_arn().contains("execution:"));
}

#[test_action("sfn", "DescribeExecution", checksum = "7574d620")]
#[tokio::test]
async fn sfn_describe_execution() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;

    let create = client
        .create_state_machine()
        .name("conf-desc-exec")
        .definition(simple_definition())
        .role_arn("arn:aws:iam::123456789012:role/test-role")
        .send()
        .await
        .unwrap();

    let start = client
        .start_execution()
        .state_machine_arn(create.state_machine_arn())
        .send()
        .await
        .unwrap();

    wait_for_execution(&client, start.execution_arn()).await;

    let resp = client
        .describe_execution()
        .execution_arn(start.execution_arn())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_str(), "SUCCEEDED");
}

#[test_action("sfn", "ListExecutions", checksum = "6e3c28ed")]
#[tokio::test]
async fn sfn_list_executions() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;

    let create = client
        .create_state_machine()
        .name("conf-list-exec")
        .definition(simple_definition())
        .role_arn("arn:aws:iam::123456789012:role/test-role")
        .send()
        .await
        .unwrap();

    client
        .start_execution()
        .state_machine_arn(create.state_machine_arn())
        .send()
        .await
        .unwrap();

    sleep(Duration::from_millis(200)).await;

    let resp = client
        .list_executions()
        .state_machine_arn(create.state_machine_arn())
        .send()
        .await
        .unwrap();
    assert!(!resp.executions().is_empty());
}

#[test_action("sfn", "StopExecution", checksum = "96371e61")]
#[tokio::test]
async fn sfn_stop_execution() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;

    let create = client
        .create_state_machine()
        .name("conf-stop-exec")
        .definition(simple_definition())
        .role_arn("arn:aws:iam::123456789012:role/test-role")
        .send()
        .await
        .unwrap();

    let start = client
        .start_execution()
        .state_machine_arn(create.state_machine_arn())
        .send()
        .await
        .unwrap();

    // Try to stop; may already be complete due to fast execution
    let _ = client
        .stop_execution()
        .execution_arn(start.execution_arn())
        .send()
        .await;

    // Just verify describe works after stop attempt
    let desc = client
        .describe_execution()
        .execution_arn(start.execution_arn())
        .send()
        .await
        .unwrap();
    // Status is either ABORTED or SUCCEEDED
    let status = desc.status().as_str();
    assert!(status == "ABORTED" || status == "SUCCEEDED");
}

#[test_action("sfn", "GetExecutionHistory", checksum = "447fb14a")]
#[tokio::test]
async fn sfn_get_execution_history() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;

    let create = client
        .create_state_machine()
        .name("conf-history")
        .definition(simple_definition())
        .role_arn("arn:aws:iam::123456789012:role/test-role")
        .send()
        .await
        .unwrap();

    let start = client
        .start_execution()
        .state_machine_arn(create.state_machine_arn())
        .send()
        .await
        .unwrap();

    wait_for_execution(&client, start.execution_arn()).await;

    let resp = client
        .get_execution_history()
        .execution_arn(start.execution_arn())
        .send()
        .await
        .unwrap();
    assert!(!resp.events().is_empty());
}

#[test_action("sfn", "DescribeStateMachineForExecution", checksum = "208431fb")]
#[tokio::test]
async fn sfn_describe_state_machine_for_execution() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;

    let create = client
        .create_state_machine()
        .name("conf-sm-for-exec")
        .definition(simple_definition())
        .role_arn("arn:aws:iam::123456789012:role/test-role")
        .send()
        .await
        .unwrap();

    let start = client
        .start_execution()
        .state_machine_arn(create.state_machine_arn())
        .send()
        .await
        .unwrap();

    wait_for_execution(&client, start.execution_arn()).await;

    let resp = client
        .describe_state_machine_for_execution()
        .execution_arn(start.execution_arn())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.name(), "conf-sm-for-exec");
}

// ─── Conformance closure batch ───

async fn create_sm(client: &aws_sdk_sfn::Client, name: &str) -> String {
    client
        .create_state_machine()
        .name(name)
        .definition(simple_definition())
        .role_arn("arn:aws:iam::123456789012:role/test-role")
        .send()
        .await
        .unwrap()
        .state_machine_arn()
        .to_string()
}

#[test_action("sfn", "CreateActivity", checksum = "fb3391fa")]
#[test_action("sfn", "DescribeActivity", checksum = "43f05641")]
#[test_action("sfn", "ListActivities", checksum = "ad58df5a")]
#[test_action("sfn", "GetActivityTask", checksum = "a221a52e")]
#[test_action("sfn", "DeleteActivity", checksum = "7bb176bf")]
#[tokio::test]
async fn sfn_activity_lifecycle() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;
    let act = client
        .create_activity()
        .name("conf-act")
        .send()
        .await
        .unwrap()
        .activity_arn()
        .to_string();
    let _ = client
        .describe_activity()
        .activity_arn(&act)
        .send()
        .await
        .unwrap();
    let _ = client.list_activities().send().await.unwrap();
    let _ = client
        .get_activity_task()
        .activity_arn(&act)
        .send()
        .await
        .unwrap();
    client
        .delete_activity()
        .activity_arn(&act)
        .send()
        .await
        .unwrap();
}

#[test_action("sfn", "SendTaskSuccess", checksum = "ece233d2")]
#[test_action("sfn", "SendTaskFailure", checksum = "0c7068a6")]
#[test_action("sfn", "SendTaskHeartbeat", checksum = "4303f138")]
#[tokio::test]
async fn sfn_task_token_round_trip() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;
    let act = client
        .create_activity()
        .name("conf-task")
        .send()
        .await
        .unwrap()
        .activity_arn()
        .to_string();
    let token = client
        .get_activity_task()
        .activity_arn(&act)
        .send()
        .await
        .unwrap()
        .task_token()
        .unwrap()
        .to_string();
    client
        .send_task_heartbeat()
        .task_token(&token)
        .send()
        .await
        .unwrap();
    client
        .send_task_success()
        .task_token(&token)
        .output("{}")
        .send()
        .await
        .unwrap();
    // Same token can also be failed (test second token).
    let token2 = client
        .get_activity_task()
        .activity_arn(&act)
        .send()
        .await
        .unwrap()
        .task_token()
        .unwrap()
        .to_string();
    client
        .send_task_failure()
        .task_token(&token2)
        .error("E")
        .cause("c")
        .send()
        .await
        .unwrap();
}

#[test_action("sfn", "PublishStateMachineVersion", checksum = "9e9b9869")]
#[test_action("sfn", "ListStateMachineVersions", checksum = "a401dcf0")]
#[test_action("sfn", "DeleteStateMachineVersion", checksum = "4cd933dc")]
#[tokio::test]
async fn sfn_version_lifecycle() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;
    let sm = create_sm(&client, "conf-ver").await;
    let v = client
        .publish_state_machine_version()
        .state_machine_arn(&sm)
        .description("v1")
        .send()
        .await
        .unwrap()
        .state_machine_version_arn()
        .to_string();
    let _ = client
        .list_state_machine_versions()
        .state_machine_arn(&sm)
        .send()
        .await
        .unwrap();
    client
        .delete_state_machine_version()
        .state_machine_version_arn(&v)
        .send()
        .await
        .unwrap();
}

#[test_action("sfn", "CreateStateMachineAlias", checksum = "4e15e19a")]
#[test_action("sfn", "DescribeStateMachineAlias", checksum = "3ce6d908")]
#[test_action("sfn", "ListStateMachineAliases", checksum = "01b390bd")]
#[test_action("sfn", "UpdateStateMachineAlias", checksum = "e5fc5d51")]
#[test_action("sfn", "DeleteStateMachineAlias", checksum = "174bb160")]
#[tokio::test]
async fn sfn_alias_lifecycle() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;
    let sm = create_sm(&client, "conf-alias").await;
    let v = client
        .publish_state_machine_version()
        .state_machine_arn(&sm)
        .send()
        .await
        .unwrap()
        .state_machine_version_arn()
        .to_string();
    let alias_arn = client
        .create_state_machine_alias()
        .name("live")
        .routing_configuration(
            aws_sdk_sfn::types::RoutingConfigurationListItem::builder()
                .state_machine_version_arn(&v)
                .weight(100)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap()
        .state_machine_alias_arn()
        .to_string();
    let _ = client
        .describe_state_machine_alias()
        .state_machine_alias_arn(&alias_arn)
        .send()
        .await
        .unwrap();
    let _ = client
        .list_state_machine_aliases()
        .state_machine_arn(&sm)
        .send()
        .await
        .unwrap();
    client
        .update_state_machine_alias()
        .state_machine_alias_arn(&alias_arn)
        .description("updated")
        .send()
        .await
        .unwrap();
    client
        .delete_state_machine_alias()
        .state_machine_alias_arn(&alias_arn)
        .send()
        .await
        .unwrap();
}

#[test_action("sfn", "DescribeMapRun", checksum = "a96ec57d")]
#[test_action("sfn", "ListMapRuns", checksum = "87689e09")]
#[test_action("sfn", "UpdateMapRun", checksum = "2e31051f")]
#[tokio::test]
async fn sfn_map_run_describe_list_update_via_route() {
    // No real Map state runs in fakecloud; the routes accept a synthetic
    // ARN and the service returns empty listings or 404 on Describe.
    let server = TestServer::start().await;
    let client = server.sfn_client().await;
    let _ = client
        .list_map_runs()
        .execution_arn("arn:aws:states:us-east-1:123456789012:execution:foo:bar")
        .send()
        .await
        .unwrap();
    let res = client
        .describe_map_run()
        .map_run_arn("arn:aws:states:us-east-1:123456789012:mapRun:foo:bar:1")
        .send()
        .await;
    assert!(res.is_err(), "describe_map_run on unknown arn should fail");
    let res = client
        .update_map_run()
        .map_run_arn("arn:aws:states:us-east-1:123456789012:mapRun:foo:bar:1")
        .max_concurrency(5)
        .send()
        .await;
    assert!(res.is_err(), "update_map_run on unknown arn should fail");
}

#[test_action("sfn", "RedriveExecution", checksum = "c281a324")]
#[tokio::test]
async fn sfn_redrive_execution_via_route() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;
    // Unknown execution ARN: route is wired, response is the documented
    // error.
    let res = client
        .redrive_execution()
        .execution_arn("arn:aws:states:us-east-1:123456789012:execution:foo:bar")
        .send()
        .await;
    assert!(res.is_err());
}

async fn sfn_post_raw(server: &TestServer, target: &str, body: serde_json::Value) {
    let resp = reqwest::Client::new()
        .post(server.endpoint())
        .header("content-type", "application/x-amz-json-1.0")
        .header("x-amz-target", target)
        .header(
            "Authorization",
            "AWS4-HMAC-SHA256 Credential=test/20240101/us-east-1/states/aws4_request",
        )
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "{target} -> {:?}",
        resp.status()
    );
}

#[test_action("sfn", "StartSyncExecution", checksum = "9a48e02b")]
#[tokio::test]
async fn sfn_start_sync_execution() {
    // SDK routes StartSyncExecution to a sync-states host fakecloud
    // doesn't model; raw POST hits the documented JSON RPC route.
    let server = TestServer::start().await;
    let client = server.sfn_client().await;
    let sm = client
        .create_state_machine()
        .name("conf-sync")
        .definition(simple_definition())
        .role_arn("arn:aws:iam::123456789012:role/test-role")
        .r#type(aws_sdk_sfn::types::StateMachineType::Express)
        .send()
        .await
        .unwrap()
        .state_machine_arn()
        .to_string();
    sfn_post_raw(
        &server,
        "AWSStepFunctions.StartSyncExecution",
        serde_json::json!({"stateMachineArn": sm, "input": "{\"hello\":\"world\"}"}),
    )
    .await;
}

#[test_action("sfn", "TestState", checksum = "4e2b6e54")]
#[tokio::test]
async fn sfn_test_state() {
    let server = TestServer::start().await;
    sfn_post_raw(
        &server,
        "AWSStepFunctions.TestState",
        serde_json::json!({
            "definition": simple_definition(),
            "roleArn": "arn:aws:iam::123456789012:role/test-role",
            "input": "{}",
        }),
    )
    .await;
}

#[test_action("sfn", "ValidateStateMachineDefinition", checksum = "aab17dcd")]
#[tokio::test]
async fn sfn_validate_state_machine_definition() {
    let server = TestServer::start().await;
    let client = server.sfn_client().await;
    let _ = client
        .validate_state_machine_definition()
        .definition(simple_definition())
        .send()
        .await
        .unwrap();
}
