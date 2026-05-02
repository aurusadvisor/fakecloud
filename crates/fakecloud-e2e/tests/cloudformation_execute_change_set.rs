mod helpers;

use helpers::TestServer;

#[tokio::test]
async fn execute_change_set_adds_and_removes_resources() {
    let server = TestServer::start().await;
    let cf = server.cloudformation_client().await;
    let sqs = server.sqs_client().await;

    let initial_template = r#"{
        "Resources": {
            "QueueA": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": "cs-queue-a"}
            }
        }
    }"#;

    cf.create_stack()
        .stack_name("cs-stack")
        .template_body(initial_template)
        .send()
        .await
        .unwrap();

    // Verify the initial queue exists
    let queues = sqs.list_queues().send().await.unwrap();
    assert!(
        queues.queue_urls().iter().any(|u| u.contains("cs-queue-a")),
        "initial queue should exist after CreateStack: {:?}",
        queues.queue_urls()
    );

    // Change set: add a second queue, drop the first.
    let new_template = r#"{
        "Resources": {
            "QueueB": {
                "Type": "AWS::SQS::Queue",
                "Properties": {"QueueName": "cs-queue-b"}
            }
        }
    }"#;

    let cs = cf
        .create_change_set()
        .stack_name("cs-stack")
        .change_set_name("cs1")
        .template_body(new_template)
        .send()
        .await
        .unwrap();
    let cs_id = cs.id().unwrap().to_string();

    // DescribeChangeSet should reflect the diff: Add QueueB, Remove QueueA.
    let describe = cf
        .describe_change_set()
        .change_set_name(&cs_id)
        .send()
        .await
        .unwrap();
    let changes = describe.changes();
    assert_eq!(changes.len(), 2, "expected 2 changes, got {changes:?}");
    let actions: Vec<String> = changes
        .iter()
        .filter_map(|c| c.resource_change())
        .map(|rc| {
            rc.action()
                .map(|a| a.as_str().to_string())
                .unwrap_or_default()
        })
        .collect();
    assert!(
        actions.contains(&"Add".to_string()),
        "expected Add action: {actions:?}"
    );
    assert!(
        actions.contains(&"Remove".to_string()),
        "expected Remove action: {actions:?}"
    );
    assert_eq!(
        describe.execution_status().map(|s| s.as_str()),
        Some("AVAILABLE"),
    );

    // Execute and verify state
    cf.execute_change_set()
        .change_set_name(&cs_id)
        .send()
        .await
        .unwrap();

    let queues = sqs.list_queues().send().await.unwrap();
    let urls: Vec<&str> = queues.queue_urls().iter().map(|s| s.as_str()).collect();
    assert!(
        urls.iter().any(|u| u.contains("cs-queue-b")),
        "queue-b should be created, got: {urls:?}"
    );
    assert!(
        !urls.iter().any(|u| u.contains("cs-queue-a")),
        "queue-a should be removed, got: {urls:?}"
    );

    // Stack status should be UPDATE_COMPLETE
    let stacks = cf
        .describe_stacks()
        .stack_name("cs-stack")
        .send()
        .await
        .unwrap();
    assert_eq!(
        stacks.stacks()[0]
            .stack_status()
            .map(|s| s.as_str().to_string()),
        Some("UPDATE_COMPLETE".to_string()),
    );

    // ChangeSet ExecutionStatus should be EXECUTE_COMPLETE
    let post = cf
        .describe_change_set()
        .change_set_name(&cs_id)
        .send()
        .await
        .unwrap();
    assert_eq!(
        post.execution_status().map(|s| s.as_str()),
        Some("EXECUTE_COMPLETE"),
    );
}

#[tokio::test]
async fn execute_change_set_modify_only() {
    let server = TestServer::start().await;
    let cf = server.cloudformation_client().await;
    let sns = server.sns_client().await;

    let template_v1 = r#"{
        "Resources": {
            "Topic1": {
                "Type": "AWS::SNS::Topic",
                "Properties": {"TopicName": "cs-mod-topic"}
            }
        }
    }"#;

    cf.create_stack()
        .stack_name("cs-mod-stack")
        .template_body(template_v1)
        .send()
        .await
        .unwrap();

    // Same template, different DisplayName so the diff is Modify.
    let template_v2 = r#"{
        "Resources": {
            "Topic1": {
                "Type": "AWS::SNS::Topic",
                "Properties": {"TopicName": "cs-mod-topic", "DisplayName": "v2"}
            }
        }
    }"#;

    let cs = cf
        .create_change_set()
        .stack_name("cs-mod-stack")
        .change_set_name("modify-cs")
        .template_body(template_v2)
        .send()
        .await
        .unwrap();
    let cs_id = cs.id().unwrap().to_string();

    let describe = cf
        .describe_change_set()
        .change_set_name(&cs_id)
        .send()
        .await
        .unwrap();
    let changes = describe.changes();
    assert_eq!(changes.len(), 1);
    assert_eq!(
        changes[0]
            .resource_change()
            .and_then(|rc| rc.action())
            .map(|a| a.as_str().to_string()),
        Some("Modify".to_string()),
    );

    cf.execute_change_set()
        .change_set_name(&cs_id)
        .send()
        .await
        .unwrap();

    // Topic still exists
    let topics = sns.list_topics().send().await.unwrap();
    assert!(topics
        .topics()
        .iter()
        .any(|t| t.topic_arn().is_some_and(|a| a.contains("cs-mod-topic"))));

    let stacks = cf
        .describe_stacks()
        .stack_name("cs-mod-stack")
        .send()
        .await
        .unwrap();
    assert_eq!(
        stacks.stacks()[0]
            .stack_status()
            .map(|s| s.as_str().to_string()),
        Some("UPDATE_COMPLETE".to_string()),
    );
}
