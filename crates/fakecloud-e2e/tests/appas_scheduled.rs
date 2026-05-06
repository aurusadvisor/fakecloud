//! Application Auto Scaling scheduled-action executor E2E.
//!
//! Verifies the scheduled-action executor:
//!   - fires a `cron(* * * * ? *)` schedule on the next admin tick
//!   - moves the linked DynamoDB table's read capacity up to the
//!     action's `ScalableTargetAction.MinCapacity`
//!   - records a `ScalingActivity` whose cause references the scheduled
//!     action by name and schedule

mod helpers;

use aws_sdk_applicationautoscaling::types::{
    ScalableDimension, ScalableTargetAction, ServiceNamespace,
};
use aws_sdk_dynamodb::types::{
    AttributeDefinition as DdbAttributeDefinition, BillingMode, KeySchemaElement,
    KeyType as DdbKeyType, ProvisionedThroughput, ScalarAttributeType,
};
use helpers::TestServer;

async fn create_provisioned_table(
    ddb: &aws_sdk_dynamodb::Client,
    name: &str,
    read: i64,
    write: i64,
) {
    ddb.create_table()
        .table_name(name)
        .billing_mode(BillingMode::Provisioned)
        .attribute_definitions(
            DdbAttributeDefinition::builder()
                .attribute_name("pk")
                .attribute_type(ScalarAttributeType::S)
                .build()
                .unwrap(),
        )
        .key_schema(
            KeySchemaElement::builder()
                .attribute_name("pk")
                .key_type(DdbKeyType::Hash)
                .build()
                .unwrap(),
        )
        .provisioned_throughput(
            ProvisionedThroughput::builder()
                .read_capacity_units(read)
                .write_capacity_units(write)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("create table");
}

async fn force_scheduled_tick(server: &TestServer) -> usize {
    let url = format!(
        "{}/_fakecloud/application-autoscaling/scheduled-tick",
        server.endpoint()
    );
    let resp = reqwest::Client::new()
        .post(&url)
        .send()
        .await
        .expect("admin scheduled-tick");
    let body: serde_json::Value = resp.json().await.expect("json");
    body["fired"].as_u64().unwrap_or(0) as usize
}

#[tokio::test]
async fn cron_scheduled_action_bumps_dynamodb_capacity() {
    let server = TestServer::start().await;
    let aas = server.application_autoscaling_client().await;
    let ddb = server.dynamodb_client().await;

    create_provisioned_table(&ddb, "sched-orders", 5, 5).await;

    aas.register_scalable_target()
        .service_namespace(ServiceNamespace::Dynamodb)
        .resource_id("table/sched-orders")
        .scalable_dimension(ScalableDimension::DynamoDbTableReadCapacityUnits)
        .min_capacity(1)
        .max_capacity(100)
        .send()
        .await
        .expect("register");

    aas.put_scheduled_action()
        .service_namespace(ServiceNamespace::Dynamodb)
        .resource_id("table/sched-orders")
        .scalable_dimension(ScalableDimension::DynamoDbTableReadCapacityUnits)
        .scheduled_action_name("warm-up")
        .schedule("cron(* * * * ? *)")
        .scalable_target_action(
            ScalableTargetAction::builder()
                .min_capacity(10)
                .max_capacity(50)
                .build(),
        )
        .send()
        .await
        .expect("put scheduled action");

    let fired = force_scheduled_tick(&server).await;
    assert_eq!(fired, 1, "cron(* * * * ? *) must fire on first tick");

    // The DynamoDB table's read capacity must be bumped to >= 10.
    let described = ddb
        .describe_table()
        .table_name("sched-orders")
        .send()
        .await
        .expect("describe");
    let read_now = described
        .table()
        .and_then(|t| t.provisioned_throughput())
        .and_then(|p| p.read_capacity_units())
        .unwrap_or(0);
    assert!(
        read_now >= 10,
        "expected read capacity >= 10 after scheduled fire, got {read_now}"
    );
    // Write capacity untouched.
    let write_now = described
        .table()
        .and_then(|t| t.provisioned_throughput())
        .and_then(|p| p.write_capacity_units())
        .unwrap_or(0);
    assert_eq!(write_now, 5);

    // The scalable target itself must reflect the new bounds.
    let target = aas
        .describe_scalable_targets()
        .service_namespace(ServiceNamespace::Dynamodb)
        .send()
        .await
        .expect("describe target")
        .scalable_targets()
        .first()
        .cloned()
        .expect("target");
    assert_eq!(target.min_capacity(), 10);
    assert_eq!(target.max_capacity(), 50);

    // DescribeScalingActivities must surface the scheduled-action fire.
    let activities = aas
        .describe_scaling_activities()
        .service_namespace(ServiceNamespace::Dynamodb)
        .resource_id("table/sched-orders")
        .scalable_dimension(ScalableDimension::DynamoDbTableReadCapacityUnits)
        .send()
        .await
        .expect("activities")
        .scaling_activities()
        .to_vec();
    assert!(
        activities
            .iter()
            .any(|a| a.cause().contains("warm-up") && a.cause().contains("cron(* * * * ? *)")),
        "expected scaling activity from scheduled action, got {activities:?}"
    );

    // Re-tick within the same minute must NOT re-fire (per-minute dedupe).
    let fired_again = force_scheduled_tick(&server).await;
    assert_eq!(
        fired_again, 0,
        "cron schedule must not double-fire within the same wall-clock minute"
    );
}

#[tokio::test]
async fn at_scheduled_action_fires_once() {
    let server = TestServer::start().await;
    let aas = server.application_autoscaling_client().await;
    let ddb = server.dynamodb_client().await;

    create_provisioned_table(&ddb, "sched-once", 5, 5).await;
    aas.register_scalable_target()
        .service_namespace(ServiceNamespace::Dynamodb)
        .resource_id("table/sched-once")
        .scalable_dimension(ScalableDimension::DynamoDbTableReadCapacityUnits)
        .min_capacity(1)
        .max_capacity(100)
        .send()
        .await
        .expect("register");

    // Schedule for the past so the first tick fires immediately.
    aas.put_scheduled_action()
        .service_namespace(ServiceNamespace::Dynamodb)
        .resource_id("table/sched-once")
        .scalable_dimension(ScalableDimension::DynamoDbTableReadCapacityUnits)
        .scheduled_action_name("one-shot")
        .schedule("at(2020-01-01T00:00:00)")
        .scalable_target_action(
            ScalableTargetAction::builder()
                .min_capacity(20)
                .max_capacity(60)
                .build(),
        )
        .send()
        .await
        .expect("put scheduled action");

    assert_eq!(force_scheduled_tick(&server).await, 1, "must fire once");
    assert_eq!(
        force_scheduled_tick(&server).await,
        0,
        "at(...) schedule must not re-fire after first match"
    );

    let described = ddb
        .describe_table()
        .table_name("sched-once")
        .send()
        .await
        .expect("describe");
    let read_now = described
        .table()
        .and_then(|t| t.provisioned_throughput())
        .and_then(|p| p.read_capacity_units())
        .unwrap_or(0);
    assert!(read_now >= 20, "expected >= 20, got {read_now}");
}

#[tokio::test]
async fn unparseable_schedule_silently_does_not_fire() {
    let server = TestServer::start().await;
    let aas = server.application_autoscaling_client().await;
    let ddb = server.dynamodb_client().await;
    create_provisioned_table(&ddb, "sched-bad", 5, 5).await;
    aas.register_scalable_target()
        .service_namespace(ServiceNamespace::Dynamodb)
        .resource_id("table/sched-bad")
        .scalable_dimension(ScalableDimension::DynamoDbTableReadCapacityUnits)
        .min_capacity(1)
        .max_capacity(100)
        .send()
        .await
        .expect("register");

    // Range expressions are not supported by our cron grammar — must
    // silently never fire rather than crash the executor.
    aas.put_scheduled_action()
        .service_namespace(ServiceNamespace::Dynamodb)
        .resource_id("table/sched-bad")
        .scalable_dimension(ScalableDimension::DynamoDbTableReadCapacityUnits)
        .scheduled_action_name("ranges-not-supported")
        .schedule("cron(0-30 * * * ? *)")
        .scalable_target_action(ScalableTargetAction::builder().min_capacity(99).build())
        .send()
        .await
        .expect("put");

    assert_eq!(force_scheduled_tick(&server).await, 0);
    let read_now = ddb
        .describe_table()
        .table_name("sched-bad")
        .send()
        .await
        .expect("describe")
        .table()
        .and_then(|t| t.provisioned_throughput())
        .and_then(|p| p.read_capacity_units())
        .unwrap_or(0);
    assert_eq!(read_now, 5, "capacity must not change for unsupported cron");
}
