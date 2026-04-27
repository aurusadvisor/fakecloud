//! Application Auto Scaling service E2E.

mod helpers;

use std::collections::HashMap;

use aws_sdk_applicationautoscaling::primitives::DateTime as AwsDateTime;
use aws_sdk_applicationautoscaling::types::{
    MetricAggregationType, PolicyType, PredefinedMetricSpecification, ScalableDimension,
    ScalableTargetAction, ServiceNamespace, StepAdjustment, StepScalingPolicyConfiguration,
    SuspendedState, TargetTrackingScalingPolicyConfiguration,
};
use helpers::TestServer;

#[tokio::test]
async fn register_and_describe_scalable_target_round_trip() {
    let server = TestServer::start().await;
    let aas = server.application_autoscaling_client().await;

    let arn = aas
        .register_scalable_target()
        .service_namespace(ServiceNamespace::Ecs)
        .resource_id("service/cluster/svc")
        .scalable_dimension(ScalableDimension::EcsServiceDesiredCount)
        .min_capacity(1)
        .max_capacity(10)
        .send()
        .await
        .expect("register")
        .scalable_target_arn()
        .map(str::to_owned)
        .expect("arn");
    assert!(arn.contains(":scalable-target/"));

    let described = aas
        .describe_scalable_targets()
        .service_namespace(ServiceNamespace::Ecs)
        .send()
        .await
        .expect("describe");
    let targets = described.scalable_targets();
    assert_eq!(targets.len(), 1);
    let t = &targets[0];
    assert_eq!(t.resource_id(), "service/cluster/svc");
    assert_eq!(t.min_capacity(), 1);
    assert_eq!(t.max_capacity(), 10);
    // SDK auto-injects a default IAM role ARN; verify presence.
    assert!(t
        .role_arn()
        .contains("AWSServiceRoleForApplicationAutoScaling"));
}

#[tokio::test]
async fn register_scalable_target_update_path_only_changes_supplied_fields() {
    let server = TestServer::start().await;
    let aas = server.application_autoscaling_client().await;

    aas.register_scalable_target()
        .service_namespace(ServiceNamespace::Lambda)
        .resource_id("function:my-fn:PROVISIONED")
        .scalable_dimension(ScalableDimension::LambdaFunctionProvisionedConcurrency)
        .min_capacity(2)
        .max_capacity(20)
        .send()
        .await
        .expect("register");

    aas.register_scalable_target()
        .service_namespace(ServiceNamespace::Lambda)
        .resource_id("function:my-fn:PROVISIONED")
        .scalable_dimension(ScalableDimension::LambdaFunctionProvisionedConcurrency)
        .max_capacity(40)
        .suspended_state(
            SuspendedState::builder()
                .dynamic_scaling_in_suspended(true)
                .build(),
        )
        .send()
        .await
        .expect("update");

    let target = aas
        .describe_scalable_targets()
        .service_namespace(ServiceNamespace::Lambda)
        .send()
        .await
        .expect("describe")
        .scalable_targets()
        .first()
        .cloned()
        .expect("target");
    assert_eq!(target.min_capacity(), 2);
    assert_eq!(target.max_capacity(), 40);
    assert_eq!(
        target
            .suspended_state()
            .and_then(|s| s.dynamic_scaling_in_suspended()),
        Some(true)
    );
}

#[tokio::test]
async fn deregister_scalable_target_cascades_to_policies_and_actions() {
    let server = TestServer::start().await;
    let aas = server.application_autoscaling_client().await;

    aas.register_scalable_target()
        .service_namespace(ServiceNamespace::Dynamodb)
        .resource_id("table/orders")
        .scalable_dimension(ScalableDimension::DynamoDbTableReadCapacityUnits)
        .min_capacity(5)
        .max_capacity(50)
        .send()
        .await
        .expect("register");

    aas.put_scaling_policy()
        .service_namespace(ServiceNamespace::Dynamodb)
        .resource_id("table/orders")
        .scalable_dimension(ScalableDimension::DynamoDbTableReadCapacityUnits)
        .policy_name("read-target")
        .policy_type(PolicyType::TargetTrackingScaling)
        .target_tracking_scaling_policy_configuration(
            TargetTrackingScalingPolicyConfiguration::builder()
                .target_value(70.0)
                .predefined_metric_specification(
                    PredefinedMetricSpecification::builder()
                        .predefined_metric_type(
                            aws_sdk_applicationautoscaling::types::MetricType::DynamoDbReadCapacityUtilization,
                        )
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("policy");

    aas.put_scheduled_action()
        .service_namespace(ServiceNamespace::Dynamodb)
        .resource_id("table/orders")
        .scalable_dimension(ScalableDimension::DynamoDbTableReadCapacityUnits)
        .scheduled_action_name("nightly-scale")
        .schedule("cron(0 22 * * ? *)")
        .scalable_target_action(
            ScalableTargetAction::builder()
                .min_capacity(2)
                .max_capacity(8)
                .build(),
        )
        .send()
        .await
        .expect("scheduled");

    aas.deregister_scalable_target()
        .service_namespace(ServiceNamespace::Dynamodb)
        .resource_id("table/orders")
        .scalable_dimension(ScalableDimension::DynamoDbTableReadCapacityUnits)
        .send()
        .await
        .expect("deregister");

    let policies = aas
        .describe_scaling_policies()
        .service_namespace(ServiceNamespace::Dynamodb)
        .send()
        .await
        .expect("policies")
        .scaling_policies()
        .len();
    let actions = aas
        .describe_scheduled_actions()
        .service_namespace(ServiceNamespace::Dynamodb)
        .send()
        .await
        .expect("actions")
        .scheduled_actions()
        .len();
    assert_eq!(policies, 0, "policies cascade-delete with target");
    assert_eq!(actions, 0, "scheduled actions cascade-delete with target");
}

#[tokio::test]
async fn put_scaling_policy_step_then_describe_and_delete() {
    let server = TestServer::start().await;
    let aas = server.application_autoscaling_client().await;

    aas.register_scalable_target()
        .service_namespace(ServiceNamespace::Ecs)
        .resource_id("service/cluster/api")
        .scalable_dimension(ScalableDimension::EcsServiceDesiredCount)
        .min_capacity(1)
        .max_capacity(20)
        .send()
        .await
        .expect("register");

    let policy_arn = aas
        .put_scaling_policy()
        .service_namespace(ServiceNamespace::Ecs)
        .resource_id("service/cluster/api")
        .scalable_dimension(ScalableDimension::EcsServiceDesiredCount)
        .policy_name("scale-out")
        .policy_type(PolicyType::StepScaling)
        .step_scaling_policy_configuration(
            StepScalingPolicyConfiguration::builder()
                .adjustment_type(
                    aws_sdk_applicationautoscaling::types::AdjustmentType::ChangeInCapacity,
                )
                .metric_aggregation_type(MetricAggregationType::Average)
                .step_adjustments(
                    StepAdjustment::builder()
                        .scaling_adjustment(2)
                        .metric_interval_lower_bound(0.0)
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .send()
        .await
        .expect("put policy")
        .policy_arn()
        .to_owned();
    assert!(policy_arn.contains(":scalingPolicy:"));

    let policies = aas
        .describe_scaling_policies()
        .service_namespace(ServiceNamespace::Ecs)
        .send()
        .await
        .expect("describe")
        .scaling_policies()
        .to_vec();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].policy_name(), "scale-out");
    assert_eq!(policies[0].policy_type(), &PolicyType::StepScaling);

    aas.delete_scaling_policy()
        .service_namespace(ServiceNamespace::Ecs)
        .resource_id("service/cluster/api")
        .scalable_dimension(ScalableDimension::EcsServiceDesiredCount)
        .policy_name("scale-out")
        .send()
        .await
        .expect("delete policy");
    assert_eq!(
        aas.describe_scaling_policies()
            .service_namespace(ServiceNamespace::Ecs)
            .send()
            .await
            .expect("describe2")
            .scaling_policies()
            .len(),
        0
    );
}

#[tokio::test]
async fn put_scheduled_action_lifecycle() {
    let server = TestServer::start().await;
    let aas = server.application_autoscaling_client().await;

    aas.register_scalable_target()
        .service_namespace(ServiceNamespace::Ecs)
        .resource_id("service/cluster/web")
        .scalable_dimension(ScalableDimension::EcsServiceDesiredCount)
        .min_capacity(1)
        .max_capacity(10)
        .send()
        .await
        .expect("register");

    aas.put_scheduled_action()
        .service_namespace(ServiceNamespace::Ecs)
        .resource_id("service/cluster/web")
        .scalable_dimension(ScalableDimension::EcsServiceDesiredCount)
        .scheduled_action_name("morning-warmup")
        .schedule("cron(0 7 * * ? *)")
        .timezone("America/New_York")
        .scalable_target_action(
            ScalableTargetAction::builder()
                .min_capacity(3)
                .max_capacity(10)
                .build(),
        )
        .send()
        .await
        .expect("put");

    let actions = aas
        .describe_scheduled_actions()
        .service_namespace(ServiceNamespace::Ecs)
        .send()
        .await
        .expect("describe")
        .scheduled_actions()
        .to_vec();
    assert_eq!(actions.len(), 1);
    let a = &actions[0];
    assert_eq!(a.scheduled_action_name(), "morning-warmup");
    assert_eq!(a.timezone(), Some("America/New_York"));

    aas.delete_scheduled_action()
        .service_namespace(ServiceNamespace::Ecs)
        .resource_id("service/cluster/web")
        .scalable_dimension(ScalableDimension::EcsServiceDesiredCount)
        .scheduled_action_name("morning-warmup")
        .send()
        .await
        .expect("delete");
    assert_eq!(
        aas.describe_scheduled_actions()
            .service_namespace(ServiceNamespace::Ecs)
            .send()
            .await
            .expect("d2")
            .scheduled_actions()
            .len(),
        0
    );
}

#[tokio::test]
async fn put_scaling_policy_without_target_returns_object_not_found() {
    let server = TestServer::start().await;
    let aas = server.application_autoscaling_client().await;

    let err = aas
        .put_scaling_policy()
        .service_namespace(ServiceNamespace::Ecs)
        .resource_id("service/cluster/no-target")
        .scalable_dimension(ScalableDimension::EcsServiceDesiredCount)
        .policy_name("orphan")
        .policy_type(PolicyType::StepScaling)
        .step_scaling_policy_configuration(
            StepScalingPolicyConfiguration::builder()
                .adjustment_type(
                    aws_sdk_applicationautoscaling::types::AdjustmentType::ChangeInCapacity,
                )
                .build(),
        )
        .send()
        .await
        .expect_err("must error without a target");
    assert!(format!("{err:?}").contains("ObjectNotFound"));
}

#[tokio::test]
async fn deregister_unknown_target_returns_object_not_found() {
    let server = TestServer::start().await;
    let aas = server.application_autoscaling_client().await;

    let err = aas
        .deregister_scalable_target()
        .service_namespace(ServiceNamespace::Ecs)
        .resource_id("service/cluster/missing")
        .scalable_dimension(ScalableDimension::EcsServiceDesiredCount)
        .send()
        .await
        .expect_err("missing target");
    assert!(format!("{err:?}").contains("ObjectNotFound"));
}

#[tokio::test]
async fn describe_scaling_activities_returns_empty_initially() {
    let server = TestServer::start().await;
    let aas = server.application_autoscaling_client().await;

    let activities = aas
        .describe_scaling_activities()
        .service_namespace(ServiceNamespace::Ecs)
        .send()
        .await
        .expect("activities")
        .scaling_activities()
        .len();
    assert_eq!(activities, 0);
}

#[tokio::test]
async fn get_predictive_scaling_forecast_requires_predictive_policy() {
    let server = TestServer::start().await;
    let aas = server.application_autoscaling_client().await;

    aas.register_scalable_target()
        .service_namespace(ServiceNamespace::Ecs)
        .resource_id("service/cluster/pred")
        .scalable_dimension(ScalableDimension::EcsServiceDesiredCount)
        .min_capacity(1)
        .max_capacity(20)
        .send()
        .await
        .expect("register");

    aas.put_scaling_policy()
        .service_namespace(ServiceNamespace::Ecs)
        .resource_id("service/cluster/pred")
        .scalable_dimension(ScalableDimension::EcsServiceDesiredCount)
        .policy_name("step-only")
        .policy_type(PolicyType::StepScaling)
        .step_scaling_policy_configuration(
            StepScalingPolicyConfiguration::builder()
                .adjustment_type(
                    aws_sdk_applicationautoscaling::types::AdjustmentType::ChangeInCapacity,
                )
                .build(),
        )
        .send()
        .await
        .expect("step");
    let now = AwsDateTime::from_secs(1_700_000_000);
    let later = AwsDateTime::from_secs(1_700_000_000 + 86_400);
    let err = aas
        .get_predictive_scaling_forecast()
        .service_namespace(ServiceNamespace::Ecs)
        .resource_id("service/cluster/pred")
        .scalable_dimension(ScalableDimension::EcsServiceDesiredCount)
        .policy_name("step-only")
        .start_time(now)
        .end_time(later)
        .send()
        .await
        .expect_err("not predictive");
    assert!(format!("{err:?}").contains("ValidationException"));
}

#[tokio::test]
async fn tag_untag_list_tags_round_trip() {
    let server = TestServer::start().await;
    let aas = server.application_autoscaling_client().await;

    let arn = aas
        .register_scalable_target()
        .service_namespace(ServiceNamespace::Ecs)
        .resource_id("service/cluster/tagme")
        .scalable_dimension(ScalableDimension::EcsServiceDesiredCount)
        .min_capacity(1)
        .max_capacity(5)
        .send()
        .await
        .expect("register")
        .scalable_target_arn()
        .map(str::to_owned)
        .expect("arn");

    let mut tags = HashMap::new();
    tags.insert("env".to_string(), "prod".to_string());
    tags.insert("team".to_string(), "sre".to_string());
    aas.tag_resource()
        .resource_arn(&arn)
        .set_tags(Some(tags))
        .send()
        .await
        .expect("tag");

    let listed = aas
        .list_tags_for_resource()
        .resource_arn(&arn)
        .send()
        .await
        .expect("list")
        .tags()
        .cloned()
        .unwrap_or_default();
    assert_eq!(listed.get("env").map(String::as_str), Some("prod"));
    assert_eq!(listed.get("team").map(String::as_str), Some("sre"));

    aas.untag_resource()
        .resource_arn(&arn)
        .tag_keys("env")
        .send()
        .await
        .expect("untag");

    let post = aas
        .list_tags_for_resource()
        .resource_arn(&arn)
        .send()
        .await
        .expect("list2")
        .tags()
        .cloned()
        .unwrap_or_default();
    assert!(!post.contains_key("env"));
    assert_eq!(post.get("team").map(String::as_str), Some("sre"));
}

#[tokio::test]
async fn tag_unknown_resource_returns_object_not_found() {
    let server = TestServer::start().await;
    let aas = server.application_autoscaling_client().await;
    let mut tags = HashMap::new();
    tags.insert("k".to_string(), "v".to_string());

    let err = aas
        .tag_resource()
        .resource_arn(
            "arn:aws:application-autoscaling:us-east-1:123456789012:scalable-target/0000000000",
        )
        .set_tags(Some(tags))
        .send()
        .await
        .expect_err("missing arn");
    assert!(format!("{err:?}").contains("ObjectNotFound"));
}
