//! CloudFormation provisioner for AWS::ApiGateway::* (BB9). Exercises
//! a RestApi with a child Resource, a Method+Integration, a Deployment
//! that inlines a Stage, plus a UsagePlan/ApiKey. Asserts via the real
//! API Gateway v1 SDK so the test only passes when both the CFN side
//! and the runtime API GW side agree on stored shape.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Api": {
      "Type": "AWS::ApiGateway::RestApi",
      "Properties": {
        "Name": "cfn-api",
        "Description": "from cfn",
        "EndpointConfiguration": {"Types": ["REGIONAL"]}
      }
    },
    "Pets": {
      "Type": "AWS::ApiGateway::Resource",
      "Properties": {
        "RestApiId": {"Ref": "Api"},
        "ParentId": {"Fn::GetAtt": ["Api", "RootResourceId"]},
        "PathPart": "pets"
      }
    },
    "GetPets": {
      "Type": "AWS::ApiGateway::Method",
      "Properties": {
        "RestApiId": {"Ref": "Api"},
        "ResourceId": {"Ref": "Pets"},
        "HttpMethod": "GET",
        "AuthorizationType": "NONE",
        "Integration": {
          "Type": "MOCK",
          "PassthroughBehavior": "WHEN_NO_MATCH",
          "RequestTemplates": {"application/json": "{\"statusCode\":200}"}
        }
      }
    },
    "Deploy": {
      "Type": "AWS::ApiGateway::Deployment",
      "DependsOn": "GetPets",
      "Properties": {
        "RestApiId": {"Ref": "Api"},
        "StageName": "prod"
      }
    },
    "Plan": {
      "Type": "AWS::ApiGateway::UsagePlan",
      "Properties": {
        "UsagePlanName": "cfn-plan",
        "Description": "test plan",
        "Throttle": {"BurstLimit": 100, "RateLimit": 50}
      }
    },
    "Key": {
      "Type": "AWS::ApiGateway::ApiKey",
      "Properties": {
        "Name": "cfn-key",
        "Enabled": true
      }
    }
  },
  "Outputs": {
    "ApiId": {"Value": {"Ref": "Api"}},
    "RootId": {"Value": {"Fn::GetAtt": ["Api", "RootResourceId"]}},
    "PetsId": {"Value": {"Ref": "Pets"}},
    "PlanId": {"Value": {"Ref": "Plan"}},
    "KeyId": {"Value": {"Ref": "Key"}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_apigateway_v1() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let agw = server.apigateway_client().await;

    cfn.create_stack()
        .stack_name("apigw-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("apigw-stack")
        .send()
        .await
        .expect("describe_stacks");
    let stack = described.stacks().first().expect("stack present");
    assert_eq!(stack.stack_status().unwrap().as_str(), "CREATE_COMPLETE");

    let outputs: std::collections::HashMap<&str, &str> = stack
        .outputs()
        .iter()
        .filter_map(|o| Some((o.output_key()?, o.output_value()?)))
        .collect();
    let api_id = outputs.get("ApiId").copied().expect("ApiId output");
    let root_id = outputs.get("RootId").copied().expect("RootId output");
    let pets_id = outputs.get("PetsId").copied().expect("PetsId output");
    let plan_id = outputs.get("PlanId").copied().expect("PlanId output");
    let key_id = outputs.get("KeyId").copied().expect("KeyId output");

    // Verify RestApi via SDK GetRestApi.
    let api = agw
        .get_rest_api()
        .rest_api_id(api_id)
        .send()
        .await
        .expect("get_rest_api");
    assert_eq!(api.name(), Some("cfn-api"));
    assert_eq!(api.description(), Some("from cfn"));
    assert_eq!(api.root_resource_id(), Some(root_id));

    // Verify Resource via GetResources.
    let resources = agw
        .get_resources()
        .rest_api_id(api_id)
        .send()
        .await
        .expect("get_resources");
    let pets = resources
        .items()
        .iter()
        .find(|r| r.id() == Some(pets_id))
        .expect("pets resource present");
    assert_eq!(pets.path_part(), Some("pets"));
    assert_eq!(pets.path(), Some("/pets"));

    // Verify Method + Integration.
    let method = agw
        .get_method()
        .rest_api_id(api_id)
        .resource_id(pets_id)
        .http_method("GET")
        .send()
        .await
        .expect("get_method");
    assert_eq!(method.http_method(), Some("GET"));
    assert_eq!(method.authorization_type(), Some("NONE"));

    let integration = agw
        .get_integration()
        .rest_api_id(api_id)
        .resource_id(pets_id)
        .http_method("GET")
        .send()
        .await
        .expect("get_integration");
    assert_eq!(integration.r#type().map(|t| t.as_str()), Some("MOCK"));

    // Verify Stage from inline Deployment.StageName.
    let stage = agw
        .get_stage()
        .rest_api_id(api_id)
        .stage_name("prod")
        .send()
        .await
        .expect("get_stage");
    assert_eq!(stage.stage_name(), Some("prod"));
    assert!(!stage.deployment_id().unwrap_or_default().is_empty());

    // Verify UsagePlan.
    let plan = agw
        .get_usage_plan()
        .usage_plan_id(plan_id)
        .send()
        .await
        .expect("get_usage_plan");
    assert_eq!(plan.name(), Some("cfn-plan"));
    let throttle = plan.throttle().expect("throttle present");
    assert_eq!(throttle.burst_limit(), 100);
    assert!((throttle.rate_limit() - 50.0).abs() < f64::EPSILON);

    // Verify ApiKey.
    let key = agw
        .get_api_key()
        .api_key(key_id)
        .send()
        .await
        .expect("get_api_key");
    assert_eq!(key.name(), Some("cfn-key"));
    assert!(key.enabled());

    // Tear down.
    cfn.delete_stack()
        .stack_name("apigw-stack")
        .send()
        .await
        .expect("delete_stack");

    let after = agw.get_rest_api().rest_api_id(api_id).send().await;
    assert!(after.is_err(), "api should be gone after delete");
}
