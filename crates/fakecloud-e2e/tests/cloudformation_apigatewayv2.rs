//! CloudFormation provisioner for AWS::ApiGatewayV2::* (BB10). Provisions
//! an HTTP API + Integration + Route + Stage + Authorizer (JWT) and
//! asserts via the real apigatewayv2 SDK.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Api": {
      "Type": "AWS::ApiGatewayV2::Api",
      "Properties": {
        "Name": "cfn-http-api",
        "ProtocolType": "HTTP",
        "Description": "from cfn",
        "CorsConfiguration": {
          "AllowOrigins": ["https://example.com"],
          "AllowMethods": ["GET","POST"]
        }
      }
    },
    "Integ": {
      "Type": "AWS::ApiGatewayV2::Integration",
      "Properties": {
        "ApiId": {"Ref": "Api"},
        "IntegrationType": "HTTP_PROXY",
        "IntegrationUri": "https://example.com/upstream",
        "PayloadFormatVersion": "2.0"
      }
    },
    "GetPets": {
      "Type": "AWS::ApiGatewayV2::Route",
      "Properties": {
        "ApiId": {"Ref": "Api"},
        "RouteKey": "GET /pets",
        "Target": {"Fn::Join": ["/", ["integrations", {"Ref": "Integ"}]]},
        "AuthorizationType": "NONE"
      }
    },
    "Deploy": {
      "Type": "AWS::ApiGatewayV2::Deployment",
      "DependsOn": "GetPets",
      "Properties": {
        "ApiId": {"Ref": "Api"},
        "Description": "first"
      }
    },
    "ProdStage": {
      "Type": "AWS::ApiGatewayV2::Stage",
      "Properties": {
        "ApiId": {"Ref": "Api"},
        "StageName": "prod",
        "DeploymentId": {"Ref": "Deploy"},
        "AutoDeploy": false
      }
    },
    "JwtAuth": {
      "Type": "AWS::ApiGatewayV2::Authorizer",
      "Properties": {
        "ApiId": {"Ref": "Api"},
        "Name": "jwt-auth",
        "AuthorizerType": "JWT",
        "IdentitySource": ["$request.header.Authorization"],
        "JwtConfiguration": {
          "Audience": ["my-aud"],
          "Issuer": "https://issuer.example.com"
        }
      }
    }
  },
  "Outputs": {
    "ApiId": {"Value": {"Ref": "Api"}},
    "IntegId": {"Value": {"Ref": "Integ"}},
    "RouteId": {"Value": {"Ref": "GetPets"}},
    "DeployId": {"Value": {"Ref": "Deploy"}},
    "AuthorizerId": {"Value": {"Ref": "JwtAuth"}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_apigatewayv2() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let agw = aws_sdk_apigatewayv2::Client::new(&server.aws_config().await);

    cfn.create_stack()
        .stack_name("apigwv2-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("apigwv2-stack")
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
    let api_id = outputs.get("ApiId").copied().expect("ApiId");
    let integ_id = outputs.get("IntegId").copied().expect("IntegId");
    let route_id = outputs.get("RouteId").copied().expect("RouteId");
    let deploy_id = outputs.get("DeployId").copied().expect("DeployId");
    let authz_id = outputs.get("AuthorizerId").copied().expect("AuthorizerId");

    let api = agw.get_api().api_id(api_id).send().await.expect("get_api");
    assert_eq!(api.name(), Some("cfn-http-api"));
    assert_eq!(api.protocol_type().map(|p| p.as_str()), Some("HTTP"));
    let cors = api.cors_configuration().expect("cors present");
    assert!(cors
        .allow_origins()
        .iter()
        .any(|o| o == "https://example.com"));

    let integ = agw
        .get_integration()
        .api_id(api_id)
        .integration_id(integ_id)
        .send()
        .await
        .expect("get_integration");
    assert_eq!(
        integ.integration_type().map(|t| t.as_str()),
        Some("HTTP_PROXY")
    );
    assert_eq!(
        integ.integration_uri(),
        Some("https://example.com/upstream")
    );

    let route = agw
        .get_route()
        .api_id(api_id)
        .route_id(route_id)
        .send()
        .await
        .expect("get_route");
    assert_eq!(route.route_key(), Some("GET /pets"));

    let stage = agw
        .get_stage()
        .api_id(api_id)
        .stage_name("prod")
        .send()
        .await
        .expect("get_stage");
    assert_eq!(stage.stage_name(), Some("prod"));
    assert_eq!(stage.deployment_id(), Some(deploy_id));

    let auth = agw
        .get_authorizer()
        .api_id(api_id)
        .authorizer_id(authz_id)
        .send()
        .await
        .expect("get_authorizer");
    assert_eq!(auth.name(), Some("jwt-auth"));
    assert_eq!(auth.authorizer_type().map(|t| t.as_str()), Some("JWT"));
    let jwt = auth.jwt_configuration().expect("jwt cfg");
    assert!(jwt.audience().iter().any(|a| a == "my-aud"));

    cfn.delete_stack()
        .stack_name("apigwv2-stack")
        .send()
        .await
        .expect("delete_stack");

    let after = agw.get_api().api_id(api_id).send().await;
    assert!(after.is_err(), "api should be gone after delete");
}
