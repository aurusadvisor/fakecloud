//! CloudFormation provisioner for AWS::SecretsManager::* extras (BB13).
//! Provisions a Secret + RotationSchedule + ResourcePolicy and asserts via
//! the real Secrets Manager SDK.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Secret": {
      "Type": "AWS::SecretsManager::Secret",
      "Properties": {
        "Name": "cfn-rot-secret",
        "Description": "for rotation",
        "SecretString": "{\"username\":\"admin\",\"password\":\"hunter2\"}"
      }
    },
    "Schedule": {
      "Type": "AWS::SecretsManager::RotationSchedule",
      "Properties": {
        "SecretId": {"Ref": "Secret"},
        "RotationLambdaARN": "arn:aws:lambda:us-east-1:000000000000:function:rotator",
        "RotationRules": {"AutomaticallyAfterDays": 30}
      }
    },
    "Policy": {
      "Type": "AWS::SecretsManager::ResourcePolicy",
      "Properties": {
        "SecretId": {"Ref": "Secret"},
        "ResourcePolicy": {
          "Version": "2012-10-17",
          "Statement": [{
            "Effect": "Deny",
            "Principal": "*",
            "Action": "secretsmanager:DeleteSecret",
            "Resource": "*"
          }]
        }
      }
    }
  },
  "Outputs": {
    "SecretArn": {"Value": {"Ref": "Secret"}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_secrets_manager_extras() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let sm = aws_sdk_secretsmanager::Client::new(&server.aws_config().await);

    cfn.create_stack()
        .stack_name("sm-extras-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("sm-extras-stack")
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
    let secret_arn = outputs.get("SecretArn").copied().expect("SecretArn output");

    // RotationSchedule - DescribeSecret returns rotation fields.
    let desc = sm
        .describe_secret()
        .secret_id(secret_arn)
        .send()
        .await
        .expect("describe_secret");
    assert_eq!(desc.rotation_enabled(), Some(true));
    assert_eq!(
        desc.rotation_lambda_arn(),
        Some("arn:aws:lambda:us-east-1:000000000000:function:rotator")
    );
    let rules = desc.rotation_rules().expect("rotation_rules");
    assert_eq!(rules.automatically_after_days(), Some(30));

    // ResourcePolicy
    let policy = sm
        .get_resource_policy()
        .secret_id(secret_arn)
        .send()
        .await
        .expect("get_resource_policy");
    let body = policy.resource_policy().expect("policy body");
    assert!(body.contains("secretsmanager:DeleteSecret"));
    assert!(body.contains("Deny"));

    cfn.delete_stack()
        .stack_name("sm-extras-stack")
        .send()
        .await
        .expect("delete_stack");
}
