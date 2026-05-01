//! CloudFormation provisioner for AWS::Events::Connection + ApiDestination + Archive.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Conn": {
      "Type": "AWS::Events::Connection",
      "Properties": {
        "Name": "cfn-conn",
        "AuthorizationType": "API_KEY",
        "AuthParameters": {
          "ApiKeyAuthParameters": {
            "ApiKeyName": "X-API-Key",
            "ApiKeyValue": "secret-shhh"
          }
        }
      }
    },
    "Dest": {
      "Type": "AWS::Events::ApiDestination",
      "Properties": {
        "Name": "cfn-dest",
        "ConnectionArn": {"Fn::GetAtt": ["Conn", "Arn"]},
        "InvocationEndpoint": "https://example.com/webhook",
        "HttpMethod": "POST",
        "InvocationRateLimitPerSecond": 10
      }
    },
    "Arch": {
      "Type": "AWS::Events::Archive",
      "Properties": {
        "ArchiveName": "cfn-archive",
        "SourceArn": "arn:aws:events:us-east-1:123456789012:event-bus/default",
        "RetentionDays": 30
      }
    }
  }
}"#;

#[tokio::test]
async fn cfn_provisions_events_connection_apidest_archive() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let eb = server.eventbridge_client().await;

    cfn.create_stack()
        .stack_name("events-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("events-stack")
        .send()
        .await
        .expect("describe_stacks");
    let stack = described.stacks().first().expect("stack present");
    assert_eq!(stack.stack_status().unwrap().as_str(), "CREATE_COMPLETE");

    let conn = eb
        .describe_connection()
        .name("cfn-conn")
        .send()
        .await
        .expect("describe_connection");
    assert_eq!(conn.name(), Some("cfn-conn"));
    assert_eq!(
        conn.authorization_type().map(|a| a.as_str()),
        Some("API_KEY")
    );

    let dest = eb
        .describe_api_destination()
        .name("cfn-dest")
        .send()
        .await
        .expect("describe_api_destination");
    assert_eq!(dest.name(), Some("cfn-dest"));
    assert_eq!(
        dest.invocation_endpoint(),
        Some("https://example.com/webhook")
    );
    assert_eq!(dest.invocation_rate_limit_per_second(), Some(10));

    let archive = eb
        .describe_archive()
        .archive_name("cfn-archive")
        .send()
        .await
        .expect("describe_archive");
    assert_eq!(archive.archive_name(), Some("cfn-archive"));
    assert_eq!(archive.retention_days(), Some(30));

    cfn.delete_stack()
        .stack_name("events-stack")
        .send()
        .await
        .expect("delete_stack");

    let after = eb.describe_connection().name("cfn-conn").send().await;
    assert!(
        after.is_err(),
        "connection should be gone after stack deletion"
    );
}
