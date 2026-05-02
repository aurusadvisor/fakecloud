//! CloudFormation provisioner for AWS::Events::EventBus + EventBusPolicy + Endpoint.
//! These complement the existing Rule/Connection/ApiDestination/Archive coverage.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Bus": {
      "Type": "AWS::Events::EventBus",
      "Properties": {
        "Name": "cfn-bus",
        "Description": "managed by cfn"
      }
    },
    "BusPolicy": {
      "Type": "AWS::Events::EventBusPolicy",
      "Properties": {
        "EventBusName": {"Ref": "Bus"},
        "StatementId": "AllowDescribe",
        "Action": "events:DescribeRule",
        "Principal": "111111111111"
      }
    },
    "Endpoint": {
      "Type": "AWS::Events::Endpoint",
      "Properties": {
        "Name": "cfn-endpoint",
        "RoutingConfig": {
          "FailoverConfig": {
            "Primary": {"HealthCheck": "arn:aws:route53:::healthcheck/abc"},
            "Secondary": {"Route": "us-west-2"}
          }
        },
        "EventBuses": [
          {"EventBusArn": {"Fn::GetAtt": ["Bus", "Arn"]}}
        ]
      },
      "DependsOn": ["Bus"]
    }
  },
  "Outputs": {
    "BusName": {"Value": {"Ref": "Bus"}},
    "BusArn": {"Value": {"Fn::GetAtt": ["Bus", "Arn"]}},
    "EndpointName": {"Value": {"Ref": "Endpoint"}},
    "EndpointArn": {"Value": {"Fn::GetAtt": ["Endpoint", "Arn"]}},
    "EndpointUrl": {"Value": {"Fn::GetAtt": ["Endpoint", "EndpointUrl"]}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_events_extras() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let eb = aws_sdk_eventbridge::Client::new(&server.aws_config().await);

    cfn.create_stack()
        .stack_name("events-extras-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("events-extras-stack")
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

    assert_eq!(outputs.get("BusName").copied(), Some("cfn-bus"));
    let bus_arn = outputs.get("BusArn").expect("BusArn");
    assert!(bus_arn.contains(":event-bus/cfn-bus"));
    assert_eq!(outputs.get("EndpointName").copied(), Some("cfn-endpoint"));
    let endpoint_url = outputs.get("EndpointUrl").expect("EndpointUrl");
    assert!(endpoint_url.starts_with("https://"));

    // Verify bus via SDK.
    let bus = eb
        .describe_event_bus()
        .name("cfn-bus")
        .send()
        .await
        .expect("describe_event_bus");
    assert_eq!(bus.name(), Some("cfn-bus"));
    // Policy should now exist after the EventBusPolicy resource provisioned.
    assert!(bus.policy().is_some(), "bus policy should be set");

    cfn.delete_stack()
        .stack_name("events-extras-stack")
        .send()
        .await
        .expect("delete_stack");
}
