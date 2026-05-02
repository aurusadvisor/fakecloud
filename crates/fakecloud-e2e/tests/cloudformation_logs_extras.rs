//! CloudFormation provisioner for the additional AWS::Logs::* resources
//! beyond LogGroup/LogStream/MetricFilter/SubscriptionFilter:
//! Destination, ResourcePolicy, QueryDefinition, Delivery,
//! DeliveryDestination, DeliverySource.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "LG": {
      "Type": "AWS::Logs::LogGroup",
      "Properties": {"LogGroupName": "/cfn/extras", "RetentionInDays": 7}
    },
    "Dest": {
      "Type": "AWS::Logs::Destination",
      "Properties": {
        "DestinationName": "cfn-dest",
        "TargetArn": "arn:aws:kinesis:us-east-1:000000000000:stream/cfn-stream",
        "RoleArn": "arn:aws:iam::000000000000:role/CfnDestRole"
      }
    },
    "Policy": {
      "Type": "AWS::Logs::ResourcePolicy",
      "Properties": {
        "PolicyName": "cfn-policy",
        "PolicyDocument": "{\"Version\":\"2012-10-17\",\"Statement\":[]}"
      }
    },
    "Query": {
      "Type": "AWS::Logs::QueryDefinition",
      "Properties": {
        "Name": "cfn-query",
        "QueryString": "fields @timestamp, @message",
        "LogGroupNames": ["/cfn/extras"]
      }
    },
    "DeliverySource": {
      "Type": "AWS::Logs::DeliverySource",
      "Properties": {
        "Name": "cfn-source",
        "ResourceArn": "arn:aws:bedrock:us-east-1:000000000000:knowledgebase/abc",
        "LogType": "APPLICATION_LOGS"
      }
    },
    "DeliveryDest": {
      "Type": "AWS::Logs::DeliveryDestination",
      "Properties": {
        "Name": "cfn-deliv-dest",
        "OutputFormat": "json",
        "DestinationResourceArn": {"Fn::GetAtt": ["LG", "Arn"]}
      }
    },
    "Delivery": {
      "Type": "AWS::Logs::Delivery",
      "Properties": {
        "DeliverySourceName": {"Ref": "DeliverySource"},
        "DeliveryDestinationArn": {"Fn::GetAtt": ["DeliveryDest", "Arn"]}
      },
      "DependsOn": ["DeliverySource", "DeliveryDest"]
    }
  },
  "Outputs": {
    "DestId": {"Value": {"Ref": "Dest"}},
    "DestArn": {"Value": {"Fn::GetAtt": ["Dest", "Arn"]}},
    "PolicyId": {"Value": {"Ref": "Policy"}},
    "QueryId": {"Value": {"Ref": "Query"}},
    "DeliverySrcId": {"Value": {"Ref": "DeliverySource"}},
    "DeliveryDestArn": {"Value": {"Fn::GetAtt": ["DeliveryDest", "Arn"]}},
    "DeliveryId": {"Value": {"Ref": "Delivery"}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_logs_extras() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let logs = aws_sdk_cloudwatchlogs::Client::new(&server.aws_config().await);

    cfn.create_stack()
        .stack_name("logs-extras-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("logs-extras-stack")
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

    assert_eq!(outputs.get("DestId").copied(), Some("cfn-dest"));
    let dest_arn = outputs.get("DestArn").expect("DestArn");
    assert!(dest_arn.contains(":destination:cfn-dest"));
    assert_eq!(outputs.get("PolicyId").copied(), Some("cfn-policy"));
    assert!(!outputs.get("QueryId").expect("QueryId").is_empty());
    assert_eq!(outputs.get("DeliverySrcId").copied(), Some("cfn-source"));
    let deliv_dest_arn = outputs.get("DeliveryDestArn").expect("DeliveryDestArn");
    assert!(deliv_dest_arn.contains(":delivery-destination:cfn-deliv-dest"));
    let delivery_id = outputs.get("DeliveryId").expect("DeliveryId");
    assert!(!delivery_id.is_empty());

    // Verify destination + resource policy + query definition via SDK.
    let dests = logs
        .describe_destinations()
        .destination_name_prefix("cfn-dest")
        .send()
        .await
        .expect("describe_destinations");
    assert!(dests
        .destinations()
        .iter()
        .any(|d| d.destination_name() == Some("cfn-dest")));

    let policies = logs
        .describe_resource_policies()
        .send()
        .await
        .expect("describe_resource_policies");
    assert!(policies
        .resource_policies()
        .iter()
        .any(|p| p.policy_name() == Some("cfn-policy")));

    let queries = logs
        .describe_query_definitions()
        .send()
        .await
        .expect("describe_query_definitions");
    assert!(queries
        .query_definitions()
        .iter()
        .any(|q| q.name() == Some("cfn-query")));

    cfn.delete_stack()
        .stack_name("logs-extras-stack")
        .send()
        .await
        .expect("delete_stack");
}
