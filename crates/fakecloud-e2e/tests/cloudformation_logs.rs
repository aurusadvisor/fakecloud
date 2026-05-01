//! CloudFormation provisioner for AWS::Logs::LogStream + MetricFilter + SubscriptionFilter.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Group": {
      "Type": "AWS::Logs::LogGroup",
      "Properties": {"LogGroupName": "cfn-logs-app"}
    },
    "Stream": {
      "Type": "AWS::Logs::LogStream",
      "Properties": {
        "LogGroupName": {"Ref": "Group"},
        "LogStreamName": "main"
      }
    },
    "Errors": {
      "Type": "AWS::Logs::MetricFilter",
      "Properties": {
        "LogGroupName": {"Ref": "Group"},
        "FilterName": "error-count",
        "FilterPattern": "ERROR",
        "MetricTransformations": [
          {"MetricName": "Errors", "MetricNamespace": "App", "MetricValue": "1"}
        ]
      }
    },
    "Subscription": {
      "Type": "AWS::Logs::SubscriptionFilter",
      "Properties": {
        "LogGroupName": {"Ref": "Group"},
        "FilterName": "kinesis-fanout",
        "FilterPattern": "",
        "DestinationArn": "arn:aws:kinesis:us-east-1:000000000000:stream/cfn-fanout"
      }
    }
  }
}"#;

#[tokio::test]
async fn cfn_provisions_logs_filters_and_streams() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let logs = server.logs_client().await;

    cfn.create_stack()
        .stack_name("logs-filters-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("logs-filters-stack")
        .send()
        .await
        .expect("describe_stacks");
    let stack = described.stacks().first().expect("stack present");
    assert_eq!(stack.stack_status().unwrap().as_str(), "CREATE_COMPLETE");

    let streams = logs
        .describe_log_streams()
        .log_group_name("cfn-logs-app")
        .send()
        .await
        .expect("describe_log_streams");
    assert!(
        streams
            .log_streams()
            .iter()
            .any(|s| s.log_stream_name() == Some("main")),
        "log stream should exist"
    );

    let metric_filters = logs
        .describe_metric_filters()
        .log_group_name("cfn-logs-app")
        .send()
        .await
        .expect("describe_metric_filters");
    let mf = metric_filters
        .metric_filters()
        .iter()
        .find(|f| f.filter_name() == Some("error-count"))
        .expect("metric filter present");
    assert_eq!(mf.filter_pattern(), Some("ERROR"));

    let sub_filters = logs
        .describe_subscription_filters()
        .log_group_name("cfn-logs-app")
        .send()
        .await
        .expect("describe_subscription_filters");
    let sf = sub_filters
        .subscription_filters()
        .iter()
        .find(|f| f.filter_name() == Some("kinesis-fanout"))
        .expect("subscription filter present");
    assert_eq!(
        sf.destination_arn(),
        Some("arn:aws:kinesis:us-east-1:000000000000:stream/cfn-fanout")
    );

    cfn.delete_stack()
        .stack_name("logs-filters-stack")
        .send()
        .await
        .expect("delete_stack");

    let after_groups = logs
        .describe_log_groups()
        .log_group_name_prefix("cfn-logs-app")
        .send()
        .await
        .expect("describe_log_groups after");
    assert!(
        after_groups.log_groups().is_empty(),
        "log group should be gone after stack deletion"
    );
}
