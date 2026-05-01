//! CloudFormation provisioner for AWS::CloudWatch::Alarm.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "HighCpu": {
      "Type": "AWS::CloudWatch::Alarm",
      "Properties": {
        "AlarmName": "cfn-high-cpu",
        "AlarmDescription": "CPU > 80% for 5 minutes",
        "Namespace": "AWS/EC2",
        "MetricName": "CPUUtilization",
        "Statistic": "Average",
        "Period": 300,
        "EvaluationPeriods": 2,
        "Threshold": 80,
        "ComparisonOperator": "GreaterThanThreshold",
        "TreatMissingData": "notBreaching",
        "Dimensions": [
          {"Name": "InstanceId", "Value": "i-0123456789abcdef0"}
        ],
        "AlarmActions": ["arn:aws:sns:us-east-1:000000000000:alerts"],
        "OKActions": ["arn:aws:sns:us-east-1:000000000000:recoveries"]
      }
    }
  },
  "Outputs": {
    "AlarmName": {"Value": {"Ref": "HighCpu"}},
    "AlarmArn": {"Value": {"Fn::GetAtt": ["HighCpu", "Arn"]}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_and_deletes_cloudwatch_alarm() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let cw = server.cloudwatch_client().await;

    cfn.create_stack()
        .stack_name("alarm-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("alarm-stack")
        .send()
        .await
        .expect("describe_stacks");
    let stack = described.stacks().first().expect("stack present");
    assert_eq!(stack.stack_status().unwrap().as_str(), "CREATE_COMPLETE");

    let mut name = None;
    let mut arn = None;
    for o in stack.outputs() {
        match o.output_key() {
            Some("AlarmName") => name = o.output_value().map(|s| s.to_string()),
            Some("AlarmArn") => arn = o.output_value().map(|s| s.to_string()),
            _ => {}
        }
    }
    let name = name.expect("AlarmName output");
    let arn = arn.expect("AlarmArn output");
    assert_eq!(name, "cfn-high-cpu");
    assert!(arn.starts_with("arn:aws:cloudwatch:") && arn.ends_with(":alarm:cfn-high-cpu"));

    let described_alarms = cw
        .describe_alarms()
        .alarm_names(&name)
        .send()
        .await
        .expect("describe_alarms");
    let alarm = described_alarms
        .metric_alarms()
        .first()
        .expect("alarm present");
    assert_eq!(alarm.alarm_name(), Some(name.as_str()));
    assert_eq!(alarm.namespace(), Some("AWS/EC2"));
    assert_eq!(alarm.metric_name(), Some("CPUUtilization"));
    assert_eq!(alarm.threshold(), Some(80.0));
    assert_eq!(alarm.evaluation_periods(), Some(2));
    assert_eq!(
        alarm.comparison_operator().map(|c| c.as_str()),
        Some("GreaterThanThreshold")
    );
    assert_eq!(alarm.alarm_actions().len(), 1);
    assert_eq!(alarm.ok_actions().len(), 1);

    cfn.delete_stack()
        .stack_name("alarm-stack")
        .send()
        .await
        .expect("delete_stack");

    let after = cw
        .describe_alarms()
        .alarm_names(&name)
        .send()
        .await
        .expect("describe_alarms after");
    assert!(
        after.metric_alarms().is_empty(),
        "alarm should be gone after stack deletion"
    );
}
