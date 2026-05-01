//! CloudFormation provisioner for AWS::Kinesis::Stream.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Events": {
      "Type": "AWS::Kinesis::Stream",
      "Properties": {
        "Name": "cfn-events",
        "ShardCount": 2,
        "RetentionPeriodHours": 48
      }
    }
  },
  "Outputs": {
    "StreamArn": {"Value": {"Fn::GetAtt": ["Events", "Arn"]}},
    "StreamName": {"Value": {"Ref": "Events"}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_and_deletes_kinesis_stream() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let kinesis = server.kinesis_client().await;

    cfn.create_stack()
        .stack_name("kinesis-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("kinesis-stack")
        .send()
        .await
        .expect("describe_stacks");
    let stack = described.stacks().first().expect("stack present");
    assert_eq!(stack.stack_status().unwrap().as_str(), "CREATE_COMPLETE");

    let mut name = None;
    let mut arn = None;
    for o in stack.outputs() {
        match o.output_key() {
            Some("StreamArn") => arn = o.output_value().map(|s| s.to_string()),
            Some("StreamName") => name = o.output_value().map(|s| s.to_string()),
            _ => {}
        }
    }
    let arn = arn.expect("StreamArn output");
    let name = name.expect("StreamName output");
    assert!(arn.starts_with("arn:aws:kinesis:"), "unexpected arn {arn}");

    let described_stream = kinesis
        .describe_stream()
        .stream_name(&name)
        .send()
        .await
        .expect("describe_stream");
    let descr = described_stream.stream_description().expect("description");
    assert_eq!(descr.stream_name(), &name);
    assert_eq!(descr.shards().len(), 2);
    assert_eq!(descr.retention_period_hours(), 48);

    cfn.delete_stack()
        .stack_name("kinesis-stack")
        .send()
        .await
        .expect("delete_stack");

    let after = kinesis.describe_stream().stream_name(&name).send().await;
    assert!(after.is_err(), "stream should be gone after stack deletion");
}
