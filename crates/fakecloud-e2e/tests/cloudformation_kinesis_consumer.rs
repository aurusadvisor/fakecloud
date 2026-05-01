//! CloudFormation provisioner for AWS::Kinesis::StreamConsumer.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Events": {
      "Type": "AWS::Kinesis::Stream",
      "Properties": {"Name": "cfn-consumer-stream", "ShardCount": 1}
    },
    "Reader": {
      "Type": "AWS::Kinesis::StreamConsumer",
      "Properties": {
        "ConsumerName": "cfn-reader",
        "StreamARN": {"Fn::GetAtt": ["Events", "Arn"]}
      }
    }
  },
  "Outputs": {
    "ConsumerArn": {"Value": {"Fn::GetAtt": ["Reader", "ConsumerARN"]}},
    "ConsumerName": {"Value": {"Fn::GetAtt": ["Reader", "ConsumerName"]}},
    "StreamArn": {"Value": {"Fn::GetAtt": ["Reader", "StreamARN"]}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_and_deletes_kinesis_stream_consumer() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let kinesis = server.kinesis_client().await;

    cfn.create_stack()
        .stack_name("kinesis-consumer-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("kinesis-consumer-stack")
        .send()
        .await
        .expect("describe_stacks");
    let stack = described.stacks().first().expect("stack present");
    assert_eq!(stack.stack_status().unwrap().as_str(), "CREATE_COMPLETE");

    let mut consumer_arn = None;
    let mut consumer_name = None;
    let mut stream_arn = None;
    for o in stack.outputs() {
        match o.output_key() {
            Some("ConsumerArn") => consumer_arn = o.output_value().map(|s| s.to_string()),
            Some("ConsumerName") => consumer_name = o.output_value().map(|s| s.to_string()),
            Some("StreamArn") => stream_arn = o.output_value().map(|s| s.to_string()),
            _ => {}
        }
    }
    let consumer_arn = consumer_arn.expect("ConsumerARN output");
    let consumer_name = consumer_name.expect("ConsumerName output");
    let stream_arn = stream_arn.expect("StreamARN output");
    assert_eq!(consumer_name, "cfn-reader");
    assert!(consumer_arn.starts_with(&stream_arn));
    assert!(consumer_arn.contains("/consumer/cfn-reader:"));

    let described_consumer = kinesis
        .describe_stream_consumer()
        .consumer_arn(&consumer_arn)
        .send()
        .await
        .expect("describe_stream_consumer");
    let descr = described_consumer
        .consumer_description()
        .expect("description");
    assert_eq!(descr.consumer_name(), "cfn-reader");
    assert_eq!(descr.consumer_arn(), &consumer_arn);

    cfn.delete_stack()
        .stack_name("kinesis-consumer-stack")
        .send()
        .await
        .expect("delete_stack");

    let after = kinesis
        .describe_stream_consumer()
        .consumer_arn(&consumer_arn)
        .send()
        .await;
    assert!(
        after.is_err(),
        "consumer should be gone after stack deletion"
    );
}
