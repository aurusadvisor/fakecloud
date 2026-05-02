//! CloudFormation provisioner for AWS::StepFunctions::* resources.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Activity": {
      "Type": "AWS::StepFunctions::Activity",
      "Properties": {"Name": "cfn-activity"}
    },
    "StateMachine": {
      "Type": "AWS::StepFunctions::StateMachine",
      "Properties": {
        "StateMachineName": "cfn-sm",
        "RoleArn": "arn:aws:iam::000000000000:role/StepRole",
        "StateMachineType": "STANDARD",
        "DefinitionString": "{\"Comment\":\"hello\",\"StartAt\":\"Done\",\"States\":{\"Done\":{\"Type\":\"Succeed\"}}}"
      }
    }
  },
  "Outputs": {
    "ActivityArn": {"Value": {"Ref": "Activity"}},
    "StateMachineArn": {"Value": {"Ref": "StateMachine"}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_stepfunctions_resources() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let sfn = aws_sdk_sfn::Client::new(&server.aws_config().await);

    cfn.create_stack()
        .stack_name("sfn-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("sfn-stack")
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

    let activity_arn = outputs.get("ActivityArn").expect("ActivityArn");
    let sm_arn = outputs.get("StateMachineArn").expect("StateMachineArn");

    assert!(
        activity_arn.contains(":activity:cfn-activity"),
        "activity arn format: {activity_arn}"
    );
    assert!(
        sm_arn.contains(":stateMachine:cfn-sm"),
        "state machine arn format: {sm_arn}"
    );

    // Verify state machine via SDK.
    let sm = sfn
        .describe_state_machine()
        .state_machine_arn(*sm_arn)
        .send()
        .await
        .expect("describe_state_machine");
    assert_eq!(sm.name(), "cfn-sm");
    assert_eq!(sm.role_arn(), "arn:aws:iam::000000000000:role/StepRole");

    // Verify activity via SDK.
    let act = sfn
        .describe_activity()
        .activity_arn(*activity_arn)
        .send()
        .await
        .expect("describe_activity");
    assert_eq!(act.name(), "cfn-activity");

    // Tear down.
    cfn.delete_stack()
        .stack_name("sfn-stack")
        .send()
        .await
        .expect("delete_stack");

    let sm_after = sfn
        .describe_state_machine()
        .state_machine_arn(*sm_arn)
        .send()
        .await;
    assert!(sm_after.is_err(), "state machine should be gone");
}
