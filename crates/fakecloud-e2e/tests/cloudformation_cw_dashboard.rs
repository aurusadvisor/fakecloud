//! CloudFormation provisioner for AWS::CloudWatch::Dashboard. The
//! existing CFN provisioner already covers AWS::CloudWatch::Alarm; this
//! test exercises the dashboard side and rounds out BB18.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Dash": {
      "Type": "AWS::CloudWatch::Dashboard",
      "Properties": {
        "DashboardName": "cfn-dashboard",
        "DashboardBody": "{\"widgets\":[{\"type\":\"metric\",\"properties\":{\"metrics\":[[\"AWS/Lambda\",\"Invocations\"]],\"region\":\"us-east-1\"}}]}"
      }
    }
  },
  "Outputs": {
    "Name": {"Value": {"Ref": "Dash"}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_cloudwatch_dashboard() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let cw = aws_sdk_cloudwatch::Client::new(&server.aws_config().await);

    cfn.create_stack()
        .stack_name("cw-dashboard-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("cw-dashboard-stack")
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
    assert_eq!(outputs.get("Name").copied(), Some("cfn-dashboard"));

    // Verify via SDK GetDashboard.
    let got = cw
        .get_dashboard()
        .dashboard_name("cfn-dashboard")
        .send()
        .await
        .expect("get_dashboard");
    let body = got.dashboard_body().expect("dashboard body");
    assert!(body.contains("AWS/Lambda"));

    // Verify ListDashboards picks it up.
    let listed = cw.list_dashboards().send().await.expect("list_dashboards");
    assert!(listed
        .dashboard_entries()
        .iter()
        .any(|e| e.dashboard_name() == Some("cfn-dashboard")));

    cfn.delete_stack()
        .stack_name("cw-dashboard-stack")
        .send()
        .await
        .expect("delete_stack");

    // After teardown, GetDashboard should fail.
    let after = cw
        .get_dashboard()
        .dashboard_name("cfn-dashboard")
        .send()
        .await;
    assert!(after.is_err(), "dashboard should be gone after delete");
}

const DASH_V1: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Dash": {
      "Type": "AWS::CloudWatch::Dashboard",
      "Properties": {
        "DashboardName": "cfn-dash-update",
        "DashboardBody": "{\"widgets\":[{\"type\":\"metric\",\"properties\":{\"metrics\":[[\"AWS/Lambda\",\"Invocations\"]]}}]}"
      }
    }
  }
}"#;

const DASH_V2: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Dash": {
      "Type": "AWS::CloudWatch::Dashboard",
      "Properties": {
        "DashboardName": "cfn-dash-update",
        "DashboardBody": "{\"widgets\":[{\"type\":\"metric\",\"properties\":{\"metrics\":[[\"AWS/SQS\",\"NumberOfMessagesSent\"]]}}]}"
      }
    }
  }
}"#;

#[tokio::test]
async fn cfn_updates_cloudwatch_dashboard_body() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let cw = aws_sdk_cloudwatch::Client::new(&server.aws_config().await);

    cfn.create_stack()
        .stack_name("cw-dash-update-stack")
        .template_body(DASH_V1)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let v1 = cw
        .get_dashboard()
        .dashboard_name("cfn-dash-update")
        .send()
        .await
        .expect("get v1");
    assert!(v1.dashboard_body().unwrap().contains("AWS/Lambda"));

    cfn.update_stack()
        .stack_name("cw-dash-update-stack")
        .template_body(DASH_V2)
        .send()
        .await
        .expect("update_stack");

    let v2 = cw
        .get_dashboard()
        .dashboard_name("cfn-dash-update")
        .send()
        .await
        .expect("get v2");
    let body_v2 = v2.dashboard_body().unwrap();
    assert!(body_v2.contains("AWS/SQS"));
    assert!(!body_v2.contains("AWS/Lambda"));

    cfn.delete_stack()
        .stack_name("cw-dash-update-stack")
        .send()
        .await
        .expect("delete_stack");
}
