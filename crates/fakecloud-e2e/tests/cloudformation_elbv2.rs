//! CloudFormation provisioner for ELBv2 LB + TargetGroup + Listener + ListenerRule.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Web": {
      "Type": "AWS::ElasticLoadBalancingV2::LoadBalancer",
      "Properties": {
        "Name": "cfn-web",
        "Scheme": "internet-facing",
        "Type": "application",
        "Subnets": ["subnet-aaa", "subnet-bbb"],
        "SecurityGroups": ["sg-deadbeef"]
      }
    },
    "ApiTg": {
      "Type": "AWS::ElasticLoadBalancingV2::TargetGroup",
      "Properties": {
        "Name": "cfn-api",
        "Protocol": "HTTP",
        "Port": 8080,
        "VpcId": "vpc-1234",
        "TargetType": "ip",
        "HealthCheckPath": "/healthz"
      }
    },
    "WebListener": {
      "Type": "AWS::ElasticLoadBalancingV2::Listener",
      "Properties": {
        "LoadBalancerArn": {"Ref": "Web"},
        "Port": 80,
        "Protocol": "HTTP",
        "DefaultActions": [
          {"Type": "forward", "TargetGroupArn": {"Ref": "ApiTg"}}
        ]
      }
    },
    "WebRule": {
      "Type": "AWS::ElasticLoadBalancingV2::ListenerRule",
      "Properties": {
        "ListenerArn": {"Ref": "WebListener"},
        "Priority": 10,
        "Conditions": [
          {"Field": "host-header", "Values": ["api.example.com"]}
        ],
        "Actions": [
          {"Type": "forward", "TargetGroupArn": {"Ref": "ApiTg"}}
        ]
      }
    }
  },
  "Outputs": {
    "LbArn": {"Value": {"Ref": "Web"}},
    "LbDns": {"Value": {"Fn::GetAtt": ["Web", "DNSName"]}},
    "TgArn": {"Value": {"Ref": "ApiTg"}},
    "ListenerArn": {"Value": {"Ref": "WebListener"}},
    "RuleArn": {"Value": {"Ref": "WebRule"}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_elbv2_lb_tg_listener_rule() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let elb = server.elbv2_client().await;

    cfn.create_stack()
        .stack_name("elbv2-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("elbv2-stack")
        .send()
        .await
        .expect("describe_stacks");
    let stack = described.stacks().first().expect("stack present");
    assert_eq!(stack.stack_status().unwrap().as_str(), "CREATE_COMPLETE");

    let mut lb_arn = None;
    let mut tg_arn = None;
    let mut listener_arn = None;
    let mut rule_arn = None;
    for o in stack.outputs() {
        match o.output_key() {
            Some("LbArn") => lb_arn = o.output_value().map(|s| s.to_string()),
            Some("TgArn") => tg_arn = o.output_value().map(|s| s.to_string()),
            Some("ListenerArn") => listener_arn = o.output_value().map(|s| s.to_string()),
            Some("RuleArn") => rule_arn = o.output_value().map(|s| s.to_string()),
            _ => {}
        }
    }
    let lb_arn = lb_arn.expect("LbArn");
    let tg_arn = tg_arn.expect("TgArn");
    let listener_arn = listener_arn.expect("ListenerArn");
    let rule_arn = rule_arn.expect("RuleArn");

    let lbs = elb
        .describe_load_balancers()
        .load_balancer_arns(&lb_arn)
        .send()
        .await
        .expect("describe_load_balancers");
    let lb = lbs.load_balancers().first().expect("lb");
    assert_eq!(lb.load_balancer_name(), Some("cfn-web"));

    let tgs = elb
        .describe_target_groups()
        .target_group_arns(&tg_arn)
        .send()
        .await
        .expect("describe_target_groups");
    let tg = tgs.target_groups().first().expect("tg");
    assert_eq!(tg.target_group_name(), Some("cfn-api"));
    assert_eq!(tg.port(), Some(8080));

    let listeners = elb
        .describe_listeners()
        .load_balancer_arn(&lb_arn)
        .send()
        .await
        .expect("describe_listeners");
    assert!(listeners
        .listeners()
        .iter()
        .any(|l| l.listener_arn() == Some(&listener_arn)));

    let rules = elb
        .describe_rules()
        .listener_arn(&listener_arn)
        .send()
        .await
        .expect("describe_rules");
    assert!(
        rules
            .rules()
            .iter()
            .any(|r| r.rule_arn() == Some(&rule_arn)),
        "rule should exist on listener"
    );

    cfn.delete_stack()
        .stack_name("elbv2-stack")
        .send()
        .await
        .expect("delete_stack");

    let after = elb
        .describe_load_balancers()
        .load_balancer_arns(&lb_arn)
        .send()
        .await;
    assert!(after.is_err(), "lb should be gone after stack deletion");
}
