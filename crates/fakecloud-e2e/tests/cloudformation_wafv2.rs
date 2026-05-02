//! CloudFormation provisioner for AWS::WAFv2::* resources.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use aws_sdk_wafv2::types::Scope as WafScope;
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "IPSet": {
      "Type": "AWS::WAFv2::IPSet",
      "Properties": {
        "Name": "cfn-blocked-ips",
        "Scope": "REGIONAL",
        "IPAddressVersion": "IPV4",
        "Addresses": ["10.0.0.0/8", "192.168.1.1/32"]
      }
    },
    "RegexSet": {
      "Type": "AWS::WAFv2::RegexPatternSet",
      "Properties": {
        "Name": "cfn-bad-paths",
        "Scope": "REGIONAL",
        "RegularExpressionList": ["/admin/.*", "\\.php$"]
      }
    },
    "RuleGroup": {
      "Type": "AWS::WAFv2::RuleGroup",
      "Properties": {
        "Name": "cfn-rule-group",
        "Scope": "REGIONAL",
        "Capacity": 100,
        "Rules": [],
        "VisibilityConfig": {
          "SampledRequestsEnabled": true,
          "CloudWatchMetricsEnabled": true,
          "MetricName": "cfn-rg"
        }
      }
    },
    "WebACL": {
      "Type": "AWS::WAFv2::WebACL",
      "Properties": {
        "Name": "cfn-web-acl",
        "Scope": "REGIONAL",
        "DefaultAction": {"Allow": {}},
        "Rules": [],
        "VisibilityConfig": {
          "SampledRequestsEnabled": true,
          "CloudWatchMetricsEnabled": true,
          "MetricName": "cfn-acl"
        }
      }
    }
  },
  "Outputs": {
    "WebAclArn": {"Value": {"Fn::GetAtt": ["WebACL", "Arn"]}},
    "WebAclId": {"Value": {"Fn::GetAtt": ["WebACL", "Id"]}},
    "IPSetArn": {"Value": {"Fn::GetAtt": ["IPSet", "Arn"]}},
    "IPSetId": {"Value": {"Fn::GetAtt": ["IPSet", "Id"]}},
    "RegexSetArn": {"Value": {"Fn::GetAtt": ["RegexSet", "Arn"]}},
    "RuleGroupArn": {"Value": {"Fn::GetAtt": ["RuleGroup", "Arn"]}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_wafv2_resources() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let waf = aws_sdk_wafv2::Client::new(&server.aws_config().await);

    cfn.create_stack()
        .stack_name("waf-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("waf-stack")
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

    let acl_arn = outputs.get("WebAclArn").expect("WebAclArn");
    let acl_id = outputs.get("WebAclId").expect("WebAclId");
    let ip_set_id = outputs.get("IPSetId").expect("IPSetId");
    let regex_arn = outputs.get("RegexSetArn").expect("RegexSetArn");
    let rg_arn = outputs.get("RuleGroupArn").expect("RuleGroupArn");

    assert!(acl_arn.contains("/webacl/cfn-web-acl"));
    assert!(regex_arn.contains("/regexpatternset/cfn-bad-paths"));
    assert!(rg_arn.contains("/rulegroup/cfn-rule-group"));

    // Verify via SDK.
    let acl = waf
        .get_web_acl()
        .name("cfn-web-acl")
        .scope(WafScope::Regional)
        .id(*acl_id)
        .send()
        .await
        .expect("get_web_acl");
    assert_eq!(acl.web_acl().map(|w| w.name()), Some("cfn-web-acl"));

    let ip_set = waf
        .get_ip_set()
        .name("cfn-blocked-ips")
        .scope(WafScope::Regional)
        .id(*ip_set_id)
        .send()
        .await
        .expect("get_ip_set");
    let ips = ip_set.ip_set().expect("ip set");
    assert_eq!(ips.name(), "cfn-blocked-ips");
    assert!(ips.addresses().contains(&"10.0.0.0/8".to_string()));

    // Tear down.
    cfn.delete_stack()
        .stack_name("waf-stack")
        .send()
        .await
        .expect("delete_stack");
}
