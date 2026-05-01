//! CloudFormation provisioner for AWS::Organizations::Organization + OU + Policy + ResourcePolicy.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Org": {
      "Type": "AWS::Organizations::Organization",
      "Properties": {"FeatureSet": "ALL"}
    },
    "Sandbox": {
      "Type": "AWS::Organizations::OrganizationalUnit",
      "Properties": {
        "Name": "Sandbox",
        "ParentId": {"Fn::GetAtt": ["Org", "RootId"]}
      }
    },
    "DenyRoot": {
      "Type": "AWS::Organizations::Policy",
      "Properties": {
        "Name": "DenyRootUser",
        "Description": "Block root sign-in",
        "Type": "SERVICE_CONTROL_POLICY",
        "Content": {
          "Version": "2012-10-17",
          "Statement": [{"Effect": "Deny", "Action": "*", "Resource": "*", "Condition": {"StringLike": {"aws:PrincipalArn": "*:root"}}}]
        }
      }
    },
    "OrgPolicy": {
      "Type": "AWS::Organizations::ResourcePolicy",
      "Properties": {
        "Content": {
          "Version": "2012-10-17",
          "Statement": [{"Sid": "Allow", "Effect": "Allow", "Principal": {"AWS": "*"}, "Action": "organizations:DescribeOrganization", "Resource": "*"}]
        }
      }
    }
  },
  "Outputs": {
    "OrgId": {"Value": {"Ref": "Org"}},
    "OrgArn": {"Value": {"Fn::GetAtt": ["Org", "Arn"]}},
    "RootId": {"Value": {"Fn::GetAtt": ["Org", "RootId"]}},
    "OuId": {"Value": {"Ref": "Sandbox"}},
    "PolicyId": {"Value": {"Ref": "DenyRoot"}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_organization_ou_policy_resource_policy() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let orgs = aws_sdk_organizations::Client::new(&server.aws_config().await);

    cfn.create_stack()
        .stack_name("orgs-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("orgs-stack")
        .send()
        .await
        .expect("describe_stacks");
    let stack = described.stacks().first().expect("stack present");
    assert_eq!(stack.stack_status().unwrap().as_str(), "CREATE_COMPLETE");

    let mut org_id = None;
    let mut ou_id = None;
    let mut policy_id = None;
    for o in stack.outputs() {
        match o.output_key() {
            Some("OrgId") => org_id = o.output_value().map(|s| s.to_string()),
            Some("OuId") => ou_id = o.output_value().map(|s| s.to_string()),
            Some("PolicyId") => policy_id = o.output_value().map(|s| s.to_string()),
            _ => {}
        }
    }
    let org_id = org_id.expect("OrgId");
    let ou_id = ou_id.expect("OuId");
    let policy_id = policy_id.expect("PolicyId");
    assert!(org_id.starts_with("o-"));
    assert!(ou_id.starts_with("ou-"));
    assert!(policy_id.starts_with("p-"));

    let described_org = orgs
        .describe_organization()
        .send()
        .await
        .expect("describe_organization");
    let org = described_org.organization().expect("organization");
    assert_eq!(org.id(), Some(org_id.as_str()));

    let described_ou = orgs
        .describe_organizational_unit()
        .organizational_unit_id(&ou_id)
        .send()
        .await
        .expect("describe_organizational_unit");
    let ou = described_ou.organizational_unit().expect("ou");
    assert_eq!(ou.name(), Some("Sandbox"));

    let described_policy = orgs
        .describe_policy()
        .policy_id(&policy_id)
        .send()
        .await
        .expect("describe_policy");
    let p = described_policy.policy().expect("policy");
    assert_eq!(
        p.policy_summary().and_then(|s| s.name()),
        Some("DenyRootUser")
    );

    let described_resource_policy = orgs
        .describe_resource_policy()
        .send()
        .await
        .expect("describe_resource_policy");
    assert!(described_resource_policy.resource_policy().is_some());

    cfn.delete_stack()
        .stack_name("orgs-stack")
        .send()
        .await
        .expect("delete_stack");

    let after = orgs.describe_organization().send().await;
    assert!(
        after.is_err(),
        "organization should be gone after stack deletion"
    );
}
