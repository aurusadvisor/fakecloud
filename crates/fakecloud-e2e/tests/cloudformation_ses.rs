//! CloudFormation provisioner for AWS::SES::* (BB27). Provisions a
//! ConfigurationSet, EmailIdentity, Template, ContactList, DedicatedIpPool,
//! ReceiptRuleSet+ReceiptRule and asserts via the real SES v2 + v1 SDKs.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Cs": {
      "Type": "AWS::SES::ConfigurationSet",
      "Properties": {
        "Name": "cfn-cs",
        "SendingOptions": {"SendingEnabled": true},
        "DeliveryOptions": {"TlsPolicy": "REQUIRE"},
        "ReputationOptions": {"ReputationMetricsEnabled": true}
      }
    },
    "Identity": {
      "Type": "AWS::SES::EmailIdentity",
      "Properties": {
        "EmailIdentity": "cfn-domain.example.com",
        "DkimAttributes": {"SigningEnabled": true},
        "MailFromAttributes": {
          "MailFromDomain": "mail.cfn-domain.example.com",
          "BehaviorOnMxFailure": "USE_DEFAULT_VALUE"
        }
      }
    },
    "Tpl": {
      "Type": "AWS::SES::Template",
      "Properties": {
        "Template": {
          "TemplateName": "cfn-tpl",
          "SubjectPart": "Hi {{name}}",
          "TextPart": "Hello {{name}}",
          "HtmlPart": "<p>Hello {{name}}</p>"
        }
      }
    },
    "Cl": {
      "Type": "AWS::SES::ContactList",
      "Properties": {
        "ContactListName": "cfn-cl",
        "Description": "from cfn"
      }
    },
    "Pool": {
      "Type": "AWS::SES::DedicatedIpPool",
      "Properties": {
        "PoolName": "cfn-pool",
        "ScalingMode": "STANDARD"
      }
    },
    "Rs": {
      "Type": "AWS::SES::ReceiptRuleSet",
      "Properties": {
        "RuleSetName": "cfn-rs"
      }
    },
    "Rule": {
      "Type": "AWS::SES::ReceiptRule",
      "DependsOn": "Rs",
      "Properties": {
        "RuleSetName": "cfn-rs",
        "Rule": {
          "Name": "cfn-rule",
          "Enabled": true,
          "ScanEnabled": false,
          "TlsPolicy": "Optional",
          "Recipients": ["test@cfn-domain.example.com"],
          "Actions": [
            {"AddHeaderAction": {"HeaderName": "X-CFN", "HeaderValue": "yes"}}
          ]
        }
      }
    }
  },
  "Outputs": {
    "CsName": {"Value": {"Ref": "Cs"}},
    "IdName": {"Value": {"Ref": "Identity"}},
    "TplName": {"Value": {"Ref": "Tpl"}},
    "ClName": {"Value": {"Ref": "Cl"}},
    "PoolName": {"Value": {"Ref": "Pool"}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_ses() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let ses = aws_sdk_sesv2::Client::new(&server.aws_config().await);
    let ses_v1 = aws_sdk_ses::Client::new(&server.aws_config().await);

    cfn.create_stack()
        .stack_name("ses-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("ses-stack")
        .send()
        .await
        .expect("describe_stacks");
    let stack = described.stacks().first().expect("stack present");
    assert_eq!(stack.stack_status().unwrap().as_str(), "CREATE_COMPLETE");

    let cs = ses
        .get_configuration_set()
        .configuration_set_name("cfn-cs")
        .send()
        .await
        .expect("get_configuration_set");
    assert_eq!(cs.configuration_set_name(), Some("cfn-cs"));
    assert_eq!(
        cs.delivery_options()
            .and_then(|d| d.tls_policy())
            .map(|t| t.as_str()),
        Some("REQUIRE")
    );

    let id = ses
        .get_email_identity()
        .email_identity("cfn-domain.example.com")
        .send()
        .await
        .expect("get_email_identity");
    assert_eq!(id.identity_type().map(|t| t.as_str()), Some("DOMAIN"));
    assert!(id.verified_for_sending_status());

    let tpl = ses
        .get_email_template()
        .template_name("cfn-tpl")
        .send()
        .await
        .expect("get_email_template");
    assert_eq!(tpl.template_name(), "cfn-tpl");

    let cl = ses
        .get_contact_list()
        .contact_list_name("cfn-cl")
        .send()
        .await
        .expect("get_contact_list");
    assert_eq!(cl.contact_list_name(), Some("cfn-cl"));

    let pool = ses
        .get_dedicated_ip_pool()
        .pool_name("cfn-pool")
        .send()
        .await
        .expect("get_dedicated_ip_pool");
    assert_eq!(
        pool.dedicated_ip_pool().map(|p| p.scaling_mode().as_str()),
        Some("STANDARD")
    );

    // Use SES v1 for receipt rule readback.
    let rule = ses_v1
        .describe_receipt_rule()
        .rule_set_name("cfn-rs")
        .rule_name("cfn-rule")
        .send()
        .await
        .expect("describe_receipt_rule");
    let r = rule.rule().expect("rule present");
    assert_eq!(r.name(), "cfn-rule");
    assert!(r.enabled());

    cfn.delete_stack()
        .stack_name("ses-stack")
        .send()
        .await
        .expect("delete_stack");

    let after = ses
        .get_configuration_set()
        .configuration_set_name("cfn-cs")
        .send()
        .await;
    assert!(after.is_err(), "configuration set should be gone");
}
