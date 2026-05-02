//! CloudFormation provisioner for AWS::CertificateManager::Certificate.

mod helpers;

use aws_sdk_cloudformation::types::{Capability, OnFailure};
use helpers::TestServer;

const TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "Cert": {
      "Type": "AWS::CertificateManager::Certificate",
      "Properties": {
        "DomainName": "example.com",
        "SubjectAlternativeNames": ["www.example.com", "api.example.com"],
        "ValidationMethod": "DNS"
      }
    }
  },
  "Outputs": {
    "CertArn": {"Value": {"Ref": "Cert"}}
  }
}"#;

#[tokio::test]
async fn cfn_provisions_acm_certificate() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let acm = aws_sdk_acm::Client::new(&server.aws_config().await);

    cfn.create_stack()
        .stack_name("acm-stack")
        .template_body(TEMPLATE)
        .capabilities(Capability::CapabilityIam)
        .on_failure(OnFailure::Rollback)
        .send()
        .await
        .expect("create_stack");

    let described = cfn
        .describe_stacks()
        .stack_name("acm-stack")
        .send()
        .await
        .expect("describe_stacks");
    let stack = described.stacks().first().expect("stack present");
    assert_eq!(stack.stack_status().unwrap().as_str(), "CREATE_COMPLETE");

    let cert_arn = stack
        .outputs()
        .iter()
        .find(|o| o.output_key() == Some("CertArn"))
        .and_then(|o| o.output_value())
        .expect("CertArn")
        .to_string();
    assert!(cert_arn.starts_with("arn:aws:acm:"));
    assert!(cert_arn.contains(":certificate/"));

    let described_cert = acm
        .describe_certificate()
        .certificate_arn(&cert_arn)
        .send()
        .await
        .expect("describe_certificate");
    let cert = described_cert.certificate().expect("certificate");
    assert_eq!(cert.domain_name(), Some("example.com"));
    assert_eq!(cert.status().map(|s| s.as_str()), Some("ISSUED"));
    assert!(cert
        .subject_alternative_names()
        .iter()
        .any(|s| s == "www.example.com"));

    cfn.delete_stack()
        .stack_name("acm-stack")
        .send()
        .await
        .expect("delete_stack");

    let after = acm
        .describe_certificate()
        .certificate_arn(&cert_arn)
        .send()
        .await;
    assert!(
        after.is_err(),
        "certificate should be gone after stack deletion"
    );
}

const ACCOUNT_TEMPLATE: &str = r#"{
  "AWSTemplateFormatVersion": "2010-09-09",
  "Resources": {
    "AcmAcct": {
      "Type": "AWS::CertificateManager::Account",
      "Properties": {
        "ExpiryEventsConfiguration": {
          "DaysBeforeExpiry": 17
        }
      }
    }
  }
}"#;

#[tokio::test]
async fn cfn_provisions_acm_account_expiry_events() {
    let server = TestServer::start().await;
    let cfn = server.cloudformation_client().await;
    let acm = aws_sdk_acm::Client::new(&server.aws_config().await);

    cfn.create_stack()
        .stack_name("acm-account-stack")
        .template_body(ACCOUNT_TEMPLATE)
        .send()
        .await
        .expect("create_stack");

    let cfg = acm
        .get_account_configuration()
        .send()
        .await
        .expect("get_account_configuration");
    assert_eq!(
        cfg.expiry_events().and_then(|e| e.days_before_expiry()),
        Some(17),
    );

    cfn.delete_stack()
        .stack_name("acm-account-stack")
        .send()
        .await
        .expect("delete_stack");

    let cfg_after = acm
        .get_account_configuration()
        .send()
        .await
        .expect("get_account_configuration after delete");
    assert!(
        cfg_after
            .expiry_events()
            .and_then(|e| e.days_before_expiry())
            .is_none(),
        "expiry days should reset to default after stack delete",
    );
}
