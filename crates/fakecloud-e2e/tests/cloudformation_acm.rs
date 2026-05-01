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
