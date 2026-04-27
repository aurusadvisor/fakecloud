//! ACM conformance tests.

mod helpers;

use aws_sdk_acm::primitives::Blob;
use aws_sdk_acm::types::{
    CertificateOptions, CertificateTransparencyLoggingPreference, RevocationReason, Tag,
    ValidationMethod,
};
use fakecloud_conformance_macros::test_action;
use helpers::TestServer;

const FAKE_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n";
const FAKE_KEY_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\nfake\n-----END RSA PRIVATE KEY-----\n";

async fn make_cert(server: &TestServer, domain: &str) -> String {
    let acm = server.acm_client().await;
    acm.request_certificate()
        .domain_name(domain)
        .validation_method(ValidationMethod::Dns)
        .send()
        .await
        .unwrap()
        .certificate_arn()
        .unwrap()
        .to_string()
}

#[test_action("acm", "RequestCertificate", checksum = "795348c4")]
#[tokio::test]
async fn acm_request_certificate() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;
    acm.request_certificate()
        .domain_name("conf.example.com")
        .send()
        .await
        .unwrap();
}

#[test_action("acm", "DescribeCertificate", checksum = "d8f31b97")]
#[tokio::test]
async fn acm_describe_certificate() {
    let server = TestServer::start().await;
    let arn = make_cert(&server, "conf-describe.example.com").await;
    let acm = server.acm_client().await;
    acm.describe_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .unwrap();
}

#[test_action("acm", "ListCertificates", checksum = "e06172c7")]
#[tokio::test]
async fn acm_list_certificates() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;
    acm.list_certificates().send().await.unwrap();
}

#[test_action("acm", "DeleteCertificate", checksum = "2881e632")]
#[tokio::test]
async fn acm_delete_certificate() {
    let server = TestServer::start().await;
    let arn = make_cert(&server, "conf-delete.example.com").await;
    let acm = server.acm_client().await;
    acm.delete_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .unwrap();
}

#[test_action("acm", "ImportCertificate", checksum = "14eb26f8")]
#[tokio::test]
async fn acm_import_certificate() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;
    acm.import_certificate()
        .certificate(Blob::new(FAKE_CERT_PEM.as_bytes().to_vec()))
        .private_key(Blob::new(FAKE_KEY_PEM.as_bytes().to_vec()))
        .send()
        .await
        .unwrap();
}

#[test_action("acm", "ExportCertificate", checksum = "0d462416")]
#[tokio::test]
async fn acm_export_certificate() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;
    let arn = acm
        .import_certificate()
        .certificate(Blob::new(FAKE_CERT_PEM.as_bytes().to_vec()))
        .private_key(Blob::new(FAKE_KEY_PEM.as_bytes().to_vec()))
        .send()
        .await
        .unwrap()
        .certificate_arn()
        .unwrap()
        .to_string();
    acm.export_certificate()
        .certificate_arn(&arn)
        .passphrase(Blob::new(b"hunter2".to_vec()))
        .send()
        .await
        .unwrap();
}

#[test_action("acm", "GetCertificate", checksum = "4a899d0a")]
#[tokio::test]
async fn acm_get_certificate() {
    let server = TestServer::start().await;
    let arn = make_cert(&server, "conf-get.example.com").await;
    let acm = server.acm_client().await;
    acm.get_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .unwrap();
}

#[test_action("acm", "RenewCertificate", checksum = "a7519f9c")]
#[tokio::test]
async fn acm_renew_certificate() {
    let server = TestServer::start().await;
    let arn = make_cert(&server, "conf-renew.example.com").await;
    let acm = server.acm_client().await;
    acm.renew_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .unwrap();
}

#[test_action("acm", "RevokeCertificate", checksum = "24bd5e25")]
#[tokio::test]
async fn acm_revoke_certificate() {
    let server = TestServer::start().await;
    let arn = make_cert(&server, "conf-revoke.example.com").await;
    let acm = server.acm_client().await;
    acm.revoke_certificate()
        .certificate_arn(&arn)
        .revocation_reason(RevocationReason::Unspecified)
        .send()
        .await
        .unwrap();
}

#[test_action("acm", "ResendValidationEmail", checksum = "e5d1dca9")]
#[tokio::test]
async fn acm_resend_validation_email() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;
    let arn = acm
        .request_certificate()
        .domain_name("conf-resend.example.com")
        .validation_method(ValidationMethod::Email)
        .send()
        .await
        .unwrap()
        .certificate_arn()
        .unwrap()
        .to_string();
    acm.resend_validation_email()
        .certificate_arn(&arn)
        .domain("conf-resend.example.com")
        .validation_domain("example.com")
        .send()
        .await
        .unwrap();
}

#[test_action("acm", "AddTagsToCertificate", checksum = "68f86501")]
#[tokio::test]
async fn acm_add_tags() {
    let server = TestServer::start().await;
    let arn = make_cert(&server, "conf-addtag.example.com").await;
    let acm = server.acm_client().await;
    acm.add_tags_to_certificate()
        .certificate_arn(&arn)
        .tags(Tag::builder().key("k").value("v").build().unwrap())
        .send()
        .await
        .unwrap();
}

#[test_action("acm", "RemoveTagsFromCertificate", checksum = "59c03653")]
#[tokio::test]
async fn acm_remove_tags() {
    let server = TestServer::start().await;
    let arn = make_cert(&server, "conf-rmtag.example.com").await;
    let acm = server.acm_client().await;
    acm.add_tags_to_certificate()
        .certificate_arn(&arn)
        .tags(Tag::builder().key("k").value("v").build().unwrap())
        .send()
        .await
        .unwrap();
    acm.remove_tags_from_certificate()
        .certificate_arn(&arn)
        .tags(Tag::builder().key("k").build().unwrap())
        .send()
        .await
        .unwrap();
}

#[test_action("acm", "ListTagsForCertificate", checksum = "07259da8")]
#[tokio::test]
async fn acm_list_tags() {
    let server = TestServer::start().await;
    let arn = make_cert(&server, "conf-listtag.example.com").await;
    let acm = server.acm_client().await;
    acm.list_tags_for_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .unwrap();
}

#[test_action("acm", "GetAccountConfiguration", checksum = "40ab0077")]
#[tokio::test]
async fn acm_get_account_config() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;
    acm.get_account_configuration().send().await.unwrap();
}

#[test_action("acm", "PutAccountConfiguration", checksum = "1f1e8ad9")]
#[tokio::test]
async fn acm_put_account_config() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;
    acm.put_account_configuration()
        .idempotency_token("conf-put-1")
        .expiry_events(
            aws_sdk_acm::types::ExpiryEventsConfiguration::builder()
                .days_before_expiry(45)
                .build(),
        )
        .send()
        .await
        .unwrap();
}

#[test_action("acm", "UpdateCertificateOptions", checksum = "7663903f")]
#[tokio::test]
async fn acm_update_options() {
    let server = TestServer::start().await;
    let arn = make_cert(&server, "conf-opts.example.com").await;
    let acm = server.acm_client().await;
    acm.update_certificate_options()
        .certificate_arn(&arn)
        .options(
            CertificateOptions::builder()
                .certificate_transparency_logging_preference(
                    CertificateTransparencyLoggingPreference::Disabled,
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
}

#[test_action("acm", "SearchCertificates", checksum = "96284413")]
#[tokio::test]
async fn acm_search_certificates() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;
    acm.search_certificates().send().await.unwrap();
}
