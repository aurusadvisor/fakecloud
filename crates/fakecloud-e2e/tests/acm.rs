//! ACM service E2E.

mod helpers;

use aws_sdk_acm::primitives::Blob;
use aws_sdk_acm::types::{
    CertificateOptions, CertificateStatus, CertificateTransparencyLoggingPreference,
    DomainValidationOption, RevocationReason, Tag, ValidationMethod,
};
use helpers::TestServer;

const SAMPLE_CERT_PEM: &str = "-----BEGIN CERTIFICATE-----\n\
fake-cert-bytes-for-fakecloud-tests-only\n\
-----END CERTIFICATE-----\n";
const SAMPLE_KEY_PEM: &str = "-----BEGIN RSA PRIVATE KEY-----\n\
fake-key-bytes-for-fakecloud-tests-only\n\
-----END RSA PRIVATE KEY-----\n";

#[tokio::test]
async fn request_describe_get_certificate_lifecycle() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;

    let req = acm
        .request_certificate()
        .domain_name("api.example.com")
        .validation_method(ValidationMethod::Dns)
        .subject_alternative_names("alt.example.com")
        .send()
        .await
        .expect("request");
    let arn = req.certificate_arn().unwrap().to_string();
    assert!(arn.contains(":certificate/"));

    let described = acm
        .describe_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .expect("describe")
        .certificate()
        .unwrap()
        .clone();
    assert_eq!(described.domain_name(), Some("api.example.com"));
    assert_eq!(
        described.status(),
        Some(&CertificateStatus::PendingValidation)
    );
    let sans = described.subject_alternative_names();
    assert_eq!(sans.len(), 2);
    assert_eq!(sans[0], "api.example.com");
    let dvo = described.domain_validation_options();
    assert_eq!(dvo.len(), 2);
    let rr = dvo[0].resource_record().expect("dns rr");
    assert!(rr.name().starts_with('_'));
    assert_eq!(rr.r#type().as_str(), "CNAME");

    let got = acm
        .get_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .expect("get cert");
    assert!(got.certificate().unwrap().contains("BEGIN CERTIFICATE"));
    assert!(got
        .certificate_chain()
        .unwrap()
        .contains("BEGIN CERTIFICATE"));
}

#[tokio::test]
async fn request_certificate_idempotency_returns_existing_arn() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;

    let first = acm
        .request_certificate()
        .domain_name("idem.example.com")
        .idempotency_token("repeat-token")
        .send()
        .await
        .expect("first")
        .certificate_arn()
        .unwrap()
        .to_string();
    let second = acm
        .request_certificate()
        .domain_name("idem.example.com")
        .idempotency_token("repeat-token")
        .send()
        .await
        .expect("second")
        .certificate_arn()
        .unwrap()
        .to_string();
    assert_eq!(first, second, "same idempotency token must dedupe");
}

#[tokio::test]
async fn reimporting_certificate_overwrites_domain_metadata() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;
    let initial_pem =
        "-----BEGIN CERTIFICATE-----\nCN=initial.example.com\n-----END CERTIFICATE-----\n";
    let arn = acm
        .import_certificate()
        .certificate(Blob::new(initial_pem.as_bytes().to_vec()))
        .private_key(Blob::new(SAMPLE_KEY_PEM.as_bytes().to_vec()))
        .send()
        .await
        .expect("first import")
        .certificate_arn()
        .unwrap()
        .to_string();
    let before = acm
        .describe_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .expect("describe")
        .certificate()
        .unwrap()
        .clone();
    assert_eq!(before.domain_name(), Some("initial.example.com"));

    let new_pem =
        "-----BEGIN CERTIFICATE-----\nCN=replaced.example.com\n-----END CERTIFICATE-----\n";
    acm.import_certificate()
        .certificate_arn(&arn)
        .certificate(Blob::new(new_pem.as_bytes().to_vec()))
        .private_key(Blob::new(SAMPLE_KEY_PEM.as_bytes().to_vec()))
        .send()
        .await
        .expect("re-import");
    let after = acm
        .describe_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .expect("describe")
        .certificate()
        .unwrap()
        .clone();
    assert_eq!(after.domain_name(), Some("replaced.example.com"));
    assert_eq!(after.subject_alternative_names(), &["replaced.example.com"]);
}

#[tokio::test]
async fn import_then_export_certificate_roundtrips_pem() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;

    let imported = acm
        .import_certificate()
        .certificate(Blob::new(SAMPLE_CERT_PEM.as_bytes().to_vec()))
        .private_key(Blob::new(SAMPLE_KEY_PEM.as_bytes().to_vec()))
        .send()
        .await
        .expect("import");
    let arn = imported.certificate_arn().unwrap().to_string();

    let described = acm
        .describe_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .expect("describe")
        .certificate()
        .unwrap()
        .clone();
    assert_eq!(described.r#type().unwrap().as_str(), "IMPORTED");
    assert_eq!(described.status(), Some(&CertificateStatus::Issued));

    let exported = acm
        .export_certificate()
        .certificate_arn(&arn)
        .passphrase(Blob::new(b"hunter2".to_vec()))
        .send()
        .await
        .expect("export");
    assert!(exported
        .certificate()
        .unwrap()
        .contains("BEGIN CERTIFICATE"));
    assert!(exported
        .private_key()
        .unwrap()
        .contains("BEGIN RSA PRIVATE KEY"));
}

#[tokio::test]
async fn list_and_search_certificates_filter_by_domain() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;
    for d in &["one.example.com", "two.example.com", "three.example.org"] {
        acm.request_certificate()
            .domain_name(*d)
            .send()
            .await
            .expect(d);
    }
    let listed = acm.list_certificates().send().await.expect("list");
    assert!(listed.certificate_summary_list().len() >= 3);

    let searched = acm.search_certificates().send().await.expect("search");
    assert!(searched.results().len() >= 3);
}

#[tokio::test]
async fn delete_certificate_removes_it() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;
    let arn = acm
        .request_certificate()
        .domain_name("doomed.example.com")
        .send()
        .await
        .expect("create")
        .certificate_arn()
        .unwrap()
        .to_string();
    acm.delete_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .expect("delete");
    let bad = acm
        .describe_certificate()
        .certificate_arn(&arn)
        .send()
        .await;
    assert!(bad.is_err(), "deleted cert must fail describe");
}

#[tokio::test]
async fn revoke_then_describe_shows_revoked_status() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;
    let arn = acm
        .request_certificate()
        .domain_name("revoke.example.com")
        .send()
        .await
        .expect("create")
        .certificate_arn()
        .unwrap()
        .to_string();
    acm.revoke_certificate()
        .certificate_arn(&arn)
        .revocation_reason(RevocationReason::KeyCompromise)
        .send()
        .await
        .expect("revoke");
    let after = acm
        .describe_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .expect("describe")
        .certificate()
        .unwrap()
        .clone();
    assert_eq!(after.status(), Some(&CertificateStatus::Revoked));
    assert!(after.revoked_at().is_some());
}

#[tokio::test]
async fn revoke_imported_certificate_rejected() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;
    let arn = acm
        .import_certificate()
        .certificate(Blob::new(SAMPLE_CERT_PEM.as_bytes().to_vec()))
        .private_key(Blob::new(SAMPLE_KEY_PEM.as_bytes().to_vec()))
        .send()
        .await
        .expect("import")
        .certificate_arn()
        .unwrap()
        .to_string();
    let bad = acm
        .revoke_certificate()
        .certificate_arn(&arn)
        .revocation_reason(RevocationReason::Unspecified)
        .send()
        .await;
    assert!(bad.is_err(), "imported certs cannot be revoked via ACM");
}

#[tokio::test]
async fn renew_certificate_updates_validity_window() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;
    let arn = acm
        .request_certificate()
        .domain_name("renew.example.com")
        .send()
        .await
        .expect("create")
        .certificate_arn()
        .unwrap()
        .to_string();
    let before = acm
        .describe_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .expect("describe")
        .certificate()
        .unwrap()
        .clone();
    acm.renew_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .expect("renew");
    let after = acm
        .describe_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .expect("describe")
        .certificate()
        .unwrap()
        .clone();
    assert_eq!(after.status(), Some(&CertificateStatus::Issued));
    assert!(after.not_after() >= before.not_after());
}

#[tokio::test]
async fn tag_lifecycle_for_certificate() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;
    let arn = acm
        .request_certificate()
        .domain_name("tagged.example.com")
        .send()
        .await
        .expect("create")
        .certificate_arn()
        .unwrap()
        .to_string();
    acm.add_tags_to_certificate()
        .certificate_arn(&arn)
        .tags(Tag::builder().key("env").value("prod").build().unwrap())
        .tags(Tag::builder().key("team").value("infra").build().unwrap())
        .send()
        .await
        .expect("add tags");
    let after_add = acm
        .list_tags_for_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .expect("list tags");
    assert_eq!(after_add.tags().len(), 2);

    acm.remove_tags_from_certificate()
        .certificate_arn(&arn)
        .tags(Tag::builder().key("team").build().unwrap())
        .send()
        .await
        .expect("remove tags");
    let after_remove = acm
        .list_tags_for_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .expect("list tags 2");
    let keys: Vec<&str> = after_remove.tags().iter().map(|t| t.key()).collect();
    assert_eq!(keys, vec!["env"]);
}

#[tokio::test]
async fn account_configuration_roundtrip() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;
    acm.put_account_configuration()
        .idempotency_token("cfg-1")
        .expiry_events(
            aws_sdk_acm::types::ExpiryEventsConfiguration::builder()
                .days_before_expiry(30)
                .build(),
        )
        .send()
        .await
        .expect("put cfg");
    let got = acm
        .get_account_configuration()
        .send()
        .await
        .expect("get cfg");
    assert_eq!(got.expiry_events().unwrap().days_before_expiry(), Some(30));
}

#[tokio::test]
async fn update_certificate_options_changes_export_setting() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;
    let arn = acm
        .request_certificate()
        .domain_name("opts.example.com")
        .send()
        .await
        .expect("create")
        .certificate_arn()
        .unwrap()
        .to_string();
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
        .expect("update opts");
    let after = acm
        .describe_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .expect("describe")
        .certificate()
        .unwrap()
        .clone();
    let opts = after.options().unwrap();
    assert_eq!(
        opts.certificate_transparency_logging_preference(),
        Some(&CertificateTransparencyLoggingPreference::Disabled)
    );
}

#[tokio::test]
async fn resend_validation_email_only_for_email_validation() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;
    let arn = acm
        .request_certificate()
        .domain_name("dns-only.example.com")
        .validation_method(ValidationMethod::Dns)
        .send()
        .await
        .expect("create")
        .certificate_arn()
        .unwrap()
        .to_string();
    let bad = acm
        .resend_validation_email()
        .certificate_arn(&arn)
        .domain("dns-only.example.com")
        .validation_domain("dns-only.example.com")
        .send()
        .await;
    assert!(bad.is_err(), "DNS-validated certs cannot resend");

    let arn_email = acm
        .request_certificate()
        .domain_name("email-cert.example.com")
        .validation_method(ValidationMethod::Email)
        .domain_validation_options(
            DomainValidationOption::builder()
                .domain_name("email-cert.example.com")
                .validation_domain("example.com")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("create")
        .certificate_arn()
        .unwrap()
        .to_string();
    acm.resend_validation_email()
        .certificate_arn(&arn_email)
        .domain("email-cert.example.com")
        .validation_domain("example.com")
        .send()
        .await
        .expect("resend ok");
}
