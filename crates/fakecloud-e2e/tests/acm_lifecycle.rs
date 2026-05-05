//! ACM certificate-issue lifecycle E2E (V2).
//!
//! Covers the three async-issue paths:
//!   1. DNS validation auto-transitions PENDING_VALIDATION -> ISSUED
//!      after a short delay (driven by `FAKECLOUD_ACM_AUTO_ISSUE_SECS`).
//!   2. EMAIL validation stays PENDING_VALIDATION until the admin
//!      `/_fakecloud/acm/certificates/{arn}/approve` endpoint flips it.
//!   3. RenewCertificate immediately reports ISSUED and refreshes the
//!      `RenewalSummary` block.

mod helpers;

use aws_sdk_acm::types::{CertificateStatus, ValidationMethod};
use helpers::{wait_until, TestServer};

/// Time budget for the auto-issue tick when the test sets
/// `FAKECLOUD_ACM_AUTO_ISSUE_SECS=1`. Polled rather than hard-slept so
/// the test fails fast on a regression instead of waiting wall-clock.
const AUTO_ISSUE_BUDGET: std::time::Duration = std::time::Duration::from_secs(10);

#[tokio::test]
async fn dns_validation_auto_transitions_to_issued() {
    let server = TestServer::start_with_env(&[("FAKECLOUD_ACM_AUTO_ISSUE_SECS", "1")]).await;
    let acm = server.acm_client().await;

    let arn = acm
        .request_certificate()
        .domain_name("auto.example.com")
        .validation_method(ValidationMethod::Dns)
        .send()
        .await
        .expect("request")
        .certificate_arn()
        .unwrap()
        .to_string();

    // Right after RequestCertificate, the cert must be PENDING with
    // INELIGIBLE renewal eligibility and no RenewalSummary populated.
    let early = acm
        .describe_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .expect("describe-early")
        .certificate()
        .unwrap()
        .clone();
    assert_eq!(
        early.status(),
        Some(&CertificateStatus::PendingValidation),
        "fresh DNS cert must start PENDING_VALIDATION"
    );
    assert!(
        early.renewal_summary().is_none(),
        "RenewalSummary should be absent before issuance"
    );

    // Poll for the async tick.
    let issued = wait_until(AUTO_ISSUE_BUDGET, || {
        let acm = acm.clone();
        let arn = arn.clone();
        async move {
            let resp = acm
                .describe_certificate()
                .certificate_arn(&arn)
                .send()
                .await
                .ok()?;
            let cert = resp.certificate()?.clone();
            if cert.status() == Some(&CertificateStatus::Issued) {
                Some(cert)
            } else {
                None
            }
        }
    })
    .await
    .expect("auto-issue tick should fire within the budget");

    assert!(issued.issued_at().is_some(), "IssuedAt must be populated");
    let summary = issued
        .renewal_summary()
        .expect("RenewalSummary must populate after issuance");
    assert_eq!(
        summary.renewal_status().as_str(),
        "PENDING_AUTO_RENEWAL",
        "freshly issued certs are queued for managed renewal"
    );
    // RenewalSummary.UpdatedAt is required by the Smithy model so it's
    // always populated; just sanity-check it's a real timestamp.
    assert!(summary.updated_at().secs() > 0);
    // Domain validation is now SUCCESS for every entry.
    for dv in issued.domain_validation_options() {
        assert_eq!(dv.validation_status().map(|s| s.as_str()), Some("SUCCESS"));
    }
}

#[tokio::test]
async fn email_validation_stays_pending_until_admin_approves() {
    // Even with a tiny auto-issue delay, EMAIL validation must NOT
    // auto-transition. Real ACM sends a confirmation email and waits
    // for human action.
    let server = TestServer::start_with_env(&[("FAKECLOUD_ACM_AUTO_ISSUE_SECS", "1")]).await;
    let acm = server.acm_client().await;

    let arn = acm
        .request_certificate()
        .domain_name("manual.example.com")
        .validation_method(ValidationMethod::Email)
        .send()
        .await
        .expect("request")
        .certificate_arn()
        .unwrap()
        .to_string();

    // Wait well past the DNS auto-issue budget; an EMAIL cert must
    // still be PENDING because no tick was scheduled.
    tokio::time::sleep(std::time::Duration::from_millis(2_500)).await;
    let still_pending = acm
        .describe_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .expect("describe-pending")
        .certificate()
        .unwrap()
        .clone();
    assert_eq!(
        still_pending.status(),
        Some(&CertificateStatus::PendingValidation),
        "EMAIL cert must NOT auto-issue"
    );
    assert!(still_pending.renewal_summary().is_none());

    // Admin approval flips it synchronously.
    let code = server.approve_acm_certificate(&arn).await;
    assert_eq!(code, 204, "expected 204 from /approve");

    let approved = acm
        .describe_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .expect("describe-approved")
        .certificate()
        .unwrap()
        .clone();
    assert_eq!(approved.status(), Some(&CertificateStatus::Issued));
    assert!(approved.issued_at().is_some());
    assert!(approved.renewal_summary().is_some());
    for dv in approved.domain_validation_options() {
        assert_eq!(dv.validation_status().map(|s| s.as_str()), Some("SUCCESS"));
    }
}

#[tokio::test]
async fn approve_unknown_certificate_returns_404() {
    let server = TestServer::start().await;
    let code = server.approve_acm_certificate("nope-not-a-real-id").await;
    assert_eq!(code, 404, "approving an unknown cert must 404");
}

#[tokio::test]
async fn renew_certificate_round_trips_with_refreshed_summary() {
    // Use a fast auto-issue so the cert reaches ISSUED before we renew
    // — RenewCertificate is only valid against an issued cert in
    // practice (real ACM returns ResourceNotFound otherwise but
    // fakecloud is permissive; we still test the realistic flow).
    let server = TestServer::start_with_env(&[("FAKECLOUD_ACM_AUTO_ISSUE_SECS", "1")]).await;
    let acm = server.acm_client().await;

    let arn = acm
        .request_certificate()
        .domain_name("renew-cycle.example.com")
        .validation_method(ValidationMethod::Dns)
        .send()
        .await
        .expect("request")
        .certificate_arn()
        .unwrap()
        .to_string();

    let issued = wait_until(AUTO_ISSUE_BUDGET, || {
        let acm = acm.clone();
        let arn = arn.clone();
        async move {
            let cert = acm
                .describe_certificate()
                .certificate_arn(&arn)
                .send()
                .await
                .ok()?
                .certificate()?
                .clone();
            if cert.status() == Some(&CertificateStatus::Issued) {
                Some(cert)
            } else {
                None
            }
        }
    })
    .await
    .expect("cert should reach ISSUED");

    let issued_summary = issued
        .renewal_summary()
        .expect("RenewalSummary present after issuance");
    let issued_updated_at = *issued_summary.updated_at();

    // A small wait so RenewCertificate's UpdatedAt timestamp is
    // strictly greater than the auto-issue one (chrono timestamps are
    // millisecond-resolution under our serializer).
    tokio::time::sleep(std::time::Duration::from_millis(1_100)).await;

    acm.renew_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .expect("renew");

    let renewed = acm
        .describe_certificate()
        .certificate_arn(&arn)
        .send()
        .await
        .expect("describe-renewed")
        .certificate()
        .unwrap()
        .clone();
    assert_eq!(renewed.status(), Some(&CertificateStatus::Issued));
    let renewed_summary = renewed.renewal_summary().expect("RenewalSummary refreshed");
    assert_eq!(
        renewed_summary.renewal_status().as_str(),
        "SUCCESS",
        "RenewCertificate flips RenewalStatus to SUCCESS"
    );
    let renewed_updated_at = *renewed_summary.updated_at();
    assert!(
        renewed_updated_at > issued_updated_at,
        "RenewalSummary.UpdatedAt must move forward after renew"
    );
    assert!(renewed.not_after().unwrap() >= issued.not_after().unwrap());
}
