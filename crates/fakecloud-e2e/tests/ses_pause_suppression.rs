//! End-to-end coverage for the SES sending-pause + suppression gates.
//!
//! Real SES rejects every send while account-level sending is paused
//! (`AccountSendingPausedException`), every send into a paused
//! configuration set (`ConfigurationSetSendingPausedException`), and
//! every send to an address on the suppression list when the relevant
//! reason is enforced. fakecloud mirrors all three across SES v1 + v2;
//! this suite drives them through the AWS SDKs so regressions in the
//! Smithy-translated request paths get caught.

mod helpers;

use aws_sdk_sesv2::types::{
    Body, Content, Destination, EmailContent, Message, SuppressionListReason,
};
use helpers::TestServer;

async fn pause_account_v2(client: &aws_sdk_sesv2::Client, paused: bool) {
    client
        .put_account_sending_attributes()
        .sending_enabled(!paused)
        .send()
        .await
        .expect("PutAccountSendingAttributes");
}

fn simple_content(subject: &str, body: &str) -> EmailContent {
    EmailContent::builder()
        .simple(
            Message::builder()
                .subject(Content::builder().data(subject).build().unwrap())
                .body(
                    Body::builder()
                        .text(Content::builder().data(body).build().unwrap())
                        .build(),
                )
                .build(),
        )
        .build()
}

async fn metrics_drops_total(server: &TestServer) -> u64 {
    let url = format!("{}/_fakecloud/ses/metrics", server.endpoint());
    let resp = reqwest::Client::new()
        .get(&url)
        .send()
        .await
        .expect("metrics request");
    let body: serde_json::Value = resp.json().await.expect("metrics body");
    body["suppressedDropsTotal"].as_u64().unwrap_or(0)
}

#[tokio::test]
async fn v2_send_email_rejected_when_account_sending_paused() {
    let server = TestServer::start().await;
    let client = server.sesv2_client().await;

    client
        .create_email_identity()
        .email_identity("sender@example.com")
        .send()
        .await
        .unwrap();
    pause_account_v2(&client, true).await;

    let err = client
        .send_email()
        .from_email_address("sender@example.com")
        .destination(
            Destination::builder()
                .to_addresses("anyone@elsewhere.test")
                .build(),
        )
        .content(simple_content("Hi", "Hello"))
        .send()
        .await
        .unwrap_err();
    let dbg = format!("{err:?}");
    assert!(
        dbg.contains("AccountSendingPausedException")
            || dbg.contains("Email sending for the account is paused"),
        "expected AccountSendingPausedException, got: {dbg}"
    );

    // Flip back on and confirm sends resume.
    pause_account_v2(&client, false).await;
    client
        .send_email()
        .from_email_address("sender@example.com")
        .destination(
            Destination::builder()
                .to_addresses("anyone@elsewhere.test")
                .build(),
        )
        .content(simple_content("Hi", "Hello"))
        .send()
        .await
        .expect("send should resume after un-pausing");
}

#[tokio::test]
async fn v2_send_email_rejected_when_config_set_sending_paused() {
    let server = TestServer::start().await;
    let client = server.sesv2_client().await;
    let cs_name = "paused-cs";

    client
        .create_email_identity()
        .email_identity("sender@example.com")
        .send()
        .await
        .unwrap();
    client
        .create_configuration_set()
        .configuration_set_name(cs_name)
        .send()
        .await
        .unwrap();
    client
        .put_configuration_set_sending_options()
        .configuration_set_name(cs_name)
        .sending_enabled(false)
        .send()
        .await
        .unwrap();

    let err = client
        .send_email()
        .from_email_address("sender@example.com")
        .configuration_set_name(cs_name)
        .destination(
            Destination::builder()
                .to_addresses("anyone@elsewhere.test")
                .build(),
        )
        .content(simple_content("Hi", "Hello"))
        .send()
        .await
        .unwrap_err();
    let dbg = format!("{err:?}");
    assert!(
        dbg.contains("ConfigurationSetSendingPausedException")
            || dbg.contains(&format!(
                "Email sending for the configuration set {cs_name} is paused"
            )),
        "expected ConfigurationSetSendingPausedException, got: {dbg}"
    );

    // Sends without that config set should still go through.
    client
        .send_email()
        .from_email_address("sender@example.com")
        .destination(
            Destination::builder()
                .to_addresses("anyone@elsewhere.test")
                .build(),
        )
        .content(simple_content("Hi", "Hello"))
        .send()
        .await
        .expect("send without paused config-set should succeed");
}

#[tokio::test]
async fn v2_send_email_rejected_when_recipient_on_suppression_list() {
    let server = TestServer::start().await;
    let client = server.sesv2_client().await;

    client
        .create_email_identity()
        .email_identity("sender@example.com")
        .send()
        .await
        .unwrap();
    client
        .put_suppressed_destination()
        .email_address("blocked@example.com")
        .reason(SuppressionListReason::Bounce)
        .send()
        .await
        .unwrap();

    let before = metrics_drops_total(&server).await;
    let err = client
        .send_email()
        .from_email_address("sender@example.com")
        .destination(
            Destination::builder()
                .to_addresses("blocked@example.com")
                .build(),
        )
        .content(simple_content("Hi", "Hello"))
        .send()
        .await
        .unwrap_err();
    let dbg = format!("{err:?}");
    assert!(
        dbg.contains("MessageRejected") || dbg.contains("suppression list"),
        "expected MessageRejected for suppressed recipient, got: {dbg}"
    );
    let after = metrics_drops_total(&server).await;
    assert_eq!(
        after,
        before + 1,
        "suppression-drop counter should increment exactly once"
    );
}

#[tokio::test]
async fn v2_send_email_suppression_lookup_is_case_insensitive() {
    let server = TestServer::start().await;
    let client = server.sesv2_client().await;

    client
        .create_email_identity()
        .email_identity("sender@example.com")
        .send()
        .await
        .unwrap();
    client
        .put_suppressed_destination()
        .email_address("Blocked@Example.com")
        .reason(SuppressionListReason::Complaint)
        .send()
        .await
        .unwrap();

    // Different casing on the recipient must still hit the suppression list.
    let err = client
        .send_email()
        .from_email_address("sender@example.com")
        .destination(
            Destination::builder()
                .to_addresses("BLOCKED@example.COM")
                .build(),
        )
        .content(simple_content("Hi", "Hello"))
        .send()
        .await
        .unwrap_err();
    let dbg = format!("{err:?}");
    assert!(
        dbg.contains("MessageRejected") || dbg.contains("suppression list"),
        "expected case-insensitive suppression match, got: {dbg}"
    );
}

#[tokio::test]
async fn v2_send_email_suppression_reason_filter_excludes_complaint() {
    let server = TestServer::start().await;
    let client = server.sesv2_client().await;

    client
        .create_email_identity()
        .email_identity("sender@example.com")
        .send()
        .await
        .unwrap();
    // Account-level filter only enforces BOUNCE; recipient is on the list
    // for COMPLAINT, so the send should proceed.
    client
        .put_account_suppression_attributes()
        .suppressed_reasons(SuppressionListReason::Bounce)
        .send()
        .await
        .unwrap();
    client
        .put_suppressed_destination()
        .email_address("complainer@example.com")
        .reason(SuppressionListReason::Complaint)
        .send()
        .await
        .unwrap();

    client
        .send_email()
        .from_email_address("sender@example.com")
        .destination(
            Destination::builder()
                .to_addresses("complainer@example.com")
                .build(),
        )
        .content(simple_content("Hi", "Hello"))
        .send()
        .await
        .expect("BOUNCE-only filter should let COMPLAINT-suppressed addresses through");

    // Now with a BOUNCE-suppressed address, the same send must be rejected.
    client
        .put_suppressed_destination()
        .email_address("hardbounce@example.com")
        .reason(SuppressionListReason::Bounce)
        .send()
        .await
        .unwrap();
    let err = client
        .send_email()
        .from_email_address("sender@example.com")
        .destination(
            Destination::builder()
                .to_addresses("hardbounce@example.com")
                .build(),
        )
        .content(simple_content("Hi", "Hello"))
        .send()
        .await
        .unwrap_err();
    let dbg = format!("{err:?}");
    assert!(
        dbg.contains("MessageRejected") || dbg.contains("suppression list"),
        "expected BOUNCE filter to reject BOUNCE-suppressed address, got: {dbg}"
    );
}

#[tokio::test]
async fn v2_send_email_config_set_filter_overrides_account_filter() {
    let server = TestServer::start().await;
    let client = server.sesv2_client().await;
    let cs_name = "complaint-only-cs";

    client
        .create_email_identity()
        .email_identity("sender@example.com")
        .send()
        .await
        .unwrap();
    client
        .create_configuration_set()
        .configuration_set_name(cs_name)
        .send()
        .await
        .unwrap();
    // Account enforces both reasons (default), config set narrows to COMPLAINT.
    client
        .put_configuration_set_suppression_options()
        .configuration_set_name(cs_name)
        .suppressed_reasons(SuppressionListReason::Complaint)
        .send()
        .await
        .unwrap();
    client
        .put_suppressed_destination()
        .email_address("hardbounce@example.com")
        .reason(SuppressionListReason::Bounce)
        .send()
        .await
        .unwrap();

    // The config-set scope narrows the filter, so a BOUNCE-suppressed
    // address must NOT be rejected when sending into that config set.
    client
        .send_email()
        .from_email_address("sender@example.com")
        .configuration_set_name(cs_name)
        .destination(
            Destination::builder()
                .to_addresses("hardbounce@example.com")
                .build(),
        )
        .content(simple_content("Hi", "Hello"))
        .send()
        .await
        .expect("config-set COMPLAINT-only filter should let BOUNCE-suppressed addresses through");

    // Without the config-set override the default filter (both reasons)
    // applies and the same send is rejected.
    let err = client
        .send_email()
        .from_email_address("sender@example.com")
        .destination(
            Destination::builder()
                .to_addresses("hardbounce@example.com")
                .build(),
        )
        .content(simple_content("Hi", "Hello"))
        .send()
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("MessageRejected"));
}

#[tokio::test]
async fn v1_send_email_rejected_when_account_sending_paused() {
    let server = TestServer::start().await;
    let v1 = server.ses_client().await;
    let v2 = server.sesv2_client().await;

    v1.verify_email_identity()
        .email_address("sender@example.com")
        .send()
        .await
        .unwrap();
    pause_account_v2(&v2, true).await;

    let err = v1
        .send_email()
        .source("sender@example.com")
        .destination(
            aws_sdk_ses::types::Destination::builder()
                .to_addresses("anyone@elsewhere.test")
                .build(),
        )
        .message(
            aws_sdk_ses::types::Message::builder()
                .subject(
                    aws_sdk_ses::types::Content::builder()
                        .data("Hi")
                        .build()
                        .unwrap(),
                )
                .body(
                    aws_sdk_ses::types::Body::builder()
                        .text(
                            aws_sdk_ses::types::Content::builder()
                                .data("Hello")
                                .build()
                                .unwrap(),
                        )
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    let dbg = format!("{err:?}");
    assert!(
        dbg.contains("MessageRejected") || dbg.contains("Email sending for the account is paused"),
        "expected MessageRejected (account paused) from SES v1, got: {dbg}"
    );
}

#[tokio::test]
async fn v1_send_email_rejected_when_recipient_on_suppression_list() {
    let server = TestServer::start().await;
    let v1 = server.ses_client().await;
    let v2 = server.sesv2_client().await;

    v1.verify_email_identity()
        .email_address("sender@example.com")
        .send()
        .await
        .unwrap();
    v2.put_suppressed_destination()
        .email_address("blocked-v1@example.com")
        .reason(SuppressionListReason::Bounce)
        .send()
        .await
        .unwrap();

    let before = metrics_drops_total(&server).await;
    let err = v1
        .send_email()
        .source("sender@example.com")
        .destination(
            aws_sdk_ses::types::Destination::builder()
                .to_addresses("blocked-v1@example.com")
                .build(),
        )
        .message(
            aws_sdk_ses::types::Message::builder()
                .subject(
                    aws_sdk_ses::types::Content::builder()
                        .data("Hi")
                        .build()
                        .unwrap(),
                )
                .body(
                    aws_sdk_ses::types::Body::builder()
                        .text(
                            aws_sdk_ses::types::Content::builder()
                                .data("Hello")
                                .build()
                                .unwrap(),
                        )
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    let dbg = format!("{err:?}");
    assert!(
        dbg.contains("MessageRejected") || dbg.contains("suppression list"),
        "expected MessageRejected for suppressed recipient on v1, got: {dbg}"
    );
    let after = metrics_drops_total(&server).await;
    assert_eq!(
        after,
        before + 1,
        "v1 suppression-drop should bump the same counter v2 uses"
    );
}

#[tokio::test]
async fn v1_send_email_rejected_when_config_set_sending_paused() {
    let server = TestServer::start().await;
    let v1 = server.ses_client().await;
    let v2 = server.sesv2_client().await;
    let cs_name = "paused-cs-v1";

    v1.verify_email_identity()
        .email_address("sender@example.com")
        .send()
        .await
        .unwrap();
    v2.create_configuration_set()
        .configuration_set_name(cs_name)
        .send()
        .await
        .unwrap();
    v2.put_configuration_set_sending_options()
        .configuration_set_name(cs_name)
        .sending_enabled(false)
        .send()
        .await
        .unwrap();

    let err = v1
        .send_email()
        .source("sender@example.com")
        .configuration_set_name(cs_name)
        .destination(
            aws_sdk_ses::types::Destination::builder()
                .to_addresses("anyone@elsewhere.test")
                .build(),
        )
        .message(
            aws_sdk_ses::types::Message::builder()
                .subject(
                    aws_sdk_ses::types::Content::builder()
                        .data("Hi")
                        .build()
                        .unwrap(),
                )
                .body(
                    aws_sdk_ses::types::Body::builder()
                        .text(
                            aws_sdk_ses::types::Content::builder()
                                .data("Hello")
                                .build()
                                .unwrap(),
                        )
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap_err();
    let dbg = format!("{err:?}");
    assert!(
        dbg.contains("MessageRejected") || dbg.contains("paused"),
        "expected MessageRejected (config set paused) from SES v1, got: {dbg}"
    );
}
