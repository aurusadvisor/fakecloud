mod helpers;

use helpers::TestServer;

/// Identity + configuration set + email template round-trip across a restart.
#[tokio::test]
async fn persistence_round_trip_identity_config_set_and_template() {
    let tmp = tempfile::tempdir().unwrap();
    let mut server = TestServer::start_persistent(tmp.path()).await;
    let ses = server.sesv2_client().await;

    ses.create_email_identity()
        .email_identity("sender@example.com")
        .send()
        .await
        .unwrap();

    ses.create_configuration_set()
        .configuration_set_name("primary")
        .send()
        .await
        .unwrap();

    ses.create_email_template()
        .template_name("welcome")
        .template_content(
            aws_sdk_sesv2::types::EmailTemplateContent::builder()
                .subject("Hi {{name}}")
                .text("Hello {{name}}, welcome aboard.")
                .build(),
        )
        .send()
        .await
        .unwrap();

    server.restart().await;
    let ses = server.sesv2_client().await;

    let identities = ses.list_email_identities().send().await.unwrap();
    assert!(identities
        .email_identities()
        .iter()
        .any(|i| i.identity_name() == Some("sender@example.com")));

    let config_sets = ses.list_configuration_sets().send().await.unwrap();
    assert!(config_sets
        .configuration_sets()
        .iter()
        .any(|n| n == "primary"));

    let template = ses
        .get_email_template()
        .template_name("welcome")
        .send()
        .await
        .unwrap();
    let content = template.template_content().unwrap();
    assert_eq!(content.subject(), Some("Hi {{name}}"));
}

/// Tags on a configuration set survive a restart.
#[tokio::test]
async fn persistence_configuration_set_tags() {
    let tmp = tempfile::tempdir().unwrap();
    let mut server = TestServer::start_persistent(tmp.path()).await;
    let ses = server.sesv2_client().await;

    ses.create_configuration_set()
        .configuration_set_name("tagged")
        .send()
        .await
        .unwrap();
    let arn_for_tag = "arn:aws:ses:us-east-1:123456789012:configuration-set/tagged";
    ses.tag_resource()
        .resource_arn(arn_for_tag)
        .tags(
            aws_sdk_sesv2::types::Tag::builder()
                .key("env")
                .value("prod")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    server.restart().await;
    let ses = server.sesv2_client().await;

    let tags = ses
        .list_tags_for_resource()
        .resource_arn(arn_for_tag)
        .send()
        .await
        .unwrap();
    assert!(tags
        .tags()
        .iter()
        .any(|t| t.key() == "env" && t.value() == "prod"));
}

/// Suppression list entries persist, but the `/_fakecloud/ses/emails`
/// introspection buffer does not.
#[tokio::test]
async fn persistence_suppression_persists_introspection_does_not() {
    let tmp = tempfile::tempdir().unwrap();
    let mut server = TestServer::start_persistent(tmp.path()).await;
    let ses = server.sesv2_client().await;

    ses.create_email_identity()
        .email_identity("sender@example.com")
        .send()
        .await
        .unwrap();
    ses.create_email_identity()
        .email_identity("to@example.com")
        .send()
        .await
        .unwrap();

    ses.put_suppressed_destination()
        .email_address("blocked@example.com")
        .reason(aws_sdk_sesv2::types::SuppressionListReason::Bounce)
        .send()
        .await
        .unwrap();

    ses.send_email()
        .from_email_address("sender@example.com")
        .destination(
            aws_sdk_sesv2::types::Destination::builder()
                .to_addresses("to@example.com")
                .build(),
        )
        .content(
            aws_sdk_sesv2::types::EmailContent::builder()
                .simple(
                    aws_sdk_sesv2::types::Message::builder()
                        .subject(
                            aws_sdk_sesv2::types::Content::builder()
                                .data("hi")
                                .build()
                                .unwrap(),
                        )
                        .body(
                            aws_sdk_sesv2::types::Body::builder()
                                .text(
                                    aws_sdk_sesv2::types::Content::builder()
                                        .data("hello")
                                        .build()
                                        .unwrap(),
                                )
                                .build(),
                        )
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();

    server.restart().await;
    let ses = server.sesv2_client().await;

    let suppressed = ses
        .get_suppressed_destination()
        .email_address("blocked@example.com")
        .send()
        .await
        .unwrap();
    assert_eq!(
        suppressed
            .suppressed_destination()
            .map(|d| d.email_address()),
        Some("blocked@example.com"),
    );

    // Introspection buffer must NOT be restored.
    let resp = reqwest::get(format!("{}/_fakecloud/ses/emails", server.endpoint()))
        .await
        .unwrap();
    let body: serde_json::Value = resp.json().await.unwrap();
    let emails = body
        .get("emails")
        .and_then(|v| v.as_array())
        .cloned()
        .unwrap_or_default();
    assert!(
        emails.is_empty(),
        "introspection sent_emails should not persist across restarts, got: {body:?}"
    );
}
