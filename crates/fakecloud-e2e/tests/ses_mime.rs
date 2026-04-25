mod helpers;

use aws_sdk_sesv2::types::{EmailTemplateContent, EmailTemplateMetadata};
use helpers::TestServer;
use mail_parser::MessageParser;

/// Render a templated email through SESv2 `TestRenderEmailTemplate` and verify
/// the returned MIME parses cleanly into the expected multipart/alternative
/// structure with proper Date / Message-ID / encoding headers.
#[tokio::test]
async fn ses_test_render_template_returns_rfc5322_multipart() {
    let server = TestServer::start().await;
    let ses = server.sesv2_client().await;

    ses.create_email_template()
        .template_name("welcome")
        .template_content(
            EmailTemplateContent::builder()
                .subject("Welcome, {{name}}")
                .text("Hi {{name}}, plain text greeting")
                .html("<p>Hi <b>{{name}}</b>, html greeting</p>")
                .build(),
        )
        .send()
        .await
        .unwrap();

    let resp = ses
        .test_render_email_template()
        .template_name("welcome")
        .template_data(r#"{"name":"Alice"}"#)
        .send()
        .await
        .unwrap();
    let mime_str = resp.rendered_template().to_string();

    let parsed = MessageParser::default().parse(mime_str.as_bytes()).unwrap();
    assert_eq!(parsed.subject().unwrap(), "Welcome, Alice");
    assert!(parsed.date().is_some(), "Date header must be present");
    assert!(parsed.message_id().is_some(), "Message-ID must be present");

    let parts: Vec<_> = parsed.parts.iter().collect();
    assert!(
        parts.len() >= 3,
        "expected multipart/alternative with two parts and root"
    );

    let bodies: Vec<String> = parsed
        .text_bodies()
        .map(|p| p.text_contents().unwrap_or_default().to_string())
        .chain(
            parsed
                .html_bodies()
                .map(|p| p.text_contents().unwrap_or_default().to_string()),
        )
        .collect();
    assert!(bodies.iter().any(|b| b.contains("Hi Alice, plain text")));
    assert!(bodies
        .iter()
        .any(|b| b.contains("<p>Hi <b>Alice</b>, html greeting</p>")));
}

#[tokio::test]
async fn ses_test_render_template_handles_non_ascii() {
    let server = TestServer::start().await;
    let ses = server.sesv2_client().await;

    ses.create_email_template()
        .template_name("intl")
        .template_content(
            EmailTemplateContent::builder()
                .subject("héllo {{name}}")
                .text("café for {{name}}")
                .build(),
        )
        .send()
        .await
        .unwrap();

    let resp = ses
        .test_render_email_template()
        .template_name("intl")
        .template_data(r#"{"name":"Élise"}"#)
        .send()
        .await
        .unwrap();
    let mime_str = resp.rendered_template().to_string();

    let parsed = MessageParser::default()
        .parse(mime_str.as_bytes())
        .expect("MIME parses");
    assert_eq!(parsed.subject().unwrap(), "héllo Élise");
    let body = parsed
        .text_bodies()
        .next()
        .unwrap()
        .text_contents()
        .unwrap();
    assert!(body.contains("café for Élise"));

    let _ = EmailTemplateMetadata::builder().build();
}
