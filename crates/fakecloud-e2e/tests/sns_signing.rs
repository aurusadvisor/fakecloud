mod helpers;

use base64::Engine;
use helpers::TestServer;
use rsa::pkcs1v15::{Signature, VerifyingKey};
use rsa::pkcs8::DecodePublicKey;
use rsa::sha2::Sha256;
use rsa::signature::Verifier;
use rsa::RsaPublicKey;
use serde_json::Value;
use x509_cert::der::{DecodePem, Encode};
use x509_cert::Certificate;

/// Read the SNS signing cert via the introspection endpoint, publish a
/// notification, and verify the resulting envelope's RSA-SHA256 signature
/// over the AWS canonical string with the public key from the cert.
#[tokio::test]
async fn sns_publish_signature_verifies_against_cert_pem() {
    let server = TestServer::start().await;
    let sns = server.sns_client().await;
    let sqs = server.sqs_client().await;

    let topic = sns.create_topic().name("sig-topic").send().await.unwrap();
    let topic_arn = topic.topic_arn().unwrap().to_string();

    let queue = sqs.create_queue().queue_name("sig-q").send().await.unwrap();
    let queue_url = queue.queue_url().unwrap().to_string();
    let attrs = sqs
        .get_queue_attributes()
        .queue_url(&queue_url)
        .attribute_names(aws_sdk_sqs::types::QueueAttributeName::QueueArn)
        .send()
        .await
        .unwrap();
    let queue_arn = attrs
        .attributes()
        .unwrap()
        .get(&aws_sdk_sqs::types::QueueAttributeName::QueueArn)
        .unwrap()
        .clone();

    sns.subscribe()
        .topic_arn(&topic_arn)
        .protocol("sqs")
        .endpoint(&queue_arn)
        .return_subscription_arn(true)
        .send()
        .await
        .unwrap();

    sns.publish()
        .topic_arn(&topic_arn)
        .message("hello world")
        .subject("greetings")
        .send()
        .await
        .unwrap();

    let recv = sqs
        .receive_message()
        .queue_url(&queue_url)
        .max_number_of_messages(1)
        .wait_time_seconds(2)
        .send()
        .await
        .unwrap();
    let body = recv.messages().first().unwrap().body().unwrap().to_string();
    let envelope: Value = serde_json::from_str(&body).unwrap();
    let signature_b64 = envelope["Signature"].as_str().unwrap();
    let cert_url = envelope["SigningCertURL"].as_str().unwrap();
    let message = envelope["Message"].as_str().unwrap();
    let message_id = envelope["MessageId"].as_str().unwrap();
    let subject = envelope["Subject"].as_str();
    let timestamp = envelope["Timestamp"].as_str().unwrap();
    let arn = envelope["TopicArn"].as_str().unwrap();
    assert_ne!(signature_b64, "FAKE_SIGNATURE");
    assert!(cert_url.ends_with("/_fakecloud/sns/cert.pem"));

    let pem = reqwest::get(cert_url).await.unwrap().text().await.unwrap();
    assert!(pem.starts_with("-----BEGIN CERTIFICATE-----"));

    let cert = Certificate::from_pem(pem.as_bytes()).unwrap();
    let spki_der = cert
        .tbs_certificate
        .subject_public_key_info
        .to_der()
        .unwrap();
    let public_key = RsaPublicKey::from_public_key_der(&spki_der).unwrap();
    let verifying = VerifyingKey::<Sha256>::new(public_key);

    let signature_bytes = base64::engine::general_purpose::STANDARD
        .decode(signature_b64)
        .unwrap();
    let signature = Signature::try_from(signature_bytes.as_slice()).unwrap();

    let mut canonical = String::new();
    canonical.push_str("Message\n");
    canonical.push_str(message);
    canonical.push('\n');
    canonical.push_str("MessageId\n");
    canonical.push_str(message_id);
    canonical.push('\n');
    if let Some(s) = subject.filter(|s| !s.is_empty()) {
        canonical.push_str("Subject\n");
        canonical.push_str(s);
        canonical.push('\n');
    }
    canonical.push_str("Timestamp\n");
    canonical.push_str(timestamp);
    canonical.push('\n');
    canonical.push_str("TopicArn\n");
    canonical.push_str(arn);
    canonical.push('\n');
    canonical.push_str("Type\n");
    canonical.push_str("Notification\n");

    verifying
        .verify(canonical.as_bytes(), &signature)
        .expect("signature must verify against fakecloud's public cert");
}
