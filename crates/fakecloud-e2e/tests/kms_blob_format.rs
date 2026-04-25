mod helpers;

use aws_sdk_kms::primitives::Blob;
use base64::Engine;
use helpers::TestServer;

const VERSION_HEADER: [u8; 4] = [0x01, 0x02, 0x02, 0x00];

#[tokio::test]
async fn encrypt_decrypt_round_trips_through_blob_format() {
    let server = TestServer::start().await;
    let client = server.kms_client().await;

    let key = client
        .create_key()
        .description("blob-test")
        .send()
        .await
        .unwrap();
    let key_id = key.key_metadata().unwrap().key_id().to_string();

    let plaintext = b"plaintext-bytes-for-blob-test";
    let resp = client
        .encrypt()
        .key_id(&key_id)
        .plaintext(Blob::new(plaintext.to_vec()))
        .send()
        .await
        .unwrap();
    let ct = resp.ciphertext_blob().unwrap();

    // Verify it's the AWS-shaped binary blob (version header) and never
    // contains plaintext bytes.
    let raw = ct.as_ref();
    assert_eq!(&raw[0..4], VERSION_HEADER, "expected version header");
    assert!(
        raw.windows(plaintext.len()).all(|w| w != plaintext),
        "plaintext must not appear anywhere in the ciphertext"
    );

    // Round-trip through Decrypt
    let decrypted = client
        .decrypt()
        .ciphertext_blob(ct.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(decrypted.plaintext().unwrap().as_ref(), plaintext);
}

#[tokio::test]
async fn legacy_textual_envelope_still_decrypts() {
    let server = TestServer::start().await;
    let client = server.kms_client().await;

    let key = client.create_key().send().await.unwrap();
    let key_id = key.key_metadata().unwrap().key_id().to_string();

    // Build a legacy envelope `fakecloud-kms:<key>:<base64-plaintext>`. The
    // SDK base64-encodes the bytes for wire transport; the server decodes
    // once and parses the inner envelope.
    let plaintext = b"legacy-envelope-payload";
    let pt_b64 = base64::engine::general_purpose::STANDARD.encode(plaintext);
    let envelope = format!("fakecloud-kms:{key_id}:{pt_b64}");

    let resp = client
        .decrypt()
        .ciphertext_blob(Blob::new(envelope.into_bytes()))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.plaintext().unwrap().as_ref(), plaintext);
}

#[tokio::test]
async fn generate_data_key_returns_blob_format() {
    let server = TestServer::start().await;
    let client = server.kms_client().await;

    let key = client.create_key().send().await.unwrap();
    let key_id = key.key_metadata().unwrap().key_id().to_string();

    let resp = client
        .generate_data_key()
        .key_id(&key_id)
        .key_spec(aws_sdk_kms::types::DataKeySpec::Aes256)
        .send()
        .await
        .unwrap();

    let ct = resp.ciphertext_blob().unwrap();
    assert_eq!(&ct.as_ref()[0..4], VERSION_HEADER);

    // Decrypt the wrapped data key — should match plaintext.
    let plaintext = resp.plaintext().unwrap();
    let decrypted = client
        .decrypt()
        .ciphertext_blob(ct.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(decrypted.plaintext().unwrap().as_ref(), plaintext.as_ref());
}
