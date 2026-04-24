//! S3 SSE-KMS end-to-end:
//! - PutObject with `ServerSideEncryption=aws:kms` triggers
//!   `kms:GenerateDataKey` with the bucket-arn encryption context
//! - GetObject decrypts via `kms:Decrypt` and returns the original bytes
//! - Both calls land in `/_fakecloud/kms/usage`
//! - Range reads against an SSE-KMS object slice plaintext, not ciphertext

mod helpers;

use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::ServerSideEncryption;
use helpers::TestServer;

#[tokio::test]
async fn s3_put_get_sse_kms_round_trip() {
    let server = TestServer::start().await;
    let s3 = server.s3_client().await;
    let http = reqwest::Client::new();

    s3.create_bucket().bucket("encrypted").send().await.unwrap();
    s3.put_object()
        .bucket("encrypted")
        .key("note.txt")
        .body(ByteStream::from_static(b"top-secret-payload"))
        .server_side_encryption(ServerSideEncryption::AwsKms)
        .ssekms_key_id("alias/aws/s3")
        .send()
        .await
        .unwrap();

    let got = s3
        .get_object()
        .bucket("encrypted")
        .key("note.txt")
        .send()
        .await
        .unwrap();
    let bytes = got.body.collect().await.unwrap().into_bytes();
    assert_eq!(
        &bytes[..],
        b"top-secret-payload",
        "GetObject must return plaintext after SSE-KMS round-trip"
    );

    let usage: serde_json::Value = http
        .get(format!("{}/_fakecloud/kms/usage", server.endpoint()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let records = usage["records"].as_array().expect("records array");
    let s3_records: Vec<&serde_json::Value> = records
        .iter()
        .filter(|r| r["servicePrincipal"].as_str() == Some("s3.amazonaws.com"))
        .collect();
    assert!(
        s3_records.iter().any(|r| {
            r["operation"].as_str() == Some("GenerateDataKey")
                && r["encryptionContext"]["aws:s3:arn"].as_str() == Some("arn:aws:s3:::encrypted")
        }),
        "expected GenerateDataKey bound to bucket arn, got: {s3_records:?}"
    );
    assert!(
        s3_records.iter().any(|r| {
            r["operation"].as_str() == Some("Decrypt")
                && r["encryptionContext"]["aws:s3:arn"].as_str() == Some("arn:aws:s3:::encrypted")
        }),
        "expected Decrypt bound to bucket arn, got: {s3_records:?}"
    );
}

#[tokio::test]
async fn s3_sse_kms_range_read_returns_plaintext_slice() {
    let server = TestServer::start().await;
    let s3 = server.s3_client().await;

    s3.create_bucket().bucket("ranges").send().await.unwrap();
    s3.put_object()
        .bucket("ranges")
        .key("doc")
        .body(ByteStream::from_static(b"abcdefghij"))
        .server_side_encryption(ServerSideEncryption::AwsKms)
        .ssekms_key_id("alias/aws/s3")
        .send()
        .await
        .unwrap();

    let got = s3
        .get_object()
        .bucket("ranges")
        .key("doc")
        .range("bytes=2-5")
        .send()
        .await
        .unwrap();
    let bytes = got.body.collect().await.unwrap().into_bytes();
    assert_eq!(
        &bytes[..],
        b"cdef",
        "ranged read of SSE-KMS object must slice plaintext, not the stored ciphertext envelope"
    );
}

#[tokio::test]
async fn s3_plain_put_does_not_invoke_kms() {
    let server = TestServer::start().await;
    let s3 = server.s3_client().await;
    let http = reqwest::Client::new();

    s3.create_bucket().bucket("plain").send().await.unwrap();
    s3.put_object()
        .bucket("plain")
        .key("k")
        .body(ByteStream::from_static(b"v"))
        .send()
        .await
        .unwrap();

    let usage: serde_json::Value = http
        .get(format!("{}/_fakecloud/kms/usage", server.endpoint()))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let records = usage["records"].as_array().expect("records array");
    assert!(
        !records
            .iter()
            .any(|r| r["servicePrincipal"].as_str() == Some("s3.amazonaws.com")),
        "PutObject without SSE-KMS must not record KMS usage, got: {records:?}"
    );
}
