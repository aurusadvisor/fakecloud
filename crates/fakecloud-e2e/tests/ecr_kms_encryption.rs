//! ECR layer blobs are encrypted with AES-256-GCM via fakecloud-kms
//! when the repo is configured with `encryptionType=KMS`. The raw
//! bytes stored on disk differ from the plaintext, but round-tripping
//! through the OCI v2 blob GET returns the plaintext.

mod helpers;

use aws_sdk_ecr::types::{EncryptionConfiguration, EncryptionType};
use base64::Engine;
use helpers::TestServer;
use reqwest::StatusCode;

#[tokio::test]
async fn kms_encrypted_repo_round_trips_layer_bytes() {
    let server = TestServer::start().await;
    let kms = server.kms_client().await;
    let ecr = server.ecr_client().await;

    // Set up a KMS key.
    let key = kms
        .create_key()
        .description("ecr-encryption-test")
        .send()
        .await
        .expect("create_key");
    let key_arn = key.key_metadata().unwrap().arn().unwrap().to_string();

    // Repo configured with KMS encryption under that key.
    ecr.create_repository()
        .repository_name("kms-encrypted-repo")
        .encryption_configuration(
            EncryptionConfiguration::builder()
                .encryption_type(EncryptionType::Kms)
                .kms_key(&key_arn)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("create_repository with KMS");

    // Push a blob via the OCI v2 single-POST upload path.
    let http = reqwest::Client::new();
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("AWS:test")
    );
    let plaintext = b"hello fakecloud-kms encrypted layer bytes".to_vec();
    let digest = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&plaintext);
        format!("sha256:{:x}", h.finalize())
    };

    // Two-phase: POST /uploads/ (no body), capture Location + upload id.
    let start = http
        .post(format!(
            "{}/v2/kms-encrypted-repo/blobs/uploads/",
            server.endpoint()
        ))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(start.status(), StatusCode::ACCEPTED);
    let upload_location = start
        .headers()
        .get("location")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string();

    // PATCH bytes + PUT with digest.
    let patch_url = format!("{}{}", server.endpoint(), upload_location);
    let patched = http
        .patch(&patch_url)
        .header("Authorization", &auth)
        .body(plaintext.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(patched.status(), StatusCode::ACCEPTED);

    let put_url = format!("{}{}?digest={}", server.endpoint(), upload_location, digest);
    let put = http
        .put(&put_url)
        .header("Authorization", &auth)
        .body(Vec::<u8>::new())
        .send()
        .await
        .unwrap();
    assert_eq!(put.status(), StatusCode::CREATED);

    // GET the blob back — should be plaintext.
    let got = http
        .get(format!(
            "{}/v2/kms-encrypted-repo/blobs/{digest}",
            server.endpoint()
        ))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert!(
        got.status().is_success(),
        "blob GET status = {}",
        got.status()
    );
    let got_bytes = got.bytes().await.unwrap();
    assert_eq!(
        got_bytes.as_ref(),
        plaintext.as_slice(),
        "blob GET returned non-plaintext"
    );
}

#[tokio::test]
async fn aes256_repo_stores_plaintext_as_before() {
    // Default encryption_type=AES256 is a no-op in fakecloud: blobs
    // stored plaintext. This test guards against accidentally
    // flipping that path to encrypted when KMS isn't configured.
    let server = TestServer::start().await;
    let ecr = server.ecr_client().await;
    ecr.create_repository()
        .repository_name("aes256-repo")
        .send()
        .await
        .unwrap();

    let http = reqwest::Client::new();
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("AWS:test")
    );
    let plaintext = b"plaintext under aes256".to_vec();
    let digest = {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(&plaintext);
        format!("sha256:{:x}", h.finalize())
    };
    let url = format!(
        "{}/v2/aes256-repo/blobs/uploads/?digest={}",
        server.endpoint(),
        digest
    );
    let posted = http
        .post(&url)
        .header("Authorization", &auth)
        .body(plaintext.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(posted.status(), StatusCode::CREATED);

    let got = http
        .get(format!(
            "{}/v2/aes256-repo/blobs/{digest}",
            server.endpoint()
        ))
        .header("Authorization", &auth)
        .send()
        .await
        .unwrap();
    assert_eq!(got.bytes().await.unwrap().as_ref(), plaintext.as_slice());
}
