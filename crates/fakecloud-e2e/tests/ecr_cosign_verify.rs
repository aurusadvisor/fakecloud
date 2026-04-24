//! ECR cosign signature verification end-to-end: push an image, push
//! a cosign companion `.sig` manifest, configure a trusted public
//! key, and assert `DescribeImageSigningStatus` reports SIGNED.

mod helpers;

use base64::Engine;
use helpers::TestServer;
use p256::ecdsa::signature::Signer;
use p256::ecdsa::{Signature, SigningKey};
use p256::pkcs8::EncodePublicKey;
use reqwest::StatusCode;

fn auth_header() -> String {
    format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("AWS:test")
    )
}

fn sha256(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(bytes);
    format!("sha256:{:x}", h.finalize())
}

/// Push `bytes` as a generic blob via OCI v2 single-POST upload.
async fn push_blob(http: &reqwest::Client, endpoint: &str, repo: &str, bytes: &[u8]) -> String {
    let digest = sha256(bytes);
    let url = format!(
        "{endpoint}/v2/{repo}/blobs/uploads/?digest={digest}",
        endpoint = endpoint,
        repo = repo,
        digest = digest,
    );
    let r = http
        .post(&url)
        .header("Authorization", auth_header())
        .body(bytes.to_vec())
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.status(),
        StatusCode::CREATED,
        "blob push failed: {}",
        r.status()
    );
    digest
}

async fn push_manifest(
    http: &reqwest::Client,
    endpoint: &str,
    repo: &str,
    reference: &str,
    manifest: &serde_json::Value,
) -> String {
    let body = serde_json::to_vec(manifest).unwrap();
    let r = http
        .put(format!(
            "{endpoint}/v2/{repo}/manifests/{reference}",
            endpoint = endpoint,
            repo = repo,
            reference = reference,
        ))
        .header("Authorization", auth_header())
        .header(
            "Content-Type",
            "application/vnd.docker.distribution.manifest.v2+json",
        )
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    r.headers()
        .get("docker-content-digest")
        .and_then(|v| v.to_str().ok())
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn cosign_signed_image_reports_signed() {
    let server = TestServer::start().await;
    let ecr = server.ecr_client().await;
    ecr.create_repository()
        .repository_name("cosign-test")
        .send()
        .await
        .unwrap();

    // Push a minimal empty image (no layers) so we have something to sign.
    let http = reqwest::Client::new();
    let config_blob = br#"{}"#.to_vec();
    let config_digest = push_blob(&http, server.endpoint(), "cosign-test", &config_blob).await;
    let image_manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": config_blob.len(),
            "digest": config_digest
        },
        "layers": []
    });
    let image_digest = push_manifest(
        &http,
        server.endpoint(),
        "cosign-test",
        "v1",
        &image_manifest,
    )
    .await;
    let image_hex = image_digest.strip_prefix("sha256:").unwrap();

    // Build cosign simple-signing payload that names the signed image.
    let payload = serde_json::json!({
        "critical": {
            "identity": {"docker-reference": "fakecloud.local/cosign-test"},
            "image": {"docker-manifest-digest": image_digest},
            "type": "cosign container image signature"
        },
        "optional": {}
    });
    let payload_bytes = serde_json::to_vec(&payload).unwrap();

    // Deterministic keypair so the public PEM is stable across runs.
    let sk_bytes = [9u8; 32];
    let sk = SigningKey::from_bytes((&sk_bytes).into()).unwrap();
    let vk_pem = sk
        .verifying_key()
        .to_public_key_pem(Default::default())
        .unwrap();
    let sig: Signature = sk.sign(&payload_bytes);
    let sig_der_b64 = base64::engine::general_purpose::STANDARD.encode(sig.to_der());

    // Push the payload as a blob and the cosign manifest tagged `.sig`.
    let payload_digest = push_blob(&http, server.endpoint(), "cosign-test", &payload_bytes).await;
    let sig_manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.manifest.v1+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 2,
            "digest": config_digest
        },
        "layers": [{
            "mediaType": "application/vnd.dev.cosign.simplesigning.v1+json",
            "size": payload_bytes.len(),
            "digest": payload_digest,
            "annotations": {
                "dev.cosignproject.cosign/signature": sig_der_b64
            }
        }]
    });
    let sig_tag = format!("sha256-{image_hex}.sig");
    push_manifest(
        &http,
        server.endpoint(),
        "cosign-test",
        &sig_tag,
        &sig_manifest,
    )
    .await;

    // Without a trusted key configured yet, status should be UNVERIFIED.
    let resp = ecr
        .describe_image_signing_status()
        .repository_name("cosign-test")
        .image_id(
            aws_sdk_ecr::types::ImageIdentifier::builder()
                .image_tag("v1")
                .build(),
        )
        .send()
        .await
        .expect("describe_image_signing_status pre-config");
    // Raw HTTP to read signingStatus — unknown SDK fields get dropped.
    let raw: serde_json::Value = reqwest::Client::new()
        .post(server.endpoint())
        .header(
            "X-Amz-Target",
            "AmazonEC2ContainerRegistry_V20150921.DescribeImageSigningStatus",
        )
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("Authorization", "AWS4-HMAC-SHA256 Credential=test/20260424/us-east-1/ecr/aws4_request, SignedHeaders=host, Signature=0")
        .body(
            serde_json::json!({
                "repositoryName": "cosign-test",
                "imageId": {"imageTag": "v1"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        raw["signingStatus"].as_str(),
        Some("UNVERIFIED"),
        "expected UNVERIFIED pre-config; raw={raw}"
    );
    let _ = resp;

    // Configure the trusted key.
    reqwest::Client::new()
        .post(server.endpoint())
        .header(
            "X-Amz-Target",
            "AmazonEC2ContainerRegistry_V20150921.PutSigningConfiguration",
        )
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("Authorization", "AWS4-HMAC-SHA256 Credential=test/20260424/us-east-1/ecr/aws4_request, SignedHeaders=host, Signature=0")
        .body(
            serde_json::json!({
                "signingConfiguration": {
                    "rules": [{
                        "trustedKeys": [{
                            "keyId": "test-key",
                            "pem": vk_pem,
                            "algorithm": "ECDSA-P256",
                        }]
                    }]
                }
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();

    // Re-describe — should now be SIGNED + valid.
    let raw: serde_json::Value = reqwest::Client::new()
        .post(server.endpoint())
        .header(
            "X-Amz-Target",
            "AmazonEC2ContainerRegistry_V20150921.DescribeImageSigningStatus",
        )
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("Authorization", "AWS4-HMAC-SHA256 Credential=test/20260424/us-east-1/ecr/aws4_request, SignedHeaders=host, Signature=0")
        .body(
            serde_json::json!({
                "repositoryName": "cosign-test",
                "imageId": {"imageTag": "v1"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(
        raw["signingStatus"].as_str(),
        Some("SIGNED"),
        "expected SIGNED post-config; raw={raw}"
    );
    assert_eq!(raw["imageSignatures"][0]["valid"].as_bool(), Some(true));
    assert_eq!(
        raw["imageSignatures"][0]["keyId"].as_str(),
        Some("test-key")
    );
}

#[tokio::test]
async fn unsigned_image_reports_unsigned() {
    let server = TestServer::start().await;
    let ecr = server.ecr_client().await;
    ecr.create_repository()
        .repository_name("unsigned-repo")
        .send()
        .await
        .unwrap();

    let http = reqwest::Client::new();
    let manifest = serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.docker.distribution.manifest.v2+json",
        "config": {
            "mediaType": "application/vnd.docker.container.image.v1+json",
            "size": 0,
            "digest": "sha256:0000000000000000000000000000000000000000000000000000000000000000"
        },
        "layers": []
    });
    push_manifest(&http, server.endpoint(), "unsigned-repo", "v1", &manifest).await;

    let raw: serde_json::Value = reqwest::Client::new()
        .post(server.endpoint())
        .header(
            "X-Amz-Target",
            "AmazonEC2ContainerRegistry_V20150921.DescribeImageSigningStatus",
        )
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("Authorization", "AWS4-HMAC-SHA256 Credential=test/20260424/us-east-1/ecr/aws4_request, SignedHeaders=host, Signature=0")
        .body(
            serde_json::json!({
                "repositoryName": "unsigned-repo",
                "imageId": {"imageTag": "v1"}
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(raw["signingStatus"].as_str(), Some("UNSIGNED"));
    assert_eq!(raw["imageSignatures"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn put_signing_configuration_rejects_bad_pem() {
    let server = TestServer::start().await;
    let resp = reqwest::Client::new()
        .post(server.endpoint())
        .header(
            "X-Amz-Target",
            "AmazonEC2ContainerRegistry_V20150921.PutSigningConfiguration",
        )
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("Authorization", "AWS4-HMAC-SHA256 Credential=test/20260424/us-east-1/ecr/aws4_request, SignedHeaders=host, Signature=0")
        .body(
            serde_json::json!({
                "signingConfiguration": {
                    "rules": [{
                        "trustedKeys": [{
                            "keyId": "bad",
                            "pem": "not-a-pem",
                            "algorithm": "ECDSA-P256"
                        }]
                    }]
                }
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
}
