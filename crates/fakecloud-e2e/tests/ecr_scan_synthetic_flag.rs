//! ECR `DescribeImageScanFindings` returns `isSynthetic: true` so
//! users introspecting scan results can tell fakecloud's stub scanner
//! from real AWS Inspector output. Asserted via raw HTTP because
//! aws-sdk-ecr drops unknown response fields during Smithy decode.

mod helpers;

use helpers::TestServer;

#[tokio::test]
async fn describe_image_scan_findings_is_flagged_synthetic() {
    let server = TestServer::start().await;
    let ecr = server.ecr_client().await;

    ecr.create_repository()
        .repository_name("synthetic-flag-repo")
        .send()
        .await
        .unwrap();

    // Push a minimal empty manifest via OCI v2 so there's an image to
    // reference — `DescribeImageScanFindings` requires an existing
    // imageId (digest or tag).
    let http = reqwest::Client::new();
    let auth = format!(
        "Basic {}",
        base64::engine::general_purpose::STANDARD.encode("AWS:test")
    );
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
    let body = serde_json::to_vec(&manifest).unwrap();
    http.put(format!(
        "{}/v2/synthetic-flag-repo/manifests/v1",
        server.endpoint()
    ))
    .header("Authorization", &auth)
    .header(
        "Content-Type",
        "application/vnd.docker.distribution.manifest.v2+json",
    )
    .body(body)
    .send()
    .await
    .unwrap()
    .error_for_status()
    .unwrap();

    // Hit the AWS JSON surface via raw HTTP so the unknown
    // `isSynthetic` key survives the response envelope.
    let resp = http
        .post(server.endpoint())
        .header("X-Amz-Target", "AmazonEC2ContainerRegistry_V20150921.DescribeImageScanFindings")
        .header("Content-Type", "application/x-amz-json-1.1")
        .header("Authorization", "AWS4-HMAC-SHA256 Credential=test/20260424/us-east-1/ecr/aws4_request, SignedHeaders=host, Signature=0000")
        .body(
            serde_json::json!({
                "repositoryName": "synthetic-flag-repo",
                "imageId": { "imageTag": "v1" }
            })
            .to_string(),
        )
        .send()
        .await
        .unwrap();
    assert!(resp.status().is_success(), "status = {}", resp.status());
    let body: serde_json::Value = resp.json().await.unwrap();
    assert_eq!(
        body["imageScanFindings"]["isSynthetic"].as_bool(),
        Some(true),
        "expected isSynthetic=true; full body: {body}"
    );
}

use base64::Engine;
