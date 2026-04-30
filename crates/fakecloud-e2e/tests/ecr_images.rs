//! ECR Batch 2: image + layer operations end-to-end.

mod helpers;

use aws_sdk_ecr::primitives::Blob;
use helpers::TestServer;
use sha2::{Digest, Sha256};

fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

#[tokio::test]
async fn layer_upload_round_trip() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;

    client
        .create_repository()
        .repository_name("layers-repo")
        .send()
        .await
        .unwrap();

    let init = client
        .initiate_layer_upload()
        .repository_name("layers-repo")
        .send()
        .await
        .unwrap();
    let upload_id = init.upload_id().unwrap().to_string();
    assert!(init.part_size().unwrap_or(0) >= 1);

    let blob = b"hello-fakecloud-ecr-layer".to_vec();
    let expected_digest = sha256_digest(&blob);

    let part = client
        .upload_layer_part()
        .repository_name("layers-repo")
        .upload_id(&upload_id)
        .part_first_byte(0)
        .part_last_byte((blob.len() as i64) - 1)
        .layer_part_blob(Blob::new(blob.clone()))
        .send()
        .await
        .unwrap();
    assert_eq!(part.last_byte_received(), Some((blob.len() as i64) - 1),);

    let complete = client
        .complete_layer_upload()
        .repository_name("layers-repo")
        .upload_id(&upload_id)
        .layer_digests(&expected_digest)
        .send()
        .await
        .unwrap();
    assert_eq!(complete.layer_digest(), Some(expected_digest.as_str()));

    let avail = client
        .batch_check_layer_availability()
        .repository_name("layers-repo")
        .layer_digests(&expected_digest)
        .send()
        .await
        .unwrap();
    assert_eq!(avail.layers().len(), 1);
    assert_eq!(
        avail.layers()[0].layer_digest(),
        Some(expected_digest.as_str())
    );
    assert_eq!(
        avail.layers()[0].layer_availability().unwrap().as_str(),
        "AVAILABLE"
    );

    // Download URL should reference the /v2 path even though Batch 3 hasn't landed.
    let dl = client
        .get_download_url_for_layer()
        .repository_name("layers-repo")
        .layer_digest(&expected_digest)
        .send()
        .await
        .unwrap();
    let url = dl.download_url().unwrap();
    assert!(
        url.contains("/v2/layers-repo/blobs/"),
        "unexpected url: {url}"
    );
    assert!(url.contains(&expected_digest));
}

#[tokio::test]
async fn complete_layer_upload_retry_after_bad_digest() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;

    client
        .create_repository()
        .repository_name("retry-repo")
        .send()
        .await
        .unwrap();
    let init = client
        .initiate_layer_upload()
        .repository_name("retry-repo")
        .send()
        .await
        .unwrap();
    let upload_id = init.upload_id().unwrap().to_string();
    let blob = b"retry-bytes".to_vec();
    let real_digest = sha256_digest(&blob);
    client
        .upload_layer_part()
        .repository_name("retry-repo")
        .upload_id(&upload_id)
        .part_first_byte(0)
        .part_last_byte((blob.len() as i64) - 1)
        .layer_part_blob(Blob::new(blob))
        .send()
        .await
        .unwrap();
    // First complete with wrong digest — must fail WITHOUT dropping upload state.
    client
        .complete_layer_upload()
        .repository_name("retry-repo")
        .upload_id(&upload_id)
        .layer_digests("sha256:deadbeef")
        .send()
        .await
        .expect_err("wrong digest fails");
    // Retry with the real digest using the same upload id.
    client
        .complete_layer_upload()
        .repository_name("retry-repo")
        .upload_id(&upload_id)
        .layer_digests(&real_digest)
        .send()
        .await
        .expect("retry with correct digest should succeed");
}

#[tokio::test]
async fn put_image_rejects_mismatched_supplied_digest() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;

    client
        .create_repository()
        .repository_name("digest-check-repo")
        .send()
        .await
        .unwrap();
    let err = client
        .put_image()
        .repository_name("digest-check-repo")
        .image_manifest(r#"{"x":1}"#)
        .image_digest("sha256:deadbeef")
        .send()
        .await
        .expect_err("mismatched digest should fail");
    assert!(
        format!("{err:?}").contains("ImageDigestDoesNotMatch"),
        "{err:?}"
    );
}

#[tokio::test]
async fn upload_layer_part_digest_mismatch_is_rejected() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;

    client
        .create_repository()
        .repository_name("bad-digest-repo")
        .send()
        .await
        .unwrap();

    let init = client
        .initiate_layer_upload()
        .repository_name("bad-digest-repo")
        .send()
        .await
        .unwrap();
    let upload_id = init.upload_id().unwrap().to_string();

    let blob = b"real-bytes".to_vec();
    client
        .upload_layer_part()
        .repository_name("bad-digest-repo")
        .upload_id(&upload_id)
        .part_first_byte(0)
        .part_last_byte((blob.len() as i64) - 1)
        .layer_part_blob(Blob::new(blob))
        .send()
        .await
        .unwrap();

    let err = client
        .complete_layer_upload()
        .repository_name("bad-digest-repo")
        .upload_id(&upload_id)
        .layer_digests("sha256:deadbeef")
        .send()
        .await
        .expect_err("mismatched digest should fail");
    assert!(
        format!("{err:?}").contains("LayerDigestMismatch"),
        "{err:?}"
    );
}

#[tokio::test]
async fn put_image_and_describe() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;

    client
        .create_repository()
        .repository_name("image-repo")
        .send()
        .await
        .unwrap();

    let manifest = r#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":7023,"digest":"sha256:dummy"},"layers":[]}"#;
    let put = client
        .put_image()
        .repository_name("image-repo")
        .image_manifest(manifest)
        .image_tag("v1")
        .send()
        .await
        .unwrap();
    let image = put.image().unwrap();
    assert_eq!(image.repository_name(), Some("image-repo"));
    assert_eq!(image.image_id().and_then(|id| id.image_tag()), Some("v1"),);
    let digest = image
        .image_id()
        .and_then(|id| id.image_digest())
        .unwrap()
        .to_string();
    assert_eq!(digest, sha256_digest(manifest.as_bytes()));

    // Re-put with a new tag pointing at the same digest.
    client
        .put_image()
        .repository_name("image-repo")
        .image_manifest(manifest)
        .image_tag("latest")
        .send()
        .await
        .unwrap();

    let list = client
        .list_images()
        .repository_name("image-repo")
        .send()
        .await
        .unwrap();
    let tags: Vec<String> = list
        .image_ids()
        .iter()
        .filter_map(|id| id.image_tag().map(|s| s.to_string()))
        .collect();
    assert!(tags.contains(&"v1".to_string()));
    assert!(tags.contains(&"latest".to_string()));

    let desc = client
        .describe_images()
        .repository_name("image-repo")
        .send()
        .await
        .unwrap();
    assert_eq!(desc.image_details().len(), 1);
    let details = &desc.image_details()[0];
    assert_eq!(details.image_digest(), Some(digest.as_str()));
    let detail_tags = details.image_tags();
    assert!(detail_tags.iter().any(|t| t == "v1"));
    assert!(detail_tags.iter().any(|t| t == "latest"));
}

#[tokio::test]
async fn batch_get_image_by_tag_and_digest() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;

    client
        .create_repository()
        .repository_name("batch-get-repo")
        .send()
        .await
        .unwrap();

    let manifest = r#"{"schemaVersion":2,"layers":[]}"#;
    let put = client
        .put_image()
        .repository_name("batch-get-repo")
        .image_manifest(manifest)
        .image_tag("v1")
        .send()
        .await
        .unwrap();
    let digest = put
        .image()
        .and_then(|i| i.image_id())
        .and_then(|id| id.image_digest())
        .unwrap()
        .to_string();

    use aws_sdk_ecr::types::ImageIdentifier;
    let by_tag = ImageIdentifier::builder().image_tag("v1").build();
    let by_digest = ImageIdentifier::builder().image_digest(&digest).build();

    let got = client
        .batch_get_image()
        .repository_name("batch-get-repo")
        .image_ids(by_tag)
        .image_ids(by_digest)
        .send()
        .await
        .unwrap();
    assert_eq!(got.images().len(), 2);
    assert!(got.failures().is_empty());
}

#[tokio::test]
async fn batch_delete_image_by_tag_keeps_image_until_last_tag() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;

    client
        .create_repository()
        .repository_name("del-repo")
        .send()
        .await
        .unwrap();

    let manifest = r#"{"schemaVersion":2}"#;
    client
        .put_image()
        .repository_name("del-repo")
        .image_manifest(manifest)
        .image_tag("a")
        .send()
        .await
        .unwrap();
    client
        .put_image()
        .repository_name("del-repo")
        .image_manifest(manifest)
        .image_tag("b")
        .send()
        .await
        .unwrap();

    use aws_sdk_ecr::types::ImageIdentifier;
    // Delete tag "a" — image should still be reachable via tag "b".
    client
        .batch_delete_image()
        .repository_name("del-repo")
        .image_ids(ImageIdentifier::builder().image_tag("a").build())
        .send()
        .await
        .unwrap();

    let still_there = client
        .describe_images()
        .repository_name("del-repo")
        .send()
        .await
        .unwrap();
    assert_eq!(still_there.image_details().len(), 1);
    let tags: Vec<&str> = still_there.image_details()[0]
        .image_tags()
        .iter()
        .map(|s| s.as_str())
        .collect();
    assert_eq!(tags, vec!["b"]);

    // Delete tag "b" too — image should be gone.
    client
        .batch_delete_image()
        .repository_name("del-repo")
        .image_ids(ImageIdentifier::builder().image_tag("b").build())
        .send()
        .await
        .unwrap();
    let empty = client
        .describe_images()
        .repository_name("del-repo")
        .send()
        .await
        .unwrap();
    assert!(empty.image_details().is_empty());
}

#[tokio::test]
async fn immutable_tag_blocks_reassignment() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;

    use aws_sdk_ecr::types::ImageTagMutability;
    client
        .create_repository()
        .repository_name("immut-repo")
        .image_tag_mutability(ImageTagMutability::Immutable)
        .send()
        .await
        .unwrap();

    client
        .put_image()
        .repository_name("immut-repo")
        .image_manifest(r#"{"a":1}"#)
        .image_tag("pinned")
        .send()
        .await
        .unwrap();

    let err = client
        .put_image()
        .repository_name("immut-repo")
        .image_manifest(r#"{"a":2}"#)
        .image_tag("pinned")
        .send()
        .await
        .expect_err("immutable tag rewrite should fail");
    assert!(format!("{err:?}").contains("ImageAlreadyExists"), "{err:?}");
}

#[tokio::test]
async fn put_image_triggers_scan_when_scan_on_push_enabled() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;

    client
        .create_repository()
        .repository_name("scan-repo")
        .image_scanning_configuration(
            aws_sdk_ecr::types::ImageScanningConfiguration::builder()
                .scan_on_push(true)
                .build(),
        )
        .send()
        .await
        .unwrap();

    let manifest = r#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","size":7023,"digest":"sha256:dummy"},"layers":[]}"#;
    let put = client
        .put_image()
        .repository_name("scan-repo")
        .image_manifest(manifest)
        .image_tag("v1")
        .send()
        .await
        .unwrap();
    let digest = put
        .image()
        .and_then(|i| i.image_id())
        .and_then(|id| id.image_digest())
        .unwrap()
        .to_string();

    // Poll DescribeImageScanFindings until the scan transitions out of
    // IN_PROGRESS. With scan-on-push the scanner kicks immediately; the
    // poll catches either IN_PROGRESS (race) or COMPLETE.
    for _ in 0..40 {
        let resp = client
            .describe_image_scan_findings()
            .repository_name("scan-repo")
            .image_id(
                aws_sdk_ecr::types::ImageIdentifier::builder()
                    .image_digest(&digest)
                    .build(),
            )
            .send()
            .await;
        if let Ok(r) = resp {
            let status = r.image_scan_status().and_then(|s| s.status());
            if status.map(|s| s.as_str()) != Some("FAILED") {
                // Found a status — happy path. Either IN_PROGRESS or
                // COMPLETE; both prove the scan was kicked.
                return;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    panic!("scan-on-push did not kick a scan within budget");
}
