//! ECR cross-account repository policy enforcement (P2).
//!
//! Validates that the JSON control plane evaluates the repository
//! resource policy via the IAM evaluator on cross-account image and
//! layer ops, returning the canonical AWS error codes:
//!
//! * `RepositoryPolicyNotFoundException` when the repository has no
//!   policy at all.
//! * `AccessDeniedException` when a policy exists but doesn't grant
//!   the requested action to the caller.
//! * Allow when the policy explicitly grants the action to the caller.
//!
//! Same-account flows are covered by the wider ECR test suite — this
//! file deliberately focuses on the cross-account gate that real AWS
//! enforces and that real customers rely on for share-out scenarios.

mod helpers;

use aws_credential_types::Credentials;
use aws_sdk_ecr::Client as EcrClient;
use helpers::TestServer;

const ACCOUNT_A: &str = "123456789012"; // repository owner
const ACCOUNT_B: &str = "222222222222"; // allowed cross-account caller
const ACCOUNT_C: &str = "333333333333"; // unrelated caller

async fn start() -> TestServer {
    TestServer::start_with_env(&[
        ("FAKECLOUD_IAM", "strict"),
        ("FAKECLOUD_VERIFY_SIGV4", "true"),
    ])
    .await
}

async fn ecr_client_for(server: &TestServer, akid: &str, secret: &str) -> EcrClient {
    let cfg = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .endpoint_url(server.endpoint())
        .region(aws_config::Region::new("us-east-1"))
        .credentials_provider(Credentials::new(akid, secret, None, None, "ecr-x-acct"))
        .load()
        .await;
    EcrClient::new(&cfg)
}

#[tokio::test]
async fn cross_account_batch_get_image_honours_repo_policy() {
    let server = start().await;

    // Bootstrap admins in all three accounts.
    let (a_akid, a_secret) = server.create_admin(ACCOUNT_A, "admin-a").await;
    let (b_akid, b_secret) = server.create_admin(ACCOUNT_B, "admin-b").await;
    let (c_akid, c_secret) = server.create_admin(ACCOUNT_C, "admin-c").await;

    let ecr_a = ecr_client_for(&server, &a_akid, &a_secret).await;
    let ecr_b = ecr_client_for(&server, &b_akid, &b_secret).await;
    let ecr_c = ecr_client_for(&server, &c_akid, &c_secret).await;

    // Account A creates a repo and pushes an image so we can request it
    // by tag from accounts B and C.
    ecr_a
        .create_repository()
        .repository_name("shared")
        .send()
        .await
        .expect("create_repository in A");

    let manifest = r#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":0,"mediaType":"application/vnd.docker.container.image.v1+json"},"layers":[]}"#;
    ecr_a
        .put_image()
        .repository_name("shared")
        .image_manifest(manifest)
        .image_tag("v1")
        .send()
        .await
        .expect("put_image in A");

    // Step 1: with NO policy, account B's BatchGetImage targeting A's
    // registry must fail with RepositoryPolicyNotFoundException so the
    // caller can tell that the owner hasn't shared the repo at all.
    let err_no_policy = ecr_b
        .batch_get_image()
        .registry_id(ACCOUNT_A)
        .repository_name("shared")
        .image_ids(
            aws_sdk_ecr::types::ImageIdentifier::builder()
                .image_tag("v1")
                .build(),
        )
        .send()
        .await
        .expect_err("expected RepositoryPolicyNotFoundException without policy");
    let msg = format!("{err_no_policy:?}");
    assert!(
        msg.contains("RepositoryPolicyNotFound"),
        "expected RepositoryPolicyNotFoundException without policy, got: {msg}"
    );

    // Step 2: A sets a policy allowing only account B for BatchGetImage.
    let policy = format!(
        r#"{{
            "Version": "2012-10-17",
            "Statement": [{{
                "Sid": "ShareToB",
                "Effect": "Allow",
                "Principal": {{"AWS": "arn:aws:iam::{ACCOUNT_B}:root"}},
                "Action": ["ecr:BatchGetImage", "ecr:GetDownloadUrlForLayer"],
                "Resource": "*"
            }}]
        }}"#
    );
    ecr_a
        .set_repository_policy()
        .repository_name("shared")
        .policy_text(&policy)
        .send()
        .await
        .expect("set_repository_policy");

    // Step 3: account B's BatchGetImage now succeeds (policy explicitly allows).
    let resp_b = ecr_b
        .batch_get_image()
        .registry_id(ACCOUNT_A)
        .repository_name("shared")
        .image_ids(
            aws_sdk_ecr::types::ImageIdentifier::builder()
                .image_tag("v1")
                .build(),
        )
        .send()
        .await
        .expect("BatchGetImage from B should succeed");
    assert_eq!(
        resp_b.images().len(),
        1,
        "expected one image returned to allowed caller"
    );

    // Step 4: account C is not in the policy — implicit deny path returns
    // AccessDeniedException, NOT RepositoryPolicyNotFoundException, so the
    // caller can tell a policy exists but they're not on the allow list.
    let err_c = ecr_c
        .batch_get_image()
        .registry_id(ACCOUNT_A)
        .repository_name("shared")
        .image_ids(
            aws_sdk_ecr::types::ImageIdentifier::builder()
                .image_tag("v1")
                .build(),
        )
        .send()
        .await
        .expect_err("expected AccessDeniedException for unrelated caller");
    let msg_c = format!("{err_c:?}");
    assert!(
        msg_c.contains("AccessDenied"),
        "expected AccessDeniedException for C, got: {msg_c}"
    );

    // Step 5: same-account caller (A itself) bypasses the resource policy
    // entirely. The IAM identity policies handle this path; the
    // resource-policy gate must not block the owner.
    let resp_a = ecr_a
        .batch_get_image()
        .repository_name("shared")
        .image_ids(
            aws_sdk_ecr::types::ImageIdentifier::builder()
                .image_tag("v1")
                .build(),
        )
        .send()
        .await
        .expect("BatchGetImage from A should always succeed");
    assert_eq!(resp_a.images().len(), 1);
}

#[tokio::test]
async fn cross_account_get_download_url_honours_repo_policy() {
    let server = start().await;

    let (a_akid, a_secret) = server.create_admin(ACCOUNT_A, "admin-a").await;
    let (b_akid, b_secret) = server.create_admin(ACCOUNT_B, "admin-b").await;
    let (c_akid, c_secret) = server.create_admin(ACCOUNT_C, "admin-c").await;

    let ecr_a = ecr_client_for(&server, &a_akid, &a_secret).await;
    let ecr_b = ecr_client_for(&server, &b_akid, &b_secret).await;
    let ecr_c = ecr_client_for(&server, &c_akid, &c_secret).await;

    ecr_a
        .create_repository()
        .repository_name("layer-share")
        .send()
        .await
        .expect("create_repository");

    // Push a layer so GetDownloadUrlForLayer has something to look up.
    let init = ecr_a
        .initiate_layer_upload()
        .repository_name("layer-share")
        .send()
        .await
        .expect("initiate_layer_upload");
    let upload_id = init.upload_id().unwrap().to_string();

    let blob = b"hello-fakecloud-layer-bytes";
    ecr_a
        .upload_layer_part()
        .repository_name("layer-share")
        .upload_id(&upload_id)
        .part_first_byte(0)
        .part_last_byte((blob.len() as i64) - 1)
        .layer_part_blob(aws_smithy_types::Blob::new(blob.to_vec()))
        .send()
        .await
        .expect("upload_layer_part");

    // Compute sha256 of the blob so CompleteLayerUpload accepts the digest.
    use sha2::Digest as _;
    let mut hasher = sha2::Sha256::new();
    hasher.update(blob);
    let bytes = hasher.finalize();
    let mut hex_digest = String::with_capacity(2 * bytes.len());
    for b in bytes.iter() {
        hex_digest.push_str(&format!("{b:02x}"));
    }
    let digest = format!("sha256:{hex_digest}");

    ecr_a
        .complete_layer_upload()
        .repository_name("layer-share")
        .upload_id(&upload_id)
        .layer_digests(&digest)
        .send()
        .await
        .expect("complete_layer_upload");

    // No policy: B sees RepositoryPolicyNotFoundException.
    let err_no_policy = ecr_b
        .get_download_url_for_layer()
        .registry_id(ACCOUNT_A)
        .repository_name("layer-share")
        .layer_digest(&digest)
        .send()
        .await
        .expect_err("expected RepositoryPolicyNotFoundException without policy");
    let msg = format!("{err_no_policy:?}");
    assert!(
        msg.contains("RepositoryPolicyNotFound"),
        "expected RepositoryPolicyNotFoundException, got: {msg}"
    );

    // Owner allows only B for GetDownloadUrlForLayer.
    let policy = format!(
        r#"{{
            "Version": "2012-10-17",
            "Statement": [{{
                "Effect": "Allow",
                "Principal": {{"AWS": "arn:aws:iam::{ACCOUNT_B}:root"}},
                "Action": "ecr:GetDownloadUrlForLayer",
                "Resource": "*"
            }}]
        }}"#
    );
    ecr_a
        .set_repository_policy()
        .repository_name("layer-share")
        .policy_text(&policy)
        .send()
        .await
        .expect("set_repository_policy");

    // B succeeds.
    let resp_b = ecr_b
        .get_download_url_for_layer()
        .registry_id(ACCOUNT_A)
        .repository_name("layer-share")
        .layer_digest(&digest)
        .send()
        .await
        .expect("GetDownloadUrlForLayer from B should succeed");
    assert_eq!(resp_b.layer_digest(), Some(digest.as_str()));

    // C is denied with AccessDeniedException.
    let err_c = ecr_c
        .get_download_url_for_layer()
        .registry_id(ACCOUNT_A)
        .repository_name("layer-share")
        .layer_digest(&digest)
        .send()
        .await
        .expect_err("expected AccessDeniedException for unrelated caller");
    let msg_c = format!("{err_c:?}");
    assert!(
        msg_c.contains("AccessDenied"),
        "expected AccessDeniedException, got: {msg_c}"
    );
}

#[tokio::test]
async fn cross_account_explicit_deny_overrides_allow() {
    let server = start().await;

    let (a_akid, a_secret) = server.create_admin(ACCOUNT_A, "admin-a").await;
    let (b_akid, b_secret) = server.create_admin(ACCOUNT_B, "admin-b").await;

    let ecr_a = ecr_client_for(&server, &a_akid, &a_secret).await;
    let ecr_b = ecr_client_for(&server, &b_akid, &b_secret).await;

    ecr_a
        .create_repository()
        .repository_name("deny-wins")
        .send()
        .await
        .expect("create_repository");

    let manifest = r#"{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"digest":"sha256:0000000000000000000000000000000000000000000000000000000000000000","size":0,"mediaType":"application/vnd.docker.container.image.v1+json"},"layers":[]}"#;
    ecr_a
        .put_image()
        .repository_name("deny-wins")
        .image_manifest(manifest)
        .image_tag("v1")
        .send()
        .await
        .expect("put_image");

    // Allow + explicit Deny on the same action — Deny wins (matches AWS
    // semantics implemented in fakecloud-iam's evaluator).
    let policy = format!(
        r#"{{
            "Version": "2012-10-17",
            "Statement": [
                {{
                    "Effect": "Allow",
                    "Principal": {{"AWS": "arn:aws:iam::{ACCOUNT_B}:root"}},
                    "Action": "ecr:BatchGetImage",
                    "Resource": "*"
                }},
                {{
                    "Effect": "Deny",
                    "Principal": {{"AWS": "arn:aws:iam::{ACCOUNT_B}:root"}},
                    "Action": "ecr:BatchGetImage",
                    "Resource": "*"
                }}
            ]
        }}"#
    );
    ecr_a
        .set_repository_policy()
        .repository_name("deny-wins")
        .policy_text(&policy)
        .send()
        .await
        .expect("set_repository_policy");

    let err = ecr_b
        .batch_get_image()
        .registry_id(ACCOUNT_A)
        .repository_name("deny-wins")
        .image_ids(
            aws_sdk_ecr::types::ImageIdentifier::builder()
                .image_tag("v1")
                .build(),
        )
        .send()
        .await
        .expect_err("expected AccessDeniedException due to explicit Deny");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("AccessDenied"),
        "expected AccessDeniedException with explicit Deny, got: {msg}"
    );
}
