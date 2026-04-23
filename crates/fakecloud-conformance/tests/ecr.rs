mod helpers;

use fakecloud_conformance_macros::test_action;
use helpers::TestServer;

#[test_action("ecr", "CreateRepository", checksum = "d8c2447c")]
#[tokio::test]
async fn ecr_create_repository() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    let resp = client
        .create_repository()
        .repository_name("confo-create")
        .send()
        .await
        .unwrap();
    let repo = resp.repository().unwrap();
    assert_eq!(repo.repository_name(), Some("confo-create"));
}

#[test_action("ecr", "DescribeRepositories", checksum = "adbdbb42")]
#[tokio::test]
async fn ecr_describe_repositories() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    client
        .create_repository()
        .repository_name("confo-describe")
        .send()
        .await
        .unwrap();
    let resp = client.describe_repositories().send().await.unwrap();
    assert!(!resp.repositories().is_empty());
}

#[test_action("ecr", "DeleteRepository", checksum = "526c8e45")]
#[tokio::test]
async fn ecr_delete_repository() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    client
        .create_repository()
        .repository_name("confo-delete")
        .send()
        .await
        .unwrap();
    client
        .delete_repository()
        .repository_name("confo-delete")
        .send()
        .await
        .unwrap();
}

#[test_action("ecr", "PutImageTagMutability", checksum = "7329c053")]
#[tokio::test]
async fn ecr_put_image_tag_mutability() {
    use aws_sdk_ecr::types::ImageTagMutability;
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    client
        .create_repository()
        .repository_name("confo-mut")
        .send()
        .await
        .unwrap();
    let resp = client
        .put_image_tag_mutability()
        .repository_name("confo-mut")
        .image_tag_mutability(ImageTagMutability::Immutable)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.image_tag_mutability().unwrap().as_str(), "IMMUTABLE");
}

#[test_action("ecr", "PutImageScanningConfiguration", checksum = "2625a257")]
#[tokio::test]
async fn ecr_put_image_scanning_configuration() {
    use aws_sdk_ecr::types::ImageScanningConfiguration;
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    client
        .create_repository()
        .repository_name("confo-scan")
        .send()
        .await
        .unwrap();
    let resp = client
        .put_image_scanning_configuration()
        .repository_name("confo-scan")
        .image_scanning_configuration(
            ImageScanningConfiguration::builder()
                .scan_on_push(true)
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert!(resp.image_scanning_configuration().unwrap().scan_on_push());
}

#[test_action("ecr", "SetRepositoryPolicy", checksum = "84a66730")]
#[tokio::test]
async fn ecr_set_repository_policy() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    client
        .create_repository()
        .repository_name("confo-policy")
        .send()
        .await
        .unwrap();
    let policy = r#"{"Version":"2012-10-17","Statement":[]}"#;
    let resp = client
        .set_repository_policy()
        .repository_name("confo-policy")
        .policy_text(policy)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.policy_text(), Some(policy));
}

#[test_action("ecr", "GetRepositoryPolicy", checksum = "76e968fc")]
#[tokio::test]
async fn ecr_get_repository_policy() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    client
        .create_repository()
        .repository_name("confo-getpolicy")
        .send()
        .await
        .unwrap();
    let policy = r#"{"Version":"2012-10-17","Statement":[]}"#;
    client
        .set_repository_policy()
        .repository_name("confo-getpolicy")
        .policy_text(policy)
        .send()
        .await
        .unwrap();
    let resp = client
        .get_repository_policy()
        .repository_name("confo-getpolicy")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.policy_text(), Some(policy));
}

#[test_action("ecr", "DeleteRepositoryPolicy", checksum = "832fdaa7")]
#[tokio::test]
async fn ecr_delete_repository_policy() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    client
        .create_repository()
        .repository_name("confo-delpolicy")
        .send()
        .await
        .unwrap();
    let policy = r#"{"Version":"2012-10-17","Statement":[]}"#;
    client
        .set_repository_policy()
        .repository_name("confo-delpolicy")
        .policy_text(policy)
        .send()
        .await
        .unwrap();
    client
        .delete_repository_policy()
        .repository_name("confo-delpolicy")
        .send()
        .await
        .unwrap();
}

#[test_action("ecr", "GetAuthorizationToken", checksum = "af93b65b")]
#[tokio::test]
async fn ecr_get_authorization_token() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    let resp = client.get_authorization_token().send().await.unwrap();
    assert_eq!(resp.authorization_data().len(), 1);
    assert!(resp.authorization_data()[0].authorization_token().is_some());
}

#[test_action("ecr", "PutImage", checksum = "6e4bc561")]
#[tokio::test]
async fn ecr_put_image() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    client
        .create_repository()
        .repository_name("confo-putimg")
        .send()
        .await
        .unwrap();
    let resp = client
        .put_image()
        .repository_name("confo-putimg")
        .image_manifest(r#"{"schemaVersion":2}"#)
        .image_tag("v1")
        .send()
        .await
        .unwrap();
    assert!(resp.image().is_some());
}

#[test_action("ecr", "BatchGetImage", checksum = "753d3e24")]
#[tokio::test]
async fn ecr_batch_get_image() {
    use aws_sdk_ecr::types::ImageIdentifier;
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    client
        .create_repository()
        .repository_name("confo-batchget")
        .send()
        .await
        .unwrap();
    client
        .put_image()
        .repository_name("confo-batchget")
        .image_manifest(r#"{"a":1}"#)
        .image_tag("v1")
        .send()
        .await
        .unwrap();
    let resp = client
        .batch_get_image()
        .repository_name("confo-batchget")
        .image_ids(ImageIdentifier::builder().image_tag("v1").build())
        .send()
        .await
        .unwrap();
    assert_eq!(resp.images().len(), 1);
}

#[test_action("ecr", "BatchDeleteImage", checksum = "523e89b9")]
#[tokio::test]
async fn ecr_batch_delete_image() {
    use aws_sdk_ecr::types::ImageIdentifier;
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    client
        .create_repository()
        .repository_name("confo-batchdel")
        .send()
        .await
        .unwrap();
    client
        .put_image()
        .repository_name("confo-batchdel")
        .image_manifest(r#"{"a":1}"#)
        .image_tag("v1")
        .send()
        .await
        .unwrap();
    client
        .batch_delete_image()
        .repository_name("confo-batchdel")
        .image_ids(ImageIdentifier::builder().image_tag("v1").build())
        .send()
        .await
        .unwrap();
}

#[test_action("ecr", "BatchCheckLayerAvailability", checksum = "eb040870")]
#[tokio::test]
async fn ecr_batch_check_layer_availability() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    client
        .create_repository()
        .repository_name("confo-checklayer")
        .send()
        .await
        .unwrap();
    let resp = client
        .batch_check_layer_availability()
        .repository_name("confo-checklayer")
        .layer_digests("sha256:deadbeef")
        .send()
        .await
        .unwrap();
    assert!(!resp.failures().is_empty());
}

#[test_action("ecr", "DescribeImages", checksum = "822fc635")]
#[tokio::test]
async fn ecr_describe_images() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    client
        .create_repository()
        .repository_name("confo-descrimg")
        .send()
        .await
        .unwrap();
    client
        .put_image()
        .repository_name("confo-descrimg")
        .image_manifest(r#"{"a":1}"#)
        .image_tag("v1")
        .send()
        .await
        .unwrap();
    let resp = client
        .describe_images()
        .repository_name("confo-descrimg")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.image_details().len(), 1);
}

#[test_action("ecr", "ListImages", checksum = "f082164b")]
#[tokio::test]
async fn ecr_list_images() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    client
        .create_repository()
        .repository_name("confo-listimg")
        .send()
        .await
        .unwrap();
    client
        .put_image()
        .repository_name("confo-listimg")
        .image_manifest(r#"{"a":1}"#)
        .image_tag("v1")
        .send()
        .await
        .unwrap();
    let resp = client
        .list_images()
        .repository_name("confo-listimg")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.image_ids().len(), 1);
}

#[test_action("ecr", "GetDownloadUrlForLayer", checksum = "5d5dfa91")]
#[tokio::test]
async fn ecr_get_download_url_for_layer() {
    use aws_sdk_ecr::primitives::Blob;
    use sha2::{Digest, Sha256};
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    client
        .create_repository()
        .repository_name("confo-dlurl")
        .send()
        .await
        .unwrap();
    let init = client
        .initiate_layer_upload()
        .repository_name("confo-dlurl")
        .send()
        .await
        .unwrap();
    let upload_id = init.upload_id().unwrap().to_string();
    let blob = b"x".to_vec();
    let digest = {
        let mut h = Sha256::new();
        h.update(&blob);
        format!("sha256:{:x}", h.finalize())
    };
    client
        .upload_layer_part()
        .repository_name("confo-dlurl")
        .upload_id(&upload_id)
        .part_first_byte(0)
        .part_last_byte(0)
        .layer_part_blob(Blob::new(blob))
        .send()
        .await
        .unwrap();
    client
        .complete_layer_upload()
        .repository_name("confo-dlurl")
        .upload_id(&upload_id)
        .layer_digests(&digest)
        .send()
        .await
        .unwrap();
    let resp = client
        .get_download_url_for_layer()
        .repository_name("confo-dlurl")
        .layer_digest(&digest)
        .send()
        .await
        .unwrap();
    assert!(resp.download_url().unwrap().contains(&digest));
}

#[test_action("ecr", "InitiateLayerUpload", checksum = "f7d9ee29")]
#[tokio::test]
async fn ecr_initiate_layer_upload() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    client
        .create_repository()
        .repository_name("confo-initup")
        .send()
        .await
        .unwrap();
    let resp = client
        .initiate_layer_upload()
        .repository_name("confo-initup")
        .send()
        .await
        .unwrap();
    assert!(resp.upload_id().is_some());
}

#[test_action("ecr", "UploadLayerPart", checksum = "5312a154")]
#[tokio::test]
async fn ecr_upload_layer_part() {
    use aws_sdk_ecr::primitives::Blob;
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    client
        .create_repository()
        .repository_name("confo-uppart")
        .send()
        .await
        .unwrap();
    let init = client
        .initiate_layer_upload()
        .repository_name("confo-uppart")
        .send()
        .await
        .unwrap();
    let upload_id = init.upload_id().unwrap().to_string();
    client
        .upload_layer_part()
        .repository_name("confo-uppart")
        .upload_id(&upload_id)
        .part_first_byte(0)
        .part_last_byte(2)
        .layer_part_blob(Blob::new(vec![1u8, 2, 3]))
        .send()
        .await
        .unwrap();
}

#[test_action("ecr", "CompleteLayerUpload", checksum = "06e7311e")]
#[tokio::test]
async fn ecr_complete_layer_upload() {
    use aws_sdk_ecr::primitives::Blob;
    use sha2::{Digest, Sha256};
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    client
        .create_repository()
        .repository_name("confo-complete")
        .send()
        .await
        .unwrap();
    let init = client
        .initiate_layer_upload()
        .repository_name("confo-complete")
        .send()
        .await
        .unwrap();
    let upload_id = init.upload_id().unwrap().to_string();
    let blob = vec![1u8, 2, 3];
    let digest = {
        let mut h = Sha256::new();
        h.update(&blob);
        format!("sha256:{:x}", h.finalize())
    };
    client
        .upload_layer_part()
        .repository_name("confo-complete")
        .upload_id(&upload_id)
        .part_first_byte(0)
        .part_last_byte(2)
        .layer_part_blob(Blob::new(blob))
        .send()
        .await
        .unwrap();
    client
        .complete_layer_upload()
        .repository_name("confo-complete")
        .upload_id(&upload_id)
        .layer_digests(&digest)
        .send()
        .await
        .unwrap();
}

#[test_action("ecr", "TagResource", checksum = "866cf7cc")]
#[tokio::test]
async fn ecr_tag_resource() {
    use aws_sdk_ecr::types::Tag;
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    let created = client
        .create_repository()
        .repository_name("confo-tag")
        .send()
        .await
        .unwrap();
    let arn = created.repository().unwrap().repository_arn().unwrap();
    client
        .tag_resource()
        .resource_arn(arn)
        .tags(Tag::builder().key("env").value("prod").build().unwrap())
        .send()
        .await
        .unwrap();
}

#[test_action("ecr", "UntagResource", checksum = "6c74e2a3")]
#[tokio::test]
async fn ecr_untag_resource() {
    use aws_sdk_ecr::types::Tag;
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    let created = client
        .create_repository()
        .repository_name("confo-untag")
        .send()
        .await
        .unwrap();
    let arn = created.repository().unwrap().repository_arn().unwrap();
    client
        .tag_resource()
        .resource_arn(arn)
        .tags(Tag::builder().key("env").value("prod").build().unwrap())
        .send()
        .await
        .unwrap();
    client
        .untag_resource()
        .resource_arn(arn)
        .tag_keys("env")
        .send()
        .await
        .unwrap();
}

#[test_action("ecr", "ListTagsForResource", checksum = "904513ef")]
#[tokio::test]
async fn ecr_list_tags_for_resource() {
    use aws_sdk_ecr::types::Tag;
    let server = TestServer::start().await;
    let client = server.ecr_client().await;
    let created = client
        .create_repository()
        .repository_name("confo-listtags")
        .send()
        .await
        .unwrap();
    let arn = created.repository().unwrap().repository_arn().unwrap();
    client
        .tag_resource()
        .resource_arn(arn)
        .tags(Tag::builder().key("env").value("prod").build().unwrap())
        .send()
        .await
        .unwrap();
    let resp = client
        .list_tags_for_resource()
        .resource_arn(arn)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.tags().len(), 1);
}
