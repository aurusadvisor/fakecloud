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
