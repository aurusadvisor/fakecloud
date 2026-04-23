//! ECR Batch 1: repository CRUD, policy, tagging.

mod helpers;

use helpers::TestServer;

#[tokio::test]
async fn create_describe_list_delete_repository() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;

    let created = client
        .create_repository()
        .repository_name("batch1-repo")
        .send()
        .await
        .expect("create_repository");
    let repo = created.repository().expect("repository");
    assert_eq!(repo.repository_name(), Some("batch1-repo"));
    assert_eq!(repo.image_tag_mutability().unwrap().as_str(), "MUTABLE");
    let uri = repo.repository_uri().unwrap();
    assert!(uri.ends_with("/batch1-repo"), "unexpected uri: {uri}");

    // DescribeRepositories without filter returns everything.
    let all = client
        .describe_repositories()
        .send()
        .await
        .expect("describe_repositories");
    assert_eq!(all.repositories().len(), 1);

    // With repositoryNames filter returns the matching one.
    let filtered = client
        .describe_repositories()
        .repository_names("batch1-repo")
        .send()
        .await
        .expect("describe filtered");
    assert_eq!(filtered.repositories().len(), 1);

    // Delete returns the repository snapshot.
    let deleted = client
        .delete_repository()
        .repository_name("batch1-repo")
        .send()
        .await
        .expect("delete_repository");
    assert_eq!(
        deleted.repository().and_then(|r| r.repository_name()),
        Some("batch1-repo")
    );

    // And subsequent describe 404s.
    let err = client
        .describe_repositories()
        .repository_names("batch1-repo")
        .send()
        .await
        .expect_err("should error after delete");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("RepositoryNotFound"),
        "unexpected error: {msg}"
    );
}

#[tokio::test]
async fn create_repository_with_options() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;

    use aws_sdk_ecr::types::{ImageScanningConfiguration, ImageTagMutability, Tag};

    client
        .create_repository()
        .repository_name("immutable-repo")
        .image_tag_mutability(ImageTagMutability::Immutable)
        .image_scanning_configuration(
            ImageScanningConfiguration::builder()
                .scan_on_push(true)
                .build(),
        )
        .tags(Tag::builder().key("env").value("prod").build().unwrap())
        .send()
        .await
        .expect("create with options");

    let resp = client
        .describe_repositories()
        .repository_names("immutable-repo")
        .send()
        .await
        .expect("describe");
    let repo = resp.repositories().first().expect("one repo");
    assert_eq!(repo.image_tag_mutability().unwrap().as_str(), "IMMUTABLE");
    assert!(repo.image_scanning_configuration().unwrap().scan_on_push());
}

#[tokio::test]
async fn repository_policy_round_trip() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;

    client
        .create_repository()
        .repository_name("policy-repo")
        .send()
        .await
        .expect("create");

    let policy = r#"{"Version":"2012-10-17","Statement":[{"Sid":"Allow","Effect":"Allow","Principal":{"AWS":"*"},"Action":"ecr:GetDownloadUrlForLayer"}]}"#;

    client
        .set_repository_policy()
        .repository_name("policy-repo")
        .policy_text(policy)
        .send()
        .await
        .expect("set_repository_policy");

    let fetched = client
        .get_repository_policy()
        .repository_name("policy-repo")
        .send()
        .await
        .expect("get_repository_policy");
    assert_eq!(fetched.policy_text(), Some(policy));

    client
        .delete_repository_policy()
        .repository_name("policy-repo")
        .send()
        .await
        .expect("delete_repository_policy");

    let err = client
        .get_repository_policy()
        .repository_name("policy-repo")
        .send()
        .await
        .expect_err("policy gone");
    assert!(format!("{err:?}").contains("RepositoryPolicyNotFound"));
}

#[tokio::test]
async fn put_image_tag_mutability_and_scanning() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;

    client
        .create_repository()
        .repository_name("mutability-repo")
        .send()
        .await
        .expect("create");

    use aws_sdk_ecr::types::{ImageScanningConfiguration, ImageTagMutability};

    let r1 = client
        .put_image_tag_mutability()
        .repository_name("mutability-repo")
        .image_tag_mutability(ImageTagMutability::Immutable)
        .send()
        .await
        .expect("put_image_tag_mutability");
    assert_eq!(r1.image_tag_mutability().unwrap().as_str(), "IMMUTABLE");

    let r2 = client
        .put_image_scanning_configuration()
        .repository_name("mutability-repo")
        .image_scanning_configuration(
            ImageScanningConfiguration::builder()
                .scan_on_push(true)
                .build(),
        )
        .send()
        .await
        .expect("put_image_scanning_configuration");
    assert!(r2.image_scanning_configuration().unwrap().scan_on_push());
}

#[tokio::test]
async fn tag_resource_round_trip() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;

    let created = client
        .create_repository()
        .repository_name("tagged-repo")
        .send()
        .await
        .expect("create");
    let arn = created
        .repository()
        .expect("repository")
        .repository_arn()
        .expect("arn")
        .to_string();

    use aws_sdk_ecr::types::Tag;

    client
        .tag_resource()
        .resource_arn(&arn)
        .tags(
            Tag::builder()
                .key("team")
                .value("platform")
                .build()
                .unwrap(),
        )
        .tags(Tag::builder().key("env").value("prod").build().unwrap())
        .send()
        .await
        .expect("tag_resource");

    let listed = client
        .list_tags_for_resource()
        .resource_arn(&arn)
        .send()
        .await
        .expect("list_tags_for_resource");
    let mut kv: Vec<(String, String)> = listed
        .tags()
        .iter()
        .map(|t| (t.key().to_string(), t.value().to_string()))
        .collect();
    kv.sort();
    assert_eq!(
        kv,
        vec![
            ("env".to_string(), "prod".to_string()),
            ("team".to_string(), "platform".to_string()),
        ]
    );

    client
        .untag_resource()
        .resource_arn(&arn)
        .tag_keys("env")
        .send()
        .await
        .expect("untag_resource");
    let after = client
        .list_tags_for_resource()
        .resource_arn(&arn)
        .send()
        .await
        .expect("list_tags after");
    assert_eq!(after.tags().len(), 1);
    assert_eq!(after.tags()[0].key(), "team");
}

#[tokio::test]
async fn duplicate_create_returns_already_exists() {
    let server = TestServer::start().await;
    let client = server.ecr_client().await;

    client
        .create_repository()
        .repository_name("dup-repo")
        .send()
        .await
        .expect("first create");

    let err = client
        .create_repository()
        .repository_name("dup-repo")
        .send()
        .await
        .expect_err("duplicate should fail");
    assert!(format!("{err:?}").contains("RepositoryAlreadyExists"));
}
