mod helpers;

use helpers::TestServer;

/// Repository metadata, policy, tags, and per-repo config survive restart.
#[tokio::test]
async fn persistence_round_trip_repository() {
    let tmp = tempfile::tempdir().unwrap();
    let mut server = TestServer::start_persistent(tmp.path()).await;
    let client = server.ecr_client().await;

    use aws_sdk_ecr::types::{ImageScanningConfiguration, ImageTagMutability, Tag};

    client
        .create_repository()
        .repository_name("persist-repo")
        .image_tag_mutability(ImageTagMutability::Immutable)
        .image_scanning_configuration(
            ImageScanningConfiguration::builder()
                .scan_on_push(true)
                .build(),
        )
        .tags(Tag::builder().key("env").value("prod").build().unwrap())
        .send()
        .await
        .unwrap();

    let policy = r#"{"Version":"2012-10-17","Statement":[{"Sid":"Allow","Effect":"Allow","Principal":{"AWS":"*"},"Action":"ecr:GetDownloadUrlForLayer"}]}"#;
    client
        .set_repository_policy()
        .repository_name("persist-repo")
        .policy_text(policy)
        .send()
        .await
        .unwrap();

    drop(client);
    server.restart().await;
    let client = server.ecr_client().await;

    // Repo survives with its configured options
    let described = client
        .describe_repositories()
        .repository_names("persist-repo")
        .send()
        .await
        .unwrap();
    let repo = described.repositories().first().unwrap();
    assert_eq!(repo.repository_name(), Some("persist-repo"));
    assert_eq!(repo.image_tag_mutability().unwrap().as_str(), "IMMUTABLE");
    assert!(repo.image_scanning_configuration().unwrap().scan_on_push());

    // Tag survives
    let arn = repo.repository_arn().unwrap().to_string();
    let tags = client
        .list_tags_for_resource()
        .resource_arn(&arn)
        .send()
        .await
        .unwrap();
    assert_eq!(tags.tags().len(), 1);
    assert_eq!(tags.tags()[0].key(), "env");
    assert_eq!(tags.tags()[0].value(), "prod");

    // Policy survives
    let got = client
        .get_repository_policy()
        .repository_name("persist-repo")
        .send()
        .await
        .unwrap();
    assert_eq!(got.policy_text(), Some(policy));
}
