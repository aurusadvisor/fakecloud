mod helpers;

use aws_smithy_types::error::metadata::ProvideErrorMetadata;
use fakecloud_conformance_macros::test_action;
use helpers::TestServer;
use std::collections::HashMap;

#[test_action("cognito-identity", "CreateIdentityPool", checksum = "a2b71e1f")]
#[tokio::test]
async fn cognito_identity_create_identity_pool() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;

    let resp = client
        .create_identity_pool()
        .identity_pool_name("conformance-pool")
        .allow_unauthenticated_identities(false)
        .send()
        .await
        .unwrap();
    assert!(!resp.identity_pool_id().is_empty());
    assert_eq!(resp.identity_pool_name(), "conformance-pool");
}

#[test_action("cognito-identity", "ListIdentityPools", checksum = "44f5832d")]
#[tokio::test]
async fn cognito_identity_list_identity_pools() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;

    client
        .create_identity_pool()
        .identity_pool_name("pool-a")
        .allow_unauthenticated_identities(false)
        .send()
        .await
        .unwrap();

    let resp = client
        .list_identity_pools()
        .max_results(10)
        .send()
        .await
        .unwrap();
    assert!(!resp.identity_pools().is_empty());
}

#[test_action("cognito-identity", "DescribeIdentityPool", checksum = "f007efcc")]
#[tokio::test]
async fn cognito_identity_describe_identity_pool() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;

    let create = client
        .create_identity_pool()
        .identity_pool_name("desc-pool")
        .allow_unauthenticated_identities(false)
        .send()
        .await
        .unwrap();
    let pool_id = create.identity_pool_id().to_string();

    let resp = client
        .describe_identity_pool()
        .identity_pool_id(&pool_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.identity_pool_name(), "desc-pool");
}

#[test_action("cognito-identity", "UpdateIdentityPool", checksum = "205dd5ea")]
#[tokio::test]
async fn cognito_identity_update_identity_pool() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;

    let create = client
        .create_identity_pool()
        .identity_pool_name("update-pool")
        .allow_unauthenticated_identities(false)
        .send()
        .await
        .unwrap();
    let pool_id = create.identity_pool_id().to_string();

    let resp = client
        .update_identity_pool()
        .identity_pool_id(&pool_id)
        .identity_pool_name("updated-pool")
        .allow_unauthenticated_identities(true)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.identity_pool_name(), "updated-pool");
}

#[test_action("cognito-identity", "DeleteIdentityPool", checksum = "c2af35fd")]
#[tokio::test]
async fn cognito_identity_delete_identity_pool() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;

    let create = client
        .create_identity_pool()
        .identity_pool_name("delete-pool")
        .allow_unauthenticated_identities(false)
        .send()
        .await
        .unwrap();
    let pool_id = create.identity_pool_id().to_string();

    client
        .delete_identity_pool()
        .identity_pool_id(&pool_id)
        .send()
        .await
        .unwrap();

    let err = client
        .describe_identity_pool()
        .identity_pool_id(&pool_id)
        .send()
        .await
        .unwrap_err();
    assert!(
        err.code() == Some("NotFoundException") || err.code() == Some("ResourceNotFoundException")
    );
}

#[test_action("cognito-identity", "GetId", checksum = "651044ef")]
#[tokio::test]
async fn cognito_identity_get_id() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;

    let create = client
        .create_identity_pool()
        .identity_pool_name("getid-pool")
        .allow_unauthenticated_identities(true)
        .send()
        .await
        .unwrap();
    let pool_id = create.identity_pool_id().to_string();

    let resp = client
        .get_id()
        .identity_pool_id(&pool_id)
        .send()
        .await
        .unwrap();
    assert!(!resp.identity_id().unwrap().is_empty());
}

#[test_action("cognito-identity", "GetOpenIdToken", checksum = "703d339b")]
#[tokio::test]
async fn cognito_identity_get_open_id_token() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;

    let create = client
        .create_identity_pool()
        .identity_pool_name("token-pool")
        .allow_unauthenticated_identities(true)
        .send()
        .await
        .unwrap();
    let pool_id = create.identity_pool_id().to_string();

    let get_id = client
        .get_id()
        .identity_pool_id(&pool_id)
        .send()
        .await
        .unwrap();
    let identity_id = get_id.identity_id().unwrap().to_string();

    let resp = client
        .get_open_id_token()
        .identity_id(&identity_id)
        .send()
        .await
        .unwrap();
    assert!(!resp.token().unwrap().is_empty());
}

#[test_action("cognito-identity", "GetCredentialsForIdentity", checksum = "deadb7f5")]
#[tokio::test]
async fn cognito_identity_get_credentials_for_identity() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;
    let iam = server.iam_client().await;

    let create = client
        .create_identity_pool()
        .identity_pool_name("creds-pool")
        .allow_unauthenticated_identities(true)
        .send()
        .await
        .unwrap();
    let pool_id = create.identity_pool_id().to_string();

    let role = iam
        .create_role()
        .role_name("CognitoUnauthRole")
        .assume_role_policy_document(r#"{"Version":"2012-10-17","Statement":[]}"#)
        .send()
        .await
        .unwrap();
    let role_arn = role.role().unwrap().arn().to_string();

    let mut roles = HashMap::new();
    roles.insert("unauthenticated".to_string(), role_arn);
    client
        .set_identity_pool_roles()
        .identity_pool_id(&pool_id)
        .set_roles(Some(roles))
        .send()
        .await
        .unwrap();

    let get_id = client
        .get_id()
        .identity_pool_id(&pool_id)
        .send()
        .await
        .unwrap();
    let identity_id = get_id.identity_id().unwrap().to_string();

    let resp = client
        .get_credentials_for_identity()
        .identity_id(&identity_id)
        .send()
        .await
        .unwrap();
    assert!(resp.credentials().is_some());
}

#[test_action(
    "cognito-identity",
    "GetOpenIdTokenForDeveloperIdentity",
    checksum = "1c0dbdac"
)]
#[tokio::test]
async fn cognito_identity_get_open_id_token_for_developer_identity() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;

    let create = client
        .create_identity_pool()
        .identity_pool_name("dev-pool")
        .allow_unauthenticated_identities(false)
        .send()
        .await
        .unwrap();
    let pool_id = create.identity_pool_id().to_string();

    let mut logins = HashMap::new();
    logins.insert("login.provider".to_string(), "user123".to_string());

    let resp = client
        .get_open_id_token_for_developer_identity()
        .identity_pool_id(&pool_id)
        .set_logins(Some(logins))
        .send()
        .await
        .unwrap();
    assert!(!resp.identity_id().unwrap().is_empty());
    assert!(!resp.token().unwrap().is_empty());
}

#[test_action("cognito-identity", "LookupDeveloperIdentity", checksum = "f468454c")]
#[tokio::test]
async fn cognito_identity_lookup_developer_identity() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;

    let create = client
        .create_identity_pool()
        .identity_pool_name("lookup-pool")
        .allow_unauthenticated_identities(false)
        .send()
        .await
        .unwrap();
    let pool_id = create.identity_pool_id().to_string();

    let mut logins = HashMap::new();
    logins.insert("login.provider".to_string(), "user123".to_string());

    let dev = client
        .get_open_id_token_for_developer_identity()
        .identity_pool_id(&pool_id)
        .set_logins(Some(logins))
        .send()
        .await
        .unwrap();

    let resp = client
        .lookup_developer_identity()
        .identity_pool_id(&pool_id)
        .developer_user_identifier("user123")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.identity_id().unwrap(), dev.identity_id().unwrap());
}

#[test_action("cognito-identity", "MergeDeveloperIdentities", checksum = "9fc2623c")]
#[tokio::test]
async fn cognito_identity_merge_developer_identities() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;

    let create = client
        .create_identity_pool()
        .identity_pool_name("merge-pool")
        .allow_unauthenticated_identities(false)
        .send()
        .await
        .unwrap();
    let pool_id = create.identity_pool_id().to_string();

    let mut logins1 = HashMap::new();
    logins1.insert("login.provider".to_string(), "user1".to_string());
    let mut logins2 = HashMap::new();
    logins2.insert("login.provider".to_string(), "user2".to_string());

    let _dev1 = client
        .get_open_id_token_for_developer_identity()
        .identity_pool_id(&pool_id)
        .set_logins(Some(logins1))
        .send()
        .await
        .unwrap();
    let dev2 = client
        .get_open_id_token_for_developer_identity()
        .identity_pool_id(&pool_id)
        .set_logins(Some(logins2))
        .send()
        .await
        .unwrap();

    let resp = client
        .merge_developer_identities()
        .identity_pool_id(&pool_id)
        .source_user_identifier("user1")
        .destination_user_identifier("user2")
        .developer_provider_name("login.provider")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.identity_id().unwrap(), dev2.identity_id().unwrap());
}

#[test_action("cognito-identity", "UnlinkDeveloperIdentity", checksum = "d9dab3e9")]
#[tokio::test]
async fn cognito_identity_unlink_developer_identity() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;

    let create = client
        .create_identity_pool()
        .identity_pool_name("unlink-pool")
        .allow_unauthenticated_identities(false)
        .send()
        .await
        .unwrap();
    let pool_id = create.identity_pool_id().to_string();

    let mut logins = HashMap::new();
    logins.insert("login.provider".to_string(), "user123".to_string());

    let dev = client
        .get_open_id_token_for_developer_identity()
        .identity_pool_id(&pool_id)
        .set_logins(Some(logins))
        .send()
        .await
        .unwrap();

    client
        .unlink_developer_identity()
        .identity_id(dev.identity_id().unwrap())
        .identity_pool_id(&pool_id)
        .developer_provider_name("login.provider")
        .developer_user_identifier("user123")
        .send()
        .await
        .unwrap();
}

#[test_action("cognito-identity", "ListIdentities", checksum = "7574a107")]
#[tokio::test]
async fn cognito_identity_list_identities() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;

    let create = client
        .create_identity_pool()
        .identity_pool_name("list-id-pool")
        .allow_unauthenticated_identities(true)
        .send()
        .await
        .unwrap();
    let pool_id = create.identity_pool_id().to_string();

    let _get_id = client
        .get_id()
        .identity_pool_id(&pool_id)
        .send()
        .await
        .unwrap();

    let resp = client
        .list_identities()
        .identity_pool_id(&pool_id)
        .max_results(10)
        .send()
        .await
        .unwrap();
    assert!(!resp.identities().is_empty());
}

#[test_action("cognito-identity", "DescribeIdentity", checksum = "6d078bfb")]
#[tokio::test]
async fn cognito_identity_describe_identity() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;

    let create = client
        .create_identity_pool()
        .identity_pool_name("desc-id-pool")
        .allow_unauthenticated_identities(true)
        .send()
        .await
        .unwrap();
    let pool_id = create.identity_pool_id().to_string();

    let get_id = client
        .get_id()
        .identity_pool_id(&pool_id)
        .send()
        .await
        .unwrap();
    let identity_id = get_id.identity_id().unwrap().to_string();

    let resp = client
        .describe_identity()
        .identity_id(&identity_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.identity_id().unwrap(), identity_id.as_str());
}

#[test_action("cognito-identity", "SetIdentityPoolRoles", checksum = "3b25b181")]
#[tokio::test]
async fn cognito_identity_set_identity_pool_roles() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;
    let iam = server.iam_client().await;

    let create = client
        .create_identity_pool()
        .identity_pool_name("roles-pool")
        .allow_unauthenticated_identities(false)
        .send()
        .await
        .unwrap();
    let pool_id = create.identity_pool_id().to_string();

    let role = iam
        .create_role()
        .role_name("CognitoAuthRole")
        .assume_role_policy_document(r#"{"Version":"2012-10-17","Statement":[]}"#)
        .send()
        .await
        .unwrap();
    let role_arn = role.role().unwrap().arn().to_string();

    let mut roles = HashMap::new();
    roles.insert("authenticated".to_string(), role_arn.clone());

    client
        .set_identity_pool_roles()
        .identity_pool_id(&pool_id)
        .set_roles(Some(roles))
        .send()
        .await
        .unwrap();

    let resp = client
        .get_identity_pool_roles()
        .identity_pool_id(&pool_id)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.roles()
            .and_then(|m| m.get("authenticated"))
            .map(String::as_str),
        Some(role_arn.as_str())
    );
}

#[test_action("cognito-identity", "GetIdentityPoolRoles", checksum = "81acc5db")]
#[tokio::test]
async fn cognito_identity_get_identity_pool_roles() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;

    let create = client
        .create_identity_pool()
        .identity_pool_name("get-roles-pool")
        .allow_unauthenticated_identities(false)
        .send()
        .await
        .unwrap();
    let pool_id = create.identity_pool_id().to_string();

    let resp = client
        .get_identity_pool_roles()
        .identity_pool_id(&pool_id)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.identity_pool_id(), Some(pool_id.as_str()));
}

#[test_action("cognito-identity", "TagResource", checksum = "b2287de5")]
#[tokio::test]
async fn cognito_identity_tag_resource() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;

    let create = client
        .create_identity_pool()
        .identity_pool_name("tag-pool")
        .allow_unauthenticated_identities(false)
        .send()
        .await
        .unwrap();
    let pool_id = create.identity_pool_id();
    let pool_arn = format!(
        "arn:aws:cognito-identity:us-east-1:123456789012:identitypool/{}",
        pool_id
    );

    client
        .tag_resource()
        .resource_arn(&pool_arn)
        .tags("env", "test")
        .send()
        .await
        .unwrap();

    let resp = client
        .list_tags_for_resource()
        .resource_arn(&pool_arn)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.tags().and_then(|m| m.get("env")).map(String::as_str),
        Some("test")
    );
}

#[test_action("cognito-identity", "UntagResource", checksum = "a389b067")]
#[tokio::test]
async fn cognito_identity_untag_resource() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;

    let create = client
        .create_identity_pool()
        .identity_pool_name("untag-pool")
        .allow_unauthenticated_identities(false)
        .send()
        .await
        .unwrap();
    let pool_id = create.identity_pool_id();
    let pool_arn = format!(
        "arn:aws:cognito-identity:us-east-1:123456789012:identitypool/{}",
        pool_id
    );

    client
        .tag_resource()
        .resource_arn(&pool_arn)
        .tags("env", "test")
        .send()
        .await
        .unwrap();

    client
        .untag_resource()
        .resource_arn(&pool_arn)
        .tag_keys("env")
        .send()
        .await
        .unwrap();

    let resp = client
        .list_tags_for_resource()
        .resource_arn(&pool_arn)
        .send()
        .await
        .unwrap();
    assert!(resp.tags().and_then(|m| m.get("env")).is_none());
}

#[test_action("cognito-identity", "ListTagsForResource", checksum = "6d454c4a")]
#[tokio::test]
async fn cognito_identity_list_tags_for_resource() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;

    let create = client
        .create_identity_pool()
        .identity_pool_name("list-tags-pool")
        .allow_unauthenticated_identities(false)
        .send()
        .await
        .unwrap();
    let pool_id = create.identity_pool_id();
    let pool_arn = format!(
        "arn:aws:cognito-identity:us-east-1:123456789012:identitypool/{}",
        pool_id
    );

    client
        .tag_resource()
        .resource_arn(&pool_arn)
        .tags("team", "conformance")
        .send()
        .await
        .unwrap();

    let resp = client
        .list_tags_for_resource()
        .resource_arn(&pool_arn)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.tags().and_then(|m| m.get("team")).map(String::as_str),
        Some("conformance")
    );
}

#[test_action("cognito-identity", "UnlinkIdentity", checksum = "08ce7e8a")]
#[tokio::test]
async fn cognito_identity_unlink_identity() {
    let server = TestServer::start().await;
    let client = server.cognito_identity_client().await;

    let create = client
        .create_identity_pool()
        .identity_pool_name("unlink-id-pool")
        .allow_unauthenticated_identities(true)
        .send()
        .await
        .unwrap();
    let pool_id = create.identity_pool_id().to_string();

    let get_id = client
        .get_id()
        .identity_pool_id(&pool_id)
        .send()
        .await
        .unwrap();
    let identity_id = get_id.identity_id().unwrap().to_string();

    let mut logins = HashMap::new();
    logins.insert("login.provider".to_string(), "user123".to_string());

    client
        .unlink_identity()
        .identity_id(&identity_id)
        .set_logins(Some(logins))
        .send()
        .await
        .unwrap();
}
