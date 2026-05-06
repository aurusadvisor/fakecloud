//! End-to-end coverage for the `cognito-identity` (Federated Identity
//! Pools) service. Verifies pool CRUD, role attachment, identity
//! minting, and end-to-end credential issuance — the latter is the
//! load-bearing assertion: `GetCredentialsForIdentity` must return real
//! STS-style temporary credentials so downstream IAM / SigV4 pipelines
//! treat them like AssumeRoleWithWebIdentity output.

mod helpers;
use helpers::TestServer;

#[tokio::test]
async fn cognito_identity_pool_crud_and_unauthenticated_credentials() {
    let server = TestServer::start().await;
    let cognito_identity = server.cognito_identity_client().await;
    let iam = server.iam_client().await;

    // Create an unauth IAM role first so we can attach it. Trust policy
    // matches the AWS-suggested template for Cognito Identity unauth
    // roles.
    let trust_doc = r#"{
        "Version": "2012-10-17",
        "Statement": [{
            "Effect": "Allow",
            "Principal": {"Federated": "cognito-identity.amazonaws.com"},
            "Action": "sts:AssumeRoleWithWebIdentity"
        }]
    }"#;
    let role = iam
        .create_role()
        .role_name("CognitoUnauthRole")
        .assume_role_policy_document(trust_doc)
        .send()
        .await
        .expect("create unauth role");
    let role_arn = role.role().unwrap().arn().to_string();

    // CreateIdentityPool with unauth allowed.
    let created = cognito_identity
        .create_identity_pool()
        .identity_pool_name("e2e-pool")
        .allow_unauthenticated_identities(true)
        .send()
        .await
        .expect("create identity pool");
    let pool_id = created.identity_pool_id().to_string();
    assert!(
        pool_id.starts_with("us-east-1:"),
        "identity pool id should be `<region>:<uuid>`: {pool_id}"
    );
    assert_eq!(created.identity_pool_name(), "e2e-pool");
    assert!(created.allow_unauthenticated_identities());

    // DescribeIdentityPool round-trips.
    let described = cognito_identity
        .describe_identity_pool()
        .identity_pool_id(&pool_id)
        .send()
        .await
        .expect("describe identity pool");
    assert_eq!(described.identity_pool_id(), pool_id);
    assert_eq!(described.identity_pool_name(), "e2e-pool");

    // ListIdentityPools surfaces the new pool.
    let list = cognito_identity
        .list_identity_pools()
        .max_results(60)
        .send()
        .await
        .expect("list identity pools");
    assert!(list
        .identity_pools()
        .iter()
        .any(|p| p.identity_pool_id() == Some(pool_id.as_str())));

    // SetIdentityPoolRoles attaches authenticated + unauthenticated roles.
    use std::collections::HashMap;
    let mut roles = HashMap::new();
    roles.insert("authenticated".to_string(), role_arn.clone());
    roles.insert("unauthenticated".to_string(), role_arn.clone());
    cognito_identity
        .set_identity_pool_roles()
        .identity_pool_id(&pool_id)
        .set_roles(Some(roles))
        .send()
        .await
        .expect("set identity pool roles");

    // GetIdentityPoolRoles reads them back.
    let got_roles = cognito_identity
        .get_identity_pool_roles()
        .identity_pool_id(&pool_id)
        .send()
        .await
        .expect("get identity pool roles");
    assert_eq!(
        got_roles
            .roles()
            .and_then(|m| m.get("unauthenticated"))
            .map(String::as_str),
        Some(role_arn.as_str())
    );

    // GetId mints a synthetic identity (unauth flow — no Logins).
    let id = cognito_identity
        .get_id()
        .identity_pool_id(&pool_id)
        .send()
        .await
        .expect("get id");
    let identity_id = id.identity_id().unwrap().to_string();
    assert!(
        identity_id.starts_with("us-east-1:"),
        "identity id format should be `<region>:<uuid>`: {identity_id}"
    );

    // GetId is sticky-by-pool for unauthenticated calls only as a new id
    // each call (no Logins to dedupe on). We only verify it doesn't error.
    let _ = cognito_identity
        .get_id()
        .identity_pool_id(&pool_id)
        .send()
        .await
        .expect("get id second call");

    // GetCredentialsForIdentity returns real temporary credentials.
    let creds = cognito_identity
        .get_credentials_for_identity()
        .identity_id(&identity_id)
        .send()
        .await
        .expect("get credentials for identity");
    assert_eq!(creds.identity_id().unwrap(), identity_id);
    let c = creds.credentials().expect("credentials present");
    let access_key = c.access_key_id().expect("access key");
    let secret = c.secret_key().expect("secret key");
    let session_token = c.session_token().expect("session token");
    assert!(!access_key.is_empty(), "access key id is non-empty");
    assert!(!secret.is_empty(), "secret key is non-empty");
    assert!(!session_token.is_empty(), "session token is non-empty");

    // DescribeIdentity sees the minted identity.
    let described = cognito_identity
        .describe_identity()
        .identity_id(&identity_id)
        .send()
        .await
        .expect("describe identity");
    assert_eq!(described.identity_id().unwrap(), identity_id);

    // ListIdentities surfaces it.
    let listed = cognito_identity
        .list_identities()
        .identity_pool_id(&pool_id)
        .max_results(60)
        .send()
        .await
        .expect("list identities");
    assert!(listed
        .identities()
        .iter()
        .any(|i| i.identity_id() == Some(identity_id.as_str())));

    // DeleteIdentityPool drops the pool and cascades identities.
    cognito_identity
        .delete_identity_pool()
        .identity_pool_id(&pool_id)
        .send()
        .await
        .expect("delete identity pool");
    let after = cognito_identity
        .describe_identity_pool()
        .identity_pool_id(&pool_id)
        .send()
        .await;
    assert!(after.is_err(), "describe after delete should fail");
}

#[tokio::test]
async fn cognito_identity_unauthenticated_disallowed_when_pool_doesnt_allow_it() {
    let server = TestServer::start().await;
    let cognito_identity = server.cognito_identity_client().await;

    // Pool without unauth identities allowed.
    let pool = cognito_identity
        .create_identity_pool()
        .identity_pool_name("auth-only")
        .allow_unauthenticated_identities(false)
        .send()
        .await
        .expect("create identity pool");
    let pool_id = pool.identity_pool_id().to_string();

    let res = cognito_identity
        .get_id()
        .identity_pool_id(&pool_id)
        .send()
        .await;
    assert!(
        res.is_err(),
        "GetId without Logins must fail when AllowUnauthenticatedIdentities=false"
    );
}

#[tokio::test]
async fn cognito_identity_tagging_round_trip() {
    let server = TestServer::start().await;
    let cognito_identity = server.cognito_identity_client().await;

    let pool = cognito_identity
        .create_identity_pool()
        .identity_pool_name("tagged")
        .allow_unauthenticated_identities(true)
        .send()
        .await
        .expect("create identity pool");
    let pool_id = pool.identity_pool_id();
    let arn = format!(
        "arn:aws:cognito-identity:us-east-1:123456789012:identitypool/{}",
        pool_id
    );

    cognito_identity
        .tag_resource()
        .resource_arn(&arn)
        .tags("env", "prod")
        .send()
        .await
        .expect("tag resource");

    let tags = cognito_identity
        .list_tags_for_resource()
        .resource_arn(&arn)
        .send()
        .await
        .expect("list tags");
    assert_eq!(
        tags.tags().and_then(|m| m.get("env")).map(String::as_str),
        Some("prod")
    );

    cognito_identity
        .untag_resource()
        .resource_arn(&arn)
        .tag_keys("env")
        .send()
        .await
        .expect("untag resource");

    let after = cognito_identity
        .list_tags_for_resource()
        .resource_arn(&arn)
        .send()
        .await
        .expect("list tags after untag");
    assert!(after.tags().and_then(|m| m.get("env")).is_none());
}
