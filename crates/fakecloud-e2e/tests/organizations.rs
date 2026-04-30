//! End-to-end tests for the minimal Organizations control plane
//! (Batch 1: CreateOrganization / DescribeOrganization / DeleteOrganization).
//!
//! Drives `aws-sdk-organizations` against a fakecloud server running in
//! `FAKECLOUD_IAM=strict` to prove the wire format matches and that the
//! service participates in multi-account dispatch correctly.

mod helpers;

use aws_credential_types::Credentials;
use aws_sdk_organizations::Client as OrgsClient;
use helpers::TestServer;

const ACCOUNT_A: &str = "111111111111";
const ACCOUNT_B: &str = "222222222222";

async fn start() -> TestServer {
    TestServer::start_with_env(&[
        ("FAKECLOUD_IAM", "strict"),
        ("FAKECLOUD_VERIFY_SIGV4", "true"),
        // Organizations is pure control plane; no container runtime
        // needed. Skip the reaper to keep CI fast and avoid flaky
        // docker-info probes on machines where the daemon is slow.
        ("FAKECLOUD_CONTAINER_CLI", "false"),
    ])
    .await
}

async fn config_with(server: &TestServer, akid: &str, secret: &str) -> aws_config::SdkConfig {
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .endpoint_url(server.endpoint())
        .region(aws_config::Region::new("us-east-1"))
        .credentials_provider(Credentials::new(akid, secret, None, None, "orgs-test"))
        .load()
        .await
}

#[tokio::test]
async fn create_and_describe_round_trip() {
    let server = start().await;
    let (akid, secret) = server.create_admin(ACCOUNT_A, "admin-a").await;
    let cfg = config_with(&server, &akid, &secret).await;
    let orgs = OrgsClient::new(&cfg);

    let created = orgs.create_organization().send().await.unwrap();
    let org = created.organization().unwrap();
    assert_eq!(org.master_account_id().unwrap(), ACCOUNT_A);
    assert_eq!(
        org.feature_set().unwrap(),
        &aws_sdk_organizations::types::OrganizationFeatureSet::All
    );
    assert!(org.id().unwrap().starts_with("o-"));

    let described = orgs.describe_organization().send().await.unwrap();
    let org2 = described.organization().unwrap();
    assert_eq!(org2.id(), org.id());
    assert_eq!(org2.master_account_id().unwrap(), ACCOUNT_A);
}

#[tokio::test]
async fn second_create_fails_with_already_in_org() {
    let server = start().await;
    let (akid, secret) = server.create_admin(ACCOUNT_A, "admin-a").await;
    let cfg = config_with(&server, &akid, &secret).await;
    let orgs = OrgsClient::new(&cfg);

    orgs.create_organization().send().await.unwrap();
    let err = orgs.create_organization().send().await.unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("AlreadyInOrganizationException"),
        "expected AlreadyInOrganizationException, got: {msg}"
    );
}

#[tokio::test]
async fn describe_without_org_returns_not_in_use() {
    let server = start().await;
    let (akid, secret) = server.create_admin(ACCOUNT_A, "admin-a").await;
    let cfg = config_with(&server, &akid, &secret).await;
    let orgs = OrgsClient::new(&cfg);

    let err = orgs.describe_organization().send().await.unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("AWSOrganizationsNotInUseException"),
        "expected AWSOrganizationsNotInUseException, got: {msg}"
    );
}

#[tokio::test]
async fn only_management_can_delete_organization() {
    let server = start().await;
    let (a_akid, a_secret) = server.create_admin(ACCOUNT_A, "admin-a").await;
    let (b_akid, b_secret) = server.create_admin(ACCOUNT_B, "admin-b").await;

    let a_cfg = config_with(&server, &a_akid, &a_secret).await;
    let b_cfg = config_with(&server, &b_akid, &b_secret).await;
    let orgs_a = OrgsClient::new(&a_cfg);
    let orgs_b = OrgsClient::new(&b_cfg);

    // Account A creates the organization -> A is the management account.
    orgs_a.create_organization().send().await.unwrap();

    // Account B is not a member of the organization, so both
    // DescribeOrganization and DeleteOrganization must look exactly
    // like "no org exists" — we don't leak org metadata to non-members.
    let err = orgs_b.describe_organization().send().await.unwrap_err();
    assert!(format!("{err:?}").contains("AWSOrganizationsNotInUseException"));
    let err = orgs_b.delete_organization().send().await.unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("AWSOrganizationsNotInUseException"),
        "expected AWSOrganizationsNotInUseException, got: {msg}"
    );

    // Management account deletes successfully.
    orgs_a.delete_organization().send().await.unwrap();

    // Describe now fails again -> state really went back to None.
    let err = orgs_a.describe_organization().send().await.unwrap_err();
    assert!(format!("{err:?}").contains("AWSOrganizationsNotInUseException"));
}

#[tokio::test]
async fn list_roots_after_create() {
    let server = start().await;
    let (akid, secret) = server.create_admin(ACCOUNT_A, "admin-a").await;
    let cfg = config_with(&server, &akid, &secret).await;
    let orgs = OrgsClient::new(&cfg);

    orgs.create_organization().send().await.unwrap();
    let roots = orgs.list_roots().send().await.unwrap();
    let roots = roots.roots();
    assert_eq!(roots.len(), 1);
    assert!(roots[0].id().unwrap().starts_with("r-"));
}

#[tokio::test]
async fn ou_tree_crud_and_move_account() {
    let server = start().await;
    let (a_akid, a_secret) = server.create_admin(ACCOUNT_A, "admin-a").await;
    let a_cfg = config_with(&server, &a_akid, &a_secret).await;
    let orgs = OrgsClient::new(&a_cfg);

    orgs.create_organization().send().await.unwrap();
    let root_id = orgs.list_roots().send().await.unwrap().roots()[0]
        .id()
        .unwrap()
        .to_string();

    // Create OU, account B auto-enrolls into root when admin created.
    let (_b_akid, _b_secret) = server.create_admin(ACCOUNT_B, "admin-b").await;

    let ou = orgs
        .create_organizational_unit()
        .parent_id(&root_id)
        .name("engineering")
        .send()
        .await
        .unwrap();
    let ou_id = ou.organizational_unit().unwrap().id().unwrap().to_string();

    // Duplicate name under same parent -> DuplicateOrganizationalUnitException.
    let err = orgs
        .create_organizational_unit()
        .parent_id(&root_id)
        .name("engineering")
        .send()
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("DuplicateOrganizationalUnitException"));

    // Move account B from root to the new OU.
    orgs.move_account()
        .account_id(ACCOUNT_B)
        .source_parent_id(&root_id)
        .destination_parent_id(&ou_id)
        .send()
        .await
        .unwrap();

    let in_ou = orgs
        .list_accounts_for_parent()
        .parent_id(&ou_id)
        .send()
        .await
        .unwrap();
    assert_eq!(in_ou.accounts().len(), 1);
    assert_eq!(in_ou.accounts()[0].id().unwrap(), ACCOUNT_B);

    // Deleting the non-empty OU must fail.
    let err = orgs
        .delete_organizational_unit()
        .organizational_unit_id(&ou_id)
        .send()
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("OrganizationalUnitNotEmptyException"));

    // Move back, then delete — should succeed.
    orgs.move_account()
        .account_id(ACCOUNT_B)
        .source_parent_id(&ou_id)
        .destination_parent_id(&root_id)
        .send()
        .await
        .unwrap();
    orgs.delete_organizational_unit()
        .organizational_unit_id(&ou_id)
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn non_management_member_cannot_create_ou() {
    let server = start().await;
    let (a_akid, a_secret) = server.create_admin(ACCOUNT_A, "admin-a").await;
    let a_cfg = config_with(&server, &a_akid, &a_secret).await;
    let orgs_a = OrgsClient::new(&a_cfg);

    // Create the org before bootstrapping account B so B auto-enrolls
    // into root as a member — otherwise B is a non-member and the
    // attempt would return `AWSOrganizationsNotInUseException` instead
    // of `AccessDeniedException`.
    orgs_a.create_organization().send().await.unwrap();
    let root_id = orgs_a.list_roots().send().await.unwrap().roots()[0]
        .id()
        .unwrap()
        .to_string();

    let (b_akid, b_secret) = server.create_admin(ACCOUNT_B, "admin-b").await;
    let b_cfg = config_with(&server, &b_akid, &b_secret).await;
    let orgs_b = OrgsClient::new(&b_cfg);

    let err = orgs_b
        .create_organizational_unit()
        .parent_id(&root_id)
        .name("forbidden")
        .send()
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("AccessDeniedException"));
}

const SCP_ALLOW_ALL: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;

#[tokio::test]
async fn scp_create_attach_detach_delete_roundtrip() {
    let server = start().await;
    let (akid, secret) = server.create_admin(ACCOUNT_A, "admin-a").await;
    let cfg = config_with(&server, &akid, &secret).await;
    let orgs = OrgsClient::new(&cfg);

    orgs.create_organization().send().await.unwrap();
    let root_id = orgs.list_roots().send().await.unwrap().roots()[0]
        .id()
        .unwrap()
        .to_string();

    // CreatePolicy -> returned id starts with p-.
    let created = orgs
        .create_policy()
        .name("CustomGuardrail")
        .description("test SCP")
        .r#type(aws_sdk_organizations::types::PolicyType::ServiceControlPolicy)
        .content(SCP_ALLOW_ALL)
        .send()
        .await
        .unwrap();
    let policy_id = created
        .policy()
        .unwrap()
        .policy_summary()
        .unwrap()
        .id()
        .unwrap()
        .to_string();
    assert!(policy_id.starts_with("p-"));

    // Attach to root.
    orgs.attach_policy()
        .policy_id(&policy_id)
        .target_id(&root_id)
        .send()
        .await
        .unwrap();

    // Delete attached -> fails.
    let err = orgs
        .delete_policy()
        .policy_id(&policy_id)
        .send()
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("PolicyInUseException"));

    // ListPoliciesForTarget sees Custom + FullAWSAccess.
    let list = orgs
        .list_policies_for_target()
        .target_id(&root_id)
        .filter(aws_sdk_organizations::types::PolicyType::ServiceControlPolicy)
        .send()
        .await
        .unwrap();
    let names: Vec<String> = list
        .policies()
        .iter()
        .map(|p| p.name().unwrap().to_string())
        .collect();
    assert!(names.contains(&"CustomGuardrail".to_string()));
    assert!(names.contains(&"FullAWSAccess".to_string()));

    // ListTargetsForPolicy sees the root.
    let targets = orgs
        .list_targets_for_policy()
        .policy_id(&policy_id)
        .send()
        .await
        .unwrap();
    assert_eq!(targets.targets().len(), 1);
    assert_eq!(targets.targets()[0].target_id().unwrap(), root_id);

    // Detach + delete succeed.
    orgs.detach_policy()
        .policy_id(&policy_id)
        .target_id(&root_id)
        .send()
        .await
        .unwrap();
    orgs.delete_policy()
        .policy_id(&policy_id)
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn scp_full_aws_access_is_immutable() {
    let server = start().await;
    let (akid, secret) = server.create_admin(ACCOUNT_A, "admin-a").await;
    let cfg = config_with(&server, &akid, &secret).await;
    let orgs = OrgsClient::new(&cfg);

    orgs.create_organization().send().await.unwrap();
    let err = orgs
        .delete_policy()
        .policy_id("p-FullAWSAccess")
        .send()
        .await
        .unwrap_err();
    assert!(format!("{err:?}").contains("PolicyChangesNotAllowedException"));
}

