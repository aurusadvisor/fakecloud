//! End-to-end tests for the Organizations trusted-service +
//! delegated-administrator surface:
//! `EnableAWSServiceAccess`, `DisableAWSServiceAccess`,
//! `ListAWSServiceAccessForOrganization`,
//! `RegisterDelegatedAdministrator`, `DeregisterDelegatedAdministrator`,
//! `ListDelegatedAdministrators`, `ListDelegatedServicesForAccount`.
//!
//! Drives real `aws-sdk-organizations` against a fakecloud server with
//! `FAKECLOUD_IAM=strict` so the wire format and management-account
//! gating match real AWS Organizations.

mod helpers;

use aws_credential_types::Credentials;
use aws_sdk_organizations::types::HandshakeParty;
use aws_sdk_organizations::types::HandshakePartyType;
use aws_sdk_organizations::Client as OrgsClient;
use helpers::TestServer;

const MGMT_ACCOUNT: &str = "111111111111";
const MEMBER_ACCOUNT: &str = "222222222222";
const SECOND_MEMBER: &str = "333333333333";

const SERVICE_CONFIG: &str = "config.amazonaws.com";
const SERVICE_SSM: &str = "ssm.amazonaws.com";
const SERVICE_GUARDDUTY: &str = "guardduty.amazonaws.com";

async fn start() -> TestServer {
    TestServer::start_with_env(&[
        ("FAKECLOUD_IAM", "strict"),
        ("FAKECLOUD_VERIFY_SIGV4", "true"),
        // Organizations is pure control plane; no container runtime needed.
        ("FAKECLOUD_CONTAINER_CLI", "false"),
    ])
    .await
}

async fn config_with(server: &TestServer, akid: &str, secret: &str) -> aws_config::SdkConfig {
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .endpoint_url(server.endpoint())
        .region(aws_config::Region::new("us-east-1"))
        .credentials_provider(Credentials::new(akid, secret, None, None, "orgs-trusted"))
        .load()
        .await
}

/// Build an `OrgsClient` for `account_id` with admin credentials issued
/// by the test server's create-admin endpoint.
async fn client_for(server: &TestServer, account_id: &str) -> OrgsClient {
    let (akid, secret) = server.create_admin(account_id, "admin").await;
    let cfg = config_with(server, &akid, &secret).await;
    OrgsClient::new(&cfg)
}

/// Invite + accept `member` into the org owned by `mgmt`. Used by every
/// test that needs a real member account before registering a delegate.
async fn enroll_member(mgmt: &OrgsClient, member_client: &OrgsClient, member_id: &str) {
    let invite = mgmt
        .invite_account_to_organization()
        .target(
            HandshakeParty::builder()
                .id(member_id)
                .r#type(HandshakePartyType::Account)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let handshake_id = invite.handshake().unwrap().id().unwrap().to_string();
    member_client
        .accept_handshake()
        .handshake_id(handshake_id)
        .send()
        .await
        .unwrap();
}

#[tokio::test]
async fn enable_aws_service_access_then_list_shows_principal() {
    let server = start().await;
    let mgmt = client_for(&server, MGMT_ACCOUNT).await;
    mgmt.create_organization().send().await.unwrap();

    mgmt.enable_aws_service_access()
        .service_principal(SERVICE_CONFIG)
        .send()
        .await
        .unwrap();

    let listed = mgmt
        .list_aws_service_access_for_organization()
        .send()
        .await
        .unwrap();
    let principals: Vec<_> = listed
        .enabled_service_principals()
        .iter()
        .map(|p| p.service_principal().unwrap().to_string())
        .collect();
    assert_eq!(principals, vec![SERVICE_CONFIG.to_string()]);
    assert!(
        listed.enabled_service_principals()[0]
            .date_enabled()
            .is_some(),
        "DateEnabled should round-trip to the SDK"
    );
}

#[tokio::test]
async fn disable_aws_service_access_drops_principal() {
    let server = start().await;
    let mgmt = client_for(&server, MGMT_ACCOUNT).await;
    mgmt.create_organization().send().await.unwrap();

    mgmt.enable_aws_service_access()
        .service_principal(SERVICE_CONFIG)
        .send()
        .await
        .unwrap();
    mgmt.enable_aws_service_access()
        .service_principal(SERVICE_SSM)
        .send()
        .await
        .unwrap();

    mgmt.disable_aws_service_access()
        .service_principal(SERVICE_CONFIG)
        .send()
        .await
        .unwrap();

    let listed = mgmt
        .list_aws_service_access_for_organization()
        .send()
        .await
        .unwrap();
    let principals: Vec<_> = listed
        .enabled_service_principals()
        .iter()
        .map(|p| p.service_principal().unwrap().to_string())
        .collect();
    assert_eq!(principals, vec![SERVICE_SSM.to_string()]);
}

#[tokio::test]
async fn register_delegated_administrator_shows_in_both_lists() {
    let server = start().await;
    let mgmt = client_for(&server, MGMT_ACCOUNT).await;
    let member = client_for(&server, MEMBER_ACCOUNT).await;
    mgmt.create_organization().send().await.unwrap();
    enroll_member(&mgmt, &member, MEMBER_ACCOUNT).await;

    mgmt.enable_aws_service_access()
        .service_principal(SERVICE_SSM)
        .send()
        .await
        .unwrap();
    mgmt.enable_aws_service_access()
        .service_principal(SERVICE_GUARDDUTY)
        .send()
        .await
        .unwrap();

    mgmt.register_delegated_administrator()
        .account_id(MEMBER_ACCOUNT)
        .service_principal(SERVICE_SSM)
        .send()
        .await
        .unwrap();
    mgmt.register_delegated_administrator()
        .account_id(MEMBER_ACCOUNT)
        .service_principal(SERVICE_GUARDDUTY)
        .send()
        .await
        .unwrap();

    // ListDelegatedAdministrators returns both registrations (one per
    // service-principal) plus the same MEMBER_ACCOUNT id; default page
    // size lists everything.
    let admins = mgmt.list_delegated_administrators().send().await.unwrap();
    let ids: Vec<_> = admins
        .delegated_administrators()
        .iter()
        .map(|d| d.id().unwrap().to_string())
        .collect();
    assert_eq!(ids.len(), 2, "two registrations expected");
    assert!(ids.iter().all(|id| id == MEMBER_ACCOUNT));
    let first = &admins.delegated_administrators()[0];
    assert_eq!(
        first.email(),
        Some(format!("{MEMBER_ACCOUNT}@example.com").as_str())
    );
    assert!(first.delegation_enabled_date().is_some());
    assert!(first.joined_timestamp().is_some());

    // Filter by ServicePrincipal narrows to one row.
    let only_ssm = mgmt
        .list_delegated_administrators()
        .service_principal(SERVICE_SSM)
        .send()
        .await
        .unwrap();
    assert_eq!(only_ssm.delegated_administrators().len(), 1);

    // ListDelegatedServicesForAccount returns both service principals.
    let svcs = mgmt
        .list_delegated_services_for_account()
        .account_id(MEMBER_ACCOUNT)
        .send()
        .await
        .unwrap();
    let mut names: Vec<_> = svcs
        .delegated_services()
        .iter()
        .map(|s| s.service_principal().unwrap().to_string())
        .collect();
    names.sort();
    assert_eq!(
        names,
        vec![SERVICE_GUARDDUTY.to_string(), SERVICE_SSM.to_string()]
    );
    assert!(svcs.delegated_services()[0]
        .delegation_enabled_date()
        .is_some());
}

#[tokio::test]
async fn deregister_delegated_administrator_removes_entry() {
    let server = start().await;
    let mgmt = client_for(&server, MGMT_ACCOUNT).await;
    let member = client_for(&server, MEMBER_ACCOUNT).await;
    mgmt.create_organization().send().await.unwrap();
    enroll_member(&mgmt, &member, MEMBER_ACCOUNT).await;

    mgmt.enable_aws_service_access()
        .service_principal(SERVICE_SSM)
        .send()
        .await
        .unwrap();
    mgmt.register_delegated_administrator()
        .account_id(MEMBER_ACCOUNT)
        .service_principal(SERVICE_SSM)
        .send()
        .await
        .unwrap();

    mgmt.deregister_delegated_administrator()
        .account_id(MEMBER_ACCOUNT)
        .service_principal(SERVICE_SSM)
        .send()
        .await
        .unwrap();

    let admins = mgmt.list_delegated_administrators().send().await.unwrap();
    assert!(
        admins.delegated_administrators().is_empty(),
        "deregister should empty the delegated-administrator list"
    );

    let svcs = mgmt
        .list_delegated_services_for_account()
        .account_id(MEMBER_ACCOUNT)
        .send()
        .await
        .unwrap();
    assert!(svcs.delegated_services().is_empty());
}

#[tokio::test]
async fn list_delegated_services_filters_per_account() {
    let server = start().await;
    let mgmt = client_for(&server, MGMT_ACCOUNT).await;
    let member1 = client_for(&server, MEMBER_ACCOUNT).await;
    let member2 = client_for(&server, SECOND_MEMBER).await;
    mgmt.create_organization().send().await.unwrap();
    enroll_member(&mgmt, &member1, MEMBER_ACCOUNT).await;
    enroll_member(&mgmt, &member2, SECOND_MEMBER).await;

    mgmt.enable_aws_service_access()
        .service_principal(SERVICE_SSM)
        .send()
        .await
        .unwrap();
    mgmt.enable_aws_service_access()
        .service_principal(SERVICE_GUARDDUTY)
        .send()
        .await
        .unwrap();

    // member1 -> SSM only; member2 -> GuardDuty only.
    mgmt.register_delegated_administrator()
        .account_id(MEMBER_ACCOUNT)
        .service_principal(SERVICE_SSM)
        .send()
        .await
        .unwrap();
    mgmt.register_delegated_administrator()
        .account_id(SECOND_MEMBER)
        .service_principal(SERVICE_GUARDDUTY)
        .send()
        .await
        .unwrap();

    let svcs1 = mgmt
        .list_delegated_services_for_account()
        .account_id(MEMBER_ACCOUNT)
        .send()
        .await
        .unwrap();
    let names1: Vec<_> = svcs1
        .delegated_services()
        .iter()
        .map(|s| s.service_principal().unwrap().to_string())
        .collect();
    assert_eq!(names1, vec![SERVICE_SSM.to_string()]);

    let svcs2 = mgmt
        .list_delegated_services_for_account()
        .account_id(SECOND_MEMBER)
        .send()
        .await
        .unwrap();
    let names2: Vec<_> = svcs2
        .delegated_services()
        .iter()
        .map(|s| s.service_principal().unwrap().to_string())
        .collect();
    assert_eq!(names2, vec![SERVICE_GUARDDUTY.to_string()]);
}

#[tokio::test]
async fn list_aws_service_access_paginates() {
    let server = start().await;
    let mgmt = client_for(&server, MGMT_ACCOUNT).await;
    mgmt.create_organization().send().await.unwrap();

    for principal in [
        "config.amazonaws.com",
        "guardduty.amazonaws.com",
        "ssm.amazonaws.com",
    ] {
        mgmt.enable_aws_service_access()
            .service_principal(principal)
            .send()
            .await
            .unwrap();
    }

    // Page 1: max_results=2 -> two entries plus a NextToken.
    let page1 = mgmt
        .list_aws_service_access_for_organization()
        .max_results(2)
        .send()
        .await
        .unwrap();
    assert_eq!(page1.enabled_service_principals().len(), 2);
    let next = page1
        .next_token()
        .expect("first page should hand back a NextToken");

    // Page 2 with the token returns the remaining entry and no token.
    let page2 = mgmt
        .list_aws_service_access_for_organization()
        .max_results(2)
        .next_token(next)
        .send()
        .await
        .unwrap();
    assert_eq!(page2.enabled_service_principals().len(), 1);
    assert!(page2.next_token().is_none());
}
