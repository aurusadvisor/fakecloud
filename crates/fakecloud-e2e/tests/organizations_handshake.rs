//! End-to-end tests for the Organizations handshake invitation flow:
//! `InviteAccountToOrganization`, `AcceptHandshake`, `DeclineHandshake`,
//! `CancelHandshake`, `DescribeHandshake`, `ListHandshakesForAccount`,
//! and `ListHandshakesForOrganization`.
//!
//! Drives real `aws-sdk-organizations` against a fakecloud server with
//! `FAKECLOUD_IAM=strict` so the wire format and party-routing match
//! the real AWS shape.

mod helpers;

use aws_credential_types::Credentials;
use aws_sdk_organizations::types::{
    ActionType, HandshakeFilter, HandshakeParty, HandshakePartyType, HandshakeState,
};
use aws_sdk_organizations::Client as OrgsClient;
use helpers::TestServer;

const MGMT_ACCOUNT: &str = "111111111111";
const TARGET_ACCOUNT: &str = "222222222222";
const SECOND_TARGET: &str = "333333333333";

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
        .credentials_provider(Credentials::new(akid, secret, None, None, "orgs-handshake"))
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

#[tokio::test]
async fn invite_then_accept_enrolls_account() {
    let server = start().await;
    let mgmt = client_for(&server, MGMT_ACCOUNT).await;
    let target = client_for(&server, TARGET_ACCOUNT).await;
    mgmt.create_organization().send().await.unwrap();

    let invite = mgmt
        .invite_account_to_organization()
        .target(
            HandshakeParty::builder()
                .id(TARGET_ACCOUNT)
                .r#type(HandshakePartyType::Account)
                .build()
                .unwrap(),
        )
        .notes("welcome aboard")
        .send()
        .await
        .unwrap();
    let h = invite.handshake().unwrap();
    assert!(h.id().unwrap().starts_with("h-"));
    assert_eq!(h.action(), Some(&ActionType::InviteAccountToOrganization));
    assert_eq!(h.state(), Some(&HandshakeState::Open));
    let parties = h.parties();
    assert!(
        parties
            .iter()
            .any(|p| p.r#type() == &HandshakePartyType::Organization),
        "parties should include the inviting organization"
    );
    assert!(
        parties
            .iter()
            .any(|p| p.id() == TARGET_ACCOUNT && p.r#type() == &HandshakePartyType::Account),
        "parties should include the target account"
    );

    let handshake_id = h.id().unwrap().to_string();

    // Accept from the target account; this enrolls the account.
    let accepted = target
        .accept_handshake()
        .handshake_id(&handshake_id)
        .send()
        .await
        .unwrap();
    assert_eq!(
        accepted.handshake().unwrap().state(),
        Some(&HandshakeState::Accepted)
    );

    // Management's ListAccounts now sees the new member.
    let listed = mgmt.list_accounts().send().await.unwrap();
    assert!(
        listed
            .accounts()
            .iter()
            .any(|a| a.id() == Some(TARGET_ACCOUNT)),
        "target account should now appear in ListAccounts after accept"
    );
}

#[tokio::test]
async fn decline_handshake_keeps_account_out() {
    let server = start().await;
    let mgmt = client_for(&server, MGMT_ACCOUNT).await;
    let target = client_for(&server, TARGET_ACCOUNT).await;
    mgmt.create_organization().send().await.unwrap();

    let invite = mgmt
        .invite_account_to_organization()
        .target(
            HandshakeParty::builder()
                .id(TARGET_ACCOUNT)
                .r#type(HandshakePartyType::Account)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let id = invite.handshake().unwrap().id().unwrap().to_string();

    let declined = target
        .decline_handshake()
        .handshake_id(&id)
        .send()
        .await
        .unwrap();
    assert_eq!(
        declined.handshake().unwrap().state(),
        Some(&HandshakeState::Declined)
    );

    let listed = mgmt.list_accounts().send().await.unwrap();
    assert!(
        !listed
            .accounts()
            .iter()
            .any(|a| a.id() == Some(TARGET_ACCOUNT)),
        "declined invitations must not enroll the target account"
    );
}

#[tokio::test]
async fn cancel_handshake_before_accept_locks_terminal() {
    let server = start().await;
    let mgmt = client_for(&server, MGMT_ACCOUNT).await;
    let target = client_for(&server, TARGET_ACCOUNT).await;
    mgmt.create_organization().send().await.unwrap();

    let invite = mgmt
        .invite_account_to_organization()
        .target(
            HandshakeParty::builder()
                .id(TARGET_ACCOUNT)
                .r#type(HandshakePartyType::Account)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let id = invite.handshake().unwrap().id().unwrap().to_string();

    let canceled = mgmt
        .cancel_handshake()
        .handshake_id(&id)
        .send()
        .await
        .unwrap();
    assert_eq!(
        canceled.handshake().unwrap().state(),
        Some(&HandshakeState::Canceled)
    );

    // Now target tries to accept — it should fail because the handshake
    // is already terminal.
    let err = target
        .accept_handshake()
        .handshake_id(&id)
        .send()
        .await
        .unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("InvalidHandshakeTransition"),
        "expected InvalidHandshakeTransition, got: {msg}"
    );
}

#[tokio::test]
async fn list_handshakes_for_account_filters_by_target() {
    let server = start().await;
    let mgmt = client_for(&server, MGMT_ACCOUNT).await;
    let target = client_for(&server, TARGET_ACCOUNT).await;
    let other = client_for(&server, SECOND_TARGET).await;
    mgmt.create_organization().send().await.unwrap();

    // Invite two distinct targets.
    mgmt.invite_account_to_organization()
        .target(
            HandshakeParty::builder()
                .id(TARGET_ACCOUNT)
                .r#type(HandshakePartyType::Account)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    mgmt.invite_account_to_organization()
        .target(
            HandshakeParty::builder()
                .id(SECOND_TARGET)
                .r#type(HandshakePartyType::Account)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    let target_list = target.list_handshakes_for_account().send().await.unwrap();
    let target_handshakes = target_list.handshakes();
    assert_eq!(
        target_handshakes.len(),
        1,
        "TARGET_ACCOUNT should only see its own handshake"
    );
    let other_list = other.list_handshakes_for_account().send().await.unwrap();
    assert_eq!(
        other_list.handshakes().len(),
        1,
        "SECOND_TARGET should only see its own handshake"
    );

    // Org-wide list (management only) should see both.
    let org_list = mgmt
        .list_handshakes_for_organization()
        .send()
        .await
        .unwrap();
    assert_eq!(org_list.handshakes().len(), 2);

    // Filter by ActionType=INVITE — both still match.
    let filtered = mgmt
        .list_handshakes_for_organization()
        .filter(
            HandshakeFilter::builder()
                .action_type(ActionType::InviteAccountToOrganization)
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(filtered.handshakes().len(), 2);

    // Filter by an unrelated ActionType — none match.
    let none = mgmt
        .list_handshakes_for_organization()
        .filter(
            HandshakeFilter::builder()
                .action_type(ActionType::EnableAllFeatures)
                .build(),
        )
        .send()
        .await
        .unwrap();
    assert!(none.handshakes().is_empty());
}

#[tokio::test]
async fn describe_handshake_round_trips_invite() {
    let server = start().await;
    let mgmt = client_for(&server, MGMT_ACCOUNT).await;
    mgmt.create_organization().send().await.unwrap();

    let invite = mgmt
        .invite_account_to_organization()
        .target(
            HandshakeParty::builder()
                .id(TARGET_ACCOUNT)
                .r#type(HandshakePartyType::Account)
                .build()
                .unwrap(),
        )
        .notes("hello")
        .send()
        .await
        .unwrap();
    let h = invite.handshake().unwrap();
    let id = h.id().unwrap().to_string();

    let described = mgmt
        .describe_handshake()
        .handshake_id(&id)
        .send()
        .await
        .unwrap();
    let h2 = described.handshake().unwrap();
    assert_eq!(h2.id(), Some(id.as_str()));
    assert_eq!(h2.action(), Some(&ActionType::InviteAccountToOrganization));
    assert_eq!(h2.state(), Some(&HandshakeState::Open));
}

#[tokio::test]
async fn pagination_caps_results_and_round_trips_token() {
    let server = start().await;
    let mgmt = client_for(&server, MGMT_ACCOUNT).await;
    mgmt.create_organization().send().await.unwrap();

    // Issue three invites.
    for acct in ["222222222222", "333333333333", "444444444444"] {
        mgmt.invite_account_to_organization()
            .target(
                HandshakeParty::builder()
                    .id(acct)
                    .r#type(HandshakePartyType::Account)
                    .build()
                    .unwrap(),
            )
            .send()
            .await
            .unwrap();
    }

    let page1 = mgmt
        .list_handshakes_for_organization()
        .max_results(2)
        .send()
        .await
        .unwrap();
    assert_eq!(page1.handshakes().len(), 2);
    let token = page1.next_token().expect("next_token for second page");

    let page2 = mgmt
        .list_handshakes_for_organization()
        .max_results(2)
        .next_token(token)
        .send()
        .await
        .unwrap();
    assert_eq!(page2.handshakes().len(), 1);
    assert!(page2.next_token().is_none());
}
