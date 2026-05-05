//! End-to-end tests for the Organizations account lifecycle ops:
//! `CreateAccount`, `CreateGovCloudAccount`, `DescribeCreateAccountStatus`,
//! `ListCreateAccountStatus`, `CloseAccount`, and
//! `RemoveAccountFromOrganization`.
//!
//! Drives real `aws-sdk-organizations` against a fakecloud server with
//! `FAKECLOUD_IAM=strict` so the wire format and async lifecycle
//! (IN_PROGRESS -> SUCCEEDED) match the real AWS shape.

mod helpers;

use std::time::{Duration, Instant};

use aws_credential_types::Credentials;
use aws_sdk_organizations::types::{
    CreateAccountState, CreateAccountStatus as SdkCreateAccountStatus,
};
use aws_sdk_organizations::Client as OrgsClient;
use helpers::TestServer;

const MGMT_ACCOUNT: &str = "111111111111";

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
        .credentials_provider(Credentials::new(akid, secret, None, None, "orgs-lifecycle"))
        .load()
        .await
}

/// Poll `DescribeCreateAccountStatus` until the request reaches a
/// terminal state, with a generous timeout so CI machines under load
/// still pass. Returns the terminal status.
async fn poll_until_terminal(orgs: &OrgsClient, request_id: &str) -> SdkCreateAccountStatus {
    let deadline = Instant::now() + Duration::from_secs(15);
    loop {
        let resp = orgs
            .describe_create_account_status()
            .create_account_request_id(request_id)
            .send()
            .await
            .unwrap();
        let status = resp.create_account_status().unwrap().clone();
        match status.state() {
            Some(CreateAccountState::Succeeded) | Some(CreateAccountState::Failed) => {
                return status;
            }
            _ => {}
        }
        assert!(
            Instant::now() < deadline,
            "CreateAccount {request_id} did not terminate within 15s"
        );
        tokio::time::sleep(Duration::from_millis(150)).await;
    }
}

#[tokio::test]
async fn create_account_in_progress_then_succeeds_then_lists() {
    let server = start().await;
    let (akid, secret) = server.create_admin(MGMT_ACCOUNT, "admin").await;
    let cfg = config_with(&server, &akid, &secret).await;
    let orgs = OrgsClient::new(&cfg);
    orgs.create_organization().send().await.unwrap();

    let created = orgs
        .create_account()
        .email("new@example.com")
        .account_name("New")
        .send()
        .await
        .unwrap();
    let initial = created.create_account_status().unwrap();
    assert_eq!(
        initial.state(),
        Some(&CreateAccountState::InProgress),
        "first response should be IN_PROGRESS"
    );
    let request_id = initial.id().unwrap().to_string();
    assert!(
        request_id.starts_with("car-"),
        "request id should start with car-, got {request_id}"
    );
    let new_account_id = initial.account_id().unwrap().to_string();
    assert_eq!(new_account_id.len(), 12);
    assert!(
        new_account_id.chars().all(|c| c.is_ascii_digit()),
        "account id should be 12 digits, got {new_account_id}"
    );

    // While IN_PROGRESS, the new account is not yet in ListAccounts —
    // mirrors AWS's "appears only after success" semantics.
    let listed_pending = orgs.list_accounts().send().await.unwrap();
    assert!(
        !listed_pending
            .accounts()
            .iter()
            .any(|a| a.id() == Some(&new_account_id)),
        "new account should not appear in ListAccounts while IN_PROGRESS"
    );

    let final_status = poll_until_terminal(&orgs, &request_id).await;
    assert_eq!(final_status.state(), Some(&CreateAccountState::Succeeded));
    assert!(final_status.completed_timestamp().is_some());

    // Now the account should be enrolled.
    let listed_post = orgs.list_accounts().send().await.unwrap();
    let found = listed_post
        .accounts()
        .iter()
        .find(|a| a.id() == Some(&new_account_id))
        .expect("new account must appear in ListAccounts after SUCCEEDED");
    assert_eq!(found.email(), Some("new@example.com"));
    assert_eq!(found.name(), Some("New"));
    assert_eq!(
        found.status(),
        Some(&aws_sdk_organizations::types::AccountStatus::Active)
    );
}

#[tokio::test]
async fn list_create_account_status_filters_and_paginates() {
    let server = start().await;
    let (akid, secret) = server.create_admin(MGMT_ACCOUNT, "admin").await;
    let cfg = config_with(&server, &akid, &secret).await;
    let orgs = OrgsClient::new(&cfg);
    orgs.create_organization().send().await.unwrap();

    // Three concurrent CreateAccount requests.
    let mut request_ids = Vec::new();
    for i in 0..3 {
        let resp = orgs
            .create_account()
            .email(format!("p{i}@example.com"))
            .account_name(format!("P{i}"))
            .send()
            .await
            .unwrap();
        request_ids.push(
            resp.create_account_status()
                .unwrap()
                .id()
                .unwrap()
                .to_string(),
        );
    }

    // Wait for all to reach SUCCEEDED.
    for id in &request_ids {
        poll_until_terminal(&orgs, id).await;
    }

    // SUCCEEDED filter returns all three.
    let succeeded = orgs
        .list_create_account_status()
        .states(CreateAccountState::Succeeded)
        .send()
        .await
        .unwrap();
    assert_eq!(succeeded.create_account_statuses().len(), 3);

    // IN_PROGRESS filter returns none.
    let in_progress = orgs
        .list_create_account_status()
        .states(CreateAccountState::InProgress)
        .send()
        .await
        .unwrap();
    assert!(in_progress.create_account_statuses().is_empty());

    // Pagination: MaxResults=2 yields 2 + NextToken; second page yields 1.
    let page1 = orgs
        .list_create_account_status()
        .max_results(2)
        .send()
        .await
        .unwrap();
    assert_eq!(page1.create_account_statuses().len(), 2);
    let token = page1
        .next_token()
        .expect("first page should return a NextToken")
        .to_string();
    let page2 = orgs
        .list_create_account_status()
        .max_results(2)
        .next_token(token)
        .send()
        .await
        .unwrap();
    assert_eq!(page2.create_account_statuses().len(), 1);
    assert!(
        page2.next_token().is_none(),
        "last page should not return a NextToken"
    );
}

#[tokio::test]
async fn create_gov_cloud_account_returns_paired_id() {
    let server = start().await;
    let (akid, secret) = server.create_admin(MGMT_ACCOUNT, "admin").await;
    let cfg = config_with(&server, &akid, &secret).await;
    let orgs = OrgsClient::new(&cfg);
    orgs.create_organization().send().await.unwrap();

    let created = orgs
        .create_gov_cloud_account()
        .email("gov@example.com")
        .account_name("Gov")
        .send()
        .await
        .unwrap();
    let status = created.create_account_status().unwrap();
    assert_eq!(status.state(), Some(&CreateAccountState::InProgress));
    let request_id = status.id().unwrap().to_string();
    let commercial_id = status.account_id().unwrap().to_string();
    let gov_id = status.gov_cloud_account_id().unwrap().to_string();
    assert_ne!(
        commercial_id, gov_id,
        "commercial and GovCloud ids must differ"
    );

    let final_status = poll_until_terminal(&orgs, &request_id).await;
    assert_eq!(final_status.state(), Some(&CreateAccountState::Succeeded));
    assert_eq!(final_status.account_id(), Some(commercial_id.as_str()));
    assert_eq!(final_status.gov_cloud_account_id(), Some(gov_id.as_str()));

    // Both the commercial and GovCloud paired accounts should now be
    // enrolled in the org.
    let accounts = orgs.list_accounts().send().await.unwrap();
    let ids: Vec<&str> = accounts.accounts().iter().filter_map(|a| a.id()).collect();
    assert!(ids.contains(&commercial_id.as_str()));
    assert!(ids.contains(&gov_id.as_str()));
}

#[tokio::test]
async fn close_account_marks_suspended() {
    let server = start().await;
    let (akid, secret) = server.create_admin(MGMT_ACCOUNT, "admin").await;
    let cfg = config_with(&server, &akid, &secret).await;
    let orgs = OrgsClient::new(&cfg);
    orgs.create_organization().send().await.unwrap();

    let created = orgs
        .create_account()
        .email("close@example.com")
        .account_name("Close")
        .send()
        .await
        .unwrap();
    let request_id = created
        .create_account_status()
        .unwrap()
        .id()
        .unwrap()
        .to_string();
    let final_status = poll_until_terminal(&orgs, &request_id).await;
    let account_id = final_status.account_id().unwrap().to_string();

    orgs.close_account()
        .account_id(&account_id)
        .send()
        .await
        .unwrap();

    let described = orgs
        .describe_account()
        .account_id(&account_id)
        .send()
        .await
        .unwrap();
    assert_eq!(
        described.account().unwrap().status(),
        Some(&aws_sdk_organizations::types::AccountStatus::Suspended),
    );

    // Closing the management account is rejected.
    let err = orgs
        .close_account()
        .account_id(MGMT_ACCOUNT)
        .send()
        .await
        .unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("ConstraintViolationException"),
        "expected ConstraintViolationException, got: {msg}"
    );
}

#[tokio::test]
async fn remove_account_unlinks_member_from_organization() {
    let server = start().await;
    let (akid, secret) = server.create_admin(MGMT_ACCOUNT, "admin").await;
    let cfg = config_with(&server, &akid, &secret).await;
    let orgs = OrgsClient::new(&cfg);
    orgs.create_organization().send().await.unwrap();

    let created = orgs
        .create_account()
        .email("remove@example.com")
        .account_name("Remove")
        .send()
        .await
        .unwrap();
    let request_id = created
        .create_account_status()
        .unwrap()
        .id()
        .unwrap()
        .to_string();
    let final_status = poll_until_terminal(&orgs, &request_id).await;
    let account_id = final_status.account_id().unwrap().to_string();

    // Move the account into a fresh OU so we can confirm removal also
    // unlinks it from the OU subtree (DescribeAccount must fail across
    // the board, not just under the root).
    let root = orgs.list_roots().send().await.unwrap();
    let root_id = root.roots().first().unwrap().id().unwrap().to_string();
    let ou = orgs
        .create_organizational_unit()
        .parent_id(&root_id)
        .name("UnlinkTest")
        .send()
        .await
        .unwrap();
    let ou_id = ou.organizational_unit().unwrap().id().unwrap().to_string();
    orgs.move_account()
        .account_id(&account_id)
        .source_parent_id(&root_id)
        .destination_parent_id(&ou_id)
        .send()
        .await
        .unwrap();

    orgs.remove_account_from_organization()
        .account_id(&account_id)
        .send()
        .await
        .unwrap();

    let err = orgs
        .describe_account()
        .account_id(&account_id)
        .send()
        .await
        .unwrap_err();
    let msg = format!("{err:?}");
    assert!(
        msg.contains("AccountNotFoundException"),
        "expected AccountNotFoundException after removal, got: {msg}"
    );

    // The OU should no longer list the account either.
    let ou_accounts = orgs
        .list_accounts_for_parent()
        .parent_id(&ou_id)
        .send()
        .await
        .unwrap();
    assert!(
        ou_accounts.accounts().is_empty(),
        "OU should be empty after RemoveAccountFromOrganization"
    );
}
