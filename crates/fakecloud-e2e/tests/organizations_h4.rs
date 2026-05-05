//! End-to-end tests for batch H4: Organizations tagging + nav ops.
//!
//! Covers:
//! * `TagResource` / `UntagResource` / `ListTagsForResource` round-trip on
//!   Account, OU, Policy, and Root targets.
//! * `ListParents` traversal through a 3-level OU tree.
//! * `ListChildren` filtered by `ChildType` (ACCOUNT vs ORGANIZATIONAL_UNIT).
//! * `DescribeEffectivePolicy` walking from a leaf account up through OUs to
//!   root, unioning tag-policy statements at each level.
//! * `PutResourcePolicy` -> `DescribeResourcePolicy` -> `DeleteResourcePolicy`
//!   round-trip on the org-level resource policy.

mod helpers;

use aws_credential_types::Credentials;
use aws_sdk_organizations::types::{ChildType, EffectivePolicyType, PolicyType, Tag};
use aws_sdk_organizations::Client as OrgsClient;
use helpers::TestServer;

const MGMT_ACCOUNT: &str = "111111111111";

async fn start() -> TestServer {
    TestServer::start_with_env(&[
        ("FAKECLOUD_IAM", "strict"),
        ("FAKECLOUD_VERIFY_SIGV4", "true"),
        ("FAKECLOUD_CONTAINER_CLI", "false"),
    ])
    .await
}

async fn config_with(server: &TestServer, akid: &str, secret: &str) -> aws_config::SdkConfig {
    aws_config::defaults(aws_config::BehaviorVersion::latest())
        .endpoint_url(server.endpoint())
        .region(aws_config::Region::new("us-east-1"))
        .credentials_provider(Credentials::new(akid, secret, None, None, "orgs-h4"))
        .load()
        .await
}

async fn bootstrap() -> (TestServer, OrgsClient, String) {
    let server = start().await;
    let (akid, secret) = server.create_admin(MGMT_ACCOUNT, "admin").await;
    let cfg = config_with(&server, &akid, &secret).await;
    let orgs = OrgsClient::new(&cfg);
    orgs.create_organization().send().await.unwrap();
    let roots = orgs.list_roots().send().await.unwrap();
    let root_id = roots.roots()[0].id().unwrap().to_string();
    (server, orgs, root_id)
}

fn tag(key: &str, value: &str) -> Tag {
    Tag::builder().key(key).value(value).build().unwrap()
}

#[tokio::test]
async fn tag_resource_round_trip_on_account_ou_policy_and_root() {
    let (_server, orgs, root_id) = bootstrap().await;

    // Build a target of each type:
    // - Root (already exists)
    // - Account (the management account)
    // - OU under root
    // - Customer-managed SCP
    let ou = orgs
        .create_organizational_unit()
        .parent_id(&root_id)
        .name("dev")
        .send()
        .await
        .unwrap();
    let ou_id = ou.organizational_unit().unwrap().id().unwrap().to_string();

    let policy = orgs
        .create_policy()
        .name("DenyTags")
        .description("h4 test")
        .content(r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"*","Resource":"*"}]}"#)
        .r#type(PolicyType::ServiceControlPolicy)
        .send()
        .await
        .unwrap();
    let policy_id = policy
        .policy()
        .unwrap()
        .policy_summary()
        .unwrap()
        .id()
        .unwrap()
        .to_string();

    for target in [
        root_id.as_str(),
        MGMT_ACCOUNT,
        ou_id.as_str(),
        policy_id.as_str(),
    ] {
        // Empty initially.
        let initial = orgs
            .list_tags_for_resource()
            .resource_id(target)
            .send()
            .await
            .unwrap();
        assert!(
            initial.tags().is_empty(),
            "{target} should have no tags before TagResource"
        );

        // Tag with two pairs.
        orgs.tag_resource()
            .resource_id(target)
            .tags(tag("env", "prod"))
            .tags(tag("team", "platform"))
            .send()
            .await
            .unwrap();

        let after_tag = orgs
            .list_tags_for_resource()
            .resource_id(target)
            .send()
            .await
            .unwrap();
        let mut keys: Vec<&str> = after_tag.tags().iter().map(|t| t.key()).collect();
        keys.sort();
        assert_eq!(keys, vec!["env", "team"], "{target} tags after TagResource");

        // Untag one of the keys.
        orgs.untag_resource()
            .resource_id(target)
            .tag_keys("env")
            .send()
            .await
            .unwrap();

        let after_untag = orgs
            .list_tags_for_resource()
            .resource_id(target)
            .send()
            .await
            .unwrap();
        let remaining: Vec<&str> = after_untag.tags().iter().map(|t| t.key()).collect();
        assert_eq!(
            remaining,
            vec!["team"],
            "{target} should keep only the un-removed tag"
        );

        // Tagging the same key again should overwrite, not duplicate.
        orgs.tag_resource()
            .resource_id(target)
            .tags(tag("team", "billing"))
            .send()
            .await
            .unwrap();
        let overwritten = orgs
            .list_tags_for_resource()
            .resource_id(target)
            .send()
            .await
            .unwrap();
        assert_eq!(overwritten.tags().len(), 1);
        assert_eq!(overwritten.tags()[0].key(), "team");
        assert_eq!(overwritten.tags()[0].value(), "billing");
    }
}

#[tokio::test]
async fn list_parents_walks_three_level_ou_tree() {
    let (_server, orgs, root_id) = bootstrap().await;

    // root -> ou1 -> ou2 -> ou3
    let ou1 = orgs
        .create_organizational_unit()
        .parent_id(&root_id)
        .name("level1")
        .send()
        .await
        .unwrap();
    let ou1_id = ou1.organizational_unit().unwrap().id().unwrap().to_string();
    let ou2 = orgs
        .create_organizational_unit()
        .parent_id(&ou1_id)
        .name("level2")
        .send()
        .await
        .unwrap();
    let ou2_id = ou2.organizational_unit().unwrap().id().unwrap().to_string();
    let ou3 = orgs
        .create_organizational_unit()
        .parent_id(&ou2_id)
        .name("level3")
        .send()
        .await
        .unwrap();
    let ou3_id = ou3.organizational_unit().unwrap().id().unwrap().to_string();

    let p_ou3 = orgs.list_parents().child_id(&ou3_id).send().await.unwrap();
    assert_eq!(p_ou3.parents().len(), 1);
    assert_eq!(p_ou3.parents()[0].id().unwrap(), ou2_id);
    assert_eq!(
        p_ou3.parents()[0].r#type().unwrap().as_str(),
        "ORGANIZATIONAL_UNIT"
    );

    let p_ou2 = orgs.list_parents().child_id(&ou2_id).send().await.unwrap();
    assert_eq!(p_ou2.parents()[0].id().unwrap(), ou1_id);
    let p_ou1 = orgs.list_parents().child_id(&ou1_id).send().await.unwrap();
    assert_eq!(p_ou1.parents()[0].id().unwrap(), root_id);
    assert_eq!(p_ou1.parents()[0].r#type().unwrap().as_str(), "ROOT");

    // Account parent walks back to root by default.
    let p_acct = orgs
        .list_parents()
        .child_id(MGMT_ACCOUNT)
        .send()
        .await
        .unwrap();
    assert_eq!(p_acct.parents()[0].id().unwrap(), root_id);
    assert_eq!(p_acct.parents()[0].r#type().unwrap().as_str(), "ROOT");
}

#[tokio::test]
async fn list_children_filters_by_type() {
    let (_server, orgs, root_id) = bootstrap().await;

    let ou_a = orgs
        .create_organizational_unit()
        .parent_id(&root_id)
        .name("a")
        .send()
        .await
        .unwrap();
    let ou_a_id = ou_a
        .organizational_unit()
        .unwrap()
        .id()
        .unwrap()
        .to_string();
    let ou_b = orgs
        .create_organizational_unit()
        .parent_id(&root_id)
        .name("b")
        .send()
        .await
        .unwrap();
    let ou_b_id = ou_b
        .organizational_unit()
        .unwrap()
        .id()
        .unwrap()
        .to_string();

    let ous_under_root = orgs
        .list_children()
        .parent_id(&root_id)
        .child_type(ChildType::OrganizationalUnit)
        .send()
        .await
        .unwrap();
    let mut ou_ids: Vec<&str> = ous_under_root
        .children()
        .iter()
        .map(|c| c.id().unwrap())
        .collect();
    ou_ids.sort();
    let mut expected = vec![ou_a_id.as_str(), ou_b_id.as_str()];
    expected.sort();
    assert_eq!(ou_ids, expected);
    assert!(ous_under_root
        .children()
        .iter()
        .all(|c| c.r#type().unwrap().as_str() == "ORGANIZATIONAL_UNIT"));

    let accts_under_root = orgs
        .list_children()
        .parent_id(&root_id)
        .child_type(ChildType::Account)
        .send()
        .await
        .unwrap();
    let acct_ids: Vec<&str> = accts_under_root
        .children()
        .iter()
        .map(|c| c.id().unwrap())
        .collect();
    assert_eq!(acct_ids, vec![MGMT_ACCOUNT]);
    assert_eq!(
        accts_under_root.children()[0].r#type().unwrap().as_str(),
        "ACCOUNT"
    );

    // Empty OU has no children of either type.
    let empty_accts = orgs
        .list_children()
        .parent_id(&ou_a_id)
        .child_type(ChildType::Account)
        .send()
        .await
        .unwrap();
    assert!(empty_accts.children().is_empty());
}

#[tokio::test]
async fn describe_effective_policy_unions_tag_policy_up_the_tree() {
    let (_server, orgs, root_id) = bootstrap().await;

    // Enable tag policies at the root so attachments are valid.
    orgs.enable_policy_type()
        .root_id(&root_id)
        .policy_type(PolicyType::TagPolicy)
        .send()
        .await
        .unwrap();

    // Build a 2-level tree: root -> ou_team, with the management account
    // moved under ou_team. Each layer attaches a different TAG_POLICY so
    // the effective policy is a union of all three statements.
    let ou_team = orgs
        .create_organizational_unit()
        .parent_id(&root_id)
        .name("team")
        .send()
        .await
        .unwrap();
    let ou_team_id = ou_team
        .organizational_unit()
        .unwrap()
        .id()
        .unwrap()
        .to_string();
    orgs.move_account()
        .account_id(MGMT_ACCOUNT)
        .source_parent_id(&root_id)
        .destination_parent_id(&ou_team_id)
        .send()
        .await
        .unwrap();

    // Tag policies have their own schema, but `DescribeEffectivePolicy`
    // walks the declared content as-is and unions any top-level
    // `Statement[]`. Each layer registers a synthetic Statement[] keyed by
    // a distinct Sid so we can verify the walker visits root, OU, and
    // account in turn.
    async fn make_layer_policy(orgs: &OrgsClient, name: &str, sid: &str) -> String {
        let body = format!(
            r#"{{"Version":"2012-10-17","Statement":[{{"Sid":"{sid}","Effect":"Allow","Action":"*","Resource":"*"}}]}}"#
        );
        let p = orgs
            .create_policy()
            .name(name)
            .description("h4 effective")
            .content(&body)
            .r#type(PolicyType::TagPolicy)
            .send()
            .await
            .unwrap();
        p.policy()
            .unwrap()
            .policy_summary()
            .unwrap()
            .id()
            .unwrap()
            .to_string()
    }

    let p_root = make_layer_policy(&orgs, "rootTag", "RootSid").await;
    let p_ou = make_layer_policy(&orgs, "ouTag", "OuSid").await;
    let p_acct = make_layer_policy(&orgs, "acctTag", "AcctSid").await;

    orgs.attach_policy()
        .policy_id(&p_root)
        .target_id(&root_id)
        .send()
        .await
        .unwrap();
    orgs.attach_policy()
        .policy_id(&p_ou)
        .target_id(&ou_team_id)
        .send()
        .await
        .unwrap();
    orgs.attach_policy()
        .policy_id(&p_acct)
        .target_id(MGMT_ACCOUNT)
        .send()
        .await
        .unwrap();

    let effective = orgs
        .describe_effective_policy()
        .policy_type(EffectivePolicyType::TagPolicy)
        .target_id(MGMT_ACCOUNT)
        .send()
        .await
        .unwrap();
    let body = effective.effective_policy().unwrap();
    assert_eq!(body.target_id().unwrap(), MGMT_ACCOUNT);
    assert_eq!(body.policy_type().unwrap().as_str(), "TAG_POLICY");
    let content = body.policy_content().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(content).unwrap();
    let stmts = parsed.get("Statement").and_then(|v| v.as_array()).unwrap();
    let sids: Vec<&str> = stmts
        .iter()
        .filter_map(|s| s.get("Sid").and_then(|v| v.as_str()))
        .collect();
    // All three layers contribute their statement to the effective policy.
    assert!(sids.contains(&"AcctSid"), "account-level statement missing");
    assert!(sids.contains(&"OuSid"), "OU-level statement missing");
    assert!(sids.contains(&"RootSid"), "root-level statement missing");
}

#[tokio::test]
async fn resource_policy_round_trip() {
    let (_server, orgs, _root_id) = bootstrap().await;

    // No resource policy initially: DescribeResourcePolicy returns
    // ResourcePolicyNotFoundException.
    let missing = orgs.describe_resource_policy().send().await;
    assert!(
        missing.is_err(),
        "DescribeResourcePolicy without prior Put should fail"
    );

    let document = r#"{"Version":"2012-10-17","Statement":[{"Sid":"AllowAll","Effect":"Allow","Principal":{"AWS":"*"},"Action":"organizations:*","Resource":"*"}]}"#;

    let put = orgs
        .put_resource_policy()
        .content(document)
        .send()
        .await
        .unwrap();
    let put_summary = put
        .resource_policy()
        .unwrap()
        .resource_policy_summary()
        .unwrap();
    assert!(put_summary.id().unwrap().starts_with("rp-"));
    assert!(put_summary.arn().unwrap().contains(":organizations::"));

    let described = orgs.describe_resource_policy().send().await.unwrap();
    let body = described.resource_policy().unwrap();
    assert_eq!(body.content().unwrap(), document);
    assert_eq!(
        body.resource_policy_summary().unwrap().id().unwrap(),
        put_summary.id().unwrap()
    );

    orgs.delete_resource_policy().send().await.unwrap();

    let after_delete = orgs.describe_resource_policy().send().await;
    assert!(
        after_delete.is_err(),
        "DescribeResourcePolicy after Delete should fail again"
    );
}

#[tokio::test]
async fn put_resource_policy_rejects_malformed_json() {
    let (_server, orgs, _root_id) = bootstrap().await;
    let err = orgs
        .put_resource_policy()
        .content("not-json{")
        .send()
        .await
        .expect_err("malformed Content should error");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("InvalidInput") || msg.to_lowercase().contains("json"),
        "expected InvalidInput-style error, got: {msg}"
    );
}
