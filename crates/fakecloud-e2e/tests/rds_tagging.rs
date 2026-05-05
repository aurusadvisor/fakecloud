//! End-to-end coverage for RDS tagging multiplexed across every
//! supported resource type (M4 batch).
//!
//! `AddTagsToResource`, `ListTagsForResource`, and
//! `RemoveTagsFromResource` accept any RDS resource ARN and dispatch
//! on the resource-type segment (`db`, `snapshot`, `cluster`,
//! `cluster-snapshot`, `pg`, `cluster-pg`, `og`, `subgrp`, `secgrp`,
//! `db-proxy`, `es`). These tests exercise the dispatch over the
//! types that are easy to spin up via the SDK without booting a real
//! engine container, plus the unknown-resource-type error path.

mod helpers;

use aws_sdk_rds::types::{Tag, UserAuthConfig};
use helpers::TestServer;

async fn add_tag(client: &aws_sdk_rds::Client, arn: &str, key: &str, value: &str) {
    client
        .add_tags_to_resource()
        .resource_name(arn)
        .tags(Tag::builder().key(key).value(value).build())
        .send()
        .await
        .unwrap_or_else(|e| panic!("AddTagsToResource failed for {arn}: {e}"));
}

async fn list_tag_keys(client: &aws_sdk_rds::Client, arn: &str) -> Vec<String> {
    let resp = client
        .list_tags_for_resource()
        .resource_name(arn)
        .send()
        .await
        .unwrap_or_else(|e| panic!("ListTagsForResource failed for {arn}: {e}"));
    resp.tag_list()
        .iter()
        .filter_map(|t| t.key().map(str::to_string))
        .collect()
}

async fn remove_tag(client: &aws_sdk_rds::Client, arn: &str, key: &str) {
    client
        .remove_tags_from_resource()
        .resource_name(arn)
        .tag_keys(key)
        .send()
        .await
        .unwrap_or_else(|e| panic!("RemoveTagsFromResource failed for {arn}: {e}"));
}

async fn assert_tag_round_trip(client: &aws_sdk_rds::Client, arn: &str, label: &str) {
    add_tag(client, arn, "env", "prod").await;
    add_tag(client, arn, "team", "platform").await;

    let keys = list_tag_keys(client, arn).await;
    assert!(
        keys.contains(&"env".to_string()) && keys.contains(&"team".to_string()),
        "[{label}] expected env+team after AddTags, got {keys:?}"
    );

    remove_tag(client, arn, "env").await;

    let keys = list_tag_keys(client, arn).await;
    assert!(
        !keys.contains(&"env".to_string()) && keys.contains(&"team".to_string()),
        "[{label}] expected env removed and team present after RemoveTags, got {keys:?}"
    );
}

#[tokio::test]
async fn rds_tagging_db_parameter_group() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    let arn = client
        .create_db_parameter_group()
        .db_parameter_group_name("tag-pg")
        .db_parameter_group_family("postgres16")
        .description("tag dispatch test")
        .send()
        .await
        .unwrap()
        .db_parameter_group()
        .and_then(|g| g.db_parameter_group_arn())
        .map(str::to_string)
        .expect("parameter group arn");
    assert!(arn.contains(":pg:"), "expected pg ARN segment, got {arn}");

    assert_tag_round_trip(&client, &arn, "pg").await;
}

#[tokio::test]
async fn rds_tagging_db_subnet_group() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    let arn = client
        .create_db_subnet_group()
        .db_subnet_group_name("tag-subnet")
        .db_subnet_group_description("tag dispatch test")
        .subnet_ids("subnet-aaa")
        .subnet_ids("subnet-bbb")
        .send()
        .await
        .unwrap()
        .db_subnet_group()
        .and_then(|g| g.db_subnet_group_arn())
        .map(str::to_string)
        .expect("subnet group arn");
    assert!(
        arn.contains(":subgrp:"),
        "expected subgrp ARN segment, got {arn}"
    );

    assert_tag_round_trip(&client, &arn, "subgrp").await;
}

#[tokio::test]
async fn rds_tagging_db_cluster() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    let arn = client
        .create_db_cluster()
        .db_cluster_identifier("tag-cluster")
        .engine("aurora-postgresql")
        .send()
        .await
        .unwrap()
        .db_cluster()
        .and_then(|c| c.db_cluster_arn())
        .map(str::to_string)
        .expect("cluster arn");
    assert!(
        arn.contains(":cluster:"),
        "expected cluster ARN segment, got {arn}"
    );

    assert_tag_round_trip(&client, &arn, "cluster").await;
}

#[tokio::test]
async fn rds_tagging_db_cluster_snapshot() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    client
        .create_db_cluster()
        .db_cluster_identifier("tag-cluster-for-snap")
        .engine("aurora-postgresql")
        .send()
        .await
        .unwrap();

    let arn = client
        .create_db_cluster_snapshot()
        .db_cluster_identifier("tag-cluster-for-snap")
        .db_cluster_snapshot_identifier("tag-csnap")
        .send()
        .await
        .unwrap()
        .db_cluster_snapshot()
        .and_then(|s| s.db_cluster_snapshot_arn())
        .map(str::to_string)
        .expect("cluster snapshot arn");
    assert!(
        arn.contains(":cluster-snapshot:"),
        "expected cluster-snapshot ARN segment, got {arn}"
    );

    assert_tag_round_trip(&client, &arn, "cluster-snapshot").await;
}

#[tokio::test]
async fn rds_tagging_db_cluster_parameter_group() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    let arn = client
        .create_db_cluster_parameter_group()
        .db_cluster_parameter_group_name("tag-cpg")
        .db_parameter_group_family("aurora-postgresql15")
        .description("tag dispatch test")
        .send()
        .await
        .unwrap()
        .db_cluster_parameter_group()
        .and_then(|g| g.db_cluster_parameter_group_arn())
        .map(str::to_string)
        .expect("cluster parameter group arn");
    assert!(
        arn.contains(":cluster-pg:"),
        "expected cluster-pg ARN segment, got {arn}"
    );

    assert_tag_round_trip(&client, &arn, "cluster-pg").await;
}

#[tokio::test]
async fn rds_tagging_option_group() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    // CreateOptionGroup currently emits a flat XML body without an
    // <OptionGroup> wrapper, so the SDK can't extract the arn from the
    // response; we construct it deterministically from the testkit's
    // hardcoded account/region. The dispatcher itself is what we're
    // testing, not the response shape.
    client
        .create_option_group()
        .option_group_name("tag-og")
        .engine_name("mysql")
        .major_engine_version("8.0")
        .option_group_description("tag dispatch test")
        .send()
        .await
        .unwrap();

    let arn = "arn:aws:rds:us-east-1:123456789012:og:tag-og";
    assert_tag_round_trip(&client, arn, "og").await;
}

#[tokio::test]
async fn rds_tagging_db_proxy() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    // CreateDBProxy emits a flat XML body without a <DBProxy> wrapper,
    // so we construct the ARN deterministically rather than parsing it
    // out of the SDK response. The dispatcher under test resolves the
    // ARN to the `proxies` extras bucket regardless.
    client
        .create_db_proxy()
        .db_proxy_name("tag-proxy")
        .engine_family(aws_sdk_rds::types::EngineFamily::Postgresql)
        .auth(
            UserAuthConfig::builder()
                .auth_scheme(aws_sdk_rds::types::AuthScheme::Secrets)
                .secret_arn("arn:aws:secretsmanager:us-east-1:123:secret:dummy")
                .build(),
        )
        .role_arn("arn:aws:iam::123:role/dummy")
        .vpc_subnet_ids("subnet-aaa")
        .vpc_subnet_ids("subnet-bbb")
        .send()
        .await
        .unwrap();

    let arn = "arn:aws:rds:us-east-1:123456789012:db-proxy:tag-proxy";
    assert_tag_round_trip(&client, arn, "db-proxy").await;
}

#[tokio::test]
async fn rds_tagging_event_subscription() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    // Same shape gap as option_group / db-proxy — construct the ARN
    // ourselves so the test exercises the `es` dispatch arm.
    client
        .create_event_subscription()
        .subscription_name("tag-es")
        .sns_topic_arn("arn:aws:sns:us-east-1:123456789012:dummy")
        .source_type("db-instance")
        .send()
        .await
        .unwrap();

    let arn = "arn:aws:rds:us-east-1:123456789012:es:tag-es";
    assert_tag_round_trip(&client, arn, "es").await;
}

// `db` ARN coverage already lives in `rds.rs::rds_tag_roundtrip`,
// which exercises the same dispatcher arm against a real DBInstance.
// Replicating it here would just double the Docker engine startup
// cost without adding signal.

#[tokio::test]
async fn rds_tagging_unknown_arn_segment_errors() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    // Unknown resource-type segment must reject as InvalidParameterValue
    // (per AWS), not surface as a per-type NotFound, so callers can
    // distinguish "you typed the ARN wrong" from "the resource is gone".
    let err = client
        .list_tags_for_resource()
        .resource_name("arn:aws:rds:us-east-1:000000000000:bogus:nope")
        .send()
        .await
        .expect_err("unknown segment should error");
    assert_eq!(
        err.into_service_error().meta().code(),
        Some("InvalidParameterValue"),
        "unknown ARN segment should map to InvalidParameterValue"
    );
}

#[tokio::test]
async fn rds_tagging_missing_resource_returns_typed_not_found() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    // Well-formed ARN, recognised segment, missing instance: the typed
    // NotFound is what AWS clients (and most IaC tooling) expect.
    let err = client
        .list_tags_for_resource()
        .resource_name("arn:aws:rds:us-east-1:000000000000:db:does-not-exist")
        .send()
        .await
        .expect_err("missing db should error");
    assert_eq!(
        err.into_service_error().meta().code(),
        Some("DBInstanceNotFound"),
        "missing DB should map to DBInstanceNotFound"
    );
}
