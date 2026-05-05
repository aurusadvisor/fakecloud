//! End-to-end coverage for `DescribeEvents` reading from the buffer
//! that lifecycle ops populate via `emit_event` (M3 batch).
//!
//! Exercises:
//!
//! * Cluster + parameter-group lifecycle ops (Create/Modify/Delete)
//!   land in the events buffer with the expected RDS messages.
//! * `SourceIdentifier` filter narrows to a single resource.
//! * `SourceType` filter respects the kebab-case AWS spec values
//!   (`db-cluster`, `db-parameter-group`, ...).
//! * `MaxRecords` + `Marker` paginate the result set deterministically.
//!
//! The cluster + parameter-group paths take the no-runtime branch, so
//! these tests run on every shard without Docker.

mod helpers;

use aws_sdk_rds::types::{ApplyMethod, Parameter};
use helpers::TestServer;

#[tokio::test]
async fn describe_events_returns_create_db_cluster_event() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    client
        .create_db_cluster()
        .db_cluster_identifier("orders-cluster")
        .engine("aurora-postgresql")
        .send()
        .await
        .unwrap();

    let response = client.describe_events().send().await.unwrap();
    let events = response.events();
    assert!(
        events
            .iter()
            .any(|e| e.source_identifier() == Some("orders-cluster")
                && e.source_type().is_some_and(|t| t.as_str() == "db-cluster")
                && e.message() == Some("DB cluster created")),
        "expected DB cluster created event, got {events:#?}"
    );
}

#[tokio::test]
async fn describe_events_filter_by_source_identifier_narrows_to_single_resource() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    for id in ["cluster-a", "cluster-b", "cluster-c"] {
        client
            .create_db_cluster()
            .db_cluster_identifier(id)
            .engine("aurora-postgresql")
            .send()
            .await
            .unwrap();
    }

    let response = client
        .describe_events()
        .source_identifier("cluster-b")
        .send()
        .await
        .unwrap();

    let events = response.events();
    assert!(!events.is_empty(), "expected at least one event");
    for e in events {
        assert_eq!(e.source_identifier(), Some("cluster-b"));
    }
}

#[tokio::test]
async fn describe_events_filter_by_source_type_only_returns_matching_resources() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    client
        .create_db_cluster()
        .db_cluster_identifier("the-cluster")
        .engine("aurora-postgresql")
        .send()
        .await
        .unwrap();

    client
        .create_db_parameter_group()
        .db_parameter_group_name("the-pg")
        .db_parameter_group_family("postgres16")
        .description("source type filter check")
        .send()
        .await
        .unwrap();

    // db-cluster only
    let cluster_response = client
        .describe_events()
        .source_type(aws_sdk_rds::types::SourceType::DbCluster)
        .send()
        .await
        .unwrap();
    let cluster_events = cluster_response.events();
    assert!(!cluster_events.is_empty());
    for e in cluster_events {
        assert_eq!(e.source_type().map(|t| t.as_str()), Some("db-cluster"));
    }

    // db-parameter-group only
    let pg_response = client
        .describe_events()
        .source_type(aws_sdk_rds::types::SourceType::DbParameterGroup)
        .send()
        .await
        .unwrap();
    let pg_events = pg_response.events();
    assert!(pg_events
        .iter()
        .any(|e| e.source_identifier() == Some("the-pg")));
    for e in pg_events {
        assert_eq!(
            e.source_type().map(|t| t.as_str()),
            Some("db-parameter-group")
        );
    }
}

#[tokio::test]
async fn describe_events_modify_db_parameter_group_records_event() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    let group = "pg-modify-event";
    client
        .create_db_parameter_group()
        .db_parameter_group_name(group)
        .db_parameter_group_family("postgres16")
        .description("modify event check")
        .send()
        .await
        .unwrap();

    client
        .modify_db_parameter_group()
        .db_parameter_group_name(group)
        .parameters(
            Parameter::builder()
                .parameter_name("max_connections")
                .parameter_value("400")
                .apply_method(ApplyMethod::Immediate)
                .build(),
        )
        .send()
        .await
        .unwrap();

    let response = client
        .describe_events()
        .source_identifier(group)
        .send()
        .await
        .unwrap();
    let events = response.events();
    assert!(events
        .iter()
        .any(|e| e.message() == Some("DB parameter group created")));
    assert!(events
        .iter()
        .any(|e| e.message() == Some("DB parameter group modified")));
}

#[tokio::test]
async fn describe_events_paginates_with_max_records_and_marker() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    // Create several clusters so we have at least 5 events to paginate.
    for id in ["pg-c1", "pg-c2", "pg-c3", "pg-c4", "pg-c5"] {
        client
            .create_db_cluster()
            .db_cluster_identifier(id)
            .engine("aurora-postgresql")
            .send()
            .await
            .unwrap();
    }

    let first = client
        .describe_events()
        .source_type(aws_sdk_rds::types::SourceType::DbCluster)
        .max_records(2)
        .send()
        .await
        .unwrap();
    let first_events = first.events();
    assert_eq!(first_events.len(), 2);
    let marker = first
        .marker()
        .expect("first page should yield a marker when more events remain")
        .to_string();

    let second = client
        .describe_events()
        .source_type(aws_sdk_rds::types::SourceType::DbCluster)
        .max_records(2)
        .marker(marker)
        .send()
        .await
        .unwrap();
    let second_events = second.events();
    assert_eq!(second_events.len(), 2);

    // The second page must not duplicate the first page's events.
    let first_ids: Vec<_> = first_events
        .iter()
        .map(|e| e.source_identifier().unwrap_or_default())
        .collect();
    for e in second_events {
        let id = e.source_identifier().unwrap_or_default();
        assert!(!first_ids.contains(&id), "second page repeated id {id}");
    }
}

#[tokio::test]
async fn describe_events_rejects_invalid_source_type() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    // The Smithy enum on the SDK side filters obvious typos, so push an
    // unknown variant by hand to confirm the server validates strict
    // AWS-spec membership.
    let err = client
        .describe_events()
        .source_type(aws_sdk_rds::types::SourceType::from("not-a-real-type"))
        .send()
        .await
        .expect_err("server should reject unknown SourceType");
    let msg = format!("{err:?}");
    assert!(
        msg.contains("InvalidParameterValue") || msg.contains("not a valid value"),
        "unexpected error: {msg}"
    );
}
