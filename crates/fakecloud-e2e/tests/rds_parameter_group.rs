//! End-to-end coverage for RDS parameter group editing/inspection
//! shipped in the M2 batch:
//!
//! * `ModifyDBParameterGroup` parses `Parameters.member.N.*` and persists
//!   the values onto the parameter group.
//! * `DescribeDBParameters` reports stored values as `Source=user` and
//!   the engine-default seed for the family as `Source=engine-default`.
//! * `ModifyDBClusterParameterGroup` /
//!   `DescribeDBClusterParameters` are symmetric for cluster parameter
//!   groups.

mod helpers;

use aws_sdk_rds::types::Parameter;
use helpers::TestServer;

#[tokio::test]
async fn modify_db_parameter_group_persists_user_values_visible_via_describe() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    let group = "pg-m2-user";
    client
        .create_db_parameter_group()
        .db_parameter_group_name(group)
        .db_parameter_group_family("postgres16")
        .description("user param round-trip")
        .send()
        .await
        .unwrap();

    client
        .modify_db_parameter_group()
        .db_parameter_group_name(group)
        .parameters(
            Parameter::builder()
                .parameter_name("max_connections")
                .parameter_value("250")
                .apply_method(aws_sdk_rds::types::ApplyMethod::Immediate)
                .build(),
        )
        .parameters(
            Parameter::builder()
                .parameter_name("work_mem")
                .parameter_value("8192")
                .apply_method(aws_sdk_rds::types::ApplyMethod::PendingReboot)
                .build(),
        )
        .send()
        .await
        .unwrap();

    let user_only = client
        .describe_db_parameters()
        .db_parameter_group_name(group)
        .source("user")
        .send()
        .await
        .unwrap();

    let params = user_only.parameters();
    let max_connections = params
        .iter()
        .find(|p| p.parameter_name() == Some("max_connections"))
        .expect("max_connections present in user source");
    assert_eq!(max_connections.parameter_value(), Some("250"));
    assert_eq!(max_connections.source(), Some("user"));

    let work_mem = params
        .iter()
        .find(|p| p.parameter_name() == Some("work_mem"))
        .expect("work_mem present in user source");
    assert_eq!(work_mem.parameter_value(), Some("8192"));
    assert_eq!(work_mem.source(), Some("user"));

    // The engine-default source should not contain user-only knobs we did
    // not seed in the engine defaults table, but should still surface
    // baseline parameters (e.g. `shared_buffers` for postgres16).
    let engine_defaults = client
        .describe_db_parameters()
        .db_parameter_group_name(group)
        .source("engine-default")
        .send()
        .await
        .unwrap();

    let engine_params = engine_defaults.parameters();
    assert!(engine_params
        .iter()
        .all(|p| p.source() == Some("engine-default")));
    assert!(engine_params
        .iter()
        .any(|p| p.parameter_name() == Some("shared_buffers")));
    // `max_connections` is shadowed by the user override, so it must not
    // surface under the `engine-default` source.
    assert!(engine_params
        .iter()
        .all(|p| p.parameter_name() != Some("max_connections")));
}

#[tokio::test]
async fn describe_db_parameters_engine_default_for_fresh_group_lists_seeded_params() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    let group = "pg-m2-defaults";
    client
        .create_db_parameter_group()
        .db_parameter_group_name(group)
        .db_parameter_group_family("postgres16")
        .description("engine defaults only")
        .send()
        .await
        .unwrap();

    let response = client
        .describe_db_parameters()
        .db_parameter_group_name(group)
        .source("engine-default")
        .send()
        .await
        .unwrap();

    let names: Vec<&str> = response
        .parameters()
        .iter()
        .filter_map(|p| p.parameter_name())
        .collect();
    assert!(names.contains(&"max_connections"));
    assert!(names.contains(&"shared_buffers"));
    assert!(names.contains(&"work_mem"));
}

#[tokio::test]
async fn describe_db_parameters_no_filter_returns_user_and_engine_defaults() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    let group = "pg-m2-merged";
    client
        .create_db_parameter_group()
        .db_parameter_group_name(group)
        .db_parameter_group_family("mysql8.0")
        .description("merge user + defaults")
        .send()
        .await
        .unwrap();

    client
        .modify_db_parameter_group()
        .db_parameter_group_name(group)
        .parameters(
            Parameter::builder()
                .parameter_name("max_connections")
                .parameter_value("500")
                .build(),
        )
        .send()
        .await
        .unwrap();

    let response = client
        .describe_db_parameters()
        .db_parameter_group_name(group)
        .send()
        .await
        .unwrap();

    let max_connections_entries: Vec<&Parameter> = response
        .parameters()
        .iter()
        .filter(|p| p.parameter_name() == Some("max_connections"))
        .collect();
    assert_eq!(
        max_connections_entries.len(),
        1,
        "max_connections must appear exactly once when user shadows default"
    );
    assert_eq!(max_connections_entries[0].source(), Some("user"));
    assert_eq!(max_connections_entries[0].parameter_value(), Some("500"));

    // Other engine defaults remain.
    let names: Vec<&str> = response
        .parameters()
        .iter()
        .filter_map(|p| p.parameter_name())
        .collect();
    assert!(names.contains(&"innodb_buffer_pool_size"));
}

#[tokio::test]
async fn modify_db_cluster_parameter_group_round_trips_through_describe() {
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    let group = "cpg-m2";
    client
        .create_db_cluster_parameter_group()
        .db_cluster_parameter_group_name(group)
        .db_parameter_group_family("aurora-postgresql15")
        .description("cluster param round-trip")
        .send()
        .await
        .unwrap();

    client
        .modify_db_cluster_parameter_group()
        .db_cluster_parameter_group_name(group)
        .parameters(
            Parameter::builder()
                .parameter_name("max_connections")
                .parameter_value("750")
                .apply_method(aws_sdk_rds::types::ApplyMethod::Immediate)
                .build(),
        )
        .parameters(
            Parameter::builder()
                .parameter_name("custom_cluster_knob")
                .parameter_value("on")
                .build(),
        )
        .send()
        .await
        .unwrap();

    let user_only = client
        .describe_db_cluster_parameters()
        .db_cluster_parameter_group_name(group)
        .source("user")
        .send()
        .await
        .unwrap();

    let user_params = user_only.parameters();
    assert!(user_params.iter().all(|p| p.source() == Some("user")));
    let max_connections = user_params
        .iter()
        .find(|p| p.parameter_name() == Some("max_connections"))
        .expect("max_connections persisted");
    assert_eq!(max_connections.parameter_value(), Some("750"));
    assert!(user_params
        .iter()
        .any(|p| p.parameter_name() == Some("custom_cluster_knob")));

    let defaults = client
        .describe_db_cluster_parameters()
        .db_cluster_parameter_group_name(group)
        .source("engine-default")
        .send()
        .await
        .unwrap();
    let default_names: Vec<&str> = defaults
        .parameters()
        .iter()
        .filter_map(|p| p.parameter_name())
        .collect();
    // aurora-postgresql15 inherits the postgres engine defaults seed.
    assert!(default_names.contains(&"shared_buffers"));
    // User-only knob never surfaces under engine-default.
    assert!(!default_names.contains(&"custom_cluster_knob"));
    // Shadowed default suppressed from engine-default view.
    assert!(!default_names.contains(&"max_connections"));

    let merged = client
        .describe_db_cluster_parameters()
        .db_cluster_parameter_group_name(group)
        .send()
        .await
        .unwrap();
    let merged_names: Vec<&str> = merged
        .parameters()
        .iter()
        .filter_map(|p| p.parameter_name())
        .collect();
    assert!(merged_names.contains(&"max_connections"));
    assert!(merged_names.contains(&"custom_cluster_knob"));
    assert!(merged_names.contains(&"shared_buffers"));
}
