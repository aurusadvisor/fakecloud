//! CloudWatch Logs introspection endpoints (I9): delivery configuration
//! and field indexes. Exercises the AWS-shaped ops + the
//! `/_fakecloud/logs/...` admin endpoints in the same flow.

mod helpers;

use helpers::TestServer;

#[tokio::test]
async fn logs_delivery_config_introspection_returns_create_delivery_state() {
    let server = TestServer::start().await;
    let logs = server.logs_client().await;
    let s3 = server.s3_client().await;

    s3.create_bucket()
        .bucket("intro-delivery-cfg")
        .send()
        .await
        .unwrap();

    logs.create_log_group()
        .log_group_name("/intro/delivery-cfg")
        .send()
        .await
        .unwrap();

    let groups = logs
        .describe_log_groups()
        .log_group_name_prefix("/intro/delivery-cfg")
        .send()
        .await
        .unwrap();
    let group_arn = groups.log_groups()[0].arn().unwrap().to_string();

    logs.put_delivery_source()
        .name("intro-src")
        .resource_arn(&group_arn)
        .log_type("APPLICATION_LOGS")
        .send()
        .await
        .unwrap();

    let dest = logs
        .put_delivery_destination()
        .name("intro-dest")
        .delivery_destination_configuration(
            aws_sdk_cloudwatchlogs::types::DeliveryDestinationConfiguration::builder()
                .destination_resource_arn("arn:aws:s3:::intro-delivery-cfg")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let dest_arn = dest
        .delivery_destination()
        .unwrap()
        .arn()
        .unwrap()
        .to_string();

    logs.create_delivery()
        .delivery_source_name("intro-src")
        .delivery_destination_arn(&dest_arn)
        .record_fields("timestamp")
        .record_fields("message")
        .field_delimiter("|")
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = reqwest::get(format!(
        "{}/_fakecloud/logs/delivery-config",
        server.endpoint()
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    let configurations = body["configurations"].as_array().unwrap();
    assert_eq!(
        configurations.len(),
        1,
        "expected 1 delivery configuration, got {configurations:?}"
    );
    let cfg = &configurations[0];
    assert_eq!(cfg["deliverySourceName"], "intro-src");
    assert_eq!(cfg["deliveryDestinationArn"], dest_arn);
    assert_eq!(cfg["logType"], "APPLICATION_LOGS");
    assert_eq!(cfg["fieldDelimiter"], "|");
    let fields: Vec<&str> = cfg["recordFields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(fields, vec!["timestamp", "message"]);
    assert!(cfg["createdAt"].as_i64().unwrap() > 0);
    assert_eq!(cfg["id"], cfg["name"]);
}

#[tokio::test]
async fn logs_field_indexes_introspection_returns_parsed_index_policy_fields() {
    let server = TestServer::start().await;
    let logs = server.logs_client().await;

    logs.create_log_group()
        .log_group_name("intro-field-indexes")
        .send()
        .await
        .unwrap();

    let policy_doc = r#"{"Fields":["@timestamp","requestId","userId"]}"#;
    logs.put_index_policy()
        .log_group_identifier("intro-field-indexes")
        .policy_document(policy_doc)
        .send()
        .await
        .unwrap();

    let body: serde_json::Value = reqwest::get(format!(
        "{}/_fakecloud/logs/field-indexes/intro-field-indexes",
        server.endpoint(),
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    assert_eq!(body["logGroupName"], "intro-field-indexes");
    let indexes = body["indexes"].as_array().unwrap();
    assert_eq!(indexes.len(), 1);
    let fields: Vec<&str> = indexes[0]["fields"]
        .as_array()
        .unwrap()
        .iter()
        .map(|v| v.as_str().unwrap())
        .collect();
    assert_eq!(fields, vec!["@timestamp", "requestId", "userId"]);
    assert!(indexes[0]["createdAt"].as_i64().unwrap() > 0);
    assert_eq!(indexes[0]["createdAt"], indexes[0]["lastUsedAt"]);
}

#[tokio::test]
async fn logs_field_indexes_unknown_group_returns_404() {
    let server = TestServer::start().await;
    let resp = reqwest::get(format!(
        "{}/_fakecloud/logs/field-indexes/does-not-exist",
        server.endpoint(),
    ))
    .await
    .unwrap();
    assert_eq!(resp.status().as_u16(), 404);
}
