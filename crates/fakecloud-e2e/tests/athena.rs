//! Athena service E2E.

mod helpers;

use aws_sdk_athena::types::{
    DataCatalogType, QueryExecutionContext, ResultConfiguration, Tag, WorkGroupConfiguration,
};
use helpers::TestServer;

#[tokio::test]
async fn primary_workgroup_is_seeded_on_first_call() {
    let server = TestServer::start().await;
    let athena = server.athena_client().await;
    let listed = athena.list_work_groups().send().await.expect("list");
    let names: Vec<String> = listed
        .work_groups()
        .iter()
        .map(|w| w.name().unwrap_or_default().to_owned())
        .collect();
    assert!(
        names.iter().any(|n| n == "primary"),
        "expected primary workgroup to be seeded by default, got {names:?}"
    );
}

#[tokio::test]
async fn default_data_catalog_is_seeded() {
    let server = TestServer::start().await;
    let athena = server.athena_client().await;
    let listed = athena
        .list_data_catalogs()
        .send()
        .await
        .expect("list catalogs");
    let names: Vec<String> = listed
        .data_catalogs_summary()
        .iter()
        .map(|c| c.catalog_name().unwrap_or_default().to_owned())
        .collect();
    assert!(
        names.iter().any(|n| n == "AwsDataCatalog"),
        "expected AwsDataCatalog seeded by default, got {names:?}"
    );
}

#[tokio::test]
async fn workgroup_create_get_update_delete_lifecycle() {
    let server = TestServer::start().await;
    let athena = server.athena_client().await;
    let cfg = WorkGroupConfiguration::builder()
        .enforce_work_group_configuration(true)
        .publish_cloud_watch_metrics_enabled(false)
        .build();
    athena
        .create_work_group()
        .name("e2e-wg")
        .description("e2e workgroup")
        .configuration(cfg)
        .send()
        .await
        .expect("create");

    let got = athena
        .get_work_group()
        .work_group("e2e-wg")
        .send()
        .await
        .expect("get");
    let wg = got.work_group().expect("workgroup");
    assert_eq!(wg.name(), "e2e-wg");

    athena
        .update_work_group()
        .work_group("e2e-wg")
        .description("updated")
        .send()
        .await
        .expect("update");

    athena
        .delete_work_group()
        .work_group("e2e-wg")
        .send()
        .await
        .expect("delete");

    let err = athena
        .get_work_group()
        .work_group("e2e-wg")
        .send()
        .await
        .expect_err("expected not found after delete");
    let msg = format!("{err:?}");
    assert!(msg.contains("not found"), "unexpected err: {msg}");
}

#[tokio::test]
async fn primary_workgroup_cannot_be_deleted() {
    let server = TestServer::start().await;
    let athena = server.athena_client().await;
    let err = athena
        .delete_work_group()
        .work_group("primary")
        .send()
        .await
        .expect_err("primary workgroup should not be deletable");
    let msg = format!("{err:?}");
    assert!(msg.contains("primary"), "unexpected err: {msg}");
}

#[tokio::test]
async fn workgroup_with_prepared_statements_blocks_non_recursive_delete() {
    let server = TestServer::start().await;
    let athena = server.athena_client().await;
    athena
        .create_work_group()
        .name("wg-with-ps")
        .send()
        .await
        .expect("create wg");
    athena
        .create_prepared_statement()
        .statement_name("ps1")
        .work_group("wg-with-ps")
        .query_statement("SELECT ?")
        .send()
        .await
        .expect("create prepared statement");
    let err = athena
        .delete_work_group()
        .work_group("wg-with-ps")
        .send()
        .await
        .expect_err("non-recursive delete should refuse non-empty workgroup");
    let msg = format!("{err:?}");
    assert!(msg.contains("still has resources"), "unexpected err: {msg}");
    athena
        .delete_work_group()
        .work_group("wg-with-ps")
        .recursive_delete_option(true)
        .send()
        .await
        .expect("recursive delete should succeed");
}

#[tokio::test]
async fn data_catalog_create_get_delete_lifecycle() {
    let server = TestServer::start().await;
    let athena = server.athena_client().await;
    athena
        .create_data_catalog()
        .name("custom_cat")
        .r#type(DataCatalogType::Lambda)
        .description("custom lambda catalog")
        .send()
        .await
        .expect("create");

    let got = athena
        .get_data_catalog()
        .name("custom_cat")
        .send()
        .await
        .expect("get");
    let cat = got.data_catalog().expect("catalog");
    assert_eq!(cat.name(), "custom_cat");
    assert_eq!(cat.r#type(), &DataCatalogType::Lambda);

    athena
        .delete_data_catalog()
        .name("custom_cat")
        .send()
        .await
        .expect("delete");
}

#[tokio::test]
async fn aws_data_catalog_cannot_be_deleted() {
    let server = TestServer::start().await;
    let athena = server.athena_client().await;
    let err = athena
        .delete_data_catalog()
        .name("AwsDataCatalog")
        .send()
        .await
        .expect_err("AwsDataCatalog should not be deletable");
    let msg = format!("{err:?}");
    assert!(msg.contains("AwsDataCatalog"), "unexpected err: {msg}");
}

#[tokio::test]
async fn start_query_execution_returns_succeeded_result() {
    let server = TestServer::start().await;
    let athena = server.athena_client().await;
    let started = athena
        .start_query_execution()
        .query_string("SELECT 1")
        .work_group("primary")
        .query_execution_context(QueryExecutionContext::builder().database("default").build())
        .result_configuration(
            ResultConfiguration::builder()
                .output_location("s3://example-bucket/results/")
                .build(),
        )
        .send()
        .await
        .expect("start");
    let qid = started.query_execution_id().expect("qid").to_owned();

    let got = athena
        .get_query_execution()
        .query_execution_id(&qid)
        .send()
        .await
        .expect("get");
    let qe = got.query_execution().expect("qe");
    let state = qe.status().and_then(|s| s.state()).expect("status state");
    assert_eq!(state.as_str(), "SUCCEEDED");

    let results = athena
        .get_query_results()
        .query_execution_id(&qid)
        .send()
        .await
        .expect("results");
    let rs = results.result_set().expect("result set");
    assert!(!rs.rows().is_empty(), "expected at least one row");
}

#[tokio::test]
async fn named_query_create_get_list_delete() {
    let server = TestServer::start().await;
    let athena = server.athena_client().await;
    let id = athena
        .create_named_query()
        .name("greet")
        .description("hello world query")
        .database("default")
        .query_string("SELECT 'hello'")
        .work_group("primary")
        .send()
        .await
        .expect("create")
        .named_query_id()
        .expect("id")
        .to_owned();

    let got = athena
        .get_named_query()
        .named_query_id(&id)
        .send()
        .await
        .expect("get");
    let nq = got.named_query().expect("nq");
    assert_eq!(nq.name(), "greet");

    let listed = athena
        .list_named_queries()
        .work_group("primary")
        .send()
        .await
        .expect("list");
    assert!(listed.named_query_ids().iter().any(|i| i == &id));

    athena
        .delete_named_query()
        .named_query_id(&id)
        .send()
        .await
        .expect("delete");
}

#[tokio::test]
async fn prepared_statement_create_get_list_delete() {
    let server = TestServer::start().await;
    let athena = server.athena_client().await;
    athena
        .create_prepared_statement()
        .statement_name("p1")
        .work_group("primary")
        .query_statement("SELECT ?")
        .send()
        .await
        .expect("create");

    let got = athena
        .get_prepared_statement()
        .statement_name("p1")
        .work_group("primary")
        .send()
        .await
        .expect("get");
    let ps = got.prepared_statement().expect("ps");
    assert_eq!(ps.statement_name(), Some("p1"));

    let listed = athena
        .list_prepared_statements()
        .work_group("primary")
        .send()
        .await
        .expect("list");
    assert!(listed
        .prepared_statements()
        .iter()
        .any(|p| p.statement_name() == Some("p1")));

    athena
        .delete_prepared_statement()
        .statement_name("p1")
        .work_group("primary")
        .send()
        .await
        .expect("delete");
}

#[tokio::test]
async fn tag_lifecycle_on_workgroup() {
    let server = TestServer::start().await;
    let athena = server.athena_client().await;
    athena
        .create_work_group()
        .name("tagged")
        .send()
        .await
        .expect("create");
    let arn = "arn:aws:athena:us-east-1:123456789012:workgroup/tagged";
    athena
        .tag_resource()
        .resource_arn(arn)
        .tags(Tag::builder().key("env").value("test").build())
        .send()
        .await
        .expect("tag");
    let listed = athena
        .list_tags_for_resource()
        .resource_arn(arn)
        .send()
        .await
        .expect("list tags");
    let tags = listed.tags();
    assert!(tags
        .iter()
        .any(|t| t.key() == Some("env") && t.value() == Some("test")));

    athena
        .untag_resource()
        .resource_arn(arn)
        .tag_keys("env")
        .send()
        .await
        .expect("untag");
    let listed = athena
        .list_tags_for_resource()
        .resource_arn(arn)
        .send()
        .await
        .expect("list tags");
    assert!(listed.tags().is_empty());
}

#[tokio::test]
async fn list_engine_versions_returns_known_versions() {
    let server = TestServer::start().await;
    let athena = server.athena_client().await;
    let listed = athena
        .list_engine_versions()
        .send()
        .await
        .expect("list versions");
    let names: Vec<String> = listed
        .engine_versions()
        .iter()
        .filter_map(|v| v.effective_engine_version().map(str::to_owned))
        .collect();
    assert!(
        names.iter().any(|n| n.contains("Athena engine")),
        "expected at least one Athena engine version, got {names:?}"
    );
}
