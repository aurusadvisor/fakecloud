//! End-to-end tests for the Aurora-compatible MySQL/MariaDB
//! `mysql.lambda_async` / `mysql.lambda_sync` stored procedures
//! provided by the prebuilt `fakecloud-mysql` and `fakecloud-mariadb`
//! images. Each test creates a Lambda, spins up the engine container,
//! and exercises both the sync and async invocation paths through the
//! libcurl-backed UDF + bridge endpoint round trip.
//!
//! Gated behind `FAKECLOUD_E2E_HEAVY_DBS=1` (same pattern as
//! `rds_heavy_engines.rs`): on a fresh PR build the prebuilt
//! `fakecloud-mysql` / `fakecloud-mariadb` images are not yet on
//! ghcr.io for the in-flight version, so the runtime falls back to a
//! local `docker build` that pushes the per-job E2E budget over
//! 30 minutes. CI lanes that bake the heavy images opt in via the
//! variable; the regular E2E lane skips.

mod helpers;

use std::io::Write;

use aws_sdk_lambda::primitives::Blob;
use helpers::TestServer;
use mysql_async::prelude::*;

fn heavy_dbs_opted_in() -> bool {
    std::env::var("FAKECLOUD_E2E_HEAVY_DBS")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn make_echo_zip() -> Vec<u8> {
    let buf = Vec::new();
    let cursor = std::io::Cursor::new(buf);
    let mut writer = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default();
    writer.start_file("index.py", options).unwrap();
    writer
        .write_all(b"def handler(event, context):\n    return event\n")
        .unwrap();
    let cursor = writer.finish().unwrap();
    cursor.into_inner()
}

async fn run_lambda_round_trip(engine: &str, engine_version: &str, db_id: &str) {
    let server = TestServer::start_with_env(&[("FAKECLOUD_REBUILD_POSTGRES_IMAGE", "1")]).await;
    let lambda = server.lambda_client().await;
    let rds = server.rds_client().await;

    lambda
        .create_function()
        .function_name("echo")
        .runtime(aws_sdk_lambda::types::Runtime::Python312)
        .role("arn:aws:iam::000000000000:role/test-role")
        .handler("index.handler")
        .code(
            aws_sdk_lambda::types::FunctionCode::builder()
                .zip_file(Blob::new(make_echo_zip()))
                .build(),
        )
        .send()
        .await
        .expect("create echo lambda");

    rds.create_db_instance()
        .db_instance_identifier(db_id)
        .allocated_storage(20)
        .db_instance_class("db.t3.micro")
        .engine(engine)
        .engine_version(engine_version)
        .master_username("admin")
        .master_user_password("secret123")
        .db_name("appdb")
        .send()
        .await
        .expect("create db instance");

    let instance = helpers::wait_for_db_available(&rds, db_id, 360).await;
    let endpoint = instance.endpoint().expect("endpoint");
    let host = endpoint.address().expect("address").to_string();
    let port = endpoint.port().expect("port") as u16;

    let opts = mysql_async::OptsBuilder::default()
        .ip_or_hostname(host)
        .tcp_port(port)
        .user(Some("admin"))
        .pass(Some("secret123"))
        .db_name(Some("appdb"));
    let mut conn = mysql_async::Conn::new(opts)
        .await
        .expect("connect to mysql");

    // Sync invoke: payload should round-trip through the bridge.
    let row: Option<String> = conn
        .query_first("SELECT mysql.lambda_sync('echo', '{\"hello\":\"world\"}') AS payload")
        .await
        .expect("invoke lambda_sync");
    let payload_json = row.expect("payload");
    let parsed: serde_json::Value = serde_json::from_str(&payload_json).unwrap();
    assert_eq!(parsed, serde_json::json!({"hello": "world"}));

    // Async invoke: returns nothing; assert no error.
    conn.query_drop("CALL mysql.lambda_async('echo', '{\"async\":true}')")
        .await
        .expect("invoke lambda_async");

    let _ = conn.disconnect().await;
}

#[tokio::test]
async fn aws_lambda_bridge_mysql_round_trip() {
    if !heavy_dbs_opted_in() {
        eprintln!(
            "skipping aws_lambda_bridge_mysql_round_trip — set FAKECLOUD_E2E_HEAVY_DBS=1 to enable"
        );
        return;
    }
    run_lambda_round_trip("mysql", "8.0", "mysql-lambda-db").await;
}

#[tokio::test]
async fn aws_lambda_bridge_mariadb_round_trip() {
    if !heavy_dbs_opted_in() {
        eprintln!("skipping aws_lambda_bridge_mariadb_round_trip — set FAKECLOUD_E2E_HEAVY_DBS=1 to enable");
        return;
    }
    run_lambda_round_trip("mariadb", "10.11", "mariadb-lambda-db").await;
}
