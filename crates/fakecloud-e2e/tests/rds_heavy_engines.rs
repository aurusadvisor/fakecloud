//! End-to-end coverage for the heavyweight RDS engines: Oracle, SQL
//! Server, and Db2. Each test spins up the corresponding free-tier
//! container image (gvenzl/oracle-free, mcr.microsoft.com/mssql/server,
//! icr.io/db2_community/db2), so each adds 1-3 GB of disk and
//! 30-300 seconds of boot time. They are gated behind
//! `FAKECLOUD_E2E_HEAVY_DBS=1` so a normal `cargo test -p fakecloud-e2e`
//! run skips them; CI opts in via the heavy-DB workflow lane.
//!
//! When the gate is unset on a developer machine, the tests print and
//! return rather than failing — matching the existing
//! `docker_available()` pattern. CI machines that do not set the
//! variable will likewise skip; CI machines that *do* set it must have
//! Docker available, so the cluster operates as a hard-required
//! dependency in that lane.

mod helpers;

use helpers::TestServer;

fn heavy_dbs_opted_in() -> bool {
    std::env::var("FAKECLOUD_E2E_HEAVY_DBS")
        .map(|v| v == "1")
        .unwrap_or(false)
}

fn docker_available() -> bool {
    std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn skip_unless_ready(test_name: &str) -> bool {
    if !heavy_dbs_opted_in() {
        eprintln!(
            "{test_name}: set FAKECLOUD_E2E_HEAVY_DBS=1 to run; skipping (matches \
             the heavy-engine soft-skip pattern)",
        );
        return true;
    }
    if !docker_available() {
        eprintln!("{test_name}: docker required for RDS heavy engines; skipping");
        return true;
    }
    false
}

#[tokio::test]
async fn rds_oracle_create_describe_delete() {
    if skip_unless_ready("rds_oracle_create_describe_delete") {
        return;
    }
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    client
        .create_db_instance()
        .db_instance_identifier("oracle-smoke")
        .allocated_storage(20)
        .db_instance_class("db.t3.micro")
        .engine("oracle-ee")
        .engine_version("23.0.0")
        // Oracle requires the password not start with a digit and to
        // contain an upper, lower, and digit. Strong default for tests.
        .master_username("admin")
        .master_user_password("Aa1234567")
        .send()
        .await
        .expect("create oracle instance");

    let describe = client
        .describe_db_instances()
        .db_instance_identifier("oracle-smoke")
        .send()
        .await
        .expect("describe");
    let instance = describe.db_instances().first().expect("one instance");
    assert_eq!(instance.engine(), Some("oracle-ee"));
    assert_eq!(instance.db_instance_status(), Some("available"));
    assert_eq!(
        instance
            .endpoint()
            .and_then(|e| e.address())
            .map(|a| a.to_string()),
        Some("127.0.0.1".to_string())
    );

    client
        .delete_db_instance()
        .db_instance_identifier("oracle-smoke")
        .skip_final_snapshot(true)
        .send()
        .await
        .expect("delete");
}

#[tokio::test]
async fn rds_sqlserver_create_describe_delete() {
    if skip_unless_ready("rds_sqlserver_create_describe_delete") {
        return;
    }
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    client
        .create_db_instance()
        .db_instance_identifier("mssql-smoke")
        .allocated_storage(20)
        .db_instance_class("db.t3.micro")
        .engine("sqlserver-ex")
        .engine_version("16.00.4085.2.v1")
        // SQL Server's SA password must be at least 8 chars with mixed
        // classes. The image rejects shorter passwords and refuses to
        // start.
        .master_username("admin")
        .master_user_password("Aa1!Aa1!")
        .send()
        .await
        .expect("create sqlserver instance");

    let describe = client
        .describe_db_instances()
        .db_instance_identifier("mssql-smoke")
        .send()
        .await
        .expect("describe");
    let instance = describe.db_instances().first().expect("one instance");
    assert_eq!(instance.engine(), Some("sqlserver-ex"));
    assert_eq!(instance.db_instance_status(), Some("available"));

    client
        .delete_db_instance()
        .db_instance_identifier("mssql-smoke")
        .skip_final_snapshot(true)
        .send()
        .await
        .expect("delete");
}

#[tokio::test]
async fn rds_db2_create_describe_delete() {
    if skip_unless_ready("rds_db2_create_describe_delete") {
        return;
    }
    let server = TestServer::start().await;
    let client = server.rds_client().await;

    client
        .create_db_instance()
        .db_instance_identifier("db2-smoke")
        .allocated_storage(20)
        .db_instance_class("db.t3.micro")
        .engine("db2-se")
        .engine_version("11.5.9.0.sb00000000.r1")
        .master_username("db2inst1")
        .master_user_password("password123")
        .db_name("testdb")
        .send()
        .await
        .expect("create db2 instance");

    let describe = client
        .describe_db_instances()
        .db_instance_identifier("db2-smoke")
        .send()
        .await
        .expect("describe");
    let instance = describe.db_instances().first().expect("one instance");
    assert_eq!(instance.engine(), Some("db2-se"));
    assert_eq!(instance.db_instance_status(), Some("available"));

    client
        .delete_db_instance()
        .db_instance_identifier("db2-smoke")
        .skip_final_snapshot(true)
        .send()
        .await
        .expect("delete");
}
