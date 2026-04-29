//! Re-exports of `fakecloud_testkit` items used by the e2e suite, plus a
//! couple of crate-local helpers (`gunzip`) that don't belong in testkit.
//!
//! `TestServer`, including every per-service SDK client factory and the
//! `aws_cli` wrapper, lives in `fakecloud_testkit` under the `sdk-clients`
//! feature which this crate enables in its `Cargo.toml`.

#![allow(dead_code, unused_imports)]

pub use fakecloud_testkit::{data_path_for, run_until_exit, CliOutput, TestServer};

/// Decompress gzipped data.
pub fn gunzip(data: &[u8]) -> Vec<u8> {
    use std::io::Read;
    let mut decoder = flate2::read::GzDecoder::new(data);
    let mut result = Vec::new();
    decoder.read_to_end(&mut result).unwrap();
    result
}

/// Poll DescribeDBInstances until the instance reports
/// `db_instance_status = "available"`, then return the populated
/// `DbInstance`. CreateDBInstance returns a `creating` placeholder
/// immediately; this helper bridges tests that need the endpoint.
pub async fn wait_for_db_available(
    rds: &aws_sdk_rds::Client,
    db_instance_identifier: &str,
    max_secs: u64,
) -> aws_sdk_rds::types::DbInstance {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(max_secs);
    while std::time::Instant::now() < deadline {
        if let Ok(resp) = rds
            .describe_db_instances()
            .db_instance_identifier(db_instance_identifier)
            .send()
            .await
        {
            for inst in resp.db_instances() {
                if inst.db_instance_status() == Some("available") {
                    return inst.clone();
                }
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    panic!(
        "DB instance {} did not reach 'available' within {}s",
        db_instance_identifier, max_secs
    );
}
