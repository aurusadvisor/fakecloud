//! Re-exports of `fakecloud_testkit` items used by the e2e suite, plus a
//! couple of crate-local helpers (`gunzip`) that don't belong in testkit.
//!
//! `TestServer`, including every per-service SDK client factory and the
//! `aws_cli` wrapper, lives in `fakecloud_testkit` under the `sdk-clients`
//! feature which this crate enables in its `Cargo.toml`.

#![allow(dead_code, unused_imports)]

pub use fakecloud_testkit::{data_path_for, run_until_exit, CliOutput, TestServer};

/// Poll SQS ReceiveMessage until at least `n` messages have been collected
/// across one or more calls, or the deadline elapses. Returns whatever was
/// gathered so the caller's assertion can produce a useful failure message.
///
/// Useful when an upstream system (SES → SNS → SQS, EventBridge → SQS, etc.)
/// publishes asynchronously and a fixed sleep would either be too short under
/// CI load or wastefully long under local development.
pub async fn sqs_receive_at_least(
    sqs: &aws_sdk_sqs::Client,
    queue_url: &str,
    n: usize,
    deadline: std::time::Duration,
) -> Vec<aws_sdk_sqs::types::Message> {
    let until = std::time::Instant::now() + deadline;
    let mut all: Vec<aws_sdk_sqs::types::Message> = Vec::new();
    while std::time::Instant::now() < until {
        let resp = sqs
            .receive_message()
            .queue_url(queue_url)
            .max_number_of_messages(10)
            .send()
            .await
            .unwrap();
        all.extend(resp.messages().to_vec());
        if all.len() >= n {
            return all;
        }
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    }
    all
}

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
