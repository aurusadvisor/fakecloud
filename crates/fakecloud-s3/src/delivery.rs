use bytes::Bytes;
use chrono::Utc;
use fakecloud_core::delivery::S3Delivery;
use md5::{Digest, Md5};

use crate::state::{memory_body, S3Object, SharedS3State};

/// Lets non-S3 services write objects to buckets without taking a
/// direct dep on this crate. Used by CloudWatch Logs export tasks,
/// CloudWatch Logs deliveries, Firehose S3 destinations, ELB access
/// logs, and similar producers.
pub struct S3DeliveryImpl {
    state: SharedS3State,
}

impl S3DeliveryImpl {
    pub fn new(state: SharedS3State) -> Self {
        Self { state }
    }
}

impl S3Delivery for S3DeliveryImpl {
    fn put_object(
        &self,
        account_id: &str,
        bucket: &str,
        key: &str,
        body: Vec<u8>,
        content_type: Option<&str>,
    ) -> Result<(), String> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        let bucket_ref = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| format!("bucket {bucket} not found in account {account_id}"))?;

        let bytes = Bytes::from(body);
        let size = bytes.len() as u64;
        let etag = format!("{:x}", Md5::digest(&bytes));
        let obj = S3Object {
            key: key.to_string(),
            body: memory_body(bytes),
            content_type: content_type
                .unwrap_or("application/octet-stream")
                .to_string(),
            etag,
            size,
            last_modified: Utc::now(),
            ..Default::default()
        };
        bucket_ref.objects.insert(key.to_string(), obj);
        Ok(())
    }

    fn get_object(&self, account_id: &str, bucket: &str, key: &str) -> Result<Vec<u8>, String> {
        let accounts = self.state.read();
        let state = accounts
            .get(account_id)
            .ok_or_else(|| format!("account {account_id} has no S3 state"))?;
        let bucket_ref = state
            .buckets
            .get(bucket)
            .ok_or_else(|| format!("bucket {bucket} not found in account {account_id}"))?;
        let object = bucket_ref
            .objects
            .get(key)
            .ok_or_else(|| format!("key {key} not found in bucket {bucket}"))?;
        let body = state
            .read_body(&object.body)
            .map_err(|e| format!("failed to read body: {e}"))?;
        Ok(body.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{S3Bucket, S3State};
    use fakecloud_core::multi_account::MultiAccountState;
    use parking_lot::RwLock;
    use std::sync::Arc;

    const ACCOUNT: &str = "123456789012";

    fn shared_state() -> SharedS3State {
        let mut mas: MultiAccountState<S3State> =
            MultiAccountState::new(ACCOUNT, "us-east-1", "http://localhost");
        let st = mas.get_or_create(ACCOUNT);
        st.buckets.insert(
            "logs-bucket".to_string(),
            S3Bucket::new("logs-bucket", "us-east-1", "owner-id"),
        );
        Arc::new(RwLock::new(mas))
    }

    #[test]
    fn put_object_writes_to_bucket() {
        let state = shared_state();
        let delivery = S3DeliveryImpl::new(state.clone());
        delivery
            .put_object(
                ACCOUNT,
                "logs-bucket",
                "exports/run-1.txt",
                b"hello world".to_vec(),
                Some("text/plain"),
            )
            .expect("put should succeed");
        let accounts = state.read();
        let st = accounts.get(ACCOUNT).unwrap();
        let bucket = st.buckets.get("logs-bucket").unwrap();
        let obj = bucket.objects.get("exports/run-1.txt").unwrap();
        assert_eq!(obj.size, 11);
        assert_eq!(obj.content_type, "text/plain");
        assert!(!obj.etag.is_empty());
    }

    #[test]
    fn put_object_rejects_missing_bucket() {
        let state = shared_state();
        let delivery = S3DeliveryImpl::new(state);
        let err = delivery
            .put_object(ACCOUNT, "ghost", "k", b"x".to_vec(), None)
            .expect_err("missing bucket");
        assert!(err.contains("not found"));
    }

    #[test]
    fn get_object_round_trips_put_object() {
        let state = shared_state();
        let delivery = S3DeliveryImpl::new(state);
        delivery
            .put_object(
                ACCOUNT,
                "logs-bucket",
                "dump.sql",
                b"-- pg dump --".to_vec(),
                Some("application/sql"),
            )
            .expect("put");
        let body = delivery
            .get_object(ACCOUNT, "logs-bucket", "dump.sql")
            .expect("get");
        assert_eq!(body, b"-- pg dump --".to_vec());
    }

    #[test]
    fn get_object_rejects_missing_key() {
        let state = shared_state();
        let delivery = S3DeliveryImpl::new(state);
        let err = delivery
            .get_object(ACCOUNT, "logs-bucket", "ghost")
            .expect_err("missing key");
        assert!(err.contains("not found"));
    }
}
