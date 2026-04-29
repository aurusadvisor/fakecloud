use std::sync::Arc;

use base64::Engine;
use chrono::Utc;
use fakecloud_core::delivery::KinesisDelivery;

use crate::state::{KinesisRecord, SharedKinesisState};

/// Kinesis delivery implementation for cross-service integrations.
pub struct KinesisDeliveryImpl {
    state: SharedKinesisState,
}

impl KinesisDeliveryImpl {
    pub fn new(state: SharedKinesisState) -> Arc<Self> {
        Arc::new(Self { state })
    }
}

impl KinesisDelivery for KinesisDeliveryImpl {
    fn put_record(&self, stream_arn: &str, data: &str, partition_key: &str) {
        // Extract stream name from ARN: arn:aws:kinesis:region:account:stream/StreamName
        let stream_name = if let Some(name_part) = stream_arn.rsplit('/').next() {
            // Handles both arn:aws:kinesis:region:account:stream/Name and plain name
            name_part
        } else {
            stream_arn
        };

        let default_id = self.state.read().default_account_id().to_string();
        let target_account = stream_arn
            .split(':')
            .nth(4)
            .filter(|s| !s.is_empty())
            .unwrap_or(&default_id);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(target_account);
        if let Some(stream) = state.streams.get_mut(stream_name) {
            // Find the shard to write to based on partition key
            // For simplicity, hash the partition key and mod by shard count
            let shard_idx = if stream.shards.is_empty() {
                0
            } else {
                partition_key
                    .bytes()
                    .fold(0u64, |acc, b| acc.wrapping_add(b as u64))
                    % stream.shards.len() as u64
            };

            if let Some(shard) = stream.shards.get_mut(shard_idx as usize) {
                let now = Utc::now();
                let sequence_number = now.timestamp_nanos_opt().unwrap_or(0).to_string();

                // Data is base64-encoded; decode to raw bytes for storage.
                // GetRecords will base64-encode when returning, matching AWS behavior.
                let data_bytes = base64::engine::general_purpose::STANDARD
                    .decode(data)
                    .unwrap_or_else(|_| data.as_bytes().to_vec());

                shard.records.push(KinesisRecord {
                    sequence_number: sequence_number.clone(),
                    partition_key: partition_key.to_string(),
                    data: data_bytes,
                    approximate_arrival_timestamp: now,
                });

                tracing::debug!(
                    stream_name = %stream_name,
                    partition_key = %partition_key,
                    sequence_number = %sequence_number,
                    "Delivered record to Kinesis stream"
                );
            }
        } else {
            tracing::warn!(
                stream_arn = %stream_arn,
                stream_name = %stream_name,
                "Stream not found for Kinesis delivery"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{KinesisShard, KinesisState, KinesisStream, SharedKinesisState};
    use fakecloud_aws::arn::Arn;
    use parking_lot::RwLock;
    use std::collections::BTreeMap;

    fn make_stream(name: &str, shard_count: usize) -> KinesisStream {
        let shards = (0..shard_count)
            .map(|i| KinesisShard {
                shard_id: format!("shardId-{i:012}"),
                starting_hash_key: "0".to_string(),
                ending_hash_key: "340282366920938463463374607431768211455".to_string(),
                parent_shard_id: None,
                adjacent_parent_shard_id: None,
                is_open: true,
                next_sequence_number: 0,
                records: Vec::new(),
            })
            .collect();
        KinesisStream {
            stream_name: name.to_string(),
            stream_arn: Arn::new(
                "kinesis",
                "us-east-1",
                "123456789012",
                &format!("stream/{name}"),
            )
            .to_string(),
            stream_status: "ACTIVE".to_string(),
            stream_creation_timestamp: Utc::now(),
            retention_period_hours: 24,
            stream_mode: "PROVISIONED".to_string(),
            encryption_type: "NONE".to_string(),
            key_id: None,
            shard_count: shard_count as i32,
            open_shard_count: shard_count as i32,
            tags: BTreeMap::new(),
            shards,
            next_shard_index: shard_count as i32,
            enhanced_metrics: Vec::new(),
            warm_throughput_mibps: None,
            max_record_size_kib: None,
        }
    }

    fn make_state(stream: KinesisStream) -> SharedKinesisState {
        let mut mas: fakecloud_core::multi_account::MultiAccountState<KinesisState> =
            fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", "");
        mas.get_or_create("123456789012")
            .streams
            .insert(stream.stream_name.clone(), stream);
        Arc::new(RwLock::new(mas))
    }

    #[test]
    fn put_record_delivers_to_shard() {
        let stream = make_stream("my-stream", 1);
        let state = make_state(stream);
        let delivery = KinesisDeliveryImpl::new(state.clone());
        let encoded = base64::engine::general_purpose::STANDARD.encode(b"hello");
        delivery.put_record(
            "arn:aws:kinesis:us-east-1:123456789012:stream/my-stream",
            &encoded,
            "pk-1",
        );
        let mas = state.read();
        let guard = mas.default_ref();
        let stream = guard.streams.get("my-stream").unwrap();
        assert_eq!(stream.shards[0].records.len(), 1);
        let rec = &stream.shards[0].records[0];
        assert_eq!(rec.data, b"hello");
        assert_eq!(rec.partition_key, "pk-1");
    }

    #[test]
    fn put_record_stores_raw_bytes_when_not_base64() {
        let stream = make_stream("s", 1);
        let state = make_state(stream);
        let delivery = KinesisDeliveryImpl::new(state.clone());
        delivery.put_record(
            "arn:aws:kinesis:us-east-1:123456789012:stream/s",
            "not-base64!",
            "p",
        );
        let mas = state.read();
        let guard = mas.default_ref();
        let rec = &guard.streams.get("s").unwrap().shards[0].records[0];
        assert_eq!(rec.data, b"not-base64!");
    }

    #[test]
    fn put_record_distributes_across_shards_by_partition_key() {
        let stream = make_stream("s", 4);
        let state = make_state(stream);
        let delivery = KinesisDeliveryImpl::new(state.clone());
        delivery.put_record(
            "arn:aws:kinesis:us-east-1:123456789012:stream/s",
            &base64::engine::general_purpose::STANDARD.encode(b"a"),
            "A",
        );
        delivery.put_record(
            "arn:aws:kinesis:us-east-1:123456789012:stream/s",
            &base64::engine::general_purpose::STANDARD.encode(b"b"),
            "B",
        );
        let mas = state.read();
        let guard = mas.default_ref();
        let stream = guard.streams.get("s").unwrap();
        let total: usize = stream.shards.iter().map(|s| s.records.len()).sum();
        assert_eq!(total, 2);
    }

    #[test]
    fn put_record_unknown_stream_is_noop() {
        let stream = make_stream("s", 1);
        let state = make_state(stream);
        let delivery = KinesisDeliveryImpl::new(state.clone());
        delivery.put_record(
            "arn:aws:kinesis:us-east-1:123456789012:stream/other",
            "AAA=",
            "p",
        );
        let mas = state.read();
        let guard = mas.default_ref();
        assert!(guard.streams.get("s").unwrap().shards[0].records.is_empty());
    }

    #[test]
    fn put_record_handles_plain_stream_name_arg() {
        let stream = make_stream("plain", 1);
        let state = make_state(stream);
        let delivery = KinesisDeliveryImpl::new(state.clone());
        delivery.put_record("plain", "AAA=", "p");
        let mas = state.read();
        let guard = mas.default_ref();
        assert_eq!(
            guard.streams.get("plain").unwrap().shards[0].records.len(),
            1
        );
    }
}
