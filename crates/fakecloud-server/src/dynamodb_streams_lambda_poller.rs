//! Background poller that bridges DynamoDB Streams -> Lambda event source mappings.
//!
//! Periodically checks Lambda state for enabled event source mappings
//! pointing to DynamoDB streams, reads stream records, and invokes Lambda
//! functions with batches of records.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde_json::json;

use fakecloud_core::delivery::LambdaDelivery;
use fakecloud_dynamodb::SharedDynamoDbState;
use fakecloud_lambda::filter::FilterSet;
use fakecloud_lambda::{LambdaInvocation, SharedLambdaState};

/// DynamoDB Streams -> Lambda event source mapping poller.
pub struct DynamoDbStreamsLambdaPoller {
    dynamodb_state: SharedDynamoDbState,
    lambda_state: SharedLambdaState,
    lambda_delivery: Option<Arc<dyn LambdaDelivery>>,
    /// Track the last processed sequence number per mapping
    checkpoints: parking_lot::RwLock<HashMap<String, String>>,
}

impl DynamoDbStreamsLambdaPoller {
    pub fn new(dynamodb_state: SharedDynamoDbState, lambda_state: SharedLambdaState) -> Self {
        Self {
            dynamodb_state,
            lambda_state,
            lambda_delivery: None,
            checkpoints: parking_lot::RwLock::new(HashMap::new()),
        }
    }

    pub fn with_lambda_delivery(mut self, delivery: Arc<dyn LambdaDelivery>) -> Self {
        self.lambda_delivery = Some(delivery);
        self
    }

    pub async fn run(self: Arc<Self>) {
        let mut interval = tokio::time::interval(Duration::from_millis(500));
        loop {
            interval.tick().await;
            self.poll().await;
        }
    }

    async fn poll(&self) {
        struct DdbMapping {
            uuid: String,
            stream_arn: String,
            function_arn: String,
            batch_size: i64,
            filter: FilterSet,
            starting_position: Option<String>,
            starting_position_timestamp: Option<f64>,
        }

        // Collect enabled mappings that point to DynamoDB streams
        let mappings: Vec<DdbMapping> = {
            let lambda_accounts = self.lambda_state.read();
            let lambda = lambda_accounts.default_ref();
            lambda
                .event_source_mappings
                .values()
                .filter(|m| {
                    m.enabled
                        && m.event_source_arn.contains(":dynamodb:")
                        && m.event_source_arn.contains("/stream/")
                })
                .map(|m| DdbMapping {
                    uuid: m.uuid.clone(),
                    stream_arn: m.event_source_arn.clone(),
                    function_arn: m.function_arn.clone(),
                    batch_size: m.batch_size,
                    filter: FilterSet::from_strings(m.filter_patterns.iter()),
                    starting_position: m.starting_position.clone(),
                    starting_position_timestamp: m.starting_position_timestamp,
                })
                .collect()
        };

        if mappings.is_empty() {
            return;
        }

        for DdbMapping {
            uuid: mapping_id,
            stream_arn,
            function_arn,
            batch_size,
            filter,
            starting_position,
            starting_position_timestamp,
        } in mappings
        {
            // Extract table name from stream ARN
            // Format: arn:aws:dynamodb:region:account:table/TableName/stream/timestamp
            let table_name = if let Some(table_part) = stream_arn.split(":table/").nth(1) {
                table_part.split('/').next().unwrap_or("")
            } else {
                continue;
            };

            // AT_TIMESTAMP isn't valid for DDB streams in real AWS;
            // suppress the field if the user supplied it.
            let _ = starting_position_timestamp;

            // Initialize the checkpoint based on StartingPosition the
            // first time we see this mapping. For DDB streams AWS only
            // accepts TRIM_HORIZON (default — replays existing records)
            // and LATEST (skip whatever is already in the stream).
            let checkpoint = {
                let mut cps = self.checkpoints.write();
                if !cps.contains_key(&mapping_id) {
                    let dynamodb_mas = self.dynamodb_state.read();
                    let dynamodb = dynamodb_mas.default_ref();
                    if let Some(table) = dynamodb.tables.get(table_name) {
                        let stream_records = table.stream_records.read();
                        let init = match starting_position.as_deref().unwrap_or("TRIM_HORIZON") {
                            "LATEST" => stream_records
                                .iter()
                                .map(|r| r.dynamodb.sequence_number.clone())
                                .max()
                                .unwrap_or_default(),
                            _ => String::new(),
                        };
                        cps.insert(mapping_id.clone(), init);
                    }
                }
                cps.get(&mapping_id).cloned()
            };

            // Read stream records from DynamoDB
            let records = {
                let dynamodb_mas = self.dynamodb_state.read();
                let dynamodb = dynamodb_mas.default_ref();
                let table = match dynamodb.tables.get(table_name) {
                    Some(t) => t,
                    None => continue,
                };

                if !table.stream_enabled {
                    continue;
                }

                let stream_records = table.stream_records.read();

                // Filter records after checkpoint
                let mut filtered: Vec<_> = stream_records
                    .iter()
                    .filter(|r| match checkpoint.as_deref() {
                        Some(cp) if !cp.is_empty() => r.dynamodb.sequence_number.as_str() > cp,
                        _ => true,
                    })
                    .take(batch_size.max(0) as usize)
                    .cloned()
                    .collect();

                // Sort by sequence number to ensure order
                filtered
                    .sort_by(|a, b| a.dynamodb.sequence_number.cmp(&b.dynamodb.sequence_number));

                filtered
            };

            if records.is_empty() {
                continue;
            }

            // Build per-record Lambda event JSON, then drop any record
            // whose JSON doesn't match FilterCriteria. AWS treats
            // filtered-out records as consumed — the checkpoint always
            // advances past them.
            let last_seq = records.last().map(|r| r.dynamodb.sequence_number.clone());
            let event_records: Vec<serde_json::Value> = records
                .iter()
                .filter_map(|record| {
                    let mut event_record = json!({
                        "eventID": record.event_id,
                        "eventName": record.event_name,
                        "eventVersion": record.event_version,
                        "eventSource": record.event_source,
                        "awsRegion": record.aws_region,
                        "dynamodb": {
                            "Keys": record.dynamodb.keys,
                            "SequenceNumber": record.dynamodb.sequence_number,
                            "SizeBytes": record.dynamodb.size_bytes,
                            "StreamViewType": record.dynamodb.stream_view_type,
                        },
                        "eventSourceARN": record.event_source_arn,
                    });

                    if let Some(ref new_img) = record.dynamodb.new_image {
                        event_record["dynamodb"]["NewImage"] = json!(new_img);
                    }
                    if let Some(ref old_img) = record.dynamodb.old_image {
                        event_record["dynamodb"]["OldImage"] = json!(old_img);
                    }

                    if filter.matches(&event_record) {
                        Some(event_record)
                    } else {
                        None
                    }
                })
                .collect();

            // If the filter dropped every record, advance the
            // checkpoint past them — AWS treats filtered records as
            // consumed. Otherwise, hold the checkpoint until after a
            // successful invoke so failures retry on the next poll.
            if event_records.is_empty() {
                if let Some(seq) = last_seq.clone() {
                    self.checkpoints.write().insert(mapping_id.clone(), seq);
                }
                continue;
            }

            let event = json!({ "Records": &event_records });
            let payload = serde_json::to_string(&event).unwrap_or_default();

            let invoke_succeeded = match &self.lambda_delivery {
                Some(delivery) => match delivery.invoke_lambda(&function_arn, &payload).await {
                    Ok(_) => {
                        tracing::info!(
                            function_arn = %function_arn,
                            record_count = event_records.len(),
                            "DynamoDB Streams->Lambda invocation succeeded"
                        );
                        true
                    }
                    Err(e) => {
                        tracing::error!(
                            function_arn = %function_arn,
                            error = %e,
                            "DynamoDB Streams->Lambda invocation failed"
                        );
                        false
                    }
                },
                None => true,
            };

            if !invoke_succeeded {
                continue;
            }

            // Successful invoke — advance the checkpoint and record
            // the invocation when no real Lambda runtime is wired.
            if let Some(seq) = last_seq.clone() {
                self.checkpoints.write().insert(mapping_id.clone(), seq);
            }

            if self.lambda_delivery.is_none() {
                let mut lambda_accounts = self.lambda_state.write();
                let lambda = lambda_accounts.default_mut();
                lambda.invocations.push(LambdaInvocation {
                    function_arn: function_arn.clone(),
                    payload: payload.clone(),
                    timestamp: Utc::now(),
                    source: "dynamodb:streams".to_string(),
                });
            }
        }
    }
}
