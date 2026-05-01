use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use bytes::Bytes;
use chrono::Utc;
use http::StatusCode;
use parking_lot::RwLock;
use serde_json::{json, Value};
use uuid::Uuid;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
use fakecloud_s3::{memory_body, S3Object, SharedS3State};

use crate::state::{DeliveryStream, FirehoseAccounts, S3Destination, SharedFirehoseState};

const SUPPORTED_ACTIONS: &[&str] = &[
    "CreateDeliveryStream",
    "DescribeDeliveryStream",
    "ListDeliveryStreams",
    "DeleteDeliveryStream",
    "PutRecord",
    "PutRecordBatch",
    "TagDeliveryStream",
    "UntagDeliveryStream",
    "ListTagsForDeliveryStream",
    "UpdateDestination",
];

pub struct FirehoseService {
    state: SharedFirehoseState,
    s3: Option<SharedS3State>,
}

impl FirehoseService {
    pub fn new(state: SharedFirehoseState) -> Self {
        Self { state, s3: None }
    }

    pub fn with_s3(mut self, s3: SharedS3State) -> Self {
        self.s3 = Some(s3);
        self
    }

    pub fn shared_state(&self) -> SharedFirehoseState {
        Arc::clone(&self.state)
    }
}

impl Default for FirehoseService {
    fn default() -> Self {
        Self::new(Arc::new(RwLock::new(FirehoseAccounts::new())))
    }
}

#[async_trait]
impl AwsService for FirehoseService {
    fn service_name(&self) -> &str {
        "firehose"
    }

    fn supported_actions(&self) -> &[&str] {
        SUPPORTED_ACTIONS
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        match req.action.as_str() {
            "CreateDeliveryStream" => self.create_delivery_stream(&req),
            "DescribeDeliveryStream" => self.describe_delivery_stream(&req),
            "ListDeliveryStreams" => self.list_delivery_streams(&req),
            "DeleteDeliveryStream" => self.delete_delivery_stream(&req),
            "PutRecord" => self.put_record(&req),
            "PutRecordBatch" => self.put_record_batch(&req),
            "TagDeliveryStream" => self.tag_delivery_stream(&req),
            "UntagDeliveryStream" => self.untag_delivery_stream(&req),
            "ListTagsForDeliveryStream" => self.list_tags_for_delivery_stream(&req),
            "UpdateDestination" => self.update_destination(&req),
            other => Err(AwsServiceError::action_not_implemented("firehose", other)),
        }
    }
}

fn missing(field: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "InvalidArgumentException",
        format!("Missing required field: {field}"),
    )
}

fn parse_s3_destination(val: &Value) -> Option<S3Destination> {
    if !val.is_object() {
        return None;
    }
    let role_arn = val["RoleARN"].as_str()?.to_string();
    let bucket_arn = val["BucketARN"].as_str()?.to_string();
    let buf = &val["BufferingHints"];
    Some(S3Destination {
        destination_id: format!("destinationId-{}", Uuid::new_v4()),
        role_arn,
        bucket_arn,
        prefix: val["Prefix"].as_str().map(|s| s.to_string()),
        error_output_prefix: val["ErrorOutputPrefix"].as_str().map(|s| s.to_string()),
        buffering_size_mb: buf["SizeInMBs"].as_i64(),
        buffering_interval_seconds: buf["IntervalInSeconds"].as_i64(),
        compression_format: val["CompressionFormat"].as_str().map(|s| s.to_string()),
    })
}

fn s3_destination_json(dest: &S3Destination) -> Value {
    let mut buf = json!({});
    if let Some(s) = dest.buffering_size_mb {
        buf["SizeInMBs"] = json!(s);
    }
    if let Some(i) = dest.buffering_interval_seconds {
        buf["IntervalInSeconds"] = json!(i);
    }
    let mut s3 = json!({
        "RoleARN": dest.role_arn,
        "BucketARN": dest.bucket_arn,
        "BufferingHints": buf,
        "CompressionFormat": dest.compression_format.clone().unwrap_or_else(|| "UNCOMPRESSED".to_string()),
    });
    if let Some(ref p) = dest.prefix {
        s3["Prefix"] = json!(p);
    }
    if let Some(ref p) = dest.error_output_prefix {
        s3["ErrorOutputPrefix"] = json!(p);
    }
    json!({
        "DestinationId": dest.destination_id,
        "S3DestinationDescription": s3,
        "ExtendedS3DestinationDescription": s3.clone(),
    })
}

fn arn_for(region: &str, account: &str, name: &str) -> String {
    format!("arn:aws:firehose:{region}:{account}:deliverystream/{name}")
}

fn bucket_name_from_arn(arn: &str) -> Option<&str> {
    arn.strip_prefix("arn:aws:s3:::")
}

impl FirehoseService {
    fn create_delivery_stream(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = body["DeliveryStreamName"]
            .as_str()
            .ok_or_else(|| missing("DeliveryStreamName"))?
            .to_string();
        let stream_type = body["DeliveryStreamType"]
            .as_str()
            .unwrap_or("DirectPut")
            .to_string();

        let s3_dest = parse_s3_destination(&body["S3DestinationConfiguration"])
            .or_else(|| parse_s3_destination(&body["ExtendedS3DestinationConfiguration"]));

        let now = Utc::now();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id, &req.region);
        if state.streams.contains_key(&name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceInUseException",
                format!("DeliveryStream {name} already exists"),
            ));
        }
        let arn = arn_for(&req.region, &req.account_id, &name);
        let stream = DeliveryStream {
            name: name.clone(),
            arn: arn.clone(),
            status: "ACTIVE".to_string(),
            stream_type,
            created_at: now,
            last_update: now,
            version_id: "1".to_string(),
            destination: s3_dest,
            tags: BTreeMap::new(),
        };
        state.streams.insert(name, stream);
        Ok(AwsResponse::ok_json(json!({
            "DeliveryStreamARN": arn,
        })))
    }

    fn describe_delivery_stream(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = body["DeliveryStreamName"]
            .as_str()
            .ok_or_else(|| missing("DeliveryStreamName"))?;
        let accounts = self.state.read();
        let state = accounts
            .get(&req.account_id)
            .ok_or_else(|| not_found(name))?;
        let stream = state.streams.get(name).ok_or_else(|| not_found(name))?;

        let destinations: Vec<Value> = stream
            .destination
            .as_ref()
            .map(|d| vec![s3_destination_json(d)])
            .unwrap_or_default();

        Ok(AwsResponse::ok_json(json!({
            "DeliveryStreamDescription": {
                "DeliveryStreamName": stream.name,
                "DeliveryStreamARN": stream.arn,
                "DeliveryStreamStatus": stream.status,
                "DeliveryStreamType": stream.stream_type,
                "VersionId": stream.version_id,
                "CreateTimestamp": stream.created_at.timestamp() as f64,
                "LastUpdateTimestamp": stream.last_update.timestamp() as f64,
                "Destinations": destinations,
                "HasMoreDestinations": false,
            }
        })))
    }

    fn list_delivery_streams(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let limit = body["Limit"].as_i64().unwrap_or(10).max(1) as usize;
        let exclusive_start = body["ExclusiveStartDeliveryStreamName"]
            .as_str()
            .map(|s| s.to_string());
        let type_filter = body["DeliveryStreamType"].as_str().map(|s| s.to_string());

        let accounts = self.state.read();
        let names: Vec<String> = accounts
            .get(&req.account_id)
            .map(|s| {
                s.streams
                    .iter()
                    .filter(|(n, stream)| {
                        if let Some(ref start) = exclusive_start {
                            if n.as_str() <= start.as_str() {
                                return false;
                            }
                        }
                        if let Some(ref t) = type_filter {
                            return &stream.stream_type == t;
                        }
                        true
                    })
                    .map(|(n, _)| n.clone())
                    .collect()
            })
            .unwrap_or_default();
        let truncated = names.len() > limit;
        let names: Vec<String> = names.into_iter().take(limit).collect();
        Ok(AwsResponse::ok_json(json!({
            "DeliveryStreamNames": names,
            "HasMoreDeliveryStreams": truncated,
        })))
    }

    fn delete_delivery_stream(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = body["DeliveryStreamName"]
            .as_str()
            .ok_or_else(|| missing("DeliveryStreamName"))?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id, &req.region);
        if state.streams.remove(name).is_none() {
            return Err(not_found(name));
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn put_record(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = body["DeliveryStreamName"]
            .as_str()
            .ok_or_else(|| missing("DeliveryStreamName"))?
            .to_string();
        let data_b64 = body["Record"]["Data"]
            .as_str()
            .ok_or_else(|| missing("Record.Data"))?;
        let data = base64::engine::general_purpose::STANDARD
            .decode(data_b64)
            .map_err(|_| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidArgumentException",
                    "Record.Data must be valid base64",
                )
            })?;
        let record_id = format!("{}", Uuid::new_v4());
        self.deliver_records(&req.account_id, &req.region, &name, vec![data])?;
        Ok(AwsResponse::ok_json(json!({
            "RecordId": record_id,
            "Encrypted": false,
        })))
    }

    fn put_record_batch(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = body["DeliveryStreamName"]
            .as_str()
            .ok_or_else(|| missing("DeliveryStreamName"))?
            .to_string();
        let records = body["Records"]
            .as_array()
            .ok_or_else(|| missing("Records"))?;
        let mut datas = Vec::with_capacity(records.len());
        let mut response_records = Vec::with_capacity(records.len());
        for r in records {
            let b64 = r["Data"].as_str().unwrap_or_default();
            let data = base64::engine::general_purpose::STANDARD
                .decode(b64)
                .unwrap_or_default();
            datas.push(data);
            response_records.push(json!({
                "RecordId": Uuid::new_v4().to_string(),
            }));
        }
        self.deliver_records(&req.account_id, &req.region, &name, datas)?;
        Ok(AwsResponse::ok_json(json!({
            "FailedPutCount": 0,
            "Encrypted": false,
            "RequestResponses": response_records,
        })))
    }

    fn tag_delivery_stream(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = body["DeliveryStreamName"]
            .as_str()
            .ok_or_else(|| missing("DeliveryStreamName"))?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id, &req.region);
        let stream = state.streams.get_mut(name).ok_or_else(|| not_found(name))?;
        if let Some(arr) = body["Tags"].as_array() {
            for t in arr {
                if let (Some(k), Some(v)) = (t["Key"].as_str(), t["Value"].as_str()) {
                    stream.tags.insert(k.to_string(), v.to_string());
                }
            }
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn untag_delivery_stream(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = body["DeliveryStreamName"]
            .as_str()
            .ok_or_else(|| missing("DeliveryStreamName"))?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id, &req.region);
        let stream = state.streams.get_mut(name).ok_or_else(|| not_found(name))?;
        if let Some(arr) = body["TagKeys"].as_array() {
            for k in arr {
                if let Some(s) = k.as_str() {
                    stream.tags.remove(s);
                }
            }
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn list_tags_for_delivery_stream(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = body["DeliveryStreamName"]
            .as_str()
            .ok_or_else(|| missing("DeliveryStreamName"))?;
        let accounts = self.state.read();
        let state = accounts
            .get(&req.account_id)
            .ok_or_else(|| not_found(name))?;
        let stream = state.streams.get(name).ok_or_else(|| not_found(name))?;
        let tags: Vec<Value> = stream
            .tags
            .iter()
            .map(|(k, v)| json!({"Key": k, "Value": v}))
            .collect();
        Ok(AwsResponse::ok_json(json!({
            "Tags": tags,
            "HasMoreTags": false,
        })))
    }

    fn update_destination(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = body["DeliveryStreamName"]
            .as_str()
            .ok_or_else(|| missing("DeliveryStreamName"))?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id, &req.region);
        let stream = state.streams.get_mut(name).ok_or_else(|| not_found(name))?;
        if let Some(d) = parse_s3_destination(&body["S3DestinationUpdate"])
            .or_else(|| parse_s3_destination(&body["ExtendedS3DestinationUpdate"]))
        {
            stream.destination = Some(d);
        }
        stream.last_update = Utc::now();
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn deliver_records(
        &self,
        account_id: &str,
        region: &str,
        stream_name: &str,
        datas: Vec<Vec<u8>>,
    ) -> Result<(), AwsServiceError> {
        let dest = {
            let accounts = self.state.read();
            let state = accounts
                .get(account_id)
                .ok_or_else(|| not_found(stream_name))?;
            let stream = state
                .streams
                .get(stream_name)
                .ok_or_else(|| not_found(stream_name))?;
            stream.destination.clone()
        };
        let Some(dest) = dest else {
            return Ok(());
        };
        let Some(s3) = &self.s3 else {
            return Ok(());
        };
        let Some(bucket_name) = bucket_name_from_arn(&dest.bucket_arn) else {
            return Ok(());
        };
        let mut payload = Vec::new();
        for d in datas {
            payload.extend_from_slice(&d);
            if !d.last().map(|b| *b == b'\n').unwrap_or(false) {
                payload.push(b'\n');
            }
        }
        if payload.is_empty() {
            return Ok(());
        }
        let now = Utc::now();
        let prefix = dest.prefix.clone().unwrap_or_default();
        let key = format!(
            "{prefix}{date}/{stream_name}-{ts}-{rand}",
            date = now.format("%Y/%m/%d/%H"),
            ts = now.timestamp(),
            rand = &Uuid::new_v4().to_string()[..8],
        );
        let size = payload.len() as u64;
        let etag = format!("\"{}\"", Uuid::new_v4().simple());
        let body = memory_body(Bytes::from(payload));
        let _ = region;
        let mut s3_state = s3.write();
        let s3 = s3_state.get_or_create(account_id);
        if let Some(bucket) = s3.buckets.get_mut(bucket_name) {
            let object = S3Object {
                key: key.clone(),
                body,
                content_type: "application/octet-stream".to_string(),
                etag,
                size,
                last_modified: now,
                metadata: BTreeMap::new(),
                storage_class: "STANDARD".to_string(),
                tags: BTreeMap::new(),
                acl_grants: Vec::new(),
                acl_owner_id: None,
                parts_count: None,
                part_sizes: None,
                sse_algorithm: None,
                sse_kms_key_id: None,
                bucket_key_enabled: None,
                version_id: None,
                is_delete_marker: false,
                content_encoding: None,
                website_redirect_location: None,
                restore_ongoing: None,
                restore_expiry: None,
                checksum_algorithm: None,
                checksum_value: None,
                lock_mode: None,
                lock_retain_until: None,
                lock_legal_hold: None,
            };
            bucket.objects.insert(key, object);
        }
        Ok(())
    }
}

fn not_found(name: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ResourceNotFoundException",
        format!("DeliveryStream {name} not found"),
    )
}
