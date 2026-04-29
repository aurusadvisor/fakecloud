use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Timelike, Utc};
use http::{HeaderMap, Method, StatusCode};
use md5::{Digest, Md5};

use fakecloud_aws::arn::Arn;
use fakecloud_core::delivery::DeliveryBus;
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
use fakecloud_kms::state::SharedKmsState;
use fakecloud_persistence::{MemoryS3Store, S3Store, StoreError};

use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine as _;

use crate::logging;
use crate::state::{AclGrant, S3Bucket, S3Object, SharedS3State};

mod acl;
mod buckets;
mod config;
mod lock;
mod multipart;
mod notifications;
mod objects;
mod tags;

// Re-export notification helpers for use in sub-modules
#[cfg(test)]
use notifications::replicate_object;
pub(super) use notifications::{
    deliver_notifications, normalize_notification_ids, normalize_replication_xml,
    replicate_through_store,
};

// Used only within this file (parse_cors_config)
use notifications::extract_all_xml_values;

// Re-exports used only in tests
#[cfg(test)]
use notifications::{
    event_matches, key_matches_filters, parse_notification_config, parse_replication_rules,
    NotificationTargetType,
};

pub struct S3Service {
    state: SharedS3State,
    delivery: Arc<DeliveryBus>,
    kms_state: Option<SharedKmsState>,
    pub(crate) kms_hook: Option<Arc<dyn fakecloud_core::delivery::KmsHook>>,
    store: Arc<dyn S3Store>,
}

/// Map a [`StoreError`] from the persistence layer to a 500 InternalError
/// response. Invoked at every mutation site when the write-through persistence
/// call fails: the in-memory mutation has already happened, but we surface the
/// failure to the client so they know to retry (and so logs/metrics flag it).
pub(crate) fn persistence_error(err: StoreError) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "InternalError",
        format!("persistence store error: {err}"),
    )
}

/// Convert a filesystem IO error from a disk-backed body read into an
/// InternalError response.
pub(crate) fn io_to_aws(err: std::io::Error) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "InternalError",
        format!("failed to read object body from disk: {err}"),
    )
}

impl S3Service {
    pub fn new(state: SharedS3State, delivery: Arc<DeliveryBus>) -> Self {
        Self::with_store(state, delivery, Arc::new(MemoryS3Store::new()))
    }

    pub fn with_store(
        state: SharedS3State,
        delivery: Arc<DeliveryBus>,
        store: Arc<dyn S3Store>,
    ) -> Self {
        Self {
            state,
            delivery,
            kms_state: None,
            kms_hook: None,
            store,
        }
    }

    pub fn with_kms(mut self, kms_state: SharedKmsState) -> Self {
        self.kms_state = Some(kms_state);
        self
    }

    pub fn with_kms_hook(mut self, hook: Arc<dyn fakecloud_core::delivery::KmsHook>) -> Self {
        self.kms_hook = Some(hook);
        self
    }

    /// Encrypt object body bytes for SSE-KMS storage. Returns ciphertext as
    /// raw bytes (a UTF-8 fakecloud-kms envelope) on success.
    ///
    /// Fail-closed: if the KMS hook reports an error (key denied, key not
    /// found, etc.), this returns `Err` so PutObject aborts with a 500
    /// rather than silently storing plaintext. AWS S3 has the same
    /// behavior — `KMS.NotFoundException` and friends surface as
    /// `AccessDenied` / `KMS.*` errors back to the caller. When no hook is
    /// wired (legacy / in-process tests with no KMS dependency), the
    /// plaintext is returned unchanged so existing tests keep working.
    pub(crate) fn encrypt_object_body(
        &self,
        account_id: &str,
        region: &str,
        bucket: &str,
        plaintext: &[u8],
        kms_key_id: Option<&str>,
    ) -> Result<bytes::Bytes, AwsServiceError> {
        let Some(hook) = &self.kms_hook else {
            return Ok(bytes::Bytes::copy_from_slice(plaintext));
        };
        let key = kms_key_id.filter(|k| !k.is_empty()).unwrap_or("aws/s3");
        let bucket_arn = Arn::s3(bucket).to_string();
        let mut ctx = std::collections::HashMap::new();
        ctx.insert("aws:s3:arn".to_string(), bucket_arn);
        match hook.encrypt(account_id, region, key, plaintext, "s3.amazonaws.com", ctx) {
            Ok(envelope) => Ok(bytes::Bytes::from(envelope.into_bytes())),
            Err(err) => {
                tracing::warn!(bucket = %bucket, error = %err, "SSE-KMS encrypt failed");
                Err(AwsServiceError::aws_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "KMS.InternalFailureException",
                    format!("Failed to encrypt object via KMS: {err}"),
                ))
            }
        }
    }

    /// Decrypt object body bytes that were stored as a fakecloud-kms
    /// envelope. Caller is expected to gate this on
    /// `obj.sse_algorithm == Some("aws:kms")`.
    ///
    /// Fail-closed: when a hook is wired and the bytes look like an
    /// envelope but don't decrypt (key revoked, malformed ciphertext),
    /// this returns `Err` so GetObject surfaces a 500. When no hook is
    /// wired, or the bytes aren't UTF-8 (legacy snapshots from before
    /// the hook landed), the bytes are returned unchanged.
    pub(crate) fn decrypt_object_body(
        &self,
        account_id: &str,
        bucket: &str,
        ciphertext: &[u8],
    ) -> Result<bytes::Bytes, AwsServiceError> {
        let Some(hook) = &self.kms_hook else {
            return Ok(bytes::Bytes::copy_from_slice(ciphertext));
        };
        // Stored envelope is base64 ASCII; non-UTF-8 bytes are pre-hook
        // legacy snapshots, return as-is.
        let envelope = match std::str::from_utf8(ciphertext) {
            Ok(s) => s,
            Err(_) => return Ok(bytes::Bytes::copy_from_slice(ciphertext)),
        };
        let bucket_arn = Arn::s3(bucket).to_string();
        let mut ctx = std::collections::HashMap::new();
        ctx.insert("aws:s3:arn".to_string(), bucket_arn);
        match hook.decrypt(account_id, envelope, "s3.amazonaws.com", ctx) {
            Ok(bytes) => Ok(bytes::Bytes::from(bytes)),
            Err(err) => {
                tracing::warn!(bucket = %bucket, error = %err, "SSE-KMS decrypt failed");
                Err(AwsServiceError::aws_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "KMS.InternalFailureException",
                    format!("Failed to decrypt object via KMS: {err}"),
                ))
            }
        }
    }
}

#[async_trait]
impl AwsService for S3Service {
    fn service_name(&self) -> &str {
        "s3"
    }

    async fn handle(&self, mut req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        // PutObject / UploadPart enter dispatch via the streaming path
        // with `body = Bytes::new()` and the raw HTTP body available on
        // `req.body_stream`. Those handlers consume the stream directly
        // — spooling chunks to disk while computing MD5 + size in
        // constant memory — so a 1 GiB upload never materializes into
        // RAM. Every *other* PUT-on-bucket-key the streaming dispatch
        // flagged (PutObjectTagging, PutObjectAcl, PutObjectRetention,
        // PutObjectLegalHold, CopyObject, …) reads a small XML/JSON
        // body from `req.body`, so drain the stream for them.
        let is_put_to_key = req.method == Method::PUT
            && req.path_segments.len() >= 2
            && req
                .path_segments
                .first()
                .map(|s| !s.is_empty())
                .unwrap_or(false);
        let q = &req.query_params;
        let is_put_object = is_put_to_key
            && !q.contains_key("tagging")
            && !q.contains_key("acl")
            && !q.contains_key("retention")
            && !q.contains_key("legal-hold")
            && !q.contains_key("renameObject")
            && !q.contains_key("encryption")
            && !req.headers.contains_key("x-amz-copy-source");
        // UploadPart requires both partNumber AND uploadId; checking
        // only partNumber would skip body draining for stray PUTs that
        // happened to carry a partNumber query param without being a
        // real multipart upload.
        let is_upload_part =
            is_put_to_key && q.contains_key("partNumber") && q.contains_key("uploadId");
        if !is_put_object && !is_upload_part {
            if let Some(stream) = req.take_body_stream() {
                req.body = fakecloud_core::service::drain_request_stream(stream).await?;
            }
        }

        // S3 REST routing: method + path segments + query params
        let bucket = req.path_segments.first().map(|s| s.as_str());
        // Extract key from the raw path to preserve leading slashes and empty segments.
        // The raw path is like "/bucket/key/parts" — we strip the bucket prefix.
        let key = if let Some(b) = bucket {
            let prefix = format!("/{b}/");
            if req.raw_path.starts_with(&prefix) && req.raw_path.len() > prefix.len() {
                let raw_key = &req.raw_path[prefix.len()..];
                Some(
                    percent_encoding::percent_decode_str(raw_key)
                        .decode_utf8_lossy()
                        .into_owned(),
                )
            } else if req.path_segments.len() > 1 {
                let raw = req.path_segments[1..].join("/");
                Some(
                    percent_encoding::percent_decode_str(&raw)
                        .decode_utf8_lossy()
                        .into_owned(),
                )
            } else {
                None
            }
        } else {
            None
        };

        let account_id = req.account_id.as_str();

        // Multipart upload operations (checked before main match)
        if let Some(b) = bucket {
            // POST /{bucket}/{key}?uploads — CreateMultipartUpload
            if req.method == Method::POST
                && key.is_some()
                && req.query_params.contains_key("uploads")
            {
                return self.create_multipart_upload(account_id, &req, b, key.as_deref().unwrap());
            }

            // POST /{bucket}/{key}?restore
            if req.method == Method::POST
                && key.is_some()
                && req.query_params.contains_key("restore")
            {
                return self.restore_object(account_id, &req, b, key.as_deref().unwrap());
            }

            // POST /{bucket}/{key}?uploadId=X — CompleteMultipartUpload
            if req.method == Method::POST && key.is_some() {
                if let Some(upload_id) = req.query_params.get("uploadId").cloned() {
                    return self.complete_multipart_upload(
                        account_id,
                        &req,
                        b,
                        key.as_deref().unwrap(),
                        &upload_id,
                    );
                }
            }

            // PUT /{bucket}/{key}?partNumber=N&uploadId=X — UploadPart or UploadPartCopy
            if req.method == Method::PUT && key.is_some() {
                if let (Some(part_num_str), Some(upload_id)) = (
                    req.query_params.get("partNumber").cloned(),
                    req.query_params.get("uploadId").cloned(),
                ) {
                    if let Ok(part_number) = part_num_str.parse::<i64>() {
                        if req.headers.contains_key("x-amz-copy-source") {
                            return self.upload_part_copy(
                                account_id,
                                &req,
                                b,
                                key.as_deref().unwrap(),
                                &upload_id,
                                part_number,
                            );
                        }
                        return self
                            .upload_part(
                                account_id,
                                &req,
                                b,
                                key.as_deref().unwrap(),
                                &upload_id,
                                part_number,
                            )
                            .await;
                    }
                }
            }

            // DELETE /{bucket}/{key}?uploadId=X — AbortMultipartUpload
            if req.method == Method::DELETE && key.is_some() {
                if let Some(upload_id) = req.query_params.get("uploadId").cloned() {
                    return self.abort_multipart_upload(
                        account_id,
                        b,
                        key.as_deref().unwrap(),
                        &upload_id,
                    );
                }
            }

            // GET /{bucket}?uploads — ListMultipartUploads
            if req.method == Method::GET
                && key.is_none()
                && req.query_params.contains_key("uploads")
            {
                return self.list_multipart_uploads(account_id, b);
            }

            // GET /{bucket}/{key}?uploadId=X — ListParts
            if req.method == Method::GET && key.is_some() {
                if let Some(upload_id) = req.query_params.get("uploadId").cloned() {
                    return self.list_parts(
                        account_id,
                        &req,
                        b,
                        key.as_deref().unwrap(),
                        &upload_id,
                    );
                }
            }
        }

        // Handle OPTIONS preflight requests (CORS)
        if req.method == Method::OPTIONS {
            if let Some(b_name) = bucket {
                let cors_config = {
                    let accounts = self.state.read();
                    let _empty_s3 = crate::state::S3State::new(&req.account_id, &req.region);
                    let state = accounts.get(&req.account_id).unwrap_or(&_empty_s3);
                    state
                        .buckets
                        .get(b_name)
                        .and_then(|b| b.cors_config.clone())
                };
                if let Some(ref config) = cors_config {
                    let origin = req
                        .headers
                        .get("origin")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let request_method = req
                        .headers
                        .get("access-control-request-method")
                        .and_then(|v| v.to_str().ok())
                        .unwrap_or("");
                    let rules = parse_cors_config(config);
                    if let Some(rule) = find_cors_rule(&rules, origin, Some(request_method)) {
                        let mut headers = HeaderMap::new();
                        let matched_origin = if rule.allowed_origins.contains(&"*".to_string()) {
                            "*"
                        } else {
                            origin
                        };
                        headers.insert(
                            "access-control-allow-origin",
                            matched_origin
                                .parse()
                                .unwrap_or_else(|_| http::HeaderValue::from_static("")),
                        );
                        headers.insert(
                            "access-control-allow-methods",
                            rule.allowed_methods
                                .join(", ")
                                .parse()
                                .unwrap_or_else(|_| http::HeaderValue::from_static("")),
                        );
                        if !rule.allowed_headers.is_empty() {
                            let ah = if rule.allowed_headers.contains(&"*".to_string()) {
                                req.headers
                                    .get("access-control-request-headers")
                                    .and_then(|v| v.to_str().ok())
                                    .unwrap_or("*")
                                    .to_string()
                            } else {
                                rule.allowed_headers.join(", ")
                            };
                            headers.insert(
                                "access-control-allow-headers",
                                ah.parse()
                                    .unwrap_or_else(|_| http::HeaderValue::from_static("")),
                            );
                        }
                        if let Some(max_age) = rule.max_age_seconds {
                            headers.insert(
                                "access-control-max-age",
                                max_age
                                    .to_string()
                                    .parse()
                                    .unwrap_or_else(|_| http::HeaderValue::from_static("")),
                            );
                        }
                        return Ok(AwsResponse {
                            status: StatusCode::OK,
                            content_type: String::new(),
                            body: Bytes::new().into(),
                            headers,
                        });
                    }
                }
                return Err(AwsServiceError::aws_error(
                    StatusCode::FORBIDDEN,
                    "CORSResponse",
                    "CORS is not enabled for this bucket",
                ));
            }
        }

        // Capture origin for CORS response headers
        let origin_header = req
            .headers
            .get("origin")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let mut result = match (&req.method, bucket, key.as_deref()) {
            // ListBuckets: GET /
            (&Method::GET, None, None) => {
                if req.query_params.get("x-id").map(|s| s.as_str()) == Some("ListDirectoryBuckets")
                {
                    self.list_directory_buckets(account_id, &req)
                } else {
                    self.list_buckets(account_id, &req)
                }
            }

            // Bucket-level operations (no key)
            (&Method::PUT, Some(b), None) => {
                if req.query_params.contains_key("tagging") {
                    self.put_bucket_tagging(account_id, &req, b)
                } else if req.query_params.contains_key("acl") {
                    self.put_bucket_acl(account_id, &req, b)
                } else if req.query_params.contains_key("versioning") {
                    self.put_bucket_versioning(account_id, &req, b)
                } else if req.query_params.contains_key("cors") {
                    self.put_bucket_cors(account_id, &req, b)
                } else if req.query_params.contains_key("notification") {
                    self.put_bucket_notification(account_id, &req, b)
                } else if req.query_params.contains_key("website") {
                    self.put_bucket_website(account_id, &req, b)
                } else if req.query_params.contains_key("accelerate") {
                    self.put_bucket_accelerate(account_id, &req, b)
                } else if req.query_params.contains_key("publicAccessBlock") {
                    self.put_public_access_block(account_id, &req, b)
                } else if req.query_params.contains_key("encryption") {
                    self.put_bucket_encryption(account_id, &req, b)
                } else if req.query_params.contains_key("lifecycle") {
                    self.put_bucket_lifecycle(account_id, &req, b)
                } else if req.query_params.contains_key("logging") {
                    self.put_bucket_logging(account_id, &req, b)
                } else if req.query_params.contains_key("policy") {
                    self.put_bucket_policy(account_id, &req, b)
                } else if req.query_params.contains_key("object-lock") {
                    self.put_object_lock_config(account_id, &req, b)
                } else if req.query_params.contains_key("replication") {
                    self.put_bucket_replication(account_id, &req, b)
                } else if req.query_params.contains_key("ownershipControls") {
                    self.put_bucket_ownership_controls(account_id, &req, b)
                } else if req.query_params.contains_key("inventory") {
                    self.put_bucket_inventory(account_id, &req, b)
                } else if req.query_params.contains_key("analytics") {
                    self.put_bucket_analytics_config(account_id, &req, b)
                } else if req.query_params.contains_key("intelligent-tiering") {
                    self.put_bucket_intelligent_tiering_config(account_id, &req, b)
                } else if req.query_params.contains_key("metrics") {
                    self.put_bucket_metrics_config(account_id, &req, b)
                } else if req.query_params.contains_key("requestPayment") {
                    self.put_bucket_request_payment(account_id, &req, b)
                } else if req.query_params.contains_key("abac") {
                    self.put_bucket_abac(account_id, &req, b)
                } else if req.query_params.contains_key("metadataInventoryTable") {
                    self.update_bucket_metadata_inventory_table(account_id, &req, b)
                } else if req.query_params.contains_key("metadataJournalTable") {
                    self.update_bucket_metadata_journal_table(account_id, &req, b)
                } else {
                    self.create_bucket(account_id, &req, b)
                }
            }
            (&Method::DELETE, Some(b), None) => {
                if req.query_params.contains_key("tagging") {
                    self.delete_bucket_tagging(account_id, &req, b)
                } else if req.query_params.contains_key("cors") {
                    self.delete_bucket_cors(account_id, b)
                } else if req.query_params.contains_key("website") {
                    self.delete_bucket_website(account_id, b)
                } else if req.query_params.contains_key("publicAccessBlock") {
                    self.delete_public_access_block(account_id, b)
                } else if req.query_params.contains_key("encryption") {
                    self.delete_bucket_encryption(account_id, b)
                } else if req.query_params.contains_key("lifecycle") {
                    self.delete_bucket_lifecycle(account_id, b)
                } else if req.query_params.contains_key("policy") {
                    self.delete_bucket_policy(account_id, b)
                } else if req.query_params.contains_key("replication") {
                    self.delete_bucket_replication(account_id, b)
                } else if req.query_params.contains_key("ownershipControls") {
                    self.delete_bucket_ownership_controls(account_id, b)
                } else if req.query_params.contains_key("inventory") {
                    self.delete_bucket_inventory(account_id, &req, b)
                } else if req.query_params.contains_key("analytics") {
                    self.delete_bucket_analytics_config(account_id, &req, b)
                } else if req.query_params.contains_key("intelligent-tiering") {
                    self.delete_bucket_intelligent_tiering_config(account_id, &req, b)
                } else if req.query_params.contains_key("metrics") {
                    self.delete_bucket_metrics_config(account_id, &req, b)
                } else if req.query_params.contains_key("metadataConfiguration") {
                    self.delete_bucket_metadata_config(account_id, b)
                } else if req.query_params.contains_key("metadataTable") {
                    self.delete_bucket_metadata_table_config(account_id, b)
                } else {
                    self.delete_bucket(account_id, &req, b)
                }
            }
            (&Method::HEAD, Some(b), None) => self.head_bucket(account_id, b),
            (&Method::GET, Some(b), None) => {
                if req.query_params.contains_key("tagging") {
                    self.get_bucket_tagging(account_id, &req, b)
                } else if req.query_params.contains_key("location") {
                    self.get_bucket_location(account_id, b)
                } else if req.query_params.contains_key("acl") {
                    self.get_bucket_acl(account_id, &req, b)
                } else if req.query_params.contains_key("versioning") {
                    self.get_bucket_versioning(account_id, b)
                } else if req.query_params.contains_key("versions") {
                    self.list_object_versions(account_id, &req, b)
                } else if req.query_params.contains_key("object-lock") {
                    self.get_object_lock_configuration(account_id, b)
                } else if req.query_params.contains_key("cors") {
                    self.get_bucket_cors(account_id, b)
                } else if req.query_params.contains_key("notification") {
                    self.get_bucket_notification(account_id, b)
                } else if req.query_params.contains_key("website") {
                    self.get_bucket_website(account_id, b)
                } else if req.query_params.contains_key("accelerate") {
                    self.get_bucket_accelerate(account_id, b)
                } else if req.query_params.contains_key("publicAccessBlock") {
                    self.get_public_access_block(account_id, b)
                } else if req.query_params.contains_key("encryption") {
                    self.get_bucket_encryption(account_id, b)
                } else if req.query_params.contains_key("lifecycle") {
                    self.get_bucket_lifecycle(account_id, b)
                } else if req.query_params.contains_key("logging") {
                    self.get_bucket_logging(account_id, b)
                } else if req.query_params.contains_key("policy") {
                    self.get_bucket_policy(account_id, b)
                } else if req.query_params.contains_key("replication") {
                    self.get_bucket_replication(account_id, b)
                } else if req.query_params.contains_key("ownershipControls") {
                    self.get_bucket_ownership_controls(account_id, b)
                } else if req.query_params.contains_key("inventory") {
                    if req.query_params.contains_key("id") {
                        self.get_bucket_inventory(account_id, &req, b)
                    } else {
                        self.list_bucket_inventory_configurations(account_id, b)
                    }
                } else if req.query_params.contains_key("analytics") {
                    if req.query_params.contains_key("id") {
                        self.get_bucket_analytics_config(account_id, &req, b)
                    } else {
                        self.list_bucket_analytics_configurations(account_id, b)
                    }
                } else if req.query_params.contains_key("intelligent-tiering") {
                    if req.query_params.contains_key("id") {
                        self.get_bucket_intelligent_tiering_config(account_id, &req, b)
                    } else {
                        self.list_bucket_intelligent_tiering_configurations(account_id, b)
                    }
                } else if req.query_params.contains_key("metrics") {
                    if req.query_params.contains_key("id") {
                        self.get_bucket_metrics_config(account_id, &req, b)
                    } else {
                        self.list_bucket_metrics_configurations(account_id, b)
                    }
                } else if req.query_params.contains_key("requestPayment") {
                    self.get_bucket_request_payment(account_id, b)
                } else if req.query_params.contains_key("abac") {
                    self.get_bucket_abac(account_id, b)
                } else if req.query_params.contains_key("policyStatus") {
                    self.get_bucket_policy_status(account_id, b)
                } else if req.query_params.contains_key("metadataConfiguration") {
                    self.get_bucket_metadata_config(account_id, b)
                } else if req.query_params.contains_key("metadataTable") {
                    self.get_bucket_metadata_table_config(account_id, b)
                } else if req.query_params.contains_key("session") {
                    self.create_session(account_id, &req, b)
                } else if req.query_params.get("list-type").map(|s| s.as_str()) == Some("2") {
                    self.list_objects_v2(account_id, &req, b)
                } else if req.query_params.is_empty() {
                    // If bucket has website config and no query params, serve index document
                    let website_config = {
                        let accounts = self.state.read();
                        let _empty_s3 = crate::state::S3State::new(&req.account_id, &req.region);
                        let state = accounts.get(&req.account_id).unwrap_or(&_empty_s3);
                        state
                            .buckets
                            .get(b)
                            .and_then(|bkt| bkt.website_config.clone())
                    };
                    if let Some(ref config) = website_config {
                        if let Some(index_doc) = extract_xml_value(config, "Suffix").or_else(|| {
                            extract_xml_value(config, "IndexDocument").and_then(|inner| {
                                let open = "<Suffix>";
                                let close = "</Suffix>";
                                let s = inner.find(open)? + open.len();
                                let e = inner.find(close)?;
                                Some(inner[s..e].trim().to_string())
                            })
                        }) {
                            self.serve_website_object(account_id, &req, b, &index_doc, config)
                        } else {
                            self.list_objects_v1(account_id, &req, b)
                        }
                    } else {
                        self.list_objects_v1(account_id, &req, b)
                    }
                } else {
                    self.list_objects_v1(account_id, &req, b)
                }
            }

            // Object-level operations
            (&Method::PUT, Some(b), Some(k)) => {
                if req.query_params.contains_key("tagging") {
                    self.put_object_tagging(account_id, &req, b, k)
                } else if req.query_params.contains_key("acl") {
                    self.put_object_acl(account_id, &req, b, k)
                } else if req.query_params.contains_key("retention") {
                    self.put_object_retention(account_id, &req, b, k)
                } else if req.query_params.contains_key("legal-hold") {
                    self.put_object_legal_hold(account_id, &req, b, k)
                } else if req.query_params.contains_key("renameObject") {
                    self.rename_object(account_id, &req, b, k)
                } else if req.query_params.contains_key("encryption") {
                    self.update_object_encryption(account_id, &req, b, k)
                } else if req.headers.contains_key("x-amz-copy-source") {
                    self.copy_object(account_id, &req, b, k)
                } else {
                    self.put_object(account_id, &req, b, k).await
                }
            }
            (&Method::GET, Some(b), Some(k)) => {
                if req.query_params.contains_key("tagging") {
                    self.get_object_tagging(account_id, &req, b, k)
                } else if req.query_params.contains_key("acl") {
                    self.get_object_acl(account_id, &req, b, k)
                } else if req.query_params.contains_key("retention") {
                    self.get_object_retention(account_id, &req, b, k)
                } else if req.query_params.contains_key("legal-hold") {
                    self.get_object_legal_hold(account_id, &req, b, k)
                } else if req.query_params.contains_key("attributes") {
                    self.get_object_attributes(account_id, &req, b, k)
                } else if req.query_params.contains_key("torrent") {
                    self.get_object_torrent(account_id, &req, b, k)
                } else {
                    let result = self.get_object(account_id, &req, b, k);
                    // If object not found and bucket has website config, serve error document
                    let is_not_found = matches!(
                        &result,
                        Err(e) if e.code() == "NoSuchKey"
                    );
                    if is_not_found {
                        let website_config = {
                            let accounts = self.state.read();
                            let _empty_s3 =
                                crate::state::S3State::new(&req.account_id, &req.region);
                            let state = accounts.get(&req.account_id).unwrap_or(&_empty_s3);
                            state
                                .buckets
                                .get(b)
                                .and_then(|bkt| bkt.website_config.clone())
                        };
                        if let Some(ref config) = website_config {
                            if let Some(error_key) = extract_xml_value(config, "ErrorDocument")
                                .and_then(|inner| {
                                    let open = "<Key>";
                                    let close = "</Key>";
                                    let s = inner.find(open)? + open.len();
                                    let e = inner.find(close)?;
                                    Some(inner[s..e].trim().to_string())
                                })
                                .or_else(|| extract_xml_value(config, "Key"))
                            {
                                return self.serve_website_error(account_id, &req, b, &error_key);
                            }
                        }
                    }
                    result
                }
            }
            (&Method::DELETE, Some(b), Some(k)) => {
                if req.query_params.contains_key("tagging") {
                    self.delete_object_tagging(account_id, b, k)
                } else {
                    self.delete_object(account_id, &req, b, k)
                }
            }
            (&Method::HEAD, Some(b), Some(k)) => self.head_object(account_id, &req, b, k),

            // POST /{bucket}?delete — batch delete
            (&Method::POST, Some(b), None) if req.query_params.contains_key("delete") => {
                self.delete_objects(account_id, &req, b)
            }
            (&Method::POST, Some(b), None)
                if req.query_params.contains_key("metadataConfiguration") =>
            {
                self.create_bucket_metadata_config(account_id, &req, b)
            }
            (&Method::POST, Some(b), None) if req.query_params.contains_key("metadataTable") => {
                self.create_bucket_metadata_table_config(account_id, &req, b)
            }
            (&Method::POST, Some(b), Some(k))
                if req.query_params.get("select-type").map(|s| s.as_str()) == Some("2") =>
            {
                self.select_object_content(account_id, &req, b, k)
            }
            (&Method::POST, Some("WriteGetObjectResponse"), None) => {
                self.write_get_object_response(account_id, &req)
            }

            _ => Err(AwsServiceError::aws_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "The specified method is not allowed against this resource",
            )),
        };

        // Apply CORS headers to the response if Origin was present
        if let (Some(ref origin), Some(b_name)) = (&origin_header, bucket) {
            let cors_config = {
                let accounts = self.state.read();
                let _empty_s3 = crate::state::S3State::new(&req.account_id, &req.region);
                let state = accounts.get(&req.account_id).unwrap_or(&_empty_s3);
                state
                    .buckets
                    .get(b_name)
                    .and_then(|b| b.cors_config.clone())
            };
            if let Some(ref config) = cors_config {
                let rules = parse_cors_config(config);
                if let Some(rule) = find_cors_rule(&rules, origin, None) {
                    if let Ok(ref mut resp) = result {
                        let matched_origin = if rule.allowed_origins.contains(&"*".to_string()) {
                            "*"
                        } else {
                            origin
                        };
                        resp.headers.insert(
                            "access-control-allow-origin",
                            matched_origin
                                .parse()
                                .unwrap_or_else(|_| http::HeaderValue::from_static("")),
                        );
                        if !rule.expose_headers.is_empty() {
                            resp.headers.insert(
                                "access-control-expose-headers",
                                rule.expose_headers
                                    .join(", ")
                                    .parse()
                                    .unwrap_or_else(|_| http::HeaderValue::from_static("")),
                            );
                        }
                    }
                }
            }
        }

        // Write S3 access log entry if the source bucket has logging enabled
        if let Some(b_name) = bucket {
            let status_code = match &result {
                Ok(resp) => resp.status.as_u16(),
                Err(e) => e.status().as_u16(),
            };
            let op = logging::operation_name(&req.method, key.as_deref());
            logging::maybe_write_access_log(
                &self.state,
                &self.store,
                b_name,
                &logging::AccessLogRequest {
                    operation: op,
                    key: key.as_deref(),
                    status: status_code,
                    request_id: &req.request_id,
                    method: req.method.as_str(),
                    path: &req.raw_path,
                },
            );
        }

        result
    }

    fn supported_actions(&self) -> &[&str] {
        &[
            // Buckets
            "ListBuckets",
            "CreateBucket",
            "DeleteBucket",
            "HeadBucket",
            "GetBucketLocation",
            // Objects
            "PutObject",
            "GetObject",
            "DeleteObject",
            "HeadObject",
            "CopyObject",
            "DeleteObjects",
            "ListObjectsV2",
            "ListObjects",
            "ListObjectVersions",
            "GetObjectAttributes",
            "RestoreObject",
            // Object properties
            "PutObjectTagging",
            "GetObjectTagging",
            "DeleteObjectTagging",
            "PutObjectAcl",
            "GetObjectAcl",
            "PutObjectRetention",
            "GetObjectRetention",
            "PutObjectLegalHold",
            "GetObjectLegalHold",
            // Bucket configuration
            "PutBucketTagging",
            "GetBucketTagging",
            "DeleteBucketTagging",
            "PutBucketAcl",
            "GetBucketAcl",
            "PutBucketVersioning",
            "GetBucketVersioning",
            "PutBucketCors",
            "GetBucketCors",
            "DeleteBucketCors",
            "PutBucketNotificationConfiguration",
            "GetBucketNotificationConfiguration",
            "PutBucketWebsite",
            "GetBucketWebsite",
            "DeleteBucketWebsite",
            "PutBucketAccelerateConfiguration",
            "GetBucketAccelerateConfiguration",
            "PutPublicAccessBlock",
            "GetPublicAccessBlock",
            "DeletePublicAccessBlock",
            "PutBucketEncryption",
            "GetBucketEncryption",
            "DeleteBucketEncryption",
            "PutBucketLifecycleConfiguration",
            "GetBucketLifecycleConfiguration",
            "DeleteBucketLifecycle",
            "PutBucketLogging",
            "GetBucketLogging",
            "PutBucketPolicy",
            "GetBucketPolicy",
            "DeleteBucketPolicy",
            "PutObjectLockConfiguration",
            "GetObjectLockConfiguration",
            "PutBucketReplication",
            "GetBucketReplication",
            "DeleteBucketReplication",
            "PutBucketOwnershipControls",
            "GetBucketOwnershipControls",
            "DeleteBucketOwnershipControls",
            "PutBucketInventoryConfiguration",
            "GetBucketInventoryConfiguration",
            "DeleteBucketInventoryConfiguration",
            "ListBucketInventoryConfigurations",
            "PutBucketAnalyticsConfiguration",
            "GetBucketAnalyticsConfiguration",
            "DeleteBucketAnalyticsConfiguration",
            "ListBucketAnalyticsConfigurations",
            "PutBucketIntelligentTieringConfiguration",
            "GetBucketIntelligentTieringConfiguration",
            "DeleteBucketIntelligentTieringConfiguration",
            "ListBucketIntelligentTieringConfigurations",
            "PutBucketMetricsConfiguration",
            "GetBucketMetricsConfiguration",
            "DeleteBucketMetricsConfiguration",
            "ListBucketMetricsConfigurations",
            "PutBucketRequestPayment",
            "GetBucketRequestPayment",
            "PutBucketAbac",
            "GetBucketAbac",
            "GetBucketPolicyStatus",
            "CreateBucketMetadataConfiguration",
            "GetBucketMetadataConfiguration",
            "DeleteBucketMetadataConfiguration",
            "CreateBucketMetadataTableConfiguration",
            "GetBucketMetadataTableConfiguration",
            "DeleteBucketMetadataTableConfiguration",
            "UpdateBucketMetadataInventoryTableConfiguration",
            "UpdateBucketMetadataJournalTableConfiguration",
            "GetObjectTorrent",
            "RenameObject",
            "SelectObjectContent",
            "UpdateObjectEncryption",
            "WriteGetObjectResponse",
            "ListDirectoryBuckets",
            "CreateSession",
            // Multipart uploads
            "CreateMultipartUpload",
            "UploadPart",
            "UploadPartCopy",
            "CompleteMultipartUpload",
            "AbortMultipartUpload",
            "ListParts",
            "ListMultipartUploads",
        ]
    }

    fn iam_enforceable(&self) -> bool {
        true
    }

    /// S3 resources are either:
    /// - Bucket ARN (`arn:aws:s3:::bucket`) for bucket-level actions
    /// - Object ARN (`arn:aws:s3:::bucket/key`) for object-level actions
    /// - Wildcard (`*`) for `ListBuckets` which doesn't target a specific
    ///   resource
    ///
    /// S3 ARNs notably omit the account id and region — this is the one
    /// AWS service that carries neither in its ARN, because bucket names
    /// are globally unique.
    fn iam_action_for(&self, request: &AwsRequest) -> Option<fakecloud_core::auth::IamAction> {
        // S3 doesn't set `request.action` — the handler dispatches on
        // method + path + query params directly. Re-derive the action
        // name here so enforcement can match against IAM policies the
        // same way the real service would.
        let bucket = request.path_segments.first().map(|s| s.as_str());
        let key = if request.path_segments.len() > 1 {
            Some(request.path_segments[1..].join("/"))
        } else {
            None
        };
        let action = s3_detect_action(
            request.method.as_str(),
            bucket,
            key.as_deref(),
            &request.query_params,
        )?;
        let resource = s3_resource_for(action, bucket, key.as_deref());
        Some(fakecloud_core::auth::IamAction {
            service: "s3",
            action,
            resource,
        })
    }

    fn iam_condition_keys_for(
        &self,
        request: &AwsRequest,
        action: &fakecloud_core::auth::IamAction,
    ) -> std::collections::BTreeMap<String, Vec<String>> {
        s3_condition_keys(action.action, &request.query_params)
    }

    fn resource_tags_for(
        &self,
        resource_arn: &str,
    ) -> Option<std::collections::HashMap<String, String>> {
        s3_resource_tags(&self.state, resource_arn)
            .map(|m| m.into_iter().collect::<std::collections::HashMap<_, _>>())
    }

    fn request_tags_from(
        &self,
        request: &AwsRequest,
        action: &str,
    ) -> Option<std::collections::HashMap<String, String>> {
        s3_request_tags(request, action)
            .map(|m| m.into_iter().collect::<std::collections::HashMap<_, _>>())
    }
}

/// Extract service-specific IAM condition keys from an S3 request.
///
/// Today only `ListObjects` / `ListObjectsV2` expose keys (`s3:prefix`,
/// `s3:delimiter`, `s3:max-keys`) via their query params. Other actions
/// return an empty map so the evaluator's safe-fail semantics treat any
/// policy condition referencing an unknown key as "doesn't apply".
fn s3_condition_keys(
    action: &str,
    query: &std::collections::HashMap<String, String>,
) -> std::collections::BTreeMap<String, Vec<String>> {
    let mut out = std::collections::BTreeMap::new();
    if matches!(action, "ListObjects" | "ListObjectsV2") {
        // Both list variants share the same query param shape.
        if let Some(prefix) = query.get("prefix") {
            out.insert("s3:prefix".to_string(), vec![prefix.clone()]);
        }
        if let Some(delimiter) = query.get("delimiter") {
            out.insert("s3:delimiter".to_string(), vec![delimiter.clone()]);
        }
        if let Some(max_keys) = query.get("max-keys") {
            out.insert("s3:max-keys".to_string(), vec![max_keys.clone()]);
        }
    }
    out
}

/// Look up resource tags for an S3 ARN.
///
/// Bucket-level ARN (`arn:aws:s3:::bucket`) -> bucket tags.
/// Object-level ARN (`arn:aws:s3:::bucket/key`) -> object tags.
/// `*` (ListBuckets) -> `Some(empty)` (no resource to tag).
fn s3_resource_tags(
    state: &SharedS3State,
    resource_arn: &str,
) -> Option<std::collections::BTreeMap<String, String>> {
    if resource_arn == "*" {
        return Some(std::collections::BTreeMap::new());
    }
    // S3 ARNs: arn:aws:s3:::bucket or arn:aws:s3:::bucket/key
    let after_prefix = resource_arn.strip_prefix("arn:aws:s3:::")?;
    let mas = state.read();
    // S3 bucket names are globally unique; scan all accounts to find the bucket
    let bucket_name = after_prefix.split('/').next().unwrap_or(after_prefix);
    let state = mas
        .find_account(|s| s.buckets.contains_key(bucket_name))
        .and_then(|id| mas.get(id))
        .or_else(|| Some(mas.default_ref()))?;
    if let Some(slash_pos) = after_prefix.find('/') {
        // Object-level: bucket/key
        let bucket_name = &after_prefix[..slash_pos];
        let key = &after_prefix[slash_pos + 1..];
        let bucket = state.buckets.get(bucket_name)?;
        // Try current objects first, then versioned objects (latest version)
        if let Some(obj) = bucket.objects.get(key) {
            Some(obj.tags.clone())
        } else if let Some(versions) = bucket.object_versions.get(key) {
            versions.last().map(|v| v.tags.clone())
        } else {
            // Object doesn't exist yet (e.g. PutObject creating it)
            Some(std::collections::BTreeMap::new())
        }
    } else {
        // Bucket-level
        let bucket = state.buckets.get(after_prefix)?;
        Some(bucket.tags.clone())
    }
}

/// Extract tags from an S3 request body/headers.
///
/// S3 sends tags via:
/// - `x-amz-tagging` header (URL-encoded `key=value&...`) on PutObject
/// - XML body on PutBucketTagging / PutObjectTagging
fn s3_request_tags(
    request: &AwsRequest,
    action: &str,
) -> Option<std::collections::BTreeMap<String, String>> {
    match action {
        "PutObject" | "CopyObject" | "CreateMultipartUpload" => {
            // Tags come via x-amz-tagging header
            if let Some(tagging) = request.headers.get("x-amz-tagging") {
                let tags = parse_url_encoded_tags(tagging.to_str().unwrap_or(""));
                Some(tags.into_iter().collect())
            } else {
                Some(std::collections::BTreeMap::new())
            }
        }
        "PutBucketTagging" | "PutObjectTagging" => {
            // Tags come in XML body
            let body = std::str::from_utf8(&request.body).unwrap_or("");
            let tags = parse_tagging_xml(body);
            Some(tags.into_iter().collect())
        }
        _ => Some(std::collections::BTreeMap::new()),
    }
}

/// Derive the IAM action name from an S3 REST request. Handles the
/// common cases (GetObject, PutObject, DeleteObject, ListObjectsV2,
/// CreateBucket, ...) plus a subset of sub-resource operations
/// (`?acl`, `?tagging`, `?versioning`, `?policy`, `?cors`, `?website`,
/// `?lifecycle`, `?encryption`, `?logging`, `?notification`, `?replication`,
/// `?ownershipControls`, `?publicAccessBlock`, `?accelerate`, `?inventory`,
/// `?object-lock`, `?uploads`, `?uploadId`).
///
/// Returns `None` for requests that don't map to a known action — the
/// dispatch layer then skips enforcement for that request rather than
/// guessing (and a warn log fires via the "service is iam_enforceable
/// but has no mapping" branch in dispatch.rs).
fn s3_detect_action(
    method: &str,
    bucket: Option<&str>,
    key: Option<&str>,
    query: &std::collections::HashMap<String, String>,
) -> Option<&'static str> {
    let has = |q: &str| query.contains_key(q);
    let is_get = method == "GET";
    let is_put = method == "PUT";
    let is_post = method == "POST";
    let is_delete = method == "DELETE";

    // Service root
    if bucket.is_none() {
        return match method {
            "GET" => Some("ListBuckets"),
            _ => None,
        };
    }
    let has_key = key.is_some();

    // Multipart sub-resource forms
    if has_key && is_post && has("uploads") {
        return Some("CreateMultipartUpload");
    }
    if has_key && is_post && has("uploadId") {
        return Some("CompleteMultipartUpload");
    }
    if has_key && is_put && has("partNumber") && has("uploadId") {
        return Some("UploadPart");
    }
    if has_key && is_delete && has("uploadId") {
        return Some("AbortMultipartUpload");
    }
    if has_key && is_get && has("uploadId") {
        return Some("ListParts");
    }
    if !has_key && is_get && has("uploads") {
        return Some("ListMultipartUploads");
    }

    // Sub-resource-keyed actions (?acl, ?tagging, ...). Order matters
    // since a request can carry multiple; we pick the most specific.
    // Object-level sub-resources come first (key present).
    if has_key {
        if has("tagging") {
            return Some(match method {
                "GET" => "GetObjectTagging",
                "PUT" => "PutObjectTagging",
                "DELETE" => "DeleteObjectTagging",
                _ => return None,
            });
        }
        if has("acl") {
            return Some(match method {
                "GET" => "GetObjectAcl",
                "PUT" => "PutObjectAcl",
                _ => return None,
            });
        }
        if has("retention") {
            return Some(match method {
                "GET" => "GetObjectRetention",
                "PUT" => "PutObjectRetention",
                _ => return None,
            });
        }
        if has("legal-hold") {
            return Some(match method {
                "GET" => "GetObjectLegalHold",
                "PUT" => "PutObjectLegalHold",
                _ => return None,
            });
        }
        // Identified by cubic on PR #399: both ?attributes and ?restore
        // need method guards — otherwise e.g. GET /bucket/key?restore
        // would be classified as RestoreObject (POST-only in AWS) and
        // IAM-evaluated against s3:RestoreObject instead of s3:GetObject.
        if has("attributes") && is_get {
            return Some("GetObjectAttributes");
        }
        if has("restore") && is_post {
            return Some("RestoreObject");
        }
    }

    // Bucket-level sub-resources (key absent).
    if !has_key {
        if has("tagging") {
            return Some(match method {
                "GET" => "GetBucketTagging",
                "PUT" => "PutBucketTagging",
                "DELETE" => "DeleteBucketTagging",
                _ => return None,
            });
        }
        if has("acl") {
            return Some(match method {
                "GET" => "GetBucketAcl",
                "PUT" => "PutBucketAcl",
                _ => return None,
            });
        }
        if has("versioning") {
            return Some(match method {
                "GET" => "GetBucketVersioning",
                "PUT" => "PutBucketVersioning",
                _ => return None,
            });
        }
        if has("cors") {
            return Some(match method {
                "GET" => "GetBucketCors",
                "PUT" => "PutBucketCors",
                "DELETE" => "DeleteBucketCors",
                _ => return None,
            });
        }
        if has("policy") {
            return Some(match method {
                "GET" => "GetBucketPolicy",
                "PUT" => "PutBucketPolicy",
                "DELETE" => "DeleteBucketPolicy",
                _ => return None,
            });
        }
        if has("website") {
            return Some(match method {
                "GET" => "GetBucketWebsite",
                "PUT" => "PutBucketWebsite",
                "DELETE" => "DeleteBucketWebsite",
                _ => return None,
            });
        }
        if has("lifecycle") {
            return Some(match method {
                "GET" => "GetBucketLifecycleConfiguration",
                "PUT" => "PutBucketLifecycleConfiguration",
                "DELETE" => "DeleteBucketLifecycle",
                _ => return None,
            });
        }
        if has("encryption") {
            return Some(match method {
                "GET" => "GetBucketEncryption",
                "PUT" => "PutBucketEncryption",
                "DELETE" => "DeleteBucketEncryption",
                _ => return None,
            });
        }
        if has("logging") {
            return Some(match method {
                "GET" => "GetBucketLogging",
                "PUT" => "PutBucketLogging",
                _ => return None,
            });
        }
        if has("notification") {
            return Some(match method {
                "GET" => "GetBucketNotificationConfiguration",
                "PUT" => "PutBucketNotificationConfiguration",
                _ => return None,
            });
        }
        if has("replication") {
            return Some(match method {
                "GET" => "GetBucketReplication",
                "PUT" => "PutBucketReplication",
                "DELETE" => "DeleteBucketReplication",
                _ => return None,
            });
        }
        if has("ownershipControls") {
            return Some(match method {
                "GET" => "GetBucketOwnershipControls",
                "PUT" => "PutBucketOwnershipControls",
                "DELETE" => "DeleteBucketOwnershipControls",
                _ => return None,
            });
        }
        if has("publicAccessBlock") {
            return Some(match method {
                "GET" => "GetPublicAccessBlock",
                "PUT" => "PutPublicAccessBlock",
                "DELETE" => "DeletePublicAccessBlock",
                _ => return None,
            });
        }
        if has("accelerate") {
            return Some(match method {
                "GET" => "GetBucketAccelerateConfiguration",
                "PUT" => "PutBucketAccelerateConfiguration",
                _ => return None,
            });
        }
        if has("inventory") {
            return Some(match method {
                "GET" => "GetBucketInventoryConfiguration",
                "PUT" => "PutBucketInventoryConfiguration",
                "DELETE" => "DeleteBucketInventoryConfiguration",
                _ => return None,
            });
        }
        if has("analytics") {
            return Some(match method {
                "GET" if has("id") => "GetBucketAnalyticsConfiguration",
                "GET" => "ListBucketAnalyticsConfigurations",
                "PUT" => "PutBucketAnalyticsConfiguration",
                "DELETE" => "DeleteBucketAnalyticsConfiguration",
                _ => return None,
            });
        }
        if has("intelligent-tiering") {
            return Some(match method {
                "GET" if has("id") => "GetBucketIntelligentTieringConfiguration",
                "GET" => "ListBucketIntelligentTieringConfigurations",
                "PUT" => "PutBucketIntelligentTieringConfiguration",
                "DELETE" => "DeleteBucketIntelligentTieringConfiguration",
                _ => return None,
            });
        }
        if has("metrics") {
            return Some(match method {
                "GET" if has("id") => "GetBucketMetricsConfiguration",
                "GET" => "ListBucketMetricsConfigurations",
                "PUT" => "PutBucketMetricsConfiguration",
                "DELETE" => "DeleteBucketMetricsConfiguration",
                _ => return None,
            });
        }
        if has("requestPayment") {
            return Some(match method {
                "GET" => "GetBucketRequestPayment",
                "PUT" => "PutBucketRequestPayment",
                _ => return None,
            });
        }
        if has("policyStatus") && is_get {
            return Some("GetBucketPolicyStatus");
        }
        if has("metadataConfiguration") {
            return Some(match method {
                "GET" => "GetBucketMetadataConfiguration",
                "POST" => "CreateBucketMetadataConfiguration",
                "DELETE" => "DeleteBucketMetadataConfiguration",
                _ => return None,
            });
        }
        if has("metadataTable") {
            return Some(match method {
                "GET" => "GetBucketMetadataTableConfiguration",
                "POST" => "CreateBucketMetadataTableConfiguration",
                "DELETE" => "DeleteBucketMetadataTableConfiguration",
                _ => return None,
            });
        }
        if has("metadataInventoryTable") && is_put {
            return Some("UpdateBucketMetadataInventoryTableConfiguration");
        }
        if has("metadataJournalTable") && is_put {
            return Some("UpdateBucketMetadataJournalTableConfiguration");
        }
        if has("abac") && is_put {
            return Some("PutBucketAbacConfiguration");
        }
        if has("renameObject") && is_put {
            return Some("RenameObject");
        }
        if has("object-lock") {
            return Some(match method {
                "GET" => "GetObjectLockConfiguration",
                "PUT" => "PutObjectLockConfiguration",
                _ => return None,
            });
        }
        if has("location") {
            return Some("GetBucketLocation");
        }
        if is_post && has("delete") {
            return Some("DeleteObjects");
        }
        if is_get && has("versions") {
            return Some("ListObjectVersions");
        }
    }

    // Plain bucket/object methods.
    match (method, has_key) {
        ("GET", true) => Some("GetObject"),
        ("PUT", true) => {
            // CopyObject uses x-amz-copy-source but we don't have headers
            // handy here — treat both PutObject and CopyObject as PutObject
            // for IAM purposes; CopyObject additionally requires
            // s3:GetObject on the source but that's evaluated per-request
            // by real AWS, not on the PUT call itself.
            Some("PutObject")
        }
        ("DELETE", true) => Some("DeleteObject"),
        ("HEAD", true) => Some("HeadObject"),
        ("GET", false) => {
            if query.contains_key("list-type") {
                Some("ListObjectsV2")
            } else {
                Some("ListObjects")
            }
        }
        ("PUT", false) => Some("CreateBucket"),
        ("DELETE", false) => Some("DeleteBucket"),
        ("HEAD", false) => Some("HeadBucket"),
        _ => None,
    }
}

/// Build the S3 resource ARN for an action. Returns `*` for
/// `ListBuckets` (account-scoped), a bucket ARN for bucket-level
/// configuration actions, or an object ARN for object-level actions.
fn s3_resource_for(action: &'static str, bucket: Option<&str>, key: Option<&str>) -> String {
    // Object-level actions work on `bucket/key`.
    const OBJECT_ACTIONS: &[&str] = &[
        "PutObject",
        "GetObject",
        "DeleteObject",
        "HeadObject",
        "CopyObject",
        "GetObjectAttributes",
        "RestoreObject",
        "PutObjectTagging",
        "GetObjectTagging",
        "DeleteObjectTagging",
        "PutObjectAcl",
        "GetObjectAcl",
        "PutObjectRetention",
        "GetObjectRetention",
        "PutObjectLegalHold",
        "GetObjectLegalHold",
        "CreateMultipartUpload",
        "UploadPart",
        "UploadPartCopy",
        "CompleteMultipartUpload",
        "AbortMultipartUpload",
        "ListParts",
    ];
    if action == "ListBuckets" {
        return "*".to_string();
    }
    let Some(bucket) = bucket else {
        return "*".to_string();
    };
    if OBJECT_ACTIONS.contains(&action) {
        match key {
            Some(k) if !k.is_empty() => Arn::s3(&format!("{bucket}/{k}")).to_string(),
            _ => Arn::s3(&format!("{bucket}/*")).to_string(),
        }
    } else {
        // Bucket-level actions (ListObjectsV2, GetBucketTagging, ...).
        Arn::s3(bucket).to_string()
    }
}

// Conditional request helpers

/// Truncate a DateTime to second-level precision (HTTP dates have no sub-second info).
pub(crate) fn truncate_to_seconds(dt: DateTime<Utc>) -> DateTime<Utc> {
    dt.with_nanosecond(0).unwrap_or(dt)
}

pub(crate) fn check_get_conditionals(
    req: &AwsRequest,
    obj: &S3Object,
) -> Result<(), AwsServiceError> {
    let obj_etag = format!("\"{}\"", obj.etag);
    let obj_time = truncate_to_seconds(obj.last_modified);

    // If-Match
    if let Some(if_match) = req.headers.get("if-match").and_then(|v| v.to_str().ok()) {
        if !etag_matches(if_match, &obj_etag) {
            return Err(precondition_failed("If-Match"));
        }
    }

    // If-None-Match
    if let Some(if_none_match) = req
        .headers
        .get("if-none-match")
        .and_then(|v| v.to_str().ok())
    {
        if etag_matches(if_none_match, &obj_etag) {
            return Err(not_modified_with_etag(&obj_etag));
        }
    }

    // If-Unmodified-Since
    if let Some(since) = req
        .headers
        .get("if-unmodified-since")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(dt) = parse_http_date(since) {
            if obj_time > dt {
                return Err(precondition_failed("If-Unmodified-Since"));
            }
        }
    }

    // If-Modified-Since
    if let Some(since) = req
        .headers
        .get("if-modified-since")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(dt) = parse_http_date(since) {
            if obj_time <= dt {
                return Err(not_modified());
            }
        }
    }

    Ok(())
}

pub(crate) fn check_head_conditionals(
    req: &AwsRequest,
    obj: &S3Object,
) -> Result<(), AwsServiceError> {
    let obj_etag = format!("\"{}\"", obj.etag);
    let obj_time = truncate_to_seconds(obj.last_modified);

    // If-Match
    if let Some(if_match) = req.headers.get("if-match").and_then(|v| v.to_str().ok()) {
        if !etag_matches(if_match, &obj_etag) {
            return Err(AwsServiceError::aws_error(
                StatusCode::PRECONDITION_FAILED,
                "412",
                "Precondition Failed",
            ));
        }
    }

    // If-None-Match
    if let Some(if_none_match) = req
        .headers
        .get("if-none-match")
        .and_then(|v| v.to_str().ok())
    {
        if etag_matches(if_none_match, &obj_etag) {
            return Err(not_modified_with_etag(&obj_etag));
        }
    }

    // If-Unmodified-Since
    if let Some(since) = req
        .headers
        .get("if-unmodified-since")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(dt) = parse_http_date(since) {
            if obj_time > dt {
                return Err(AwsServiceError::aws_error(
                    StatusCode::PRECONDITION_FAILED,
                    "412",
                    "Precondition Failed",
                ));
            }
        }
    }

    // If-Modified-Since
    if let Some(since) = req
        .headers
        .get("if-modified-since")
        .and_then(|v| v.to_str().ok())
    {
        if let Some(dt) = parse_http_date(since) {
            if obj_time <= dt {
                return Err(not_modified());
            }
        }
    }

    Ok(())
}

pub(crate) fn etag_matches(condition: &str, obj_etag: &str) -> bool {
    let condition = condition.trim();
    if condition == "*" {
        return true;
    }
    let clean_etag = obj_etag.replace('"', "");
    // Split on comma to handle multi-value If-Match / If-None-Match
    for part in condition.split(',') {
        let part = part.trim().replace('"', "");
        if part == clean_etag {
            return true;
        }
    }
    false
}

pub(crate) fn parse_http_date(s: &str) -> Option<DateTime<Utc>> {
    // Try RFC 2822 format: "Sat, 01 Jan 2000 00:00:00 GMT"
    if let Ok(dt) = DateTime::parse_from_rfc2822(s) {
        return Some(dt.with_timezone(&Utc));
    }
    // Try RFC 3339
    if let Ok(dt) = DateTime::parse_from_rfc3339(s) {
        return Some(dt.with_timezone(&Utc));
    }
    // Try common HTTP date format: "%a, %d %b %Y %H:%M:%S GMT"
    if let Ok(dt) =
        chrono::NaiveDateTime::parse_from_str(s.trim_end_matches(" GMT"), "%a, %d %b %Y %H:%M:%S")
    {
        return Some(dt.and_utc());
    }
    // Try ISO 8601
    if let Ok(dt) = s.parse::<DateTime<Utc>>() {
        return Some(dt);
    }
    None
}

pub(crate) fn not_modified() -> AwsServiceError {
    AwsServiceError::aws_error(StatusCode::NOT_MODIFIED, "304", "Not Modified")
}

pub(crate) fn not_modified_with_etag(etag: &str) -> AwsServiceError {
    AwsServiceError::aws_error_with_headers(
        StatusCode::NOT_MODIFIED,
        "304",
        "Not Modified",
        vec![("etag".to_string(), etag.to_string())],
    )
}

pub(crate) fn precondition_failed(condition: &str) -> AwsServiceError {
    AwsServiceError::aws_error_with_fields(
        StatusCode::PRECONDITION_FAILED,
        "PreconditionFailed",
        "At least one of the pre-conditions you specified did not hold",
        vec![("Condition".to_string(), condition.to_string())],
    )
}

// ACL helpers

pub(crate) fn build_acl_xml(owner_id: &str, grants: &[AclGrant], _account_id: &str) -> String {
    let mut grants_xml = String::new();
    for g in grants {
        let grantee_xml = if g.grantee_type == "Group" {
            let uri = g.grantee_uri.as_deref().unwrap_or("");
            format!(
                "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"Group\">\
                 <URI>{}</URI></Grantee>",
                xml_escape(uri),
            )
        } else {
            let id = g.grantee_id.as_deref().unwrap_or("");
            format!(
                "<Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\">\
                 <ID>{}</ID></Grantee>",
                xml_escape(id),
            )
        };
        grants_xml.push_str(&format!(
            "<Grant>{grantee_xml}<Permission>{}</Permission></Grant>",
            xml_escape(&g.permission),
        ));
    }

    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <AccessControlPolicy xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
         <Owner><ID>{owner_id}</ID><DisplayName>{owner_id}</DisplayName></Owner>\
         <AccessControlList>{grants_xml}</AccessControlList>\
         </AccessControlPolicy>",
        owner_id = xml_escape(owner_id),
    )
}

pub(crate) fn canned_acl_grants(acl: &str, owner_id: &str) -> Vec<AclGrant> {
    let owner_grant = AclGrant {
        grantee_type: "CanonicalUser".to_string(),
        grantee_id: Some(owner_id.to_string()),
        grantee_display_name: Some(owner_id.to_string()),
        grantee_uri: None,
        permission: "FULL_CONTROL".to_string(),
    };
    match acl {
        "private" => vec![owner_grant],
        "public-read" => vec![
            owner_grant,
            AclGrant {
                grantee_type: "Group".to_string(),
                grantee_id: None,
                grantee_display_name: None,
                grantee_uri: Some("http://acs.amazonaws.com/groups/global/AllUsers".to_string()),
                permission: "READ".to_string(),
            },
        ],
        "public-read-write" => vec![
            owner_grant,
            AclGrant {
                grantee_type: "Group".to_string(),
                grantee_id: None,
                grantee_display_name: None,
                grantee_uri: Some("http://acs.amazonaws.com/groups/global/AllUsers".to_string()),
                permission: "READ".to_string(),
            },
            AclGrant {
                grantee_type: "Group".to_string(),
                grantee_id: None,
                grantee_display_name: None,
                grantee_uri: Some("http://acs.amazonaws.com/groups/global/AllUsers".to_string()),
                permission: "WRITE".to_string(),
            },
        ],
        "authenticated-read" => vec![
            owner_grant,
            AclGrant {
                grantee_type: "Group".to_string(),
                grantee_id: None,
                grantee_display_name: None,
                grantee_uri: Some(
                    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers".to_string(),
                ),
                permission: "READ".to_string(),
            },
        ],
        "bucket-owner-full-control" => vec![owner_grant],
        _ => vec![owner_grant],
    }
}

pub(crate) fn canned_acl_grants_for_object(acl: &str, owner_id: &str) -> Vec<AclGrant> {
    // For objects, canned ACLs work the same way
    canned_acl_grants(acl, owner_id)
}

pub(crate) fn parse_grant_headers(headers: &HeaderMap) -> Vec<AclGrant> {
    let mut grants = Vec::new();
    let header_permission_map = [
        ("x-amz-grant-read", "READ"),
        ("x-amz-grant-write", "WRITE"),
        ("x-amz-grant-read-acp", "READ_ACP"),
        ("x-amz-grant-write-acp", "WRITE_ACP"),
        ("x-amz-grant-full-control", "FULL_CONTROL"),
    ];

    for (header, permission) in &header_permission_map {
        if let Some(value) = headers.get(*header).and_then(|v| v.to_str().ok()) {
            // Parse "id=xxx" or "uri=xxx" or "emailAddress=xxx"
            for part in value.split(',') {
                let part = part.trim();
                if let Some((key, val)) = part.split_once('=') {
                    let val = val.trim().trim_matches('"');
                    let key = key.trim().to_lowercase();
                    match key.as_str() {
                        "id" => {
                            grants.push(AclGrant {
                                grantee_type: "CanonicalUser".to_string(),
                                grantee_id: Some(val.to_string()),
                                grantee_display_name: Some(val.to_string()),
                                grantee_uri: None,
                                permission: permission.to_string(),
                            });
                        }
                        "uri" | "url" => {
                            grants.push(AclGrant {
                                grantee_type: "Group".to_string(),
                                grantee_id: None,
                                grantee_display_name: None,
                                grantee_uri: Some(val.to_string()),
                                permission: permission.to_string(),
                            });
                        }
                        _ => {}
                    }
                }
            }
        }
    }
    grants
}

pub(crate) fn parse_acl_xml(xml: &str) -> Result<Vec<AclGrant>, AwsServiceError> {
    // Check for Owner presence
    if xml.contains("<AccessControlPolicy") && !xml.contains("<Owner>") {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "MalformedACLError",
            "The XML you provided was not well-formed or did not validate against our published schema",
        ));
    }

    let valid_permissions = ["READ", "WRITE", "READ_ACP", "WRITE_ACP", "FULL_CONTROL"];

    let mut grants = Vec::new();
    let mut remaining = xml;
    while let Some(start) = remaining.find("<Grant>") {
        let after = &remaining[start + 7..];
        if let Some(end) = after.find("</Grant>") {
            let grant_body = &after[..end];

            // Extract permission
            let permission = extract_xml_value(grant_body, "Permission").unwrap_or_default();
            if !valid_permissions.contains(&permission.as_str()) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "MalformedACLError",
                    "The XML you provided was not well-formed or did not validate against our published schema",
                ));
            }

            // Determine grantee type
            if grant_body.contains("xsi:type=\"Group\"") || grant_body.contains("<URI>") {
                let uri = extract_xml_value(grant_body, "URI").unwrap_or_default();
                grants.push(AclGrant {
                    grantee_type: "Group".to_string(),
                    grantee_id: None,
                    grantee_display_name: None,
                    grantee_uri: Some(uri),
                    permission,
                });
            } else {
                let id = extract_xml_value(grant_body, "ID").unwrap_or_default();
                let display =
                    extract_xml_value(grant_body, "DisplayName").unwrap_or_else(|| id.clone());
                grants.push(AclGrant {
                    grantee_type: "CanonicalUser".to_string(),
                    grantee_id: Some(id),
                    grantee_display_name: Some(display),
                    grantee_uri: None,
                    permission,
                });
            }

            remaining = &after[end + 8..];
        } else {
            break;
        }
    }
    Ok(grants)
}

// Range helpers

pub(crate) enum RangeResult {
    Satisfiable { start: usize, end: usize },
    NotSatisfiable,
    Ignored,
}

pub(crate) fn parse_range_header(range_str: &str, total_size: usize) -> Option<RangeResult> {
    let range_str = range_str.strip_prefix("bytes=")?;
    let (start_str, end_str) = range_str.split_once('-')?;
    if start_str.is_empty() {
        let suffix_len: usize = end_str.parse().ok()?;
        if suffix_len == 0 || total_size == 0 {
            return Some(RangeResult::NotSatisfiable);
        }
        let start = total_size.saturating_sub(suffix_len);
        Some(RangeResult::Satisfiable {
            start,
            end: total_size - 1,
        })
    } else {
        let start: usize = start_str.parse().ok()?;
        if start >= total_size {
            return Some(RangeResult::NotSatisfiable);
        }
        let end = if end_str.is_empty() {
            total_size - 1
        } else {
            let e: usize = end_str.parse().ok()?;
            if e < start {
                return Some(RangeResult::Ignored);
            }
            std::cmp::min(e, total_size - 1)
        };
        Some(RangeResult::Satisfiable { start, end })
    }
}

// Helpers

/// S3 XML response with `application/xml` content type (unlike Query protocol's `text/xml`).
pub(crate) fn s3_xml(status: StatusCode, body: impl Into<Bytes>) -> AwsResponse {
    AwsResponse {
        status,
        content_type: "application/xml".to_string(),
        body: body.into().into(),
        headers: HeaderMap::new(),
    }
}

pub(crate) fn empty_response(status: StatusCode) -> AwsResponse {
    AwsResponse {
        status,
        content_type: "application/xml".to_string(),
        body: Bytes::new().into(),
        headers: HeaderMap::new(),
    }
}

/// Returns true when the object is stored in a "cold" storage class (GLACIER, DEEP_ARCHIVE)
/// and has NOT been restored (or restore is still in progress).
pub(crate) fn is_frozen(obj: &S3Object) -> bool {
    matches!(obj.storage_class.as_str(), "GLACIER" | "DEEP_ARCHIVE")
        && obj.restore_ongoing != Some(false)
}

pub(crate) fn no_such_bucket(bucket: &str) -> AwsServiceError {
    AwsServiceError::aws_error_with_fields(
        StatusCode::NOT_FOUND,
        "NoSuchBucket",
        "The specified bucket does not exist",
        vec![("BucketName".to_string(), bucket.to_string())],
    )
}

pub(crate) fn no_such_key(key: &str) -> AwsServiceError {
    AwsServiceError::aws_error_with_fields(
        StatusCode::NOT_FOUND,
        "NoSuchKey",
        "The specified key does not exist.",
        vec![("Key".to_string(), key.to_string())],
    )
}

pub(crate) fn no_such_upload(upload_id: &str) -> AwsServiceError {
    AwsServiceError::aws_error_with_fields(
        StatusCode::NOT_FOUND,
        "NoSuchUpload",
        "The specified upload does not exist. The upload ID may be invalid, \
         or the upload may have been aborted or completed.",
        vec![("UploadId".to_string(), upload_id.to_string())],
    )
}

pub(crate) fn no_such_key_with_detail(key: &str) -> AwsServiceError {
    AwsServiceError::aws_error_with_fields(
        StatusCode::NOT_FOUND,
        "NoSuchKey",
        "The specified key does not exist.",
        vec![("Key".to_string(), key.to_string())],
    )
}

pub(crate) fn compute_md5(data: &[u8]) -> String {
    let digest = Md5::digest(data);
    format!("{:x}", digest)
}

pub(crate) fn compute_checksum(algorithm: &str, data: &[u8]) -> String {
    match algorithm {
        "CRC32" => {
            let crc = crc32fast::hash(data);
            BASE64.encode(crc.to_be_bytes())
        }
        "SHA1" => {
            use sha1::Digest as _;
            let hash = sha1::Sha1::digest(data);
            BASE64.encode(hash)
        }
        "SHA256" => {
            use sha2::Digest as _;
            let hash = sha2::Sha256::digest(data);
            BASE64.encode(hash)
        }
        _ => String::new(),
    }
}

/// Streaming variant of [`compute_checksum`] for spool files. Reads
/// the file in 1 MiB chunks and feeds each chunk into the hasher so a
/// 1 GiB upload computes its CRC32 / SHA-1 / SHA-256 in constant
/// memory rather than via `tokio::fs::read` (which would allocate the
/// whole file as one buffer).
pub(crate) async fn compute_checksum_streaming(
    algorithm: &str,
    path: &std::path::Path,
) -> Result<String, std::io::Error> {
    use tokio::io::AsyncReadExt;
    let mut file = tokio::fs::File::open(path).await?;
    let mut buf = vec![0u8; 1024 * 1024];
    match algorithm {
        "CRC32" => {
            let mut hasher = crc32fast::Hasher::new();
            loop {
                let n = file.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(BASE64.encode(hasher.finalize().to_be_bytes()))
        }
        "SHA1" => {
            use sha1::Digest as _;
            let mut hasher = sha1::Sha1::new();
            loop {
                let n = file.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(BASE64.encode(hasher.finalize()))
        }
        "SHA256" => {
            use sha2::Digest as _;
            let mut hasher = sha2::Sha256::new();
            loop {
                let n = file.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
            }
            Ok(BASE64.encode(hasher.finalize()))
        }
        _ => Ok(String::new()),
    }
}

pub(crate) fn url_encode_s3_key(s: &str) -> String {
    let mut out = String::with_capacity(s.len() * 2);
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' | b'/' => {
                out.push(byte as char);
            }
            _ => {
                out.push_str(&format!("%{:02X}", byte));
            }
        }
    }
    out
}

pub(crate) use fakecloud_aws::xml::xml_escape;

pub(crate) fn extract_user_metadata(
    headers: &HeaderMap,
) -> std::collections::BTreeMap<String, String> {
    let mut meta = std::collections::BTreeMap::new();
    for (name, value) in headers {
        if let Some(key) = name.as_str().strip_prefix("x-amz-meta-") {
            if let Ok(v) = value.to_str() {
                meta.insert(key.to_string(), v.to_string());
            }
        }
    }
    meta
}

pub(crate) fn is_valid_storage_class(class: &str) -> bool {
    matches!(
        class,
        "STANDARD"
            | "REDUCED_REDUNDANCY"
            | "STANDARD_IA"
            | "ONEZONE_IA"
            | "INTELLIGENT_TIERING"
            | "GLACIER"
            | "DEEP_ARCHIVE"
            | "GLACIER_IR"
            | "OUTPOSTS"
            | "SNOW"
            | "EXPRESS_ONEZONE"
    )
}

pub(crate) fn is_valid_bucket_name(name: &str) -> bool {
    if name.len() < 3 || name.len() > 63 {
        return false;
    }
    // Must start and end with alphanumeric
    let bytes = name.as_bytes();
    if !bytes[0].is_ascii_alphanumeric() || !bytes[bytes.len() - 1].is_ascii_alphanumeric() {
        return false;
    }
    // Only lowercase letters, digits, hyphens, dots (also allow underscores for compatibility)
    name.chars()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '.' || c == '_')
}

pub(crate) fn is_valid_region(region: &str) -> bool {
    // Basic validation: region should match pattern like us-east-1, eu-west-2, etc.
    let valid_regions = [
        "us-east-1",
        "us-east-2",
        "us-west-1",
        "us-west-2",
        "af-south-1",
        "ap-east-1",
        "ap-south-1",
        "ap-south-2",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-southeast-3",
        "ap-southeast-4",
        "ap-northeast-1",
        "ap-northeast-2",
        "ap-northeast-3",
        "ca-central-1",
        "ca-west-1",
        "eu-central-1",
        "eu-central-2",
        "eu-west-1",
        "eu-west-2",
        "eu-west-3",
        "eu-south-1",
        "eu-south-2",
        "eu-north-1",
        "il-central-1",
        "me-south-1",
        "me-central-1",
        "sa-east-1",
        "cn-north-1",
        "cn-northwest-1",
        "us-gov-east-1",
        "us-gov-east-2",
        "us-gov-west-1",
        "us-iso-east-1",
        "us-iso-west-1",
        "us-isob-east-1",
        "us-isof-south-1",
    ];
    valid_regions.contains(&region)
}

pub(crate) fn resolve_object<'a>(
    b: &'a S3Bucket,
    key: &str,
    version_id: Option<&String>,
) -> Result<&'a S3Object, AwsServiceError> {
    if let Some(vid) = version_id {
        // "null" version ID refers to an object with no version_id (pre-versioning)
        if vid == "null" {
            // Check versions for a pre-versioning object (version_id == None or Some("null"))
            if let Some(versions) = b.object_versions.get(key) {
                if let Some(obj) = versions
                    .iter()
                    .find(|o| o.version_id.is_none() || o.version_id.as_deref() == Some("null"))
                {
                    return Ok(obj);
                }
            }
            // Also check current object if it has no version_id
            if let Some(obj) = b.objects.get(key) {
                if obj.version_id.is_none() || obj.version_id.as_deref() == Some("null") {
                    return Ok(obj);
                }
            }
        } else {
            // When a specific versionId is requested, check versions first
            if let Some(versions) = b.object_versions.get(key) {
                if let Some(obj) = versions
                    .iter()
                    .find(|o| o.version_id.as_deref() == Some(vid.as_str()))
                {
                    return Ok(obj);
                }
            }
            // Also check current object
            if let Some(obj) = b.objects.get(key) {
                if obj.version_id.as_deref() == Some(vid.as_str()) {
                    return Ok(obj);
                }
            }
        }
        // For versioned buckets, return NoSuchVersion; for non-versioned, return 400
        if b.versioning.is_some() {
            Err(AwsServiceError::aws_error_with_fields(
                StatusCode::NOT_FOUND,
                "NoSuchVersion",
                "The specified version does not exist.",
                vec![
                    ("Key".to_string(), key.to_string()),
                    ("VersionId".to_string(), vid.to_string()),
                ],
            ))
        } else {
            Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidArgument",
                "Invalid version id specified",
            ))
        }
    } else {
        b.objects.get(key).ok_or_else(|| no_such_key(key))
    }
}

pub(crate) fn make_delete_marker(key: &str, dm_id: &str) -> S3Object {
    S3Object {
        key: key.to_string(),
        last_modified: Utc::now(),
        storage_class: "STANDARD".to_string(),
        version_id: Some(dm_id.to_string()),
        is_delete_marker: true,
        ..Default::default()
    }
}

/// Represents an object to delete in a batch delete request.
pub(crate) struct DeleteObjectEntry {
    key: String,
    version_id: Option<String>,
}

pub(crate) fn parse_delete_objects_xml(xml: &str) -> Vec<DeleteObjectEntry> {
    let mut entries = Vec::new();
    let mut remaining = xml;
    while let Some(obj_start) = remaining.find("<Object>") {
        let after = &remaining[obj_start + 8..];
        if let Some(obj_end) = after.find("</Object>") {
            let obj_body = &after[..obj_end];
            let key = extract_xml_value(obj_body, "Key");
            let version_id = extract_xml_value(obj_body, "VersionId");
            if let Some(k) = key {
                entries.push(DeleteObjectEntry { key: k, version_id });
            }
            remaining = &after[obj_end + 9..];
        } else {
            break;
        }
    }
    entries
}

/// Minimal XML parser for `<Tagging><TagSet><Tag><Key>k</Key><Value>v</Value></Tag>...`.
/// Returns a Vec to preserve insertion order and detect duplicates.
pub(crate) fn parse_tagging_xml(xml: &str) -> Vec<(String, String)> {
    let mut tags = Vec::new();
    let mut remaining = xml;
    while let Some(tag_start) = remaining.find("<Tag>") {
        let after = &remaining[tag_start + 5..];
        if let Some(tag_end) = after.find("</Tag>") {
            let tag_body = &after[..tag_end];
            let key = extract_xml_value(tag_body, "Key");
            let value = extract_xml_value(tag_body, "Value");
            if let (Some(k), Some(v)) = (key, value) {
                tags.push((k, v));
            }
            remaining = &after[tag_end + 6..];
        } else {
            break;
        }
    }
    tags
}

pub(crate) fn validate_tags(tags: &[(String, String)]) -> Result<(), AwsServiceError> {
    // Check for duplicate keys
    let mut seen = std::collections::HashSet::new();
    for (k, _) in tags {
        if !seen.insert(k.as_str()) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidTag",
                "Cannot provide multiple Tags with the same key",
            ));
        }
        // Check for aws: prefix
        if k.starts_with("aws:") {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidTag",
                "System tags cannot be added/updated by requester",
            ));
        }
    }
    Ok(())
}

pub(crate) fn extract_xml_value(xml: &str, tag: &str) -> Option<String> {
    // Handle self-closing tags like <Value /> or <Value/>
    let self_closing1 = format!("<{tag} />");
    let self_closing2 = format!("<{tag}/>");
    if xml.contains(&self_closing1) || xml.contains(&self_closing2) {
        // Check if the self-closing tag appears before any open+close pair
        let self_pos = xml
            .find(&self_closing1)
            .or_else(|| xml.find(&self_closing2));
        let open = format!("<{tag}>");
        let open_pos = xml.find(&open);
        match (self_pos, open_pos) {
            (Some(sp), Some(op)) if sp < op => return Some(String::new()),
            (Some(_), None) => return Some(String::new()),
            _ => {}
        }
    }

    let open = format!("<{tag}>");
    let close = format!("</{tag}>");
    let start = xml.find(&open)? + open.len();
    let end = xml.find(&close)?;
    Some(xml[start..end].to_string())
}

/// Parse the CompleteMultipartUpload XML body into (part_number, etag) pairs.
pub(crate) fn parse_complete_multipart_xml(xml: &str) -> Vec<(u32, String)> {
    let mut parts = Vec::new();
    let mut remaining = xml;
    while let Some(part_start) = remaining.find("<Part>") {
        let after = &remaining[part_start + 6..];
        if let Some(part_end) = after.find("</Part>") {
            let part_body = &after[..part_end];
            let part_num =
                extract_xml_value(part_body, "PartNumber").and_then(|s| s.parse::<u32>().ok());
            let etag = extract_xml_value(part_body, "ETag")
                .map(|s| s.replace("&quot;", "").replace('"', ""));
            if let (Some(num), Some(e)) = (part_num, etag) {
                parts.push((num, e));
            }
            remaining = &after[part_end + 7..];
        } else {
            break;
        }
    }
    parts
}

pub(crate) fn parse_url_encoded_tags(s: &str) -> Vec<(String, String)> {
    let mut tags = Vec::new();
    for pair in s.split('&') {
        if pair.is_empty() {
            continue;
        }
        let (key, value) = match pair.find('=') {
            Some(pos) => (&pair[..pos], &pair[pos + 1..]),
            None => (pair, ""),
        };
        tags.push((
            percent_encoding::percent_decode_str(key)
                .decode_utf8_lossy()
                .to_string(),
            percent_encoding::percent_decode_str(value)
                .decode_utf8_lossy()
                .to_string(),
        ));
    }
    tags
}

/// Validate lifecycle configuration XML. Returns MalformedXML on invalid configs.
pub(crate) fn validate_lifecycle_xml(xml: &str) -> Result<(), AwsServiceError> {
    let malformed = || {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "MalformedXML",
            "The XML you provided was not well-formed or did not validate against our published schema",
        )
    };

    let mut remaining = xml;
    while let Some(rule_start) = remaining.find("<Rule>") {
        let after = &remaining[rule_start + 6..];
        if let Some(rule_end) = after.find("</Rule>") {
            let rule_body = &after[..rule_end];

            // Must have Filter or Prefix
            let has_filter = rule_body.contains("<Filter>")
                || rule_body.contains("<Filter/>")
                || rule_body.contains("<Filter />");

            // Check for <Prefix> at rule level (outside of <Filter>...</Filter>)
            let has_prefix_outside_filter = {
                if !rule_body.contains("<Prefix") {
                    false
                } else if !has_filter {
                    true // No filter means any Prefix is at rule level
                } else {
                    // Remove the Filter block and check if Prefix remains
                    let mut stripped = rule_body.to_string();
                    // Remove <Filter>...</Filter> or self-closing variants
                    if let Some(fs) = stripped.find("<Filter") {
                        if let Some(fe) = stripped.find("</Filter>") {
                            stripped = format!("{}{}", &stripped[..fs], &stripped[fe + 9..]);
                        }
                    }
                    stripped.contains("<Prefix")
                }
            };

            if !has_filter && !has_prefix_outside_filter {
                return Err(malformed());
            }
            // Can't have both Filter and rule-level Prefix
            if has_filter && has_prefix_outside_filter {
                return Err(malformed());
            }

            // Expiration: if has ExpiredObjectDeleteMarker, cannot also have Days or Date
            // (only check within <Expiration> block)
            if let Some(exp_start) = rule_body.find("<Expiration>") {
                if let Some(exp_end) = rule_body[exp_start..].find("</Expiration>") {
                    let exp_body = &rule_body[exp_start..exp_start + exp_end];
                    if exp_body.contains("<ExpiredObjectDeleteMarker>")
                        && (exp_body.contains("<Days>") || exp_body.contains("<Date>"))
                    {
                        return Err(malformed());
                    }
                }
            }

            // Filter validation
            if has_filter {
                if let Some(fs) = rule_body.find("<Filter>") {
                    if let Some(fe) = rule_body.find("</Filter>") {
                        let filter_body = &rule_body[fs + 8..fe];
                        let has_prefix_in_filter = filter_body.contains("<Prefix");
                        let has_tag_in_filter = filter_body.contains("<Tag>");
                        let has_and_in_filter = filter_body.contains("<And>");
                        // Can't have both Prefix and Tag without And
                        if has_prefix_in_filter && has_tag_in_filter && !has_and_in_filter {
                            return Err(malformed());
                        }
                        // Can't have Tag and And simultaneously at the Filter level
                        if has_tag_in_filter && has_and_in_filter {
                            // Check if the <Tag> is outside <And>
                            let and_start = filter_body.find("<And>").unwrap_or(0);
                            let tag_pos = filter_body.find("<Tag>").unwrap_or(0);
                            if tag_pos < and_start {
                                return Err(malformed());
                            }
                        }
                    }
                }
            }

            // NoncurrentVersionTransition must have NoncurrentDays and StorageClass
            if rule_body.contains("<NoncurrentVersionTransition>") {
                let mut nvt_remaining = rule_body;
                while let Some(nvt_start) = nvt_remaining.find("<NoncurrentVersionTransition>") {
                    let nvt_after = &nvt_remaining[nvt_start + 29..];
                    if let Some(nvt_end) = nvt_after.find("</NoncurrentVersionTransition>") {
                        let nvt_body = &nvt_after[..nvt_end];
                        if !nvt_body.contains("<NoncurrentDays>") {
                            return Err(malformed());
                        }
                        if !nvt_body.contains("<StorageClass>") {
                            return Err(malformed());
                        }
                        nvt_remaining = &nvt_after[nvt_end + 30..];
                    } else {
                        break;
                    }
                }
            }

            remaining = &after[rule_end + 7..];
        } else {
            break;
        }
    }

    Ok(())
}

/// Parsed CORS rule from bucket configuration XML.
pub(crate) struct CorsRule {
    allowed_origins: Vec<String>,
    allowed_methods: Vec<String>,
    allowed_headers: Vec<String>,
    expose_headers: Vec<String>,
    max_age_seconds: Option<u32>,
}

/// Parse CORS configuration XML into rules.
pub(crate) fn parse_cors_config(xml: &str) -> Vec<CorsRule> {
    let mut rules = Vec::new();
    let mut remaining = xml;
    while let Some(start) = remaining.find("<CORSRule>") {
        let after = &remaining[start + 10..];
        if let Some(end) = after.find("</CORSRule>") {
            let block = &after[..end];
            let allowed_origins = extract_all_xml_values(block, "AllowedOrigin");
            let allowed_methods = extract_all_xml_values(block, "AllowedMethod");
            let allowed_headers = extract_all_xml_values(block, "AllowedHeader");
            let expose_headers = extract_all_xml_values(block, "ExposeHeader");
            let max_age_seconds =
                extract_xml_value(block, "MaxAgeSeconds").and_then(|s| s.parse().ok());
            rules.push(CorsRule {
                allowed_origins,
                allowed_methods,
                allowed_headers,
                expose_headers,
                max_age_seconds,
            });
            remaining = &after[end + 11..];
        } else {
            break;
        }
    }
    rules
}

/// Match an origin against a CORS allowed origin pattern (supports "*" wildcard).
pub(crate) fn origin_matches(origin: &str, pattern: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    // Simple wildcard: *.example.com
    if let Some(suffix) = pattern.strip_prefix('*') {
        return origin.ends_with(suffix);
    }
    origin == pattern
}

/// Find the matching CORS rule for a given origin and method.
pub(crate) fn find_cors_rule<'a>(
    rules: &'a [CorsRule],
    origin: &str,
    method: Option<&str>,
) -> Option<&'a CorsRule> {
    rules.iter().find(|rule| {
        let origin_ok = rule
            .allowed_origins
            .iter()
            .any(|o| origin_matches(origin, o));
        let method_ok = match method {
            Some(m) => rule.allowed_methods.iter().any(|am| am == m),
            None => true,
        };
        origin_ok && method_ok
    })
}

/// Check if an object is locked (retention or legal hold) and should block mutation.
/// Returns an error string if locked, None if allowed.
pub(crate) fn check_object_lock_for_overwrite(
    obj: &S3Object,
    req: &AwsRequest,
) -> Option<&'static str> {
    // Legal hold blocks overwrite
    if obj.lock_legal_hold.as_deref() == Some("ON") {
        return Some("AccessDenied");
    }
    // Retention check
    if let (Some(mode), Some(until)) = (&obj.lock_mode, &obj.lock_retain_until) {
        if *until > Utc::now() {
            if mode == "COMPLIANCE" {
                return Some("AccessDenied");
            }
            if mode == "GOVERNANCE" {
                let bypass = req
                    .headers
                    .get("x-amz-bypass-governance-retention")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                if !bypass {
                    return Some("AccessDenied");
                }
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn s3_condition_keys_emits_list_params() {
        let mut q = std::collections::HashMap::new();
        q.insert("prefix".to_string(), "logs/".to_string());
        q.insert("delimiter".to_string(), "/".to_string());
        q.insert("max-keys".to_string(), "100".to_string());
        let keys = s3_condition_keys("ListObjectsV2", &q);
        assert_eq!(keys.get("s3:prefix"), Some(&vec!["logs/".to_string()]));
        assert_eq!(keys.get("s3:delimiter"), Some(&vec!["/".to_string()]));
        assert_eq!(keys.get("s3:max-keys"), Some(&vec!["100".to_string()]));
    }

    #[test]
    fn s3_condition_keys_omits_absent_params() {
        let q = std::collections::HashMap::new();
        let keys = s3_condition_keys("ListObjectsV2", &q);
        assert!(keys.is_empty());
    }

    #[test]
    fn s3_condition_keys_partial_params() {
        let mut q = std::collections::HashMap::new();
        q.insert("prefix".to_string(), "archive/".to_string());
        let keys = s3_condition_keys("ListObjects", &q);
        assert_eq!(keys.len(), 1);
        assert_eq!(keys.get("s3:prefix"), Some(&vec!["archive/".to_string()]));
    }

    #[test]
    fn s3_condition_keys_empty_for_non_list_actions() {
        let mut q = std::collections::HashMap::new();
        q.insert("prefix".to_string(), "logs/".to_string());
        assert!(s3_condition_keys("GetObject", &q).is_empty());
        assert!(s3_condition_keys("PutObject", &q).is_empty());
        assert!(s3_condition_keys("ListBuckets", &q).is_empty());
    }

    #[test]
    fn valid_bucket_names() {
        assert!(is_valid_bucket_name("my-bucket"));
        assert!(is_valid_bucket_name("my.bucket.name"));
        assert!(is_valid_bucket_name("abc"));
        assert!(!is_valid_bucket_name("ab"));
        assert!(!is_valid_bucket_name("-bucket"));
        assert!(!is_valid_bucket_name("Bucket"));
        assert!(!is_valid_bucket_name("bucket-"));
    }

    #[test]
    fn parse_delete_xml() {
        let xml = r#"<Delete><Object><Key>a.txt</Key></Object><Object><Key>b/c.txt</Key></Object></Delete>"#;
        let entries = parse_delete_objects_xml(xml);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key, "a.txt");
        assert!(entries[0].version_id.is_none());
        assert_eq!(entries[1].key, "b/c.txt");
    }

    #[test]
    fn parse_delete_xml_with_version() {
        let xml = r#"<Delete><Object><Key>a.txt</Key><VersionId>v1</VersionId></Object></Delete>"#;
        let entries = parse_delete_objects_xml(xml);
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].key, "a.txt");
        assert_eq!(entries[0].version_id.as_deref(), Some("v1"));
    }

    #[test]
    fn parse_tags_xml() {
        let xml =
            r#"<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>"#;
        let tags = parse_tagging_xml(xml);
        assert_eq!(tags, vec![("env".to_string(), "prod".to_string())]);
    }

    #[test]
    fn md5_hash() {
        let hash = compute_md5(b"hello");
        assert_eq!(hash, "5d41402abc4b2a76b9719d911017c592");
    }

    #[test]
    fn test_etag_matches() {
        assert!(etag_matches("\"abc\"", "\"abc\""));
        assert!(etag_matches("abc", "\"abc\""));
        assert!(etag_matches("*", "\"abc\""));
        assert!(!etag_matches("\"xyz\"", "\"abc\""));
    }

    #[test]
    fn test_event_matches() {
        assert!(event_matches("s3:ObjectCreated:Put", "s3:ObjectCreated:*"));
        assert!(event_matches("s3:ObjectCreated:Copy", "s3:ObjectCreated:*"));
        assert!(event_matches(
            "s3:ObjectRemoved:Delete",
            "s3:ObjectRemoved:*"
        ));
        assert!(!event_matches(
            "s3:ObjectRemoved:Delete",
            "s3:ObjectCreated:*"
        ));
        assert!(event_matches(
            "s3:ObjectCreated:Put",
            "s3:ObjectCreated:Put"
        ));
        assert!(event_matches("s3:ObjectCreated:Put", "s3:*"));
    }

    #[test]
    fn test_parse_notification_config() {
        let xml = r#"<NotificationConfiguration>
            <QueueConfiguration>
                <Queue>arn:aws:sqs:us-east-1:123456789012:my-queue</Queue>
                <Event>s3:ObjectCreated:*</Event>
            </QueueConfiguration>
            <TopicConfiguration>
                <Topic>arn:aws:sns:us-east-1:123456789012:my-topic</Topic>
                <Event>s3:ObjectRemoved:*</Event>
            </TopicConfiguration>
        </NotificationConfiguration>"#;
        let targets = parse_notification_config(xml);
        assert_eq!(targets.len(), 2);
        assert_eq!(
            targets[0].arn,
            "arn:aws:sqs:us-east-1:123456789012:my-queue"
        );
        assert_eq!(targets[0].events, vec!["s3:ObjectCreated:*"]);
        assert_eq!(
            targets[1].arn,
            "arn:aws:sns:us-east-1:123456789012:my-topic"
        );
        assert_eq!(targets[1].events, vec!["s3:ObjectRemoved:*"]);
    }

    #[test]
    fn test_parse_notification_config_lambda() {
        // Test CloudFunctionConfiguration (older format)
        let xml = r#"<NotificationConfiguration>
            <CloudFunctionConfiguration>
                <CloudFunction>arn:aws:lambda:us-east-1:123456789012:function:my-func</CloudFunction>
                <Event>s3:ObjectCreated:*</Event>
            </CloudFunctionConfiguration>
        </NotificationConfiguration>"#;
        let targets = parse_notification_config(xml);
        assert_eq!(targets.len(), 1);
        assert!(matches!(
            targets[0].target_type,
            NotificationTargetType::Lambda
        ));
        assert_eq!(
            targets[0].arn,
            "arn:aws:lambda:us-east-1:123456789012:function:my-func"
        );
        assert_eq!(targets[0].events, vec!["s3:ObjectCreated:*"]);
    }

    #[test]
    fn test_parse_notification_config_lambda_new_format() {
        // Test LambdaFunctionConfiguration (newer format used by AWS SDK)
        let xml = r#"<NotificationConfiguration>
            <LambdaFunctionConfiguration>
                <Function>arn:aws:lambda:us-east-1:123456789012:function:my-func</Function>
                <Event>s3:ObjectCreated:Put</Event>
                <Event>s3:ObjectRemoved:*</Event>
            </LambdaFunctionConfiguration>
        </NotificationConfiguration>"#;
        let targets = parse_notification_config(xml);
        assert_eq!(targets.len(), 1);
        assert!(matches!(
            targets[0].target_type,
            NotificationTargetType::Lambda
        ));
        assert_eq!(
            targets[0].arn,
            "arn:aws:lambda:us-east-1:123456789012:function:my-func"
        );
        assert_eq!(
            targets[0].events,
            vec!["s3:ObjectCreated:Put", "s3:ObjectRemoved:*"]
        );
    }

    #[test]
    fn test_parse_notification_config_all_types() {
        let xml = r#"<NotificationConfiguration>
            <QueueConfiguration>
                <Queue>arn:aws:sqs:us-east-1:123456789012:q</Queue>
                <Event>s3:ObjectCreated:*</Event>
            </QueueConfiguration>
            <TopicConfiguration>
                <Topic>arn:aws:sns:us-east-1:123456789012:t</Topic>
                <Event>s3:ObjectRemoved:*</Event>
            </TopicConfiguration>
            <LambdaFunctionConfiguration>
                <Function>arn:aws:lambda:us-east-1:123456789012:function:f</Function>
                <Event>s3:ObjectCreated:Put</Event>
            </LambdaFunctionConfiguration>
        </NotificationConfiguration>"#;
        let targets = parse_notification_config(xml);
        assert_eq!(targets.len(), 3);
        assert!(matches!(
            targets[0].target_type,
            NotificationTargetType::Sqs
        ));
        assert!(matches!(
            targets[1].target_type,
            NotificationTargetType::Sns
        ));
        assert!(matches!(
            targets[2].target_type,
            NotificationTargetType::Lambda
        ));
    }

    #[test]
    fn test_parse_notification_config_with_filters() {
        let xml = r#"<NotificationConfiguration>
            <LambdaFunctionConfiguration>
                <Function>arn:aws:lambda:us-east-1:123456789012:function:my-func</Function>
                <Event>s3:ObjectCreated:*</Event>
                <Filter>
                    <S3Key>
                        <FilterRule>
                            <Name>prefix</Name>
                            <Value>images/</Value>
                        </FilterRule>
                        <FilterRule>
                            <Name>suffix</Name>
                            <Value>.jpg</Value>
                        </FilterRule>
                    </S3Key>
                </Filter>
            </LambdaFunctionConfiguration>
        </NotificationConfiguration>"#;
        let targets = parse_notification_config(xml);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].prefix_filter, Some("images/".to_string()));
        assert_eq!(targets[0].suffix_filter, Some(".jpg".to_string()));
    }

    #[test]
    fn test_parse_notification_config_no_filters() {
        let xml = r#"<NotificationConfiguration>
            <LambdaFunctionConfiguration>
                <Function>arn:aws:lambda:us-east-1:123456789012:function:my-func</Function>
                <Event>s3:ObjectCreated:*</Event>
            </LambdaFunctionConfiguration>
        </NotificationConfiguration>"#;
        let targets = parse_notification_config(xml);
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].prefix_filter, None);
        assert_eq!(targets[0].suffix_filter, None);
    }

    #[test]
    fn test_key_matches_filters() {
        // No filters — everything matches
        assert!(key_matches_filters("anything", &None, &None));

        // Prefix only
        assert!(key_matches_filters(
            "images/photo.jpg",
            &Some("images/".to_string()),
            &None
        ));
        assert!(!key_matches_filters(
            "docs/file.txt",
            &Some("images/".to_string()),
            &None
        ));

        // Suffix only
        assert!(key_matches_filters(
            "images/photo.jpg",
            &None,
            &Some(".jpg".to_string())
        ));
        assert!(!key_matches_filters(
            "images/photo.png",
            &None,
            &Some(".jpg".to_string())
        ));

        // Both prefix and suffix
        assert!(key_matches_filters(
            "images/photo.jpg",
            &Some("images/".to_string()),
            &Some(".jpg".to_string())
        ));
        assert!(!key_matches_filters(
            "images/photo.png",
            &Some("images/".to_string()),
            &Some(".jpg".to_string())
        ));
        assert!(!key_matches_filters(
            "docs/photo.jpg",
            &Some("images/".to_string()),
            &Some(".jpg".to_string())
        ));
    }

    #[test]
    fn test_parse_cors_config() {
        let xml = r#"<CORSConfiguration>
            <CORSRule>
                <AllowedOrigin>https://example.com</AllowedOrigin>
                <AllowedMethod>GET</AllowedMethod>
                <AllowedMethod>PUT</AllowedMethod>
                <AllowedHeader>*</AllowedHeader>
                <ExposeHeader>x-amz-request-id</ExposeHeader>
                <MaxAgeSeconds>3600</MaxAgeSeconds>
            </CORSRule>
        </CORSConfiguration>"#;
        let rules = parse_cors_config(xml);
        assert_eq!(rules.len(), 1);
        assert_eq!(rules[0].allowed_origins, vec!["https://example.com"]);
        assert_eq!(rules[0].allowed_methods, vec!["GET", "PUT"]);
        assert_eq!(rules[0].allowed_headers, vec!["*"]);
        assert_eq!(rules[0].expose_headers, vec!["x-amz-request-id"]);
        assert_eq!(rules[0].max_age_seconds, Some(3600));
    }

    #[test]
    fn test_origin_matches() {
        assert!(origin_matches("https://example.com", "https://example.com"));
        assert!(origin_matches("https://example.com", "*"));
        assert!(origin_matches("https://foo.example.com", "*.example.com"));
        assert!(!origin_matches("https://evil.com", "https://example.com"));
    }

    /// Regression: resolve_object with versionId="null" must match objects
    /// whose version_id is either None or Some("null").
    #[test]
    fn resolve_null_version_matches_both_none_and_null_string() {
        use crate::state::S3Bucket;
        use bytes::Bytes;
        use chrono::Utc;

        let mut b = S3Bucket::new("test", "us-east-1", "owner");

        // Helper to create a minimal S3Object
        let make_obj = |key: &str, vid: Option<&str>| crate::state::S3Object {
            key: key.to_string(),
            body: crate::state::memory_body(Bytes::from_static(b"x")),
            content_type: "text/plain".to_string(),
            etag: "\"abc\"".to_string(),
            size: 1,
            last_modified: Utc::now(),
            storage_class: "STANDARD".to_string(),
            version_id: vid.map(|s| s.to_string()),
            ..Default::default()
        };

        // Object with version_id = Some("null") (pre-versioning migrated)
        let obj = make_obj("file.txt", Some("null"));
        b.objects.insert("file.txt".to_string(), obj.clone());
        b.object_versions.insert("file.txt".to_string(), vec![obj]);

        let null_str = "null".to_string();
        let result = resolve_object(&b, "file.txt", Some(&null_str));
        assert!(
            result.is_ok(),
            "versionId=null should match version_id=Some(\"null\")"
        );

        // Object with version_id = None (true pre-versioning)
        let obj2 = make_obj("file2.txt", None);
        b.objects.insert("file2.txt".to_string(), obj2.clone());
        b.object_versions
            .insert("file2.txt".to_string(), vec![obj2]);

        let result2 = resolve_object(&b, "file2.txt", Some(&null_str));
        assert!(
            result2.is_ok(),
            "versionId=null should match version_id=None"
        );
    }

    #[test]
    fn test_parse_replication_rules() {
        let xml = r#"<ReplicationConfiguration>
            <Role>arn:aws:iam::role/replication</Role>
            <Rule>
                <Status>Enabled</Status>
                <Filter><Prefix>logs/</Prefix></Filter>
                <Destination><Bucket>arn:aws:s3:::dest-bucket</Bucket></Destination>
            </Rule>
            <Rule>
                <Status>Disabled</Status>
                <Filter><Prefix></Prefix></Filter>
                <Destination><Bucket>arn:aws:s3:::other-bucket</Bucket></Destination>
            </Rule>
        </ReplicationConfiguration>"#;

        let rules = parse_replication_rules(xml);
        assert_eq!(rules.len(), 2);
        assert_eq!(rules[0].status, "Enabled");
        assert_eq!(rules[0].prefix, "logs/");
        assert_eq!(rules[0].dest_bucket, "dest-bucket");
        assert_eq!(rules[1].status, "Disabled");
        assert_eq!(rules[1].prefix, "");
        assert_eq!(rules[1].dest_bucket, "other-bucket");
    }

    #[test]
    fn test_parse_normalized_replication_rules() {
        // First, normalize the XML like the server does
        let input_xml = r#"<ReplicationConfiguration xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Role>arn:aws:iam::123456789012:role/replication-role</Role><Rule><ID>replicate-all</ID><Status>Enabled</Status><Filter><Prefix></Prefix></Filter><Destination><Bucket>arn:aws:s3:::repl-dest</Bucket></Destination></Rule></ReplicationConfiguration>"#;
        let normalized = normalize_replication_xml(input_xml);
        eprintln!("Normalized XML: {normalized}");
        let rules = parse_replication_rules(&normalized);
        assert_eq!(rules.len(), 1, "Expected 1 rule, got {}", rules.len());
        assert_eq!(rules[0].status, "Enabled");
        assert_eq!(rules[0].dest_bucket, "repl-dest");
    }

    #[test]
    fn test_replicate_object() {
        use crate::state::{S3Bucket, S3State};

        let mut state = S3State::new("123456789012", "us-east-1");

        // Create source and destination buckets
        let mut src = S3Bucket::new("source", "us-east-1", "owner");
        src.versioning = Some("Enabled".to_string());
        src.replication_config = Some(
            "<ReplicationConfiguration>\
             <Rule><Status>Enabled</Status>\
             <Filter><Prefix></Prefix></Filter>\
             <Destination><Bucket>arn:aws:s3:::destination</Bucket></Destination>\
             </Rule></ReplicationConfiguration>"
                .to_string(),
        );
        let obj = S3Object {
            key: "test-key".to_string(),
            body: crate::state::memory_body(Bytes::from_static(b"hello")),
            content_type: "text/plain".to_string(),
            etag: "abc".to_string(),
            size: 5,
            last_modified: Utc::now(),
            storage_class: "STANDARD".to_string(),
            version_id: Some("v1".to_string()),
            ..Default::default()
        };
        src.objects.insert("test-key".to_string(), obj);
        state.buckets.insert("source".to_string(), src);

        let dest = S3Bucket::new("destination", "us-east-1", "owner");
        state.buckets.insert("destination".to_string(), dest);

        replicate_object(&mut state, "source", "test-key");

        // Object should now exist in destination
        let dest_obj = state
            .buckets
            .get("destination")
            .unwrap()
            .objects
            .get("test-key");
        assert!(dest_obj.is_some());
        assert_eq!(
            state.read_body(&dest_obj.unwrap().body).unwrap(),
            Bytes::from_static(b"hello")
        );
    }

    #[test]
    fn cors_header_value_does_not_panic_on_unusual_input() {
        // Verify that CORS header value parsing doesn't panic even with unusual strings.
        // HeaderValue::from_str rejects non-visible-ASCII, so our unwrap_or_else fallback
        // must produce a valid (empty) header value instead of panicking.
        let valid_origin = "https://example.com";
        let result: Result<http::HeaderValue, _> = valid_origin.parse();
        assert!(result.is_ok());

        // Non-ASCII would fail .parse() for HeaderValue; verify fallback works
        let bad_origin = "https://ex\x01ample.com";
        let result: Result<http::HeaderValue, _> = bad_origin.parse();
        assert!(result.is_err());
        // Our production code uses unwrap_or_else to return empty HeaderValue
        let fallback = bad_origin
            .parse()
            .unwrap_or_else(|_| http::HeaderValue::from_static(""));
        assert_eq!(fallback, "");
    }

    // ────────────────────────────────────────────────────────────────
    // Service-level tests for tags / multipart / config submodules.
    //
    // Each helper below builds an isolated S3Service with the in-memory
    // store so the submodule handlers can be driven directly without a
    // running Axum router.
    // ────────────────────────────────────────────────────────────────

    use crate::state::{S3Bucket, S3Object};
    use bytes::Bytes;
    use fakecloud_core::delivery::DeliveryBus;
    use fakecloud_core::service::{AwsRequest, AwsServiceError};
    use http::{HeaderMap, Method, StatusCode};
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn make_service() -> S3Service {
        let state: SharedS3State = Arc::new(RwLock::new(
            fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", ""),
        ));
        S3Service::new(state, Arc::new(DeliveryBus::new()))
    }

    fn seed_bucket(svc: &S3Service, name: &str) {
        let mut mas = svc.state.write();
        let state = mas.default_mut();
        state
            .buckets
            .insert(name.to_string(), S3Bucket::new(name, "us-east-1", "owner"));
    }

    fn seed_object(svc: &S3Service, bucket: &str, key: &str, body: &[u8]) {
        let mut mas = svc.state.write();
        let state = mas.default_mut();
        let b = state.buckets.get_mut(bucket).expect("bucket seeded");
        let mut obj = S3Object {
            key: key.to_string(),
            body: fakecloud_persistence::BodyRef::Memory(Bytes::copy_from_slice(body)),
            content_type: "application/octet-stream".to_string(),
            etag: format!("\"{}\"", compute_md5(body)),
            size: body.len() as u64,
            last_modified: chrono::Utc::now(),
            ..Default::default()
        };
        obj.metadata.insert("version".to_string(), "1".to_string());
        b.objects.insert(key.to_string(), obj);
    }

    fn make_request(method: Method, path: &str, query: &[(&str, &str)], body: &[u8]) -> AwsRequest {
        let segments: Vec<String> = path
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        let query_params: HashMap<String, String> = query
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect();
        let raw_query = query
            .iter()
            .map(|(k, v)| format!("{k}={v}"))
            .collect::<Vec<_>>()
            .join("&");
        // Wire body_stream from the same bytes so streaming-only handlers
        // (put_object, upload_part) can consume it. Buffered handlers
        // (put_object_tagging, put_object_acl, …) read `body` directly
        // and ignore the stream.
        let stream_body =
            fakecloud_core::service::RequestBodyStream::from(Bytes::copy_from_slice(body));
        AwsRequest {
            service: "s3".to_string(),
            action: String::new(),
            region: "us-east-1".to_string(),
            account_id: "123456789012".to_string(),
            request_id: "test-req".to_string(),
            headers: HeaderMap::new(),
            query_params,
            body: Bytes::copy_from_slice(body),
            body_stream: parking_lot::Mutex::new(Some(stream_body)),
            path_segments: segments,
            raw_path: path.to_string(),
            raw_query,
            method,
            is_query_protocol: false,
            access_key_id: None,
            principal: None,
        }
    }

    fn assert_aws_err(
        result: Result<AwsResponse, AwsServiceError>,
        expect_code: &str,
    ) -> AwsServiceError {
        let err = match result {
            Ok(_) => panic!("expected error, got Ok response"),
            Err(e) => e,
        };
        match &err {
            AwsServiceError::AwsError { code, .. } => {
                assert_eq!(code, expect_code, "wrong error code");
            }
            other => panic!("expected AwsError, got {other:?}"),
        }
        err
    }

    // ── Tags (service/tags.rs) ───────────────────────────────────────

    #[test]
    fn get_object_tagging_on_object_returns_xml_tagset() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        seed_object(&svc, "b", "k", b"hello");
        {
            let mut mas = svc.state.write();
            let obj = mas
                .default_mut()
                .buckets
                .get_mut("b")
                .unwrap()
                .objects
                .get_mut("k")
                .unwrap();
            obj.tags.insert("env".to_string(), "prod".to_string());
            obj.tags.insert("team".to_string(), "plat".to_string());
        }

        let req = make_request(Method::GET, "/b/k", &[("tagging", "")], b"");
        let resp = svc
            .get_object_tagging("123456789012", &req, "b", "k")
            .unwrap();
        assert_eq!(resp.status, StatusCode::OK);
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<Tag><Key>env</Key><Value>prod</Value></Tag>"));
        assert!(body.contains("<Tag><Key>team</Key><Value>plat</Value></Tag>"));
    }

    #[test]
    fn get_object_tagging_missing_bucket_errors() {
        let svc = make_service();
        let req = make_request(Method::GET, "/nope/k", &[("tagging", "")], b"");
        assert_aws_err(
            svc.get_object_tagging("123456789012", &req, "nope", "k"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn put_object_tagging_rejects_aws_prefixed_key() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        seed_object(&svc, "b", "k", b"x");

        let xml = r#"<Tagging><TagSet><Tag><Key>aws:internal</Key><Value>v</Value></Tag></TagSet></Tagging>"#;
        let req = make_request(Method::PUT, "/b/k", &[("tagging", "")], xml.as_bytes());
        assert_aws_err(
            svc.put_object_tagging("123456789012", &req, "b", "k"),
            "InvalidTag",
        );
    }

    #[test]
    fn put_object_tagging_rejects_too_many_tags() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        seed_object(&svc, "b", "k", b"x");

        let mut xml = String::from("<Tagging><TagSet>");
        for i in 0..11 {
            xml.push_str(&format!("<Tag><Key>k{i}</Key><Value>v</Value></Tag>"));
        }
        xml.push_str("</TagSet></Tagging>");
        let req = make_request(Method::PUT, "/b/k", &[("tagging", "")], xml.as_bytes());
        assert_aws_err(
            svc.put_object_tagging("123456789012", &req, "b", "k"),
            "BadRequest",
        );
    }

    #[test]
    fn put_object_tagging_on_missing_object_errors() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let xml =
            r#"<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>"#;
        let req = make_request(
            Method::PUT,
            "/b/missing",
            &[("tagging", "")],
            xml.as_bytes(),
        );
        assert_aws_err(
            svc.put_object_tagging("123456789012", &req, "b", "missing"),
            "NoSuchKey",
        );
    }

    #[test]
    fn put_object_tagging_replaces_existing_tags() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        seed_object(&svc, "b", "k", b"x");
        {
            let mut mas = svc.state.write();
            let obj = mas
                .default_mut()
                .buckets
                .get_mut("b")
                .unwrap()
                .objects
                .get_mut("k")
                .unwrap();
            obj.tags.insert("old".to_string(), "gone".to_string());
        }

        let xml =
            r#"<Tagging><TagSet><Tag><Key>new</Key><Value>here</Value></Tag></TagSet></Tagging>"#;
        let req = make_request(Method::PUT, "/b/k", &[("tagging", "")], xml.as_bytes());
        let resp = svc
            .put_object_tagging("123456789012", &req, "b", "k")
            .unwrap();
        assert_eq!(resp.status, StatusCode::OK);

        let __mas = svc.state.read();
        let state = __mas.default_ref();
        let tags = &state
            .buckets
            .get("b")
            .unwrap()
            .objects
            .get("k")
            .unwrap()
            .tags;
        assert_eq!(tags.get("new").map(String::as_str), Some("here"));
        assert!(!tags.contains_key("old"));
    }

    #[test]
    fn delete_object_tagging_clears_tags() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        seed_object(&svc, "b", "k", b"x");
        {
            let mut mas = svc.state.write();
            let obj = mas
                .default_mut()
                .buckets
                .get_mut("b")
                .unwrap()
                .objects
                .get_mut("k")
                .unwrap();
            obj.tags.insert("env".to_string(), "prod".to_string());
        }

        let resp = svc.delete_object_tagging("123456789012", "b", "k").unwrap();
        assert_eq!(resp.status, StatusCode::NO_CONTENT);
        let __mas = svc.state.read();
        let state = __mas.default_ref();
        assert!(state
            .buckets
            .get("b")
            .unwrap()
            .objects
            .get("k")
            .unwrap()
            .tags
            .is_empty());
    }

    #[test]
    fn delete_object_tagging_missing_key_errors() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        assert_aws_err(
            svc.delete_object_tagging("123456789012", "b", "gone"),
            "NoSuchKey",
        );
    }

    // ── Multipart (service/multipart.rs) ─────────────────────────────

    fn initiate_mpu(svc: &S3Service, bucket: &str, key: &str) -> String {
        let req = make_request(
            Method::POST,
            &format!("/{bucket}/{key}"),
            &[("uploads", "")],
            b"",
        );
        let resp = svc
            .create_multipart_upload("123456789012", &req, bucket, key)
            .unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        let start = body.find("<UploadId>").unwrap() + "<UploadId>".len();
        let end = body.find("</UploadId>").unwrap();
        body[start..end].to_string()
    }

    #[test]
    fn create_multipart_upload_records_upload_in_state() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let upload_id = initiate_mpu(&svc, "b", "big.bin");
        let __mas = svc.state.read();
        let state = __mas.default_ref();
        assert!(state
            .buckets
            .get("b")
            .unwrap()
            .multipart_uploads
            .contains_key(&upload_id));
    }

    #[test]
    fn create_multipart_upload_rejects_acl_and_grants_combo() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let mut req = make_request(Method::POST, "/b/k", &[("uploads", "")], b"");
        req.headers.insert("x-amz-acl", "private".parse().unwrap());
        req.headers
            .insert("x-amz-grant-read", "id=owner".parse().unwrap());
        assert_aws_err(
            svc.create_multipart_upload("123456789012", &req, "b", "k"),
            "InvalidRequest",
        );
    }

    #[test]
    fn create_multipart_upload_missing_bucket_errors() {
        let svc = make_service();
        let req = make_request(Method::POST, "/ghost/k", &[("uploads", "")], b"");
        assert_aws_err(
            svc.create_multipart_upload("123456789012", &req, "ghost", "k"),
            "NoSuchBucket",
        );
    }

    #[tokio::test]
    async fn upload_part_rejects_invalid_part_number() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let upload_id = initiate_mpu(&svc, "b", "k");

        // part_number < 1 is masked as NoSuchUpload (matching AWS behavior).
        let req = make_request(Method::PUT, "/b/k", &[("partNumber", "0")], b"body");
        assert_aws_err(
            svc.upload_part("123456789012", &req, "b", "k", &upload_id, 0)
                .await,
            "NoSuchUpload",
        );

        // part_number > 10000 returns InvalidArgument.
        let req2 = make_request(Method::PUT, "/b/k", &[("partNumber", "10001")], b"body");
        assert_aws_err(
            svc.upload_part("123456789012", &req2, "b", "k", &upload_id, 10_001)
                .await,
            "InvalidArgument",
        );
    }

    #[tokio::test]
    async fn upload_part_missing_upload_errors() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let req = make_request(Method::PUT, "/b/k", &[("partNumber", "1")], b"body");
        assert_aws_err(
            svc.upload_part("123456789012", &req, "b", "k", "not-an-upload", 1)
                .await,
            "NoSuchUpload",
        );
    }

    #[tokio::test]
    async fn mpu_full_lifecycle_creates_object() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let upload_id = initiate_mpu(&svc, "b", "k");

        // Single-part upload — CompleteMultipartUpload's MIN_PART_SIZE check
        // only applies to non-last parts, so a single part of any size works.
        let part_body = b"hello";
        let req = make_request(Method::PUT, "/b/k", &[("partNumber", "1")], part_body);
        let resp = svc
            .upload_part("123456789012", &req, "b", "k", &upload_id, 1)
            .await
            .unwrap();
        let etag = resp
            .headers
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let complete_xml = format!(
            r#"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag}</ETag></Part></CompleteMultipartUpload>"#,
        );
        let complete_req = make_request(
            Method::POST,
            "/b/k",
            &[("uploadId", &upload_id)],
            complete_xml.as_bytes(),
        );
        let resp = svc
            .complete_multipart_upload("123456789012", &complete_req, "b", "k", &upload_id)
            .unwrap();
        assert_eq!(resp.status, StatusCode::OK);

        let __mas = svc.state.read();
        let state = __mas.default_ref();
        let bucket = state.buckets.get("b").unwrap();
        let obj = bucket.objects.get("k").expect("object materialized");
        assert_eq!(obj.size, part_body.len() as u64);
        assert!(!bucket.multipart_uploads.contains_key(&upload_id));
    }

    #[tokio::test]
    async fn mpu_complete_rejects_small_non_last_part() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let upload_id = initiate_mpu(&svc, "b", "k");

        for n in 1..=2 {
            let body = format!("part{n}");
            let req = make_request(
                Method::PUT,
                "/b/k",
                &[("partNumber", &n.to_string())],
                body.as_bytes(),
            );
            svc.upload_part("123456789012", &req, "b", "k", &upload_id, n)
                .await
                .unwrap();
        }

        // Grab the etags from state.
        let (etag1, etag2) = {
            let __mas = svc.state.read();
            let state = __mas.default_ref();
            let parts = &state
                .buckets
                .get("b")
                .unwrap()
                .multipart_uploads
                .get(&upload_id)
                .unwrap()
                .parts;
            (
                parts.get(&1).unwrap().etag.clone(),
                parts.get(&2).unwrap().etag.clone(),
            )
        };

        let complete_xml = format!(
            r#"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{etag2}</ETag></Part></CompleteMultipartUpload>"#,
        );
        let complete_req = make_request(
            Method::POST,
            "/b/k",
            &[("uploadId", &upload_id)],
            complete_xml.as_bytes(),
        );
        assert_aws_err(
            svc.complete_multipart_upload("123456789012", &complete_req, "b", "k", &upload_id),
            "EntityTooSmall",
        );
    }

    #[test]
    fn abort_multipart_upload_removes_upload() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let upload_id = initiate_mpu(&svc, "b", "k");
        let resp = svc
            .abort_multipart_upload("123456789012", "b", "k", &upload_id)
            .unwrap();
        assert_eq!(resp.status, StatusCode::NO_CONTENT);
        let __mas = svc.state.read();
        let state = __mas.default_ref();
        assert!(!state
            .buckets
            .get("b")
            .unwrap()
            .multipart_uploads
            .contains_key(&upload_id));
    }

    #[test]
    fn abort_multipart_upload_unknown_id_errors() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        assert_aws_err(
            svc.abort_multipart_upload("123456789012", "b", "k", "no-such"),
            "NoSuchUpload",
        );
    }

    #[test]
    fn list_multipart_uploads_includes_all_in_flight() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let u1 = initiate_mpu(&svc, "b", "a");
        let u2 = initiate_mpu(&svc, "b", "b");
        let resp = svc.list_multipart_uploads("123456789012", "b").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains(&u1));
        assert!(body.contains(&u2));
    }

    #[tokio::test]
    async fn list_parts_after_upload_returns_parts() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let upload_id = initiate_mpu(&svc, "b", "k");
        let req = make_request(Method::PUT, "/b/k", &[("partNumber", "1")], b"data");
        svc.upload_part("123456789012", &req, "b", "k", &upload_id, 1)
            .await
            .unwrap();

        let list_req = make_request(Method::GET, "/b/k", &[("uploadId", &upload_id)], b"");
        let resp = svc
            .list_parts("123456789012", &list_req, "b", "k", &upload_id)
            .unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<PartNumber>1</PartNumber>"));
    }

    // ── Config (service/config.rs) ───────────────────────────────────

    #[test]
    fn bucket_encryption_put_get_delete_round_trip() {
        let svc = make_service();
        seed_bucket(&svc, "b");

        let xml = r#"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>"#;
        let req = make_request(Method::PUT, "/b", &[("encryption", "")], xml.as_bytes());
        let resp = svc
            .put_bucket_encryption("123456789012", &req, "b")
            .unwrap();
        assert_eq!(resp.status, StatusCode::OK);

        // Normalized body should include BucketKeyEnabled=false.
        let get = svc.get_bucket_encryption("123456789012", "b").unwrap();
        let body = std::str::from_utf8(get.body.expect_bytes()).unwrap();
        assert!(body.contains("AES256"));
        assert!(body.contains("<BucketKeyEnabled>false</BucketKeyEnabled>"));

        let del = svc.delete_bucket_encryption("123456789012", "b").unwrap();
        assert_eq!(del.status, StatusCode::NO_CONTENT);
        assert_aws_err(
            svc.get_bucket_encryption("123456789012", "b"),
            "ServerSideEncryptionConfigurationNotFoundError",
        );
    }

    #[test]
    fn bucket_policy_rejects_malformed_json() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let req = make_request(Method::PUT, "/b", &[("policy", "")], b"not-json");
        assert_aws_err(
            svc.put_bucket_policy("123456789012", &req, "b"),
            "MalformedPolicy",
        );
    }

    #[test]
    fn bucket_policy_put_get_delete_round_trip() {
        let svc = make_service();
        seed_bucket(&svc, "b");

        let body = br#"{"Version":"2012-10-17","Statement":[]}"#;
        let put_req = make_request(Method::PUT, "/b", &[("policy", "")], body);
        let resp = svc
            .put_bucket_policy("123456789012", &put_req, "b")
            .unwrap();
        assert_eq!(resp.status, StatusCode::NO_CONTENT);

        let get = svc.get_bucket_policy("123456789012", "b").unwrap();
        assert_eq!(get.body.expect_bytes(), body);

        let del = svc.delete_bucket_policy("123456789012", "b").unwrap();
        assert_eq!(del.status, StatusCode::NO_CONTENT);
        assert_aws_err(
            svc.get_bucket_policy("123456789012", "b"),
            "NoSuchBucketPolicy",
        );
    }

    #[test]
    fn bucket_lifecycle_empty_rules_clears_config() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        {
            let mut __mas = svc.state.write();
            let state = __mas.default_mut();
            state.buckets.get_mut("b").unwrap().lifecycle_config = Some("placeholder".to_string());
        }
        let req = make_request(
            Method::PUT,
            "/b",
            &[("lifecycle", "")],
            b"<LifecycleConfiguration></LifecycleConfiguration>",
        );
        svc.put_bucket_lifecycle("123456789012", &req, "b").unwrap();
        let __mas = svc.state.read();
        let state = __mas.default_ref();
        assert!(state.buckets.get("b").unwrap().lifecycle_config.is_none());
    }

    #[test]
    fn bucket_cors_put_get_delete_round_trip() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let xml = br#"<CORSConfiguration><CORSRule><AllowedMethod>GET</AllowedMethod><AllowedOrigin>*</AllowedOrigin></CORSRule></CORSConfiguration>"#;
        let req = make_request(Method::PUT, "/b", &[("cors", "")], xml);
        svc.put_bucket_cors("123456789012", &req, "b").unwrap();
        let got = svc.get_bucket_cors("123456789012", "b").unwrap();
        assert!(std::str::from_utf8(got.body.expect_bytes())
            .unwrap()
            .contains("CORSConfiguration"));
        svc.delete_bucket_cors("123456789012", "b").unwrap();
        assert_aws_err(
            svc.get_bucket_cors("123456789012", "b"),
            "NoSuchCORSConfiguration",
        );
    }

    #[test]
    fn bucket_versioning_put_and_get() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let req = make_request(
            Method::PUT,
            "/b",
            &[("versioning", "")],
            b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
        );
        svc.put_bucket_versioning("123456789012", &req, "b")
            .unwrap();

        let __mas = svc.state.read();
        let state = __mas.default_ref();
        assert_eq!(
            state.buckets.get("b").unwrap().versioning.as_deref(),
            Some("Enabled")
        );
        drop(__mas);

        let resp = svc.get_bucket_versioning("123456789012", "b").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<Status>Enabled</Status>"));
    }

    #[test]
    fn bucket_tagging_put_get_delete_round_trip() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let req = make_request(
            Method::PUT,
            "/b",
            &[("tagging", "")],
            br#"<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>"#,
        );
        svc.put_bucket_tagging("123456789012", &req, "b").unwrap();
        let get_req = make_request(Method::GET, "/b", &[("tagging", "")], b"");
        let got = svc
            .get_bucket_tagging("123456789012", &get_req, "b")
            .unwrap();
        assert!(std::str::from_utf8(got.body.expect_bytes())
            .unwrap()
            .contains("<Key>env</Key>"));
        let del_req = make_request(Method::DELETE, "/b", &[("tagging", "")], b"");
        svc.delete_bucket_tagging("123456789012", &del_req, "b")
            .unwrap();
        assert_aws_err(
            svc.get_bucket_tagging("123456789012", &get_req, "b"),
            "NoSuchTagSet",
        );
    }

    #[test]
    fn bucket_accelerate_rejects_invalid_status() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let req = make_request(
            Method::PUT,
            "/b",
            &[("accelerate", "")],
            b"<AccelerateConfiguration><Status>Bogus</Status></AccelerateConfiguration>",
        );
        assert_aws_err(
            svc.put_bucket_accelerate("123456789012", &req, "b"),
            "MalformedXML",
        );
    }

    #[test]
    fn bucket_accelerate_enabled_is_persisted() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let req = make_request(
            Method::PUT,
            "/b",
            &[("accelerate", "")],
            b"<AccelerateConfiguration><Status>Enabled</Status></AccelerateConfiguration>",
        );
        svc.put_bucket_accelerate("123456789012", &req, "b")
            .unwrap();
        let got = svc.get_bucket_accelerate("123456789012", "b").unwrap();
        assert!(std::str::from_utf8(got.body.expect_bytes())
            .unwrap()
            .contains("<Status>Enabled</Status>"));
    }

    #[test]
    fn public_access_block_put_get_delete_round_trip() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let body = br#"<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls><BlockPublicPolicy>true</BlockPublicPolicy><RestrictPublicBuckets>true</RestrictPublicBuckets></PublicAccessBlockConfiguration>"#;
        let req = make_request(Method::PUT, "/b", &[("publicAccessBlock", "")], body);
        svc.put_public_access_block("123456789012", &req, "b")
            .unwrap();
        let got = svc.get_public_access_block("123456789012", "b").unwrap();
        assert!(std::str::from_utf8(got.body.expect_bytes())
            .unwrap()
            .contains("<BlockPublicAcls>true</BlockPublicAcls>"));
        svc.delete_public_access_block("123456789012", "b").unwrap();
        assert_aws_err(
            svc.get_public_access_block("123456789012", "b"),
            "NoSuchPublicAccessBlockConfiguration",
        );
    }

    #[test]
    fn bucket_website_put_get_delete_round_trip() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let req = make_request(
            Method::PUT,
            "/b",
            &[("website", "")],
            b"<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>",
        );
        svc.put_bucket_website("123456789012", &req, "b").unwrap();
        let got = svc.get_bucket_website("123456789012", "b").unwrap();
        assert!(std::str::from_utf8(got.body.expect_bytes())
            .unwrap()
            .contains("<Suffix>index.html</Suffix>"));
        svc.delete_bucket_website("123456789012", "b").unwrap();
        assert_aws_err(
            svc.get_bucket_website("123456789012", "b"),
            "NoSuchWebsiteConfiguration",
        );
    }

    #[test]
    fn bucket_replication_requires_existing_bucket() {
        let svc = make_service();
        let req = make_request(Method::PUT, "/nope", &[("replication", "")], b"<x/>");
        assert_aws_err(
            svc.put_bucket_replication("123456789012", &req, "nope"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn bucket_ownership_controls_put_get_delete_round_trip() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let req = make_request(
            Method::PUT,
            "/b",
            &[("ownershipControls", "")],
            b"<OwnershipControls><Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule></OwnershipControls>",
        );
        svc.put_bucket_ownership_controls("123456789012", &req, "b")
            .unwrap();
        let got = svc
            .get_bucket_ownership_controls("123456789012", "b")
            .unwrap();
        assert!(std::str::from_utf8(got.body.expect_bytes())
            .unwrap()
            .contains("BucketOwnerEnforced"));
        svc.delete_bucket_ownership_controls("123456789012", "b")
            .unwrap();
        assert_aws_err(
            svc.get_bucket_ownership_controls("123456789012", "b"),
            "OwnershipControlsNotFoundError",
        );
    }

    // ── Error branch tests: object operations ──

    #[test]
    fn get_object_nonexistent_bucket() {
        let svc = make_service();
        let req = make_request(Method::GET, "/no-bucket/key", &[], b"");
        assert_aws_err(
            svc.get_object("123456789012", &req, "no-bucket", "key"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn get_object_nonexistent_key() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let req = make_request(Method::GET, "/b/missing", &[], b"");
        assert_aws_err(
            svc.get_object("123456789012", &req, "b", "missing"),
            "NoSuchKey",
        );
    }

    #[tokio::test]
    async fn put_object_key_too_long() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let long_key = "x".repeat(1025);
        let req = make_request(Method::PUT, &format!("/b/{long_key}"), &[], b"data");
        assert_aws_err(
            svc.put_object("123456789012", &req, "b", &long_key).await,
            "KeyTooLongError",
        );
    }

    #[tokio::test]
    async fn put_object_with_aws_tag_prefix() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let mut req = make_request(Method::PUT, "/b/tagged", &[], b"data");
        req.headers
            .insert("x-amz-tagging", "aws:reserved=nope".parse().unwrap());
        assert_aws_err(
            svc.put_object("123456789012", &req, "b", "tagged").await,
            "InvalidTag",
        );
    }

    #[tokio::test]
    async fn put_object_acl_and_grant_conflict() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let mut req = make_request(Method::PUT, "/b/conflict", &[], b"data");
        req.headers
            .insert("x-amz-acl", "public-read".parse().unwrap());
        req.headers
            .insert("x-amz-grant-read", "id=abc123".parse().unwrap());
        assert_aws_err(
            svc.put_object("123456789012", &req, "b", "conflict").await,
            "InvalidRequest",
        );
    }

    #[test]
    fn head_object_nonexistent_key() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let req = make_request(Method::HEAD, "/b/missing", &[], b"");
        assert_aws_err(
            svc.head_object("123456789012", &req, "b", "missing"),
            "NoSuchKey",
        );
    }

    #[test]
    fn head_object_nonexistent_bucket() {
        let svc = make_service();
        let req = make_request(Method::HEAD, "/nope/key", &[], b"");
        assert_aws_err(
            svc.head_object("123456789012", &req, "nope", "key"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn delete_object_nonexistent_bucket() {
        let svc = make_service();
        let req = make_request(Method::DELETE, "/nope/key", &[], b"");
        assert_aws_err(
            svc.delete_object("123456789012", &req, "nope", "key"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn copy_object_source_not_found() {
        let svc = make_service();
        seed_bucket(&svc, "src-b");
        seed_bucket(&svc, "dst-b");
        let mut req = make_request(Method::PUT, "/dst-b/copied", &[], b"");
        req.headers
            .insert("x-amz-copy-source", "src-b/nonexistent".parse().unwrap());
        assert_aws_err(
            svc.copy_object("123456789012", &req, "dst-b", "copied"),
            "NoSuchKey",
        );
    }

    #[test]
    fn copy_object_source_bucket_not_found() {
        let svc = make_service();
        seed_bucket(&svc, "dst-b2");
        let mut req = make_request(Method::PUT, "/dst-b2/copied", &[], b"");
        req.headers
            .insert("x-amz-copy-source", "nope-bucket/key".parse().unwrap());
        assert_aws_err(
            svc.copy_object("123456789012", &req, "dst-b2", "copied"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn list_objects_v2_nonexistent_bucket() {
        let svc = make_service();
        let req = make_request(Method::GET, "/nope", &[("list-type", "2")], b"");
        assert_aws_err(
            svc.list_objects_v2("123456789012", &req, "nope"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn list_objects_v2_empty_continuation_token() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let req = make_request(
            Method::GET,
            "/b",
            &[("list-type", "2"), ("continuation-token", "")],
            b"",
        );
        assert_aws_err(
            svc.list_objects_v2("123456789012", &req, "b"),
            "InvalidArgument",
        );
    }

    #[test]
    fn list_objects_v1_nonexistent_bucket() {
        let svc = make_service();
        let req = make_request(Method::GET, "/nope", &[], b"");
        assert_aws_err(
            svc.list_objects_v1("123456789012", &req, "nope"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn list_object_versions_nonexistent_bucket() {
        let svc = make_service();
        let req = make_request(Method::GET, "/nope", &[("versions", "")], b"");
        assert_aws_err(
            svc.list_object_versions("123456789012", &req, "nope"),
            "NoSuchBucket",
        );
    }

    // ── Error branch tests: multipart operations ──

    #[test]
    fn create_multipart_nonexistent_bucket() {
        let svc = make_service();
        let req = make_request(Method::POST, "/nope/key", &[("uploads", "")], b"");
        assert_aws_err(
            svc.create_multipart_upload("123456789012", &req, "nope", "key"),
            "NoSuchBucket",
        );
    }

    #[tokio::test]
    async fn upload_part_nonexistent_upload() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let req = make_request(
            Method::PUT,
            "/b/key",
            &[("uploadId", "bogus"), ("partNumber", "1")],
            b"data",
        );
        assert_aws_err(
            svc.upload_part("123456789012", &req, "b", "key", "bogus", 1)
                .await,
            "NoSuchUpload",
        );
    }

    #[test]
    fn complete_multipart_nonexistent_upload() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let req = make_request(
            Method::POST,
            "/b/key",
            &[("uploadId", "bogus")],
            b"<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>\"abc\"</ETag></Part></CompleteMultipartUpload>",
        );
        assert_aws_err(
            svc.complete_multipart_upload("123456789012", &req, "b", "key", "bogus"),
            "NoSuchUpload",
        );
    }

    #[test]
    fn abort_multipart_nonexistent_upload() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        assert_aws_err(
            svc.abort_multipart_upload("123456789012", "b", "key", "bogus"),
            "NoSuchUpload",
        );
    }

    #[test]
    fn list_parts_nonexistent_upload() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let req = make_request(Method::GET, "/b/key", &[("uploadId", "bogus")], b"");
        assert_aws_err(
            svc.list_parts("123456789012", &req, "b", "key", "bogus"),
            "NoSuchUpload",
        );
    }

    // ── Error branch tests: config operations ──

    #[test]
    fn get_bucket_acl_nonexistent() {
        let svc = make_service();
        let req = make_request(Method::GET, "/nope", &[("acl", "")], b"");
        assert_aws_err(
            svc.get_bucket_acl("123456789012", &req, "nope"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn get_bucket_versioning_nonexistent() {
        let svc = make_service();
        assert_aws_err(
            svc.get_bucket_versioning("123456789012", "nope"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn put_bucket_versioning_nonexistent() {
        let svc = make_service();
        let req = make_request(
            Method::PUT,
            "/nope",
            &[("versioning", "")],
            b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
        );
        assert_aws_err(
            svc.put_bucket_versioning("123456789012", &req, "nope"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn get_bucket_location_nonexistent() {
        let svc = make_service();
        assert_aws_err(
            svc.get_bucket_location("123456789012", "nope"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn get_bucket_lifecycle_nonexistent() {
        let svc = make_service();
        assert_aws_err(
            svc.get_bucket_lifecycle("123456789012", "nope"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn get_bucket_notification_nonexistent() {
        let svc = make_service();
        assert_aws_err(
            svc.get_bucket_notification("123456789012", "nope"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn get_bucket_encryption_nonexistent() {
        let svc = make_service();
        assert_aws_err(
            svc.get_bucket_encryption("123456789012", "nope"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn get_bucket_logging_nonexistent() {
        let svc = make_service();
        assert_aws_err(
            svc.get_bucket_logging("123456789012", "nope"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn get_object_lock_nonexistent() {
        let svc = make_service();
        assert_aws_err(
            svc.get_object_lock_configuration("123456789012", "nope"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn get_object_attributes_nonexistent_key() {
        let svc = make_service();
        seed_bucket(&svc, "b");
        let req = make_request(Method::GET, "/b/missing", &[("attributes", "")], b"");
        assert_aws_err(
            svc.get_object_attributes("123456789012", &req, "b", "missing"),
            "NoSuchKey",
        );
    }

    #[test]
    fn get_object_attributes_nonexistent_bucket() {
        let svc = make_service();
        let req = make_request(Method::GET, "/nope/key", &[("attributes", "")], b"");
        assert_aws_err(
            svc.get_object_attributes("123456789012", &req, "nope", "key"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn restore_object_nonexistent_bucket() {
        let svc = make_service();
        let req = make_request(
            Method::POST,
            "/nope/key",
            &[("restore", "")],
            b"<RestoreRequest><Days>1</Days></RestoreRequest>",
        );
        assert_aws_err(
            svc.restore_object("123456789012", &req, "nope", "key"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn get_public_access_block_nonexistent() {
        let svc = make_service();
        assert_aws_err(
            svc.get_public_access_block("123456789012", "nope"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn get_bucket_policy_nonexistent() {
        let svc = make_service();
        assert_aws_err(
            svc.get_bucket_policy("123456789012", "nope"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn get_bucket_cors_nonexistent() {
        let svc = make_service();
        assert_aws_err(svc.get_bucket_cors("123456789012", "nope"), "NoSuchBucket");
    }

    #[test]
    fn get_bucket_tagging_nonexistent() {
        let svc = make_service();
        let req = make_request(Method::GET, "/nope", &[("tagging", "")], b"");
        assert_aws_err(
            svc.get_bucket_tagging("123456789012", &req, "nope"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn get_bucket_website_nonexistent() {
        let svc = make_service();
        assert_aws_err(
            svc.get_bucket_website("123456789012", "nope"),
            "NoSuchBucket",
        );
    }

    // ── Object lock (lock.rs - 0% coverage) ──

    #[test]
    fn put_and_get_object_retention() {
        let svc = make_service();
        seed_bucket(&svc, "lock-b");
        seed_object(&svc, "lock-b", "retained.txt", b"data");

        let body = b"<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2030-01-01T00:00:00Z</RetainUntilDate></Retention>";
        let req = make_request(
            Method::PUT,
            "/lock-b/retained.txt",
            &[("retention", "")],
            body,
        );
        svc.put_object_retention("123456789012", &req, "lock-b", "retained.txt")
            .unwrap();

        let req = make_request(
            Method::GET,
            "/lock-b/retained.txt",
            &[("retention", "")],
            b"",
        );
        let resp = svc
            .get_object_retention("123456789012", &req, "lock-b", "retained.txt")
            .unwrap();
        let body_str = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body_str.contains("GOVERNANCE"));
    }

    #[test]
    fn get_object_retention_nonexistent_bucket() {
        let svc = make_service();
        let req = make_request(Method::GET, "/nope/key", &[("retention", "")], b"");
        assert_aws_err(
            svc.get_object_retention("123456789012", &req, "nope", "key"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn get_object_retention_nonexistent_key() {
        let svc = make_service();
        seed_bucket(&svc, "lock-b2");
        let req = make_request(Method::GET, "/lock-b2/missing", &[("retention", "")], b"");
        assert_aws_err(
            svc.get_object_retention("123456789012", &req, "lock-b2", "missing"),
            "NoSuchKey",
        );
    }

    #[test]
    fn put_and_get_object_legal_hold() {
        let svc = make_service();
        seed_bucket(&svc, "hold-b");
        seed_object(&svc, "hold-b", "held.txt", b"data");

        let body = b"<LegalHold><Status>ON</Status></LegalHold>";
        let req = make_request(Method::PUT, "/hold-b/held.txt", &[("legal-hold", "")], body);
        svc.put_object_legal_hold("123456789012", &req, "hold-b", "held.txt")
            .unwrap();

        let req = make_request(Method::GET, "/hold-b/held.txt", &[("legal-hold", "")], b"");
        let resp = svc
            .get_object_legal_hold("123456789012", &req, "hold-b", "held.txt")
            .unwrap();
        let body_str = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body_str.contains("ON"));
    }

    #[test]
    fn get_object_legal_hold_nonexistent() {
        let svc = make_service();
        let req = make_request(Method::GET, "/nope/key", &[("legal-hold", "")], b"");
        assert_aws_err(
            svc.get_object_legal_hold("123456789012", &req, "nope", "key"),
            "NoSuchBucket",
        );
    }

    // ── Object ACL (acl.rs - 0% coverage) ──

    #[test]
    fn get_object_acl_default() {
        let svc = make_service();
        seed_bucket(&svc, "acl-b");
        seed_object(&svc, "acl-b", "file.txt", b"data");

        let req = make_request(Method::GET, "/acl-b/file.txt", &[("acl", "")], b"");
        let resp = svc
            .get_object_acl("123456789012", &req, "acl-b", "file.txt")
            .unwrap();
        let body_str = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body_str.contains("AccessControlPolicy"));
    }

    #[test]
    fn get_object_acl_nonexistent_bucket() {
        let svc = make_service();
        let req = make_request(Method::GET, "/nope/key", &[("acl", "")], b"");
        assert_aws_err(
            svc.get_object_acl("123456789012", &req, "nope", "key"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn get_object_acl_nonexistent_key() {
        let svc = make_service();
        seed_bucket(&svc, "acl-b2");
        let req = make_request(Method::GET, "/acl-b2/missing", &[("acl", "")], b"");
        assert_aws_err(
            svc.get_object_acl("123456789012", &req, "acl-b2", "missing"),
            "NoSuchKey",
        );
    }

    #[test]
    fn put_object_acl() {
        let svc = make_service();
        seed_bucket(&svc, "acl-put-b");
        seed_object(&svc, "acl-put-b", "file.txt", b"data");

        let acl_xml = b"<AccessControlPolicy><Owner><ID>owner</ID></Owner><AccessControlList><Grant><Grantee xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"CanonicalUser\"><ID>owner</ID></Grantee><Permission>FULL_CONTROL</Permission></Grant></AccessControlList></AccessControlPolicy>";
        let req = make_request(Method::PUT, "/acl-put-b/file.txt", &[("acl", "")], acl_xml);
        svc.put_object_acl("123456789012", &req, "acl-put-b", "file.txt")
            .unwrap();
    }

    // ── Happy-path handler tests (objects.rs coverage) ──

    #[tokio::test]
    async fn put_object_via_handler_and_get_back() {
        let svc = make_service();
        seed_bucket(&svc, "hp");

        // PUT through handler (not seed_object)
        let req = make_request(Method::PUT, "/hp/test.txt", &[], b"hello world");
        let resp = svc
            .put_object("123456789012", &req, "hp", "test.txt")
            .await
            .unwrap();
        assert_eq!(resp.status, StatusCode::OK);

        // GET back
        let req = make_request(Method::GET, "/hp/test.txt", &[], b"");
        let resp = svc
            .get_object("123456789012", &req, "hp", "test.txt")
            .unwrap();
        assert_eq!(resp.body.expect_bytes(), b"hello world");
    }

    #[tokio::test]
    async fn put_object_with_content_type() {
        let svc = make_service();
        seed_bucket(&svc, "ct");

        let mut req = make_request(Method::PUT, "/ct/doc.json", &[], b"{\"key\":\"val\"}");
        req.headers
            .insert("content-type", "application/json".parse().unwrap());
        svc.put_object("123456789012", &req, "ct", "doc.json")
            .await
            .unwrap();

        let req = make_request(Method::GET, "/ct/doc.json", &[], b"");
        let resp = svc
            .get_object("123456789012", &req, "ct", "doc.json")
            .unwrap();
        assert_eq!(resp.content_type, "application/json");
    }

    #[tokio::test]
    async fn put_object_with_metadata() {
        let svc = make_service();
        seed_bucket(&svc, "meta");

        let mut req = make_request(Method::PUT, "/meta/obj", &[], b"data");
        req.headers
            .insert("x-amz-meta-color", "blue".parse().unwrap());
        req.headers
            .insert("x-amz-meta-size", "large".parse().unwrap());
        svc.put_object("123456789012", &req, "meta", "obj")
            .await
            .unwrap();

        let req = make_request(Method::HEAD, "/meta/obj", &[], b"");
        let resp = svc
            .head_object("123456789012", &req, "meta", "obj")
            .unwrap();
        assert!(resp
            .headers
            .get("x-amz-meta-color")
            .is_some_and(|v| v == "blue"));
    }

    #[tokio::test]
    async fn put_object_returns_etag() {
        let svc = make_service();
        seed_bucket(&svc, "etag");

        let req = make_request(Method::PUT, "/etag/f.txt", &[], b"content");
        let resp = svc
            .put_object("123456789012", &req, "etag", "f.txt")
            .await
            .unwrap();
        assert!(resp.headers.get("etag").is_some());
    }

    #[tokio::test]
    async fn head_object_returns_headers() {
        let svc = make_service();
        seed_bucket(&svc, "head");

        let req = make_request(Method::PUT, "/head/f.txt", &[], b"12345");
        svc.put_object("123456789012", &req, "head", "f.txt")
            .await
            .unwrap();

        let req = make_request(Method::HEAD, "/head/f.txt", &[], b"");
        let resp = svc
            .head_object("123456789012", &req, "head", "f.txt")
            .unwrap();
        assert_eq!(
            resp.headers
                .get("content-length")
                .unwrap()
                .to_str()
                .unwrap(),
            "5"
        );
    }

    #[tokio::test]
    async fn delete_object_via_handler() {
        let svc = make_service();
        seed_bucket(&svc, "del");

        let req = make_request(Method::PUT, "/del/rm.txt", &[], b"bye");
        svc.put_object("123456789012", &req, "del", "rm.txt")
            .await
            .unwrap();

        let req = make_request(Method::DELETE, "/del/rm.txt", &[], b"");
        svc.delete_object("123456789012", &req, "del", "rm.txt")
            .unwrap();

        let req = make_request(Method::GET, "/del/rm.txt", &[], b"");
        assert_aws_err(
            svc.get_object("123456789012", &req, "del", "rm.txt"),
            "NoSuchKey",
        );
    }

    #[tokio::test]
    async fn copy_object_via_handler() {
        let svc = make_service();
        seed_bucket(&svc, "cpsrc");
        seed_bucket(&svc, "cpdst");

        let req = make_request(Method::PUT, "/cpsrc/orig.txt", &[], b"original");
        svc.put_object("123456789012", &req, "cpsrc", "orig.txt")
            .await
            .unwrap();

        let mut req = make_request(Method::PUT, "/cpdst/copy.txt", &[], b"");
        req.headers
            .insert("x-amz-copy-source", "cpsrc/orig.txt".parse().unwrap());
        svc.copy_object("123456789012", &req, "cpdst", "copy.txt")
            .unwrap();

        let req = make_request(Method::GET, "/cpdst/copy.txt", &[], b"");
        let resp = svc
            .get_object("123456789012", &req, "cpdst", "copy.txt")
            .unwrap();
        assert_eq!(resp.body.expect_bytes(), b"original");
    }

    #[tokio::test]
    async fn copy_object_within_same_bucket() {
        let svc = make_service();
        seed_bucket(&svc, "same");

        let req = make_request(Method::PUT, "/same/a.txt", &[], b"aaa");
        svc.put_object("123456789012", &req, "same", "a.txt")
            .await
            .unwrap();

        let mut req = make_request(Method::PUT, "/same/b.txt", &[], b"");
        req.headers
            .insert("x-amz-copy-source", "same/a.txt".parse().unwrap());
        svc.copy_object("123456789012", &req, "same", "b.txt")
            .unwrap();

        let req = make_request(Method::GET, "/same/b.txt", &[], b"");
        let resp = svc
            .get_object("123456789012", &req, "same", "b.txt")
            .unwrap();
        assert_eq!(resp.body.expect_bytes(), b"aaa");
    }

    #[tokio::test]
    async fn list_objects_v2_via_handler() {
        let svc = make_service();
        seed_bucket(&svc, "lsv2");

        for i in 0..3 {
            let key = format!("file{i}.txt");
            let req = make_request(Method::PUT, &format!("/lsv2/{key}"), &[], b"data");
            svc.put_object("123456789012", &req, "lsv2", &key)
                .await
                .unwrap();
        }

        let req = make_request(Method::GET, "/lsv2", &[("list-type", "2")], b"");
        let resp = svc.list_objects_v2("123456789012", &req, "lsv2").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<KeyCount>3</KeyCount>"));
    }

    #[tokio::test]
    async fn list_objects_v2_with_prefix() {
        let svc = make_service();
        seed_bucket(&svc, "pfx");

        for key in &["docs/a.txt", "docs/b.txt", "images/c.png"] {
            let req = make_request(Method::PUT, &format!("/pfx/{key}"), &[], b"x");
            svc.put_object("123456789012", &req, "pfx", key)
                .await
                .unwrap();
        }

        let req = make_request(
            Method::GET,
            "/pfx",
            &[("list-type", "2"), ("prefix", "docs/")],
            b"",
        );
        let resp = svc.list_objects_v2("123456789012", &req, "pfx").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<KeyCount>2</KeyCount>"));
    }

    #[tokio::test]
    async fn list_objects_v2_with_delimiter() {
        let svc = make_service();
        seed_bucket(&svc, "dlm");

        for key in &["a/1.txt", "a/2.txt", "b/3.txt", "root.txt"] {
            let req = make_request(Method::PUT, &format!("/dlm/{key}"), &[], b"x");
            svc.put_object("123456789012", &req, "dlm", key)
                .await
                .unwrap();
        }

        let req = make_request(
            Method::GET,
            "/dlm",
            &[("list-type", "2"), ("delimiter", "/")],
            b"",
        );
        let resp = svc.list_objects_v2("123456789012", &req, "dlm").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        // Should have common prefixes a/ and b/
        assert!(body.contains("<CommonPrefixes>"));
        // root.txt should be in contents
        assert!(body.contains("root.txt"));
    }

    #[tokio::test]
    async fn list_objects_v1_via_handler() {
        let svc = make_service();
        seed_bucket(&svc, "lsv1");

        let req = make_request(Method::PUT, "/lsv1/test.txt", &[], b"data");
        svc.put_object("123456789012", &req, "lsv1", "test.txt")
            .await
            .unwrap();

        let req = make_request(Method::GET, "/lsv1", &[], b"");
        let resp = svc.list_objects_v1("123456789012", &req, "lsv1").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<Key>test.txt</Key>"));
    }

    #[tokio::test]
    async fn delete_objects_batch() {
        let svc = make_service();
        seed_bucket(&svc, "bdel");

        for i in 0..3 {
            let key = format!("d{i}.txt");
            let req = make_request(Method::PUT, &format!("/bdel/{key}"), &[], b"x");
            svc.put_object("123456789012", &req, "bdel", &key)
                .await
                .unwrap();
        }

        let delete_xml = b"<Delete><Object><Key>d0.txt</Key></Object><Object><Key>d1.txt</Key></Object></Delete>";
        let req = make_request(Method::POST, "/bdel", &[("delete", "")], delete_xml);
        let resp = svc.delete_objects("123456789012", &req, "bdel").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<Deleted>"));

        // d2.txt should still exist
        let req = make_request(Method::GET, "/bdel/d2.txt", &[], b"");
        svc.get_object("123456789012", &req, "bdel", "d2.txt")
            .unwrap();
    }

    #[tokio::test]
    async fn put_object_overwrites_existing() {
        let svc = make_service();
        seed_bucket(&svc, "ow");

        let req = make_request(Method::PUT, "/ow/f.txt", &[], b"version1");
        svc.put_object("123456789012", &req, "ow", "f.txt")
            .await
            .unwrap();

        let req = make_request(Method::PUT, "/ow/f.txt", &[], b"version2");
        svc.put_object("123456789012", &req, "ow", "f.txt")
            .await
            .unwrap();

        let req = make_request(Method::GET, "/ow/f.txt", &[], b"");
        let resp = svc.get_object("123456789012", &req, "ow", "f.txt").unwrap();
        assert_eq!(resp.body.expect_bytes(), b"version2");
    }

    #[tokio::test]
    async fn get_object_attributes_via_handler() {
        let svc = make_service();
        seed_bucket(&svc, "attr");

        let req = make_request(Method::PUT, "/attr/f.txt", &[], b"content");
        svc.put_object("123456789012", &req, "attr", "f.txt")
            .await
            .unwrap();

        let mut req = make_request(Method::GET, "/attr/f.txt", &[], b"");
        req.headers.insert(
            "x-amz-object-attributes",
            "ETag,ObjectSize".parse().unwrap(),
        );
        let resp = svc
            .get_object_attributes("123456789012", &req, "attr", "f.txt")
            .unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<ObjectSize>"));
    }

    // ── Multipart upload happy path ──

    #[tokio::test]
    async fn multipart_upload_lifecycle() {
        let svc = make_service();
        seed_bucket(&svc, "mp");

        // Create
        let req = make_request(Method::POST, "/mp/big.bin", &[("uploads", "")], b"");
        let resp = svc
            .create_multipart_upload("123456789012", &req, "mp", "big.bin")
            .unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        let uid_start = body.find("<UploadId>").unwrap() + 10;
        let uid_end = body.find("</UploadId>").unwrap();
        let upload_id = &body[uid_start..uid_end];

        // Upload part 1 (>5MB to pass minimum size check)
        let big_data = vec![b'A'; 5 * 1024 * 1024 + 1];
        let req = make_request(Method::PUT, "/mp/big.bin", &[], &big_data);
        let resp = svc
            .upload_part("123456789012", &req, "mp", "big.bin", upload_id, 1)
            .await
            .unwrap();
        let etag1 = resp
            .headers
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        // Upload part 2 (last part can be any size)
        let req = make_request(Method::PUT, "/mp/big.bin", &[], b"part2-data");
        let resp = svc
            .upload_part("123456789012", &req, "mp", "big.bin", upload_id, 2)
            .await
            .unwrap();
        let etag2 = resp
            .headers
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        // List parts
        let req = make_request(Method::GET, "/mp/big.bin", &[], b"");
        let resp = svc
            .list_parts("123456789012", &req, "mp", "big.bin", upload_id)
            .unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<Part>"));

        // Complete
        let complete_xml = format!(
            "<CompleteMultipartUpload><Part><PartNumber>1</PartNumber><ETag>{etag1}</ETag></Part><Part><PartNumber>2</PartNumber><ETag>{etag2}</ETag></Part></CompleteMultipartUpload>"
        );
        let req = make_request(Method::POST, "/mp/big.bin", &[], complete_xml.as_bytes());
        svc.complete_multipart_upload("123456789012", &req, "mp", "big.bin", upload_id)
            .unwrap();

        // Verify object exists
        let req = make_request(Method::GET, "/mp/big.bin", &[], b"");
        let resp = svc
            .get_object("123456789012", &req, "mp", "big.bin")
            .unwrap();
        let body = resp.body.expect_bytes();
        // First part is 5MB+1 of 'A', second is "part2-data"
        assert!(body.len() > 5 * 1024 * 1024);
    }

    #[test]
    fn multipart_upload_abort() {
        let svc = make_service();
        seed_bucket(&svc, "mpa");

        let req = make_request(Method::POST, "/mpa/abort.bin", &[("uploads", "")], b"");
        let resp = svc
            .create_multipart_upload("123456789012", &req, "mpa", "abort.bin")
            .unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        let uid_start = body.find("<UploadId>").unwrap() + 10;
        let uid_end = body.find("</UploadId>").unwrap();
        let upload_id = body[uid_start..uid_end].to_string();

        svc.abort_multipart_upload("123456789012", "mpa", "abort.bin", &upload_id)
            .unwrap();

        // Upload should be gone
        let req = make_request(Method::GET, "/mpa/abort.bin", &[], b"");
        assert_aws_err(
            svc.list_parts("123456789012", &req, "mpa", "abort.bin", &upload_id),
            "NoSuchUpload",
        );
    }

    #[test]
    fn list_multipart_uploads() {
        let svc = make_service();
        seed_bucket(&svc, "mpl");

        let req = make_request(Method::POST, "/mpl/f1.bin", &[("uploads", "")], b"");
        svc.create_multipart_upload("123456789012", &req, "mpl", "f1.bin")
            .unwrap();

        let resp = svc.list_multipart_uploads("123456789012", "mpl").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<Upload>"));
        assert!(body.contains("f1.bin"));
    }

    // ── Config handler happy paths ──

    #[test]
    fn put_and_get_bucket_versioning() {
        let svc = make_service();
        seed_bucket(&svc, "ver");

        let req = make_request(
            Method::PUT,
            "/ver",
            &[("versioning", "")],
            b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
        );
        svc.put_bucket_versioning("123456789012", &req, "ver")
            .unwrap();

        let resp = svc.get_bucket_versioning("123456789012", "ver").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("Enabled"));
    }

    #[test]
    fn put_and_get_bucket_lifecycle() {
        let svc = make_service();
        seed_bucket(&svc, "lc");

        let xml = b"<LifecycleConfiguration><Rule><ID>expire</ID><Filter><Prefix></Prefix></Filter><Status>Enabled</Status><Expiration><Days>30</Days></Expiration></Rule></LifecycleConfiguration>";
        let req = make_request(Method::PUT, "/lc", &[("lifecycle", "")], xml);
        svc.put_bucket_lifecycle("123456789012", &req, "lc")
            .unwrap();

        let resp = svc.get_bucket_lifecycle("123456789012", "lc").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<Rule>"));
    }

    #[test]
    fn put_and_get_bucket_notification() {
        let svc = make_service();
        seed_bucket(&svc, "notif");

        let xml = b"<NotificationConfiguration></NotificationConfiguration>";
        let req = make_request(Method::PUT, "/notif", &[("notification", "")], xml);
        svc.put_bucket_notification("123456789012", &req, "notif")
            .unwrap();

        let resp = svc
            .get_bucket_notification("123456789012", "notif")
            .unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("NotificationConfiguration"));
    }

    #[test]
    fn put_and_get_and_delete_bucket_encryption() {
        let svc = make_service();
        seed_bucket(&svc, "enc");

        let xml = b"<ServerSideEncryptionConfiguration><Rule><ApplyServerSideEncryptionByDefault><SSEAlgorithm>AES256</SSEAlgorithm></ApplyServerSideEncryptionByDefault></Rule></ServerSideEncryptionConfiguration>";
        let req = make_request(Method::PUT, "/enc", &[("encryption", "")], xml);
        svc.put_bucket_encryption("123456789012", &req, "enc")
            .unwrap();

        let resp = svc.get_bucket_encryption("123456789012", "enc").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("AES256"));

        svc.delete_bucket_encryption("123456789012", "enc").unwrap();
    }

    #[test]
    fn bucket_logging_put_and_get() {
        let svc = make_service();
        seed_bucket(&svc, "logging-b");

        let xml = b"<BucketLoggingStatus><LoggingEnabled><TargetBucket>logging-b</TargetBucket><TargetPrefix>logs/</TargetPrefix></LoggingEnabled></BucketLoggingStatus>";
        let req = make_request(Method::PUT, "/logging-b", &[("logging", "")], xml);
        svc.put_bucket_logging("123456789012", &req, "logging-b")
            .unwrap();

        let resp = svc.get_bucket_logging("123456789012", "logging-b").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("LoggingEnabled"));
    }

    // ── Versioned object operations ──

    #[tokio::test]
    async fn versioned_put_and_get() {
        let svc = make_service();
        seed_bucket(&svc, "vb");

        // Enable versioning
        let req = make_request(
            Method::PUT,
            "/vb",
            &[("versioning", "")],
            b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
        );
        svc.put_bucket_versioning("123456789012", &req, "vb")
            .unwrap();

        // Put v1
        let req = make_request(Method::PUT, "/vb/key", &[], b"version1");
        let resp = svc
            .put_object("123456789012", &req, "vb", "key")
            .await
            .unwrap();
        let v1 = resp
            .headers
            .get("x-amz-version-id")
            .map(|h| h.to_str().unwrap().to_string());
        assert!(v1.is_some());

        // Put v2
        let req = make_request(Method::PUT, "/vb/key", &[], b"version2");
        let resp = svc
            .put_object("123456789012", &req, "vb", "key")
            .await
            .unwrap();
        let _v2 = resp
            .headers
            .get("x-amz-version-id")
            .map(|h| h.to_str().unwrap().to_string());

        // Get latest
        let req = make_request(Method::GET, "/vb/key", &[], b"");
        let resp = svc.get_object("123456789012", &req, "vb", "key").unwrap();
        assert_eq!(resp.body.expect_bytes(), b"version2");

        // List versions
        let req = make_request(Method::GET, "/vb", &[("versions", "")], b"");
        let resp = svc
            .list_object_versions("123456789012", &req, "vb")
            .unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<Version>"));
    }

    // ── Conditional GET ──

    #[tokio::test]
    async fn get_object_if_match_succeeds() {
        let svc = make_service();
        seed_bucket(&svc, "cond");

        let req = make_request(Method::PUT, "/cond/f.txt", &[], b"data");
        let resp = svc
            .put_object("123456789012", &req, "cond", "f.txt")
            .await
            .unwrap();
        let etag = resp
            .headers
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let mut req = make_request(Method::GET, "/cond/f.txt", &[], b"");
        req.headers.insert("if-match", etag.parse().unwrap());
        let resp = svc
            .get_object("123456789012", &req, "cond", "f.txt")
            .unwrap();
        assert_eq!(resp.body.expect_bytes(), b"data");
    }

    #[tokio::test]
    async fn get_object_if_match_fails() {
        let svc = make_service();
        seed_bucket(&svc, "cond2");

        let req = make_request(Method::PUT, "/cond2/f.txt", &[], b"data");
        svc.put_object("123456789012", &req, "cond2", "f.txt")
            .await
            .unwrap();

        let mut req = make_request(Method::GET, "/cond2/f.txt", &[], b"");
        req.headers
            .insert("if-match", "\"wrong-etag\"".parse().unwrap());
        assert_aws_err(
            svc.get_object("123456789012", &req, "cond2", "f.txt"),
            "PreconditionFailed",
        );
    }

    #[tokio::test]
    async fn get_object_if_none_match_returns_304() {
        let svc = make_service();
        seed_bucket(&svc, "cond3");

        let req = make_request(Method::PUT, "/cond3/f.txt", &[], b"data");
        let resp = svc
            .put_object("123456789012", &req, "cond3", "f.txt")
            .await
            .unwrap();
        let etag = resp
            .headers
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();

        let mut req = make_request(Method::GET, "/cond3/f.txt", &[], b"");
        req.headers.insert("if-none-match", etag.parse().unwrap());
        let err = svc.get_object("123456789012", &req, "cond3", "f.txt");
        // Should return PreconditionFailed or 304 Not Modified
        assert!(err.is_err());
    }

    // ── Put with if-none-match (conditional put) ──

    #[tokio::test]
    async fn put_object_if_none_match_prevents_overwrite() {
        let svc = make_service();
        seed_bucket(&svc, "cnm");

        let req = make_request(Method::PUT, "/cnm/f.txt", &[], b"first");
        svc.put_object("123456789012", &req, "cnm", "f.txt")
            .await
            .unwrap();

        // Try to put again with if-none-match: *
        let mut req = make_request(Method::PUT, "/cnm/f.txt", &[], b"second");
        req.headers.insert("if-none-match", "*".parse().unwrap());
        assert_aws_err(
            svc.put_object("123456789012", &req, "cnm", "f.txt").await,
            "PreconditionFailed",
        );
    }

    // ── Storage class ──

    #[tokio::test]
    async fn put_object_with_storage_class() {
        let svc = make_service();
        seed_bucket(&svc, "sc");

        let mut req = make_request(Method::PUT, "/sc/f.txt", &[], b"data");
        req.headers
            .insert("x-amz-storage-class", "GLACIER".parse().unwrap());
        svc.put_object("123456789012", &req, "sc", "f.txt")
            .await
            .unwrap();

        let req = make_request(Method::HEAD, "/sc/f.txt", &[], b"");
        let resp = svc
            .head_object("123456789012", &req, "sc", "f.txt")
            .unwrap();
        assert_eq!(
            resp.headers
                .get("x-amz-storage-class")
                .unwrap()
                .to_str()
                .unwrap(),
            "GLACIER"
        );
    }

    // ── Delete versioned object creates delete marker ──

    #[tokio::test]
    async fn delete_versioned_object_creates_marker() {
        let svc = make_service();
        seed_bucket(&svc, "dv");

        let req = make_request(
            Method::PUT,
            "/dv",
            &[("versioning", "")],
            b"<VersioningConfiguration><Status>Enabled</Status></VersioningConfiguration>",
        );
        svc.put_bucket_versioning("123456789012", &req, "dv")
            .unwrap();

        let req = make_request(Method::PUT, "/dv/key", &[], b"data");
        svc.put_object("123456789012", &req, "dv", "key")
            .await
            .unwrap();

        let req = make_request(Method::DELETE, "/dv/key", &[], b"");
        let resp = svc
            .delete_object("123456789012", &req, "dv", "key")
            .unwrap();
        assert!(resp.headers.get("x-amz-delete-marker").is_some());

        // GET should fail (object is "deleted")
        let req = make_request(Method::GET, "/dv/key", &[], b"");
        assert_aws_err(
            svc.get_object("123456789012", &req, "dv", "key"),
            "NoSuchKey",
        );
    }

    // ── Copy with metadata replacement ──

    #[tokio::test]
    async fn copy_object_with_metadata_replace() {
        let svc = make_service();
        seed_bucket(&svc, "cpm");

        let mut req = make_request(Method::PUT, "/cpm/src", &[], b"data");
        req.headers
            .insert("x-amz-meta-original", "yes".parse().unwrap());
        svc.put_object("123456789012", &req, "cpm", "src")
            .await
            .unwrap();

        let mut req = make_request(Method::PUT, "/cpm/dst", &[], b"");
        req.headers
            .insert("x-amz-copy-source", "cpm/src".parse().unwrap());
        req.headers
            .insert("x-amz-metadata-directive", "REPLACE".parse().unwrap());
        req.headers
            .insert("x-amz-meta-new-key", "new-val".parse().unwrap());
        svc.copy_object("123456789012", &req, "cpm", "dst").unwrap();

        let req = make_request(Method::HEAD, "/cpm/dst", &[], b"");
        let resp = svc.head_object("123456789012", &req, "cpm", "dst").unwrap();
        assert!(resp
            .headers
            .get("x-amz-meta-new-key")
            .is_some_and(|v| v == "new-val"));
        // Original metadata should NOT be present
        assert!(resp.headers.get("x-amz-meta-original").is_none());
    }

    // ── Large list with pagination (max-keys) ──

    #[tokio::test]
    async fn list_objects_v2_with_max_keys() {
        let svc = make_service();
        seed_bucket(&svc, "pg");

        for i in 0..5 {
            let key = format!("k{i}");
            let req = make_request(Method::PUT, &format!("/pg/{key}"), &[], b"x");
            svc.put_object("123456789012", &req, "pg", &key)
                .await
                .unwrap();
        }

        let req = make_request(
            Method::GET,
            "/pg",
            &[("list-type", "2"), ("max-keys", "2")],
            b"",
        );
        let resp = svc.list_objects_v2("123456789012", &req, "pg").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<IsTruncated>true</IsTruncated>"));
        assert!(body.contains("<MaxKeys>2</MaxKeys>"));
    }

    // ── buckets.rs coverage (list/create/delete/head/location) ──

    #[test]
    fn list_buckets_empty_account() {
        let svc = make_service();
        let req = make_request(Method::GET, "/", &[], b"");
        let resp = svc.list_buckets("123456789012", &req).unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<ListAllMyBucketsResult"));
        assert!(body.contains("<Owner><ID>123456789012</ID>"));
        assert!(body.contains("<Buckets></Buckets>"));
    }

    #[test]
    fn list_buckets_sorted_by_name() {
        let svc = make_service();
        seed_bucket(&svc, "zeta");
        seed_bucket(&svc, "alpha");
        seed_bucket(&svc, "middle");

        let req = make_request(Method::GET, "/", &[], b"");
        let resp = svc.list_buckets("123456789012", &req).unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        let a = body.find("alpha").unwrap();
        let m = body.find("middle").unwrap();
        let z = body.find("zeta").unwrap();
        assert!(a < m && m < z, "buckets must be sorted");
    }

    fn seed_bucket_in_region(svc: &S3Service, name: &str, region: &str) {
        let mut mas = svc.state.write();
        let state = mas.default_mut();
        state
            .buckets
            .insert(name.to_string(), S3Bucket::new(name, region, "owner"));
    }

    #[test]
    fn list_buckets_includes_bucket_region() {
        let svc = make_service();
        seed_bucket(&svc, "alpha");

        let req = make_request(Method::GET, "/", &[], b"");
        let resp = svc.list_buckets("123456789012", &req).unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(
            body.contains("<BucketRegion>us-east-1</BucketRegion>"),
            "response should include BucketRegion per-bucket: {body}"
        );
    }

    #[test]
    fn list_buckets_filter_by_bucket_region() {
        let svc = make_service();
        seed_bucket_in_region(&svc, "east-bucket", "us-east-1");
        seed_bucket_in_region(&svc, "west-bucket", "us-west-2");

        let req = make_request(Method::GET, "/", &[("bucket-region", "us-west-2")], b"");
        let resp = svc.list_buckets("123456789012", &req).unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("west-bucket"));
        assert!(!body.contains("east-bucket"));
        assert!(body.contains("<BucketRegion>us-west-2</BucketRegion>"));
    }

    #[test]
    fn list_buckets_filter_by_prefix() {
        let svc = make_service();
        seed_bucket(&svc, "foo-1");
        seed_bucket(&svc, "foo-2");
        seed_bucket(&svc, "bar");

        let req = make_request(Method::GET, "/", &[("prefix", "foo-")], b"");
        let resp = svc.list_buckets("123456789012", &req).unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("foo-1"));
        assert!(body.contains("foo-2"));
        assert!(!body.contains("<Name>bar</Name>"));
        assert!(body.contains("<Prefix>foo-</Prefix>"));
    }

    #[test]
    fn list_buckets_max_buckets_paginates() {
        let svc = make_service();
        for n in &["a", "b", "c", "d", "e"] {
            seed_bucket(&svc, n);
        }

        let req = make_request(Method::GET, "/", &[("max-buckets", "2")], b"");
        let resp = svc.list_buckets("123456789012", &req).unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<Name>a</Name>"));
        assert!(body.contains("<Name>b</Name>"));
        assert!(!body.contains("<Name>c</Name>"));
        assert!(body.contains("<ContinuationToken>"));
    }

    #[test]
    fn list_buckets_continuation_token_resumes() {
        let svc = make_service();
        for n in &["a", "b", "c", "d", "e"] {
            seed_bucket(&svc, n);
        }

        let req = make_request(Method::GET, "/", &[("max-buckets", "2")], b"");
        let resp = svc.list_buckets("123456789012", &req).unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        let start = body.find("<ContinuationToken>").unwrap() + "<ContinuationToken>".len();
        let end = body.find("</ContinuationToken>").unwrap();
        let token = body[start..end].to_string();

        let req2 = make_request(
            Method::GET,
            "/",
            &[("max-buckets", "2"), ("continuation-token", &token)],
            b"",
        );
        let resp2 = svc.list_buckets("123456789012", &req2).unwrap();
        let body2 = std::str::from_utf8(resp2.body.expect_bytes()).unwrap();
        assert!(body2.contains("<Name>c</Name>"));
        assert!(body2.contains("<Name>d</Name>"));
        assert!(!body2.contains("<Name>a</Name>"));
        assert!(!body2.contains("<Name>b</Name>"));
        // page 2 has more (e remains) so still emits a token
        assert!(body2.contains("<ContinuationToken>"));

        // page 3: should be e + no continuation
        let start = body2.find("<ContinuationToken>").unwrap() + "<ContinuationToken>".len();
        let end = body2.find("</ContinuationToken>").unwrap();
        let token2 = body2[start..end].to_string();
        let req3 = make_request(
            Method::GET,
            "/",
            &[("max-buckets", "2"), ("continuation-token", &token2)],
            b"",
        );
        let resp3 = svc.list_buckets("123456789012", &req3).unwrap();
        let body3 = std::str::from_utf8(resp3.body.expect_bytes()).unwrap();
        assert!(body3.contains("<Name>e</Name>"));
        assert!(!body3.contains("<ContinuationToken>"));
    }

    #[test]
    fn list_buckets_invalid_max_buckets_errors() {
        let svc = make_service();
        let req = make_request(Method::GET, "/", &[("max-buckets", "0")], b"");
        assert_aws_err(svc.list_buckets("123456789012", &req), "InvalidArgument");

        let req2 = make_request(Method::GET, "/", &[("max-buckets", "20000")], b"");
        assert_aws_err(svc.list_buckets("123456789012", &req2), "InvalidArgument");

        let req3 = make_request(Method::GET, "/", &[("max-buckets", "abc")], b"");
        assert_aws_err(svc.list_buckets("123456789012", &req3), "InvalidArgument");
    }

    #[test]
    fn list_buckets_invalid_continuation_token_errors() {
        let svc = make_service();
        let req = make_request(
            Method::GET,
            "/",
            &[("continuation-token", "!!!notb64!!!")],
            b"",
        );
        assert_aws_err(svc.list_buckets("123456789012", &req), "InvalidArgument");

        let req2 = make_request(Method::GET, "/", &[("continuation-token", "")], b"");
        assert_aws_err(svc.list_buckets("123456789012", &req2), "InvalidArgument");
    }

    #[test]
    fn create_bucket_invalid_name_errors() {
        let svc = make_service();
        let req = make_request(Method::PUT, "/AB", &[], b"");
        assert_aws_err(
            svc.create_bucket("123456789012", &req, "AB"),
            "InvalidBucketName",
        );
    }

    #[test]
    fn create_bucket_idempotent_same_region_us_east_1() {
        let svc = make_service();
        let req = make_request(Method::PUT, "/idem", &[], b"");
        svc.create_bucket("123456789012", &req, "idem").unwrap();
        let resp = svc.create_bucket("123456789012", &req, "idem").unwrap();
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn create_bucket_already_owned_other_region() {
        let svc = make_service();
        let mut req = make_request(
            Method::PUT,
            "/bk1",
            &[],
            b"<CreateBucketConfiguration><LocationConstraint>eu-west-1</LocationConstraint></CreateBucketConfiguration>",
        );
        req.region = "eu-west-1".to_string();
        svc.create_bucket("123456789012", &req, "bk1").unwrap();
        assert_aws_err(
            svc.create_bucket("123456789012", &req, "bk1"),
            "BucketAlreadyOwnedByYou",
        );
    }

    #[test]
    fn create_bucket_us_east_1_with_explicit_constraint_invalid() {
        let svc = make_service();
        let req = make_request(
            Method::PUT,
            "/bk2",
            &[],
            b"<CreateBucketConfiguration><LocationConstraint>us-east-1</LocationConstraint></CreateBucketConfiguration>",
        );
        assert_aws_err(
            svc.create_bucket("123456789012", &req, "bk2"),
            "InvalidLocationConstraint",
        );
    }

    #[test]
    fn create_bucket_constraint_mismatch_region_errors() {
        let svc = make_service();
        let mut req = make_request(
            Method::PUT,
            "/bk3",
            &[],
            b"<CreateBucketConfiguration><LocationConstraint>us-west-2</LocationConstraint></CreateBucketConfiguration>",
        );
        req.region = "eu-west-1".to_string();
        assert_aws_err(
            svc.create_bucket("123456789012", &req, "bk3"),
            "IllegalLocationConstraintException",
        );
    }

    #[test]
    fn create_bucket_missing_constraint_in_non_default_region_errors() {
        let svc = make_service();
        let mut req = make_request(Method::PUT, "/bk4", &[], b"");
        req.region = "eu-west-1".to_string();
        assert_aws_err(
            svc.create_bucket("123456789012", &req, "bk4"),
            "IllegalLocationConstraintException",
        );
    }

    #[test]
    fn create_bucket_invalid_region_constraint() {
        let svc = make_service();
        let req = make_request(
            Method::PUT,
            "/bk5",
            &[],
            b"<CreateBucketConfiguration><LocationConstraint>not-a-region</LocationConstraint></CreateBucketConfiguration>",
        );
        assert_aws_err(
            svc.create_bucket("123456789012", &req, "bk5"),
            "InvalidLocationConstraint",
        );
    }

    #[test]
    fn create_bucket_with_us_east_1_constraint_when_region_not_matching() {
        let svc = make_service();
        let mut req = make_request(
            Method::PUT,
            "/bk6",
            &[],
            b"<CreateBucketConfiguration><LocationConstraint>us-east-1</LocationConstraint></CreateBucketConfiguration>",
        );
        req.region = "eu-west-1".to_string();
        assert_aws_err(
            svc.create_bucket("123456789012", &req, "bk6"),
            "IllegalLocationConstraintException",
        );
    }

    #[test]
    fn create_bucket_with_object_lock_enables_versioning() {
        let svc = make_service();
        let mut req = make_request(Method::PUT, "/olb", &[], b"");
        req.headers
            .insert("x-amz-bucket-object-lock-enabled", "true".parse().unwrap());
        svc.create_bucket("123456789012", &req, "olb").unwrap();
        let accts = svc.state.read();
        let state = accts.get("123456789012").unwrap();
        let b = state.buckets.get("olb").unwrap();
        assert_eq!(b.versioning.as_deref(), Some("Enabled"));
        assert!(b
            .object_lock_config
            .as_deref()
            .unwrap_or("")
            .contains("ObjectLockEnabled"));
    }

    #[test]
    fn create_bucket_with_object_ownership_header() {
        let svc = make_service();
        let mut req = make_request(Method::PUT, "/own", &[], b"");
        req.headers.insert(
            "x-amz-object-ownership",
            "BucketOwnerEnforced".parse().unwrap(),
        );
        svc.create_bucket("123456789012", &req, "own").unwrap();
        let accts = svc.state.read();
        let state = accts.get("123456789012").unwrap();
        let b = state.buckets.get("own").unwrap();
        assert!(b
            .ownership_controls
            .as_deref()
            .unwrap_or("")
            .contains("BucketOwnerEnforced"));
    }

    #[test]
    fn create_bucket_with_canned_acl_public_read() {
        let svc = make_service();
        let mut req = make_request(Method::PUT, "/prb", &[], b"");
        req.headers
            .insert("x-amz-acl", "public-read".parse().unwrap());
        svc.create_bucket("123456789012", &req, "prb").unwrap();
        let accts = svc.state.read();
        let state = accts.get("123456789012").unwrap();
        let b = state.buckets.get("prb").unwrap();
        assert!(!b.acl_grants.is_empty());
    }

    #[test]
    fn delete_bucket_nonexistent_errors() {
        let svc = make_service();
        let req = make_request(Method::DELETE, "/nope", &[], b"");
        assert_aws_err(
            svc.delete_bucket("123456789012", &req, "nope"),
            "NoSuchBucket",
        );
    }

    #[test]
    fn delete_bucket_not_empty_errors() {
        let svc = make_service();
        seed_bucket(&svc, "full");
        seed_object(&svc, "full", "k", b"x");
        let req = make_request(Method::DELETE, "/full", &[], b"");
        assert_aws_err(
            svc.delete_bucket("123456789012", &req, "full"),
            "BucketNotEmpty",
        );
    }

    #[test]
    fn delete_bucket_with_versions_not_empty_errors() {
        let svc = make_service();
        seed_bucket(&svc, "ver");
        {
            let mut mas = svc.state.write();
            let state = mas.default_mut();
            let b = state.buckets.get_mut("ver").unwrap();
            b.object_versions.insert(
                "k".to_string(),
                vec![S3Object {
                    key: "k".to_string(),
                    body: fakecloud_persistence::BodyRef::Memory(Bytes::from_static(b"v")),
                    content_type: "text/plain".to_string(),
                    etag: "\"abc\"".to_string(),
                    size: 1,
                    last_modified: chrono::Utc::now(),
                    ..Default::default()
                }],
            );
        }
        let req = make_request(Method::DELETE, "/ver", &[], b"");
        assert_aws_err(
            svc.delete_bucket("123456789012", &req, "ver"),
            "BucketNotEmpty",
        );
    }

    #[test]
    fn delete_bucket_empty_succeeds() {
        let svc = make_service();
        seed_bucket(&svc, "empty");
        let req = make_request(Method::DELETE, "/empty", &[], b"");
        let resp = svc.delete_bucket("123456789012", &req, "empty").unwrap();
        assert_eq!(resp.status, StatusCode::NO_CONTENT);
    }

    #[test]
    fn head_bucket_missing_errors() {
        let svc = make_service();
        assert_aws_err(svc.head_bucket("123456789012", "nope"), "NoSuchBucket");
    }

    #[test]
    fn head_bucket_exists_returns_ok() {
        let svc = make_service();
        seed_bucket(&svc, "hb");
        let resp = svc.head_bucket("123456789012", "hb").unwrap();
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn get_bucket_location_us_east_1_returns_empty() {
        let svc = make_service();
        seed_bucket(&svc, "loc");
        let resp = svc.get_bucket_location("123456789012", "loc").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<LocationConstraint"));
        assert!(body.contains("></LocationConstraint>"));
    }

    #[test]
    fn get_bucket_location_other_region_returns_region() {
        let svc = make_service();
        {
            let mut mas = svc.state.write();
            let state = mas.default_mut();
            state
                .buckets
                .insert("eu".to_string(), S3Bucket::new("eu", "eu-west-1", "owner"));
        }
        let resp = svc.get_bucket_location("123456789012", "eu").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains(">eu-west-1<"));
    }

    // ── objects.rs additional coverage ──

    #[tokio::test]
    async fn get_object_range_request() {
        let svc = make_service();
        seed_bucket(&svc, "range");
        let req = make_request(Method::PUT, "/range/k", &[], b"0123456789ABCDEF");
        svc.put_object("123456789012", &req, "range", "k")
            .await
            .unwrap();

        let mut req = make_request(Method::GET, "/range/k", &[], b"");
        req.headers.insert("range", "bytes=2-5".parse().unwrap());
        let resp = svc.get_object("123456789012", &req, "range", "k").unwrap();
        assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(resp.body.expect_bytes(), b"2345");
    }

    #[tokio::test]
    async fn get_object_range_suffix() {
        let svc = make_service();
        seed_bucket(&svc, "rsx");
        let req = make_request(Method::PUT, "/rsx/k", &[], b"0123456789");
        svc.put_object("123456789012", &req, "rsx", "k")
            .await
            .unwrap();

        let mut req = make_request(Method::GET, "/rsx/k", &[], b"");
        req.headers.insert("range", "bytes=-3".parse().unwrap());
        let resp = svc.get_object("123456789012", &req, "rsx", "k").unwrap();
        assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(resp.body.expect_bytes(), b"789");
    }

    #[tokio::test]
    async fn get_object_range_open_ended() {
        let svc = make_service();
        seed_bucket(&svc, "roe");
        let req = make_request(Method::PUT, "/roe/k", &[], b"0123456789");
        svc.put_object("123456789012", &req, "roe", "k")
            .await
            .unwrap();

        let mut req = make_request(Method::GET, "/roe/k", &[], b"");
        req.headers.insert("range", "bytes=7-".parse().unwrap());
        let resp = svc.get_object("123456789012", &req, "roe", "k").unwrap();
        assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
        assert_eq!(resp.body.expect_bytes(), b"789");
    }

    #[tokio::test]
    async fn get_object_range_invalid_format() {
        let svc = make_service();
        seed_bucket(&svc, "rinv");
        let req = make_request(Method::PUT, "/rinv/k", &[], b"hello");
        svc.put_object("123456789012", &req, "rinv", "k")
            .await
            .unwrap();

        let mut req = make_request(Method::GET, "/rinv/k", &[], b"");
        req.headers.insert("range", "bogus=2-5".parse().unwrap());
        // Non-standard prefix -> full content expected
        let resp = svc.get_object("123456789012", &req, "rinv", "k").unwrap();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.body.expect_bytes(), b"hello");
    }

    #[tokio::test]
    async fn get_object_if_match_mismatch_errors() {
        let svc = make_service();
        seed_bucket(&svc, "ifm");
        let req = make_request(Method::PUT, "/ifm/k", &[], b"abc");
        svc.put_object("123456789012", &req, "ifm", "k")
            .await
            .unwrap();

        let mut req = make_request(Method::GET, "/ifm/k", &[], b"");
        req.headers
            .insert("if-match", "\"nomatch\"".parse().unwrap());
        let err = svc.get_object("123456789012", &req, "ifm", "k");
        assert_aws_err(err, "PreconditionFailed");
    }

    #[tokio::test]
    async fn get_object_if_none_match_star_not_modified() {
        let svc = make_service();
        seed_bucket(&svc, "inm");
        let req = make_request(Method::PUT, "/inm/k", &[], b"abc");
        svc.put_object("123456789012", &req, "inm", "k")
            .await
            .unwrap();

        let mut req = make_request(Method::GET, "/inm/k", &[], b"");
        req.headers.insert("if-none-match", "*".parse().unwrap());
        let err = svc.get_object("123456789012", &req, "inm", "k");
        assert!(err.is_err());
    }

    #[tokio::test]
    async fn head_object_range_request() {
        let svc = make_service();
        seed_bucket(&svc, "hrng");
        let req = make_request(Method::PUT, "/hrng/k", &[], b"0123456789");
        svc.put_object("123456789012", &req, "hrng", "k")
            .await
            .unwrap();

        let mut req = make_request(Method::HEAD, "/hrng/k", &[], b"");
        req.headers.insert("range", "bytes=2-5".parse().unwrap());
        let resp = svc.head_object("123456789012", &req, "hrng", "k").unwrap();
        assert_eq!(resp.status, StatusCode::PARTIAL_CONTENT);
    }

    #[tokio::test]
    async fn put_object_with_metadata_headers() {
        let svc = make_service();
        seed_bucket(&svc, "meta");
        let mut req = make_request(Method::PUT, "/meta/k", &[], b"x");
        req.headers
            .insert("x-amz-meta-user", "alice".parse().unwrap());
        req.headers
            .insert("x-amz-meta-env", "prod".parse().unwrap());
        svc.put_object("123456789012", &req, "meta", "k")
            .await
            .unwrap();

        let req = make_request(Method::HEAD, "/meta/k", &[], b"");
        let resp = svc.head_object("123456789012", &req, "meta", "k").unwrap();
        assert_eq!(resp.headers.get("x-amz-meta-user").unwrap(), "alice");
        assert_eq!(resp.headers.get("x-amz-meta-env").unwrap(), "prod");
    }

    #[tokio::test]
    async fn put_object_with_storage_class_header() {
        let svc = make_service();
        seed_bucket(&svc, "stor");
        let mut req = make_request(Method::PUT, "/stor/k", &[], b"x");
        req.headers
            .insert("x-amz-storage-class", "STANDARD_IA".parse().unwrap());
        svc.put_object("123456789012", &req, "stor", "k")
            .await
            .unwrap();

        let req = make_request(Method::HEAD, "/stor/k", &[], b"");
        let resp = svc.head_object("123456789012", &req, "stor", "k").unwrap();
        assert_eq!(
            resp.headers.get("x-amz-storage-class").unwrap(),
            "STANDARD_IA"
        );
    }

    #[tokio::test]
    async fn put_object_with_website_redirect() {
        let svc = make_service();
        seed_bucket(&svc, "wr");
        let mut req = make_request(Method::PUT, "/wr/k", &[], b"x");
        req.headers.insert(
            "x-amz-website-redirect-location",
            "/elsewhere".parse().unwrap(),
        );
        svc.put_object("123456789012", &req, "wr", "k")
            .await
            .unwrap();
        let req = make_request(Method::GET, "/wr/k", &[], b"");
        let resp = svc.get_object("123456789012", &req, "wr", "k").unwrap();
        assert_eq!(
            resp.headers.get("x-amz-website-redirect-location").unwrap(),
            "/elsewhere"
        );
    }

    #[test]
    fn delete_object_nonexistent_is_ok() {
        let svc = make_service();
        seed_bucket(&svc, "dne");
        let req = make_request(Method::DELETE, "/dne/missing", &[], b"");
        let resp = svc
            .delete_object("123456789012", &req, "dne", "missing")
            .unwrap();
        assert_eq!(resp.status, StatusCode::NO_CONTENT);
    }

    #[test]
    fn delete_object_bucket_not_found() {
        let svc = make_service();
        let req = make_request(Method::DELETE, "/nope/k", &[], b"");
        assert_aws_err(
            svc.delete_object("123456789012", &req, "nope", "k"),
            "NoSuchBucket",
        );
    }

    #[tokio::test]
    async fn list_objects_v2_with_prefix_and_delimiter() {
        let svc = make_service();
        seed_bucket(&svc, "pfxd");
        for k in &["a/1", "a/2", "b/1"] {
            let req = make_request(Method::PUT, &format!("/pfxd/{k}"), &[], b"x");
            svc.put_object("123456789012", &req, "pfxd", k)
                .await
                .unwrap();
        }
        let req = make_request(
            Method::GET,
            "/pfxd",
            &[("list-type", "2"), ("prefix", "a/"), ("delimiter", "/")],
            b"",
        );
        let resp = svc.list_objects_v2("123456789012", &req, "pfxd").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<Contents>"));
    }

    #[tokio::test]
    async fn list_objects_v1_basic() {
        let svc = make_service();
        seed_bucket(&svc, "v1");
        for k in &["a", "b"] {
            let req = make_request(Method::PUT, &format!("/v1/{k}"), &[], b"x");
            svc.put_object("123456789012", &req, "v1", k).await.unwrap();
        }
        let req = make_request(Method::GET, "/v1", &[], b"");
        let resp = svc.list_objects_v1("123456789012", &req, "v1").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<ListBucketResult"));
        assert!(body.contains("<Key>a</Key>"));
        assert!(body.contains("<Key>b</Key>"));
    }

    #[test]
    fn get_object_key_not_found() {
        let svc = make_service();
        seed_bucket(&svc, "gkn");
        let req = make_request(Method::GET, "/gkn/missing", &[], b"");
        assert_aws_err(
            svc.get_object("123456789012", &req, "gkn", "missing"),
            "NoSuchKey",
        );
    }

    #[test]
    fn get_object_bucket_not_found() {
        let svc = make_service();
        let req = make_request(Method::GET, "/ghost/k", &[], b"");
        assert_aws_err(
            svc.get_object("123456789012", &req, "ghost", "k"),
            "NoSuchBucket",
        );
    }

    // ── restore_object ──

    #[tokio::test]
    async fn restore_object_non_archival_errors() {
        let svc = make_service();
        seed_bucket(&svc, "roc");
        let req = make_request(Method::PUT, "/roc/k", &[], b"x");
        svc.put_object("123456789012", &req, "roc", "k")
            .await
            .unwrap();

        let req = make_request(Method::POST, "/roc/k", &[("restore", "")], b"");
        assert_aws_err(
            svc.restore_object("123456789012", &req, "roc", "k"),
            "InvalidObjectState",
        );
    }

    #[tokio::test]
    async fn restore_object_glacier_accepted() {
        let svc = make_service();
        seed_bucket(&svc, "rog");
        let mut req = make_request(Method::PUT, "/rog/k", &[], b"x");
        req.headers
            .insert("x-amz-storage-class", "GLACIER".parse().unwrap());
        svc.put_object("123456789012", &req, "rog", "k")
            .await
            .unwrap();

        let req = make_request(Method::POST, "/rog/k", &[("restore", "")], b"");
        let resp = svc
            .restore_object("123456789012", &req, "rog", "k")
            .unwrap();
        assert_eq!(resp.status, StatusCode::ACCEPTED);
    }

    #[test]
    fn restore_object_nonexistent_key() {
        let svc = make_service();
        seed_bucket(&svc, "rnk");
        let req = make_request(Method::POST, "/rnk/ghost", &[("restore", "")], b"");
        assert_aws_err(
            svc.restore_object("123456789012", &req, "rnk", "ghost"),
            "NoSuchKey",
        );
    }

    // ── list_object_versions ──

    #[tokio::test]
    async fn list_object_versions_basic() {
        let svc = make_service();
        seed_bucket(&svc, "lov");
        {
            let mut mas = svc.state.write();
            let state = mas.default_mut();
            let b = state.buckets.get_mut("lov").unwrap();
            b.versioning = Some("Enabled".to_string());
        }
        let req = make_request(Method::PUT, "/lov/k", &[], b"v1");
        svc.put_object("123456789012", &req, "lov", "k")
            .await
            .unwrap();
        let req = make_request(Method::PUT, "/lov/k", &[], b"v2");
        svc.put_object("123456789012", &req, "lov", "k")
            .await
            .unwrap();

        let req = make_request(Method::GET, "/lov", &[("versions", "")], b"");
        let resp = svc
            .list_object_versions("123456789012", &req, "lov")
            .unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<ListVersionsResult"));
    }

    #[test]
    fn delete_objects_nonexistent_bucket() {
        let svc = make_service();
        let xml = b"<Delete><Object><Key>k</Key></Object></Delete>";
        let req = make_request(Method::POST, "/ghost", &[("delete", "")], xml);
        assert_aws_err(
            svc.delete_objects("123456789012", &req, "ghost"),
            "NoSuchBucket",
        );
    }

    #[tokio::test]
    async fn put_object_custom_content_type() {
        let svc = make_service();
        seed_bucket(&svc, "ct");
        let mut req = make_request(Method::PUT, "/ct/k", &[], b"hi");
        req.headers
            .insert("content-type", "text/plain".parse().unwrap());
        svc.put_object("123456789012", &req, "ct", "k")
            .await
            .unwrap();
        let req = make_request(Method::GET, "/ct/k", &[], b"");
        let resp = svc.get_object("123456789012", &req, "ct", "k").unwrap();
        assert_eq!(resp.content_type, "text/plain");
    }

    #[test]
    fn head_object_bucket_not_found() {
        let svc = make_service();
        let req = make_request(Method::HEAD, "/ghost/k", &[], b"");
        let result = svc.head_object("123456789012", &req, "ghost", "k");
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn get_object_attributes_basic() {
        let svc = make_service();
        seed_bucket(&svc, "goa");
        let req = make_request(Method::PUT, "/goa/k", &[], b"hi");
        svc.put_object("123456789012", &req, "goa", "k")
            .await
            .unwrap();

        let mut req = make_request(Method::GET, "/goa/k", &[("attributes", "")], b"");
        req.headers.insert(
            "x-amz-object-attributes",
            "ETag,ObjectSize".parse().unwrap(),
        );
        let resp = svc
            .get_object_attributes("123456789012", &req, "goa", "k")
            .unwrap();
        assert_eq!(resp.status, StatusCode::OK);
    }

    #[test]
    fn get_object_attributes_bucket_not_found() {
        let svc = make_service();
        let req = make_request(Method::GET, "/ghost/k", &[("attributes", "")], b"");
        let result = svc.get_object_attributes("123456789012", &req, "ghost", "k");
        assert!(result.is_err());
    }

    #[test]
    fn get_object_attributes_key_not_found() {
        let svc = make_service();
        seed_bucket(&svc, "gak");
        let req = make_request(Method::GET, "/gak/ghost", &[("attributes", "")], b"");
        let result = svc.get_object_attributes("123456789012", &req, "gak", "ghost");
        assert!(result.is_err());
    }

    // ── ACL ──

    #[test]
    fn get_object_acl_bucket_not_found() {
        let svc = make_service();
        let req = make_request(Method::GET, "/ghost/k", &[("acl", "")], b"");
        assert!(svc
            .get_object_acl("123456789012", &req, "ghost", "k")
            .is_err());
    }

    #[test]
    fn put_object_acl_bucket_not_found() {
        let svc = make_service();
        let mut req = make_request(Method::PUT, "/ghost/k", &[("acl", "")], b"");
        req.headers.insert("x-amz-acl", "private".parse().unwrap());
        assert!(svc
            .put_object_acl("123456789012", &req, "ghost", "k")
            .is_err());
    }

    #[tokio::test]
    async fn get_object_acl_returns_acl_xml() {
        let svc = make_service();
        seed_bucket(&svc, "acl");
        let req = make_request(Method::PUT, "/acl/k", &[], b"x");
        svc.put_object("123456789012", &req, "acl", "k")
            .await
            .unwrap();
        let req = make_request(Method::GET, "/acl/k", &[("acl", "")], b"");
        let resp = svc
            .get_object_acl("123456789012", &req, "acl", "k")
            .unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("AccessControlPolicy"));
    }

    // ── object lock ──

    #[test]
    fn put_object_retention_bucket_not_found() {
        let svc = make_service();
        let xml = b"<Retention><Mode>GOVERNANCE</Mode><RetainUntilDate>2030-01-01T00:00:00Z</RetainUntilDate></Retention>";
        let req = make_request(Method::PUT, "/ghost/k", &[("retention", "")], xml);
        assert!(svc
            .put_object_retention("123456789012", &req, "ghost", "k")
            .is_err());
    }

    #[test]
    fn get_object_legal_hold_bucket_not_found() {
        let svc = make_service();
        let req = make_request(Method::GET, "/ghost/k", &[("legal-hold", "")], b"");
        assert!(svc
            .get_object_legal_hold("123456789012", &req, "ghost", "k")
            .is_err());
    }

    #[test]
    fn get_object_retention_bucket_not_found() {
        let svc = make_service();
        let req = make_request(Method::GET, "/ghost/k", &[("retention", "")], b"");
        assert!(svc
            .get_object_retention("123456789012", &req, "ghost", "k")
            .is_err());
    }

    // ── Multipart variations ──

    #[test]
    fn list_multipart_uploads_nonexistent_bucket() {
        let svc = make_service();
        assert!(svc.list_multipart_uploads("123456789012", "ghost").is_err());
    }

    #[test]
    fn list_multipart_uploads_empty() {
        let svc = make_service();
        seed_bucket(&svc, "empmp");
        let resp = svc.list_multipart_uploads("123456789012", "empmp").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<ListMultipartUploadsResult"));
    }

    #[test]
    fn put_public_access_block_bucket_not_found() {
        let svc = make_service();
        let xml = b"<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls></PublicAccessBlockConfiguration>";
        let req = make_request(Method::PUT, "/ghost", &[("publicAccessBlock", "")], xml);
        assert!(svc
            .put_public_access_block("123456789012", &req, "ghost")
            .is_err());
    }

    #[test]
    fn public_access_block_lifecycle() {
        let svc = make_service();
        seed_bucket(&svc, "pab");
        let xml = b"<PublicAccessBlockConfiguration><BlockPublicAcls>true</BlockPublicAcls><IgnorePublicAcls>true</IgnorePublicAcls></PublicAccessBlockConfiguration>";
        let req = make_request(Method::PUT, "/pab", &[("publicAccessBlock", "")], xml);
        svc.put_public_access_block("123456789012", &req, "pab")
            .unwrap();

        let resp = svc.get_public_access_block("123456789012", "pab").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("BlockPublicAcls"));

        svc.delete_public_access_block("123456789012", "pab")
            .unwrap();
    }

    #[test]
    fn put_bucket_replication_bucket_not_found() {
        let svc = make_service();
        let xml = b"<ReplicationConfiguration><Role>arn</Role></ReplicationConfiguration>";
        let req = make_request(Method::PUT, "/ghost", &[("replication", "")], xml);
        assert!(svc
            .put_bucket_replication("123456789012", &req, "ghost")
            .is_err());
    }

    #[test]
    fn put_ownership_controls_bucket_not_found() {
        let svc = make_service();
        let xml = b"<OwnershipControls><Rule><ObjectOwnership>BucketOwnerEnforced</ObjectOwnership></Rule></OwnershipControls>";
        let req = make_request(Method::PUT, "/ghost", &[("ownershipControls", "")], xml);
        assert!(svc
            .put_bucket_ownership_controls("123456789012", &req, "ghost")
            .is_err());
    }

    #[test]
    fn put_bucket_accelerate_bucket_not_found() {
        let svc = make_service();
        let xml = b"<AccelerateConfiguration><Status>Enabled</Status></AccelerateConfiguration>";
        let req = make_request(Method::PUT, "/ghost", &[("accelerate", "")], xml);
        assert!(svc
            .put_bucket_accelerate("123456789012", &req, "ghost")
            .is_err());
    }

    #[test]
    fn get_bucket_accelerate_lifecycle() {
        let svc = make_service();
        seed_bucket(&svc, "acc");
        let xml = b"<AccelerateConfiguration><Status>Enabled</Status></AccelerateConfiguration>";
        let req = make_request(Method::PUT, "/acc", &[("accelerate", "")], xml);
        svc.put_bucket_accelerate("123456789012", &req, "acc")
            .unwrap();
        let resp = svc.get_bucket_accelerate("123456789012", "acc").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("AccelerateConfiguration"));
    }

    #[test]
    fn put_bucket_website_bucket_not_found() {
        let svc = make_service();
        let xml = b"<WebsiteConfiguration><IndexDocument><Suffix>index.html</Suffix></IndexDocument></WebsiteConfiguration>";
        let req = make_request(Method::PUT, "/ghost", &[("website", "")], xml);
        assert!(svc
            .put_bucket_website("123456789012", &req, "ghost")
            .is_err());
    }

    #[test]
    fn put_object_tagging_bucket_not_found() {
        let svc = make_service();
        let xml = b"<Tagging><TagSet></TagSet></Tagging>";
        let req = make_request(Method::PUT, "/ghost/k", &[("tagging", "")], xml);
        assert!(svc
            .put_object_tagging("123456789012", &req, "ghost", "k")
            .is_err());
    }

    #[test]
    fn put_object_tagging_key_not_found() {
        let svc = make_service();
        seed_bucket(&svc, "pot");
        let xml = b"<Tagging><TagSet></TagSet></Tagging>";
        let req = make_request(Method::PUT, "/pot/ghost", &[("tagging", "")], xml);
        assert!(svc
            .put_object_tagging("123456789012", &req, "pot", "ghost")
            .is_err());
    }

    #[tokio::test]
    async fn put_object_tagging_lifecycle() {
        let svc = make_service();
        seed_bucket(&svc, "pota");
        let req = make_request(Method::PUT, "/pota/k", &[], b"x");
        svc.put_object("123456789012", &req, "pota", "k")
            .await
            .unwrap();

        let xml =
            b"<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>";
        let req = make_request(Method::PUT, "/pota/k", &[("tagging", "")], xml);
        svc.put_object_tagging("123456789012", &req, "pota", "k")
            .unwrap();

        let req = make_request(Method::GET, "/pota/k", &[("tagging", "")], b"");
        let resp = svc
            .get_object_tagging("123456789012", &req, "pota", "k")
            .unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<Key>env</Key>"));

        svc.delete_object_tagging("123456789012", "pota", "k")
            .unwrap();
    }

    #[test]
    fn delete_object_tagging_bucket_not_found() {
        let svc = make_service();
        assert!(svc
            .delete_object_tagging("123456789012", "ghost", "k")
            .is_err());
    }

    #[test]
    fn put_bucket_tagging_bucket_not_found() {
        let svc = make_service();
        let xml = b"<Tagging><TagSet></TagSet></Tagging>";
        let req = make_request(Method::PUT, "/ghost", &[("tagging", "")], xml);
        assert!(svc
            .put_bucket_tagging("123456789012", &req, "ghost")
            .is_err());
    }

    #[test]
    fn bucket_tagging_lifecycle() {
        let svc = make_service();
        seed_bucket(&svc, "bt");
        let xml =
            b"<Tagging><TagSet><Tag><Key>env</Key><Value>prod</Value></Tag></TagSet></Tagging>";
        let req = make_request(Method::PUT, "/bt", &[("tagging", "")], xml);
        svc.put_bucket_tagging("123456789012", &req, "bt").unwrap();

        let req = make_request(Method::GET, "/bt", &[("tagging", "")], b"");
        let resp = svc.get_bucket_tagging("123456789012", &req, "bt").unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<Key>env</Key>"));

        let req = make_request(Method::DELETE, "/bt", &[("tagging", "")], b"");
        svc.delete_bucket_tagging("123456789012", &req, "bt")
            .unwrap();
    }
}
