use http::{HeaderMap, StatusCode};

use bytes::Bytes;
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};
use fakecloud_persistence::{
    AclGrantSnapshot, AclSnapshot, BucketSubresource, InventorySnapshot, TagsSnapshot,
};

use crate::inventory;
use crate::persistence::bucket_meta_snapshot;

use super::{
    build_acl_xml, canned_acl_grants, empty_response, extract_xml_value, no_such_bucket,
    normalize_notification_ids, normalize_replication_xml, parse_acl_xml, parse_tagging_xml,
    s3_xml, validate_lifecycle_xml, validate_tags, xml_escape, S3Service,
};

/// Decoded `PublicAccessBlockConfiguration` flags. Each flag defaults
/// to `false` when missing from the stored XML, matching AWS's
/// `GetPublicAccessBlock` echo path.
///
/// `ignore_public_acls` and `restrict_public_buckets` gate
/// **read-time** evaluation (effective ACL / effective policy lookup)
/// — fakecloud doesn't yet evaluate effective access at GetObject
/// time, so we parse and store them but they are not read from on
/// the request path. Removing them would silently drop the values
/// from `GetPublicAccessBlock` round-trips.
#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct PublicAccessBlockFlags {
    pub block_public_acls: bool,
    #[allow(dead_code)]
    pub ignore_public_acls: bool,
    pub block_public_policy: bool,
    #[allow(dead_code)]
    pub restrict_public_buckets: bool,
}

impl PublicAccessBlockFlags {
    fn parse(xml: &str) -> Self {
        fn flag(xml: &str, name: &str) -> bool {
            let open = format!("<{name}>");
            let close = format!("</{name}>");
            let Some(start) = xml.find(&open) else {
                return false;
            };
            let value_start = start + open.len();
            let Some(end_offset) = xml[value_start..].find(&close) else {
                return false;
            };
            xml[value_start..value_start + end_offset]
                .trim()
                .eq_ignore_ascii_case("true")
        }
        Self {
            block_public_acls: flag(xml, "BlockPublicAcls"),
            ignore_public_acls: flag(xml, "IgnorePublicAcls"),
            block_public_policy: flag(xml, "BlockPublicPolicy"),
            restrict_public_buckets: flag(xml, "RestrictPublicBuckets"),
        }
    }
}

/// Detect whether a parsed bucket-policy document grants access to an
/// anonymous principal. Mirrors AWS's "is public" classifier:
/// `Effect=Allow` with `Principal:"*"` or `{"AWS":"*"}` (or a list
/// containing `"*"`) and no `Condition` block constraining the
/// principal further. We deliberately mark conditioned policies as
/// non-public — that matches AWS's `BlockPublicPolicy` behavior since
/// IP / VPC / source-account conditions specifically narrow the
/// principal.
pub(crate) fn policy_is_public(policy_json: &str) -> bool {
    let Ok(value) = serde_json::from_str::<serde_json::Value>(policy_json) else {
        return false;
    };
    let statements = match value.get("Statement") {
        Some(serde_json::Value::Array(a)) => a.clone(),
        Some(s) => vec![s.clone()],
        None => return false,
    };
    statements.iter().any(|st| {
        if st.get("Effect").and_then(|v| v.as_str()) != Some("Allow") {
            return false;
        }
        if st.get("Condition").is_some() {
            return false;
        }
        principal_includes_wildcard(st.get("Principal").unwrap_or(&serde_json::Value::Null))
    })
}

fn principal_includes_wildcard(p: &serde_json::Value) -> bool {
    match p {
        serde_json::Value::String(s) => s == "*",
        serde_json::Value::Object(m) => m.values().any(value_contains_star),
        _ => false,
    }
}

fn value_contains_star(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::String(s) => s == "*",
        serde_json::Value::Array(arr) => arr.iter().any(value_contains_star),
        _ => false,
    }
}

/// Detect whether a set of ACL grants grants to a public group
/// (AllUsers / AuthenticatedUsers). Used by PutBucketAcl /
/// PutObjectAcl to gate the `BlockPublicAcls` flag.
pub(crate) fn grants_are_public(grants: &[crate::state::AclGrant]) -> bool {
    grants.iter().any(|g| {
        g.grantee_uri
            .as_deref()
            .map(|u| {
                u.contains("acs.amazonaws.com/groups/global/AllUsers")
                    || u.contains("acs.amazonaws.com/groups/global/AuthenticatedUsers")
            })
            .unwrap_or(false)
    })
}

impl S3Service {
    // ---- Encryption ----

    pub(super) fn put_bucket_encryption(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        // Normalize: add BucketKeyEnabled=false to each Rule if missing
        let normalized = if body_str.contains("<Rule>") && !body_str.contains("<BucketKeyEnabled>")
        {
            body_str.replace(
                "</Rule>",
                "<BucketKeyEnabled>false</BucketKeyEnabled></Rule>",
            )
        } else {
            body_str
        };
        b.encryption_config = Some(normalized.clone());
        self.store
            .put_bucket_subresource(bucket, BucketSubresource::Encryption, &normalized)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::OK))
    }

    pub(super) fn get_bucket_encryption(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let __empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&__empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        match &b.encryption_config {
            Some(config) => Ok(s3_xml(StatusCode::OK, config.clone())),
            None => Err(AwsServiceError::aws_error_with_fields(
                StatusCode::NOT_FOUND,
                "ServerSideEncryptionConfigurationNotFoundError",
                "The server side encryption configuration was not found",
                vec![("BucketName".to_string(), bucket.to_string())],
            )),
        }
    }

    pub(super) fn delete_bucket_encryption(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        b.encryption_config = None;
        self.store
            .delete_bucket_subresource(bucket, BucketSubresource::Encryption)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::NO_CONTENT))
    }

    // ---- Lifecycle ----

    pub(super) fn put_bucket_lifecycle(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();

        // Validate lifecycle configuration
        validate_lifecycle_xml(&body_str)?;

        // If there are no <Rule> elements at all, treat as deleting the configuration
        let has_rules = body_str.contains("<Rule>");

        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        if has_rules {
            b.lifecycle_config = Some(body_str.clone());
            self.store
                .put_bucket_subresource(bucket, BucketSubresource::Lifecycle, &body_str)
                .map_err(super::persistence_error)?;
        } else {
            b.lifecycle_config = None;
            self.store
                .delete_bucket_subresource(bucket, BucketSubresource::Lifecycle)
                .map_err(super::persistence_error)?;
        }
        Ok(empty_response(StatusCode::OK))
    }

    pub(super) fn get_bucket_lifecycle(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let __empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&__empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        match &b.lifecycle_config {
            Some(config) => Ok(s3_xml(StatusCode::OK, config.clone())),
            None => Err(AwsServiceError::aws_error_with_fields(
                StatusCode::NOT_FOUND,
                "NoSuchLifecycleConfiguration",
                "The lifecycle configuration does not exist",
                vec![("BucketName".to_string(), bucket.to_string())],
            )),
        }
    }

    pub(super) fn delete_bucket_lifecycle(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        b.lifecycle_config = None;
        self.store
            .delete_bucket_subresource(bucket, BucketSubresource::Lifecycle)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::NO_CONTENT))
    }

    // ---- Policy ----

    pub(super) fn put_bucket_policy(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();
        if serde_json::from_str::<serde_json::Value>(&body_str).is_err() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MalformedPolicy",
                "This policy contains invalid Json",
            ));
        }
        // Enforce PublicAccessBlock.BlockPublicPolicy: AWS rejects
        // PutBucketPolicy that grants public access while the flag is
        // set, with `AccessDenied` and a body explaining the gate.
        if let Some(flags) = self.pab_flags(account_id, bucket) {
            if flags.block_public_policy && policy_is_public(&body_str) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::FORBIDDEN,
                    "AccessDenied",
                    "User is not authorized to perform: s3:PutBucketPolicy. Reason: Public Access Block (BlockPublicPolicy)",
                ));
            }
        }
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        b.policy = Some(body_str.clone());
        self.store
            .put_bucket_subresource(bucket, BucketSubresource::Policy, &body_str)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::NO_CONTENT))
    }

    pub(super) fn get_bucket_policy(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let __empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&__empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        match &b.policy {
            Some(policy) => Ok(AwsResponse {
                status: StatusCode::OK,
                content_type: "application/json".to_string(),
                body: Bytes::from(policy.clone()).into(),
                headers: HeaderMap::new(),
            }),
            None => Err(AwsServiceError::aws_error_with_fields(
                StatusCode::NOT_FOUND,
                "NoSuchBucketPolicy",
                "The bucket policy does not exist",
                vec![("BucketName".to_string(), bucket.to_string())],
            )),
        }
    }

    pub(super) fn delete_bucket_policy(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        b.policy = None;
        self.store
            .delete_bucket_subresource(bucket, BucketSubresource::Policy)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::NO_CONTENT))
    }

    // ---- CORS ----

    pub(super) fn put_bucket_cors(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();

        // Validate CORS configuration
        let rule_count = body_str.matches("<CORSRule>").count();
        if rule_count == 0 || rule_count > 100 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "The XML you provided was not well-formed or did not validate against our published schema",
            ));
        }

        // Validate HTTP methods
        let valid_methods = ["GET", "PUT", "POST", "DELETE", "HEAD"];
        let mut remaining = body_str.as_str();
        while let Some(start) = remaining.find("<AllowedMethod>") {
            let after = &remaining[start + 15..];
            if let Some(end) = after.find("</AllowedMethod>") {
                let method = after[..end].trim();
                if !valid_methods.contains(&method) {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidRequest",
                        format!(
                            "Found unsupported HTTP method in CORS config. Unsupported method is {method}"
                        ),
                    ));
                }
                remaining = &after[end + 16..];
            } else {
                break;
            }
        }

        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        b.cors_config = Some(body_str.clone());
        self.store
            .put_bucket_subresource(bucket, BucketSubresource::Cors, &body_str)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::OK))
    }

    pub(super) fn get_bucket_cors(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let __empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&__empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        match &b.cors_config {
            Some(config) => Ok(s3_xml(StatusCode::OK, config.clone())),
            None => Err(AwsServiceError::aws_error_with_fields(
                StatusCode::NOT_FOUND,
                "NoSuchCORSConfiguration",
                "The CORS configuration does not exist",
                vec![("BucketName".to_string(), bucket.to_string())],
            )),
        }
    }

    pub(super) fn delete_bucket_cors(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        b.cors_config = None;
        self.store
            .delete_bucket_subresource(bucket, BucketSubresource::Cors)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::NO_CONTENT))
    }

    // ---- Notification ----

    pub(super) fn put_bucket_notification(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        // Check if EventBridgeConfiguration XML element is present (opening tag or self-closing)
        b.eventbridge_enabled = body_str.contains("<EventBridgeConfiguration");
        // Auto-generate Id for each configuration element if missing
        let normalized = normalize_notification_ids(&body_str);
        b.notification_config = Some(normalized.clone());
        let meta = bucket_meta_snapshot(b);
        self.store
            .put_bucket_meta(bucket, &meta)
            .map_err(super::persistence_error)?;
        self.store
            .put_bucket_subresource(bucket, BucketSubresource::Notification, &normalized)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::OK))
    }

    pub(super) fn get_bucket_notification(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let __empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&__empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        let mut body = match &b.notification_config {
            Some(config) => config.clone(),
            None => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <NotificationConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                     </NotificationConfiguration>"
                .to_string(),
        };
        // Ensure EventBridgeConfiguration is in response if enabled
        if b.eventbridge_enabled && !body.contains("EventBridgeConfiguration") {
            if let Some(pos) = body.find("</NotificationConfiguration>") {
                body.insert_str(pos, "<EventBridgeConfiguration/>");
            }
        }
        Ok(s3_xml(StatusCode::OK, body))
    }

    // ---- Logging ----

    pub(super) fn put_bucket_logging(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        b.logging_config = Some(body_str.clone());
        self.store
            .put_bucket_subresource(bucket, BucketSubresource::Logging, &body_str)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::OK))
    }

    pub(super) fn get_bucket_logging(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let __empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&__empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        let body = match &b.logging_config {
            Some(config) => config.clone(),
            None => "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <BucketLoggingStatus xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                     </BucketLoggingStatus>"
                .to_string(),
        };
        Ok(s3_xml(StatusCode::OK, body))
    }

    // ---- Website ----

    pub(super) fn put_bucket_website(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        b.website_config = Some(body_str.clone());
        self.store
            .put_bucket_subresource(bucket, BucketSubresource::Website, &body_str)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::OK))
    }

    pub(super) fn get_bucket_website(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let __empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&__empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        match &b.website_config {
            Some(config) => Ok(s3_xml(StatusCode::OK, config.clone())),
            None => Err(AwsServiceError::aws_error_with_fields(
                StatusCode::NOT_FOUND,
                "NoSuchWebsiteConfiguration",
                "The specified bucket does not have a website configuration",
                vec![("BucketName".to_string(), bucket.to_string())],
            )),
        }
    }

    pub(super) fn delete_bucket_website(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        b.website_config = None;
        self.store
            .delete_bucket_subresource(bucket, BucketSubresource::Website)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::NO_CONTENT))
    }

    // ---- Accelerate ----

    pub(super) fn put_bucket_accelerate(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        if bucket.contains('.') {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "S3 Transfer Acceleration is not supported for buckets with periods (.) in their names",
            ));
        }
        let body_str = std::str::from_utf8(&req.body).unwrap_or("");
        let status = extract_xml_value(body_str, "Status");
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        // Validate status
        if let Some(ref s) = status {
            if s != "Enabled" && s != "Suspended" {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "MalformedXML",
                    "The XML you provided was not well-formed or did not validate against our published schema",
                ));
            }
        }
        // Suspending a never-configured bucket is a no-op
        if status.as_deref() == Some("Suspended") && b.accelerate_status.is_none() {
            return Ok(empty_response(StatusCode::OK));
        }
        b.accelerate_status = status;
        let meta = bucket_meta_snapshot(b);
        self.store
            .put_bucket_meta(bucket, &meta)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::OK))
    }

    pub(super) fn get_bucket_accelerate(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let __empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&__empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        let status_xml = match &b.accelerate_status {
            Some(s) => format!("<Status>{s}</Status>"),
            None => String::new(),
        };
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <AccelerateConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             {status_xml}\
             </AccelerateConfiguration>"
        );
        Ok(s3_xml(StatusCode::OK, body))
    }

    // ---- PublicAccessBlock helpers ----

    /// Read each `PublicAccessBlock` flag from the bucket's stored XML.
    /// Missing fields default to `false` per AWS, which mirrors the
    /// `GetPublicAccessBlock` echo path. Returns `None` when no
    /// configuration is set, so callers can short-circuit.
    pub(super) fn pab_flags(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Option<PublicAccessBlockFlags> {
        let accts = self.state.read();
        let state = accts.get(account_id)?;
        let b = state.buckets.get(bucket)?;
        let xml = b.public_access_block.as_ref()?;
        Some(PublicAccessBlockFlags::parse(xml))
    }

    // ---- PublicAccessBlock ----

    pub(super) fn put_public_access_block(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();
        // Validate that at least one field is specified
        let has_field = body_str.contains("BlockPublicAcls")
            || body_str.contains("IgnorePublicAcls")
            || body_str.contains("BlockPublicPolicy")
            || body_str.contains("RestrictPublicBuckets");
        if !has_field {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "Must specify at least one configuration.",
            ));
        }
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        b.public_access_block = Some(body_str.clone());
        self.store
            .put_bucket_subresource(bucket, BucketSubresource::PublicAccessBlock, &body_str)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::OK))
    }

    pub(super) fn get_public_access_block(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let __empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&__empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        match &b.public_access_block {
            Some(config) => {
                // Ensure all four fields are present with defaults of false
                let fields = [
                    "BlockPublicAcls",
                    "IgnorePublicAcls",
                    "BlockPublicPolicy",
                    "RestrictPublicBuckets",
                ];
                let mut result = config.clone();
                for field in fields {
                    if !result.contains(field) {
                        let closing = "</PublicAccessBlockConfiguration>";
                        if let Some(pos) = result.find(closing) {
                            result.insert_str(pos, &format!("<{field}>false</{field}>"));
                        }
                    }
                }
                Ok(s3_xml(StatusCode::OK, result))
            }
            None => Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NoSuchPublicAccessBlockConfiguration",
                "The public access block configuration was not found",
            )),
        }
    }

    pub(super) fn delete_public_access_block(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        b.public_access_block = None;
        self.store
            .delete_bucket_subresource(bucket, BucketSubresource::PublicAccessBlock)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::NO_CONTENT))
    }

    // ---- ObjectLockConfiguration ----

    pub(super) fn put_object_lock_config(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();

        // Validate: body must not be empty
        if body_str.trim().is_empty() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MissingRequestBodyError",
                "Request Body is empty",
            ));
        }

        // Must contain ObjectLockEnabled
        if !body_str.contains("<ObjectLockEnabled>") {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MalformedXML",
                "The XML you provided was not well-formed or did not validate against our published schema",
            ));
        }

        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;

        // Versioning must be enabled
        if b.versioning.as_deref() != Some("Enabled") {
            return Err(AwsServiceError::aws_error(
                StatusCode::CONFLICT,
                "InvalidBucketState",
                "Versioning must be 'Enabled' on the bucket to apply a Object Lock configuration",
            ));
        }

        b.object_lock_config = Some(body_str.clone());
        self.store
            .put_bucket_subresource(bucket, BucketSubresource::ObjectLock, &body_str)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::OK))
    }

    pub(super) fn get_bucket_tagging(
        &self,
        account_id: &str,
        _req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let __empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&__empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        if b.tags.is_empty() {
            return Err(AwsServiceError::aws_error_with_fields(
                StatusCode::NOT_FOUND,
                "NoSuchTagSet",
                "The TagSet does not exist",
                vec![("BucketName".to_string(), b.name.clone())],
            ));
        }
        let mut tags_xml = String::new();
        for (k, v) in &b.tags {
            tags_xml.push_str(&format!(
                "<Tag><Key>{}</Key><Value>{}</Value></Tag>",
                xml_escape(k),
                xml_escape(v),
            ));
        }
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <Tagging xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <TagSet>{tags_xml}</TagSet></Tagging>"
        );
        Ok(s3_xml(StatusCode::OK, body))
    }

    pub(super) fn put_bucket_tagging(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("");
        let tags = parse_tagging_xml(body_str);

        // Validate tags: no duplicate keys
        validate_tags(&tags)?;

        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        b.tags = tags.into_iter().collect();
        let snap = TagsSnapshot {
            tags: b.tags.clone(),
        };
        let payload = toml::to_string(&snap).unwrap_or_default();
        self.store
            .put_bucket_subresource(bucket, BucketSubresource::Tags, &payload)
            .map_err(super::persistence_error)?;
        Ok(AwsResponse {
            status: StatusCode::NO_CONTENT,
            content_type: "application/xml".to_string(),
            body: Bytes::new().into(),
            headers: HeaderMap::new(),
        })
    }

    pub(super) fn delete_bucket_tagging(
        &self,
        account_id: &str,
        _req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        b.tags.clear();
        self.store
            .delete_bucket_subresource(bucket, BucketSubresource::Tags)
            .map_err(super::persistence_error)?;
        Ok(AwsResponse {
            status: StatusCode::NO_CONTENT,
            content_type: "application/xml".to_string(),
            body: Bytes::new().into(),
            headers: HeaderMap::new(),
        })
    }

    // ---- Bucket ACL ----

    pub(super) fn get_bucket_acl(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let __empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&__empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;

        let body = build_acl_xml(&b.acl_owner_id, &b.acl_grants, &req.account_id);
        Ok(s3_xml(StatusCode::OK, body))
    }

    pub(super) fn put_bucket_acl(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        // Check for canned ACL header
        let canned = req
            .headers
            .get("x-amz-acl")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        let pab = self.pab_flags(account_id, bucket);
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;

        let proposed_grants = if let Some(acl) = &canned {
            canned_acl_grants(acl, &b.acl_owner_id.clone())
        } else {
            let body_str = std::str::from_utf8(&req.body).unwrap_or("");
            parse_acl_xml(body_str)?
        };

        // PublicAccessBlock.BlockPublicAcls rejects any new grant that
        // would expose the bucket to AllUsers / AuthenticatedUsers,
        // whether sourced via canned ACL header, x-amz-grant-* headers,
        // or AccessControlPolicy XML body.
        if let Some(flags) = pab {
            if flags.block_public_acls && grants_are_public(&proposed_grants) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::FORBIDDEN,
                    "AccessDenied",
                    "User is not authorized to perform: s3:PutBucketAcl. Reason: Public Access Block (BlockPublicAcls)",
                ));
            }
        }
        b.acl_grants = proposed_grants;

        let snap = AclSnapshot {
            owner_id: b.acl_owner_id.clone(),
            grants: b.acl_grants.iter().map(AclGrantSnapshot::from).collect(),
        };
        let payload = toml::to_string(&snap).unwrap_or_default();
        self.store
            .put_bucket_subresource(bucket, BucketSubresource::Acl, &payload)
            .map_err(super::persistence_error)?;
        Ok(AwsResponse {
            status: StatusCode::OK,
            content_type: "application/xml".to_string(),
            body: Bytes::new().into(),
            headers: HeaderMap::new(),
        })
    }

    // ---- Bucket Versioning ----

    pub(super) fn put_bucket_versioning(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("");
        let status_val = extract_xml_value(body_str, "Status").unwrap_or_default();

        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        if status_val == "Enabled" || status_val == "Suspended" {
            b.versioning = Some(status_val);
        }
        let meta = bucket_meta_snapshot(b);
        self.store
            .put_bucket_meta(bucket, &meta)
            .map_err(super::persistence_error)?;
        Ok(AwsResponse {
            status: StatusCode::OK,
            content_type: "application/xml".to_string(),
            body: Bytes::new().into(),
            headers: HeaderMap::new(),
        })
    }

    pub(super) fn get_bucket_versioning(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let __empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&__empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        let status_xml = match &b.versioning {
            Some(s) => format!("<Status>{s}</Status>"),
            None => String::new(),
        };
        let body = format!(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <VersioningConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             {status_xml}\
             </VersioningConfiguration>"
        );
        Ok(s3_xml(StatusCode::OK, body))
    }
    pub(super) fn get_object_lock_configuration(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let __empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&__empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        match &b.object_lock_config {
            Some(config) => Ok(s3_xml(StatusCode::OK, config.clone())),
            None => Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ObjectLockConfigurationNotFoundError",
                "Object Lock configuration does not exist for this bucket",
            )),
        }
    }

    pub(super) fn put_bucket_replication(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;

        // Versioning must be enabled to set replication
        if b.versioning.as_deref() != Some("Enabled") {
            return Err(AwsServiceError::aws_error_with_fields(
                StatusCode::BAD_REQUEST,
                "InvalidRequest",
                "Versioning must be 'Enabled' on the bucket to apply a replication configuration",
                vec![("BucketName".to_string(), bucket.to_string())],
            ));
        }

        let normalized = normalize_replication_xml(&body_str);
        b.replication_config = Some(normalized.clone());
        self.store
            .put_bucket_subresource(bucket, BucketSubresource::Replication, &normalized)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::OK))
    }

    pub(super) fn get_bucket_replication(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let __empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&__empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        match &b.replication_config {
            Some(config) => Ok(s3_xml(StatusCode::OK, config.clone())),
            None => Err(AwsServiceError::aws_error_with_fields(
                StatusCode::NOT_FOUND,
                "ReplicationConfigurationNotFoundError",
                "The replication configuration was not found",
                vec![("BucketName".to_string(), bucket.to_string())],
            )),
        }
    }

    pub(super) fn delete_bucket_replication(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        b.replication_config = None;
        self.store
            .delete_bucket_subresource(bucket, BucketSubresource::Replication)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::NO_CONTENT))
    }

    pub(super) fn put_bucket_ownership_controls(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        b.ownership_controls = Some(body_str.clone());
        self.store
            .put_bucket_subresource(bucket, BucketSubresource::Ownership, &body_str)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::OK))
    }

    pub(super) fn get_bucket_ownership_controls(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let __empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&__empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        match &b.ownership_controls {
            Some(config) => Ok(s3_xml(StatusCode::OK, config.clone())),
            None => Err(AwsServiceError::aws_error_with_fields(
                StatusCode::NOT_FOUND,
                "OwnershipControlsNotFoundError",
                "The bucket ownership controls were not found",
                vec![("BucketName".to_string(), bucket.to_string())],
            )),
        }
    }

    pub(super) fn delete_bucket_ownership_controls(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        b.ownership_controls = None;
        self.store
            .delete_bucket_subresource(bucket, BucketSubresource::Ownership)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::NO_CONTENT))
    }

    pub(super) fn put_bucket_inventory(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();
        // Use the Id from the XML body if available, otherwise fall back to query param
        let inv_id = extract_xml_value(&body_str, "Id")
            .or_else(|| req.query_params.get("id").cloned())
            .unwrap_or_default();
        let payload = {
            let mut accts = self.state.write();
            let state = accts.get_or_create(account_id);
            let b = state
                .buckets
                .get_mut(bucket)
                .ok_or_else(|| no_such_bucket(bucket))?;
            b.inventory_configs.insert(inv_id.clone(), body_str);
            let snap = InventorySnapshot {
                configs: b.inventory_configs.clone(),
            };
            toml::to_string(&snap).unwrap_or_default()
        };
        self.store
            .put_bucket_subresource(bucket, BucketSubresource::Inventory, &payload)
            .map_err(super::persistence_error)?;
        // Generate the inventory report immediately so tests can verify it
        inventory::generate_inventory_report(&self.state, bucket, &inv_id);
        Ok(empty_response(StatusCode::OK))
    }

    pub(super) fn get_bucket_inventory(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let inv_id = req.query_params.get("id").cloned().unwrap_or_default();
        let accts = self.state.read();
        let __empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&__empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        match b.inventory_configs.get(&inv_id) {
            Some(config) => Ok(s3_xml(StatusCode::OK, config.clone())),
            None => Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NoSuchConfiguration",
                format!("The specified configuration does not exist: {inv_id}"),
            )),
        }
    }

    pub(super) fn list_bucket_inventory_configurations(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let __empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&__empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;

        let mut body = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
             <ListInventoryConfigurationsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <IsTruncated>false</IsTruncated>",
        );
        let mut sorted_keys: Vec<_> = b.inventory_configs.keys().collect();
        sorted_keys.sort();
        for key in sorted_keys {
            if let Some(config) = b.inventory_configs.get(key) {
                body.push_str(config);
            }
        }
        body.push_str("</ListInventoryConfigurationsResult>");
        Ok(s3_xml(StatusCode::OK, body))
    }

    pub(super) fn delete_bucket_inventory(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let inv_id = req.query_params.get("id").cloned().unwrap_or_default();
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        b.inventory_configs.remove(&inv_id);
        if b.inventory_configs.is_empty() {
            self.store
                .delete_bucket_subresource(bucket, BucketSubresource::Inventory)
                .map_err(super::persistence_error)?;
        } else {
            let snap = InventorySnapshot {
                configs: b.inventory_configs.clone(),
            };
            let payload = toml::to_string(&snap).unwrap_or_default();
            self.store
                .put_bucket_subresource(bucket, BucketSubresource::Inventory, &payload)
                .map_err(super::persistence_error)?;
        }
        Ok(empty_response(StatusCode::NO_CONTENT))
    }

    // ---- Analytics / Intelligent-Tiering / Metrics configurations ----

    pub(super) fn put_bucket_analytics_config(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        store_named_config(self, account_id, req, bucket, ConfigKind::Analytics)
    }
    pub(super) fn get_bucket_analytics_config(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        get_named_config(self, account_id, req, bucket, ConfigKind::Analytics)
    }
    pub(super) fn delete_bucket_analytics_config(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        delete_named_config(self, account_id, req, bucket, ConfigKind::Analytics)
    }
    pub(super) fn list_bucket_analytics_configurations(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        list_named_config(self, account_id, bucket, ConfigKind::Analytics)
    }

    pub(super) fn put_bucket_intelligent_tiering_config(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        store_named_config(
            self,
            account_id,
            req,
            bucket,
            ConfigKind::IntelligentTiering,
        )
    }
    pub(super) fn get_bucket_intelligent_tiering_config(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        get_named_config(
            self,
            account_id,
            req,
            bucket,
            ConfigKind::IntelligentTiering,
        )
    }
    pub(super) fn delete_bucket_intelligent_tiering_config(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        delete_named_config(
            self,
            account_id,
            req,
            bucket,
            ConfigKind::IntelligentTiering,
        )
    }
    pub(super) fn list_bucket_intelligent_tiering_configurations(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        list_named_config(self, account_id, bucket, ConfigKind::IntelligentTiering)
    }

    pub(super) fn put_bucket_metrics_config(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        store_named_config(self, account_id, req, bucket, ConfigKind::Metrics)
    }
    pub(super) fn get_bucket_metrics_config(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        get_named_config(self, account_id, req, bucket, ConfigKind::Metrics)
    }
    pub(super) fn delete_bucket_metrics_config(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        delete_named_config(self, account_id, req, bucket, ConfigKind::Metrics)
    }
    pub(super) fn list_bucket_metrics_configurations(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        list_named_config(self, account_id, bucket, ConfigKind::Metrics)
    }

    // ---- Request Payment ----

    pub(super) fn put_bucket_request_payment(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();
        {
            let mut accts = self.state.write();
            let state = accts.get_or_create(account_id);
            let b = state
                .buckets
                .get_mut(bucket)
                .ok_or_else(|| no_such_bucket(bucket))?;
            b.request_payment = Some(body_str.clone());
        }
        self.store
            .put_bucket_subresource(bucket, BucketSubresource::RequestPayment, &body_str)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::OK))
    }

    pub(super) fn get_bucket_request_payment(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        let payer = b
            .request_payment
            .as_deref()
            .and_then(|x| extract_xml_value(x, "Payer"))
            .unwrap_or_else(|| "BucketOwner".to_string());
        let body = format!(
            "<RequestPaymentConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Payer>{}</Payer></RequestPaymentConfiguration>",
            xml_escape(&payer)
        );
        Ok(s3_xml(StatusCode::OK, body))
    }

    // ---- ABAC ----

    pub(super) fn put_bucket_abac(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();
        {
            let mut accts = self.state.write();
            let state = accts.get_or_create(account_id);
            let b = state
                .buckets
                .get_mut(bucket)
                .ok_or_else(|| no_such_bucket(bucket))?;
            b.abac_config = Some(body_str.clone());
        }
        self.store
            .put_bucket_subresource(bucket, BucketSubresource::Abac, &body_str)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::OK))
    }
    pub(super) fn get_bucket_abac(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        let body = b
            .abac_config
            .clone()
            .unwrap_or_else(|| "<BucketAbacConfiguration/>".to_string());
        Ok(s3_xml(StatusCode::OK, body))
    }

    // ---- Policy Status ----

    pub(super) fn get_bucket_policy_status(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        let is_public = b
            .policy
            .as_deref()
            .map(|p| {
                // Whitespace-tolerant detection: strip all whitespace
                // before scanning for the wildcard principal markers.
                let compact: String = p.chars().filter(|c| !c.is_whitespace()).collect();
                compact.contains("\"Principal\":\"*\"") || compact.contains("\"AWS\":\"*\"")
            })
            .unwrap_or(false);
        let body = format!("<PolicyStatus><IsPublic>{is_public}</IsPublic></PolicyStatus>");
        Ok(s3_xml(StatusCode::OK, body))
    }

    // ---- Metadata configurations ----

    pub(super) fn create_bucket_metadata_config(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();
        {
            let mut accts = self.state.write();
            let state = accts.get_or_create(account_id);
            let b = state
                .buckets
                .get_mut(bucket)
                .ok_or_else(|| no_such_bucket(bucket))?;
            b.metadata_configuration = Some(body_str.clone());
        }
        self.store
            .put_bucket_subresource(bucket, BucketSubresource::MetadataConfiguration, &body_str)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::OK))
    }
    pub(super) fn get_bucket_metadata_config(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        let body = b
            .metadata_configuration
            .clone()
            .unwrap_or_else(|| "<GetBucketMetadataConfigurationResult/>".to_string());
        Ok(s3_xml(StatusCode::OK, body))
    }
    pub(super) fn delete_bucket_metadata_config(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        {
            let mut accts = self.state.write();
            let state = accts.get_or_create(account_id);
            let b = state
                .buckets
                .get_mut(bucket)
                .ok_or_else(|| no_such_bucket(bucket))?;
            b.metadata_configuration = None;
        }
        self.store
            .delete_bucket_subresource(bucket, BucketSubresource::MetadataConfiguration)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::NO_CONTENT))
    }

    pub(super) fn create_bucket_metadata_table_config(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();
        {
            let mut accts = self.state.write();
            let state = accts.get_or_create(account_id);
            let b = state
                .buckets
                .get_mut(bucket)
                .ok_or_else(|| no_such_bucket(bucket))?;
            b.metadata_table_configuration = Some(body_str.clone());
        }
        self.store
            .put_bucket_subresource(
                bucket,
                BucketSubresource::MetadataTableConfiguration,
                &body_str,
            )
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::OK))
    }
    pub(super) fn get_bucket_metadata_table_config(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        let body = b
            .metadata_table_configuration
            .clone()
            .unwrap_or_else(|| "<GetBucketMetadataTableConfigurationResult/>".to_string());
        Ok(s3_xml(StatusCode::OK, body))
    }
    pub(super) fn delete_bucket_metadata_table_config(
        &self,
        account_id: &str,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        {
            let mut accts = self.state.write();
            let state = accts.get_or_create(account_id);
            let b = state
                .buckets
                .get_mut(bucket)
                .ok_or_else(|| no_such_bucket(bucket))?;
            b.metadata_table_configuration = None;
        }
        self.store
            .delete_bucket_subresource(bucket, BucketSubresource::MetadataTableConfiguration)
            .map_err(super::persistence_error)?;
        Ok(empty_response(StatusCode::NO_CONTENT))
    }
    pub(super) fn update_bucket_metadata_inventory_table(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        // Composite metadata configuration: append/replace inventory table block.
        let combined = match b.metadata_configuration.as_deref() {
            Some(prev) => format!("{prev}\n<InventoryTable>{body_str}</InventoryTable>"),
            None => format!("<InventoryTable>{body_str}</InventoryTable>"),
        };
        b.metadata_configuration = Some(combined);
        Ok(empty_response(StatusCode::OK))
    }
    pub(super) fn update_bucket_metadata_journal_table(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        let combined = match b.metadata_configuration.as_deref() {
            Some(prev) => format!("{prev}\n<JournalTable>{body_str}</JournalTable>"),
            None => format!("<JournalTable>{body_str}</JournalTable>"),
        };
        b.metadata_configuration = Some(combined);
        Ok(empty_response(StatusCode::OK))
    }

    // ---- ListDirectoryBuckets / CreateSession (S3 Express) ----

    pub(super) fn list_directory_buckets(
        &self,
        account_id: &str,
        _req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        // S3 Express directory buckets are not modeled separately in
        // fakecloud; return an empty list per the documented schema so
        // SDK calls succeed.
        let _ = account_id;
        let body = "<ListDirectoryBucketsResult><Buckets/><ContinuationToken/></ListDirectoryBucketsResult>".to_string();
        Ok(s3_xml(StatusCode::OK, body))
    }

    pub(super) fn create_session(
        &self,
        account_id: &str,
        _req: &AwsRequest,
        bucket: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        // Issue ephemeral credentials scoped to the directory bucket. These
        // are not usable for actual SigV4 in the emulator (the S3 Express
        // session-token flow isn't enforced) but the response shape is
        // what SDKs expect.
        let _ = account_id;
        let body = format!(
            "<CreateSessionResult><Credentials><AccessKeyId>FAKEACCESSKEY</AccessKeyId><SecretAccessKey>FAKESECRET</SecretAccessKey><SessionToken>FAKESESSION-{}</SessionToken><Expiration>2099-01-01T00:00:00Z</Expiration></Credentials></CreateSessionResult>",
            xml_escape(bucket)
        );
        Ok(s3_xml(StatusCode::OK, body))
    }

    // ---- Object-level extras ----

    pub(super) fn rename_object(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
        key: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        // RenameObject is an S3 Express op: source key is taken from the
        // x-amz-rename-source header; destination is the request URI key.
        let source_key = req
            .headers
            .get("x-amz-rename-source")
            .and_then(|v| v.to_str().ok())
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidArgument",
                    "x-amz-rename-source header is required for RenameObject.",
                )
            })?
            .trim_start_matches('/')
            .to_string();
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        let obj = b.objects.remove(&source_key).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                format!("Source key {source_key} does not exist."),
            )
        })?;
        b.objects.insert(key.to_string(), obj);
        Ok(empty_response(StatusCode::OK))
    }

    pub(super) fn update_object_encryption(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
        key: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let new_alg = req
            .headers
            .get("x-amz-server-side-encryption")
            .and_then(|v| v.to_str().ok())
            .map(String::from);
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        let obj = b.objects.get_mut(key).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                format!("Key {key} does not exist."),
            )
        })?;
        obj.sse_algorithm = new_alg;
        Ok(empty_response(StatusCode::OK))
    }

    pub(super) fn get_object_torrent(
        &self,
        account_id: &str,
        _req: &AwsRequest,
        bucket: &str,
        key: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        if !b.objects.contains_key(key) {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                format!("Key {key} does not exist."),
            ));
        }
        // Return a stub torrent file body. Real S3 disabled torrent in
        // 2024; keep an honest tiny payload here so callers see the route
        // is wired.
        let body = b"d8:announce0:e".to_vec();
        Ok(AwsResponse {
            status: StatusCode::OK,
            content_type: "application/x-bittorrent".to_string(),
            body: Bytes::from(body).into(),
            headers: HeaderMap::new(),
        })
    }

    pub(super) fn select_object_content(
        &self,
        account_id: &str,
        _req: &AwsRequest,
        bucket: &str,
        key: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        // SelectObjectContent normally returns an EventStream of
        // RecordsEvent / EndEvent frames. We can't easily produce real
        // EventStream binary frames here, but the SDK only requires a 200
        // with the right content-type; the parser will then receive an
        // empty event stream which is decoded as zero records.
        let accts = self.state.read();
        let empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&empty);
        let b = state
            .buckets
            .get(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        if !b.objects.contains_key(key) {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NoSuchKey",
                format!("Key {key} does not exist."),
            ));
        }
        let body = Bytes::new();
        Ok(AwsResponse {
            status: StatusCode::OK,
            content_type: "application/octet-stream".to_string(),
            body: body.into(),
            headers: HeaderMap::new(),
        })
    }

    pub(super) fn write_get_object_response(
        &self,
        _account_id: &str,
        _req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        // Object Lambda WriteGetObjectResponse is the back-channel a
        // Lambda function uses to deliver its rewritten payload to the
        // requesting client. fakecloud doesn't run Object Lambda; ack the
        // call so SDKs don't error out, and rely on integration tests for
        // any real exercise.
        Ok(empty_response(StatusCode::OK))
    }
}

// ── Shared helpers for analytics/intelligent-tiering/metrics named configs ──

#[derive(Clone, Copy)]
enum ConfigKind {
    Analytics,
    IntelligentTiering,
    Metrics,
}

impl ConfigKind {
    fn list_root(&self) -> &'static str {
        match self {
            ConfigKind::Analytics => "ListBucketAnalyticsConfigurationResult",
            ConfigKind::IntelligentTiering => "ListBucketIntelligentTieringConfigurationsOutput",
            ConfigKind::Metrics => "ListMetricsConfigurationsResult",
        }
    }
    fn subresource(&self) -> BucketSubresource {
        match self {
            ConfigKind::Analytics => BucketSubresource::Analytics,
            ConfigKind::IntelligentTiering => BucketSubresource::IntelligentTiering,
            ConfigKind::Metrics => BucketSubresource::Metrics,
        }
    }
}

fn config_map(
    bucket: &mut crate::state::S3Bucket,
    kind: ConfigKind,
) -> &mut std::collections::BTreeMap<String, String> {
    match kind {
        ConfigKind::Analytics => &mut bucket.analytics_configs,
        ConfigKind::IntelligentTiering => &mut bucket.intelligent_tiering_configs,
        ConfigKind::Metrics => &mut bucket.metrics_configs,
    }
}

fn config_map_ref(
    bucket: &crate::state::S3Bucket,
    kind: ConfigKind,
) -> &std::collections::BTreeMap<String, String> {
    match kind {
        ConfigKind::Analytics => &bucket.analytics_configs,
        ConfigKind::IntelligentTiering => &bucket.intelligent_tiering_configs,
        ConfigKind::Metrics => &bucket.metrics_configs,
    }
}

fn store_named_config(
    svc: &S3Service,
    account_id: &str,
    req: &AwsRequest,
    bucket: &str,
    kind: ConfigKind,
) -> Result<AwsResponse, AwsServiceError> {
    let id = req.query_params.get("id").cloned().ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "Missing required query parameter: id",
        )
    })?;
    let body_str = std::str::from_utf8(&req.body).unwrap_or("").to_string();
    let payload = {
        let mut accts = svc.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        config_map(b, kind).insert(id, body_str);
        toml::to_string(config_map(b, kind)).unwrap_or_default()
    };
    svc.store
        .put_bucket_subresource(bucket, kind.subresource(), &payload)
        .map_err(super::persistence_error)?;
    Ok(empty_response(StatusCode::OK))
}

fn get_named_config(
    svc: &S3Service,
    account_id: &str,
    req: &AwsRequest,
    bucket: &str,
    kind: ConfigKind,
) -> Result<AwsResponse, AwsServiceError> {
    let id = req.query_params.get("id").cloned().ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "Missing required query parameter: id",
        )
    })?;
    let accts = svc.state.read();
    let empty = crate::state::S3State::new(account_id, "us-east-1");
    let state = accts.get(account_id).unwrap_or(&empty);
    let b = state
        .buckets
        .get(bucket)
        .ok_or_else(|| no_such_bucket(bucket))?;
    let body = config_map_ref(b, kind).get(&id).cloned().ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::NOT_FOUND,
            "NoSuchConfiguration",
            format!("Configuration {id} not found."),
        )
    })?;
    Ok(s3_xml(StatusCode::OK, body))
}

fn delete_named_config(
    svc: &S3Service,
    account_id: &str,
    req: &AwsRequest,
    bucket: &str,
    kind: ConfigKind,
) -> Result<AwsResponse, AwsServiceError> {
    let id = req.query_params.get("id").cloned().ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidArgument",
            "Missing required query parameter: id",
        )
    })?;
    let (empty, payload) = {
        let mut accts = svc.state.write();
        let state = accts.get_or_create(account_id);
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_bucket(bucket))?;
        config_map(b, kind).remove(&id);
        let map = config_map(b, kind);
        let is_empty = map.is_empty();
        (is_empty, toml::to_string(map).unwrap_or_default())
    };
    if empty {
        svc.store
            .delete_bucket_subresource(bucket, kind.subresource())
            .map_err(super::persistence_error)?;
    } else {
        svc.store
            .put_bucket_subresource(bucket, kind.subresource(), &payload)
            .map_err(super::persistence_error)?;
    }
    Ok(empty_response(StatusCode::NO_CONTENT))
}

fn list_named_config(
    svc: &S3Service,
    account_id: &str,
    bucket: &str,
    kind: ConfigKind,
) -> Result<AwsResponse, AwsServiceError> {
    let accts = svc.state.read();
    let empty = crate::state::S3State::new(account_id, "us-east-1");
    let state = accts.get(account_id).unwrap_or(&empty);
    let b = state
        .buckets
        .get(bucket)
        .ok_or_else(|| no_such_bucket(bucket))?;
    // Stored entries already include the per-config wrapper element
    // (e.g. <AnalyticsConfiguration>...</AnalyticsConfiguration>), so
    // emit them directly. Wrapping them in another <Member> here would
    // produce a nested element list that breaks SDK parsing.
    let entries: Vec<String> = config_map_ref(b, kind).values().cloned().collect();
    let body = format!(
        "<{root}>{entries}<IsTruncated>false</IsTruncated></{root}>",
        root = kind.list_root(),
        entries = entries.join(""),
    );
    Ok(s3_xml(StatusCode::OK, body))
}
