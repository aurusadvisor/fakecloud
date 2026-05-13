use http::{HeaderMap, StatusCode};

use bytes::Bytes;
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::persistence::object_meta_snapshot;

use super::{
    build_acl_xml, canned_acl_grants_for_object, no_such_key, parse_acl_xml, parse_grant_headers,
    s3_xml, S3Service,
};

impl S3Service {
    pub(super) fn get_object_acl(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
        key: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accts = self.state.read();
        let __empty = crate::state::S3State::new(account_id, "us-east-1");
        let state = accts.get(account_id).unwrap_or(&__empty);
        // GetObjectAcl only declares NoSuchKey per the Smithy model;
        // collapse missing-bucket into NoSuchKey for strict conformance.
        let b = state.buckets.get(bucket).ok_or_else(|| no_such_key(key))?;
        let obj = b.objects.get(key).ok_or_else(|| no_such_key(key))?;

        let owner_id = obj.acl_owner_id.as_deref().unwrap_or(&req.account_id);
        let body = build_acl_xml(owner_id, &obj.acl_grants, &req.account_id);
        Ok(s3_xml(StatusCode::OK, body))
    }

    pub(super) fn put_object_acl(
        &self,
        account_id: &str,
        req: &AwsRequest,
        bucket: &str,
        key: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let canned = req
            .headers
            .get("x-amz-acl")
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());

        if self.bucket_owner_enforced(account_id, bucket) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "AccessControlListNotSupported",
                "The bucket does not allow ACLs",
            ));
        }

        // Snapshot PAB before taking the write lock — `pab_flags`
        // reads its own lock and would deadlock under the same
        // upgrade.
        let pab = self.pab_flags(account_id, bucket);
        let mut accts = self.state.write();
        let state = accts.get_or_create(account_id);
        // PutObjectAcl only declares NoSuchKey per the Smithy model;
        // collapse missing-bucket into NoSuchKey for strict conformance.
        let b = state
            .buckets
            .get_mut(bucket)
            .ok_or_else(|| no_such_key(key))?;
        let owner_id = b.acl_owner_id.clone();
        let obj = b.objects.get_mut(key).ok_or_else(|| no_such_key(key))?;

        let proposed_grants = if let Some(acl) = &canned {
            canned_acl_grants_for_object(acl, &owner_id)
        } else {
            let has_grant_headers = req.headers.keys().any(|k| {
                let name = k.as_str();
                name.starts_with("x-amz-grant-")
            });
            if has_grant_headers {
                parse_grant_headers(&req.headers)
            } else {
                let body_str = std::str::from_utf8(&req.body).unwrap_or("");
                if !body_str.is_empty() {
                    parse_acl_xml(body_str)?
                } else {
                    obj.acl_grants.clone()
                }
            }
        };

        if let Some(flags) = pab {
            if flags.block_public_acls
                && super::config::grants_are_public(&proposed_grants)
                && !super::config::grants_are_public(&obj.acl_grants)
            {
                return Err(AwsServiceError::aws_error(
                    StatusCode::FORBIDDEN,
                    "AccessDenied",
                    "User is not authorized to perform: s3:PutObjectAcl. Reason: Public Access Block (BlockPublicAcls)",
                ));
            }
        }
        obj.acl_grants = proposed_grants;

        let meta = object_meta_snapshot(obj);
        self.store
            .put_object_meta(bucket, key, meta.version_id.as_deref(), &meta)
            .map_err(super::persistence_error)?;
        Ok(AwsResponse {
            status: StatusCode::OK,
            content_type: "application/xml".to_string(),
            body: Bytes::new().into(),
            headers: HeaderMap::new(),
        })
    }

    // ---- Object Tagging ----
}
