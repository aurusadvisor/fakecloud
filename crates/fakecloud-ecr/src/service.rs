use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::Utc;
use http::StatusCode;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
use fakecloud_persistence::SnapshotStore;

use crate::state::{
    EcrSnapshot, EncryptionConfiguration, Image, ImageScanningConfiguration, Layer, LayerUpload,
    Repository, SharedEcrState, ECR_SNAPSHOT_SCHEMA_VERSION,
};

const SUPPORTED_ACTIONS: &[&str] = &[
    "CreateRepository",
    "DeleteRepository",
    "DescribeRepositories",
    "PutImageTagMutability",
    "PutImageScanningConfiguration",
    "SetRepositoryPolicy",
    "GetRepositoryPolicy",
    "DeleteRepositoryPolicy",
    "TagResource",
    "UntagResource",
    "ListTagsForResource",
    "PutImage",
    "BatchGetImage",
    "BatchDeleteImage",
    "BatchCheckLayerAvailability",
    "DescribeImages",
    "ListImages",
    "GetDownloadUrlForLayer",
    "InitiateLayerUpload",
    "UploadLayerPart",
    "CompleteLayerUpload",
    "GetAuthorizationToken",
    "PutLifecyclePolicy",
    "GetLifecyclePolicy",
    "DeleteLifecyclePolicy",
    "StartLifecyclePolicyPreview",
    "GetLifecyclePolicyPreview",
    "StartImageScan",
    "DescribeImageScanFindings",
    "DescribeRegistry",
    "GetRegistryPolicy",
    "PutRegistryPolicy",
    "DeleteRegistryPolicy",
    "GetRegistryScanningConfiguration",
    "PutRegistryScanningConfiguration",
    "BatchGetRepositoryScanningConfiguration",
    "PutReplicationConfiguration",
    "DescribeImageReplicationStatus",
    "CreatePullThroughCacheRule",
    "DeletePullThroughCacheRule",
    "DescribePullThroughCacheRules",
    "UpdatePullThroughCacheRule",
    "ValidatePullThroughCacheRule",
    "GetAccountSetting",
    "PutAccountSetting",
    "CreateRepositoryCreationTemplate",
    "DeleteRepositoryCreationTemplate",
    "DescribeRepositoryCreationTemplates",
    "UpdateRepositoryCreationTemplate",
    "GetSigningConfiguration",
    "PutSigningConfiguration",
    "DeleteSigningConfiguration",
    "DescribeImageSigningStatus",
    "RegisterPullTimeUpdateExclusion",
    "DeregisterPullTimeUpdateExclusion",
    "ListPullTimeUpdateExclusions",
    "ListImageReferrers",
    "UpdateImageStorageClass",
];

/// Actions that mutate persisted state. Only these trigger a snapshot save.
fn is_mutating(action: &str) -> bool {
    matches!(
        action,
        "CreateRepository"
            | "DeleteRepository"
            | "PutImageTagMutability"
            | "PutImageScanningConfiguration"
            | "SetRepositoryPolicy"
            | "DeleteRepositoryPolicy"
            | "TagResource"
            | "UntagResource"
            | "PutImage"
            | "BatchDeleteImage"
            | "InitiateLayerUpload"
            | "UploadLayerPart"
            | "CompleteLayerUpload"
            | "PutLifecyclePolicy"
            | "DeleteLifecyclePolicy"
            | "StartLifecyclePolicyPreview"
            | "StartImageScan"
            | "PutRegistryPolicy"
            | "DeleteRegistryPolicy"
            | "PutRegistryScanningConfiguration"
            | "PutReplicationConfiguration"
            | "CreatePullThroughCacheRule"
            | "DeletePullThroughCacheRule"
            | "UpdatePullThroughCacheRule"
            | "PutAccountSetting"
            | "CreateRepositoryCreationTemplate"
            | "DeleteRepositoryCreationTemplate"
            | "UpdateRepositoryCreationTemplate"
            | "PutSigningConfiguration"
            | "DeleteSigningConfiguration"
            | "RegisterPullTimeUpdateExclusion"
            | "DeregisterPullTimeUpdateExclusion"
            | "UpdateImageStorageClass"
    )
}

pub struct EcrService {
    state: SharedEcrState,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    snapshot_lock: Arc<AsyncMutex<()>>,
    /// KMS state handle — when wired, repositories configured with
    /// `EncryptionConfiguration.encryption_type == "KMS"` store layer
    /// blobs encrypted under the configured CMK via
    /// `fakecloud_kms::api::encrypt_blob` / `decrypt_blob`.
    kms_state: Option<fakecloud_kms::state::SharedKmsState>,
}

impl EcrService {
    pub fn new(state: SharedEcrState) -> Self {
        Self {
            state,
            snapshot_store: None,
            snapshot_lock: Arc::new(AsyncMutex::new(())),
            kms_state: None,
        }
    }

    pub fn with_snapshot_store(mut self, store: Arc<dyn SnapshotStore>) -> Self {
        self.snapshot_store = Some(store);
        self
    }

    pub fn with_kms(mut self, kms: fakecloud_kms::state::SharedKmsState) -> Self {
        self.kms_state = Some(kms);
        self
    }

    /// Read-only accessor for the multi-account state. The sibling
    /// `oci` module owns the HTTP-layer adapter for the OCI v2
    /// protocol and needs to reach the same repositories + blobs the
    /// JSON control-plane ops read and write.
    pub fn state_handle(&self) -> &SharedEcrState {
        &self.state
    }

    /// Handle for the shared KMS state when wired. `None` skips the
    /// encrypt/decrypt paths and stores / returns plaintext blobs.
    pub(crate) fn kms_handle(&self) -> Option<&fakecloud_kms::state::SharedKmsState> {
        self.kms_state.as_ref()
    }

    async fn save_snapshot(&self) {
        let Some(store) = self.snapshot_store.clone() else {
            return;
        };
        let _guard = self.snapshot_lock.lock().await;
        let snapshot = EcrSnapshot {
            schema_version: ECR_SNAPSHOT_SCHEMA_VERSION,
            accounts: Some(self.state.read().clone()),
        };
        let join = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let bytes = serde_json::to_vec(&snapshot)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            store.save(&bytes)
        })
        .await;
        match join {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(%err, "failed to write ecr snapshot"),
            Err(err) => tracing::error!(%err, "ecr snapshot task panicked"),
        }
    }
}

#[async_trait]
impl AwsService for EcrService {
    fn service_name(&self) -> &str {
        "ecr"
    }

    async fn handle(&self, request: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        // OCI v2 Distribution requests come in as path-only REST
        // (`/v2/...` with no `X-Amz-Target`). Dispatch them before the
        // JSON control plane. Most OCI paths mutate state too (uploads,
        // manifest PUT, blob/manifest DELETE) so snapshot after.
        if request
            .path_segments
            .first()
            .map(|s| s == "v2")
            .unwrap_or(false)
        {
            let result = crate::oci::dispatch(self, &request).await;
            let mutates_oci = matches!(
                request.method,
                http::Method::POST | http::Method::PUT | http::Method::PATCH | http::Method::DELETE
            );
            if mutates_oci && matches!(result.as_ref(), Ok(resp) if resp.status.is_success()) {
                self.save_snapshot().await;
            }
            return result;
        }

        let mutates = is_mutating(request.action.as_str());
        let result = match request.action.as_str() {
            "CreateRepository" => self.create_repository(&request),
            "DeleteRepository" => self.delete_repository(&request),
            "DescribeRepositories" => self.describe_repositories(&request),
            "PutImageTagMutability" => self.put_image_tag_mutability(&request),
            "PutImageScanningConfiguration" => self.put_image_scanning_configuration(&request),
            "SetRepositoryPolicy" => self.set_repository_policy(&request),
            "GetRepositoryPolicy" => self.get_repository_policy(&request),
            "DeleteRepositoryPolicy" => self.delete_repository_policy(&request),
            "TagResource" => self.tag_resource(&request),
            "UntagResource" => self.untag_resource(&request),
            "ListTagsForResource" => self.list_tags_for_resource(&request),
            "PutImage" => self.put_image(&request),
            "BatchGetImage" => self.batch_get_image(&request),
            "BatchDeleteImage" => self.batch_delete_image(&request),
            "BatchCheckLayerAvailability" => self.batch_check_layer_availability(&request),
            "DescribeImages" => self.describe_images(&request),
            "ListImages" => self.list_images(&request),
            "GetDownloadUrlForLayer" => self.get_download_url_for_layer(&request),
            "InitiateLayerUpload" => self.initiate_layer_upload(&request),
            "UploadLayerPart" => self.upload_layer_part(&request),
            "CompleteLayerUpload" => self.complete_layer_upload(&request),
            "GetAuthorizationToken" => self.get_authorization_token(&request),
            "PutLifecyclePolicy" => self.put_lifecycle_policy(&request),
            "GetLifecyclePolicy" => self.get_lifecycle_policy(&request),
            "DeleteLifecyclePolicy" => self.delete_lifecycle_policy(&request),
            "StartLifecyclePolicyPreview" => self.start_lifecycle_policy_preview(&request),
            "GetLifecyclePolicyPreview" => self.get_lifecycle_policy_preview(&request),
            "StartImageScan" => self.start_image_scan(&request),
            "DescribeImageScanFindings" => self.describe_image_scan_findings(&request),
            "DescribeRegistry" => self.describe_registry(&request),
            "GetRegistryPolicy" => self.get_registry_policy(&request),
            "PutRegistryPolicy" => self.put_registry_policy(&request),
            "DeleteRegistryPolicy" => self.delete_registry_policy(&request),
            "GetRegistryScanningConfiguration" => {
                self.get_registry_scanning_configuration(&request)
            }
            "PutRegistryScanningConfiguration" => {
                self.put_registry_scanning_configuration(&request)
            }
            "BatchGetRepositoryScanningConfiguration" => {
                self.batch_get_repository_scanning_configuration(&request)
            }
            "PutReplicationConfiguration" => self.put_replication_configuration(&request),
            "DescribeImageReplicationStatus" => self.describe_image_replication_status(&request),
            "CreatePullThroughCacheRule" => self.create_pull_through_cache_rule(&request),
            "DeletePullThroughCacheRule" => self.delete_pull_through_cache_rule(&request),
            "DescribePullThroughCacheRules" => self.describe_pull_through_cache_rules(&request),
            "UpdatePullThroughCacheRule" => self.update_pull_through_cache_rule(&request),
            "ValidatePullThroughCacheRule" => self.validate_pull_through_cache_rule(&request),
            "GetAccountSetting" => self.get_account_setting(&request),
            "PutAccountSetting" => self.put_account_setting(&request),
            "CreateRepositoryCreationTemplate" => {
                self.create_repository_creation_template(&request)
            }
            "DeleteRepositoryCreationTemplate" => {
                self.delete_repository_creation_template(&request)
            }
            "DescribeRepositoryCreationTemplates" => {
                self.describe_repository_creation_templates(&request)
            }
            "UpdateRepositoryCreationTemplate" => {
                self.update_repository_creation_template(&request)
            }
            "GetSigningConfiguration" => self.get_signing_configuration(&request),
            "PutSigningConfiguration" => self.put_signing_configuration(&request),
            "DeleteSigningConfiguration" => self.delete_signing_configuration(&request),
            "DescribeImageSigningStatus" => self.describe_image_signing_status(&request),
            "RegisterPullTimeUpdateExclusion" => self.register_pull_time_update_exclusion(&request),
            "DeregisterPullTimeUpdateExclusion" => {
                self.deregister_pull_time_update_exclusion(&request)
            }
            "ListPullTimeUpdateExclusions" => self.list_pull_time_update_exclusions(&request),
            "ListImageReferrers" => self.list_image_referrers(&request),
            "UpdateImageStorageClass" => self.update_image_storage_class(&request),
            _ => Err(AwsServiceError::action_not_implemented(
                self.service_name(),
                &request.action,
            )),
        };
        if mutates && matches!(result.as_ref(), Ok(resp) if resp.status.is_success()) {
            self.save_snapshot().await;
        }
        result
    }

    fn supported_actions(&self) -> &[&str] {
        SUPPORTED_ACTIONS
    }
}

// -------- helpers --------

fn req_str<'a>(body: &'a Value, field: &str) -> Result<&'a str, AwsServiceError> {
    body.get(field)
        .and_then(|v| v.as_str())
        .ok_or_else(|| invalid_parameter(format!("Missing required field: {field}")))
}

fn opt_str<'a>(body: &'a Value, field: &str) -> Option<&'a str> {
    body.get(field).and_then(|v| v.as_str())
}

fn invalid_parameter(message: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "InvalidParameterException",
        message,
    )
}

fn repository_not_found(name: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "RepositoryNotFoundException",
        format!(
            "The repository with name '{name}' does not exist in the registry with id '{registry}'",
            name = name,
            registry = "",
        ),
    )
}

fn repository_already_exists(name: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "RepositoryAlreadyExistsException",
        format!("The repository with name '{name}' already exists in the registry."),
    )
}

fn repository_policy_not_found(name: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "RepositoryPolicyNotFoundException",
        format!("Repository policy does not exist for the repository with name '{name}'."),
    )
}

/// Validate ECR repository name against AWS pattern:
/// `(?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*`, length 2–256.
/// Each `/`-separated segment starts and ends with `[a-z0-9]` and uses
/// `[._-]` only between alphanum runs.
fn validate_repository_name(name: &str) -> Result<(), AwsServiceError> {
    let invalid = || {
        invalid_parameter(format!(
            "Invalid parameter at 'repositoryName': '{name}' failed to satisfy constraint: \
             'must satisfy regular expression pattern: (?:[a-z0-9]+(?:[._-][a-z0-9]+)*/)*[a-z0-9]+(?:[._-][a-z0-9]+)*'",
        ))
    };
    if name.len() < 2 || name.len() > 256 {
        return Err(invalid());
    }
    // Segments split by `/`. Empty segment (e.g. `foo/`, `foo//bar`,
    // leading/trailing slash) is disallowed.
    for segment in name.split('/') {
        if segment.is_empty() {
            return Err(invalid());
        }
        // Segment := alphanum+ ([._-] alphanum+)*
        let bytes = segment.as_bytes();
        let mut i = 0usize;
        // Leading alphanum run (at least 1 byte).
        if !is_alnum(bytes[0]) {
            return Err(invalid());
        }
        while i < bytes.len() && is_alnum(bytes[i]) {
            i += 1;
        }
        while i < bytes.len() {
            // Separator.
            if !matches!(bytes[i], b'.' | b'_' | b'-') {
                return Err(invalid());
            }
            i += 1;
            // Required alphanum run after each separator.
            if i >= bytes.len() || !is_alnum(bytes[i]) {
                return Err(invalid());
            }
            while i < bytes.len() && is_alnum(bytes[i]) {
                i += 1;
            }
        }
    }
    Ok(())
}

fn is_alnum(b: u8) -> bool {
    b.is_ascii_lowercase() || b.is_ascii_digit()
}

fn parse_tags(body: &Value) -> Vec<(String, String)> {
    body.get("tags")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|t| {
                    let k = t.get("Key").and_then(|v| v.as_str())?;
                    let v = t.get("Value").and_then(|v| v.as_str()).unwrap_or("");
                    Some((k.to_string(), v.to_string()))
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Resolve the account to scope this request to. ECR inputs use
/// `registryId` to address another account; absent means caller's
/// account. We mirror the cross-service pattern: if `registryId` is
/// present and different, the caller must have cross-account trust —
/// but for CRUD ops we only need to pick the right state entry.
fn target_account_id(request: &AwsRequest, body: &Value) -> String {
    if let Some(id) = body.get("registryId").and_then(|v| v.as_str()) {
        if !id.is_empty() {
            return id.to_string();
        }
    }
    request.account_id.clone()
}

fn repository_to_json(repo: &Repository) -> Value {
    json!({
        "repositoryArn": repo.repository_arn,
        "registryId": repo.registry_id,
        "repositoryName": repo.repository_name,
        "repositoryUri": repo.repository_uri,
        "createdAt": repo.created_at.timestamp(),
        "imageTagMutability": repo.image_tag_mutability,
        "imageScanningConfiguration": {
            "scanOnPush": repo.image_scanning_configuration.scan_on_push,
        },
        "encryptionConfiguration": encryption_config_json(&repo.encryption_configuration),
    })
}

fn encryption_config_json(cfg: &EncryptionConfiguration) -> Value {
    let mut map = Map::new();
    map.insert("encryptionType".into(), json!(cfg.encryption_type));
    if let Some(kms) = &cfg.kms_key {
        map.insert("kmsKey".into(), json!(kms));
    }
    Value::Object(map)
}

/// Decode an ECR resource ARN into `(account_id, repository_name)`.
/// Accepts either a full ARN (`arn:aws:ecr:region:account:repository/name`)
/// or a bare repository name for request bodies that accept both.
fn decode_resource_arn(arn: &str) -> Result<(Option<String>, String), AwsServiceError> {
    if let Some(rest) = arn.strip_prefix("arn:aws:ecr:") {
        let mut parts = rest.splitn(4, ':');
        let _region = parts
            .next()
            .ok_or_else(|| invalid_parameter("Malformed resource ARN"))?;
        let account = parts
            .next()
            .ok_or_else(|| invalid_parameter("Malformed resource ARN"))?;
        let resource = parts
            .next()
            .ok_or_else(|| invalid_parameter("Malformed resource ARN"))?;
        let repo = resource
            .strip_prefix("repository/")
            .ok_or_else(|| invalid_parameter("Resource ARN must reference a repository"))?;
        Ok((Some(account.to_string()), repo.to_string()))
    } else {
        Ok((None, arn.to_string()))
    }
}

// -------- operations --------

impl EcrService {
    fn create_repository(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        validate_repository_name(&name)?;
        let image_tag_mutability = opt_str(&body, "imageTagMutability")
            .unwrap_or("MUTABLE")
            .to_string();
        if image_tag_mutability != "MUTABLE" && image_tag_mutability != "IMMUTABLE" {
            return Err(invalid_parameter(format!(
                "Invalid value for imageTagMutability: {image_tag_mutability}"
            )));
        }
        let scan_on_push = body
            .get("imageScanningConfiguration")
            .and_then(|v| v.get("scanOnPush"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let encryption = body
            .get("encryptionConfiguration")
            .map(|v| EncryptionConfiguration {
                encryption_type: v
                    .get("encryptionType")
                    .and_then(|x| x.as_str())
                    .unwrap_or("AES256")
                    .to_string(),
                kms_key: v
                    .get("kmsKey")
                    .and_then(|x| x.as_str())
                    .map(|s| s.to_string()),
            })
            .unwrap_or_default();
        let tags = parse_tags(&body);

        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let endpoint = accounts.endpoint().to_string();
        let state = accounts.get_or_create(&account);
        if state.repositories.contains_key(&name) {
            return Err(repository_already_exists(&name));
        }
        let arn = state.repository_arn(&name);
        let mut repo = Repository::new(&name, arn, state.registry_id(), &endpoint);
        repo.image_tag_mutability = image_tag_mutability;
        repo.image_scanning_configuration = ImageScanningConfiguration { scan_on_push };
        repo.encryption_configuration = encryption;
        for (k, v) in tags {
            repo.tags.insert(k, v);
        }
        let response = repository_to_json(&repo);
        state.repositories.insert(name.clone(), repo);
        Ok(AwsResponse::ok_json(json!({ "repository": response })))
    }

    fn delete_repository(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let force = body.get("force").and_then(|v| v.as_bool()).unwrap_or(false);
        let account = target_account_id(request, &body);

        let mut accounts = self.state.write();
        let state = accounts
            .get_mut(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        // Repository-image state lands in Batch 2; until then, nothing
        // to block the delete, so `force` is accepted but noop-ish.
        let _ = force;
        let snapshot = repository_to_json(repo);
        state.repositories.remove(&name);
        Ok(AwsResponse::ok_json(json!({ "repository": snapshot })))
    }

    fn describe_repositories(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        // AWS's documented default page size for DescribeRepositories.
        const DEFAULT_PAGE_SIZE: usize = 100;
        let body = request.json_body();
        let max_results = match body.get("maxResults").and_then(|v| v.as_i64()) {
            Some(n) => {
                // Smithy @range(min=1, max=1000) on DescribeRepositories.maxResults.
                if !(1..=1000).contains(&n) {
                    return Err(invalid_parameter(format!(
                        "Value '{n}' at 'maxResults' failed to satisfy constraint: \
                         Member must have value between 1 and 1000",
                    )));
                }
                n as usize
            }
            None => DEFAULT_PAGE_SIZE,
        };
        let offset = match body.get("nextToken").and_then(|v| v.as_str()) {
            Some(raw) => raw.parse::<usize>().map_err(|_| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidContinuationTokenException",
                    "The specified continuation token is not valid.",
                )
            })?,
            None => 0,
        };
        let names: Vec<String> = body
            .get("repositoryNames")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let Some(state) = accounts.get(&account) else {
            return Ok(AwsResponse::ok_json(json!({ "repositories": [] })));
        };
        let mut out: Vec<Value> = Vec::new();
        let mut next_token: Option<String> = None;
        if names.is_empty() {
            let all: Vec<&Repository> = state.repositories.values().collect();
            let start = offset.min(all.len());
            let end = (start + max_results).min(all.len());
            for repo in &all[start..end] {
                out.push(repository_to_json(repo));
            }
            if end < all.len() {
                next_token = Some(end.to_string());
            }
        } else {
            for n in &names {
                let repo = state
                    .repositories
                    .get(n)
                    .ok_or_else(|| repository_not_found(n))?;
                out.push(repository_to_json(repo));
            }
        }
        let mut response = json!({ "repositories": out });
        if let Some(token) = next_token {
            response["nextToken"] = json!(token);
        }
        Ok(AwsResponse::ok_json(response))
    }

    fn put_image_tag_mutability(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let mutability = req_str(&body, "imageTagMutability")?.to_string();
        if mutability != "MUTABLE" && mutability != "IMMUTABLE" {
            return Err(invalid_parameter(format!(
                "Invalid value for imageTagMutability: {mutability}"
            )));
        }
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts
            .get_mut(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get_mut(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        repo.image_tag_mutability = mutability.clone();
        let registry_id = repo.registry_id.clone();
        Ok(AwsResponse::ok_json(json!({
            "registryId": registry_id,
            "repositoryName": name,
            "imageTagMutability": mutability,
        })))
    }

    fn put_image_scanning_configuration(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let scan_on_push = body
            .get("imageScanningConfiguration")
            .and_then(|v| v.get("scanOnPush"))
            .and_then(|v| v.as_bool())
            .ok_or_else(|| invalid_parameter("Missing imageScanningConfiguration.scanOnPush"))?;
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts
            .get_mut(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get_mut(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        repo.image_scanning_configuration = ImageScanningConfiguration { scan_on_push };
        let registry_id = repo.registry_id.clone();
        Ok(AwsResponse::ok_json(json!({
            "registryId": registry_id,
            "repositoryName": name,
            "imageScanningConfiguration": { "scanOnPush": scan_on_push },
        })))
    }

    fn set_repository_policy(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let policy_text = req_str(&body, "policyText")?.to_string();
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts
            .get_mut(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get_mut(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        repo.policy = Some(policy_text.clone());
        let registry_id = repo.registry_id.clone();
        Ok(AwsResponse::ok_json(json!({
            "registryId": registry_id,
            "repositoryName": name,
            "policyText": policy_text,
        })))
    }

    fn get_repository_policy(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        let policy = repo
            .policy
            .clone()
            .ok_or_else(|| repository_policy_not_found(&name))?;
        Ok(AwsResponse::ok_json(json!({
            "registryId": repo.registry_id,
            "repositoryName": name,
            "policyText": policy,
        })))
    }

    fn delete_repository_policy(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts
            .get_mut(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get_mut(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        let policy = repo
            .policy
            .take()
            .ok_or_else(|| repository_policy_not_found(&name))?;
        let registry_id = repo.registry_id.clone();
        Ok(AwsResponse::ok_json(json!({
            "registryId": registry_id,
            "repositoryName": name,
            "policyText": policy,
        })))
    }

    fn tag_resource(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let arn = req_str(&body, "resourceArn")?.to_string();
        let (arn_account, name) = decode_resource_arn(&arn)?;
        let tags = parse_tags(&body);
        let account = arn_account.unwrap_or_else(|| request.account_id.clone());
        let mut accounts = self.state.write();
        let state = accounts
            .get_mut(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get_mut(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        for (k, v) in tags {
            repo.tags.insert(k, v);
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn untag_resource(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let arn = req_str(&body, "resourceArn")?.to_string();
        let (arn_account, name) = decode_resource_arn(&arn)?;
        let keys: Vec<String> = body
            .get("tagKeys")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default();
        let account = arn_account.unwrap_or_else(|| request.account_id.clone());
        let mut accounts = self.state.write();
        let state = accounts
            .get_mut(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get_mut(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        for k in keys {
            repo.tags.remove(&k);
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn list_tags_for_resource(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let arn = req_str(&body, "resourceArn")?.to_string();
        let (arn_account, name) = decode_resource_arn(&arn)?;
        let account = arn_account.unwrap_or_else(|| request.account_id.clone());
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        let tags: Vec<Value> = repo
            .tags
            .iter()
            .map(|(k, v)| json!({ "Key": k, "Value": v }))
            .collect();
        Ok(AwsResponse::ok_json(json!({ "tags": tags })))
    }
}

// -------- image + layer helpers --------

fn image_not_found(repo: &str, id: &Value) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ImageNotFoundException",
        format!("The image with imageId {{{id}}} does not exist within the repository with name '{repo}'"),
    )
}

fn layer_not_found(digest: &str, repo: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "LayersNotFoundException",
        format!(
            "The layers with layerDigests '[{digest}]' do not exist in the repository with name '{repo}'"
        ),
    )
}

fn upload_not_found(upload_id: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "UploadNotFoundException",
        format!("The upload '{upload_id}' does not exist."),
    )
}

fn image_already_exists(repo: &str, tag: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ImageAlreadyExistsException",
        format!(
            "Image with tag '{tag}' in repository '{repo}' already exists with a different digest and tag mutability is set to IMMUTABLE."
        ),
    )
}

fn invalid_layer(message: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(StatusCode::BAD_REQUEST, "InvalidLayerException", message)
}

fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

fn image_id_for(image: &Image, tag: Option<&str>) -> Value {
    let mut id = json!({ "imageDigest": image.image_digest });
    if let Some(t) = tag {
        id["imageTag"] = json!(t);
    }
    id
}

fn image_to_details(repo: &Repository, image: &Image, registry_id: &str) -> Value {
    // All tags pointing at this digest.
    let tags: Vec<&str> = repo
        .image_tags
        .iter()
        .filter(|(_, d)| d.as_str() == image.image_digest)
        .map(|(t, _)| t.as_str())
        .collect();
    let mut out = json!({
        "registryId": registry_id,
        "repositoryName": repo.repository_name,
        "imageDigest": image.image_digest,
        "imageTags": tags,
        "imageSizeInBytes": image.image_size_in_bytes,
        "imagePushedAt": image.image_pushed_at.timestamp(),
        "imageManifestMediaType": image.image_manifest_media_type,
    });
    if let Some(a) = &image.artifact_media_type {
        out["artifactMediaType"] = json!(a);
    }
    if let Some(t) = image.last_recorded_pull_time {
        out["lastRecordedPullTime"] = json!(t.timestamp());
    }
    out
}

/// Resolve `imageId` into a stored digest for this repo. Accepts either
/// `{imageDigest}` or `{imageTag}` (or both — digest wins when both set).
fn resolve_image_digest(repo: &Repository, image_id: &Value) -> Option<String> {
    if let Some(d) = image_id.get("imageDigest").and_then(|v| v.as_str()) {
        if repo.images.contains_key(d) {
            return Some(d.to_string());
        }
        return None;
    }
    if let Some(tag) = image_id.get("imageTag").and_then(|v| v.as_str()) {
        return repo.image_tags.get(tag).cloned();
    }
    None
}

// -------- image + layer operations --------

impl EcrService {
    fn put_image(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let manifest = req_str(&body, "imageManifest")?.to_string();
        let manifest_media_type = opt_str(&body, "imageManifestMediaType")
            .unwrap_or("application/vnd.docker.distribution.manifest.v2+json")
            .to_string();
        let supplied_tag = opt_str(&body, "imageTag").map(|s| s.to_string());
        let supplied_digest = opt_str(&body, "imageDigest").map(|s| s.to_string());
        let account = target_account_id(request, &body);

        let computed_digest = sha256_digest(manifest.as_bytes());
        if let Some(ref supplied) = supplied_digest {
            if supplied != &computed_digest {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ImageDigestDoesNotMatchException",
                    format!(
                        "The imageDigest '{supplied}' does not match the digest of the uploaded manifest ('{computed_digest}')."
                    ),
                ));
            }
        }
        let digest = supplied_digest.unwrap_or_else(|| computed_digest.clone());

        let mut accounts = self.state.write();
        let state = accounts
            .get_mut(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get_mut(&name)
            .ok_or_else(|| repository_not_found(&name))?;

        // Immutable tag guard: if a tag is supplied, it already maps to
        // a different digest, and the repo is IMMUTABLE, reject.
        if let Some(ref tag) = supplied_tag {
            if let Some(existing) = repo.image_tags.get(tag) {
                if existing != &digest && repo.image_tag_mutability == "IMMUTABLE" {
                    return Err(image_already_exists(&name, tag));
                }
            }
        }

        let image_entry = repo.images.entry(digest.clone()).or_insert_with(|| Image {
            image_digest: digest.clone(),
            image_manifest: manifest.clone(),
            image_manifest_media_type: manifest_media_type.clone(),
            artifact_media_type: None,
            image_size_in_bytes: manifest.len() as u64,
            image_pushed_at: Utc::now(),
            last_recorded_pull_time: None,
        });
        // If the caller re-pushes an existing digest with a new manifest
        // payload (shouldn't happen under sha256 addressing but tolerate
        // it), keep the latest manifest.
        image_entry.image_manifest = manifest;
        image_entry.image_manifest_media_type = manifest_media_type.clone();

        if let Some(tag) = supplied_tag.clone() {
            repo.image_tags.insert(tag, digest.clone());
        }

        let snapshot = repo.images.get(&digest).cloned().unwrap();
        let tag_ref = supplied_tag.as_deref();
        Ok(AwsResponse::ok_json(json!({
            "image": {
                "registryId": repo.registry_id,
                "repositoryName": name,
                "imageId": image_id_for(&snapshot, tag_ref),
                "imageManifest": snapshot.image_manifest,
                "imageManifestMediaType": snapshot.image_manifest_media_type,
            }
        })))
    }

    fn batch_get_image(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let ids = body
            .get("imageIds")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get(&name)
            .ok_or_else(|| repository_not_found(&name))?;

        let mut images: Vec<Value> = Vec::new();
        let mut failures: Vec<Value> = Vec::new();
        for id in &ids {
            match resolve_image_digest(repo, id) {
                Some(digest) => {
                    let img = repo.images.get(&digest).unwrap();
                    let tag = id.get("imageTag").and_then(|v| v.as_str());
                    images.push(json!({
                        "registryId": repo.registry_id,
                        "repositoryName": name,
                        "imageId": image_id_for(img, tag),
                        "imageManifest": img.image_manifest,
                        "imageManifestMediaType": img.image_manifest_media_type,
                    }));
                }
                None => failures.push(json!({
                    "imageId": id,
                    "failureCode": "ImageNotFound",
                    "failureReason": "Requested image not found",
                })),
            }
        }
        Ok(AwsResponse::ok_json(json!({
            "images": images,
            "failures": failures,
        })))
    }

    fn batch_delete_image(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let ids = body
            .get("imageIds")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts
            .get_mut(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get_mut(&name)
            .ok_or_else(|| repository_not_found(&name))?;

        let mut deleted: Vec<Value> = Vec::new();
        let mut failures: Vec<Value> = Vec::new();
        for id in &ids {
            if let Some(tag) = id.get("imageTag").and_then(|v| v.as_str()) {
                // Delete by tag: remove only the tag, image stays if
                // other tags still reference the digest.
                if let Some(digest) = repo.image_tags.remove(tag) {
                    deleted.push(json!({ "imageDigest": digest, "imageTag": tag }));
                    let still_tagged = repo.image_tags.values().any(|d| *d == digest);
                    if !still_tagged {
                        repo.images.remove(&digest);
                    }
                    continue;
                }
                failures.push(json!({
                    "imageId": id,
                    "failureCode": "ImageNotFound",
                    "failureReason": "Requested image not found",
                }));
            } else if let Some(digest) = id.get("imageDigest").and_then(|v| v.as_str()) {
                if repo.images.remove(digest).is_some() {
                    repo.image_tags.retain(|_, d| d != digest);
                    deleted.push(json!({ "imageDigest": digest }));
                    continue;
                }
                failures.push(json!({
                    "imageId": id,
                    "failureCode": "ImageNotFound",
                    "failureReason": "Requested image not found",
                }));
            } else {
                failures.push(json!({
                    "imageId": id,
                    "failureCode": "InvalidImageTag",
                    "failureReason": "Either imageDigest or imageTag must be supplied",
                }));
            }
        }
        Ok(AwsResponse::ok_json(json!({
            "imageIds": deleted,
            "failures": failures,
        })))
    }

    fn batch_check_layer_availability(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let digests: Vec<String> = body
            .get("layerDigests")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        if digests.is_empty() {
            return Err(invalid_parameter(
                "At least one layerDigest must be supplied to BatchCheckLayerAvailability",
            ));
        }
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        let mut layers: Vec<Value> = Vec::new();
        let mut failures: Vec<Value> = Vec::new();
        for digest in &digests {
            match repo.layers.get(digest) {
                Some(layer) => layers.push(json!({
                    "layerDigest": layer.digest,
                    "layerAvailability": "AVAILABLE",
                    "layerSize": layer.size,
                    "mediaType": layer.media_type,
                })),
                None => failures.push(json!({
                    "layerDigest": digest,
                    "failureCode": "MissingLayerDigest",
                    "failureReason": "Layer not found in repository",
                })),
            }
        }
        Ok(AwsResponse::ok_json(json!({
            "layers": layers,
            "failures": failures,
        })))
    }

    fn describe_images(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        const DEFAULT_PAGE_SIZE: usize = 100;
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let ids = body
            .get("imageIds")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let max_results = match body.get("maxResults").and_then(|v| v.as_i64()) {
            Some(n) => {
                if !(1..=1000).contains(&n) {
                    return Err(invalid_parameter(format!(
                        "Value '{n}' at 'maxResults' failed to satisfy constraint: \
                         Member must have value between 1 and 1000",
                    )));
                }
                n as usize
            }
            None => DEFAULT_PAGE_SIZE,
        };
        let offset = match body.get("nextToken").and_then(|v| v.as_str()) {
            Some(raw) => raw.parse::<usize>().map_err(|_| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidContinuationTokenException",
                    "The specified continuation token is not valid.",
                )
            })?,
            None => 0,
        };
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get(&name)
            .ok_or_else(|| repository_not_found(&name))?;

        let mut details: Vec<Value> = Vec::new();
        let mut next_token: Option<String> = None;
        if ids.is_empty() {
            let all: Vec<&Image> = repo.images.values().collect();
            let start = offset.min(all.len());
            let end = (start + max_results).min(all.len());
            for img in &all[start..end] {
                details.push(image_to_details(repo, img, &repo.registry_id));
            }
            if end < all.len() {
                next_token = Some(end.to_string());
            }
        } else {
            for id in &ids {
                let digest =
                    resolve_image_digest(repo, id).ok_or_else(|| image_not_found(&name, id))?;
                let img = repo.images.get(&digest).unwrap();
                details.push(image_to_details(repo, img, &repo.registry_id));
            }
        }
        let mut response = json!({ "imageDetails": details });
        if let Some(token) = next_token {
            response["nextToken"] = json!(token);
        }
        Ok(AwsResponse::ok_json(response))
    }

    fn list_images(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        const DEFAULT_PAGE_SIZE: usize = 100;
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let filter_tag_status = body
            .get("filter")
            .and_then(|v| v.get("tagStatus"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let max_results = match body.get("maxResults").and_then(|v| v.as_i64()) {
            Some(n) => {
                if !(1..=1000).contains(&n) {
                    return Err(invalid_parameter(format!(
                        "Value '{n}' at 'maxResults' failed to satisfy constraint: \
                         Member must have value between 1 and 1000",
                    )));
                }
                n as usize
            }
            None => DEFAULT_PAGE_SIZE,
        };
        let offset = match body.get("nextToken").and_then(|v| v.as_str()) {
            Some(raw) => raw.parse::<usize>().map_err(|_| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidContinuationTokenException",
                    "The specified continuation token is not valid.",
                )
            })?,
            None => 0,
        };
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get(&name)
            .ok_or_else(|| repository_not_found(&name))?;

        // Enumerate once per (digest, tag-or-untagged) combination.
        let mut all: Vec<(String, Option<String>)> = Vec::new();
        for (tag, digest) in &repo.image_tags {
            all.push((digest.clone(), Some(tag.clone())));
        }
        let tagged_digests: std::collections::HashSet<&String> = repo.image_tags.values().collect();
        for digest in repo.images.keys() {
            if !tagged_digests.contains(digest) {
                all.push((digest.clone(), None));
            }
        }
        // Apply filter.
        all.retain(|(_, tag)| match filter_tag_status.as_deref() {
            Some("TAGGED") => tag.is_some(),
            Some("UNTAGGED") => tag.is_none(),
            _ => true,
        });
        all.sort();

        let start = offset.min(all.len());
        let end = (start + max_results).min(all.len());
        let ids: Vec<Value> = all[start..end]
            .iter()
            .map(|(d, t)| {
                let mut v = json!({ "imageDigest": d });
                if let Some(tag) = t {
                    v["imageTag"] = json!(tag);
                }
                v
            })
            .collect();
        let mut response = json!({ "imageIds": ids });
        if end < all.len() {
            response["nextToken"] = json!(end.to_string());
        }
        Ok(AwsResponse::ok_json(response))
    }

    fn get_download_url_for_layer(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let digest = req_str(&body, "layerDigest")?.to_string();
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        if !repo.layers.contains_key(&digest) {
            return Err(layer_not_found(&digest, &name));
        }
        // Batch 3 will host `/v2/<name>/blobs/<digest>` — return that
        // path as a relative URL so callers that trust the endpoint
        // they're already talking to can resolve it.
        let endpoint = accounts.endpoint();
        let url = format!(
            "{}/v2/{}/blobs/{}",
            endpoint.trim_end_matches('/'),
            name,
            digest
        );
        Ok(AwsResponse::ok_json(json!({
            "downloadUrl": url,
            "layerDigest": digest,
        })))
    }

    fn initiate_layer_upload(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts
            .get_mut(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        if !state.repositories.contains_key(&name) {
            return Err(repository_not_found(&name));
        }
        let upload_id = Uuid::new_v4().to_string();
        state.layer_uploads.insert(
            upload_id.clone(),
            LayerUpload {
                upload_id: upload_id.clone(),
                repository_name: name,
                created_at: Utc::now(),
                blob_b64: String::new(),
                last_byte_received: 0,
            },
        );
        Ok(AwsResponse::ok_json(json!({
            "uploadId": upload_id,
            // Matches the real AWS default of 10 MiB.
            "partSize": 10_485_760u64,
        })))
    }

    fn upload_layer_part(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let upload_id = req_str(&body, "uploadId")?.to_string();
        let first_byte = body
            .get("partFirstByte")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| invalid_parameter("Missing partFirstByte"))?;
        let last_byte = body
            .get("partLastByte")
            .and_then(|v| v.as_u64())
            .ok_or_else(|| invalid_parameter("Missing partLastByte"))?;
        let part_blob_b64 = req_str(&body, "layerPartBlob")?.to_string();
        let part_bytes = B64
            .decode(part_blob_b64.as_bytes())
            .map_err(|_| invalid_layer("layerPartBlob is not valid base64"))?;
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts
            .get_mut(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let upload = state
            .layer_uploads
            .get_mut(&upload_id)
            .ok_or_else(|| upload_not_found(&upload_id))?;
        if upload.repository_name != name {
            return Err(upload_not_found(&upload_id));
        }
        if first_byte != upload.last_byte_received {
            return Err(invalid_layer(format!(
                "Layer part upload out of order: expected partFirstByte {} got {}",
                upload.last_byte_received, first_byte,
            )));
        }
        let expected_len = last_byte
            .checked_sub(first_byte)
            .and_then(|d| d.checked_add(1))
            .ok_or_else(|| invalid_layer("partLastByte < partFirstByte"))?;
        if part_bytes.len() as u64 != expected_len {
            return Err(invalid_layer(format!(
                "Layer part size mismatch: bytes {} doesn't match range [{first_byte}, {last_byte}]",
                part_bytes.len()
            )));
        }
        let existing = B64.decode(upload.blob_b64.as_bytes()).unwrap_or_default();
        let mut combined = existing;
        combined.extend_from_slice(&part_bytes);
        upload.blob_b64 = B64.encode(&combined);
        upload.last_byte_received = last_byte + 1;
        Ok(AwsResponse::ok_json(json!({
            "registryId": state.registry_id(),
            "repositoryName": name,
            "uploadId": upload_id,
            "lastByteReceived": last_byte,
        })))
    }

    fn get_authorization_token(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let registry_ids: Vec<String> = body
            .get("registryIds")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let accounts = self.state.read();
        let default_account = accounts.default_account_id().to_string();
        let targets = if registry_ids.is_empty() {
            vec![default_account]
        } else {
            registry_ids
        };
        let endpoint = accounts.endpoint().to_string();
        drop(accounts);
        let expires_at = (Utc::now() + chrono::Duration::hours(12)).timestamp();
        let authorization_data: Vec<Value> = targets
            .into_iter()
            .map(|_registry_id| {
                let token = B64.encode(format!("AWS:{}", Uuid::new_v4()).as_bytes());
                json!({
                    "authorizationToken": token,
                    "expiresAt": expires_at,
                    "proxyEndpoint": endpoint,
                })
            })
            .collect();
        Ok(AwsResponse::ok_json(json!({
            "authorizationData": authorization_data,
        })))
    }

    fn complete_layer_upload(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let upload_id = req_str(&body, "uploadId")?.to_string();
        let digests: Vec<String> = body
            .get("layerDigests")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        if digests.is_empty() {
            return Err(invalid_parameter(
                "At least one layerDigest must be supplied to CompleteLayerUpload",
            ));
        }
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts
            .get_mut(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        // Peek, validate, then commit — so a digest mismatch lets the
        // caller retry CompleteLayerUpload with the correct digest
        // instead of having to re-upload the entire blob.
        let upload = state
            .layer_uploads
            .get(&upload_id)
            .ok_or_else(|| upload_not_found(&upload_id))?;
        if upload.repository_name != name {
            return Err(upload_not_found(&upload_id));
        }
        let blob_bytes = B64.decode(upload.blob_b64.as_bytes()).unwrap_or_default();
        let computed = sha256_digest(&blob_bytes);
        if !digests.iter().any(|d| d == &computed) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "LayerDigestMismatchException",
                format!(
                    "The layer digest from the client ({}) does not match the digest of the received bytes ({computed})",
                    digests.join(",")
                ),
            ));
        }
        let _upload = state.layer_uploads.remove(&upload_id).unwrap();
        let size = blob_bytes.len() as u64;
        // Drop the write guard before the KMS encrypt call (which takes
        // its own lock). Re-acquire to insert.
        drop(accounts);
        let (stored_bytes, encrypted_with) =
            crate::oci::encrypt_layer_bytes(self, &account, &name, &blob_bytes);
        let mut accounts = self.state.write();
        let state = accounts
            .get_mut(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get_mut(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        repo.layers.insert(
            computed.clone(),
            Layer {
                digest: computed.clone(),
                size,
                blob_b64: B64.encode(&stored_bytes),
                media_type: "application/vnd.docker.image.rootfs.diff.tar.gzip".to_string(),
                encrypted_with_kms_key: encrypted_with,
            },
        );
        let registry_id = repo.registry_id.clone();
        Ok(AwsResponse::ok_json(json!({
            "registryId": registry_id,
            "repositoryName": name,
            "uploadId": upload_id,
            "layerDigest": computed,
        })))
    }
}

// -------- lifecycle + scan + registry + polish handlers (Batch 4) --------

fn lifecycle_policy_not_found(name: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "LifecyclePolicyNotFoundException",
        format!("Lifecycle policy does not exist for the repository with name '{name}'."),
    )
}

fn registry_policy_not_found() -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "RegistryPolicyNotFoundException",
        "The registry doesn't have an associated registry policy.",
    )
}

/// Apply lifecycle-policy rules to this repo's stored images and
/// return the digests that should be pruned. Covers the four AWS
/// selection dimensions in use today: `tagStatus` (tagged/untagged/any),
/// `tagPrefixList`, `tagPatternList` (wildcard `*`), and `countType`
/// (`imageCountMoreThan` or `sinceImagePushed` with `countUnit=days`).
/// Rules run in ascending `rulePriority` order; later rules can't
/// re-prune images earlier rules already marked.
fn evaluate_lifecycle_policy(repo: &crate::state::Repository, policy: &str) -> Vec<String> {
    let Ok(doc) = serde_json::from_str::<Value>(policy) else {
        return Vec::new();
    };
    let Some(rules) = doc.get("rules").and_then(|v| v.as_array()) else {
        return Vec::new();
    };
    let mut to_delete: std::collections::BTreeSet<String> = std::collections::BTreeSet::new();
    // Sort rules by priority ascending (lower priority runs first
    // per AWS semantics).
    let mut sorted: Vec<&Value> = rules.iter().collect();
    sorted.sort_by_key(|r| r.get("rulePriority").and_then(|v| v.as_i64()).unwrap_or(0));
    for rule in sorted {
        let sel = rule.get("selection").cloned().unwrap_or(Value::Null);
        let tag_status = sel
            .get("tagStatus")
            .and_then(|v| v.as_str())
            .unwrap_or("any");
        let count_type = sel.get("countType").and_then(|v| v.as_str()).unwrap_or("");
        let count_number = sel.get("countNumber").and_then(|v| v.as_i64()).unwrap_or(0);
        let count_unit = sel
            .get("countUnit")
            .and_then(|v| v.as_str())
            .unwrap_or("days");
        let tag_prefix_list: Vec<String> = sel
            .get("tagPrefixList")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let tag_pattern_list: Vec<String> = sel
            .get("tagPatternList")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        // Per-image tag lookup: repo stores a tag -> digest map; invert
        // so we can ask "what tags point at this digest".
        let tags_for = |digest: &str| -> Vec<&str> {
            repo.image_tags
                .iter()
                .filter_map(|(t, d)| (d == digest).then_some(t.as_str()))
                .collect()
        };

        // Candidate images, filtered by tagStatus + tagPrefixList +
        // tagPatternList. Per AWS, the tag filters only apply when
        // tagStatus=tagged.
        let mut candidates: Vec<&Image> = repo
            .images
            .values()
            .filter(|img| {
                let tags = tags_for(&img.image_digest);
                let has_tag = !tags.is_empty();
                match tag_status {
                    "tagged" => {
                        if !has_tag {
                            return false;
                        }
                        if !tag_prefix_list.is_empty()
                            && !tags
                                .iter()
                                .any(|t| tag_prefix_list.iter().any(|p| t.starts_with(p.as_str())))
                        {
                            return false;
                        }
                        if !tag_pattern_list.is_empty()
                            && !tags.iter().any(|t| {
                                tag_pattern_list
                                    .iter()
                                    .any(|p| wildcard_match(p.as_str(), t))
                            })
                        {
                            return false;
                        }
                        true
                    }
                    "untagged" => !has_tag,
                    _ => true,
                }
            })
            .filter(|img| !to_delete.contains(&img.image_digest))
            .collect();
        candidates.sort_by_key(|img| img.image_pushed_at);
        match count_type {
            "imageCountMoreThan" => {
                // Keep the newest N, prune the rest.
                let total = candidates.len() as i64;
                if total > count_number {
                    let prune_count = (total - count_number) as usize;
                    for img in candidates.into_iter().take(prune_count) {
                        to_delete.insert(img.image_digest.clone());
                    }
                }
            }
            "sinceImagePushed" => {
                let now = chrono::Utc::now();
                let delta = match count_unit {
                    "days" => chrono::Duration::days(count_number),
                    "hours" => chrono::Duration::hours(count_number),
                    _ => chrono::Duration::days(count_number),
                };
                let threshold = now - delta;
                for img in candidates {
                    if img.image_pushed_at < threshold {
                        to_delete.insert(img.image_digest.clone());
                    }
                }
            }
            _ => {}
        }
    }
    to_delete.into_iter().collect()
}

/// AWS lifecycle `tagPatternList` supports `*` as a shell-style
/// wildcard. No regex metacharacters beyond `*`, no anchoring beyond
/// full-string match.
fn wildcard_match(pattern: &str, text: &str) -> bool {
    let parts: Vec<&str> = pattern.split('*').collect();
    if parts.len() == 1 {
        return parts[0] == text;
    }
    let mut rest = text;
    // Leading literal must match start if the pattern doesn't start
    // with a `*`.
    if let Some(first) = parts.first() {
        if !first.is_empty() {
            if !rest.starts_with(first) {
                return false;
            }
            rest = &rest[first.len()..];
        }
    }
    // Trailing literal must match end if the pattern doesn't end
    // with a `*`.
    let last_idx = parts.len() - 1;
    for (i, seg) in parts.iter().enumerate().skip(1) {
        if seg.is_empty() {
            continue;
        }
        if i == last_idx {
            if !rest.ends_with(seg) {
                return false;
            }
            rest = &rest[..rest.len() - seg.len()];
        } else if let Some(pos) = rest.find(seg) {
            rest = &rest[pos + seg.len()..];
        } else {
            return false;
        }
    }
    true
}

impl EcrService {
    fn put_lifecycle_policy(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let policy = req_str(&body, "lifecyclePolicyText")?.to_string();
        // Parse sanity-check.
        serde_json::from_str::<Value>(&policy)
            .map_err(|_| invalid_parameter("lifecyclePolicyText is not valid JSON"))?;
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts
            .get_mut(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get_mut(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        repo.lifecycle_policy = Some(policy.clone());
        // Apply immediately so the store reflects the policy.
        let prune = evaluate_lifecycle_policy(repo, &policy);
        for digest in &prune {
            repo.images.remove(digest);
            repo.image_tags.retain(|_, d| d != digest);
        }
        let registry_id = repo.registry_id.clone();
        Ok(AwsResponse::ok_json(json!({
            "registryId": registry_id,
            "repositoryName": name,
            "lifecyclePolicyText": policy,
        })))
    }

    fn get_lifecycle_policy(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        let policy = repo
            .lifecycle_policy
            .clone()
            .ok_or_else(|| lifecycle_policy_not_found(&name))?;
        Ok(AwsResponse::ok_json(json!({
            "registryId": repo.registry_id,
            "repositoryName": name,
            "lifecyclePolicyText": policy,
            "lastEvaluatedAt": Utc::now().timestamp(),
        })))
    }

    fn delete_lifecycle_policy(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts
            .get_mut(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get_mut(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        let policy = repo
            .lifecycle_policy
            .take()
            .ok_or_else(|| lifecycle_policy_not_found(&name))?;
        let registry_id = repo.registry_id.clone();
        Ok(AwsResponse::ok_json(json!({
            "registryId": registry_id,
            "repositoryName": name,
            "lifecyclePolicyText": policy,
            "lastEvaluatedAt": Utc::now().timestamp(),
        })))
    }

    fn start_lifecycle_policy_preview(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let account = target_account_id(request, &body);
        let policy = match opt_str(&body, "lifecyclePolicyText") {
            Some(s) => s.to_string(),
            None => {
                let accounts = self.state.read();
                let state = accounts
                    .get(&account)
                    .ok_or_else(|| repository_not_found(&name))?;
                let repo = state
                    .repositories
                    .get(&name)
                    .ok_or_else(|| repository_not_found(&name))?;
                repo.lifecycle_policy
                    .clone()
                    .ok_or_else(|| lifecycle_policy_not_found(&name))?
            }
        };
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        let _prune = evaluate_lifecycle_policy(repo, &policy);
        Ok(AwsResponse::ok_json(json!({
            "registryId": repo.registry_id,
            "repositoryName": name,
            "lifecyclePolicyText": policy,
            "status": "COMPLETE",
        })))
    }

    fn get_lifecycle_policy_preview(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        let policy = repo
            .lifecycle_policy
            .clone()
            .ok_or_else(|| lifecycle_policy_not_found(&name))?;
        let prune = evaluate_lifecycle_policy(repo, &policy);
        let results: Vec<Value> = prune
            .iter()
            .map(|digest| {
                json!({
                    "imageDigest": digest,
                    "imagePushedAt": repo.images.get(digest).map(|i| i.image_pushed_at.timestamp()).unwrap_or(0),
                    "action": {"type": "EXPIRE"},
                })
            })
            .collect();
        Ok(AwsResponse::ok_json(json!({
            "registryId": repo.registry_id,
            "repositoryName": name,
            "lifecyclePolicyText": policy,
            "status": "COMPLETE",
            "previewResults": results,
            "summary": {"expiringImageTotalCount": prune.len()},
        })))
    }

    fn start_image_scan(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        use crate::state::ImageScanFindings;
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let image_id = body
            .get("imageId")
            .cloned()
            .ok_or_else(|| invalid_parameter("Missing imageId"))?;
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts
            .get_mut(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get_mut(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        let digest = resolve_image_digest(repo, &image_id)
            .ok_or_else(|| image_not_found(&name, &image_id))?;
        // Synthetic-but-schema-complete findings. Real scanner integration
        // lives out of scope for a mock; a deterministic non-empty shape
        // lets callers exercise their findings plumbing.
        let findings = ImageScanFindings {
            image_digest: digest.clone(),
            scan_status: "COMPLETE".to_string(),
            scan_completed_at: Some(Utc::now()),
            vulnerability_source_updated_at: Some(Utc::now()),
            finding_severity_counts: BTreeMap::new(),
            findings: Vec::new(),
        };
        repo.scan_findings.insert(digest.clone(), findings);
        let registry_id = repo.registry_id.clone();
        Ok(AwsResponse::ok_json(json!({
            "registryId": registry_id,
            "repositoryName": name,
            "imageId": image_id,
            "imageScanStatus": {"status": "IN_PROGRESS"},
        })))
    }

    fn describe_image_scan_findings(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let image_id = body
            .get("imageId")
            .cloned()
            .ok_or_else(|| invalid_parameter("Missing imageId"))?;
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        let digest = resolve_image_digest(repo, &image_id)
            .ok_or_else(|| image_not_found(&name, &image_id))?;
        let findings = repo.scan_findings.get(&digest).cloned().unwrap_or_else(|| {
            crate::state::ImageScanFindings {
                image_digest: digest.clone(),
                scan_status: "COMPLETE".to_string(),
                scan_completed_at: Some(Utc::now()),
                vulnerability_source_updated_at: Some(Utc::now()),
                finding_severity_counts: BTreeMap::new(),
                findings: Vec::new(),
            }
        });
        Ok(AwsResponse::ok_json(json!({
            "registryId": repo.registry_id,
            "repositoryName": name,
            "imageId": image_id,
            "imageScanStatus": {"status": findings.scan_status},
            "imageScanFindings": {
                "imageScanCompletedAt": findings.scan_completed_at.map(|t| t.timestamp()),
                "vulnerabilitySourceUpdatedAt": findings.vulnerability_source_updated_at.map(|t| t.timestamp()),
                "findings": findings.findings,
                "findingSeverityCounts": findings.finding_severity_counts,
                // fakecloud-specific marker: these findings are synthetic
                // and do not reflect real CVE data. AWS SDKs using Smithy
                // codegen ignore unknown fields, so this is purely a
                // signal for introspection callers and security-tooling
                // integration tests that want to assert they're running
                // against fakecloud rather than real Inspector output.
                "isSynthetic": true,
            },
        })))
    }

    fn describe_registry(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts.get(&account);
        let registry_id = state
            .map(|s| s.account_id.clone())
            .unwrap_or_else(|| account.clone());
        let rules = state
            .and_then(|s| s.replication_configuration.as_ref())
            .map(|cfg| {
                cfg.rules
                    .iter()
                    .map(|r| {
                        json!({
                            "destinations": r.destinations.iter().map(|d| json!({
                                "region": d.region,
                                "registryId": d.registry_id,
                            })).collect::<Vec<_>>(),
                            "repositoryFilters": r.repository_filters.iter().map(|f| json!({
                                "filter": f.filter,
                                "filterType": f.filter_type,
                            })).collect::<Vec<_>>(),
                        })
                    })
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        Ok(AwsResponse::ok_json(json!({
            "registryId": registry_id,
            "replicationConfiguration": {"rules": rules},
        })))
    }

    fn get_registry_policy(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(registry_policy_not_found)?;
        let policy = state
            .registry_policy
            .clone()
            .ok_or_else(registry_policy_not_found)?;
        Ok(AwsResponse::ok_json(json!({
            "registryId": state.account_id,
            "policyText": policy,
        })))
    }

    fn put_registry_policy(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let policy = req_str(&body, "policyText")?.to_string();
        if policy.len() > 10_240 {
            return Err(invalid_parameter(format!(
                "Value at 'policyText' failed to satisfy constraint: \
                 Member must have length less than or equal to 10240 (got {})",
                policy.len()
            )));
        }
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        state.registry_policy = Some(policy.clone());
        Ok(AwsResponse::ok_json(json!({
            "registryId": state.account_id,
            "policyText": policy,
        })))
    }

    fn delete_registry_policy(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts
            .get_mut(&account)
            .ok_or_else(registry_policy_not_found)?;
        let policy = state
            .registry_policy
            .take()
            .ok_or_else(registry_policy_not_found)?;
        Ok(AwsResponse::ok_json(json!({
            "registryId": state.account_id,
            "policyText": policy,
        })))
    }

    fn get_registry_scanning_configuration(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts.get(&account);
        let cfg = state
            .map(|s| s.registry_scanning_configuration.clone())
            .unwrap_or_default();
        let rules: Vec<Value> = cfg
            .rules
            .iter()
            .map(|r| {
                json!({
                    "scanFrequency": r.scan_frequency,
                    "repositoryFilters": r.repository_filters.iter().map(|f| json!({
                        "filter": f.filter,
                        "filterType": f.filter_type,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        Ok(AwsResponse::ok_json(json!({
            "registryId": state.map(|s| s.account_id.clone()).unwrap_or(account),
            "scanningConfiguration": {
                "scanType": cfg.scan_type,
                "rules": rules,
            },
        })))
    }

    fn put_registry_scanning_configuration(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        use crate::state::{RegistryScanningConfiguration, RegistryScanningRule, RepositoryFilter};
        let body = request.json_body();
        let scan_type = opt_str(&body, "scanType").unwrap_or("BASIC").to_string();
        if scan_type != "BASIC" && scan_type != "ENHANCED" {
            return Err(invalid_parameter(format!(
                "Invalid scanType '{scan_type}'. Must be BASIC or ENHANCED."
            )));
        }
        let rules = body
            .get("rules")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let parsed_rules: Vec<RegistryScanningRule> = rules
            .iter()
            .map(|r| RegistryScanningRule {
                scan_frequency: r
                    .get("scanFrequency")
                    .and_then(|v| v.as_str())
                    .unwrap_or("SCAN_ON_PUSH")
                    .to_string(),
                repository_filters: r
                    .get("repositoryFilters")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .map(|f| RepositoryFilter {
                                filter: f
                                    .get("filter")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                filter_type: f
                                    .get("filterType")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("WILDCARD")
                                    .to_string(),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            })
            .collect();
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        state.registry_scanning_configuration = RegistryScanningConfiguration {
            scan_type: scan_type.clone(),
            rules: parsed_rules,
        };
        let cfg = state.registry_scanning_configuration.clone();
        Ok(AwsResponse::ok_json(json!({
            "registryScanningConfiguration": {
                "scanType": cfg.scan_type,
                "rules": cfg.rules.iter().map(|r| json!({
                    "scanFrequency": r.scan_frequency,
                    "repositoryFilters": r.repository_filters.iter().map(|f| json!({
                        "filter": f.filter,
                        "filterType": f.filter_type,
                    })).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
            },
        })))
    }

    fn batch_get_repository_scanning_configuration(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let names: Vec<String> = body
            .get("repositoryNames")
            .and_then(|v| v.as_array())
            .ok_or_else(|| invalid_parameter("Missing required field: repositoryNames"))?
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect();
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| repository_not_found(&account))?;
        let mut scanning: Vec<Value> = Vec::new();
        let mut failures: Vec<Value> = Vec::new();
        for n in &names {
            match state.repositories.get(n) {
                Some(repo) => scanning.push(json!({
                    "repositoryArn": repo.repository_arn,
                    "repositoryName": n,
                    "scanOnPush": repo.image_scanning_configuration.scan_on_push,
                    "scanFrequency": "SCAN_ON_PUSH",
                    "appliedScanFilters": [],
                })),
                None => failures.push(json!({
                    "repositoryName": n,
                    "failureCode": "REPOSITORY_NOT_FOUND",
                    "failureReason": format!("Repository '{n}' not found"),
                })),
            }
        }
        Ok(AwsResponse::ok_json(json!({
            "scanningConfigurations": scanning,
            "failures": failures,
        })))
    }

    fn put_replication_configuration(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        use crate::state::{
            ReplicationConfiguration, ReplicationDestination, ReplicationRule, RepositoryFilter,
        };
        let body = request.json_body();
        let cfg_value = body
            .get("replicationConfiguration")
            .cloned()
            .ok_or_else(|| invalid_parameter("Missing replicationConfiguration"))?;
        let rules_value = cfg_value
            .get("rules")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let rules: Vec<ReplicationRule> = rules_value
            .iter()
            .map(|r| ReplicationRule {
                destinations: r
                    .get("destinations")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .map(|d| ReplicationDestination {
                                region: d
                                    .get("region")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                registry_id: d
                                    .get("registryId")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                repository_filters: r
                    .get("repositoryFilters")
                    .and_then(|v| v.as_array())
                    .map(|arr| {
                        arr.iter()
                            .map(|f| RepositoryFilter {
                                filter: f
                                    .get("filter")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("")
                                    .to_string(),
                                filter_type: f
                                    .get("filterType")
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("PREFIX_MATCH")
                                    .to_string(),
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
            })
            .collect();
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        state.replication_configuration = Some(ReplicationConfiguration { rules });
        let cfg = state.replication_configuration.clone().unwrap();
        Ok(AwsResponse::ok_json(json!({
            "replicationConfiguration": {
                "rules": cfg.rules.iter().map(|r| json!({
                    "destinations": r.destinations.iter().map(|d| json!({
                        "region": d.region,
                        "registryId": d.registry_id,
                    })).collect::<Vec<_>>(),
                    "repositoryFilters": r.repository_filters.iter().map(|f| json!({
                        "filter": f.filter,
                        "filterType": f.filter_type,
                    })).collect::<Vec<_>>(),
                })).collect::<Vec<_>>(),
            },
        })))
    }

    fn describe_image_replication_status(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let image_id = body
            .get("imageId")
            .cloned()
            .ok_or_else(|| invalid_parameter("Missing imageId"))?;
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        if resolve_image_digest(repo, &image_id).is_none() {
            return Err(image_not_found(&name, &image_id));
        }
        Ok(AwsResponse::ok_json(json!({
            "repositoryName": name,
            "imageId": image_id,
            "replicationStatuses": [],
        })))
    }

    fn create_pull_through_cache_rule(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        use crate::state::PullThroughCacheRule;
        let body = request.json_body();
        let prefix = req_str(&body, "ecrRepositoryPrefix")?.to_string();
        validate_pullthrough_prefix(&prefix)?;
        let upstream_url = req_str(&body, "upstreamRegistryUrl")?.to_string();
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        if state.pull_through_cache_rules.contains_key(&prefix) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "PullThroughCacheRuleAlreadyExistsException",
                format!("A pull through cache rule with the prefix '{prefix}' already exists."),
            ));
        }
        let now = Utc::now();
        let rule = PullThroughCacheRule {
            ecr_repository_prefix: prefix.clone(),
            upstream_registry_url: upstream_url.clone(),
            upstream_registry: opt_str(&body, "upstreamRegistry").map(|s| s.to_string()),
            credential_arn: opt_str(&body, "credentialArn").map(|s| s.to_string()),
            created_at: now,
            updated_at: now,
            custom_role_arn: opt_str(&body, "customRoleArn").map(|s| s.to_string()),
        };
        state
            .pull_through_cache_rules
            .insert(prefix.clone(), rule.clone());
        Ok(AwsResponse::ok_json(pull_through_rule_json(
            state.account_id.as_str(),
            &rule,
        )))
    }

    fn delete_pull_through_cache_rule(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let prefix = req_str(&body, "ecrRepositoryPrefix")?.to_string();
        validate_pullthrough_prefix(&prefix)?;
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        let removed = state
            .pull_through_cache_rules
            .remove(&prefix)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "PullThroughCacheRuleNotFoundException",
                    format!("No pull through cache rule with prefix '{prefix}' exists."),
                )
            })?;
        // DeletePullThroughCacheRuleResponse omits upstreamRegistry per
        // the Smithy model — it only appears on Create/Describe.
        let mut response = pull_through_rule_json(state.account_id.as_str(), &removed);
        if let Value::Object(ref mut map) = response {
            map.remove("upstreamRegistry");
        }
        Ok(AwsResponse::ok_json(response))
    }

    fn describe_pull_through_cache_rules(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        validate_max_results(&body)?;
        let prefixes: Vec<String> = body
            .get("ecrRepositoryPrefixes")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts.get(&account);
        let rules: Vec<&crate::state::PullThroughCacheRule> = state
            .map(|s| s.pull_through_cache_rules.values().collect())
            .unwrap_or_default();
        let registry_id = state.map(|s| s.account_id.clone()).unwrap_or_default();
        let filtered: Vec<Value> = rules
            .iter()
            .filter(|r| prefixes.is_empty() || prefixes.contains(&r.ecr_repository_prefix))
            .map(|r| pull_through_rule_json_with_updated(&registry_id, r))
            .collect();
        Ok(AwsResponse::ok_json(json!({
            "pullThroughCacheRules": filtered,
        })))
    }

    fn update_pull_through_cache_rule(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let prefix = req_str(&body, "ecrRepositoryPrefix")?.to_string();
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        let rule = state
            .pull_through_cache_rules
            .get_mut(&prefix)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "PullThroughCacheRuleNotFoundException",
                    format!("No pull through cache rule with prefix '{prefix}' exists."),
                )
            })?;
        if let Some(cred) = opt_str(&body, "credentialArn") {
            rule.credential_arn = Some(cred.to_string());
        }
        if let Some(role) = opt_str(&body, "customRoleArn") {
            rule.custom_role_arn = Some(role.to_string());
        }
        rule.updated_at = Utc::now();
        let response = pull_through_rule_json_with_updated(state.account_id.as_str(), rule);
        Ok(AwsResponse::ok_json(response))
    }

    fn validate_pull_through_cache_rule(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let prefix = req_str(&body, "ecrRepositoryPrefix")?.to_string();
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts.get(&account);
        let rule = state
            .and_then(|s| s.pull_through_cache_rules.get(&prefix))
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "PullThroughCacheRuleNotFoundException",
                    format!("No pull through cache rule with prefix '{prefix}' exists."),
                )
            })?;
        let registry_id = state.map(|s| s.account_id.clone()).unwrap_or_default();
        let mut base = pull_through_rule_json(&registry_id, rule);
        base["isValid"] = json!(true);
        Ok(AwsResponse::ok_json(base))
    }

    fn get_account_setting(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "name")?.to_string();
        validate_account_setting_name(&name)?;
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts.get(&account);
        let value = state
            .and_then(|s| s.account_settings.get(&name).cloned())
            .unwrap_or_else(|| "DISABLED".to_string());
        Ok(AwsResponse::ok_json(json!({
            "name": name,
            "value": value,
        })))
    }

    fn put_account_setting(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "name")?.to_string();
        validate_account_setting_name(&name)?;
        let value = req_str(&body, "value")?.to_string();
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        state.account_settings.insert(name.clone(), value.clone());
        Ok(AwsResponse::ok_json(json!({
            "name": name,
            "value": value,
        })))
    }

    fn create_repository_creation_template(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        use crate::state::{EncryptionConfiguration as Enc, RepositoryCreationTemplate};
        let body = request.json_body();
        let prefix = req_str(&body, "prefix")?.to_string();
        validate_template_prefix(&prefix)?;
        let applied_for: Vec<String> = body
            .get("appliedFor")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let image_tag_mutability = opt_str(&body, "imageTagMutability")
            .unwrap_or("MUTABLE")
            .to_string();
        let resource_tags = body
            .get("resourceTags")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let encryption = body.get("encryptionConfiguration").map(|v| Enc {
            encryption_type: v
                .get("encryptionType")
                .and_then(|x| x.as_str())
                .unwrap_or("AES256")
                .to_string(),
            kms_key: v
                .get("kmsKey")
                .and_then(|x| x.as_str())
                .map(|s| s.to_string()),
        });
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        if state.repository_creation_templates.contains_key(&prefix) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "TemplateAlreadyExistsException",
                format!(
                    "A repository creation template with the prefix '{prefix}' already exists."
                ),
            ));
        }
        let now = Utc::now();
        let tpl = RepositoryCreationTemplate {
            prefix: prefix.clone(),
            description: opt_str(&body, "description").map(|s| s.to_string()),
            image_tag_mutability,
            applied_for,
            resource_tags,
            created_at: now,
            updated_at: now,
            custom_role_arn: opt_str(&body, "customRoleArn").map(|s| s.to_string()),
            repository_policy: opt_str(&body, "repositoryPolicy").map(|s| s.to_string()),
            lifecycle_policy: opt_str(&body, "lifecyclePolicy").map(|s| s.to_string()),
            encryption_configuration: encryption,
        };
        state
            .repository_creation_templates
            .insert(prefix, tpl.clone());
        Ok(AwsResponse::ok_json(json!({
            "registryId": state.account_id,
            "repositoryCreationTemplate": template_to_json(&tpl),
        })))
    }

    fn delete_repository_creation_template(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let prefix = req_str(&body, "prefix")?.to_string();
        validate_template_prefix(&prefix)?;
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        let removed = state
            .repository_creation_templates
            .remove(&prefix)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "TemplateNotFoundException",
                    format!("No repository creation template with prefix '{prefix}' exists."),
                )
            })?;
        Ok(AwsResponse::ok_json(json!({
            "registryId": state.account_id,
            "repositoryCreationTemplate": template_to_json(&removed),
        })))
    }

    fn describe_repository_creation_templates(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        validate_max_results(&body)?;
        let prefixes: Vec<String> = body
            .get("prefixes")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts.get(&account);
        let tpls: Vec<Value> = state
            .map(|s| {
                s.repository_creation_templates
                    .values()
                    .filter(|t| prefixes.is_empty() || prefixes.contains(&t.prefix))
                    .map(template_to_json)
                    .collect()
            })
            .unwrap_or_default();
        Ok(AwsResponse::ok_json(json!({
            "registryId": state.map(|s| s.account_id.clone()).unwrap_or_default(),
            "repositoryCreationTemplates": tpls,
        })))
    }

    fn update_repository_creation_template(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let prefix = req_str(&body, "prefix")?.to_string();
        validate_template_prefix(&prefix)?;
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        let tpl = state
            .repository_creation_templates
            .get_mut(&prefix)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "TemplateNotFoundException",
                    format!("No repository creation template with prefix '{prefix}' exists."),
                )
            })?;
        if let Some(desc) = opt_str(&body, "description") {
            tpl.description = Some(desc.to_string());
        }
        if let Some(mutability) = opt_str(&body, "imageTagMutability") {
            tpl.image_tag_mutability = mutability.to_string();
        }
        if let Some(arr) = body.get("appliedFor").and_then(|v| v.as_array()) {
            tpl.applied_for = arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect();
        }
        if let Some(arr) = body.get("resourceTags").and_then(|v| v.as_array()) {
            tpl.resource_tags = arr.clone();
        }
        tpl.updated_at = Utc::now();
        Ok(AwsResponse::ok_json(json!({
            "registryId": state.account_id,
            "repositoryCreationTemplate": template_to_json(tpl),
        })))
    }

    fn get_signing_configuration(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts.get(&account);
        let rules: Vec<Value> = state
            .and_then(|s| s.signing_configuration.as_ref())
            .map(|c| c.rules.clone())
            .unwrap_or_default();
        Ok(AwsResponse::ok_json(json!({
            "registryId": state.map(|s| s.account_id.clone()).unwrap_or_default(),
            "signingConfiguration": {"rules": rules},
        })))
    }

    fn put_signing_configuration(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        use crate::state::SigningConfiguration;
        let body = request.json_body();
        let cfg = body
            .get("signingConfiguration")
            .ok_or_else(|| invalid_parameter("Missing required field: signingConfiguration"))?;
        let rules: Vec<Value> = cfg
            .get("rules")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        state.signing_configuration = Some(SigningConfiguration {
            rules: rules.clone(),
        });
        Ok(AwsResponse::ok_json(json!({
            "signingConfiguration": {"rules": rules},
        })))
    }

    fn delete_signing_configuration(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        state.signing_configuration = None;
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn describe_image_signing_status(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let image_id = body
            .get("imageId")
            .cloned()
            .ok_or_else(|| invalid_parameter("Missing imageId"))?;
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        if resolve_image_digest(repo, &image_id).is_none() {
            return Err(image_not_found(&name, &image_id));
        }
        Ok(AwsResponse::ok_json(json!({
            "registryId": repo.registry_id,
            "repositoryName": name,
            "imageId": image_id,
            "imageSignatures": [],
        })))
    }

    fn register_pull_time_update_exclusion(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        use crate::state::PullTimeExclusion;
        let body = request.json_body();
        let principal_arn = req_str(&body, "principalArn")?.to_string();
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        state
            .pull_time_exclusions
            .entry(principal_arn.clone())
            .or_insert_with(|| PullTimeExclusion {
                principal_arn: principal_arn.clone(),
                registered_at: Utc::now(),
            });
        Ok(AwsResponse::ok_json(json!({
            "principalArn": principal_arn,
        })))
    }

    fn deregister_pull_time_update_exclusion(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let principal_arn = req_str(&body, "principalArn")?.to_string();
        let account = target_account_id(request, &body);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        state.pull_time_exclusions.remove(&principal_arn);
        Ok(AwsResponse::ok_json(json!({
            "principalArn": principal_arn,
        })))
    }

    fn list_pull_time_update_exclusions(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        validate_max_results(&body)?;
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts.get(&account);
        let exclusions: Vec<Value> = state
            .map(|s| {
                s.pull_time_exclusions
                    .values()
                    .map(|e| {
                        json!({
                            "principalArn": e.principal_arn,
                            "registeredAt": e.registered_at.timestamp(),
                        })
                    })
                    .collect()
            })
            .unwrap_or_default();
        Ok(AwsResponse::ok_json(json!({
            "pullTimeUpdateExclusions": exclusions,
        })))
    }

    fn list_image_referrers(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let subject = body
            .get("subjectId")
            .cloned()
            .ok_or_else(|| invalid_parameter("Missing subjectId"))?;
        let digest = subject
            .get("imageDigest")
            .and_then(|v| v.as_str())
            .ok_or_else(|| invalid_parameter("subjectId.imageDigest is required"))?
            .to_string();
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        if !repo.images.contains_key(&digest) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ImageNotFoundException",
                format!("Subject image {digest} not found in repository '{name}'"),
            ));
        }
        Ok(AwsResponse::ok_json(json!({
            "imageReferrers": [],
        })))
    }

    fn update_image_storage_class(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let name = req_str(&body, "repositoryName")?.to_string();
        let image_id = body
            .get("imageId")
            .cloned()
            .ok_or_else(|| invalid_parameter("Missing imageId"))?;
        let target_class = req_str(&body, "targetStorageClass")?.to_string();
        if target_class != "STANDARD" && target_class != "ARCHIVE" {
            return Err(invalid_parameter(format!(
                "Invalid targetStorageClass '{target_class}'. Must be STANDARD or ARCHIVE."
            )));
        }
        let account = target_account_id(request, &body);
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| repository_not_found(&name))?;
        let repo = state
            .repositories
            .get(&name)
            .ok_or_else(|| repository_not_found(&name))?;
        if resolve_image_digest(repo, &image_id).is_none() {
            return Err(image_not_found(&name, &image_id));
        }
        Ok(AwsResponse::ok_json(json!({
            "registryId": repo.registry_id,
            "repositoryName": name,
            "imageId": image_id,
            "targetStorageClass": target_class,
        })))
    }
}

fn validate_account_setting_name(name: &str) -> Result<(), AwsServiceError> {
    // Smithy `@length(1, 64)` on AccountSettingName.
    if name.is_empty() || name.len() > 64 {
        return Err(invalid_parameter(format!(
            "Invalid parameter at 'name': '{name}' failed to satisfy constraint: \
             Member must have length between 1 and 64"
        )));
    }
    Ok(())
}

fn validate_pullthrough_prefix(prefix: &str) -> Result<(), AwsServiceError> {
    // Smithy @length(2, 30) on PullThroughCacheRuleRepositoryPrefix.
    if prefix.len() < 2 || prefix.len() > 30 {
        return Err(invalid_parameter(format!(
            "Invalid parameter at 'ecrRepositoryPrefix': '{prefix}' failed to satisfy constraint: \
             Member must have length between 2 and 30"
        )));
    }
    Ok(())
}

fn validate_template_prefix(prefix: &str) -> Result<(), AwsServiceError> {
    // Smithy `@length(2, 256)` on CreationTemplatePrefixString, plus
    // AWS's `ROOT` sentinel that's allowed on any-prefix templates.
    if prefix == "ROOT" {
        return Ok(());
    }
    if prefix.len() < 2 || prefix.len() > 256 {
        return Err(invalid_parameter(format!(
            "Invalid parameter at 'prefix': '{prefix}' failed to satisfy constraint: \
             Member must have length between 2 and 256"
        )));
    }
    Ok(())
}

fn validate_max_results(body: &Value) -> Result<(), AwsServiceError> {
    if let Some(n) = body.get("maxResults").and_then(|v| v.as_i64()) {
        if !(1..=1000).contains(&n) {
            return Err(invalid_parameter(format!(
                "Value '{n}' at 'maxResults' failed to satisfy constraint: \
                 Member must have value between 1 and 1000"
            )));
        }
    }
    Ok(())
}

fn pull_through_rule_json(registry_id: &str, r: &crate::state::PullThroughCacheRule) -> Value {
    pull_through_rule_json_with(registry_id, r, false)
}

fn pull_through_rule_json_with_updated(
    registry_id: &str,
    r: &crate::state::PullThroughCacheRule,
) -> Value {
    pull_through_rule_json_with(registry_id, r, true)
}

fn pull_through_rule_json_with(
    registry_id: &str,
    r: &crate::state::PullThroughCacheRule,
    include_updated: bool,
) -> Value {
    let mut out = json!({
        "ecrRepositoryPrefix": r.ecr_repository_prefix,
        "upstreamRegistryUrl": r.upstream_registry_url,
        "createdAt": r.created_at.timestamp(),
        "registryId": registry_id,
    });
    if include_updated {
        out["updatedAt"] = json!(r.updated_at.timestamp());
    }
    if let Some(v) = &r.credential_arn {
        out["credentialArn"] = json!(v);
    }
    if let Some(v) = &r.upstream_registry {
        out["upstreamRegistry"] = json!(v);
    }
    if let Some(v) = &r.custom_role_arn {
        out["customRoleArn"] = json!(v);
    }
    out
}

fn template_to_json(tpl: &crate::state::RepositoryCreationTemplate) -> Value {
    let mut out = json!({
        "prefix": tpl.prefix,
        "imageTagMutability": tpl.image_tag_mutability,
        "appliedFor": tpl.applied_for,
        "resourceTags": tpl.resource_tags,
        "createdAt": tpl.created_at.timestamp(),
        "updatedAt": tpl.updated_at.timestamp(),
    });
    if let Some(desc) = &tpl.description {
        out["description"] = json!(desc);
    }
    if let Some(arn) = &tpl.custom_role_arn {
        out["customRoleArn"] = json!(arn);
    }
    if let Some(p) = &tpl.repository_policy {
        out["repositoryPolicy"] = json!(p);
    }
    if let Some(p) = &tpl.lifecycle_policy {
        out["lifecyclePolicy"] = json!(p);
    }
    if let Some(enc) = &tpl.encryption_configuration {
        let mut e = Map::new();
        e.insert("encryptionType".to_string(), json!(enc.encryption_type));
        if let Some(k) = &enc.kms_key {
            e.insert("kmsKey".to_string(), json!(k));
        }
        out["encryptionConfiguration"] = Value::Object(e);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::validate_repository_name;

    #[track_caller]
    fn ok(n: &str) {
        validate_repository_name(n).unwrap_or_else(|_| panic!("expected '{n}' to validate"));
    }
    #[track_caller]
    fn bad(n: &str) {
        assert!(
            validate_repository_name(n).is_err(),
            "expected '{n}' to be rejected",
        );
    }

    #[test]
    fn accepts_valid_names() {
        ok("foo");
        ok("foo-bar");
        ok("foo.bar");
        ok("foo_bar");
        ok("foo/bar");
        ok("team/svc");
        ok("a/b/c");
        ok("foo123/bar-baz.qux_q");
    }

    #[test]
    fn rejects_invalid_names() {
        bad("");
        bad("a");
        bad("/foo");
        bad("foo/");
        bad("foo//bar");
        bad("-foo");
        bad("foo-");
        bad("foo--bar");
        bad("foo..bar");
        bad("foo__bar");
        bad("Foo");
        bad("foo bar");
        bad("foo!");
    }

    // ── Lifecycle policy evaluator ─────────────────────────────────
    use super::{evaluate_lifecycle_policy, wildcard_match};
    use crate::state::{Image, Repository};
    use chrono::Utc;
    use std::collections::BTreeMap;

    fn repo_with_images(entries: &[(&str, &[&str], i64)]) -> Repository {
        // entries: (digest, tags, minutes_ago_pushed)
        let mut r = Repository::new("test-repo", "arn".into(), "123", "http://localhost");
        for (digest, tags, minutes_ago) in entries {
            let pushed = Utc::now() - chrono::Duration::minutes(*minutes_ago);
            r.images.insert(
                (*digest).to_string(),
                Image {
                    image_digest: (*digest).to_string(),
                    image_manifest: String::new(),
                    image_manifest_media_type: String::new(),
                    artifact_media_type: None,
                    image_size_in_bytes: 0,
                    image_pushed_at: pushed,
                    last_recorded_pull_time: None,
                },
            );
            for t in *tags {
                r.image_tags.insert((*t).to_string(), (*digest).to_string());
            }
        }
        r
    }

    #[test]
    fn lifecycle_count_more_than_tagged() {
        // Five tagged images; rule says keep newest 2, prune 3.
        let r = repo_with_images(&[
            ("sha256:a", &["v1"], 50),
            ("sha256:b", &["v2"], 40),
            ("sha256:c", &["v3"], 30),
            ("sha256:d", &["v4"], 20),
            ("sha256:e", &["v5"], 10),
        ]);
        let policy = r#"{"rules":[{
            "rulePriority": 1,
            "selection": {"tagStatus":"tagged","countType":"imageCountMoreThan","countNumber":2}
        }]}"#;
        let prune = evaluate_lifecycle_policy(&r, policy);
        assert_eq!(prune.len(), 3);
        assert!(prune.contains(&"sha256:a".to_string()));
        assert!(prune.contains(&"sha256:b".to_string()));
        assert!(prune.contains(&"sha256:c".to_string()));
    }

    #[test]
    fn lifecycle_untagged_only() {
        let r = repo_with_images(&[("sha256:tagged", &["v1"], 60), ("sha256:untag", &[], 30)]);
        let policy = r#"{"rules":[{
            "rulePriority": 1,
            "selection": {"tagStatus":"untagged","countType":"imageCountMoreThan","countNumber":0}
        }]}"#;
        let prune = evaluate_lifecycle_policy(&r, policy);
        assert_eq!(prune, vec!["sha256:untag".to_string()]);
    }

    #[test]
    fn lifecycle_tag_prefix_list() {
        let r = repo_with_images(&[
            ("sha256:a", &["dev-1"], 60),
            ("sha256:b", &["dev-2"], 50),
            ("sha256:c", &["prod-1"], 40),
            ("sha256:d", &["prod-2"], 30),
        ]);
        // Keep newest 1 among dev-*, prune the rest; leave prod-* alone.
        let policy = r#"{"rules":[{
            "rulePriority": 1,
            "selection": {
                "tagStatus":"tagged",
                "tagPrefixList":["dev-"],
                "countType":"imageCountMoreThan",
                "countNumber":1
            }
        }]}"#;
        let prune = evaluate_lifecycle_policy(&r, policy);
        assert_eq!(prune, vec!["sha256:a".to_string()]);
    }

    #[test]
    fn lifecycle_tag_pattern_list_wildcards() {
        let r = repo_with_images(&[
            ("sha256:a", &["release-2024-01"], 60),
            ("sha256:b", &["release-2024-02"], 50),
            ("sha256:c", &["hotfix-2024-02"], 40),
        ]);
        // Match only `release-*`; prune all of them (countNumber=0).
        let policy = r#"{"rules":[{
            "rulePriority": 1,
            "selection": {
                "tagStatus":"tagged",
                "tagPatternList":["release-*"],
                "countType":"imageCountMoreThan",
                "countNumber":0
            }
        }]}"#;
        let prune = evaluate_lifecycle_policy(&r, policy);
        assert_eq!(prune.len(), 2);
        assert!(prune.contains(&"sha256:a".to_string()));
        assert!(prune.contains(&"sha256:b".to_string()));
        assert!(!prune.contains(&"sha256:c".to_string()));
    }

    #[test]
    fn lifecycle_since_image_pushed_days() {
        let r = repo_with_images(&[
            ("sha256:old", &["v1"], 60 * 24 * 10), // 10 days ago
            ("sha256:new", &["v2"], 60 * 24),      // 1 day ago
        ]);
        let policy = r#"{"rules":[{
            "rulePriority": 1,
            "selection": {
                "tagStatus":"any",
                "countType":"sinceImagePushed",
                "countUnit":"days",
                "countNumber":5
            }
        }]}"#;
        let prune = evaluate_lifecycle_policy(&r, policy);
        assert_eq!(prune, vec!["sha256:old".to_string()]);
    }

    #[test]
    fn lifecycle_rule_priority_order() {
        // Priority 1 keeps newest 2 tagged; priority 2 then prunes all
        // remaining tagged > 1 day old. Priority 1 runs first, then 2
        // sees fewer candidates.
        let r = repo_with_images(&[
            ("sha256:a", &["v1"], 60 * 24 * 10),
            ("sha256:b", &["v2"], 60 * 24 * 5),
            ("sha256:c", &["v3"], 60 * 24 * 2),
            ("sha256:d", &["v4"], 60 * 24),
        ]);
        let policy = r#"{"rules":[
            {"rulePriority": 2,
             "selection": {"tagStatus":"any","countType":"sinceImagePushed","countUnit":"days","countNumber":3}},
            {"rulePriority": 1,
             "selection": {"tagStatus":"tagged","countType":"imageCountMoreThan","countNumber":2}}
        ]}"#;
        let prune: std::collections::BTreeSet<String> =
            evaluate_lifecycle_policy(&r, policy).into_iter().collect();
        // Priority 1 (runs first): prunes a + b (keeping newest 2 = c, d).
        // Priority 2: c and d are both < 3 days -> survives.
        assert!(prune.contains("sha256:a"));
        assert!(prune.contains("sha256:b"));
    }

    #[test]
    fn wildcard_match_basics() {
        assert!(wildcard_match("release-*", "release-2024"));
        assert!(wildcard_match("*-stable", "v1-stable"));
        assert!(wildcard_match("a*b*c", "a-something-b-more-c"));
        assert!(wildcard_match("*", "anything"));
        assert!(wildcard_match("exact", "exact"));

        assert!(!wildcard_match("release-*", "rev-2024"));
        assert!(!wildcard_match("*-stable", "v1-beta"));
        assert!(!wildcard_match("exact", "exactly"));
        assert!(!wildcard_match("a*b*c", "a-b"));
    }

    // Suppress clippy::no_effect for BTreeMap usage anchor in this mod.
    #[allow(dead_code)]
    fn _anchor_btree() -> BTreeMap<String, String> {
        BTreeMap::new()
    }
}
