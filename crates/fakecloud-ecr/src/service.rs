use std::sync::Arc;

use async_trait::async_trait;
use http::StatusCode;
use serde_json::{json, Map, Value};
use tokio::sync::Mutex as AsyncMutex;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
use fakecloud_persistence::SnapshotStore;

use crate::state::{
    EcrSnapshot, EncryptionConfiguration, ImageScanningConfiguration, Repository, SharedEcrState,
    ECR_SNAPSHOT_SCHEMA_VERSION,
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
    )
}

pub struct EcrService {
    state: SharedEcrState,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    snapshot_lock: Arc<AsyncMutex<()>>,
}

impl EcrService {
    pub fn new(state: SharedEcrState) -> Self {
        Self {
            state,
            snapshot_store: None,
            snapshot_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    pub fn with_snapshot_store(mut self, store: Arc<dyn SnapshotStore>) -> Self {
        self.snapshot_store = Some(store);
        self
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
}
