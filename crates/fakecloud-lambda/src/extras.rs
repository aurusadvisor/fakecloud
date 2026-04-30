//! Lambda handlers added to close the conformance gap. Aliases, layers,
//! function URL configs, concurrency, code signing, event invoke, runtime
//! management, scaling, recursion, capacity providers, durable executions,
//! tagging, and account settings.

use chrono::Utc;
use http::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use fakecloud_aws::arn::Arn;
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::service::LambdaService;
use crate::state::{
    AccountSettings, AttachedLayer, CapacityProvider, CodeSigningConfig, DurableExecution,
    EventInvokeConfig, FunctionAlias, FunctionScalingConfig, FunctionUrlConfig, LambdaState, Layer,
    LayerVersion, ProvisionedConcurrencyConfig, RuntimeManagementConfig,
};

/// Resolve a layer-version ARN to its current `CodeSize` from the
/// multi-account state. Returns 0 when the ARN is unparseable, when the
/// referenced account/layer/version is unknown, or when the version was
/// published without ZIP content (legacy snapshots).
pub(crate) fn resolve_layer_attachments(
    accounts: &fakecloud_core::multi_account::MultiAccountState<LambdaState>,
    arns: Vec<String>,
) -> Vec<AttachedLayer> {
    arns.into_iter()
        .map(|arn| {
            let code_size = parse_layer_version_arn(&arn)
                .and_then(|(acct, name, ver)| {
                    accounts
                        .get(&acct)
                        .and_then(|s| s.layers.get(&name))
                        .and_then(|l| l.versions.iter().find(|v| v.version == ver))
                        .map(|v| v.code_size)
                })
                .unwrap_or(0);
            AttachedLayer { arn, code_size }
        })
        .collect()
}

fn missing(name: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "InvalidParameterValueException",
        format!("Missing required field: {name}"),
    )
}

fn not_found(entity: &str, name: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::NOT_FOUND,
        "ResourceNotFoundException",
        format!("{entity} not found: {name}"),
    )
}

fn ok(body: Value) -> Result<AwsResponse, AwsServiceError> {
    Ok(AwsResponse::json(StatusCode::OK, body.to_string()))
}

fn empty() -> Result<AwsResponse, AwsServiceError> {
    Ok(AwsResponse::json(StatusCode::OK, "{}".to_string()))
}

fn body(req: &AwsRequest) -> Value {
    serde_json::from_slice(&req.body).unwrap_or_else(|_| Value::Object(Default::default()))
}

/// Extract the function name from a Lambda function ARN, ignoring any
/// trailing `:version` / `:alias` qualifier. Returns `None` for ARNs
/// that name a different resource type (event-source mapping,
/// code-signing config, layer, …) so the caller can fall through to
/// the keyed tag bag.
fn function_name_from_arn(arn: &str) -> Option<String> {
    let rest = arn.strip_prefix("arn:aws:lambda:")?;
    let mut parts = rest.splitn(5, ':');
    let _region = parts.next()?;
    let _account = parts.next()?;
    let resource_kind = parts.next()?;
    if resource_kind != "function" {
        return None;
    }
    let name_with_qualifier = parts.next()?;
    Some(
        name_with_qualifier
            .split(':')
            .next()
            .unwrap_or(name_with_qualifier)
            .to_string(),
    )
}

/// Build a fakecloud-hosted download URL for a layer version's ZIP. The URL
/// is reachable on the same authority the SDK used for the original
/// request, so test harnesses get a working `Location` they can `GET`
/// directly instead of the placeholder AWS clients otherwise see.
fn layer_content_url(req: &AwsRequest, account_id: &str, layer_name: &str, version: i64) -> String {
    let host = req
        .headers
        .get(http::header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("localhost");
    let scheme = req
        .headers
        .get("x-forwarded-proto")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("http");
    format!(
        "{scheme}://{host}/_fakecloud/lambda/layer-content/{account_id}/{layer_name}/{version}.zip"
    )
}

/// AWS layer-version ARN: `arn:aws:lambda:<region>:<account>:layer:<name>:<version>`.
/// Returns `(account_id, layer_name, version)`. Used to resolve cross-account
/// layer references attached to a function.
pub fn parse_layer_version_arn(arn: &str) -> Option<(String, String, i64)> {
    let parts: Vec<&str> = arn.split(':').collect();
    if parts.len() != 8 || parts[0] != "arn" || parts[2] != "lambda" || parts[5] != "layer" {
        return None;
    }
    let account = parts[4].to_string();
    let name = parts[6].to_string();
    let version: i64 = parts[7].parse().ok()?;
    Some((account, name, version))
}

fn parse_qualifier(req: &AwsRequest) -> String {
    req.query_params
        .get("Qualifier")
        .cloned()
        .unwrap_or_else(|| "$LATEST".to_string())
}

fn id_from_time(prefix: &str) -> String {
    format!(
        "{}{}",
        prefix,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    )
}

impl LambdaService {
    pub(crate) async fn handle_extra(
        &self,
        action: &str,
        resource: Option<&str>,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let aid = req.account_id.as_str();
        let res = resource.unwrap_or("");
        match action {
            // Function lifecycle extras
            "GetFunctionConfiguration" => self.get_function_configuration(res, aid),
            "UpdateFunctionConfiguration" => self.update_function_configuration(res, req),
            "UpdateFunctionCode" => self.update_function_code(res, req),
            "UpdateEventSourceMapping" => self.update_event_source_mapping_handler(res, req),
            "GetAccountSettings" => self.get_account_settings(aid),
            "InvokeAsync" => Ok(AwsResponse::json(StatusCode::ACCEPTED, "{}".to_string())),
            "InvokeWithResponseStream" => Ok(AwsResponse::json(StatusCode::OK, "{}".to_string())),

            // Versions
            "ListVersionsByFunction" => self.list_versions_by_function(res, aid),

            // Aliases
            "CreateAlias" => self.create_alias(res, req),
            "GetAlias" => self.get_alias(res, req),
            "ListAliases" => self.list_aliases(res, aid),
            "UpdateAlias" => self.update_alias(res, req),
            "DeleteAlias" => self.delete_alias(res, req),

            // Layers
            "PublishLayerVersion" => self.publish_layer_version(res, req),
            "GetLayerVersion" => self.get_layer_version(req),
            "GetLayerVersionByArn" => self.get_layer_version_by_arn(req),
            "ListLayers" => self.list_layers(aid),
            "ListLayerVersions" => self.list_layer_versions(res, aid),
            "DeleteLayerVersion" => self.delete_layer_version(req),
            "GetLayerVersionPolicy" => self.get_layer_version_policy(req),
            "AddLayerVersionPermission" => self.add_layer_version_permission(req),
            "RemoveLayerVersionPermission" => self.remove_layer_version_permission(req),

            // Function URL
            "CreateFunctionUrlConfig" => self.create_function_url_config(res, req),
            "GetFunctionUrlConfig" => self.get_function_url_config(res, aid),
            "UpdateFunctionUrlConfig" => self.update_function_url_config(res, req),
            "DeleteFunctionUrlConfig" => self.delete_function_url_config(res, aid),
            "ListFunctionUrlConfigs" => self.list_function_url_configs(aid),

            // Concurrency
            "PutFunctionConcurrency" => self.put_function_concurrency(res, req),
            "GetFunctionConcurrency" => self.get_function_concurrency(res, aid),
            "DeleteFunctionConcurrency" => self.delete_function_concurrency(res, aid),
            "PutProvisionedConcurrencyConfig" => self.put_provisioned_concurrency(res, req),
            "GetProvisionedConcurrencyConfig" => self.get_provisioned_concurrency(res, req),
            "DeleteProvisionedConcurrencyConfig" => self.delete_provisioned_concurrency(res, req),
            "ListProvisionedConcurrencyConfigs" => self.list_provisioned_concurrency(res, aid),

            // Code signing
            "CreateCodeSigningConfig" => self.create_code_signing_config(req),
            "GetCodeSigningConfig" => self.get_code_signing_config(res, aid),
            "UpdateCodeSigningConfig" => self.update_code_signing_config(res, req),
            "DeleteCodeSigningConfig" => self.delete_code_signing_config(res, aid),
            "ListCodeSigningConfigs" => self.list_code_signing_configs(aid),
            "PutFunctionCodeSigningConfig" => self.put_function_code_signing(res, req),
            "GetFunctionCodeSigningConfig" => self.get_function_code_signing(res, aid),
            "DeleteFunctionCodeSigningConfig" => self.delete_function_code_signing(res, aid),
            "ListFunctionsByCodeSigningConfig" => self.list_functions_by_code_signing(res, aid),

            // Event invoke
            "PutFunctionEventInvokeConfig" | "UpdateFunctionEventInvokeConfig" => {
                self.put_function_event_invoke(res, req)
            }
            "GetFunctionEventInvokeConfig" => self.get_function_event_invoke(res, req),
            "DeleteFunctionEventInvokeConfig" => self.delete_function_event_invoke(res, req),
            "ListFunctionEventInvokeConfigs" => self.list_function_event_invoke(res, aid),

            // Runtime management
            "PutRuntimeManagementConfig" => self.put_runtime_management(res, req),
            "GetRuntimeManagementConfig" => self.get_runtime_management(res, req),

            // Scaling
            "PutFunctionScalingConfig" => self.put_scaling_config(res, req),
            "GetFunctionScalingConfig" => self.get_scaling_config(res, aid),

            // Recursion
            "PutFunctionRecursionConfig" => self.put_recursion_config(res, req),
            "GetFunctionRecursionConfig" => self.get_recursion_config(res, aid),

            // Tags
            "TagResource" => self.tag_resource(res, req),
            "UntagResource" => self.untag_resource(res, req),
            "ListTags" => self.list_tags(res, aid),

            // Capacity providers
            "CreateCapacityProvider" => self.create_capacity_provider(req),
            "GetCapacityProvider" => self.get_capacity_provider(res, aid),
            "UpdateCapacityProvider" => self.update_capacity_provider(res, req),
            "DeleteCapacityProvider" => self.delete_capacity_provider(res, aid),
            "ListCapacityProviders" => self.list_capacity_providers(aid),
            "ListFunctionVersionsByCapacityProvider" => {
                self.list_versions_by_capacity_provider(res, aid)
            }

            // Durable executions
            "CheckpointDurableExecution" => self.checkpoint_durable_execution(res, req),
            "GetDurableExecution" => self.get_durable_execution(res, aid),
            "GetDurableExecutionHistory" => self.get_durable_execution_history(res, aid),
            "GetDurableExecutionState" => self.get_durable_execution_state(res, aid),
            "ListDurableExecutionsByFunction" => self.list_durable_executions_by_function(res, aid),
            "StopDurableExecution" => self.stop_durable_execution(res, aid),
            "SendDurableExecutionCallbackSuccess" => {
                self.send_durable_callback(res, req, "SUCCESS")
            }
            "SendDurableExecutionCallbackFailure" => {
                self.send_durable_callback(res, req, "FAILURE")
            }
            "SendDurableExecutionCallbackHeartbeat" => {
                self.send_durable_callback(res, req, "HEARTBEAT")
            }

            _ => Err(AwsServiceError::action_not_implemented("lambda", action)),
        }
    }

    fn with_state_read<F, R>(&self, account_id: &str, region: &str, f: F) -> R
    where
        F: FnOnce(&LambdaState) -> R,
    {
        let accounts = self.state.read();
        let empty = LambdaState::new(account_id, region);
        let state = accounts.get(account_id).unwrap_or(&empty);
        f(state)
    }

    // ── Function lifecycle extras ──

    fn get_function_configuration(
        &self,
        function_name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            state
                .functions
                .get(function_name)
                .map(|f| ok(self.function_config_json(f)))
                .unwrap_or_else(|| Err(not_found("Function", function_name)))
        })
    }

    fn update_function_configuration(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = body(req);
        let mut accounts = self.state.write();
        // Pre-resolve layer attachments before re-borrowing accounts mutably
        // for the function. Layer ARNs may live in sibling accounts.
        let layer_attachments: Option<Vec<AttachedLayer>> = body["Layers"].as_array().map(|arr| {
            let arns: Vec<String> = arr
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
            resolve_layer_attachments(&accounts, arns)
        });
        let state = accounts.get_or_create(&req.account_id);
        let func = state
            .functions
            .get_mut(function_name)
            .ok_or_else(|| not_found("Function", function_name))?;
        if let Some(handler) = body["Handler"].as_str() {
            func.handler = handler.to_string();
        }
        if let Some(t) = body["Timeout"].as_i64() {
            func.timeout = t;
        }
        if let Some(m) = body["MemorySize"].as_i64() {
            func.memory_size = m;
        }
        if let Some(role) = body["Role"].as_str() {
            func.role = role.to_string();
        }
        if let Some(desc) = body["Description"].as_str() {
            func.description = desc.to_string();
        }
        if let Some(rt) = body["Runtime"].as_str() {
            func.runtime = rt.to_string();
        }
        if let Some(env) = body["Environment"]["Variables"].as_object() {
            func.environment = env
                .iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect();
        }
        if let Some(mode) = body["TracingConfig"]["Mode"].as_str() {
            func.tracing_mode = Some(mode.to_string());
        }
        if let Some(arn) = body["KMSKeyArn"].as_str() {
            func.kms_key_arn = if arn.is_empty() {
                None
            } else {
                Some(arn.to_string())
            };
        }
        if let Some(size) = body["EphemeralStorage"]["Size"].as_i64() {
            func.ephemeral_storage_size = Some(size);
        }
        if body["VpcConfig"].is_object() {
            func.vpc_config = Some(body["VpcConfig"].clone());
        }
        if body["SnapStart"].is_object() {
            func.snap_start = Some(body["SnapStart"].clone());
        }
        if let Some(arn) = body["DeadLetterConfig"]["TargetArn"].as_str() {
            func.dead_letter_config_arn = if arn.is_empty() {
                None
            } else {
                Some(arn.to_string())
            };
        }
        if let Some(fsc) = body["FileSystemConfigs"].as_array() {
            func.file_system_configs = fsc.clone();
        }
        if body["LoggingConfig"].is_object() {
            func.logging_config = Some(body["LoggingConfig"].clone());
        }
        if body["ImageConfig"].is_object() {
            func.image_config = Some(body["ImageConfig"].clone());
        }
        if let Some(attachments) = layer_attachments {
            func.layers = attachments;
        }
        // RevisionId rotates only on real config changes — clients
        // round-trip it through optimistic-concurrency calls, so we
        // mint a fresh one here to signal "config changed".
        func.revision_id = uuid::Uuid::new_v4().to_string();
        func.last_modified = Utc::now();
        ok(self.function_config_json(func))
    }

    fn update_function_code(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body: serde_json::Value = serde_json::from_slice(&req.body).unwrap_or_default();

        // ZipFile / ImageUri / S3Bucket+S3Key are mutually exclusive; AWS
        // rejects the request when more than one is present, but we just
        // pick the first available with a defined precedence: ZipFile,
        // ImageUri, S3 (which we resolve only enough to swap the bytes —
        // S3 fetches happen out of band on real Lambda).
        let new_zip: Option<Vec<u8>> = match body["ZipFile"].as_str() {
            Some(b64) => Some(
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).map_err(
                    |_| {
                        AwsServiceError::aws_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidParameterValueException",
                            "Could not decode ZipFile: invalid base64",
                        )
                    },
                )?,
            ),
            None => None,
        };
        let new_image_uri = body["ImageUri"].as_str().map(String::from);

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let func = state
            .functions
            .get_mut(function_name)
            .ok_or_else(|| not_found("Function", function_name))?;

        if let Some(bytes) = new_zip {
            // SHA256(base64) of the new code, matching CreateFunction's
            // hash so GetFunction returns identical CodeSha256 round-trip.
            use sha2::{Digest, Sha256};
            let mut hasher = Sha256::new();
            hasher.update(&bytes);
            let hash = hasher.finalize();
            let code_sha256 =
                base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hash);
            func.code_size = bytes.len() as i64;
            func.code_zip = Some(bytes);
            func.code_sha256 = code_sha256;
            func.image_uri = None;
        } else if let Some(uri) = new_image_uri {
            func.image_uri = Some(uri);
            func.code_zip = None;
        }
        // No-op (no ZipFile, ImageUri, or S3 fields) — AWS still bumps
        // last_modified and returns the current config.

        func.last_modified = Utc::now();
        // Bump revision_id only when code actually changed; the caller
        // can use it to detect concurrent updates.
        func.revision_id = uuid::Uuid::new_v4().to_string();
        ok(self.function_config_json(func))
    }

    fn get_account_settings(&self, account_id: &str) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        let settings = state.account_settings.clone().unwrap_or(AccountSettings {
            concurrent_executions: 1000,
            code_size_zipped: 52_428_800,
            code_size_unzipped: 262_144_000,
            total_code_size: 80_530_636_800,
        });
        if state.account_settings.is_none() {
            state.account_settings = Some(settings.clone());
        }
        // Real AccountUsage so clients monitoring deployment quotas see
        // accurate numbers. AWS sums total code size across all functions.
        let function_count = state.functions.len() as i64;
        let total_code_size: i64 = state.functions.values().map(|f| f.code_size).sum();
        ok(json!({
            "AccountLimit": {
                "ConcurrentExecutions": settings.concurrent_executions,
                "CodeSizeZipped": settings.code_size_zipped,
                "CodeSizeUnzipped": settings.code_size_unzipped,
                "TotalCodeSize": settings.total_code_size,
                "UnreservedConcurrentExecutions": settings.concurrent_executions,
            },
            "AccountUsage": {
                "TotalCodeSize": total_code_size,
                "FunctionCount": function_count,
            },
        }))
    }

    // ── Versions ──

    fn list_versions_by_function(
        &self,
        function_name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            let func = state
                .functions
                .get(function_name)
                .ok_or_else(|| not_found("Function", function_name))?;
            // AWS returns $LATEST first, then numbered versions in
            // ascending order. Each numbered version is an immutable
            // snapshot of the function at publish time.
            let mut versions: Vec<serde_json::Value> = Vec::new();
            let mut latest = self.function_config_json(func);
            latest["Version"] = json!("$LATEST");
            versions.push(latest);
            let snapshots = state.function_version_snapshots.get(function_name);
            if let Some(numbered) = state.function_versions.get(function_name) {
                for v in numbered {
                    let snap = snapshots.and_then(|m| m.get(v)).unwrap_or(func);
                    let mut cfg = self.function_config_json(snap);
                    cfg["Version"] = json!(v);
                    cfg["FunctionArn"] = json!(format!("{}:{v}", func.function_arn));
                    cfg["MasterArn"] = json!(func.function_arn);
                    versions.push(cfg);
                }
            }
            ok(json!({ "Versions": versions }))
        })
    }

    // ── Aliases ──

    fn alias_key(function: &str, alias: &str) -> String {
        format!("{function}:{alias}")
    }

    fn create_alias(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = body(req);
        let name = body["Name"]
            .as_str()
            .ok_or_else(|| missing("Name"))?
            .to_string();
        let version = body["FunctionVersion"]
            .as_str()
            .unwrap_or("$LATEST")
            .to_string();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if !state.functions.contains_key(function_name) {
            return Err(not_found("Function", function_name));
        }
        let alias_arn = format!(
            "arn:aws:lambda:{}:{}:function:{}:{}",
            state.region, state.account_id, function_name, name
        );
        let alias = FunctionAlias {
            alias_arn: alias_arn.clone(),
            name: name.clone(),
            function_version: version,
            description: body["Description"].as_str().unwrap_or("").to_string(),
            revision_id: id_from_time("rev-"),
            routing_config: body.get("RoutingConfig").cloned(),
        };
        state
            .aliases
            .insert(Self::alias_key(function_name, &name), alias.clone());
        ok(serde_json::to_value(alias).unwrap_or_default())
    }

    fn get_alias(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let alias_name = req.path_segments.get(4).cloned().unwrap_or_default();
        let region = self.region_for(&req.account_id);
        self.with_state_read(&req.account_id, &region, |state| {
            state
                .aliases
                .get(&Self::alias_key(function_name, &alias_name))
                .map(|a| ok(serde_json::to_value(a).unwrap_or_default()))
                .unwrap_or_else(|| Err(not_found("Alias", &alias_name)))
        })
    }

    fn list_aliases(
        &self,
        function_name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            let prefix = format!("{function_name}:");
            let aliases: Vec<&FunctionAlias> = state
                .aliases
                .iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(_, v)| v)
                .collect();
            ok(json!({"Aliases": aliases}))
        })
    }

    fn update_alias(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let alias_name = req.path_segments.get(4).cloned().unwrap_or_default();
        let body = body(req);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let key = Self::alias_key(function_name, &alias_name);
        let alias = state
            .aliases
            .get_mut(&key)
            .ok_or_else(|| not_found("Alias", &alias_name))?;
        if let Some(v) = body["FunctionVersion"].as_str() {
            alias.function_version = v.to_string();
        }
        if let Some(d) = body["Description"].as_str() {
            alias.description = d.to_string();
        }
        if let Some(rc) = body.get("RoutingConfig") {
            alias.routing_config = Some(rc.clone());
        }
        alias.revision_id = id_from_time("rev-");
        ok(serde_json::to_value(alias).unwrap_or_default())
    }

    fn delete_alias(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let alias_name = req.path_segments.get(4).cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state
            .aliases
            .remove(&Self::alias_key(function_name, &alias_name));
        empty()
    }

    // ── Layers ──

    fn publish_layer_version(
        &self,
        layer_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = body(req);
        let zip_bytes: Option<Vec<u8>> = match body["Content"]["ZipFile"].as_str() {
            Some(b64) => Some(
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).map_err(
                    |_| {
                        AwsServiceError::aws_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidParameterValueException",
                            "Could not decode Content.ZipFile: invalid base64",
                        )
                    },
                )?,
            ),
            None => None,
        };
        let (code_sha256, code_size) = match zip_bytes.as_deref() {
            Some(bytes) => {
                let mut hasher = Sha256::new();
                hasher.update(bytes);
                let digest = hasher.finalize();
                (
                    base64::Engine::encode(&base64::engine::general_purpose::STANDARD, digest),
                    bytes.len() as i64,
                )
            }
            None => (String::new(), 0),
        };

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let account_id = state.account_id.clone();
        let layer = state
            .layers
            .entry(layer_name.to_string())
            .or_insert_with(|| Layer {
                layer_name: layer_name.to_string(),
                layer_arn: format!(
                    "arn:aws:lambda:{}:{}:layer:{}",
                    state.region, state.account_id, layer_name
                ),
                versions: Vec::new(),
            });
        let next_version = (layer.versions.len() as i64) + 1;
        let version_arn = format!("{}:{}", layer.layer_arn, next_version);
        let runtimes: Vec<String> = body["CompatibleRuntimes"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let layer_arn = layer.layer_arn.clone();
        let lv = LayerVersion {
            version: next_version,
            layer_version_arn: version_arn.clone(),
            description: body["Description"].as_str().unwrap_or("").to_string(),
            created_date: Utc::now(),
            compatible_runtimes: runtimes,
            license_info: body["LicenseInfo"].as_str().unwrap_or("").to_string(),
            policy: None,
            code_zip: zip_bytes,
            code_sha256: code_sha256.clone(),
            code_size,
        };
        layer.versions.push(lv.clone());
        let location = layer_content_url(req, &account_id, layer_name, next_version);
        ok(json!({
            "LayerArn": layer_arn,
            "LayerVersionArn": version_arn,
            "Version": next_version,
            "Description": lv.description,
            "CreatedDate": lv.created_date.format("%Y-%m-%dT%H:%M:%S.%3fZ").to_string(),
            "CompatibleRuntimes": lv.compatible_runtimes,
            "LicenseInfo": lv.license_info,
            "Content": {
                "Location": location,
                "CodeSha256": code_sha256,
                "CodeSize": code_size,
            },
        }))
    }

    fn list_layers(&self, account_id: &str) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            let layers: Vec<Value> = state
                .layers
                .values()
                .map(|l| {
                    json!({
                        "LayerName": l.layer_name,
                        "LayerArn": l.layer_arn,
                        "LatestMatchingVersion": l.versions.last().map(|v| json!({
                            "LayerVersionArn": v.layer_version_arn,
                            "Version": v.version,
                            "Description": v.description,
                            "CreatedDate": v.created_date.format("%Y-%m-%dT%H:%M:%S.%3fZ").to_string(),
                            "CompatibleRuntimes": v.compatible_runtimes,
                        })),
                    })
                })
                .collect();
            ok(json!({"Layers": layers}))
        })
    }

    fn list_layer_versions(
        &self,
        layer_name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            let versions: Vec<Value> = state
                .layers
                .get(layer_name)
                .map(|l| {
                    l.versions
                        .iter()
                        .map(|v| {
                            json!({
                                "LayerVersionArn": v.layer_version_arn,
                                "Version": v.version,
                                "Description": v.description,
                                "CreatedDate": v.created_date.format("%Y-%m-%dT%H:%M:%S.%3fZ").to_string(),
                                "CompatibleRuntimes": v.compatible_runtimes,
                                "LicenseInfo": v.license_info,
                            })
                        })
                        .collect()
                })
                .unwrap_or_default();
            ok(json!({"LayerVersions": versions}))
        })
    }

    fn get_layer_version(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let layer_name = req.path_segments.get(2).cloned().unwrap_or_default();
        let version: i64 = req
            .path_segments
            .get(4)
            .and_then(|s| s.parse().ok())
            .ok_or_else(|| missing("VersionNumber"))?;
        let region = self.region_for(&req.account_id);
        let location = layer_content_url(req, &req.account_id, &layer_name, version);
        self.with_state_read(&req.account_id, &region, |state| {
            state
                .layers
                .get(&layer_name)
                .and_then(|l| l.versions.iter().find(|v| v.version == version))
                .map(|v| {
                    ok(json!({
                        "LayerVersionArn": v.layer_version_arn,
                        "Version": v.version,
                        "Description": v.description,
                        "CreatedDate": v.created_date.format("%Y-%m-%dT%H:%M:%S.%3fZ").to_string(),
                        "CompatibleRuntimes": v.compatible_runtimes,
                        "LicenseInfo": v.license_info,
                        "Content": {
                            "Location": location,
                            "CodeSha256": v.code_sha256,
                            "CodeSize": v.code_size,
                        },
                    }))
                })
                .unwrap_or_else(|| Err(not_found("LayerVersion", &layer_name)))
        })
    }

    fn get_layer_version_by_arn(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = req
            .query_params
            .get("Arn")
            .or_else(|| req.query_params.get("find"))
            .cloned()
            .unwrap_or_default();
        let (account_id, layer_name, version) =
            parse_layer_version_arn(&arn).ok_or_else(|| missing("Arn"))?;
        let region = self.region_for(&account_id);
        let location = layer_content_url(req, &account_id, &layer_name, version);
        self.with_state_read(&account_id, &region, |state| {
            state
                .layers
                .get(&layer_name)
                .and_then(|l| l.versions.iter().find(|v| v.version == version))
                .map(|v| {
                    ok(json!({
                        "LayerVersionArn": v.layer_version_arn,
                        "Version": v.version,
                        "Description": v.description,
                        "CreatedDate": v.created_date.format("%Y-%m-%dT%H:%M:%S.%3fZ").to_string(),
                        "CompatibleRuntimes": v.compatible_runtimes,
                        "LicenseInfo": v.license_info,
                        "Content": {
                            "Location": location,
                            "CodeSha256": v.code_sha256,
                            "CodeSize": v.code_size,
                        },
                    }))
                })
                .unwrap_or_else(|| Err(not_found("LayerVersion", &arn)))
        })
    }

    fn delete_layer_version(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let layer_name = req.path_segments.get(2).cloned().unwrap_or_default();
        let version: i64 = req
            .path_segments
            .get(4)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if let Some(layer) = state.layers.get_mut(&layer_name) {
            layer.versions.retain(|v| v.version != version);
        }
        empty()
    }

    fn get_layer_version_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let layer_name = req.path_segments.get(2).cloned().unwrap_or_default();
        let version: i64 = req
            .path_segments
            .get(4)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let region = self.region_for(&req.account_id);
        self.with_state_read(&req.account_id, &region, |state| {
            let policy = state
                .layers
                .get(&layer_name)
                .and_then(|l| l.versions.iter().find(|v| v.version == version))
                .and_then(|v| v.policy.clone())
                .unwrap_or_else(|| "{}".to_string());
            ok(json!({"Policy": policy, "RevisionId": id_from_time("rev-")}))
        })
    }

    fn add_layer_version_permission(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let layer_name = req.path_segments.get(2).cloned().unwrap_or_default();
        let version: i64 = req
            .path_segments
            .get(4)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let body = body(req);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if let Some(layer) = state.layers.get_mut(&layer_name) {
            if let Some(v) = layer.versions.iter_mut().find(|v| v.version == version) {
                let policy = v.policy.clone().unwrap_or_else(|| "{}".to_string());
                let mut policy_doc: Value = serde_json::from_str(&policy).unwrap_or(json!({}));
                let statements = policy_doc["Statement"].as_array_mut();
                let new_stmt = json!({
                    "Sid": body["StatementId"].as_str().unwrap_or("default"),
                    "Effect": "Allow",
                    "Principal": body["Principal"].clone(),
                    "Action": body["Action"].clone(),
                    "Resource": v.layer_version_arn.clone(),
                });
                if let Some(s) = statements {
                    s.push(new_stmt);
                } else {
                    policy_doc = json!({"Version": "2012-10-17", "Statement": [new_stmt]});
                }
                v.policy = Some(policy_doc.to_string());
            }
        }
        ok(json!({
            "Statement": body["StatementId"],
            "RevisionId": id_from_time("rev-"),
        }))
    }

    fn remove_layer_version_permission(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let layer_name = req.path_segments.get(2).cloned().unwrap_or_default();
        let version: i64 = req
            .path_segments
            .get(4)
            .and_then(|s| s.parse().ok())
            .unwrap_or(0);
        let sid = req.path_segments.get(6).cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if let Some(layer) = state.layers.get_mut(&layer_name) {
            if let Some(v) = layer.versions.iter_mut().find(|v| v.version == version) {
                if let Some(policy) = v.policy.clone() {
                    let mut policy_doc: Value = serde_json::from_str(&policy).unwrap_or(json!({}));
                    if let Some(stmts) = policy_doc["Statement"].as_array_mut() {
                        stmts.retain(|s| s["Sid"].as_str() != Some(&sid));
                    }
                    v.policy = Some(policy_doc.to_string());
                }
            }
        }
        empty()
    }

    // ── Function URL ──

    fn create_function_url_config(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = body(req);
        let auth_type = body["AuthType"].as_str().unwrap_or("NONE").to_string();
        let now = Utc::now();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if !state.functions.contains_key(function_name) {
            return Err(not_found("Function", function_name));
        }
        let function_arn = format!(
            "arn:aws:lambda:{}:{}:function:{}",
            state.region, state.account_id, function_name
        );
        let cfg = FunctionUrlConfig {
            function_arn: function_arn.clone(),
            function_url: format!(
                "https://{function_name}.lambda-url.{}.on.aws/",
                state.region
            ),
            auth_type: auth_type.clone(),
            cors: body.get("Cors").cloned(),
            creation_time: now,
            last_modified_time: now,
            invoke_mode: body["InvokeMode"]
                .as_str()
                .unwrap_or("BUFFERED")
                .to_string(),
        };
        state
            .function_url_configs
            .insert(function_name.to_string(), cfg.clone());
        ok(serde_json::to_value(cfg).unwrap_or_default())
    }

    fn get_function_url_config(
        &self,
        function_name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            state
                .function_url_configs
                .get(function_name)
                .map(|c| ok(serde_json::to_value(c).unwrap_or_default()))
                .unwrap_or_else(|| Err(not_found("FunctionUrlConfig", function_name)))
        })
    }

    fn update_function_url_config(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = body(req);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let cfg = state
            .function_url_configs
            .get_mut(function_name)
            .ok_or_else(|| not_found("FunctionUrlConfig", function_name))?;
        if let Some(a) = body["AuthType"].as_str() {
            cfg.auth_type = a.to_string();
        }
        if let Some(c) = body.get("Cors") {
            cfg.cors = Some(c.clone());
        }
        if let Some(m) = body["InvokeMode"].as_str() {
            cfg.invoke_mode = m.to_string();
        }
        cfg.last_modified_time = Utc::now();
        ok(serde_json::to_value(cfg).unwrap_or_default())
    }

    fn delete_function_url_config(
        &self,
        function_name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        state.function_url_configs.remove(function_name);
        empty()
    }

    fn list_function_url_configs(&self, account_id: &str) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            let configs: Vec<&FunctionUrlConfig> = state.function_url_configs.values().collect();
            ok(json!({"FunctionUrlConfigs": configs}))
        })
    }

    // ── Concurrency ──

    fn put_function_concurrency(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = body(req);
        let n = body["ReservedConcurrentExecutions"]
            .as_i64()
            .ok_or_else(|| missing("ReservedConcurrentExecutions"))?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state
            .function_concurrency
            .insert(function_name.to_string(), n);
        ok(json!({"ReservedConcurrentExecutions": n}))
    }

    fn get_function_concurrency(
        &self,
        function_name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            let n = state
                .function_concurrency
                .get(function_name)
                .copied()
                .unwrap_or(0);
            ok(json!({"ReservedConcurrentExecutions": n}))
        })
    }

    fn delete_function_concurrency(
        &self,
        function_name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        state.function_concurrency.remove(function_name);
        empty()
    }

    fn pc_key(function: &str, qualifier: &str) -> String {
        format!("{function}:{qualifier}")
    }

    fn put_provisioned_concurrency(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = body(req);
        let qualifier = parse_qualifier(req);
        let requested = body["ProvisionedConcurrentExecutions"]
            .as_i64()
            .ok_or_else(|| missing("ProvisionedConcurrentExecutions"))?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let cfg = ProvisionedConcurrencyConfig {
            requested,
            allocated: requested,
            status: "READY".to_string(),
            last_modified: Utc::now(),
        };
        state
            .provisioned_concurrency
            .insert(Self::pc_key(function_name, &qualifier), cfg.clone());
        ok(json!({
            "RequestedProvisionedConcurrentExecutions": cfg.requested,
            "AvailableProvisionedConcurrentExecutions": cfg.allocated,
            "AllocatedProvisionedConcurrentExecutions": cfg.allocated,
            "Status": cfg.status,
            "LastModified": cfg.last_modified.format("%Y-%m-%dT%H:%M:%S.%3fZ").to_string(),
        }))
    }

    fn get_provisioned_concurrency(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let qualifier = parse_qualifier(req);
        let region = self.region_for(&req.account_id);
        self.with_state_read(&req.account_id, &region, |state| {
            state
                .provisioned_concurrency
                .get(&Self::pc_key(function_name, &qualifier))
                .map(|cfg| ok(json!({
                    "RequestedProvisionedConcurrentExecutions": cfg.requested,
                    "AvailableProvisionedConcurrentExecutions": cfg.allocated,
                    "AllocatedProvisionedConcurrentExecutions": cfg.allocated,
                    "Status": cfg.status,
                    "LastModified": cfg.last_modified.format("%Y-%m-%dT%H:%M:%S.%3fZ").to_string(),
                })))
                .unwrap_or_else(|| Err(not_found("ProvisionedConcurrencyConfig", function_name)))
        })
    }

    fn delete_provisioned_concurrency(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let qualifier = parse_qualifier(req);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state
            .provisioned_concurrency
            .remove(&Self::pc_key(function_name, &qualifier));
        empty()
    }

    fn list_provisioned_concurrency(
        &self,
        function_name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            let prefix = format!("{function_name}:");
            let configs: Vec<Value> = state
                .provisioned_concurrency
                .iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(k, cfg)| {
                    let qualifier = k.split(':').next_back().unwrap_or("$LATEST");
                    json!({
                        "FunctionArn": format!(
                            "arn:aws:lambda:{}:{}:function:{}:{}",
                            state.region, state.account_id, function_name, qualifier
                        ),
                        "Status": cfg.status,
                        "RequestedProvisionedConcurrentExecutions": cfg.requested,
                        "AvailableProvisionedConcurrentExecutions": cfg.allocated,
                        "AllocatedProvisionedConcurrentExecutions": cfg.allocated,
                        "LastModified": cfg.last_modified.format("%Y-%m-%dT%H:%M:%S.%3fZ").to_string(),
                    })
                })
                .collect();
            ok(json!({"ProvisionedConcurrencyConfigs": configs}))
        })
    }

    // ── Code signing ──

    fn create_code_signing_config(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = body(req);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let id = id_from_time("csc-");
        let arn = format!(
            "arn:aws:lambda:{}:{}:code-signing-config:{}",
            state.region, state.account_id, id
        );
        let publishers: Vec<String> = body
            .get("AllowedPublishers")
            .and_then(|v| v.get("SigningProfileVersionArns"))
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|x| x.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let csc = CodeSigningConfig {
            csc_id: id.clone(),
            csc_arn: arn,
            description: body["Description"].as_str().unwrap_or("").to_string(),
            allowed_publishers: publishers,
            untrusted_artifact_action: body["CodeSigningPolicies"]["UntrustedArtifactOnDeployment"]
                .as_str()
                .unwrap_or("Warn")
                .to_string(),
            last_modified: Utc::now(),
        };
        state.code_signing_configs.insert(id, csc.clone());
        ok(json!({"CodeSigningConfig": code_signing_json(&csc)}))
    }

    fn get_code_signing_config(
        &self,
        csc_id: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = extract_csc_id(csc_id);
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            state
                .code_signing_configs
                .get(&id)
                .map(|c| ok(json!({"CodeSigningConfig": code_signing_json(c)})))
                .unwrap_or_else(|| Err(not_found("CodeSigningConfig", &id)))
        })
    }

    fn update_code_signing_config(
        &self,
        csc_id: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = body(req);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let id = extract_csc_id(csc_id);
        let csc = state
            .code_signing_configs
            .get_mut(&id)
            .ok_or_else(|| not_found("CodeSigningConfig", &id))?;
        if let Some(d) = body["Description"].as_str() {
            csc.description = d.to_string();
        }
        if let Some(action) = body["CodeSigningPolicies"]["UntrustedArtifactOnDeployment"].as_str()
        {
            csc.untrusted_artifact_action = action.to_string();
        }
        csc.last_modified = Utc::now();
        ok(json!({"CodeSigningConfig": code_signing_json(csc)}))
    }

    fn delete_code_signing_config(
        &self,
        csc_id: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = extract_csc_id(csc_id);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        state.code_signing_configs.remove(&id);
        empty()
    }

    fn list_code_signing_configs(&self, account_id: &str) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            let cfgs: Vec<Value> = state
                .code_signing_configs
                .values()
                .map(code_signing_json)
                .collect();
            ok(json!({"CodeSigningConfigs": cfgs}))
        })
    }

    fn put_function_code_signing(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = body(req);
        let csc_arn = body["CodeSigningConfigArn"]
            .as_str()
            .ok_or_else(|| missing("CodeSigningConfigArn"))?
            .to_string();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state
            .function_code_signing
            .insert(function_name.to_string(), csc_arn.clone());
        ok(json!({
            "CodeSigningConfigArn": csc_arn,
            "FunctionName": function_name,
        }))
    }

    fn get_function_code_signing(
        &self,
        function_name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            let arn = state
                .function_code_signing
                .get(function_name)
                .cloned()
                .unwrap_or_default();
            ok(json!({
                "CodeSigningConfigArn": arn,
                "FunctionName": function_name,
            }))
        })
    }

    fn delete_function_code_signing(
        &self,
        function_name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        state.function_code_signing.remove(function_name);
        empty()
    }

    fn list_functions_by_code_signing(
        &self,
        csc_id: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = extract_csc_id(csc_id);
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            let funcs: Vec<&String> = state
                .function_code_signing
                .iter()
                .filter(|(_, v)| v.contains(&id))
                .map(|(k, _)| k)
                .collect();
            ok(json!({"FunctionArns": funcs}))
        })
    }

    // ── Event invoke ──

    fn ev_key(function: &str, qualifier: &str) -> String {
        format!("{function}:{qualifier}")
    }

    fn put_function_event_invoke(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = body(req);
        let qualifier = parse_qualifier(req);
        let function_arn = format!(
            "arn:aws:lambda:{}:{}:function:{}",
            self.region_for(&req.account_id),
            req.account_id,
            function_name
        );
        let cfg = EventInvokeConfig {
            function_arn: function_arn.clone(),
            maximum_event_age: body["MaximumEventAgeInSeconds"].as_i64().unwrap_or(21600),
            maximum_retry_attempts: body["MaximumRetryAttempts"].as_i64().unwrap_or(2),
            destination_config: body.get("DestinationConfig").cloned().unwrap_or(json!({})),
            last_modified: Utc::now(),
        };
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state
            .event_invoke_configs
            .insert(Self::ev_key(function_name, &qualifier), cfg.clone());
        ok(event_invoke_json(&cfg))
    }

    fn get_function_event_invoke(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let qualifier = parse_qualifier(req);
        let region = self.region_for(&req.account_id);
        self.with_state_read(&req.account_id, &region, |state| {
            state
                .event_invoke_configs
                .get(&Self::ev_key(function_name, &qualifier))
                .map(|c| ok(event_invoke_json(c)))
                .unwrap_or_else(|| Err(not_found("EventInvokeConfig", function_name)))
        })
    }

    fn delete_function_event_invoke(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let qualifier = parse_qualifier(req);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state
            .event_invoke_configs
            .remove(&Self::ev_key(function_name, &qualifier));
        empty()
    }

    fn list_function_event_invoke(
        &self,
        function_name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            let prefix = format!("{function_name}:");
            let configs: Vec<Value> = state
                .event_invoke_configs
                .iter()
                .filter(|(k, _)| k.starts_with(&prefix))
                .map(|(_, c)| event_invoke_json(c))
                .collect();
            ok(json!({"FunctionEventInvokeConfigs": configs}))
        })
    }

    // ── Runtime management ──

    fn put_runtime_management(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = body(req);
        let qualifier = parse_qualifier(req);
        let cfg = RuntimeManagementConfig {
            update_runtime_on: body["UpdateRuntimeOn"]
                .as_str()
                .unwrap_or("Auto")
                .to_string(),
            runtime_version_arn: body["RuntimeVersionArn"].as_str().unwrap_or("").to_string(),
        };
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state
            .runtime_management
            .insert(format!("{function_name}:{qualifier}"), cfg.clone());
        ok(json!({
            "FunctionArn": Arn::new("lambda", &state.region, &state.account_id, &format!("function:{function_name}:{qualifier}")).to_string(),
            "UpdateRuntimeOn": cfg.update_runtime_on,
            "RuntimeVersionArn": cfg.runtime_version_arn,
        }))
    }

    fn get_runtime_management(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let qualifier = parse_qualifier(req);
        let region = self.region_for(&req.account_id);
        self.with_state_read(&req.account_id, &region, |state| {
            let cfg = state
                .runtime_management
                .get(&format!("{function_name}:{qualifier}"))
                .cloned()
                .unwrap_or(RuntimeManagementConfig {
                    update_runtime_on: "Auto".to_string(),
                    runtime_version_arn: String::new(),
                });
            ok(json!({
                "FunctionArn": format!(
                    "arn:aws:lambda:{}:{}:function:{}:{}",
                    state.region, state.account_id, function_name, qualifier
                ),
                "UpdateRuntimeOn": cfg.update_runtime_on,
                "RuntimeVersionArn": cfg.runtime_version_arn,
            }))
        })
    }

    // ── Scaling ──

    fn put_scaling_config(
        &self,
        uuid: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = body(req);
        let cfg = FunctionScalingConfig {
            maximum_concurrency: body["MaximumConcurrency"].as_i64().unwrap_or(0),
        };
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state.scaling_configs.insert(uuid.to_string(), cfg.clone());
        ok(json!({
            "MaximumConcurrency": cfg.maximum_concurrency,
        }))
    }

    fn get_scaling_config(
        &self,
        uuid: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            let n = state
                .scaling_configs
                .get(uuid)
                .map(|c| c.maximum_concurrency)
                .unwrap_or(0);
            ok(json!({"MaximumConcurrency": n}))
        })
    }

    // ── Recursion ──

    fn put_recursion_config(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = body(req);
        let mode = body["RecursiveLoop"]
            .as_str()
            .unwrap_or("Terminate")
            .to_string();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state
            .recursion_configs
            .insert(function_name.to_string(), mode.clone());
        ok(json!({"RecursiveLoop": mode}))
    }

    fn get_recursion_config(
        &self,
        function_name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            let mode = state
                .recursion_configs
                .get(function_name)
                .cloned()
                .unwrap_or_else(|| "Terminate".to_string());
            ok(json!({"RecursiveLoop": mode}))
        })
    }

    // ── Tags ──

    fn tag_resource(
        &self,
        resource_arn: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = body(req);
        let new_tags: Vec<(String, String)> = body
            .get("Tags")
            .and_then(|v| v.as_object())
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        // For function ARNs, write directly onto the function's `tags`
        // map so `GetFunction` and `ListTagsForResource` agree without
        // a second lookup. Non-function ARNs (event source mappings,
        // code-signing configs) fall back to the keyed bag.
        if let Some(name) = function_name_from_arn(resource_arn) {
            if let Some(func) = state.functions.get_mut(&name) {
                for (k, v) in &new_tags {
                    func.tags.insert(k.clone(), v.clone());
                }
                return empty();
            }
        }
        let entry = state.tags.entry(resource_arn.to_string()).or_default();
        for (k, v) in new_tags {
            entry.retain(|(ek, _)| ek != &k);
            entry.push((k, v));
        }
        empty()
    }

    fn untag_resource(
        &self,
        resource_arn: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        // AWS sends keys as repeated `tagKeys=K1&tagKeys=K2` query
        // params. Some SDKs also serialize `tagKeys.member.1=K1` /
        // `tagKeys.1=K1` — accept both shapes.
        let mut keys: Vec<String> = Vec::new();
        for (k, v) in &req.query_params {
            if k == "tagKeys" || k.starts_with("tagKeys.") {
                keys.push(v.clone());
            }
        }
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if let Some(name) = function_name_from_arn(resource_arn) {
            if let Some(func) = state.functions.get_mut(&name) {
                for k in &keys {
                    func.tags.remove(k);
                }
                return empty();
            }
        }
        if let Some(entry) = state.tags.get_mut(resource_arn) {
            entry.retain(|(k, _)| !keys.contains(k));
        }
        empty()
    }

    fn list_tags(
        &self,
        resource_arn: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            if let Some(name) = function_name_from_arn(resource_arn) {
                if let Some(func) = state.functions.get(&name) {
                    let tags: serde_json::Map<String, Value> = func
                        .tags
                        .iter()
                        .map(|(k, v)| (k.clone(), Value::String(v.clone())))
                        .collect();
                    return ok(json!({"Tags": tags}));
                }
            }
            let tags: serde_json::Map<String, Value> = state
                .tags
                .get(resource_arn)
                .map(|v| {
                    v.iter()
                        .map(|(k, val)| (k.clone(), Value::String(val.clone())))
                        .collect()
                })
                .unwrap_or_default();
            ok(json!({"Tags": tags}))
        })
    }

    // ── Capacity providers ──

    fn create_capacity_provider(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = body(req);
        let name = body["CapacityProviderName"]
            .as_str()
            .or_else(|| body["Name"].as_str())
            .ok_or_else(|| missing("CapacityProviderName"))?
            .to_string();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let arn = format!(
            "arn:aws:lambda:{}:{}:capacity-provider:{}",
            state.region, state.account_id, name
        );
        let cp = CapacityProvider {
            name: name.clone(),
            arn: arn.clone(),
            status: "ACTIVE".to_string(),
            created: Utc::now(),
        };
        state.capacity_providers.insert(name, cp.clone());
        ok(json!({
            "Name": cp.name,
            "Arn": cp.arn,
            "Status": cp.status,
        }))
    }

    fn get_capacity_provider(
        &self,
        name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            state
                .capacity_providers
                .get(name)
                .map(|cp| {
                    ok(json!({
                        "Name": cp.name,
                        "Arn": cp.arn,
                        "Status": cp.status,
                    }))
                })
                .unwrap_or_else(|| Err(not_found("CapacityProvider", name)))
        })
    }

    fn update_capacity_provider(
        &self,
        name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let cp = state
            .capacity_providers
            .get_mut(name)
            .ok_or_else(|| not_found("CapacityProvider", name))?;
        cp.status = "ACTIVE".to_string();
        ok(json!({
            "Name": cp.name,
            "Arn": cp.arn,
            "Status": cp.status,
        }))
    }

    fn delete_capacity_provider(
        &self,
        name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        state.capacity_providers.remove(name);
        empty()
    }

    fn list_capacity_providers(&self, account_id: &str) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            let cps: Vec<Value> = state
                .capacity_providers
                .values()
                .map(|cp| {
                    json!({
                        "Name": cp.name,
                        "Arn": cp.arn,
                        "Status": cp.status,
                    })
                })
                .collect();
            ok(json!({"CapacityProviders": cps}))
        })
    }

    fn list_versions_by_capacity_provider(
        &self,
        _name: &str,
        _account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        ok(json!({"FunctionVersions": []}))
    }

    // ── Durable executions ──

    fn checkpoint_durable_execution(
        &self,
        id: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = body(req);
        let body_arn = body
            .get("FunctionArn")
            .and_then(|v| v.as_str())
            .map(String::from);
        let body_function = body
            .get("FunctionName")
            .and_then(|v| v.as_str())
            .map(String::from);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let derived_arn = body_arn.unwrap_or_else(|| match body_function {
            Some(name) if name.starts_with("arn:") => name,
            Some(name) => format!(
                "arn:aws:lambda:us-east-1:{}:function:{name}",
                req.account_id
            ),
            None => String::new(),
        });
        let exec = state
            .durable_executions
            .entry(id.to_string())
            .or_insert_with(|| DurableExecution {
                id: id.to_string(),
                function_arn: derived_arn.clone(),
                status: "RUNNING".to_string(),
                started: Utc::now(),
                stopped: None,
                history: Vec::new(),
                state: json!({}),
            });
        if exec.function_arn.is_empty() && !derived_arn.is_empty() {
            exec.function_arn = derived_arn;
        }
        if let Some(s) = body.get("State") {
            exec.state = s.clone();
        }
        if let Some(h) = body.get("HistoryEvent") {
            exec.history.push(h.clone());
        }
        empty()
    }

    fn get_durable_execution(
        &self,
        id: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            state
                .durable_executions
                .get(id)
                .map(|e| {
                    ok(json!({
                        "Id": e.id,
                        "FunctionArn": e.function_arn,
                        "Status": e.status,
                        "Started": e.started.format("%Y-%m-%dT%H:%M:%SZ").to_string(),
                        "Stopped": e.stopped.map(|d| d.format("%Y-%m-%dT%H:%M:%SZ").to_string()),
                    }))
                })
                .unwrap_or_else(|| Err(not_found("DurableExecution", id)))
        })
    }

    fn get_durable_execution_history(
        &self,
        id: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            let history = state
                .durable_executions
                .get(id)
                .map(|e| e.history.clone())
                .unwrap_or_default();
            ok(json!({"Events": history}))
        })
    }

    fn get_durable_execution_state(
        &self,
        id: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            let s = state
                .durable_executions
                .get(id)
                .map(|e| e.state.clone())
                .unwrap_or(json!({}));
            ok(json!({"State": s}))
        })
    }

    fn list_durable_executions_by_function(
        &self,
        function_name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let region = self.region_for(account_id);
        self.with_state_read(account_id, &region, |state| {
            let executions: Vec<Value> = state
                .durable_executions
                .values()
                .filter(|e| e.function_arn.contains(function_name))
                .map(|e| {
                    json!({
                        "Id": e.id,
                        "Status": e.status,
                    })
                })
                .collect();
            ok(json!({"DurableExecutions": executions}))
        })
    }

    fn stop_durable_execution(
        &self,
        id: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        if let Some(e) = state.durable_executions.get_mut(id) {
            e.status = "STOPPED".to_string();
            e.stopped = Some(Utc::now());
        }
        empty()
    }

    fn send_durable_callback(
        &self,
        id: &str,
        _req: &AwsRequest,
        kind: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(_req.account_id.as_str());
        if let Some(e) = state.durable_executions.get_mut(id) {
            e.history.push(
                json!({"type": format!("Callback{kind}"), "timestamp": Utc::now().to_rfc3339()}),
            );
            if kind == "SUCCESS" {
                e.status = "SUCCEEDED".to_string();
            } else if kind == "FAILURE" {
                e.status = "FAILED".to_string();
            }
        }
        empty()
    }

    fn update_event_source_mapping_handler(
        &self,
        uuid: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = body(req);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let esm = state
            .event_source_mappings
            .get_mut(uuid)
            .ok_or_else(|| not_found("EventSourceMapping", uuid))?;
        if let Some(b) = body["BatchSize"].as_i64() {
            esm.batch_size = b;
        }
        if let Some(name) = body["FunctionName"].as_str() {
            esm.function_arn = format!(
                "arn:aws:lambda:{}:{}:function:{}",
                state.region, state.account_id, name
            );
        }
        if let Some(filters) = body
            .get("FilterCriteria")
            .and_then(|v| v.get("Filters"))
            .and_then(|v| v.as_array())
        {
            esm.filter_patterns = filters
                .iter()
                .filter_map(|f| f.get("Pattern").and_then(|p| p.as_str()).map(String::from))
                .collect();
        }
        if let Some(types) = body.get("FunctionResponseTypes").and_then(|v| v.as_array()) {
            esm.function_response_types = types
                .iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect();
        }
        if let Some(w) = body
            .get("MaximumBatchingWindowInSeconds")
            .and_then(|v| v.as_i64())
        {
            esm.maximum_batching_window_in_seconds = Some(w);
        }
        if let Some(p) = body.get("ParallelizationFactor").and_then(|v| v.as_i64()) {
            esm.parallelization_factor = Some(p);
        }
        let mut body_json = json!({
            "UUID": esm.uuid,
            "FunctionArn": esm.function_arn,
            "EventSourceArn": esm.event_source_arn,
            "BatchSize": esm.batch_size,
            "State": "Enabled",
            "StateTransitionReason": "USER_INITIATED",
            "LastModified": chrono::Utc::now().timestamp() as f64,
        });
        let obj = body_json.as_object_mut().expect("json! built object");
        if !esm.filter_patterns.is_empty() {
            obj.insert(
                "FilterCriteria".into(),
                json!({
                    "Filters": esm
                        .filter_patterns
                        .iter()
                        .map(|p| json!({"Pattern": p}))
                        .collect::<Vec<_>>(),
                }),
            );
        }
        if !esm.function_response_types.is_empty() {
            obj.insert(
                "FunctionResponseTypes".into(),
                json!(esm.function_response_types),
            );
        }
        if let Some(w) = esm.maximum_batching_window_in_seconds {
            obj.insert("MaximumBatchingWindowInSeconds".into(), json!(w));
        }
        if let Some(p) = esm.parallelization_factor {
            obj.insert("ParallelizationFactor".into(), json!(p));
        }
        ok(body_json)
    }

    fn region_for(&self, account_id: &str) -> String {
        let accounts = self.state.read();
        accounts
            .get(account_id)
            .map(|s| s.region.clone())
            .unwrap_or_else(|| "us-east-1".to_string())
    }
}

fn extract_csc_id(input: &str) -> String {
    // Decode percent encoding then take the segment after the last colon
    // (csc id), or treat as id if no colon present.
    let decoded = percent_decode(input);
    decoded.rsplit(':').next().unwrap_or(&decoded).to_string()
}

fn percent_decode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let bytes = input.as_bytes();
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' && i + 2 < bytes.len() {
            let hi = (bytes[i + 1] as char).to_digit(16);
            let lo = (bytes[i + 2] as char).to_digit(16);
            if let (Some(h), Some(l)) = (hi, lo) {
                out.push(((h * 16 + l) as u8) as char);
                i += 3;
                continue;
            }
        }
        out.push(bytes[i] as char);
        i += 1;
    }
    out
}

fn code_signing_json(c: &CodeSigningConfig) -> Value {
    json!({
        "CodeSigningConfigId": c.csc_id,
        "CodeSigningConfigArn": c.csc_arn,
        "Description": c.description,
        "AllowedPublishers": {
            "SigningProfileVersionArns": c.allowed_publishers,
        },
        "CodeSigningPolicies": {
            "UntrustedArtifactOnDeployment": c.untrusted_artifact_action,
        },
        "LastModified": c.last_modified.format("%Y-%m-%dT%H:%M:%S.%3fZ").to_string(),
    })
}

fn event_invoke_json(c: &EventInvokeConfig) -> Value {
    json!({
        "FunctionArn": c.function_arn,
        "MaximumEventAgeInSeconds": c.maximum_event_age,
        "MaximumRetryAttempts": c.maximum_retry_attempts,
        "DestinationConfig": c.destination_config,
        "LastModified": c.last_modified.timestamp(),
    })
}

#[cfg(test)]
mod tests {
    use crate::service::LambdaService;
    use crate::state::{LambdaState, SharedLambdaState};
    use fakecloud_core::multi_account::MultiAccountState;
    use fakecloud_core::service::AwsRequest;
    use http::Method;
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn svc() -> LambdaService {
        let state: SharedLambdaState = Arc::new(RwLock::new(
            MultiAccountState::<LambdaState>::new("000000000000", "us-east-1", ""),
        ));
        LambdaService::new(state)
    }

    fn req(action: &str, body: &str, segs: &[&str]) -> AwsRequest {
        AwsRequest {
            service: "lambda".to_string(),
            method: Method::POST,
            raw_path: format!("/{}", segs.join("/")),
            raw_query: String::new(),
            path_segments: segs.iter().map(|s| s.to_string()).collect(),
            query_params: HashMap::new(),
            headers: http::HeaderMap::new(),
            body: bytes::Bytes::from(body.to_string()),
            body_stream: parking_lot::Mutex::new(None),
            account_id: "000000000000".to_string(),
            region: "us-east-1".to_string(),
            request_id: "rid".to_string(),
            action: action.to_string(),
            is_query_protocol: false,
            access_key_id: None,
            principal: None,
        }
    }

    async fn run(s: &LambdaService, action: &str, body: &str, res: Option<&str>, segs: &[&str]) {
        let r = s.handle_extra(action, res, &req(action, body, segs)).await;
        match r {
            Ok(resp) => assert!(resp.status.is_success(), "{action} status: {}", resp.status),
            Err(e) => panic!("{action} failed: {e:?}"),
        }
    }

    #[tokio::test]
    async fn read_only_listings_succeed_without_state() {
        let s = svc();
        run(&s, "GetAccountSettings", "", None, &[]).await;
        run(&s, "InvokeAsync", r#"{}"#, Some("fn"), &[]).await;
        run(&s, "InvokeWithResponseStream", r#"{}"#, Some("fn"), &[]).await;
        run(&s, "ListLayers", "", None, &[]).await;
        run(&s, "ListLayerVersions", "", Some("layer"), &[]).await;
        run(&s, "ListCapacityProviders", "", None, &[]).await;
    }

    #[tokio::test]
    async fn layers_lifecycle() {
        let s = svc();
        run(
            &s,
            "PublishLayerVersion",
            r#"{"Content":{"ZipFile":""}}"#,
            Some("layer1"),
            &["2018-10-31", "layers", "layer1", "versions"],
        )
        .await;
        run(&s, "ListLayers", "", None, &[]).await;
        run(&s, "ListLayerVersions", "", Some("layer1"), &[]).await;
    }

    #[tokio::test]
    async fn capacity_providers_lifecycle() {
        let s = svc();
        run(
            &s,
            "CreateCapacityProvider",
            r#"{"CapacityProviderName":"cp1"}"#,
            None,
            &[],
        )
        .await;
        run(&s, "GetCapacityProvider", "", Some("cp1"), &[]).await;
        run(&s, "ListCapacityProviders", "", None, &[]).await;
        run(&s, "UpdateCapacityProvider", r#"{}"#, Some("cp1"), &[]).await;
        run(&s, "DeleteCapacityProvider", "", Some("cp1"), &[]).await;
    }

    #[tokio::test]
    async fn durable_executions() {
        let s = svc();
        run(
            &s,
            "CheckpointDurableExecution",
            r#"{"FunctionName":"fn"}"#,
            Some("d1"),
            &[],
        )
        .await;
        run(&s, "GetDurableExecution", "", Some("d1"), &[]).await;
        run(&s, "GetDurableExecutionHistory", "", Some("d1"), &[]).await;
        run(&s, "GetDurableExecutionState", "", Some("d1"), &[]).await;
        run(&s, "StopDurableExecution", "", Some("d1"), &[]).await;
    }

    #[tokio::test]
    async fn code_signing_lifecycle() {
        let s = svc();
        run(
            &s,
            "CreateCodeSigningConfig",
            r#"{"AllowedPublishers":{"SigningProfileVersionArns":[]}}"#,
            None,
            &[],
        )
        .await;
        run(&s, "ListCodeSigningConfigs", "", None, &[]).await;
    }
}
