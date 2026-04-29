use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use http::{Method, StatusCode};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
use fakecloud_persistence::SnapshotStore;

use crate::runtime::ContainerRuntime;
use crate::state::{
    EventSourceMapping, LambdaFunction, LambdaSnapshot, LambdaState, SharedLambdaState,
    LAMBDA_SNAPSHOT_SCHEMA_VERSION,
};

/// Lambda actions whose URL `resource_name` slot is a `FunctionName`
/// (and therefore accepts ARN / partial ARN / `name:qualifier` forms).
/// Layer / event-source-mapping / code-signing-config actions key off
/// other resource identifiers and are excluded.
pub(crate) fn action_takes_function_name(action: &str) -> bool {
    matches!(
        action,
        "GetFunction"
            | "DeleteFunction"
            | "Invoke"
            | "InvokeAsync"
            | "InvokeWithResponseStream"
            | "PublishVersion"
            | "ListVersionsByFunction"
            | "AddPermission"
            | "RemovePermission"
            | "GetPolicy"
            | "GetFunctionConfiguration"
            | "UpdateFunctionConfiguration"
            | "UpdateFunctionCode"
            | "GetFunctionConcurrency"
            | "PutFunctionConcurrency"
            | "DeleteFunctionConcurrency"
            | "PutProvisionedConcurrencyConfig"
            | "GetProvisionedConcurrencyConfig"
            | "DeleteProvisionedConcurrencyConfig"
            | "ListProvisionedConcurrencyConfigs"
            | "PutFunctionEventInvokeConfig"
            | "UpdateFunctionEventInvokeConfig"
            | "GetFunctionEventInvokeConfig"
            | "DeleteFunctionEventInvokeConfig"
            | "ListFunctionEventInvokeConfigs"
            | "CreateFunctionUrlConfig"
            | "UpdateFunctionUrlConfig"
            | "GetFunctionUrlConfig"
            | "DeleteFunctionUrlConfig"
            | "ListFunctionUrlConfigs"
            | "PutFunctionCodeSigningConfig"
            | "GetFunctionCodeSigningConfig"
            | "DeleteFunctionCodeSigningConfig"
            | "GetFunctionScalingConfig"
            | "PutFunctionRecursionConfig"
            | "GetFunctionRecursionConfig"
            | "CreateAlias"
            | "GetAlias"
            | "ListAliases"
            | "UpdateAlias"
            | "DeleteAlias"
            | "PutRuntimeManagementConfig"
            | "GetRuntimeManagementConfig"
            | "ListDurableExecutionsByFunction"
    )
}

/// Strip an ARN, partial ARN, or trailing `:qualifier` from a Lambda
/// `FunctionName` input down to the bare function name used as the
/// state map key. AWS Lambda accepts four forms in URL path slots and
/// API params:
///
///   - `MyFunction`
///   - `MyFunction:Qualifier`
///   - `123456789012:function:MyFunction[:Qualifier]`           (partial ARN)
///   - `arn:aws:lambda:REGION:ACCOUNT:function:MyFunction[:Qualifier]`
///
/// Inputs that don't match any of those structures are returned
/// unchanged. The qualifier (version or alias) is dropped because most
/// callers look up the function by name and resolve qualifier
/// separately.
pub(crate) fn normalize_function_name(input: &str) -> String {
    if input.is_empty() {
        return String::new();
    }

    // SDKs URL-encode `:` in path segments, so `arn:aws:lambda:...`
    // arrives as `arn%3Aaws%3Alambda%3A...`. Decode first; legitimate
    // function names contain no percent-encoded characters, so this is
    // safe for the bare-name path too.
    let decoded = percent_encoding::percent_decode_str(input)
        .decode_utf8_lossy()
        .into_owned();
    let input = decoded.as_str();

    // Full ARN: arn:aws:lambda:REGION:ACCOUNT:function:NAME[:QUALIFIER]
    if let Some(rest) = input.strip_prefix("arn:aws:lambda:") {
        let parts: Vec<&str> = rest.splitn(5, ':').collect();
        // parts: [region, account, "function", name, qualifier?]
        if parts.len() >= 4 && parts[2] == "function" && !parts[3].is_empty() {
            return parts[3].to_string();
        }
        return input.to_string();
    }

    // Partial ARN: ACCOUNT:function:NAME[:QUALIFIER]
    let parts: Vec<&str> = input.splitn(4, ':').collect();
    if parts.len() >= 3 && parts[1] == "function" && parts[0].chars().all(|c| c.is_ascii_digit()) {
        if !parts[2].is_empty() {
            return parts[2].to_string();
        }
        return input.to_string();
    }

    // Bare name with qualifier: NAME:QUALIFIER. Only apply when the
    // input contains exactly one colon and the name part is a valid
    // Lambda function-name token, so malformed ARNs (e.g. wrong service
    // or wrong format) fall through unchanged rather than getting their
    // first colon-segment returned.
    if input.matches(':').count() == 1 {
        if let Some((name, _qualifier)) = input.split_once(':') {
            if !name.is_empty() && name.chars().all(is_function_name_char) {
                return name.to_string();
            }
        }
    }

    input.to_string()
}

fn is_function_name_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || c == '-' || c == '_'
}

/// All fields of a `CreateFunction` request, already parsed and
/// defaulted. The code zip (if any) is eagerly base64-decoded so the
/// caller can hash it without doing the decode again.
struct CreateFunctionInput {
    function_name: String,
    runtime: String,
    role: String,
    handler: String,
    description: String,
    timeout: i64,
    memory_size: i64,
    package_type: String,
    tags: BTreeMap<String, String>,
    environment: BTreeMap<String, String>,
    architectures: Vec<String>,
    code_zip: Option<Vec<u8>>,
    code_fallback: Vec<u8>,
    image_uri: Option<String>,
    layer_arns: Vec<String>,
}

impl CreateFunctionInput {
    fn from_body(body: &Value) -> Result<Self, AwsServiceError> {
        let function_name = body["FunctionName"]
            .as_str()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValueException",
                    "FunctionName is required",
                )
            })?
            .to_string();

        let tags: BTreeMap<String, String> = body["Tags"]
            .as_object()
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        let environment: BTreeMap<String, String> = body["Environment"]["Variables"]
            .as_object()
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect()
            })
            .unwrap_or_default();

        let architectures = body["Architectures"]
            .as_array()
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_else(|| vec!["x86_64".to_string()]);

        let code_zip: Option<Vec<u8>> = match body["Code"]["ZipFile"].as_str() {
            Some(b64) => Some(
                base64::Engine::decode(&base64::engine::general_purpose::STANDARD, b64).map_err(
                    |_| {
                        AwsServiceError::aws_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidParameterValueException",
                            "Could not decode Code.ZipFile: invalid base64",
                        )
                    },
                )?,
            ),
            None => None,
        };

        let code_fallback = serde_json::to_vec(&body["Code"]).unwrap_or_default();

        let package_type = body["PackageType"].as_str().unwrap_or("Zip").to_string();
        // ImageUri belongs to `PackageType=Image` functions. Silently
        // dropping it on `Zip` functions avoids GetFunction returning
        // ECR code metadata for a Zip-based function (AWS ignores the
        // field entirely in that case too).
        let image_uri = if package_type == "Image" {
            body["Code"]["ImageUri"].as_str().map(String::from)
        } else {
            None
        };

        // PackageType=Image requires Code.ImageUri; PackageType=Zip requires
        // code content. Reject inconsistent shapes with AWS's error code so
        // SDK-level validation tests see matching behaviour.
        if package_type == "Image" && image_uri.is_none() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValueException",
                "Code.ImageUri is required when PackageType is Image",
            ));
        }

        let layer_arns: Vec<String> = body["Layers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            function_name,
            runtime: body["Runtime"].as_str().unwrap_or("python3.12").to_string(),
            role: body["Role"].as_str().unwrap_or("").to_string(),
            handler: body["Handler"]
                .as_str()
                .unwrap_or("index.handler")
                .to_string(),
            description: body["Description"].as_str().unwrap_or("").to_string(),
            timeout: body["Timeout"].as_i64().unwrap_or(3),
            memory_size: body["MemorySize"].as_i64().unwrap_or(128),
            package_type,
            tags,
            environment,
            architectures,
            code_zip,
            code_fallback,
            image_uri,
            layer_arns,
        })
    }
}

/// AWS Lambda's InvocationType: synchronous, async (event), or dry-run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InvocationType {
    RequestResponse,
    Event,
    DryRun,
}

impl InvocationType {
    pub fn from_header(value: Option<&str>) -> Self {
        match value {
            Some("Event") => Self::Event,
            Some("DryRun") => Self::DryRun,
            _ => Self::RequestResponse,
        }
    }
}

/// Route an async-invoke result to the configured OnSuccess / OnFailure
/// destination. Destination is matched by ARN scheme: SQS, SNS, EventBridge,
/// or another Lambda. Mirrors the AWS Lambda destinations record schema.
fn route_to_destination(
    bus: Arc<fakecloud_core::delivery::DeliveryBus>,
    function_arn: &str,
    request_payload: &[u8],
    result: &Result<Vec<u8>, String>,
    destination_config: Option<&serde_json::Value>,
) {
    let Some(cfg) = destination_config else {
        return;
    };
    let (key, condition, response_value): (&str, &str, serde_json::Value) = match result {
        Ok(bytes) => (
            "OnSuccess",
            "Success",
            serde_json::from_slice(bytes).unwrap_or(serde_json::Value::Null),
        ),
        Err(err) => (
            "OnFailure",
            "RetriesExhausted",
            serde_json::json!({ "errorMessage": err }),
        ),
    };
    let Some(dest) = cfg
        .get(key)
        .and_then(|v| v.get("Destination"))
        .and_then(|v| v.as_str())
    else {
        return;
    };
    let request_payload_v: serde_json::Value =
        serde_json::from_slice(request_payload).unwrap_or(serde_json::Value::Null);
    let record = serde_json::json!({
        "version": "1.0",
        "timestamp": chrono::Utc::now().to_rfc3339(),
        "requestContext": {
            "requestId": uuid::Uuid::new_v4().to_string(),
            "functionArn": format!("{function_arn}:$LATEST"),
            "condition": condition,
            "approximateInvokeCount": 1,
        },
        "requestPayload": request_payload_v,
        "responseContext": {
            "statusCode": 200,
            "executedVersion": "$LATEST",
        },
        "responsePayload": response_value,
    });
    let body = record.to_string();
    if dest.contains(":sqs:") {
        bus.send_to_sqs(dest, &body, &std::collections::HashMap::new());
    } else if dest.contains(":sns:") {
        bus.publish_to_sns(dest, &body, None);
    } else if dest.contains(":lambda:") {
        let dest = dest.to_string();
        let payload = body.clone();
        tokio::spawn(async move {
            let _ = bus.invoke_lambda(&dest, &payload).await;
        });
    } else if dest.contains(":events:") || dest.contains(":eventbridge:") {
        let detail_type = if result.is_ok() {
            "Lambda Function Invocation Result - Success"
        } else {
            "Lambda Function Invocation Result - Failure"
        };
        bus.put_event_to_eventbridge("lambda", detail_type, &body, "default");
    }
}

pub struct LambdaService {
    pub(crate) state: SharedLambdaState,
    runtime: Option<Arc<ContainerRuntime>>,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    snapshot_lock: Arc<AsyncMutex<()>>,
    pub(crate) delivery_bus: Option<Arc<fakecloud_core::delivery::DeliveryBus>>,
    pub(crate) role_trust_validator: Option<Arc<dyn fakecloud_core::auth::RoleTrustValidator>>,
}

impl LambdaService {
    pub fn new(state: SharedLambdaState) -> Self {
        Self {
            state,
            runtime: None,
            snapshot_store: None,
            snapshot_lock: Arc::new(AsyncMutex::new(())),
            delivery_bus: None,
            role_trust_validator: None,
        }
    }

    pub fn with_runtime(mut self, runtime: Arc<ContainerRuntime>) -> Self {
        self.runtime = Some(runtime);
        self
    }

    pub fn with_snapshot_store(mut self, store: Arc<dyn SnapshotStore>) -> Self {
        self.snapshot_store = Some(store);
        self
    }

    pub fn with_delivery_bus(mut self, bus: Arc<fakecloud_core::delivery::DeliveryBus>) -> Self {
        self.delivery_bus = Some(bus);
        self
    }

    pub fn with_role_trust_validator(
        mut self,
        validator: Arc<dyn fakecloud_core::auth::RoleTrustValidator>,
    ) -> Self {
        self.role_trust_validator = Some(validator);
        self
    }

    async fn save_snapshot(&self) {
        let Some(store) = self.snapshot_store.clone() else {
            return;
        };
        let _guard = self.snapshot_lock.lock().await;
        let snapshot = LambdaSnapshot {
            schema_version: LAMBDA_SNAPSHOT_SCHEMA_VERSION,
            accounts: Some(self.state.read().clone()),
            state: None,
        };
        let join = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let bytes = serde_json::to_vec(&snapshot)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            store.save(&bytes)
        })
        .await;
        match join {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(%err, "failed to write lambda snapshot"),
            Err(err) => tracing::error!(%err, "lambda snapshot task panicked"),
        }
    }

    /// Determine the action from the HTTP method and path segments.
    /// Lambda uses REST-style routing:
    ///   POST   /2015-03-31/functions                         -> CreateFunction
    ///   GET    /2015-03-31/functions                         -> ListFunctions
    ///   GET    /2015-03-31/functions/{name}                  -> GetFunction
    ///   DELETE /2015-03-31/functions/{name}                  -> DeleteFunction
    ///   POST   /2015-03-31/functions/{name}/invocations      -> Invoke
    ///   POST   /2015-03-31/functions/{name}/versions         -> PublishVersion
    ///   POST   /2015-03-31/event-source-mappings             -> CreateEventSourceMapping
    ///   GET    /2015-03-31/event-source-mappings             -> ListEventSourceMappings
    ///   GET    /2015-03-31/event-source-mappings/{uuid}      -> GetEventSourceMapping
    ///   DELETE /2015-03-31/event-source-mappings/{uuid}      -> DeleteEventSourceMapping
    fn resolve_action(req: &AwsRequest) -> Option<(&'static str, Option<String>)> {
        let segs = &req.path_segments;
        if segs.is_empty() {
            return None;
        }
        // The Lambda data API uses many date prefixes (one per
        // operation family). Recognise any well-formed YYYY-MM-DD
        // prefix and route based on the path structure that follows.
        let prefix = segs[0].as_str();

        // Account settings + InvokeAsync — any prefix.
        if segs.get(1).map(|s| s.as_str()) == Some("account-settings") && req.method == Method::GET
        {
            return Some(("GetAccountSettings", None));
        }
        if segs.get(1).map(|s| s.as_str()) == Some("functions")
            && segs.get(3).map(|s| s.as_str()) == Some("invoke-async")
            && req.method == Method::POST
        {
            return Some(("InvokeAsync", segs.get(2).map(|s| s.to_string())));
        }
        if segs.get(1).map(|s| s.as_str()) == Some("functions")
            && segs.get(3).map(|s| s.as_str()) == Some("response-streaming-invocations")
            && req.method == Method::POST
        {
            return Some((
                "InvokeWithResponseStream",
                segs.get(2).map(|s| s.to_string()),
            ));
        }

        // Concurrency (reserved + provisioned) — any prefix.
        if segs.get(1).map(|s| s.as_str()) == Some("functions")
            && segs.get(3).map(|s| s.as_str()) == Some("concurrency")
        {
            let res = segs.get(2).map(|s| s.to_string());
            return match req.method {
                Method::PUT => Some(("PutFunctionConcurrency", res)),
                Method::GET => Some(("GetFunctionConcurrency", res)),
                Method::DELETE => Some(("DeleteFunctionConcurrency", res)),
                _ => None,
            };
        }

        // Provisioned concurrency at any prefix.
        if segs.get(1).map(|s| s.as_str()) == Some("functions")
            && segs.get(3).map(|s| s.as_str()) == Some("provisioned-concurrency")
        {
            let res = segs.get(2).map(|s| s.to_string());
            return match req.method {
                Method::PUT => Some(("PutProvisionedConcurrencyConfig", res)),
                Method::GET => Some(("GetProvisionedConcurrencyConfig", res)),
                Method::DELETE => Some(("DeleteProvisionedConcurrencyConfig", res)),
                _ => None,
            };
        }
        if segs.get(1).map(|s| s.as_str()) == Some("functions")
            && segs.get(3).map(|s| s.as_str()) == Some("provisioned-concurrency-configs")
            && req.method == Method::GET
        {
            return Some((
                "ListProvisionedConcurrencyConfigs",
                segs.get(2).map(|s| s.to_string()),
            ));
        }

        // Event invoke config — any prefix.
        if segs.get(1).map(|s| s.as_str()) == Some("functions")
            && segs.get(3).map(|s| s.as_str()) == Some("event-invoke-config")
        {
            let res = segs.get(2).map(|s| s.to_string());
            return match req.method {
                Method::POST => Some(("PutFunctionEventInvokeConfig", res)),
                Method::PUT => Some(("UpdateFunctionEventInvokeConfig", res)),
                Method::GET => Some(("GetFunctionEventInvokeConfig", res)),
                Method::DELETE => Some(("DeleteFunctionEventInvokeConfig", res)),
                _ => None,
            };
        }
        if segs.get(1).map(|s| s.as_str()) == Some("functions")
            && (segs.get(3).map(|s| s.as_str()) == Some("event-invoke-config-list")
                || (segs.get(3).map(|s| s.as_str()) == Some("event-invoke-config")
                    && segs.get(4).map(|s| s.as_str()) == Some("list")))
            && req.method == Method::GET
        {
            return Some((
                "ListFunctionEventInvokeConfigs",
                segs.get(2).map(|s| s.to_string()),
            ));
        }

        // Recursion config — any prefix.
        if segs.get(1).map(|s| s.as_str()) == Some("functions")
            && segs.get(3).map(|s| s.as_str()) == Some("recursion-config")
        {
            let res = segs.get(2).map(|s| s.to_string());
            return match req.method {
                Method::PUT => Some(("PutFunctionRecursionConfig", res)),
                Method::GET => Some(("GetFunctionRecursionConfig", res)),
                _ => None,
            };
        }

        // Runtime management config — any prefix.
        if segs.get(1).map(|s| s.as_str()) == Some("functions")
            && segs.get(3).map(|s| s.as_str()) == Some("runtime-management-config")
        {
            let res = segs.get(2).map(|s| s.to_string());
            return match req.method {
                Method::PUT => Some(("PutRuntimeManagementConfig", res)),
                Method::GET => Some(("GetRuntimeManagementConfig", res)),
                _ => None,
            };
        }

        // Code signing config (function and global) — any prefix.
        if segs.get(1).map(|s| s.as_str()) == Some("functions")
            && segs.get(3).map(|s| s.as_str()) == Some("code-signing-config")
        {
            let res = segs.get(2).map(|s| s.to_string());
            return match req.method {
                Method::PUT => Some(("PutFunctionCodeSigningConfig", res)),
                Method::GET => Some(("GetFunctionCodeSigningConfig", res)),
                Method::DELETE => Some(("DeleteFunctionCodeSigningConfig", res)),
                _ => None,
            };
        }
        if segs.get(1).map(|s| s.as_str()) == Some("code-signing-configs") {
            let res = segs.get(2).map(|s| s.to_string());
            return match (
                req.method.clone(),
                segs.len(),
                segs.get(3).map(|s| s.as_str()),
            ) {
                (Method::POST, 2, _) => Some(("CreateCodeSigningConfig", None)),
                (Method::GET, 2, _) => Some(("ListCodeSigningConfigs", None)),
                (Method::GET, 3, _) => Some(("GetCodeSigningConfig", res)),
                (Method::PUT, 3, _) => Some(("UpdateCodeSigningConfig", res)),
                (Method::DELETE, 3, _) => Some(("DeleteCodeSigningConfig", res)),
                (Method::GET, 4, Some("functions")) => {
                    Some(("ListFunctionsByCodeSigningConfig", res))
                }
                _ => None,
            };
        }

        // Tags resource ARN at any prefix.
        if segs.get(1).map(|s| s.as_str()) == Some("tags") && segs.len() >= 3 {
            let res = segs[2..].join("/");
            return match req.method {
                Method::POST => Some(("TagResource", Some(res))),
                Method::DELETE => Some(("UntagResource", Some(res))),
                Method::GET => Some(("ListTags", Some(res))),
                _ => None,
            };
        }

        // Function URL config + scaling config (any prefix).
        if segs.get(1).map(|s| s.as_str()) == Some("functions")
            && segs.get(3).map(|s| s.as_str()) == Some("url")
        {
            let res = segs.get(2).map(|s| s.to_string());
            return match req.method {
                Method::POST => Some(("CreateFunctionUrlConfig", res)),
                Method::GET => Some(("GetFunctionUrlConfig", res)),
                Method::PUT => Some(("UpdateFunctionUrlConfig", res)),
                Method::DELETE => Some(("DeleteFunctionUrlConfig", res)),
                _ => None,
            };
        }
        if segs.get(1).map(|s| s.as_str()) == Some("function-urls") && req.method == Method::GET {
            return Some(("ListFunctionUrlConfigs", None));
        }
        if segs.get(1).map(|s| s.as_str()) == Some("functions")
            && segs.get(3).map(|s| s.as_str()) == Some("urls")
            && req.method == Method::GET
        {
            return Some(("ListFunctionUrlConfigs", segs.get(2).map(|s| s.to_string())));
        }
        if segs.get(1).map(|s| s.as_str()) == Some("event-source-mappings")
            && segs.get(3).map(|s| s.as_str()) == Some("scaling-config")
        {
            let res = segs.get(2).map(|s| s.to_string());
            return match req.method {
                Method::PUT => Some(("PutFunctionScalingConfig", res)),
                Method::GET => Some(("GetFunctionScalingConfig", res)),
                _ => None,
            };
        }

        // Capacity providers (any prefix).
        if segs.get(1).map(|s| s.as_str()) == Some("capacity-providers") {
            let res = segs.get(2).map(|s| s.to_string());
            return match (
                req.method.clone(),
                segs.len(),
                segs.get(3).map(|s| s.as_str()),
            ) {
                (Method::POST, 2, _) => Some(("CreateCapacityProvider", None)),
                (Method::GET, 2, _) => Some(("ListCapacityProviders", None)),
                (Method::GET, 3, _) => Some(("GetCapacityProvider", res)),
                (Method::PUT, 3, _) => Some(("UpdateCapacityProvider", res)),
                (Method::DELETE, 3, _) => Some(("DeleteCapacityProvider", res)),
                (Method::GET, 4, Some("function-versions")) => {
                    Some(("ListFunctionVersionsByCapacityProvider", res))
                }
                _ => None,
            };
        }

        // ListDurableExecutionsByFunction lives under functions/{name}.
        if segs.get(1).map(|s| s.as_str()) == Some("functions")
            && segs.get(3).map(|s| s.as_str()) == Some("durable-executions")
            && req.method == Method::GET
        {
            return Some((
                "ListDurableExecutionsByFunction",
                segs.get(2).map(|s| s.to_string()),
            ));
        }

        // Durable execution callbacks at /durable-execution-callbacks/{id}/{kind}
        if segs.get(1).map(|s| s.as_str()) == Some("durable-execution-callbacks")
            && req.method == Method::POST
        {
            let res = segs.get(2).map(|s| s.to_string());
            return match segs.get(3).map(|s| s.as_str()) {
                Some("success") | Some("succeed") => {
                    Some(("SendDurableExecutionCallbackSuccess", res))
                }
                Some("failure") | Some("fail") => {
                    Some(("SendDurableExecutionCallbackFailure", res))
                }
                Some("heartbeat") => Some(("SendDurableExecutionCallbackHeartbeat", res)),
                _ => None,
            };
        }

        // Durable executions (any prefix).
        if segs.get(1).map(|s| s.as_str()) == Some("durable-executions") {
            let res = segs.get(2).map(|s| s.to_string());
            return match (
                req.method.clone(),
                segs.len(),
                segs.get(3).map(|s| s.as_str()),
                segs.get(4).map(|s| s.as_str()),
            ) {
                (Method::GET, 3, _, _) => Some(("GetDurableExecution", res)),
                (Method::GET, 4, Some("history"), _) => Some(("GetDurableExecutionHistory", res)),
                (Method::GET, 4, Some("state"), _) => Some(("GetDurableExecutionState", res)),
                (Method::POST, 4, Some("checkpoint"), _) => {
                    Some(("CheckpointDurableExecution", res))
                }
                (Method::POST, 4, Some("stop"), _) => Some(("StopDurableExecution", res)),
                (Method::POST, 5, Some("callback"), Some("success")) => {
                    Some(("SendDurableExecutionCallbackSuccess", res))
                }
                (Method::POST, 5, Some("callback"), Some("failure")) => {
                    Some(("SendDurableExecutionCallbackFailure", res))
                }
                (Method::POST, 5, Some("callback"), Some("heartbeat")) => {
                    Some(("SendDurableExecutionCallbackHeartbeat", res))
                }
                _ => None,
            };
        }

        // NOTE: concurrency, event-invoke-config, recursion-config,
        // capacity-providers, durable-executions, and code-signing-configs
        // routes are all handled by the prefix-agnostic blocks above.
        // The previously-present date-specific blocks were dead code.

        // /2018-10-31/layers
        if prefix == "2018-10-31" && segs.get(1).map(|s| s.as_str()) == Some("layers") {
            let layer = segs.get(2).map(|s| s.to_string());
            let third = segs.get(3).map(|s| s.as_str());
            let version = segs.get(4).map(|s| s.to_string());
            return match (&req.method, segs.len(), third, version.is_some()) {
                (&Method::GET, 2, _, _) => Some(("ListLayers", None)),
                (&Method::POST, 4, Some("versions"), false) => Some(("PublishLayerVersion", layer)),
                (&Method::GET, 4, Some("versions"), false) => Some(("ListLayerVersions", layer)),
                (&Method::GET, 5, Some("versions"), true) => Some(("GetLayerVersion", version)),
                (&Method::DELETE, 5, Some("versions"), true) => {
                    Some(("DeleteLayerVersion", version))
                }
                (&Method::GET, 6, Some("versions"), true)
                    if segs.get(5).map(|s| s.as_str()) == Some("policy") =>
                {
                    Some(("GetLayerVersionPolicy", version))
                }
                (&Method::POST, 6, Some("versions"), true)
                    if segs.get(5).map(|s| s.as_str()) == Some("policy") =>
                {
                    Some(("AddLayerVersionPermission", version))
                }
                (&Method::DELETE, 7, Some("versions"), true)
                    if segs.get(5).map(|s| s.as_str()) == Some("policy") =>
                {
                    Some(("RemoveLayerVersionPermission", version))
                }
                _ => None,
            };
        }

        // /2018-10-31/layers-by-arn
        if prefix == "2018-10-31"
            && segs.get(1).map(|s| s.as_str()) == Some("layers-by-arn")
            && req.method == Method::GET
        {
            return Some(("GetLayerVersionByArn", None));
        }

        // NOTE: 2021-10-31/functions/{name}/url and ListFunctionUrlConfigs
        // are handled by the prefix-agnostic blocks above.

        if prefix != "2015-03-31" {
            return None;
        }

        let collection = segs.get(1).map(|s| s.as_str());
        let resource = segs.get(2).map(|s| s.to_string());
        let third = segs.get(3).map(|s| s.as_str());
        let fourth = segs.get(4).map(|s| s.as_str());

        let action = match (&req.method, segs.len(), collection, third) {
            (&Method::POST, 2, Some("functions"), _) => "CreateFunction",
            (&Method::GET, 2, Some("functions"), _) => "ListFunctions",
            (&Method::GET, 3, Some("functions"), _) => "GetFunction",
            (&Method::DELETE, 3, Some("functions"), _) => "DeleteFunction",
            (&Method::POST, 4, Some("functions"), Some("invocations")) => "Invoke",
            (&Method::POST, 4, Some("functions"), Some("invoke-async")) => "InvokeAsync",
            (&Method::POST, 4, Some("functions"), Some("response-streaming-invocations")) => {
                "InvokeWithResponseStream"
            }
            (&Method::POST, 4, Some("functions"), Some("versions")) => "PublishVersion",
            (&Method::GET, 4, Some("functions"), Some("versions")) => "ListVersionsByFunction",
            (&Method::POST, 4, Some("functions"), Some("policy")) => "AddPermission",
            (&Method::GET, 4, Some("functions"), Some("policy")) => "GetPolicy",
            (&Method::DELETE, 5, Some("functions"), Some("policy")) => "RemovePermission",
            (&Method::POST, 4, Some("functions"), Some("aliases")) => "CreateAlias",
            (&Method::GET, 4, Some("functions"), Some("aliases")) => "ListAliases",
            (&Method::GET, 5, Some("functions"), Some("aliases")) => "GetAlias",
            (&Method::PUT, 5, Some("functions"), Some("aliases")) => "UpdateAlias",
            (&Method::DELETE, 5, Some("functions"), Some("aliases")) => "DeleteAlias",
            (&Method::GET, 4, Some("functions"), Some("configuration")) => {
                "GetFunctionConfiguration"
            }
            (&Method::PUT, 4, Some("functions"), Some("configuration")) => {
                "UpdateFunctionConfiguration"
            }
            (&Method::PUT, 4, Some("functions"), Some("code")) => "UpdateFunctionCode",
            (&Method::PUT, 4, Some("functions"), Some("concurrency")) => "PutFunctionConcurrency",
            (&Method::GET, 4, Some("functions"), Some("concurrency")) => "GetFunctionConcurrency",
            (&Method::DELETE, 4, Some("functions"), Some("concurrency")) => {
                "DeleteFunctionConcurrency"
            }
            (&Method::PUT, 4, Some("functions"), Some("provisioned-concurrency")) => {
                "PutProvisionedConcurrencyConfig"
            }
            (&Method::GET, 4, Some("functions"), Some("provisioned-concurrency")) => {
                "GetProvisionedConcurrencyConfig"
            }
            (&Method::DELETE, 4, Some("functions"), Some("provisioned-concurrency")) => {
                "DeleteProvisionedConcurrencyConfig"
            }
            (&Method::GET, 4, Some("functions"), Some("provisioned-concurrency-configs")) => {
                "ListProvisionedConcurrencyConfigs"
            }
            (&Method::PUT, 4, Some("functions"), Some("event-invoke-config")) => {
                "UpdateFunctionEventInvokeConfig"
            }
            (&Method::POST, 4, Some("functions"), Some("event-invoke-config")) => {
                "PutFunctionEventInvokeConfig"
            }
            (&Method::GET, 4, Some("functions"), Some("event-invoke-config")) => {
                "GetFunctionEventInvokeConfig"
            }
            (&Method::DELETE, 4, Some("functions"), Some("event-invoke-config")) => {
                "DeleteFunctionEventInvokeConfig"
            }
            (&Method::GET, 4, Some("functions"), Some("event-invoke-config-list")) => {
                "ListFunctionEventInvokeConfigs"
            }
            (&Method::PUT, 4, Some("functions"), Some("code-signing-config")) => {
                "PutFunctionCodeSigningConfig"
            }
            (&Method::GET, 4, Some("functions"), Some("code-signing-config")) => {
                "GetFunctionCodeSigningConfig"
            }
            (&Method::DELETE, 4, Some("functions"), Some("code-signing-config")) => {
                "DeleteFunctionCodeSigningConfig"
            }
            (&Method::PUT, 4, Some("functions"), Some("runtime-management-config")) => {
                "PutRuntimeManagementConfig"
            }
            (&Method::GET, 4, Some("functions"), Some("runtime-management-config")) => {
                "GetRuntimeManagementConfig"
            }
            (&Method::PUT, 4, Some("functions"), Some("scaling-config")) => {
                "PutFunctionScalingConfig"
            }
            (&Method::GET, 4, Some("functions"), Some("scaling-config")) => {
                "GetFunctionScalingConfig"
            }
            (&Method::PUT, 4, Some("functions"), Some("recursion-config")) => {
                "PutFunctionRecursionConfig"
            }
            (&Method::GET, 4, Some("functions"), Some("recursion-config")) => {
                "GetFunctionRecursionConfig"
            }
            (&Method::GET, 4, Some("functions"), Some("durable-executions")) => {
                "ListDurableExecutionsByFunction"
            }
            (&Method::POST, 2, Some("event-source-mappings"), _) => "CreateEventSourceMapping",
            (&Method::GET, 2, Some("event-source-mappings"), _) => "ListEventSourceMappings",
            (&Method::GET, 3, Some("event-source-mappings"), _) => "GetEventSourceMapping",
            (&Method::PUT, 3, Some("event-source-mappings"), _) => "UpdateEventSourceMapping",
            (&Method::DELETE, 3, Some("event-source-mappings"), _) => "DeleteEventSourceMapping",
            (&Method::POST, 3, Some("tags"), _) => "TagResource",
            (&Method::DELETE, 3, Some("tags"), _) => "UntagResource",
            (&Method::GET, 3, Some("tags"), _) => "ListTags",
            _ => return None,
        };
        let _ = fourth;

        Some((action, resource))
    }

    fn create_function(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body: Value = serde_json::from_slice(&req.body).unwrap_or_default();
        let input = CreateFunctionInput::from_body(&body)?;

        // PassRole trust-policy check: the supplied execution role must
        // have a trust policy that allows lambda.amazonaws.com to call
        // sts:AssumeRole. Real AWS rejects with InvalidParameterValueException
        // when the trust policy doesn't include the service principal.
        if let Some(ref validator) = self.role_trust_validator {
            if let Err(err) =
                validator.validate(&req.account_id, &input.role, "lambda.amazonaws.com")
            {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValueException",
                    err.to_string(),
                ));
            }
        }

        let mut accounts = self.state.write();
        // Pre-resolve layer attachments before re-borrowing accounts mutably.
        // Layer ARNs may live in sibling accounts.
        let layer_attachments =
            crate::extras::resolve_layer_attachments(&accounts, input.layer_arns.clone());
        let state = accounts.get_or_create(&req.account_id);

        if state.functions.contains_key(&input.function_name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::CONFLICT,
                "ResourceConflictException",
                format!("Function already exist: {}", input.function_name),
            ));
        }

        // Hash the actual ZIP bytes when available, falling back to the
        // raw Code JSON so image-based functions still get a stable id.
        let code_bytes = input.code_zip.as_deref().unwrap_or(&input.code_fallback);
        let mut hasher = Sha256::new();
        hasher.update(code_bytes);
        let hash = hasher.finalize();
        let code_sha256 = base64::Engine::encode(&base64::engine::general_purpose::STANDARD, hash);
        let code_size = code_bytes.len() as i64;

        let function_arn = format!(
            "arn:aws:lambda:{}:{}:function:{}",
            state.region, state.account_id, input.function_name
        );
        let now = Utc::now();

        let func = LambdaFunction {
            function_name: input.function_name.clone(),
            function_arn,
            runtime: input.runtime,
            role: input.role,
            handler: input.handler,
            description: input.description,
            timeout: input.timeout,
            memory_size: input.memory_size,
            code_sha256,
            code_size,
            version: "$LATEST".to_string(),
            last_modified: now,
            tags: input.tags,
            environment: input.environment,
            architectures: input.architectures,
            package_type: input.package_type,
            code_zip: input.code_zip,
            image_uri: input.image_uri,
            policy: None,
            layers: layer_attachments,
        };

        let response = self.function_config_json(&func);

        state.functions.insert(input.function_name, func);

        Ok(AwsResponse::json(StatusCode::CREATED, response.to_string()))
    }

    fn get_function(
        &self,
        function_name: &str,
        account_id: &str,
        region: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let empty = LambdaState::new(account_id, region);
        let state = accounts.get(account_id).unwrap_or(&empty);
        let func = state.functions.get(function_name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!(
                    "Function not found: arn:aws:lambda:{}:{}:function:{}",
                    state.region, state.account_id, function_name
                ),
            )
        })?;

        let config = self.function_config_json(func);
        let code = if let Some(ref uri) = func.image_uri {
            json!({
                "ImageUri": uri,
                "ResolvedImageUri": uri,
                "RepositoryType": "ECR",
            })
        } else {
            json!({
                "Location": format!(
                    "https://awslambda-{}-tasks.s3.{}.amazonaws.com/stub",
                    func.function_arn.split(':').nth(3).unwrap_or("us-east-1"),
                    func.function_arn.split(':').nth(3).unwrap_or("us-east-1")
                ),
                "RepositoryType": "S3",
            })
        };
        let response = json!({
            "Code": code,
            "Configuration": config,
            "Tags": func.tags,
        });

        Ok(AwsResponse::json(StatusCode::OK, response.to_string()))
    }

    fn delete_function(
        &self,
        function_name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        let region = state.region.clone();
        let account_id = state.account_id.clone();
        if state.functions.remove(function_name).is_none() {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!(
                    "Function not found: arn:aws:lambda:{}:{}:function:{}",
                    region, account_id, function_name
                ),
            ));
        }

        // Clean up any running container for this function
        if let Some(ref runtime) = self.runtime {
            let rt = runtime.clone();
            let name = function_name.to_string();
            tokio::spawn(async move { rt.stop_container(&name).await });
        }

        Ok(AwsResponse::json(StatusCode::NO_CONTENT, ""))
    }

    fn list_functions(&self, account_id: &str) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let empty = LambdaState::new(account_id, "");
        let state = accounts.get(account_id).unwrap_or(&empty);
        let functions: Vec<Value> = state
            .functions
            .values()
            .map(|f| self.function_config_json(f))
            .collect();

        let response = json!({
            "Functions": functions,
        });

        Ok(AwsResponse::json(StatusCode::OK, response.to_string()))
    }

    async fn invoke(
        &self,
        function_name: &str,
        payload: &[u8],
        account_id: &str,
        invocation_type: InvocationType,
    ) -> Result<AwsResponse, AwsServiceError> {
        let (func, layer_zips) = {
            let accounts = self.state.read();
            let empty = LambdaState::new(account_id, "");
            let state = accounts.get(account_id).unwrap_or(&empty);
            let func = state.functions.get(function_name).cloned().ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "ResourceNotFoundException",
                    format!(
                        "Function not found: arn:aws:lambda:{}:{}:function:{}",
                        state.region, state.account_id, function_name
                    ),
                )
            })?;
            // Resolve attached layer ARNs to ZIP bytes under the same read
            // lock. Layers may live in sibling accounts (cross-account
            // attach is legal in AWS); fall back to no bytes for unknown
            // ARNs and warn — invoke proceeds without that layer.
            let mut layer_zips: Vec<Vec<u8>> = Vec::with_capacity(func.layers.len());
            for attached in &func.layers {
                let bytes = crate::extras::parse_layer_version_arn(&attached.arn).and_then(
                    |(acct, name, ver)| {
                        accounts
                            .get(&acct)
                            .and_then(|s| s.layers.get(&name))
                            .and_then(|l| l.versions.iter().find(|v| v.version == ver))
                            .and_then(|v| v.code_zip.clone())
                    },
                );
                match bytes {
                    Some(b) => layer_zips.push(b),
                    None => tracing::warn!(
                        function = %function_name,
                        layer_arn = %attached.arn,
                        "attached layer not resolvable; skipping /opt mount for this layer"
                    ),
                }
            }
            (func, layer_zips)
        };

        if func.code_zip.is_none() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValueException",
                "Function has no deployment package",
            ));
        }

        if matches!(invocation_type, InvocationType::DryRun) {
            let mut resp = AwsResponse::json(StatusCode::NO_CONTENT, "");
            resp.headers.insert(
                http::header::HeaderName::from_static("x-amz-executed-version"),
                http::header::HeaderValue::from_static("$LATEST"),
            );
            return Ok(resp);
        }

        let runtime = self.runtime.as_ref().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "ServiceException",
                "Docker/Podman is required for Lambda execution but is not available",
            )
        })?;

        match invocation_type {
            InvocationType::Event => {
                // Fire-and-forget. AWS returns 202 with no body.
                let runtime = runtime.clone();
                let func_clone = func.clone();
                let payload_vec = payload.to_vec();
                let bus = self.delivery_bus.clone();
                let destination_config = self.lookup_destination_config(&func, account_id);
                let function_arn = func.function_arn.clone();
                let layer_zips_async = layer_zips.clone();
                tokio::spawn(async move {
                    let result = match runtime
                        .invoke(&func_clone, &payload_vec, &layer_zips_async)
                        .await
                    {
                        Ok(bytes) => {
                            // Lambda runtime returns 200 even on uncaught
                            // function errors; the body has errorMessage /
                            // errorType. Treat that as failure for routing.
                            let parsed: Option<serde_json::Value> =
                                serde_json::from_slice(&bytes).ok();
                            let is_error = parsed
                                .as_ref()
                                .and_then(|v| v.as_object())
                                .map(|m| {
                                    m.contains_key("errorMessage") || m.contains_key("errorType")
                                })
                                .unwrap_or(false);
                            if is_error {
                                let msg = parsed
                                    .as_ref()
                                    .and_then(|v| v.get("errorMessage"))
                                    .and_then(|v| v.as_str())
                                    .unwrap_or("function error")
                                    .to_string();
                                Err(msg)
                            } else {
                                Ok(bytes)
                            }
                        }
                        Err(e) => Err(e.to_string()),
                    };
                    if let Some(bus) = bus {
                        route_to_destination(
                            bus,
                            &function_arn,
                            &payload_vec,
                            &result,
                            destination_config.as_ref(),
                        );
                    }
                });
                let mut resp = AwsResponse::json(StatusCode::ACCEPTED, "");
                resp.headers.insert(
                    http::header::HeaderName::from_static("x-amz-executed-version"),
                    http::header::HeaderValue::from_static("$LATEST"),
                );
                Ok(resp)
            }
            InvocationType::RequestResponse | InvocationType::DryRun => {
                match runtime.invoke(&func, payload, &layer_zips).await {
                    Ok(response_bytes) => {
                        let mut resp = AwsResponse::json(StatusCode::OK, response_bytes);
                        resp.headers.insert(
                            http::header::HeaderName::from_static("x-amz-executed-version"),
                            http::header::HeaderValue::from_static("$LATEST"),
                        );
                        Ok(resp)
                    }
                    Err(e) => {
                        tracing::error!(function = %function_name, error = %e, "Lambda invocation failed");
                        Err(AwsServiceError::aws_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "ServiceException",
                            format!("Lambda execution failed: {e}"),
                        ))
                    }
                }
            }
        }
    }

    /// Pull EventInvokeConfig.DestinationConfig for the function. The
    /// stored key is `<function_name>:<qualifier>`; treat unqualified
    /// invokes as the empty qualifier (matches `parse_qualifier` in
    /// `extras.rs` when no `Qualifier` is supplied).
    fn lookup_destination_config(
        &self,
        func: &crate::state::LambdaFunction,
        account_id: &str,
    ) -> Option<serde_json::Value> {
        let accounts = self.state.read();
        let state = accounts.get(account_id)?;
        let key = format!("{}:$LATEST", func.function_name);
        state
            .event_invoke_configs
            .get(&key)
            .map(|cfg| cfg.destination_config.clone())
            .filter(|v| !v.is_null() && !v.as_object().map(|o| o.is_empty()).unwrap_or(false))
    }

    fn publish_version(
        &self,
        function_name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let empty = LambdaState::new(account_id, "");
        let state = accounts.get(account_id).unwrap_or(&empty);
        let func = state.functions.get(function_name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!(
                    "Function not found: arn:aws:lambda:{}:{}:function:{}",
                    state.region, state.account_id, function_name
                ),
            )
        })?;

        let mut config = self.function_config_json(func);
        // Stub: always return version "1"
        config["Version"] = json!("1");
        config["FunctionArn"] = json!(format!("{}:1", func.function_arn));

        Ok(AwsResponse::json(StatusCode::CREATED, config.to_string()))
    }

    pub(crate) fn function_config_json(&self, func: &LambdaFunction) -> Value {
        let mut env_vars = json!({});
        if !func.environment.is_empty() {
            env_vars = json!({ "Variables": func.environment });
        }

        let mut config = json!({
            "FunctionName": func.function_name,
            "FunctionArn": func.function_arn,
            "Runtime": func.runtime,
            "Role": func.role,
            "Handler": func.handler,
            "Description": func.description,
            "Timeout": func.timeout,
            "MemorySize": func.memory_size,
            "CodeSha256": func.code_sha256,
            "CodeSize": func.code_size,
            "Version": func.version,
            "LastModified": func.last_modified.format("%Y-%m-%dT%H:%M:%S%.3f+0000").to_string(),
            "PackageType": func.package_type,
            "Architectures": func.architectures,
            "Environment": env_vars,
            "State": "Active",
            "LastUpdateStatus": "Successful",
            "TracingConfig": { "Mode": "PassThrough" },
            "RevisionId": uuid::Uuid::new_v4().to_string(),
        });
        if let Some(ref uri) = func.image_uri {
            config["Code"] = json!({
                "ImageUri": uri,
                "ResolvedImageUri": uri,
            });
        }
        if !func.layers.is_empty() {
            config["Layers"] = json!(func
                .layers
                .iter()
                .map(|l| json!({"Arn": l.arn, "CodeSize": l.code_size}))
                .collect::<Vec<_>>());
        }
        config
    }
}

#[async_trait]
impl AwsService for LambdaService {
    fn service_name(&self) -> &str {
        "lambda"
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let (action, resource_name) = Self::resolve_action(&req).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "UnknownOperationException",
                format!("Unknown operation: {} {}", req.method, req.raw_path),
            )
        })?;

        // Normalize FunctionName-bearing resource slots: AWS Lambda accepts
        // bare name, name:qualifier, partial ARN, and full ARN in any URL
        // slot that names a function. Layer / event-source-mapping resource
        // names go through different routes and are left as-is.
        let resource_name = if action_takes_function_name(action) {
            resource_name.map(|s| normalize_function_name(&s))
        } else {
            resource_name
        };

        let mutates = matches!(
            action,
            "CreateFunction"
                | "DeleteFunction"
                | "PublishVersion"
                | "AddPermission"
                | "RemovePermission"
                | "CreateEventSourceMapping"
                | "DeleteEventSourceMapping"
                | "UpdateEventSourceMapping"
                | "UpdateFunctionCode"
                | "UpdateFunctionConfiguration"
                | "CreateAlias"
                | "DeleteAlias"
                | "UpdateAlias"
                | "PublishLayerVersion"
                | "DeleteLayerVersion"
                | "AddLayerVersionPermission"
                | "RemoveLayerVersionPermission"
                | "CreateFunctionUrlConfig"
                | "DeleteFunctionUrlConfig"
                | "UpdateFunctionUrlConfig"
                | "PutFunctionConcurrency"
                | "DeleteFunctionConcurrency"
                | "PutProvisionedConcurrencyConfig"
                | "DeleteProvisionedConcurrencyConfig"
                | "CreateCodeSigningConfig"
                | "UpdateCodeSigningConfig"
                | "DeleteCodeSigningConfig"
                | "PutFunctionCodeSigningConfig"
                | "DeleteFunctionCodeSigningConfig"
                | "PutFunctionEventInvokeConfig"
                | "UpdateFunctionEventInvokeConfig"
                | "DeleteFunctionEventInvokeConfig"
                | "PutRuntimeManagementConfig"
                | "PutFunctionScalingConfig"
                | "PutFunctionRecursionConfig"
                | "TagResource"
                | "UntagResource"
                | "CreateCapacityProvider"
                | "UpdateCapacityProvider"
                | "DeleteCapacityProvider"
                | "CheckpointDurableExecution"
                | "StopDurableExecution"
                | "SendDurableExecutionCallbackSuccess"
                | "SendDurableExecutionCallbackFailure"
                | "SendDurableExecutionCallbackHeartbeat"
                | "InvokeAsync"
                | "InvokeWithResponseStream"
        );

        let aid = &req.account_id;
        let result = match action {
            "CreateFunction" => self.create_function(&req),
            "ListFunctions" => self.list_functions(aid),
            "GetFunction" => self.get_function(
                resource_name.as_deref().unwrap_or(""),
                aid,
                req.region.as_str(),
            ),
            "DeleteFunction" => self.delete_function(resource_name.as_deref().unwrap_or(""), aid),
            "Invoke" => {
                let invocation_type = InvocationType::from_header(
                    req.headers
                        .get("x-amz-invocation-type")
                        .and_then(|v| v.to_str().ok()),
                );
                self.invoke(
                    resource_name.as_deref().unwrap_or(""),
                    &req.body,
                    aid,
                    invocation_type,
                )
                .await
            }
            "InvokeAsync" => {
                self.invoke(
                    resource_name.as_deref().unwrap_or(""),
                    &req.body,
                    aid,
                    InvocationType::Event,
                )
                .await
            }
            "PublishVersion" => self.publish_version(resource_name.as_deref().unwrap_or(""), aid),
            "AddPermission" => self.add_permission(resource_name.as_deref().unwrap_or(""), &req),
            "GetPolicy" => self.get_policy(resource_name.as_deref().unwrap_or(""), aid),
            "RemovePermission" => {
                // Path: /2015-03-31/functions/{name}/policy/{sid}
                let sid = req.path_segments.get(4).cloned().unwrap_or_default();
                self.remove_permission(resource_name.as_deref().unwrap_or(""), &sid, aid)
            }
            "CreateEventSourceMapping" => self.create_event_source_mapping(&req),
            "ListEventSourceMappings" => self.list_event_source_mappings(aid),
            "GetEventSourceMapping" => {
                self.get_event_source_mapping(resource_name.as_deref().unwrap_or(""), aid)
            }
            "DeleteEventSourceMapping" => {
                self.delete_event_source_mapping(resource_name.as_deref().unwrap_or(""), aid)
            }
            other => {
                self.handle_extra(other, resource_name.as_deref(), &req)
                    .await
            }
        };
        if mutates && matches!(result.as_ref(), Ok(resp) if resp.status.is_success()) {
            self.save_snapshot().await;
        }
        result
    }

    fn supported_actions(&self) -> &[&str] {
        &[
            "CreateFunction",
            "GetFunction",
            "DeleteFunction",
            "ListFunctions",
            "Invoke",
            "InvokeAsync",
            "InvokeWithResponseStream",
            "PublishVersion",
            "ListVersionsByFunction",
            "AddPermission",
            "RemovePermission",
            "GetPolicy",
            "CreateEventSourceMapping",
            "ListEventSourceMappings",
            "GetEventSourceMapping",
            "UpdateEventSourceMapping",
            "DeleteEventSourceMapping",
            "GetFunctionConfiguration",
            "UpdateFunctionConfiguration",
            "UpdateFunctionCode",
            "GetAccountSettings",
            "CreateAlias",
            "GetAlias",
            "ListAliases",
            "UpdateAlias",
            "DeleteAlias",
            "PublishLayerVersion",
            "GetLayerVersion",
            "GetLayerVersionByArn",
            "DeleteLayerVersion",
            "ListLayerVersions",
            "ListLayers",
            "GetLayerVersionPolicy",
            "AddLayerVersionPermission",
            "RemoveLayerVersionPermission",
            "CreateFunctionUrlConfig",
            "GetFunctionUrlConfig",
            "UpdateFunctionUrlConfig",
            "DeleteFunctionUrlConfig",
            "ListFunctionUrlConfigs",
            "PutFunctionConcurrency",
            "GetFunctionConcurrency",
            "DeleteFunctionConcurrency",
            "PutProvisionedConcurrencyConfig",
            "GetProvisionedConcurrencyConfig",
            "DeleteProvisionedConcurrencyConfig",
            "ListProvisionedConcurrencyConfigs",
            "CreateCodeSigningConfig",
            "GetCodeSigningConfig",
            "UpdateCodeSigningConfig",
            "DeleteCodeSigningConfig",
            "ListCodeSigningConfigs",
            "PutFunctionCodeSigningConfig",
            "GetFunctionCodeSigningConfig",
            "DeleteFunctionCodeSigningConfig",
            "ListFunctionsByCodeSigningConfig",
            "PutFunctionEventInvokeConfig",
            "GetFunctionEventInvokeConfig",
            "UpdateFunctionEventInvokeConfig",
            "DeleteFunctionEventInvokeConfig",
            "ListFunctionEventInvokeConfigs",
            "PutRuntimeManagementConfig",
            "GetRuntimeManagementConfig",
            "PutFunctionScalingConfig",
            "GetFunctionScalingConfig",
            "PutFunctionRecursionConfig",
            "GetFunctionRecursionConfig",
            "TagResource",
            "UntagResource",
            "ListTags",
            "CreateCapacityProvider",
            "GetCapacityProvider",
            "UpdateCapacityProvider",
            "DeleteCapacityProvider",
            "ListCapacityProviders",
            "ListFunctionVersionsByCapacityProvider",
            "CheckpointDurableExecution",
            "GetDurableExecution",
            "GetDurableExecutionHistory",
            "GetDurableExecutionState",
            "ListDurableExecutionsByFunction",
            "StopDurableExecution",
            "SendDurableExecutionCallbackSuccess",
            "SendDurableExecutionCallbackFailure",
            "SendDurableExecutionCallbackHeartbeat",
        ]
    }

    fn iam_enforceable(&self) -> bool {
        true
    }

    /// Lambda resources are function ARNs. Function-scoped ops
    /// resolve the target ARN from the path; list ops target `*`
    /// (the whole service), matching how AWS models them.
    fn iam_action_for(&self, request: &AwsRequest) -> Option<fakecloud_core::auth::IamAction> {
        // REST-JSON services don't have `request.action` populated at
        // dispatch time — it's derived from method+path inside
        // `handle()`. Reuse the same resolver so the two can never
        // drift.
        let (action_str, resource_name) = Self::resolve_action(request)?;
        let action: &'static str = match action_str {
            "CreateFunction" => "CreateFunction",
            "ListFunctions" => "ListFunctions",
            "GetFunction" => "GetFunction",
            "DeleteFunction" => "DeleteFunction",
            "Invoke" => "InvokeFunction",
            "PublishVersion" => "PublishVersion",
            "AddPermission" => "AddPermission",
            "RemovePermission" => "RemovePermission",
            "GetPolicy" => "GetPolicy",
            "CreateEventSourceMapping" => "CreateEventSourceMapping",
            "ListEventSourceMappings" => "ListEventSourceMappings",
            "GetEventSourceMapping" => "GetEventSourceMapping",
            "DeleteEventSourceMapping" => "DeleteEventSourceMapping",
            _ => return None,
        };
        let accounts = self.state.read();
        let empty = LambdaState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        let resource = match action {
            "GetFunction" | "DeleteFunction" | "InvokeFunction" | "PublishVersion"
            | "AddPermission" | "RemovePermission" | "GetPolicy" => {
                let name = resource_name.unwrap_or_default();
                if name.is_empty() {
                    "*".to_string()
                } else {
                    format!(
                        "arn:aws:lambda:{}:{}:function:{}",
                        state.region, state.account_id, name
                    )
                }
            }
            "CreateFunction" => {
                // Best-effort: parse the FunctionName from the body so
                // CreateFunction can be resource-scoped against the
                // to-be-created ARN. Falls back to `*` when the body
                // isn't JSON yet (e.g. soft-mode observability).
                serde_json::from_slice::<Value>(&request.body)
                    .ok()
                    .and_then(|v| {
                        v.get("FunctionName").and_then(|f| f.as_str()).map(|n| {
                            format!(
                                "arn:aws:lambda:{}:{}:function:{}",
                                state.region, state.account_id, n
                            )
                        })
                    })
                    .unwrap_or_else(|| "*".to_string())
            }
            _ => "*".to_string(),
        };
        Some(fakecloud_core::auth::IamAction {
            service: "lambda",
            action,
            resource,
        })
    }

    fn iam_condition_keys_for(
        &self,
        request: &AwsRequest,
        action: &fakecloud_core::auth::IamAction,
    ) -> std::collections::BTreeMap<String, Vec<String>> {
        let mut out = std::collections::BTreeMap::new();
        if action.action == "AddPermission" {
            if action.resource != "*" {
                out.insert(
                    "lambda:functionarn".to_string(),
                    vec![action.resource.clone()],
                );
            }
            if let Ok(body) = serde_json::from_slice::<Value>(&request.body) {
                if let Some(principal) = body.get("Principal").and_then(|p| p.as_str()) {
                    out.insert("lambda:principal".to_string(), vec![principal.to_string()]);
                }
            }
        }
        out
    }
}

#[path = "service_event_sources.rs"]
mod service_event_sources;
#[path = "service_permissions.rs"]
mod service_permissions;

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
