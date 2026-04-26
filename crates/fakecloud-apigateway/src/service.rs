//! API Gateway v1 (REST APIs) service implementation.

use async_trait::async_trait;
use http::{Method, StatusCode};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

use fakecloud_core::delivery::DeliveryBus;
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};
use fakecloud_persistence::SnapshotStore;

use crate::dispatch::{resolve, ResolvedAction};
use crate::state::{
    make_id, ApiGatewaySnapshot, ApiGatewayState, ApiKey, Authorizer, Deployment, Integration,
    Method as ApiMethod, Model, Resource, RestApi, SharedApiGatewayState, Stage, UsagePlan,
    APIGATEWAY_SNAPSHOT_SCHEMA_VERSION,
};

pub const SUPPORTED_ACTIONS: &[&str] = &[
    "GetAccount",
    "UpdateAccount",
    "CreateRestApi",
    "GetRestApi",
    "GetRestApis",
    "DeleteRestApi",
    "UpdateRestApi",
    "PutRestApi",
    "ImportRestApi",
    "CreateResource",
    "GetResource",
    "GetResources",
    "DeleteResource",
    "UpdateResource",
    "PutMethod",
    "GetMethod",
    "DeleteMethod",
    "UpdateMethod",
    "PutMethodResponse",
    "GetMethodResponse",
    "DeleteMethodResponse",
    "UpdateMethodResponse",
    "PutIntegration",
    "GetIntegration",
    "DeleteIntegration",
    "UpdateIntegration",
    "PutIntegrationResponse",
    "GetIntegrationResponse",
    "DeleteIntegrationResponse",
    "UpdateIntegrationResponse",
    "TestInvokeMethod",
    "TestInvokeAuthorizer",
    "CreateDeployment",
    "GetDeployment",
    "GetDeployments",
    "DeleteDeployment",
    "UpdateDeployment",
    "CreateStage",
    "GetStage",
    "GetStages",
    "DeleteStage",
    "UpdateStage",
    "FlushStageCache",
    "FlushStageAuthorizersCache",
    "CreateModel",
    "GetModel",
    "GetModels",
    "DeleteModel",
    "UpdateModel",
    "GetModelTemplate",
    "CreateRequestValidator",
    "GetRequestValidator",
    "GetRequestValidators",
    "DeleteRequestValidator",
    "UpdateRequestValidator",
    "CreateAuthorizer",
    "GetAuthorizer",
    "GetAuthorizers",
    "DeleteAuthorizer",
    "UpdateAuthorizer",
    "CreateApiKey",
    "GetApiKey",
    "GetApiKeys",
    "DeleteApiKey",
    "UpdateApiKey",
    "CreateUsagePlan",
    "GetUsagePlan",
    "GetUsagePlans",
    "DeleteUsagePlan",
    "UpdateUsagePlan",
    "CreateUsagePlanKey",
    "GetUsagePlanKey",
    "GetUsagePlanKeys",
    "DeleteUsagePlanKey",
    "GetUsage",
    "UpdateUsage",
    "CreateVpcLink",
    "GetVpcLink",
    "GetVpcLinks",
    "DeleteVpcLink",
    "UpdateVpcLink",
    "CreateDomainName",
    "GetDomainName",
    "GetDomainNames",
    "DeleteDomainName",
    "UpdateDomainName",
    "CreateBasePathMapping",
    "GetBasePathMapping",
    "GetBasePathMappings",
    "DeleteBasePathMapping",
    "UpdateBasePathMapping",
    "GenerateClientCertificate",
    "GetClientCertificate",
    "GetClientCertificates",
    "DeleteClientCertificate",
    "UpdateClientCertificate",
    "CreateDocumentationPart",
    "GetDocumentationPart",
    "GetDocumentationParts",
    "DeleteDocumentationPart",
    "UpdateDocumentationPart",
    "CreateDocumentationVersion",
    "GetDocumentationVersion",
    "GetDocumentationVersions",
    "DeleteDocumentationVersion",
    "UpdateDocumentationVersion",
    "PutGatewayResponse",
    "GetGatewayResponse",
    "GetGatewayResponses",
    "DeleteGatewayResponse",
    "UpdateGatewayResponse",
    "GetExport",
    "GetSdk",
    "GetSdkType",
    "GetSdkTypes",
    "TagResource",
    "UntagResource",
    "GetTags",
];

pub struct ApiGatewayService {
    pub(crate) state: SharedApiGatewayState,
    delivery: Option<Arc<DeliveryBus>>,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    snapshot_lock: Arc<AsyncMutex<()>>,
}

impl ApiGatewayService {
    pub fn new(state: SharedApiGatewayState) -> Self {
        Self {
            state,
            delivery: None,
            snapshot_store: None,
            snapshot_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    pub fn with_delivery(mut self, delivery: Arc<DeliveryBus>) -> Self {
        self.delivery = Some(delivery);
        self
    }

    pub fn with_snapshot_store(mut self, store: Arc<dyn SnapshotStore>) -> Self {
        self.snapshot_store = Some(store);
        self
    }

    pub(crate) fn delivery(&self) -> Option<&Arc<DeliveryBus>> {
        self.delivery.as_ref()
    }

    pub fn state_handle(&self) -> &SharedApiGatewayState {
        &self.state
    }

    pub(crate) fn record_request(
        &self,
        account_id: &str,
        api_id: &str,
        stage: &str,
        req: &AwsRequest,
        status: StatusCode,
    ) {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        state.request_history.push(crate::state::ApiRequest {
            api_id: api_id.to_string(),
            stage: stage.to_string(),
            method: req.method.as_str().to_string(),
            path: req.raw_path.clone(),
            status: status.as_u16(),
            created_at: chrono::Utc::now(),
        });
        if state.request_history.len() > 1000 {
            let drop = state.request_history.len() - 1000;
            state.request_history.drain(..drop);
        }
    }

    async fn save_snapshot(&self) {
        let Some(store) = self.snapshot_store.clone() else {
            return;
        };
        let _guard = self.snapshot_lock.lock().await;
        let snapshot = ApiGatewaySnapshot {
            schema_version: APIGATEWAY_SNAPSHOT_SCHEMA_VERSION,
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
            Ok(Err(err)) => tracing::error!(%err, "failed to write apigateway snapshot"),
            Err(err) => tracing::error!(%err, "apigateway snapshot task panicked"),
        }
    }
}

fn not_found(msg: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(StatusCode::NOT_FOUND, "NotFoundException", msg.into())
}

fn bad_request(msg: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(StatusCode::BAD_REQUEST, "BadRequestException", msg.into())
}

fn conflict(msg: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(StatusCode::CONFLICT, "ConflictException", msg.into())
}

fn ok(value: Value) -> Result<AwsResponse, AwsServiceError> {
    Ok(AwsResponse::ok_json(strip_nulls_deep(value)))
}

fn ok_status(status: StatusCode, value: Value) -> Result<AwsResponse, AwsServiceError> {
    Ok(AwsResponse::json(
        status,
        serde_json::to_vec(&strip_nulls_deep(value)).unwrap(),
    ))
}

/// Recursively strip null fields from objects (and from objects nested in
/// arrays/maps). AWS clients typed-decode optional members and reject
/// `null` for non-nullable types, so it's safer to omit absent fields
/// than to send them as `null`.
fn strip_nulls_deep(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, v) in map {
                if v.is_null() {
                    continue;
                }
                out.insert(k, strip_nulls_deep(v));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(strip_nulls_deep).collect()),
        other => other,
    }
}

fn ok_no_content() -> Result<AwsResponse, AwsServiceError> {
    Ok(AwsResponse {
        status: StatusCode::ACCEPTED,
        content_type: "application/json".to_string(),
        body: bytes::Bytes::new().into(),
        headers: http::HeaderMap::new(),
    })
}

fn method_key(api: &str, res: &str, m: &str) -> String {
    format!("{api}/{res}/{}", m.to_uppercase())
}

fn response_key(api: &str, res: &str, m: &str, code: &str) -> String {
    format!("{api}/{res}/{}/{}", m.to_uppercase(), code)
}

fn request_account(req: &AwsRequest) -> String {
    req.account_id.clone()
}

/// AWS REST-JSON omits optional fields whose runtime value is unset.
/// Smithy clients reject `null` for typed members (string, integer, …).
/// Strip null members from a JSON object before serializing it.
fn strip_nulls(mut value: Value) -> Value {
    if let Some(map) = value.as_object_mut() {
        let keys: Vec<String> = map
            .iter()
            .filter(|(_, v)| v.is_null())
            .map(|(k, _)| k.clone())
            .collect();
        for k in keys {
            map.remove(&k);
        }
    }
    value
}

fn rest_api_to_json(api: &RestApi) -> Value {
    strip_nulls(json!({
        "id": api.id,
        "name": api.name,
        "description": api.description,
        "version": api.version,
        "createdDate": api.created_date.timestamp(),
        "apiKeySource": api.api_key_source,
        "endpointConfiguration": api.endpoint_configuration,
        "policy": api.policy,
        "binaryMediaTypes": api.binary_media_types,
        "minimumCompressionSize": api.minimum_compression_size,
        "disableExecuteApiEndpoint": api.disable_execute_api_endpoint,
        "rootResourceId": api.root_resource_id,
        "tags": api.tags,
    }))
}

fn resource_to_json(r: &Resource, methods: HashMap<String, Value>) -> Value {
    let mut v = strip_nulls(json!({
        "id": r.id,
        "parentId": r.parent_id,
        "pathPart": r.path_part,
        "path": r.path,
    }));
    if !methods.is_empty() {
        v["resourceMethods"] = json!(methods);
    }
    v
}

fn method_to_json(m: &ApiMethod) -> Value {
    strip_nulls(json!({
        "httpMethod": m.http_method,
        "authorizationType": m.authorization_type,
        "authorizerId": m.authorizer_id,
        "apiKeyRequired": m.api_key_required,
        "operationName": m.operation_name,
        "requestParameters": m.request_parameters,
        "requestModels": m.request_models,
        "requestValidatorId": m.request_validator_id,
        "authorizationScopes": m.authorization_scopes,
    }))
}

fn integration_to_json(i: &Integration) -> Value {
    strip_nulls(json!({
        "type": i.integration_type,
        "httpMethod": i.integration_http_method,
        "uri": i.uri,
        "credentials": i.credentials,
        "requestParameters": i.request_parameters,
        "requestTemplates": i.request_templates,
        "passthroughBehavior": i.passthrough_behavior,
        "timeoutInMillis": i.timeout_in_millis,
        "cacheNamespace": i.cache_namespace,
        "cacheKeyParameters": i.cache_key_parameters,
        "contentHandling": i.content_handling,
        "connectionType": i.connection_type,
        "connectionId": i.connection_id,
        "tlsConfig": i.tls_config,
    }))
}

fn deployment_to_json(d: &Deployment) -> Value {
    strip_nulls(json!({
        "id": d.id,
        "description": d.description,
        "createdDate": d.created_date.timestamp(),
        "apiSummary": d.api_summary,
    }))
}

fn stage_to_json(s: &Stage) -> Value {
    strip_nulls(json!({
        "stageName": s.stage_name,
        "deploymentId": s.deployment_id,
        "description": s.description,
        "cacheClusterEnabled": s.cache_cluster_enabled,
        "cacheClusterSize": s.cache_cluster_size,
        "variables": s.variables,
        "methodSettings": s.method_settings,
        "createdDate": s.created_date.timestamp(),
        "lastUpdatedDate": s.last_updated_date.timestamp(),
        "tracingEnabled": s.tracing_enabled,
        "webAclArn": s.web_acl_arn,
        "canarySettings": s.canary_settings,
        "accessLogSettings": s.access_log_settings,
        "tags": s.tags,
    }))
}

fn model_to_json(m: &Model) -> Value {
    strip_nulls(json!({
        "id": m.id,
        "name": m.name,
        "description": m.description,
        "schema": m.schema,
        "contentType": m.content_type,
    }))
}

fn authorizer_to_json(a: &Authorizer) -> Value {
    strip_nulls(json!({
        "id": a.id,
        "name": a.name,
        "type": a.authorizer_type,
        "providerARNs": a.provider_arns,
        "authType": a.auth_type,
        "authorizerUri": a.authorizer_uri,
        "authorizerCredentials": a.authorizer_credentials,
        "identitySource": a.identity_source,
        "identityValidationExpression": a.identity_validation_expression,
        "authorizerResultTtlInSeconds": a.authorizer_result_ttl_in_seconds,
    }))
}

fn api_key_to_json(k: &ApiKey, include_value: bool) -> Value {
    let mut v = strip_nulls(json!({
        "id": k.id,
        "name": k.name,
        "description": k.description,
        "enabled": k.enabled,
        "createdDate": k.created_date.timestamp(),
        "lastUpdatedDate": k.last_updated_date.timestamp(),
        "stageKeys": k.stage_keys,
        "tags": k.tags,
        "customerId": k.customer_id,
    }));
    if include_value {
        v["value"] = Value::String(k.value.clone());
    }
    v
}

fn usage_plan_to_json(p: &UsagePlan) -> Value {
    strip_nulls(json!({
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "apiStages": p.api_stages,
        "throttle": p.throttle,
        "quota": p.quota,
        "productCode": p.product_code,
        "tags": p.tags,
    }))
}

#[async_trait]
impl fakecloud_core::service::AwsService for ApiGatewayService {
    fn service_name(&self) -> &str {
        "apigatewayv1"
    }

    fn supported_actions(&self) -> &[&str] {
        SUPPORTED_ACTIONS
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        // Identify whether this is a control-plane request (matches one
        // of the known REST routes) or a data-plane execute call.
        if let Some(resolved) = resolve(&req.method, &req.path_segments, &req.query_params) {
            let res = self.handle_control(&req, resolved).await;
            if res.is_ok() && is_mutating_method(&req.method) {
                self.save_snapshot().await;
            }
            return res;
        }
        // Fallback: data-plane invocation.
        crate::data_plane::handle(self, &req).await
    }
}

fn is_mutating_method(method: &Method) -> bool {
    matches!(
        *method,
        Method::POST | Method::PUT | Method::PATCH | Method::DELETE
    )
}

impl ApiGatewayService {
    async fn handle_control(
        &self,
        req: &AwsRequest,
        ResolvedAction { action, params }: ResolvedAction,
    ) -> Result<AwsResponse, AwsServiceError> {
        match action {
            "GetAccount" => self.get_account(req),
            "UpdateAccount" => self.update_account(req),
            "CreateRestApi" => self.create_rest_api(req),
            "GetRestApi" => self.get_rest_api(req, &params),
            "GetRestApis" => self.get_rest_apis(req),
            "DeleteRestApi" => self.delete_rest_api(req, &params),
            "UpdateRestApi" => self.update_rest_api(req, &params),
            "PutRestApi" => self.put_rest_api(req, &params),
            "ImportRestApi" => self.import_rest_api(req),
            "CreateResource" => self.create_resource(req, &params),
            "GetResource" => self.get_resource(req, &params),
            "GetResources" => self.get_resources(req, &params),
            "DeleteResource" => self.delete_resource(req, &params),
            "UpdateResource" => self.update_resource(req, &params),
            "PutMethod" => self.put_method(req, &params),
            "GetMethod" => self.get_method(req, &params),
            "DeleteMethod" => self.delete_method(req, &params),
            "UpdateMethod" => self.update_method(req, &params),
            "PutMethodResponse" => self.put_method_response(req, &params),
            "GetMethodResponse" => self.get_method_response(req, &params),
            "DeleteMethodResponse" => self.delete_method_response(req, &params),
            "UpdateMethodResponse" => self.update_method_response(req, &params),
            "PutIntegration" => self.put_integration(req, &params),
            "GetIntegration" => self.get_integration(req, &params),
            "DeleteIntegration" => self.delete_integration(req, &params),
            "UpdateIntegration" => self.update_integration(req, &params),
            "PutIntegrationResponse" => self.put_integration_response(req, &params),
            "GetIntegrationResponse" => self.get_integration_response(req, &params),
            "DeleteIntegrationResponse" => self.delete_integration_response(req, &params),
            "UpdateIntegrationResponse" => self.update_integration_response(req, &params),
            "TestInvokeMethod" => self.test_invoke_method(req, &params).await,
            "TestInvokeAuthorizer" => self.test_invoke_authorizer(req, &params),
            "CreateDeployment" => self.create_deployment(req, &params),
            "GetDeployment" => self.get_deployment(req, &params),
            "GetDeployments" => self.get_deployments(req, &params),
            "DeleteDeployment" => self.delete_deployment(req, &params),
            "UpdateDeployment" => self.update_deployment(req, &params),
            "CreateStage" => self.create_stage(req, &params),
            "GetStage" => self.get_stage(req, &params),
            "GetStages" => self.get_stages(req, &params),
            "DeleteStage" => self.delete_stage(req, &params),
            "UpdateStage" => self.update_stage(req, &params),
            "FlushStageCache" => ok_no_content(),
            "FlushStageAuthorizersCache" => ok_no_content(),
            "CreateModel" => self.create_model(req, &params),
            "GetModel" => self.get_model(req, &params),
            "GetModels" => self.get_models(req, &params),
            "DeleteModel" => self.delete_model(req, &params),
            "UpdateModel" => self.update_model(req, &params),
            "GetModelTemplate" => self.get_model_template(req, &params),
            "CreateRequestValidator" => self.create_request_validator(req, &params),
            "GetRequestValidator" => self.get_request_validator(req, &params),
            "GetRequestValidators" => self.get_request_validators(req, &params),
            "DeleteRequestValidator" => self.delete_request_validator(req, &params),
            "UpdateRequestValidator" => self.update_request_validator(req, &params),
            "CreateAuthorizer" => self.create_authorizer(req, &params),
            "GetAuthorizer" => self.get_authorizer(req, &params),
            "GetAuthorizers" => self.get_authorizers(req, &params),
            "DeleteAuthorizer" => self.delete_authorizer(req, &params),
            "UpdateAuthorizer" => self.update_authorizer(req, &params),
            "CreateApiKey" => self.create_api_key(req),
            "GetApiKey" => self.get_api_key(req, &params),
            "GetApiKeys" => self.get_api_keys(req),
            "DeleteApiKey" => self.delete_api_key(req, &params),
            "UpdateApiKey" => self.update_api_key(req, &params),
            "CreateUsagePlan" => self.create_usage_plan(req),
            "GetUsagePlan" => self.get_usage_plan(req, &params),
            "GetUsagePlans" => self.get_usage_plans(req),
            "DeleteUsagePlan" => self.delete_usage_plan(req, &params),
            "UpdateUsagePlan" => self.update_usage_plan(req, &params),
            "CreateUsagePlanKey" => self.create_usage_plan_key(req, &params),
            "GetUsagePlanKey" => self.get_usage_plan_key(req, &params),
            "GetUsagePlanKeys" => self.get_usage_plan_keys(req, &params),
            "DeleteUsagePlanKey" => self.delete_usage_plan_key(req, &params),
            "GetUsage" => self.get_usage(req, &params),
            "UpdateUsage" => ok(json!({})),
            "CreateVpcLink" => self.create_vpc_link(req),
            "GetVpcLink" => self.get_vpc_link(req, &params),
            "GetVpcLinks" => self.get_vpc_links(req),
            "DeleteVpcLink" => self.delete_vpc_link(req, &params),
            "UpdateVpcLink" => self.update_vpc_link(req, &params),
            "CreateDomainName" => self.create_domain_name(req),
            "GetDomainName" => self.get_domain_name(req, &params),
            "GetDomainNames" => self.get_domain_names(req),
            "DeleteDomainName" => self.delete_domain_name(req, &params),
            "UpdateDomainName" => self.update_domain_name(req, &params),
            "CreateBasePathMapping" => self.create_base_path_mapping(req, &params),
            "GetBasePathMapping" => self.get_base_path_mapping(req, &params),
            "GetBasePathMappings" => self.get_base_path_mappings(req, &params),
            "DeleteBasePathMapping" => self.delete_base_path_mapping(req, &params),
            "UpdateBasePathMapping" => self.update_base_path_mapping(req, &params),
            "GenerateClientCertificate" => self.generate_client_cert(req),
            "GetClientCertificate" => self.get_client_cert(req, &params),
            "GetClientCertificates" => self.get_client_certs(req),
            "DeleteClientCertificate" => self.delete_client_cert(req, &params),
            "UpdateClientCertificate" => self.update_client_cert(req, &params),
            "CreateDocumentationPart" => self.create_doc_part(req, &params),
            "GetDocumentationPart" => self.get_doc_part(req, &params),
            "GetDocumentationParts" => self.get_doc_parts(req, &params),
            "DeleteDocumentationPart" => self.delete_doc_part(req, &params),
            "UpdateDocumentationPart" => self.update_doc_part(req, &params),
            "CreateDocumentationVersion" => self.create_doc_version(req, &params),
            "GetDocumentationVersion" => self.get_doc_version(req, &params),
            "GetDocumentationVersions" => self.get_doc_versions(req, &params),
            "DeleteDocumentationVersion" => self.delete_doc_version(req, &params),
            "UpdateDocumentationVersion" => self.update_doc_version(req, &params),
            "PutGatewayResponse" => self.put_gateway_response(req, &params),
            "GetGatewayResponse" => self.get_gateway_response(req, &params),
            "GetGatewayResponses" => self.get_gateway_responses(req, &params),
            "DeleteGatewayResponse" => self.delete_gateway_response(req, &params),
            "UpdateGatewayResponse" => self.update_gateway_response(req, &params),
            "GetExport" => self.get_export(req, &params),
            "GetSdk" => self.get_sdk(req, &params),
            "GetSdkType" => ok(
                json!({"id": params.get("id"), "friendlyName": "Stub", "configurationProperties": []}),
            ),
            "GetSdkTypes" => ok(json!({
                "item": [
                    {"id": "java", "friendlyName": "Java"},
                    {"id": "javascript", "friendlyName": "JavaScript"},
                    {"id": "android", "friendlyName": "Android"},
                    {"id": "objectivec", "friendlyName": "Objective-C"},
                    {"id": "swift", "friendlyName": "Swift"},
                    {"id": "ruby", "friendlyName": "Ruby"},
                ]
            })),
            "TagResource" => self.tag_resource(req, &params),
            "UntagResource" => self.untag_resource(req, &params),
            "GetTags" => self.get_tags(req, &params),
            _ => Err(AwsServiceError::ActionNotImplemented {
                service: "apigateway".to_string(),
                action: action.to_string(),
            }),
        }
    }

    // ── Account ──

    fn get_account(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        ok(state.account_settings.clone())
    }

    fn update_account(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        if let Ok(patch) = serde_json::from_slice::<Value>(&req.body) {
            if let (Some(target), Some(extras)) =
                (state.account_settings.as_object_mut(), patch.as_object())
            {
                for (k, v) in extras {
                    target.insert(k.clone(), v.clone());
                }
            }
        }
        ok(state.account_settings.clone())
    }

    // ── REST APIs ──

    fn create_rest_api(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = body
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| bad_request("name is required"))?
            .to_string();
        let id = make_id();
        let root_id = make_id();
        let api = RestApi {
            id: id.clone(),
            name,
            description: body
                .get("description")
                .and_then(Value::as_str)
                .map(String::from),
            version: body
                .get("version")
                .and_then(Value::as_str)
                .map(String::from),
            created_date: chrono::Utc::now(),
            api_key_source: body
                .get("apiKeySource")
                .and_then(Value::as_str)
                .unwrap_or("HEADER")
                .to_string(),
            endpoint_configuration: body
                .get("endpointConfiguration")
                .cloned()
                .unwrap_or_else(|| json!({"types": ["EDGE"]})),
            policy: body.get("policy").and_then(Value::as_str).map(String::from),
            binary_media_types: body
                .get("binaryMediaTypes")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default(),
            minimum_compression_size: body.get("minimumCompressionSize").and_then(Value::as_i64),
            disable_execute_api_endpoint: body
                .get("disableExecuteApiEndpoint")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            root_resource_id: root_id.clone(),
            tags: tags_from(&body),
            import_source: None,
        };
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        state.apis.insert(id.clone(), api.clone());
        // The root resource exists implicitly with path "/".
        let root = Resource {
            id: root_id,
            parent_id: None,
            path_part: None,
            path: "/".to_string(),
        };
        let mut res_map = HashMap::new();
        res_map.insert(root.id.clone(), root);
        state.resources.insert(id, res_map);
        ok_status(StatusCode::CREATED, rest_api_to_json(&api))
    }

    fn get_rest_api(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = params.get("restApiId").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let state = accounts
            .get(&request_account(req))
            .ok_or_else(|| not_found(format!("RestApi {id} not found")))?;
        let api = state
            .apis
            .get(&id)
            .ok_or_else(|| not_found(format!("RestApi {id} not found")))?;
        ok(rest_api_to_json(api))
    }

    fn get_rest_apis(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let items: Vec<Value> = match accounts.get(&request_account(req)) {
            Some(state) => state.apis.values().map(rest_api_to_json).collect(),
            None => Vec::new(),
        };
        ok(json!({"item": items}))
    }

    fn delete_rest_api(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = params.get("restApiId").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        if state.apis.remove(&id).is_none() {
            return Err(not_found(format!("RestApi {id} not found")));
        }
        state.resources.remove(&id);
        state.deployments.remove(&id);
        state.stages.remove(&id);
        state.models.remove(&id);
        state.request_validators.remove(&id);
        state.authorizers.remove(&id);
        state.documentation_parts.remove(&id);
        state.documentation_versions.remove(&id);
        state.gateway_responses.remove(&id);
        state
            .methods
            .retain(|k, _| !k.starts_with(&format!("{id}/")));
        state
            .integrations
            .retain(|k, _| !k.starts_with(&format!("{id}/")));
        state
            .method_responses
            .retain(|k, _| !k.starts_with(&format!("{id}/")));
        state
            .integration_responses
            .retain(|k, _| !k.starts_with(&format!("{id}/")));
        ok_no_content()
    }

    fn update_rest_api(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = params.get("restApiId").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let api = state
            .apis
            .get_mut(&id)
            .ok_or_else(|| not_found(format!("RestApi {id} not found")))?;
        apply_patch_operations(req, |op, path, value| {
            apply_rest_api_patch(api, op, path, value);
        });
        ok(rest_api_to_json(api))
    }

    fn put_rest_api(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = params.get("restApiId").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let api = state
            .apis
            .get_mut(&id)
            .ok_or_else(|| not_found(format!("RestApi {id} not found")))?;
        api.import_source = Some(String::from_utf8_lossy(&req.body).to_string());
        ok(rest_api_to_json(api))
    }

    fn import_rest_api(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let id = make_id();
        let root_id = make_id();
        let api = RestApi {
            id: id.clone(),
            name: format!("imported-{id}"),
            description: None,
            version: None,
            created_date: chrono::Utc::now(),
            api_key_source: "HEADER".to_string(),
            endpoint_configuration: json!({"types": ["EDGE"]}),
            policy: None,
            binary_media_types: Vec::new(),
            minimum_compression_size: None,
            disable_execute_api_endpoint: false,
            root_resource_id: root_id.clone(),
            tags: HashMap::new(),
            import_source: Some(String::from_utf8_lossy(&req.body).to_string()),
        };
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        state.apis.insert(id.clone(), api.clone());
        let mut res_map = HashMap::new();
        res_map.insert(
            root_id.clone(),
            Resource {
                id: root_id,
                parent_id: None,
                path_part: None,
                path: "/".to_string(),
            },
        );
        state.resources.insert(id, res_map);
        ok_status(StatusCode::CREATED, rest_api_to_json(&api))
    }

    // ── Resources ──

    fn create_resource(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let parent_id = params.get("parentId").cloned().unwrap_or_default();
        let body = req.json_body();
        let path_part = body
            .get("pathPart")
            .and_then(Value::as_str)
            .ok_or_else(|| bad_request("pathPart is required"))?
            .to_string();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        if !state.apis.contains_key(&api_id) {
            return Err(not_found(format!("RestApi {api_id} not found")));
        }
        let resources = state.resources.entry(api_id.clone()).or_default();
        let parent = resources
            .get(&parent_id)
            .cloned()
            .ok_or_else(|| not_found(format!("Resource {parent_id} not found")))?;
        let path = if parent.path == "/" {
            format!("/{path_part}")
        } else {
            format!("{}/{path_part}", parent.path)
        };
        // Reject duplicate.
        if resources.values().any(|r| r.path == path) {
            return Err(conflict(format!("Resource at {path} already exists")));
        }
        let id = make_id();
        let resource = Resource {
            id: id.clone(),
            parent_id: Some(parent_id),
            path_part: Some(path_part),
            path,
        };
        resources.insert(id, resource.clone());
        ok_status(
            StatusCode::CREATED,
            resource_to_json(&resource, HashMap::new()),
        )
    }

    fn get_resource(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let id = params.get("resourceId").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let state = accounts
            .get(&request_account(req))
            .ok_or_else(|| not_found(format!("RestApi {api_id} not found")))?;
        let resources = state
            .resources
            .get(&api_id)
            .ok_or_else(|| not_found(format!("RestApi {api_id} not found")))?;
        let r = resources
            .get(&id)
            .ok_or_else(|| not_found(format!("Resource {id} not found")))?;
        let methods = methods_for_resource(state, &api_id, &id);
        ok(resource_to_json(r, methods))
    }

    fn get_resources(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let state = accounts
            .get(&request_account(req))
            .ok_or_else(|| not_found(format!("RestApi {api_id} not found")))?;
        let resources = state
            .resources
            .get(&api_id)
            .ok_or_else(|| not_found(format!("RestApi {api_id} not found")))?;
        let items: Vec<Value> = resources
            .values()
            .map(|r| resource_to_json(r, methods_for_resource(state, &api_id, &r.id)))
            .collect();
        ok(json!({"item": items}))
    }

    fn delete_resource(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let id = params.get("resourceId").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let resources = state
            .resources
            .get_mut(&api_id)
            .ok_or_else(|| not_found(format!("RestApi {api_id} not found")))?;
        if resources.remove(&id).is_none() {
            return Err(not_found(format!("Resource {id} not found")));
        }
        let prefix = format!("{api_id}/{id}/");
        state.methods.retain(|k, _| !k.starts_with(&prefix));
        state.integrations.retain(|k, _| !k.starts_with(&prefix));
        state
            .method_responses
            .retain(|k, _| !k.starts_with(&prefix));
        state
            .integration_responses
            .retain(|k, _| !k.starts_with(&prefix));
        ok_no_content()
    }

    fn update_resource(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let id = params.get("resourceId").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let resources = state
            .resources
            .get_mut(&api_id)
            .ok_or_else(|| not_found(format!("RestApi {api_id} not found")))?;
        let resource = resources
            .get_mut(&id)
            .ok_or_else(|| not_found(format!("Resource {id} not found")))?;
        apply_patch_operations(req, |op, path, value| {
            if path == "/pathPart" && op == "replace" {
                if let Some(s) = value.as_str() {
                    resource.path_part = Some(s.to_string());
                }
            }
        });
        ok(resource_to_json(resource, HashMap::new()))
    }

    // ── Methods ──

    fn put_method(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let res_id = params.get("resourceId").cloned().unwrap_or_default();
        let http_method = params.get("httpMethod").cloned().unwrap_or_default();
        let body = req.json_body();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let m = ApiMethod {
            rest_api_id: api_id.clone(),
            resource_id: res_id.clone(),
            http_method: http_method.to_uppercase(),
            authorization_type: body
                .get("authorizationType")
                .and_then(Value::as_str)
                .unwrap_or("NONE")
                .to_string(),
            authorizer_id: body
                .get("authorizerId")
                .and_then(Value::as_str)
                .map(String::from),
            api_key_required: body
                .get("apiKeyRequired")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            operation_name: body
                .get("operationName")
                .and_then(Value::as_str)
                .map(String::from),
            request_parameters: body
                .get("requestParameters")
                .and_then(Value::as_object)
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| v.as_bool().map(|b| (k.clone(), b)))
                        .collect()
                })
                .unwrap_or_default(),
            request_models: body
                .get("requestModels")
                .and_then(Value::as_object)
                .map(|m| {
                    m.iter()
                        .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                        .collect()
                })
                .unwrap_or_default(),
            request_validator_id: body
                .get("requestValidatorId")
                .and_then(Value::as_str)
                .map(String::from),
            authorization_scopes: body
                .get("authorizationScopes")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default(),
        };
        state
            .methods
            .insert(method_key(&api_id, &res_id, &http_method), m.clone());
        ok_status(StatusCode::CREATED, method_to_json(&m))
    }

    fn get_method(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let key = method_key(
            params.get("restApiId").map(|s| s.as_str()).unwrap_or(""),
            params.get("resourceId").map(|s| s.as_str()).unwrap_or(""),
            params.get("httpMethod").map(|s| s.as_str()).unwrap_or(""),
        );
        let accounts = self.state.read();
        let state = accounts
            .get(&request_account(req))
            .ok_or_else(|| not_found("Method not found"))?;
        let m = state
            .methods
            .get(&key)
            .ok_or_else(|| not_found("Method not found"))?;
        ok(method_to_json(m))
    }

    fn delete_method(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let key = method_key(
            params.get("restApiId").map(|s| s.as_str()).unwrap_or(""),
            params.get("resourceId").map(|s| s.as_str()).unwrap_or(""),
            params.get("httpMethod").map(|s| s.as_str()).unwrap_or(""),
        );
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        if state.methods.remove(&key).is_none() {
            return Err(not_found("Method not found"));
        }
        state.integrations.remove(&key);
        let prefix = format!("{key}/");
        state
            .method_responses
            .retain(|k, _| !k.starts_with(&prefix));
        state
            .integration_responses
            .retain(|k, _| !k.starts_with(&prefix));
        ok_no_content()
    }

    fn update_method(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let key = method_key(
            params.get("restApiId").map(|s| s.as_str()).unwrap_or(""),
            params.get("resourceId").map(|s| s.as_str()).unwrap_or(""),
            params.get("httpMethod").map(|s| s.as_str()).unwrap_or(""),
        );
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let m = state
            .methods
            .get_mut(&key)
            .ok_or_else(|| not_found("Method not found"))?;
        apply_patch_operations(req, |op, path, value| {
            apply_method_patch(m, op, path, value);
        });
        ok(method_to_json(m))
    }

    fn put_method_response(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let key = response_key(
            params.get("restApiId").map(|s| s.as_str()).unwrap_or(""),
            params.get("resourceId").map(|s| s.as_str()).unwrap_or(""),
            params.get("httpMethod").map(|s| s.as_str()).unwrap_or(""),
            params.get("statusCode").map(|s| s.as_str()).unwrap_or(""),
        );
        let mut payload = req.json_body();
        if let Some(o) = payload.as_object_mut() {
            o.insert(
                "statusCode".to_string(),
                json!(params.get("statusCode").cloned().unwrap_or_default()),
            );
        }
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        state.method_responses.insert(key, payload.clone());
        ok_status(StatusCode::CREATED, payload)
    }

    fn get_method_response(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let key = response_key(
            params.get("restApiId").map(|s| s.as_str()).unwrap_or(""),
            params.get("resourceId").map(|s| s.as_str()).unwrap_or(""),
            params.get("httpMethod").map(|s| s.as_str()).unwrap_or(""),
            params.get("statusCode").map(|s| s.as_str()).unwrap_or(""),
        );
        let accounts = self.state.read();
        let state = accounts
            .get(&request_account(req))
            .ok_or_else(|| not_found("MethodResponse not found"))?;
        let v = state
            .method_responses
            .get(&key)
            .cloned()
            .ok_or_else(|| not_found("MethodResponse not found"))?;
        ok(v)
    }

    fn delete_method_response(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let key = response_key(
            params.get("restApiId").map(|s| s.as_str()).unwrap_or(""),
            params.get("resourceId").map(|s| s.as_str()).unwrap_or(""),
            params.get("httpMethod").map(|s| s.as_str()).unwrap_or(""),
            params.get("statusCode").map(|s| s.as_str()).unwrap_or(""),
        );
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        if state.method_responses.remove(&key).is_none() {
            return Err(not_found("MethodResponse not found"));
        }
        ok_no_content()
    }

    fn update_method_response(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let key = response_key(
            params.get("restApiId").map(|s| s.as_str()).unwrap_or(""),
            params.get("resourceId").map(|s| s.as_str()).unwrap_or(""),
            params.get("httpMethod").map(|s| s.as_str()).unwrap_or(""),
            params.get("statusCode").map(|s| s.as_str()).unwrap_or(""),
        );
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let v = state
            .method_responses
            .get_mut(&key)
            .ok_or_else(|| not_found("MethodResponse not found"))?;
        apply_patch_operations(req, |_op, path, value| {
            if let Some(o) = v.as_object_mut() {
                o.insert(path.trim_start_matches('/').to_string(), value.clone());
            }
        });
        ok(v.clone())
    }
}

fn methods_for_resource(
    state: &ApiGatewayState,
    api_id: &str,
    res_id: &str,
) -> HashMap<String, Value> {
    let mut out = HashMap::new();
    let prefix = format!("{api_id}/{res_id}/");
    for (key, m) in &state.methods {
        if let Some(rest) = key.strip_prefix(&prefix) {
            out.insert(rest.to_string(), method_to_json(m));
        }
    }
    out
}

fn tags_from(body: &Value) -> HashMap<String, String> {
    body.get("tags")
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

fn apply_patch_operations(req: &AwsRequest, mut on: impl FnMut(&str, &str, &Value)) {
    let body = req.json_body();
    let ops = body.get("patchOperations").and_then(Value::as_array);
    if let Some(arr) = ops {
        for entry in arr {
            let op = entry.get("op").and_then(Value::as_str).unwrap_or("");
            let path = entry.get("path").and_then(Value::as_str).unwrap_or("");
            let value = entry.get("value").cloned().unwrap_or(Value::Null);
            on(op, path, &value);
        }
    }
}

fn apply_rest_api_patch(api: &mut RestApi, op: &str, path: &str, value: &Value) {
    if op != "replace" && op != "add" {
        return;
    }
    match path {
        "/name" => {
            if let Some(s) = value.as_str() {
                api.name = s.to_string();
            }
        }
        "/description" => api.description = value.as_str().map(String::from),
        "/version" => api.version = value.as_str().map(String::from),
        "/policy" => api.policy = value.as_str().map(String::from),
        "/disableExecuteApiEndpoint" => {
            if let Some(b) = value.as_bool() {
                api.disable_execute_api_endpoint = b;
            }
        }
        "/apiKeySource" => {
            if let Some(s) = value.as_str() {
                api.api_key_source = s.to_string();
            }
        }
        _ => {}
    }
}

fn apply_method_patch(m: &mut ApiMethod, op: &str, path: &str, value: &Value) {
    if op != "replace" && op != "add" {
        return;
    }
    match path {
        "/authorizationType" => {
            if let Some(s) = value.as_str() {
                m.authorization_type = s.to_string();
            }
        }
        "/authorizerId" => m.authorizer_id = value.as_str().map(String::from),
        "/apiKeyRequired" => {
            if let Some(b) = value.as_bool() {
                m.api_key_required = b;
            }
        }
        "/operationName" => m.operation_name = value.as_str().map(String::from),
        _ => {}
    }
}

// ── Integration handlers ──

impl ApiGatewayService {
    fn put_integration(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let res_id = params.get("resourceId").cloned().unwrap_or_default();
        let http_method = params.get("httpMethod").cloned().unwrap_or_default();
        let body = req.json_body();
        let integration_type = body
            .get("type")
            .and_then(Value::as_str)
            .ok_or_else(|| bad_request("type is required"))?
            .to_string();
        let integration = Integration {
            rest_api_id: api_id.clone(),
            resource_id: res_id.clone(),
            http_method: http_method.to_uppercase(),
            integration_type,
            integration_http_method: body
                .get("httpMethod")
                .and_then(Value::as_str)
                .map(String::from),
            uri: body.get("uri").and_then(Value::as_str).map(String::from),
            credentials: body
                .get("credentials")
                .and_then(Value::as_str)
                .map(String::from),
            request_parameters: extract_string_map(&body, "requestParameters"),
            request_templates: extract_string_map(&body, "requestTemplates"),
            passthrough_behavior: body
                .get("passthroughBehavior")
                .and_then(Value::as_str)
                .unwrap_or("WHEN_NO_MATCH")
                .to_string(),
            timeout_in_millis: body
                .get("timeoutInMillis")
                .and_then(Value::as_i64)
                .map(|v| v as i32),
            cache_namespace: body
                .get("cacheNamespace")
                .and_then(Value::as_str)
                .map(String::from),
            cache_key_parameters: body
                .get("cacheKeyParameters")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default(),
            content_handling: body
                .get("contentHandling")
                .and_then(Value::as_str)
                .map(String::from),
            connection_type: body
                .get("connectionType")
                .and_then(Value::as_str)
                .map(String::from),
            connection_id: body
                .get("connectionId")
                .and_then(Value::as_str)
                .map(String::from),
            tls_config: body.get("tlsConfig").cloned(),
        };
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        state.integrations.insert(
            method_key(&api_id, &res_id, &http_method),
            integration.clone(),
        );
        ok_status(StatusCode::CREATED, integration_to_json(&integration))
    }

    fn get_integration(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let key = method_key(
            params.get("restApiId").map(|s| s.as_str()).unwrap_or(""),
            params.get("resourceId").map(|s| s.as_str()).unwrap_or(""),
            params.get("httpMethod").map(|s| s.as_str()).unwrap_or(""),
        );
        let accounts = self.state.read();
        let state = accounts
            .get(&request_account(req))
            .ok_or_else(|| not_found("Integration not found"))?;
        let i = state
            .integrations
            .get(&key)
            .ok_or_else(|| not_found("Integration not found"))?;
        ok(integration_to_json(i))
    }

    fn delete_integration(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let key = method_key(
            params.get("restApiId").map(|s| s.as_str()).unwrap_or(""),
            params.get("resourceId").map(|s| s.as_str()).unwrap_or(""),
            params.get("httpMethod").map(|s| s.as_str()).unwrap_or(""),
        );
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        if state.integrations.remove(&key).is_none() {
            return Err(not_found("Integration not found"));
        }
        ok_no_content()
    }

    fn update_integration(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let key = method_key(
            params.get("restApiId").map(|s| s.as_str()).unwrap_or(""),
            params.get("resourceId").map(|s| s.as_str()).unwrap_or(""),
            params.get("httpMethod").map(|s| s.as_str()).unwrap_or(""),
        );
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let integration = state
            .integrations
            .get_mut(&key)
            .ok_or_else(|| not_found("Integration not found"))?;
        apply_patch_operations(req, |op, path, value| {
            if op != "replace" && op != "add" {
                return;
            }
            match path {
                "/uri" => integration.uri = value.as_str().map(String::from),
                "/type" => {
                    if let Some(s) = value.as_str() {
                        integration.integration_type = s.to_string();
                    }
                }
                "/timeoutInMillis" => {
                    integration.timeout_in_millis = value.as_i64().map(|v| v as i32);
                }
                _ => {}
            }
        });
        ok(integration_to_json(integration))
    }

    fn put_integration_response(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let key = response_key(
            params.get("restApiId").map(|s| s.as_str()).unwrap_or(""),
            params.get("resourceId").map(|s| s.as_str()).unwrap_or(""),
            params.get("httpMethod").map(|s| s.as_str()).unwrap_or(""),
            params.get("statusCode").map(|s| s.as_str()).unwrap_or(""),
        );
        let mut payload = req.json_body();
        if let Some(o) = payload.as_object_mut() {
            o.insert(
                "statusCode".to_string(),
                json!(params.get("statusCode").cloned().unwrap_or_default()),
            );
        }
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        state.integration_responses.insert(key, payload.clone());
        ok_status(StatusCode::CREATED, payload)
    }

    fn get_integration_response(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let key = response_key(
            params.get("restApiId").map(|s| s.as_str()).unwrap_or(""),
            params.get("resourceId").map(|s| s.as_str()).unwrap_or(""),
            params.get("httpMethod").map(|s| s.as_str()).unwrap_or(""),
            params.get("statusCode").map(|s| s.as_str()).unwrap_or(""),
        );
        let accounts = self.state.read();
        let state = accounts
            .get(&request_account(req))
            .ok_or_else(|| not_found("IntegrationResponse not found"))?;
        let v = state
            .integration_responses
            .get(&key)
            .cloned()
            .ok_or_else(|| not_found("IntegrationResponse not found"))?;
        ok(v)
    }

    fn delete_integration_response(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let key = response_key(
            params.get("restApiId").map(|s| s.as_str()).unwrap_or(""),
            params.get("resourceId").map(|s| s.as_str()).unwrap_or(""),
            params.get("httpMethod").map(|s| s.as_str()).unwrap_or(""),
            params.get("statusCode").map(|s| s.as_str()).unwrap_or(""),
        );
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        if state.integration_responses.remove(&key).is_none() {
            return Err(not_found("IntegrationResponse not found"));
        }
        ok_no_content()
    }

    fn update_integration_response(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let key = response_key(
            params.get("restApiId").map(|s| s.as_str()).unwrap_or(""),
            params.get("resourceId").map(|s| s.as_str()).unwrap_or(""),
            params.get("httpMethod").map(|s| s.as_str()).unwrap_or(""),
            params.get("statusCode").map(|s| s.as_str()).unwrap_or(""),
        );
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let v = state
            .integration_responses
            .get_mut(&key)
            .ok_or_else(|| not_found("IntegrationResponse not found"))?;
        apply_patch_operations(req, |_op, path, value| {
            if let Some(o) = v.as_object_mut() {
                o.insert(path.trim_start_matches('/').to_string(), value.clone());
            }
        });
        ok(v.clone())
    }

    async fn test_invoke_method(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        // The TestInvokeMethod operation drives the data plane through
        // an in-process call instead of an HTTP one. We mock the
        // request the way AWS does: read the body's `pathWithQueryString`,
        // build a synthetic AwsRequest, and run it through the data
        // plane handler.
        let body = req.json_body();
        let path_with_query = body
            .get("pathWithQueryString")
            .and_then(Value::as_str)
            .unwrap_or("/")
            .to_string();
        let test_method = params
            .get("httpMethod")
            .cloned()
            .unwrap_or_else(|| "GET".to_string());
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let stage = body
            .get("stageVariables")
            .and_then(Value::as_object)
            .and_then(|m| m.get("stage"))
            .and_then(Value::as_str)
            .unwrap_or("test")
            .to_string();
        let body_str = body
            .get("body")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();

        let started = std::time::Instant::now();
        // The synthetic request must use the method passed in `httpMethod`,
        // not POST (which is the wire method of TestInvokeMethod itself).
        let synthetic_method = test_method.parse::<Method>().unwrap_or(Method::GET);
        let synthetic = AwsRequest {
            service: "apigateway".to_string(),
            action: String::new(),
            method: synthetic_method,
            raw_path: format!("/{stage}{path_with_query}"),
            raw_query: String::new(),
            path_segments: build_path_segments(&stage, &path_with_query),
            query_params: HashMap::new(),
            headers: req.headers.clone(),
            body: bytes::Bytes::from(body_str.into_bytes()),
            account_id: req.account_id.clone(),
            region: req.region.clone(),
            request_id: req.request_id.clone(),
            is_query_protocol: false,
            access_key_id: req.access_key_id.clone(),
            principal: req.principal.clone(),
        };
        let _ = api_id;
        let response = match crate::data_plane::handle(self, &synthetic).await {
            Ok(r) => r,
            Err(e) => {
                return Ok(AwsResponse::ok_json(json!({
                    "status": e.status().as_u16(),
                    "body": e.to_string(),
                    "log": "TestInvokeMethod failed",
                    "latency": started.elapsed().as_millis() as i64,
                })));
            }
        };
        let body_bytes = match &response.body {
            fakecloud_core::service::ResponseBody::Bytes(b) => b.to_vec(),
            _ => Vec::new(),
        };
        ok(json!({
            "status": response.status.as_u16(),
            "body": String::from_utf8_lossy(&body_bytes).to_string(),
            "headers": serializable_headers(&response.headers),
            "log": "TestInvokeMethod ok",
            "latency": started.elapsed().as_millis() as i64,
        }))
    }

    fn test_invoke_authorizer(
        &self,
        _req: &AwsRequest,
        _params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        // Authorizer execution would need a Lambda/Cognito hook;
        // fakecloud emits an Allow stub so callers can prove the
        // surface is wired without modeling the real policy.
        ok(json!({
            "clientStatus": 200,
            "log": "TestInvokeAuthorizer ok",
            "latency": 0,
            "principalId": "user",
            "policy": "{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Action\":\"execute-api:Invoke\",\"Resource\":\"*\"}]}",
            "authorization": {},
            "claims": {},
        }))
    }
}

fn build_path_segments(stage: &str, path: &str) -> Vec<String> {
    let mut segs = vec![stage.to_string()];
    for p in path.trim_start_matches('/').split('/') {
        if !p.is_empty() {
            segs.push(p.to_string());
        }
    }
    segs
}

fn serializable_headers(headers: &http::HeaderMap) -> serde_json::Map<String, Value> {
    let mut out = serde_json::Map::new();
    for (k, v) in headers.iter() {
        if let Ok(s) = v.to_str() {
            out.insert(k.as_str().to_string(), Value::String(s.to_string()));
        }
    }
    out
}

fn extract_string_map(body: &Value, key: &str) -> HashMap<String, String> {
    body.get(key)
        .and_then(Value::as_object)
        .map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

// ── Deployment handlers ──

impl ApiGatewayService {
    fn create_deployment(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let body = req.json_body();
        let id = make_id();
        let deployment = Deployment {
            id: id.clone(),
            description: body
                .get("description")
                .and_then(Value::as_str)
                .map(String::from),
            created_date: chrono::Utc::now(),
            api_summary: snapshot_api(&self.state.read(), &request_account(req), &api_id),
        };
        let stage_name = body
            .get("stageName")
            .and_then(Value::as_str)
            .map(String::from);
        let stage_description = body
            .get("stageDescription")
            .and_then(Value::as_str)
            .map(String::from);
        let variables = body
            .get("variables")
            .and_then(Value::as_object)
            .map(|m| {
                m.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect::<HashMap<String, String>>()
            })
            .unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        if !state.apis.contains_key(&api_id) {
            return Err(not_found(format!("RestApi {api_id} not found")));
        }
        state
            .deployments
            .entry(api_id.clone())
            .or_default()
            .insert(id.clone(), deployment.clone());
        if let Some(name) = stage_name {
            // Auto-create the stage that points at this deployment.
            let now = chrono::Utc::now();
            let stage = Stage {
                stage_name: name.clone(),
                deployment_id: id.clone(),
                description: stage_description,
                cache_cluster_enabled: false,
                cache_cluster_size: None,
                variables,
                method_settings: HashMap::new(),
                created_date: now,
                last_updated_date: now,
                tracing_enabled: false,
                web_acl_arn: None,
                canary_settings: None,
                access_log_settings: None,
                tags: HashMap::new(),
            };
            state
                .stages
                .entry(api_id.clone())
                .or_default()
                .insert(name, stage);
        }
        ok_status(StatusCode::CREATED, deployment_to_json(&deployment))
    }

    fn get_deployment(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let id = params.get("deploymentId").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let state = accounts
            .get(&request_account(req))
            .ok_or_else(|| not_found("Deployment not found"))?;
        let map = state
            .deployments
            .get(&api_id)
            .ok_or_else(|| not_found("Deployment not found"))?;
        let d = map
            .get(&id)
            .ok_or_else(|| not_found("Deployment not found"))?;
        ok(deployment_to_json(d))
    }

    fn get_deployments(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let items: Vec<Value> = accounts
            .get(&request_account(req))
            .and_then(|s| s.deployments.get(&api_id))
            .map(|m| m.values().map(deployment_to_json).collect())
            .unwrap_or_default();
        ok(json!({"item": items}))
    }

    fn delete_deployment(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let id = params.get("deploymentId").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .deployments
            .get_mut(&api_id)
            .ok_or_else(|| not_found("Deployment not found"))?;
        if map.remove(&id).is_none() {
            return Err(not_found("Deployment not found"));
        }
        ok_no_content()
    }

    fn update_deployment(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let id = params.get("deploymentId").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .deployments
            .get_mut(&api_id)
            .ok_or_else(|| not_found("Deployment not found"))?;
        let d = map
            .get_mut(&id)
            .ok_or_else(|| not_found("Deployment not found"))?;
        apply_patch_operations(req, |op, path, value| {
            if (op == "replace" || op == "add") && path == "/description" {
                d.description = value.as_str().map(String::from);
            }
        });
        ok(deployment_to_json(d))
    }
}

fn snapshot_api(
    accounts: &fakecloud_core::multi_account::MultiAccountState<crate::state::ApiGatewayState>,
    account: &str,
    api_id: &str,
) -> Value {
    let Some(state) = accounts.get(account) else {
        return Value::Null;
    };
    // ApiSummary maps each resource path to its set of methods. This is
    // close enough to the AWS shape that SDKs round-trip it cleanly,
    // and the snapshot lets us interpret traffic deterministically per
    // deployment even if the live API is mutated afterwards.
    let mut summary = serde_json::Map::new();
    if let Some(resources) = state.resources.get(api_id) {
        for resource in resources.values() {
            let prefix = format!("{api_id}/{}/", resource.id);
            let mut methods = serde_json::Map::new();
            for (key, m) in &state.methods {
                if let Some(rest) = key.strip_prefix(&prefix) {
                    methods.insert(
                        rest.to_string(),
                        json!({
                            "authorizationType": m.authorization_type,
                            "apiKeyRequired": m.api_key_required,
                        }),
                    );
                }
            }
            if !methods.is_empty() {
                summary.insert(resource.path.clone(), Value::Object(methods));
            }
        }
    }
    Value::Object(summary)
}

// ── Stage handlers ──

impl ApiGatewayService {
    fn create_stage(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let body = req.json_body();
        let stage_name = body
            .get("stageName")
            .and_then(Value::as_str)
            .ok_or_else(|| bad_request("stageName is required"))?
            .to_string();
        let deployment_id = body
            .get("deploymentId")
            .and_then(Value::as_str)
            .ok_or_else(|| bad_request("deploymentId is required"))?
            .to_string();
        let now = chrono::Utc::now();
        let stage = Stage {
            stage_name: stage_name.clone(),
            deployment_id,
            description: body
                .get("description")
                .and_then(Value::as_str)
                .map(String::from),
            cache_cluster_enabled: body
                .get("cacheClusterEnabled")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            cache_cluster_size: body
                .get("cacheClusterSize")
                .and_then(Value::as_str)
                .map(String::from),
            variables: extract_string_map(&body, "variables"),
            method_settings: body
                .get("methodSettings")
                .and_then(Value::as_object)
                .map(|m| {
                    m.iter()
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect::<HashMap<String, Value>>()
                })
                .unwrap_or_default(),
            created_date: now,
            last_updated_date: now,
            tracing_enabled: body
                .get("tracingEnabled")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            web_acl_arn: body
                .get("webAclArn")
                .and_then(Value::as_str)
                .map(String::from),
            canary_settings: body.get("canarySettings").cloned(),
            access_log_settings: body.get("accessLogSettings").cloned(),
            tags: tags_from(&body),
        };
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        if !state.apis.contains_key(&api_id) {
            return Err(not_found(format!("RestApi {api_id} not found")));
        }
        state
            .stages
            .entry(api_id)
            .or_default()
            .insert(stage_name, stage.clone());
        ok_status(StatusCode::CREATED, stage_to_json(&stage))
    }

    fn get_stage(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let name = params.get("stageName").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let state = accounts
            .get(&request_account(req))
            .ok_or_else(|| not_found("Stage not found"))?;
        let map = state
            .stages
            .get(&api_id)
            .ok_or_else(|| not_found("Stage not found"))?;
        let s = map.get(&name).ok_or_else(|| not_found("Stage not found"))?;
        ok(stage_to_json(s))
    }

    fn get_stages(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let items: Vec<Value> = accounts
            .get(&request_account(req))
            .and_then(|s| s.stages.get(&api_id))
            .map(|m| m.values().map(stage_to_json).collect())
            .unwrap_or_default();
        ok(json!({"item": items}))
    }

    fn delete_stage(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let name = params.get("stageName").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .stages
            .get_mut(&api_id)
            .ok_or_else(|| not_found("Stage not found"))?;
        if map.remove(&name).is_none() {
            return Err(not_found("Stage not found"));
        }
        ok_no_content()
    }

    fn update_stage(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let name = params.get("stageName").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .stages
            .get_mut(&api_id)
            .ok_or_else(|| not_found("Stage not found"))?;
        let s = map
            .get_mut(&name)
            .ok_or_else(|| not_found("Stage not found"))?;
        apply_patch_operations(req, |op, path, value| {
            if op != "replace" && op != "add" && op != "remove" {
                return;
            }
            match path {
                "/deploymentId" => {
                    if let Some(s_) = value.as_str() {
                        s.deployment_id = s_.to_string();
                    }
                }
                "/description" => s.description = value.as_str().map(String::from),
                "/tracingEnabled" => {
                    if let Some(b) = value.as_bool() {
                        s.tracing_enabled = b;
                    }
                }
                _ if path.starts_with("/variables/") => {
                    let k = path.trim_start_matches("/variables/").to_string();
                    if op == "remove" {
                        s.variables.remove(&k);
                    } else if let Some(v) = value.as_str() {
                        s.variables.insert(k, v.to_string());
                    }
                }
                _ => {}
            }
        });
        s.last_updated_date = chrono::Utc::now();
        ok(stage_to_json(s))
    }
}

// ── Models ──

impl ApiGatewayService {
    fn create_model(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let body = req.json_body();
        let name = body
            .get("name")
            .and_then(Value::as_str)
            .ok_or_else(|| bad_request("name is required"))?
            .to_string();
        let model = Model {
            id: make_id(),
            name: name.clone(),
            description: body
                .get("description")
                .and_then(Value::as_str)
                .map(String::from),
            schema: body.get("schema").and_then(Value::as_str).map(String::from),
            content_type: body
                .get("contentType")
                .and_then(Value::as_str)
                .unwrap_or("application/json")
                .to_string(),
        };
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        state
            .models
            .entry(api_id)
            .or_default()
            .insert(name, model.clone());
        ok_status(StatusCode::CREATED, model_to_json(&model))
    }

    fn get_model(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let name = params.get("modelName").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let state = accounts
            .get(&request_account(req))
            .ok_or_else(|| not_found("Model not found"))?;
        let m = state
            .models
            .get(&api_id)
            .and_then(|m| m.get(&name))
            .ok_or_else(|| not_found("Model not found"))?;
        ok(model_to_json(m))
    }

    fn get_models(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let items: Vec<Value> = accounts
            .get(&request_account(req))
            .and_then(|s| s.models.get(&api_id))
            .map(|m| m.values().map(model_to_json).collect())
            .unwrap_or_default();
        ok(json!({"item": items}))
    }

    fn delete_model(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let name = params.get("modelName").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .models
            .get_mut(&api_id)
            .ok_or_else(|| not_found("Model not found"))?;
        if map.remove(&name).is_none() {
            return Err(not_found("Model not found"));
        }
        ok_no_content()
    }

    fn update_model(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let name = params.get("modelName").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .models
            .get_mut(&api_id)
            .ok_or_else(|| not_found("Model not found"))?;
        let m = map
            .get_mut(&name)
            .ok_or_else(|| not_found("Model not found"))?;
        apply_patch_operations(req, |op, path, value| {
            if op != "replace" && op != "add" {
                return;
            }
            match path {
                "/description" => m.description = value.as_str().map(String::from),
                "/schema" => m.schema = value.as_str().map(String::from),
                _ => {}
            }
        });
        ok(model_to_json(m))
    }

    fn get_model_template(
        &self,
        _req: &AwsRequest,
        _params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        ok(json!({"value": "{}"}))
    }
}

// ── Request validators ──

impl ApiGatewayService {
    fn create_request_validator(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let body = req.json_body();
        let id = make_id();
        let mut value = body.clone();
        if let Some(o) = value.as_object_mut() {
            o.insert("id".to_string(), Value::String(id.clone()));
        }
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        state
            .request_validators
            .entry(api_id)
            .or_default()
            .insert(id, value.clone());
        ok_status(StatusCode::CREATED, value)
    }

    fn get_request_validator(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let id = params
            .get("requestValidatorId")
            .cloned()
            .unwrap_or_default();
        let accounts = self.state.read();
        let v = accounts
            .get(&request_account(req))
            .and_then(|s| s.request_validators.get(&api_id))
            .and_then(|m| m.get(&id))
            .cloned()
            .ok_or_else(|| not_found("RequestValidator not found"))?;
        ok(v)
    }

    fn get_request_validators(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let items: Vec<Value> = accounts
            .get(&request_account(req))
            .and_then(|s| s.request_validators.get(&api_id))
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        ok(json!({"item": items}))
    }

    fn delete_request_validator(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let id = params
            .get("requestValidatorId")
            .cloned()
            .unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .request_validators
            .get_mut(&api_id)
            .ok_or_else(|| not_found("RequestValidator not found"))?;
        if map.remove(&id).is_none() {
            return Err(not_found("RequestValidator not found"));
        }
        ok_no_content()
    }

    fn update_request_validator(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let id = params
            .get("requestValidatorId")
            .cloned()
            .unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .request_validators
            .get_mut(&api_id)
            .ok_or_else(|| not_found("RequestValidator not found"))?;
        let v = map
            .get_mut(&id)
            .ok_or_else(|| not_found("RequestValidator not found"))?;
        apply_patch_operations(req, |_op, path, value| {
            if let Some(o) = v.as_object_mut() {
                o.insert(path.trim_start_matches('/').to_string(), value.clone());
            }
        });
        ok(v.clone())
    }
}

// ── Authorizers ──

impl ApiGatewayService {
    fn create_authorizer(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let body = req.json_body();
        let auth = Authorizer {
            id: make_id(),
            name: body
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| bad_request("name is required"))?
                .to_string(),
            authorizer_type: body
                .get("type")
                .and_then(Value::as_str)
                .unwrap_or("TOKEN")
                .to_string(),
            provider_arns: body
                .get("providerARNs")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(Value::as_str)
                        .map(String::from)
                        .collect()
                })
                .unwrap_or_default(),
            auth_type: body
                .get("authType")
                .and_then(Value::as_str)
                .map(String::from),
            authorizer_uri: body
                .get("authorizerUri")
                .and_then(Value::as_str)
                .map(String::from),
            authorizer_credentials: body
                .get("authorizerCredentials")
                .and_then(Value::as_str)
                .map(String::from),
            identity_source: body
                .get("identitySource")
                .and_then(Value::as_str)
                .map(String::from),
            identity_validation_expression: body
                .get("identityValidationExpression")
                .and_then(Value::as_str)
                .map(String::from),
            authorizer_result_ttl_in_seconds: body
                .get("authorizerResultTtlInSeconds")
                .and_then(Value::as_i64)
                .map(|v| v as i32),
        };
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        state
            .authorizers
            .entry(api_id)
            .or_default()
            .insert(auth.id.clone(), auth.clone());
        ok_status(StatusCode::CREATED, authorizer_to_json(&auth))
    }

    fn get_authorizer(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let id = params.get("authorizerId").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let auth = accounts
            .get(&request_account(req))
            .and_then(|s| s.authorizers.get(&api_id))
            .and_then(|m| m.get(&id))
            .cloned()
            .ok_or_else(|| not_found("Authorizer not found"))?;
        ok(authorizer_to_json(&auth))
    }

    fn get_authorizers(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let items: Vec<Value> = accounts
            .get(&request_account(req))
            .and_then(|s| s.authorizers.get(&api_id))
            .map(|m| m.values().map(authorizer_to_json).collect())
            .unwrap_or_default();
        ok(json!({"item": items}))
    }

    fn delete_authorizer(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let id = params.get("authorizerId").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .authorizers
            .get_mut(&api_id)
            .ok_or_else(|| not_found("Authorizer not found"))?;
        if map.remove(&id).is_none() {
            return Err(not_found("Authorizer not found"));
        }
        ok_no_content()
    }

    fn update_authorizer(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let id = params.get("authorizerId").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .authorizers
            .get_mut(&api_id)
            .ok_or_else(|| not_found("Authorizer not found"))?;
        let a = map
            .get_mut(&id)
            .ok_or_else(|| not_found("Authorizer not found"))?;
        apply_patch_operations(req, |op, path, value| {
            if op != "replace" && op != "add" {
                return;
            }
            match path {
                "/name" => {
                    if let Some(s) = value.as_str() {
                        a.name = s.to_string();
                    }
                }
                "/authorizerUri" => a.authorizer_uri = value.as_str().map(String::from),
                "/identitySource" => a.identity_source = value.as_str().map(String::from),
                "/authorizerResultTtlInSeconds" => {
                    a.authorizer_result_ttl_in_seconds = value.as_i64().map(|v| v as i32);
                }
                _ => {}
            }
        });
        ok(authorizer_to_json(a))
    }
}

// ── API keys ──

impl ApiGatewayService {
    fn create_api_key(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let id = make_id();
        let value = body
            .get("value")
            .and_then(Value::as_str)
            .map(String::from)
            .unwrap_or_else(|| {
                // AWS API keys are 40-char alphanumeric strings.
                uuid::Uuid::new_v4().simple().to_string()
            });
        let now = chrono::Utc::now();
        let key = ApiKey {
            id: id.clone(),
            value,
            name: body
                .get("name")
                .and_then(Value::as_str)
                .map(String::from)
                .unwrap_or_else(|| format!("key-{id}")),
            description: body
                .get("description")
                .and_then(Value::as_str)
                .map(String::from),
            enabled: body.get("enabled").and_then(Value::as_bool).unwrap_or(true),
            created_date: now,
            last_updated_date: now,
            stage_keys: body
                .get("stageKeys")
                .and_then(Value::as_array)
                .map(|arr| {
                    arr.iter()
                        .filter_map(|v| v.as_str().map(String::from))
                        .collect()
                })
                .unwrap_or_default(),
            tags: tags_from(&body),
            customer_id: body
                .get("customerId")
                .and_then(Value::as_str)
                .map(String::from),
        };
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        state.api_keys.insert(id, key.clone());
        ok_status(StatusCode::CREATED, api_key_to_json(&key, true))
    }

    fn get_api_key(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = params.get("apiKeyId").cloned().unwrap_or_default();
        let include_value = req
            .query_params
            .get("includeValue")
            .map(|s| s == "true")
            .unwrap_or(false);
        let accounts = self.state.read();
        let k = accounts
            .get(&request_account(req))
            .and_then(|s| s.api_keys.get(&id))
            .cloned()
            .ok_or_else(|| not_found("ApiKey not found"))?;
        ok(api_key_to_json(&k, include_value))
    }

    fn get_api_keys(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let include_value = req
            .query_params
            .get("includeValues")
            .map(|s| s == "true")
            .unwrap_or(false);
        let accounts = self.state.read();
        let items: Vec<Value> = accounts
            .get(&request_account(req))
            .map(|s| {
                s.api_keys
                    .values()
                    .map(|k| api_key_to_json(k, include_value))
                    .collect()
            })
            .unwrap_or_default();
        ok(json!({"item": items}))
    }

    fn delete_api_key(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = params.get("apiKeyId").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        if state.api_keys.remove(&id).is_none() {
            return Err(not_found("ApiKey not found"));
        }
        ok_no_content()
    }

    fn update_api_key(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = params.get("apiKeyId").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let k = state
            .api_keys
            .get_mut(&id)
            .ok_or_else(|| not_found("ApiKey not found"))?;
        apply_patch_operations(req, |op, path, value| {
            if op != "replace" && op != "add" {
                return;
            }
            match path {
                "/name" => {
                    if let Some(s) = value.as_str() {
                        k.name = s.to_string();
                    }
                }
                "/description" => k.description = value.as_str().map(String::from),
                "/enabled" => {
                    if let Some(b) = value.as_bool() {
                        k.enabled = b;
                    }
                }
                _ => {}
            }
        });
        k.last_updated_date = chrono::Utc::now();
        ok(api_key_to_json(k, false))
    }
}

// ── Usage plans + keys ──

impl ApiGatewayService {
    fn create_usage_plan(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let plan = UsagePlan {
            id: make_id(),
            name: body
                .get("name")
                .and_then(Value::as_str)
                .ok_or_else(|| bad_request("name is required"))?
                .to_string(),
            description: body
                .get("description")
                .and_then(Value::as_str)
                .map(String::from),
            api_stages: body
                .get("apiStages")
                .and_then(Value::as_array)
                .cloned()
                .unwrap_or_default(),
            throttle: body.get("throttle").cloned(),
            quota: body.get("quota").cloned(),
            product_code: body
                .get("productCode")
                .and_then(Value::as_str)
                .map(String::from),
            tags: tags_from(&body),
        };
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        state.usage_plans.insert(plan.id.clone(), plan.clone());
        ok_status(StatusCode::CREATED, usage_plan_to_json(&plan))
    }

    fn get_usage_plan(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = params.get("usagePlanId").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let plan = accounts
            .get(&request_account(req))
            .and_then(|s| s.usage_plans.get(&id))
            .cloned()
            .ok_or_else(|| not_found("UsagePlan not found"))?;
        ok(usage_plan_to_json(&plan))
    }

    fn get_usage_plans(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let items: Vec<Value> = accounts
            .get(&request_account(req))
            .map(|s| s.usage_plans.values().map(usage_plan_to_json).collect())
            .unwrap_or_default();
        ok(json!({"item": items}))
    }

    fn delete_usage_plan(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = params.get("usagePlanId").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        if state.usage_plans.remove(&id).is_none() {
            return Err(not_found("UsagePlan not found"));
        }
        state.usage_plan_keys.remove(&id);
        ok_no_content()
    }

    fn update_usage_plan(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = params.get("usagePlanId").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let plan = state
            .usage_plans
            .get_mut(&id)
            .ok_or_else(|| not_found("UsagePlan not found"))?;
        apply_patch_operations(req, |op, path, value| {
            if op != "replace" && op != "add" {
                return;
            }
            match path {
                "/name" => {
                    if let Some(s) = value.as_str() {
                        plan.name = s.to_string();
                    }
                }
                "/description" => plan.description = value.as_str().map(String::from),
                _ => {}
            }
        });
        ok(usage_plan_to_json(plan))
    }

    fn create_usage_plan_key(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let plan_id = params.get("usagePlanId").cloned().unwrap_or_default();
        let body = req.json_body();
        let key_id = body
            .get("keyId")
            .and_then(Value::as_str)
            .ok_or_else(|| bad_request("keyId is required"))?
            .to_string();
        let key_type = body
            .get("keyType")
            .and_then(Value::as_str)
            .unwrap_or("API_KEY")
            .to_string();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let key_value = state
            .api_keys
            .get(&key_id)
            .map(|k| k.value.clone())
            .ok_or_else(|| not_found("ApiKey not found"))?;
        if !state.usage_plans.contains_key(&plan_id) {
            return Err(not_found("UsagePlan not found"));
        }
        let entry = json!({"id": key_id, "type": key_type, "value": key_value});
        state
            .usage_plan_keys
            .entry(plan_id)
            .or_default()
            .insert(key_id, entry.clone());
        ok_status(StatusCode::CREATED, entry)
    }

    fn get_usage_plan_key(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let plan_id = params.get("usagePlanId").cloned().unwrap_or_default();
        let key_id = params.get("keyId").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let v = accounts
            .get(&request_account(req))
            .and_then(|s| s.usage_plan_keys.get(&plan_id))
            .and_then(|m| m.get(&key_id))
            .cloned()
            .ok_or_else(|| not_found("UsagePlanKey not found"))?;
        ok(v)
    }

    fn get_usage_plan_keys(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let plan_id = params.get("usagePlanId").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let items: Vec<Value> = accounts
            .get(&request_account(req))
            .and_then(|s| s.usage_plan_keys.get(&plan_id))
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        ok(json!({"item": items}))
    }

    fn delete_usage_plan_key(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let plan_id = params.get("usagePlanId").cloned().unwrap_or_default();
        let key_id = params.get("keyId").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .usage_plan_keys
            .get_mut(&plan_id)
            .ok_or_else(|| not_found("UsagePlanKey not found"))?;
        if map.remove(&key_id).is_none() {
            return Err(not_found("UsagePlanKey not found"));
        }
        ok_no_content()
    }

    fn get_usage(
        &self,
        _req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        // Real usage tracking would tie into request counters; fakecloud
        // returns the empty-but-valid AWS response shape so callers
        // that ask for usage at least see a well-formed reply.
        let plan_id = params.get("usagePlanId").cloned().unwrap_or_default();
        ok(json!({
            "usagePlanId": plan_id,
            "startDate": "1970-01-01",
            "endDate": chrono::Utc::now().format("%Y-%m-%d").to_string(),
            "values": serde_json::Value::Object(serde_json::Map::new()),
        }))
    }
}

// ── VPC links / domain names / base path mappings / client certs ──
// All accept arbitrary JSON, store it under the keyed map, and return
// the same payload — that's enough for SDK round-trip tests.

impl ApiGatewayService {
    fn create_vpc_link(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let id = make_id();
        let mut value = req.json_body();
        if let Some(o) = value.as_object_mut() {
            o.insert("id".to_string(), Value::String(id.clone()));
            o.insert("status".to_string(), Value::String("AVAILABLE".to_string()));
        }
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        state.vpc_links.insert(id, value.clone());
        ok_status(StatusCode::CREATED, value)
    }

    fn get_vpc_link(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = params.get("vpcLinkId").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let v = accounts
            .get(&request_account(req))
            .and_then(|s| s.vpc_links.get(&id))
            .cloned()
            .ok_or_else(|| not_found("VpcLink not found"))?;
        ok(v)
    }

    fn get_vpc_links(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let items: Vec<Value> = accounts
            .get(&request_account(req))
            .map(|s| s.vpc_links.values().cloned().collect())
            .unwrap_or_default();
        ok(json!({"item": items}))
    }

    fn delete_vpc_link(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = params.get("vpcLinkId").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        if state.vpc_links.remove(&id).is_none() {
            return Err(not_found("VpcLink not found"));
        }
        ok_no_content()
    }

    fn update_vpc_link(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = params.get("vpcLinkId").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let v = state
            .vpc_links
            .get_mut(&id)
            .ok_or_else(|| not_found("VpcLink not found"))?;
        apply_patch_operations(req, |_op, path, value| {
            if let Some(o) = v.as_object_mut() {
                o.insert(path.trim_start_matches('/').to_string(), value.clone());
            }
        });
        ok(v.clone())
    }

    fn create_domain_name(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let domain = body
            .get("domainName")
            .and_then(Value::as_str)
            .ok_or_else(|| bad_request("domainName is required"))?
            .to_string();
        let mut value = body.clone();
        if let Some(o) = value.as_object_mut() {
            o.insert(
                "regionalDomainName".to_string(),
                Value::String(format!("{domain}.fakecloud")),
            );
            o.insert(
                "domainNameStatus".to_string(),
                Value::String("AVAILABLE".to_string()),
            );
        }
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        state.domain_names.insert(domain, value.clone());
        ok_status(StatusCode::CREATED, value)
    }

    fn get_domain_name(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let d = params.get("domainName").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let v = accounts
            .get(&request_account(req))
            .and_then(|s| s.domain_names.get(&d))
            .cloned()
            .ok_or_else(|| not_found("DomainName not found"))?;
        ok(v)
    }

    fn get_domain_names(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let items: Vec<Value> = accounts
            .get(&request_account(req))
            .map(|s| s.domain_names.values().cloned().collect())
            .unwrap_or_default();
        ok(json!({"item": items}))
    }

    fn delete_domain_name(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let d = params.get("domainName").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        if state.domain_names.remove(&d).is_none() {
            return Err(not_found("DomainName not found"));
        }
        state.base_path_mappings.remove(&d);
        ok_no_content()
    }

    fn update_domain_name(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let d = params.get("domainName").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let v = state
            .domain_names
            .get_mut(&d)
            .ok_or_else(|| not_found("DomainName not found"))?;
        apply_patch_operations(req, |_op, path, value| {
            if let Some(o) = v.as_object_mut() {
                o.insert(path.trim_start_matches('/').to_string(), value.clone());
            }
        });
        ok(v.clone())
    }

    fn create_base_path_mapping(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let domain = params.get("domainName").cloned().unwrap_or_default();
        let body = req.json_body();
        let base_path = body
            .get("basePath")
            .and_then(Value::as_str)
            .unwrap_or("(none)")
            .to_string();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        state
            .base_path_mappings
            .entry(domain)
            .or_default()
            .insert(base_path.clone(), body.clone());
        ok_status(StatusCode::CREATED, body)
    }

    fn get_base_path_mapping(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let d = params.get("domainName").cloned().unwrap_or_default();
        let bp = params.get("basePath").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let v = accounts
            .get(&request_account(req))
            .and_then(|s| s.base_path_mappings.get(&d))
            .and_then(|m| m.get(&bp))
            .cloned()
            .ok_or_else(|| not_found("BasePathMapping not found"))?;
        ok(v)
    }

    fn get_base_path_mappings(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let d = params.get("domainName").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let items: Vec<Value> = accounts
            .get(&request_account(req))
            .and_then(|s| s.base_path_mappings.get(&d))
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        ok(json!({"item": items}))
    }

    fn delete_base_path_mapping(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let d = params.get("domainName").cloned().unwrap_or_default();
        let bp = params.get("basePath").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .base_path_mappings
            .get_mut(&d)
            .ok_or_else(|| not_found("BasePathMapping not found"))?;
        if map.remove(&bp).is_none() {
            return Err(not_found("BasePathMapping not found"));
        }
        ok_no_content()
    }

    fn update_base_path_mapping(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let d = params.get("domainName").cloned().unwrap_or_default();
        let bp = params.get("basePath").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .base_path_mappings
            .get_mut(&d)
            .ok_or_else(|| not_found("BasePathMapping not found"))?;
        let v = map
            .get_mut(&bp)
            .ok_or_else(|| not_found("BasePathMapping not found"))?;
        apply_patch_operations(req, |_op, path, value| {
            if let Some(o) = v.as_object_mut() {
                o.insert(path.trim_start_matches('/').to_string(), value.clone());
            }
        });
        ok(v.clone())
    }

    fn generate_client_cert(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let id = make_id();
        let mut value = req.json_body();
        let now = chrono::Utc::now();
        if !value.is_object() {
            value = json!({});
        }
        if let Some(o) = value.as_object_mut() {
            o.insert("clientCertificateId".to_string(), Value::String(id.clone()));
            o.insert(
                "createdDate".to_string(),
                Value::Number(serde_json::Number::from(now.timestamp())),
            );
            o.insert(
                "expirationDate".to_string(),
                Value::Number(serde_json::Number::from(
                    (now + chrono::Duration::days(365)).timestamp(),
                )),
            );
            o.insert(
                "pemEncodedCertificate".to_string(),
                Value::String(
                    "-----BEGIN CERTIFICATE-----\nfakecloud-stub\n-----END CERTIFICATE-----"
                        .to_string(),
                ),
            );
        }
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        state.client_certificates.insert(id, value.clone());
        ok_status(StatusCode::CREATED, value)
    }

    fn get_client_cert(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = params
            .get("clientCertificateId")
            .cloned()
            .unwrap_or_default();
        let accounts = self.state.read();
        let v = accounts
            .get(&request_account(req))
            .and_then(|s| s.client_certificates.get(&id))
            .cloned()
            .ok_or_else(|| not_found("ClientCertificate not found"))?;
        ok(v)
    }

    fn get_client_certs(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let items: Vec<Value> = accounts
            .get(&request_account(req))
            .map(|s| s.client_certificates.values().cloned().collect())
            .unwrap_or_default();
        ok(json!({"item": items}))
    }

    fn delete_client_cert(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = params
            .get("clientCertificateId")
            .cloned()
            .unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        if state.client_certificates.remove(&id).is_none() {
            return Err(not_found("ClientCertificate not found"));
        }
        ok_no_content()
    }

    fn update_client_cert(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = params
            .get("clientCertificateId")
            .cloned()
            .unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let v = state
            .client_certificates
            .get_mut(&id)
            .ok_or_else(|| not_found("ClientCertificate not found"))?;
        apply_patch_operations(req, |_op, path, value| {
            if let Some(o) = v.as_object_mut() {
                o.insert(path.trim_start_matches('/').to_string(), value.clone());
            }
        });
        ok(v.clone())
    }
}

// ── Documentation parts/versions, gateway responses, export, sdk, tags ──

impl ApiGatewayService {
    fn create_doc_part(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let id = make_id();
        let mut value = req.json_body();
        if let Some(o) = value.as_object_mut() {
            o.insert("id".to_string(), Value::String(id.clone()));
        }
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        state
            .documentation_parts
            .entry(api_id)
            .or_default()
            .insert(id, value.clone());
        ok_status(StatusCode::CREATED, value)
    }

    fn get_doc_part(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let id = params
            .get("documentationPartId")
            .cloned()
            .unwrap_or_default();
        let accounts = self.state.read();
        let v = accounts
            .get(&request_account(req))
            .and_then(|s| s.documentation_parts.get(&api_id))
            .and_then(|m| m.get(&id))
            .cloned()
            .ok_or_else(|| not_found("DocumentationPart not found"))?;
        ok(v)
    }

    fn get_doc_parts(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let items: Vec<Value> = accounts
            .get(&request_account(req))
            .and_then(|s| s.documentation_parts.get(&api_id))
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        ok(json!({"item": items}))
    }

    fn delete_doc_part(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let id = params
            .get("documentationPartId")
            .cloned()
            .unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .documentation_parts
            .get_mut(&api_id)
            .ok_or_else(|| not_found("DocumentationPart not found"))?;
        if map.remove(&id).is_none() {
            return Err(not_found("DocumentationPart not found"));
        }
        ok_no_content()
    }

    fn update_doc_part(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let id = params
            .get("documentationPartId")
            .cloned()
            .unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .documentation_parts
            .get_mut(&api_id)
            .ok_or_else(|| not_found("DocumentationPart not found"))?;
        let v = map
            .get_mut(&id)
            .ok_or_else(|| not_found("DocumentationPart not found"))?;
        apply_patch_operations(req, |_op, path, value| {
            if let Some(o) = v.as_object_mut() {
                o.insert(path.trim_start_matches('/').to_string(), value.clone());
            }
        });
        ok(v.clone())
    }

    fn create_doc_version(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let body = req.json_body();
        let version = body
            .get("documentationVersion")
            .and_then(Value::as_str)
            .ok_or_else(|| bad_request("documentationVersion is required"))?
            .to_string();
        let mut value = body.clone();
        if let Some(o) = value.as_object_mut() {
            o.insert(
                "createdDate".to_string(),
                Value::Number(serde_json::Number::from(chrono::Utc::now().timestamp())),
            );
        }
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        state
            .documentation_versions
            .entry(api_id)
            .or_default()
            .insert(version, value.clone());
        ok_status(StatusCode::CREATED, value)
    }

    fn get_doc_version(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let v = params
            .get("documentationVersion")
            .cloned()
            .unwrap_or_default();
        let accounts = self.state.read();
        let value = accounts
            .get(&request_account(req))
            .and_then(|s| s.documentation_versions.get(&api_id))
            .and_then(|m| m.get(&v))
            .cloned()
            .ok_or_else(|| not_found("DocumentationVersion not found"))?;
        ok(value)
    }

    fn get_doc_versions(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let items: Vec<Value> = accounts
            .get(&request_account(req))
            .and_then(|s| s.documentation_versions.get(&api_id))
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        ok(json!({"item": items}))
    }

    fn delete_doc_version(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let v = params
            .get("documentationVersion")
            .cloned()
            .unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .documentation_versions
            .get_mut(&api_id)
            .ok_or_else(|| not_found("DocumentationVersion not found"))?;
        if map.remove(&v).is_none() {
            return Err(not_found("DocumentationVersion not found"));
        }
        ok_no_content()
    }

    fn update_doc_version(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let v = params
            .get("documentationVersion")
            .cloned()
            .unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .documentation_versions
            .get_mut(&api_id)
            .ok_or_else(|| not_found("DocumentationVersion not found"))?;
        let value = map
            .get_mut(&v)
            .ok_or_else(|| not_found("DocumentationVersion not found"))?;
        apply_patch_operations(req, |_op, path, val| {
            if let Some(o) = value.as_object_mut() {
                o.insert(path.trim_start_matches('/').to_string(), val.clone());
            }
        });
        ok(value.clone())
    }

    fn put_gateway_response(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let response_type = params.get("responseType").cloned().unwrap_or_default();
        let mut value = req.json_body();
        if let Some(o) = value.as_object_mut() {
            o.insert(
                "responseType".to_string(),
                Value::String(response_type.clone()),
            );
        }
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        state
            .gateway_responses
            .entry(api_id)
            .or_default()
            .insert(response_type, value.clone());
        ok_status(StatusCode::CREATED, value)
    }

    fn get_gateway_response(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let t = params.get("responseType").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let v = accounts
            .get(&request_account(req))
            .and_then(|s| s.gateway_responses.get(&api_id))
            .and_then(|m| m.get(&t))
            .cloned()
            .ok_or_else(|| not_found("GatewayResponse not found"))?;
        ok(v)
    }

    fn get_gateway_responses(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let items: Vec<Value> = accounts
            .get(&request_account(req))
            .and_then(|s| s.gateway_responses.get(&api_id))
            .map(|m| m.values().cloned().collect())
            .unwrap_or_default();
        ok(json!({"item": items}))
    }

    fn delete_gateway_response(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let t = params.get("responseType").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .gateway_responses
            .get_mut(&api_id)
            .ok_or_else(|| not_found("GatewayResponse not found"))?;
        if map.remove(&t).is_none() {
            return Err(not_found("GatewayResponse not found"));
        }
        ok_no_content()
    }

    fn update_gateway_response(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let t = params.get("responseType").cloned().unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let map = state
            .gateway_responses
            .get_mut(&api_id)
            .ok_or_else(|| not_found("GatewayResponse not found"))?;
        let v = map
            .get_mut(&t)
            .ok_or_else(|| not_found("GatewayResponse not found"))?;
        apply_patch_operations(req, |_op, path, value| {
            if let Some(o) = v.as_object_mut() {
                o.insert(path.trim_start_matches('/').to_string(), value.clone());
            }
        });
        ok(v.clone())
    }

    fn get_export(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = params.get("restApiId").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let api = accounts
            .get(&request_account(req))
            .and_then(|s| s.apis.get(&api_id))
            .cloned()
            .ok_or_else(|| not_found("RestApi not found"))?;
        // Return either the originally imported source (if any) or a
        // minimal OpenAPI 3.0 skeleton derived from state.
        let body = if let Some(src) = api.import_source.clone() {
            src
        } else {
            json!({
                "openapi": "3.0.1",
                "info": {"title": api.name, "version": api.version.unwrap_or_default()},
                "paths": serde_json::Value::Object(serde_json::Map::new()),
            })
            .to_string()
        };
        Ok(AwsResponse {
            status: StatusCode::OK,
            content_type: "application/json".to_string(),
            body: bytes::Bytes::from(body.into_bytes()).into(),
            headers: http::HeaderMap::new(),
        })
    }

    fn get_sdk(
        &self,
        _req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let sdk_type = params.get("sdkType").cloned().unwrap_or_default();
        // AWS returns a binary blob (a zip archive) for GetSdk. fakecloud
        // returns a deterministic dummy zip header — enough for SDK
        // tests that just want to verify the endpoint exists.
        let body = format!("PK\x03\x04fakecloud-{sdk_type}-stub-zip\x00\x00\x00",);
        Ok(AwsResponse {
            status: StatusCode::OK,
            content_type: "application/octet-stream".to_string(),
            body: bytes::Bytes::from(body.into_bytes()).into(),
            headers: http::HeaderMap::new(),
        })
    }

    fn tag_resource(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = params.get("resourceArn").cloned().unwrap_or_default();
        let body = req.json_body();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        let entry = state.tags.entry(arn).or_default();
        if let Some(map) = body.get("tags").and_then(Value::as_object) {
            for (k, v) in map {
                if let Some(s) = v.as_str() {
                    entry.insert(k.clone(), s.to_string());
                }
            }
        }
        ok_no_content()
    }

    fn untag_resource(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = params.get("resourceArn").cloned().unwrap_or_default();
        let body = req.json_body();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request_account(req));
        if let Some(entry) = state.tags.get_mut(&arn) {
            if let Some(arr) = body.get("tagKeys").and_then(Value::as_array) {
                for k in arr {
                    if let Some(s) = k.as_str() {
                        entry.remove(s);
                    }
                }
            }
        }
        ok_no_content()
    }

    fn get_tags(
        &self,
        req: &AwsRequest,
        params: &HashMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = params.get("resourceArn").cloned().unwrap_or_default();
        let accounts = self.state.read();
        let map = accounts
            .get(&request_account(req))
            .and_then(|s| s.tags.get(&arn))
            .cloned()
            .unwrap_or_default();
        ok(json!({"tags": map}))
    }
}
