use async_trait::async_trait;
use http::{Method, StatusCode};
use serde_json::json;
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

use fakecloud_core::delivery::DeliveryBus;
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
use fakecloud_core::validation::*;
use fakecloud_persistence::SnapshotStore;

use crate::state::{
    ApiGatewayV2Snapshot, ApiGatewayV2State, ApiRequest, Authorizer, Deployment, HttpApi,
    Integration, Route, SharedApiGatewayV2State, Stage, APIGATEWAYV2_SNAPSHOT_SCHEMA_VERSION,
};
use crate::{cors, http_proxy, lambda_proxy, mock, router::Router};

const SUPPORTED: &[&str] = &[
    "CreateApi",
    "GetApi",
    "GetApis",
    "UpdateApi",
    "DeleteApi",
    "CreateRoute",
    "GetRoute",
    "GetRoutes",
    "UpdateRoute",
    "DeleteRoute",
    "CreateIntegration",
    "GetIntegration",
    "GetIntegrations",
    "UpdateIntegration",
    "DeleteIntegration",
    "CreateStage",
    "GetStage",
    "GetStages",
    "UpdateStage",
    "DeleteStage",
    "CreateDeployment",
    "GetDeployment",
    "GetDeployments",
    "CreateAuthorizer",
    "GetAuthorizer",
    "GetAuthorizers",
    "UpdateAuthorizer",
    "DeleteAuthorizer",
    "CreateDomainName",
    "GetDomainName",
    "GetDomainNames",
    "UpdateDomainName",
    "DeleteDomainName",
    "CreateApiMapping",
    "GetApiMapping",
    "GetApiMappings",
    "UpdateApiMapping",
    "DeleteApiMapping",
    "CreateModel",
    "GetModel",
    "GetModels",
    "UpdateModel",
    "DeleteModel",
    "GetModelTemplate",
    "CreateIntegrationResponse",
    "GetIntegrationResponse",
    "GetIntegrationResponses",
    "UpdateIntegrationResponse",
    "DeleteIntegrationResponse",
    "CreateRouteResponse",
    "GetRouteResponse",
    "GetRouteResponses",
    "UpdateRouteResponse",
    "DeleteRouteResponse",
    "CreateRoutingRule",
    "GetRoutingRule",
    "PutRoutingRule",
    "DeleteRoutingRule",
    "ListRoutingRules",
    "CreateVpcLink",
    "GetVpcLink",
    "GetVpcLinks",
    "UpdateVpcLink",
    "DeleteVpcLink",
    "TagResource",
    "UntagResource",
    "GetTags",
    "CreatePortal",
    "GetPortal",
    "ListPortals",
    "UpdatePortal",
    "DeletePortal",
    "DisablePortal",
    "PreviewPortal",
    "PublishPortal",
    "CreatePortalProduct",
    "GetPortalProduct",
    "ListPortalProducts",
    "UpdatePortalProduct",
    "DeletePortalProduct",
    "PutPortalProductSharingPolicy",
    "GetPortalProductSharingPolicy",
    "DeletePortalProductSharingPolicy",
    "CreateProductPage",
    "GetProductPage",
    "ListProductPages",
    "UpdateProductPage",
    "DeleteProductPage",
    "CreateProductRestEndpointPage",
    "GetProductRestEndpointPage",
    "ListProductRestEndpointPages",
    "UpdateProductRestEndpointPage",
    "DeleteProductRestEndpointPage",
    "ImportApi",
    "ReimportApi",
    "ExportApi",
    "DeleteCorsConfiguration",
    "DeleteAccessLogSettings",
    "DeleteRouteRequestParameter",
    "DeleteRouteSettings",
    "DeleteDeployment",
    "UpdateDeployment",
    "ResetAuthorizersCache",
];

pub struct ApiGatewayV2Service {
    pub(crate) state: SharedApiGatewayV2State,
    delivery: Option<Arc<DeliveryBus>>,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    snapshot_lock: Arc<AsyncMutex<()>>,
}

impl ApiGatewayV2Service {
    pub fn new(state: SharedApiGatewayV2State) -> Self {
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

    async fn save_snapshot(&self) {
        let Some(store) = self.snapshot_store.clone() else {
            return;
        };
        let _guard = self.snapshot_lock.lock().await;
        let snapshot = ApiGatewayV2Snapshot {
            schema_version: APIGATEWAYV2_SNAPSHOT_SCHEMA_VERSION,
            state: None,
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
            Ok(Err(err)) => tracing::error!(%err, "failed to write apigatewayv2 snapshot"),
            Err(err) => tracing::error!(%err, "apigatewayv2 snapshot task panicked"),
        }
    }

    /// Determine the action from the HTTP method and path segments.
    /// API Gateway v2 uses REST-style routing:
    ///   POST   /v2/apis              -> CreateApi
    ///   GET    /v2/apis              -> GetApis
    ///   GET    /v2/apis/{api-id}     -> GetApi
    ///   PATCH  /v2/apis/{api-id}     -> UpdateApi
    ///   DELETE /v2/apis/{api-id}     -> DeleteApi
    ///   POST   /v2/apis/{api-id}/routes -> CreateRoute
    ///   GET    /v2/apis/{api-id}/routes -> GetRoutes
    ///   GET    /v2/apis/{api-id}/routes/{route-id} -> GetRoute
    ///   PATCH  /v2/apis/{api-id}/routes/{route-id} -> UpdateRoute
    ///   DELETE /v2/apis/{api-id}/routes/{route-id} -> DeleteRoute
    ///   POST   /v2/apis/{api-id}/integrations -> CreateIntegration
    ///   GET    /v2/apis/{api-id}/integrations -> GetIntegrations
    ///   GET    /v2/apis/{api-id}/integrations/{int-id} -> GetIntegration
    ///   PATCH  /v2/apis/{api-id}/integrations/{int-id} -> UpdateIntegration
    ///   DELETE /v2/apis/{api-id}/integrations/{int-id} -> DeleteIntegration
    ///   POST   /v2/apis/{api-id}/stages -> CreateStage
    ///   GET    /v2/apis/{api-id}/stages -> GetStages
    ///   GET    /v2/apis/{api-id}/stages/{stage-name} -> GetStage
    ///   PATCH  /v2/apis/{api-id}/stages/{stage-name} -> UpdateStage
    ///   DELETE /v2/apis/{api-id}/stages/{stage-name} -> DeleteStage
    ///   POST   /v2/apis/{api-id}/deployments -> CreateDeployment
    ///   GET    /v2/apis/{api-id}/deployments -> GetDeployments
    ///   GET    /v2/apis/{api-id}/deployments/{deployment-id} -> GetDeployment
    ///   POST   /v2/apis/{api-id}/authorizers -> CreateAuthorizer
    ///   GET    /v2/apis/{api-id}/authorizers -> GetAuthorizers
    ///   GET    /v2/apis/{api-id}/authorizers/{auth-id} -> GetAuthorizer
    ///   PATCH  /v2/apis/{api-id}/authorizers/{auth-id} -> UpdateAuthorizer
    ///   DELETE /v2/apis/{api-id}/authorizers/{auth-id} -> DeleteAuthorizer
    fn resolve_action(req: &AwsRequest) -> Option<(&'static str, Option<String>, Option<String>)> {
        let segs = &req.path_segments;
        if segs.len() < 2 || segs[0] != "v2" {
            return None;
        }

        // Non-/v2/apis collections.
        let second = segs.get(1).map(|s| s.as_str());
        let m = &req.method;
        let res = segs.get(2).map(|s| s.to_string());
        let sub = segs.get(4).map(|s| s.to_string());

        // For non-/v2/apis collections, the primary identifier (domain name,
        // VPC link id, etc.) lives in segs[2] which we expose as `resource_id`
        // (slot 2 of the tuple). Sub-ids (api mapping id, page id) live in
        // segs[4] which we expose via the `api_id` slot purely as a carrier
        // — handlers always read it as the second-level identifier.
        if second == Some("domainnames") {
            return match (m, segs.len(), segs.get(3).map(|s| s.as_str())) {
                (&Method::POST, 2, _) => Some(("CreateDomainName", None, None)),
                (&Method::GET, 2, _) => Some(("GetDomainNames", None, None)),
                (&Method::GET, 3, _) => Some(("GetDomainName", None, res)),
                (&Method::PATCH, 3, _) => Some(("UpdateDomainName", None, res)),
                (&Method::DELETE, 3, _) => Some(("DeleteDomainName", None, res)),
                (&Method::POST, 4, Some("apimappings")) => Some(("CreateApiMapping", None, res)),
                (&Method::GET, 4, Some("apimappings")) => Some(("GetApiMappings", None, res)),
                (&Method::GET, 5, Some("apimappings")) => Some(("GetApiMapping", sub, res)),
                (&Method::PATCH, 5, Some("apimappings")) => Some(("UpdateApiMapping", sub, res)),
                (&Method::DELETE, 5, Some("apimappings")) => Some(("DeleteApiMapping", sub, res)),
                // Routing rules are nested under a domain name per the Smithy
                // model (/v2/domainnames/{DomainName}/routingrules[/...]).
                (&Method::POST, 4, Some("routingrules")) => Some(("CreateRoutingRule", None, res)),
                (&Method::GET, 4, Some("routingrules")) => Some(("ListRoutingRules", None, res)),
                (&Method::GET, 5, Some("routingrules")) => Some(("GetRoutingRule", sub, res)),
                (&Method::PUT, 5, Some("routingrules")) => Some(("PutRoutingRule", sub, res)),
                (&Method::DELETE, 5, Some("routingrules")) => Some(("DeleteRoutingRule", sub, res)),
                _ => None,
            };
        }

        if second == Some("vpclinks") {
            return match (m, segs.len()) {
                (&Method::POST, 2) => Some(("CreateVpcLink", None, None)),
                (&Method::GET, 2) => Some(("GetVpcLinks", None, None)),
                (&Method::GET, 3) => Some(("GetVpcLink", None, res)),
                (&Method::PATCH, 3) => Some(("UpdateVpcLink", None, res)),
                (&Method::DELETE, 3) => Some(("DeleteVpcLink", None, res)),
                _ => None,
            };
        }

        if second == Some("tags") {
            // /v2/tags/{resource-arn}
            let arn = segs.get(2).map(|s| s.to_string());
            return match *m {
                Method::POST => Some(("TagResource", None, arn)),
                Method::DELETE => Some(("UntagResource", None, arn)),
                Method::GET => Some(("GetTags", None, arn)),
                _ => None,
            };
        }

        if second == Some("portals") {
            return match (m, segs.len(), segs.get(3).map(|s| s.as_str())) {
                (&Method::POST, 2, _) => Some(("CreatePortal", None, None)),
                (&Method::GET, 2, _) => Some(("ListPortals", None, None)),
                (&Method::GET, 3, _) => Some(("GetPortal", None, res)),
                (&Method::PATCH, 3, _) => Some(("UpdatePortal", None, res)),
                (&Method::DELETE, 3, _) => Some(("DeletePortal", None, res)),
                // Smithy: DisablePortal is DELETE /v2/portals/{id}/publish
                // (it "unpublishes" the portal). PublishPortal is POST of the
                // same path.
                (&Method::DELETE, 4, Some("publish")) => Some(("DisablePortal", None, res)),
                (&Method::POST, 4, Some("preview")) => Some(("PreviewPortal", None, res)),
                (&Method::POST, 4, Some("publish")) => Some(("PublishPortal", None, res)),
                _ => None,
            };
        }

        if second == Some("portalproducts") {
            return match (m, segs.len(), segs.get(3).map(|s| s.as_str())) {
                (&Method::POST, 2, _) => Some(("CreatePortalProduct", None, None)),
                (&Method::GET, 2, _) => Some(("ListPortalProducts", None, None)),
                (&Method::GET, 3, _) => Some(("GetPortalProduct", None, res)),
                (&Method::PATCH, 3, _) => Some(("UpdatePortalProduct", None, res)),
                (&Method::DELETE, 3, _) => Some(("DeletePortalProduct", None, res)),
                (&Method::PUT, 4, Some("sharingpolicy")) => {
                    Some(("PutPortalProductSharingPolicy", None, res))
                }
                (&Method::GET, 4, Some("sharingpolicy")) => {
                    Some(("GetPortalProductSharingPolicy", None, res))
                }
                (&Method::DELETE, 4, Some("sharingpolicy")) => {
                    Some(("DeletePortalProductSharingPolicy", None, res))
                }
                (&Method::POST, 4, Some("productpages")) => Some(("CreateProductPage", None, res)),
                (&Method::GET, 4, Some("productpages")) => Some(("ListProductPages", None, res)),
                (&Method::GET, 5, Some("productpages")) => Some(("GetProductPage", sub, res)),
                (&Method::PATCH, 5, Some("productpages")) => Some(("UpdateProductPage", sub, res)),
                (&Method::DELETE, 5, Some("productpages")) => Some(("DeleteProductPage", sub, res)),
                (&Method::POST, 4, Some("productrestendpointpages")) => {
                    Some(("CreateProductRestEndpointPage", None, res))
                }
                (&Method::GET, 4, Some("productrestendpointpages")) => {
                    Some(("ListProductRestEndpointPages", None, res))
                }
                (&Method::GET, 5, Some("productrestendpointpages")) => {
                    Some(("GetProductRestEndpointPage", sub, res))
                }
                (&Method::PATCH, 5, Some("productrestendpointpages")) => {
                    Some(("UpdateProductRestEndpointPage", sub, res))
                }
                (&Method::DELETE, 5, Some("productrestendpointpages")) => {
                    Some(("DeleteProductRestEndpointPage", sub, res))
                }
                _ => None,
            };
        }

        if second != Some("apis") {
            return None;
        }

        // `api_id` is segs[2] (the api identifier) for every action below
        // that has one; `resource_id` is segs[4] (the routes/integrations/
        // stages/... child id). We resolve both once here so the match
        // body only picks the action name.
        let api_id = segs.get(2).map(|s| s.to_string());
        let resource_id = segs.get(4).map(|s| s.to_string());
        let collection = segs.get(3).map(|s| s.as_str());
        let method = &req.method;

        let action = match (method, segs.len(), collection) {
            // /v2/apis
            (&Method::POST, 2, _) => "CreateApi",
            (&Method::PUT, 2, _) => "ImportApi",
            (&Method::GET, 2, _) => "GetApis",
            // /v2/apis/{api-id}
            (&Method::GET, 3, _) => "GetApi",
            (&Method::PATCH, 3, _) => "UpdateApi",
            (&Method::PUT, 3, _) => "ReimportApi",
            (&Method::DELETE, 3, _) => "DeleteApi",
            // /v2/apis/{api-id}/{collection}
            (m, 4, Some(col)) => resolve_collection_action(m, col)?,
            // /v2/apis/{api-id}/{collection}/{resource-id}
            (m, 5, Some(col)) => resolve_resource_action(m, col)?,
            // /v2/apis/{api-id}/{collection}/{resource-id}/{sub}
            (m, 6, Some(col)) => {
                let sub = segs.get(5).map(|s| s.as_str())?;
                match (m.clone(), col, sub) {
                    (Method::POST, "integrations", "integrationresponses") => {
                        "CreateIntegrationResponse"
                    }
                    (Method::GET, "integrations", "integrationresponses") => {
                        "GetIntegrationResponses"
                    }
                    (Method::POST, "routes", "routeresponses") => "CreateRouteResponse",
                    (Method::GET, "routes", "routeresponses") => "GetRouteResponses",
                    (Method::GET, "models", "template") => "GetModelTemplate",
                    (Method::DELETE, "stages", "accesslogsettings") => "DeleteAccessLogSettings",
                    (Method::GET, "exports", _) => "ExportApi",
                    _ => return None,
                }
            }
            // /v2/apis/{api-id}/{collection}/{resource-id}/{sub}/{sub-id}
            (m, 7, Some(col)) => {
                let sub = segs.get(5).map(|s| s.as_str())?;
                match (m.clone(), col, sub) {
                    (Method::GET, "integrations", "integrationresponses") => {
                        "GetIntegrationResponse"
                    }
                    (Method::PATCH, "integrations", "integrationresponses") => {
                        "UpdateIntegrationResponse"
                    }
                    (Method::DELETE, "integrations", "integrationresponses") => {
                        "DeleteIntegrationResponse"
                    }
                    (Method::GET, "routes", "routeresponses") => "GetRouteResponse",
                    (Method::PATCH, "routes", "routeresponses") => "UpdateRouteResponse",
                    (Method::DELETE, "routes", "routeresponses") => "DeleteRouteResponse",
                    (Method::DELETE, "routes", "requestparameters") => {
                        "DeleteRouteRequestParameter"
                    }
                    (Method::DELETE, "stages", "routesettings") => "DeleteRouteSettings",
                    (Method::DELETE, "stages", "cache") => "ResetAuthorizersCache",
                    _ => return None,
                }
            }
            _ => return None,
        };

        Some((action, api_id, resource_id))
    }
}

#[async_trait]
impl AwsService for ApiGatewayV2Service {
    fn service_name(&self) -> &str {
        "apigateway"
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        // Check if this is a management API request or an execute API request
        // Management API: /v2/* (apis, domainnames, vpclinks, routingrules,
        // tags, portals, portalproducts)
        // Execute API: /{stage}/{path}
        if req.path_segments.first().map(|s| s.as_str()) == Some("v2") {
            return self.handle_management_api(req).await;
        }

        // Execute API
        self.handle_execute_api(req).await
    }

    fn supported_actions(&self) -> &[&str] {
        SUPPORTED
    }
}

impl ApiGatewayV2Service {
    async fn handle_management_api(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let (action, api_id, resource_id) = Self::resolve_action(&req).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("Unknown path: {}", req.raw_path),
            )
        })?;
        // Normalize invalid path-derived ids to None so handlers that
        // require an id reject the request instead of silently
        // operating on a placeholder. See extras::valid_path_id.
        let api_id = api_id.filter(|s| crate::extras::valid_path_id(s));
        let resource_id = resource_id.filter(|s| crate::extras::valid_path_id(s));
        let mutates = action.starts_with("Create")
            || action.starts_with("Update")
            || action.starts_with("Delete")
            || action.starts_with("Put")
            || action.starts_with("Tag")
            || action.starts_with("Untag")
            || action == "ImportApi"
            || action == "ReimportApi"
            || action == "DisablePortal"
            || action == "PreviewPortal"
            || action == "PublishPortal"
            || action == "ResetAuthorizersCache";

        let result = match action {
            "CreateApi" => self.create_api(&req),
            "GetApi" => self.get_api(&req, api_id.as_deref()),
            "GetApis" => self.get_apis(&req),
            "UpdateApi" => self.update_api(&req, api_id.as_deref()),
            "DeleteApi" => self.delete_api(&req, api_id.as_deref()),
            "CreateRoute" => self.create_route(&req, api_id.as_deref()),
            "GetRoute" => self.get_route(&req, api_id.as_deref(), resource_id.as_deref()),
            "GetRoutes" => self.get_routes(&req, api_id.as_deref()),
            "UpdateRoute" => self.update_route(&req, api_id.as_deref(), resource_id.as_deref()),
            "DeleteRoute" => self.delete_route(&req, api_id.as_deref(), resource_id.as_deref()),
            "CreateIntegration" => self.create_integration(&req, api_id.as_deref()),
            "GetIntegration" => {
                self.get_integration(&req, api_id.as_deref(), resource_id.as_deref())
            }
            "GetIntegrations" => self.get_integrations(&req, api_id.as_deref()),
            "UpdateIntegration" => {
                self.update_integration(&req, api_id.as_deref(), resource_id.as_deref())
            }
            "DeleteIntegration" => {
                self.delete_integration(&req, api_id.as_deref(), resource_id.as_deref())
            }
            "CreateStage" => self.create_stage(&req, api_id.as_deref()),
            "GetStage" => self.get_stage(&req, api_id.as_deref(), resource_id.as_deref()),
            "GetStages" => self.get_stages(&req, api_id.as_deref()),
            "UpdateStage" => self.update_stage(&req, api_id.as_deref(), resource_id.as_deref()),
            "DeleteStage" => self.delete_stage(&req, api_id.as_deref(), resource_id.as_deref()),
            "CreateDeployment" => self.create_deployment(&req, api_id.as_deref()),
            "GetDeployment" => self.get_deployment(&req, api_id.as_deref(), resource_id.as_deref()),
            "GetDeployments" => self.get_deployments(&req, api_id.as_deref()),
            "CreateAuthorizer" => self.create_authorizer(&req, api_id.as_deref()),
            "GetAuthorizer" => self.get_authorizer(&req, api_id.as_deref(), resource_id.as_deref()),
            "GetAuthorizers" => self.get_authorizers(&req, api_id.as_deref()),
            "UpdateAuthorizer" => {
                self.update_authorizer(&req, api_id.as_deref(), resource_id.as_deref())
            }
            "DeleteAuthorizer" => {
                self.delete_authorizer(&req, api_id.as_deref(), resource_id.as_deref())
            }
            other => {
                self.handle_extra_action(other, &req, api_id.as_deref(), resource_id.as_deref())
            }
        };
        if mutates && matches!(result.as_ref(), Ok(resp) if resp.status.is_success()) {
            self.save_snapshot().await;
        }
        result
    }

    // ─── API CRUD ───────────────────────────────────────────────────────

    fn create_api(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();

        // API Gateway v2 REST API uses lowercase field names
        validate_required("name", &body["name"])?;
        let name = body["name"]
            .as_str()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "name is required",
                )
            })?
            .to_string();

        validate_required("protocolType", &body["protocolType"])?;
        let protocol_type = body["protocolType"].as_str().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "protocolType is required",
            )
        })?;

        if protocol_type != "HTTP" && protocol_type != "WEBSOCKET" {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                format!("Unsupported protocol type: {}", protocol_type),
            ));
        }
        let protocol_type = protocol_type.to_string();

        let description = body["description"].as_str().map(|s| s.to_string());
        let tags = body["tags"].as_object().map(|m| {
            m.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        });

        // Parse CORS configuration if provided
        let cors_configuration = if let Some(cors) = body.get("corsConfiguration") {
            Some(serde_json::from_value(cors.clone()).map_err(|e| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    format!("Invalid corsConfiguration: {}", e),
                )
            })?)
        } else {
            None
        };

        let api_id = generate_id("api");
        let region = &req.region;

        let mut api = HttpApi::new(api_id, name, description, tags, region);
        api.cors_configuration = cors_configuration;
        api.protocol_type = protocol_type.clone();
        if protocol_type == "WEBSOCKET" {
            // WebSocket APIs use a body-based selection expression by default
            // and have no implicit api-key header selector.
            api.route_selection_expression = "$request.body.action".to_string();
            api.api_key_selection_expression = "$request.header.x-api-key".to_string();
            if let Some(rse) = body
                .get("routeSelectionExpression")
                .and_then(|v| v.as_str())
            {
                api.route_selection_expression = rse.to_string();
            }
            if let Some(akse) = body
                .get("apiKeySelectionExpression")
                .and_then(|v| v.as_str())
            {
                api.api_key_selection_expression = akse.to_string();
            }
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let api_clone = api.clone();
        state.apis.insert(api.api_id.clone(), api);

        Ok(AwsResponse::ok_json(json!(api_clone)))
    }

    fn get_api(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let accounts = self.state.read();
        let empty = ApiGatewayV2State::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let api = state.apis.get(api_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            )
        })?;

        Ok(AwsResponse::ok_json(json!(api)))
    }

    fn get_apis(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let empty = ApiGatewayV2State::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let apis: Vec<&HttpApi> = state.apis.values().collect();

        Ok(AwsResponse::ok_json(json!({
            "items": apis,
        })))
    }

    fn update_api(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let body = req.json_body();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        let api = state.apis.get_mut(api_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            )
        })?;

        if let Some(name) = body["name"].as_str() {
            api.name = name.to_string();
        }

        if let Some(description) = body["description"].as_str() {
            api.description = Some(description.to_string());
        }

        if let Some(cors) = body.get("corsConfiguration") {
            api.cors_configuration = Some(serde_json::from_value(cors.clone()).map_err(|e| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    format!("Invalid corsConfiguration: {}", e),
                )
            })?);
        }

        Ok(AwsResponse::ok_json(json!(api)))
    }

    fn delete_api(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        state.apis.remove(api_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            )
        })?;

        Ok(AwsResponse::json(StatusCode::NO_CONTENT, vec![]))
    }

    // ─── ROUTE CRUD ─────────────────────────────────────────────────────

    fn create_route(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let body = req.json_body();

        validate_required("routeKey", &body["routeKey"])?;
        let route_key = body["routeKey"]
            .as_str()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "routeKey is required",
                )
            })?
            .to_string();

        let target = body["target"].as_str().map(|s| s.to_string());
        let authorization_type = body["authorizationType"].as_str().map(|s| s.to_string());
        let authorizer_id = body["authorizerId"].as_str().map(|s| s.to_string());

        let route_id = generate_id("route");

        let route = Route {
            route_id: route_id.clone(),
            route_key,
            target,
            authorization_type,
            authorizer_id,
        };

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        // Verify API exists
        if !state.apis.contains_key(api_id) {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            ));
        }

        state
            .routes
            .entry(api_id.to_string())
            .or_default()
            .insert(route_id, route.clone());

        Ok(AwsResponse::ok_json(json!(route)))
    }

    fn get_route(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
        route_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let route_id = route_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "Route ID is required",
            )
        })?;

        let accounts = self.state.read();
        let empty = ApiGatewayV2State::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);

        let routes = state.routes.get(api_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            )
        })?;

        let route = routes.get(route_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("Route not found: {}", route_id),
            )
        })?;

        Ok(AwsResponse::ok_json(json!(route)))
    }

    fn get_routes(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let accounts = self.state.read();
        let empty = ApiGatewayV2State::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);

        // Verify API exists
        if !state.apis.contains_key(api_id) {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            ));
        }

        let routes: Vec<&Route> = state
            .routes
            .get(api_id)
            .map(|r| r.values().collect())
            .unwrap_or_default();

        Ok(AwsResponse::ok_json(json!({
            "items": routes,
        })))
    }

    fn update_route(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
        route_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let route_id = route_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "Route ID is required",
            )
        })?;

        let body = req.json_body();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        let routes = state.routes.get_mut(api_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            )
        })?;

        let route = routes.get_mut(route_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("Route not found: {}", route_id),
            )
        })?;

        if let Some(route_key) = body["routeKey"].as_str() {
            route.route_key = route_key.to_string();
        }

        if let Some(target) = body["target"].as_str() {
            route.target = Some(target.to_string());
        }

        if let Some(authorization_type) = body["authorizationType"].as_str() {
            route.authorization_type = Some(authorization_type.to_string());
        }

        if let Some(authorizer_id) = body["authorizerId"].as_str() {
            route.authorizer_id = Some(authorizer_id.to_string());
        }

        Ok(AwsResponse::ok_json(json!(route)))
    }

    fn delete_route(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
        route_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let route_id = route_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "Route ID is required",
            )
        })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        let routes = state.routes.get_mut(api_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            )
        })?;

        routes.remove(route_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("Route not found: {}", route_id),
            )
        })?;

        Ok(AwsResponse::json(StatusCode::NO_CONTENT, vec![]))
    }

    // ─── INTEGRATION CRUD ───────────────────────────────────────────────

    fn create_integration(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let body = req.json_body();

        validate_required("integrationType", &body["integrationType"])?;
        let integration_type = body["integrationType"]
            .as_str()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "integrationType is required",
                )
            })?
            .to_string();

        let integration_uri = body["integrationUri"].as_str().map(|s| s.to_string());
        let payload_format_version = body["payloadFormatVersion"].as_str().map(|s| s.to_string());
        let timeout_in_millis = body["timeoutInMillis"].as_i64();

        let integration_id = generate_id("integration");

        let integration = Integration {
            integration_id: integration_id.clone(),
            integration_type,
            integration_uri,
            payload_format_version,
            timeout_in_millis,
        };

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        // Verify API exists
        if !state.apis.contains_key(api_id) {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            ));
        }

        state
            .integrations
            .entry(api_id.to_string())
            .or_default()
            .insert(integration_id, integration.clone());

        Ok(AwsResponse::ok_json(json!(integration)))
    }

    fn get_integration(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
        integration_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let integration_id = integration_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "Integration ID is required",
            )
        })?;

        let accounts = self.state.read();
        let empty = ApiGatewayV2State::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);

        let integrations = state.integrations.get(api_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            )
        })?;

        let integration = integrations.get(integration_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("Integration not found: {}", integration_id),
            )
        })?;

        Ok(AwsResponse::ok_json(json!(integration)))
    }

    fn get_integrations(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let accounts = self.state.read();
        let empty = ApiGatewayV2State::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);

        // Verify API exists
        if !state.apis.contains_key(api_id) {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            ));
        }

        let integrations: Vec<&Integration> = state
            .integrations
            .get(api_id)
            .map(|i| i.values().collect())
            .unwrap_or_default();

        Ok(AwsResponse::ok_json(json!({
            "items": integrations,
        })))
    }

    fn update_integration(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
        integration_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let integration_id = integration_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "Integration ID is required",
            )
        })?;

        let body = req.json_body();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        let integrations = state.integrations.get_mut(api_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            )
        })?;

        let integration = integrations.get_mut(integration_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("Integration not found: {}", integration_id),
            )
        })?;

        if let Some(integration_type) = body["integrationType"].as_str() {
            integration.integration_type = integration_type.to_string();
        }

        if let Some(integration_uri) = body["integrationUri"].as_str() {
            integration.integration_uri = Some(integration_uri.to_string());
        }

        if let Some(payload_format_version) = body["payloadFormatVersion"].as_str() {
            integration.payload_format_version = Some(payload_format_version.to_string());
        }

        if let Some(timeout_in_millis) = body["timeoutInMillis"].as_i64() {
            integration.timeout_in_millis = Some(timeout_in_millis);
        }

        Ok(AwsResponse::ok_json(json!(integration)))
    }

    fn delete_integration(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
        integration_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let integration_id = integration_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "Integration ID is required",
            )
        })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        let integrations = state.integrations.get_mut(api_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            )
        })?;

        integrations.remove(integration_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("Integration not found: {}", integration_id),
            )
        })?;

        Ok(AwsResponse::json(StatusCode::NO_CONTENT, vec![]))
    }

    // ─── STAGE CRUD ─────────────────────────────────────────────────────

    fn create_stage(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let body = req.json_body();

        validate_required("stageName", &body["stageName"])?;
        let stage_name = body["stageName"]
            .as_str()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "stageName is required",
                )
            })?
            .to_string();

        let description = body["description"].as_str().map(|s| s.to_string());
        let auto_deploy = body["autoDeploy"].as_bool().unwrap_or(false);
        let deployment_id = body["deploymentId"].as_str().map(|s| s.to_string());

        let created_date = chrono::Utc::now();

        let stage = Stage {
            stage_name: stage_name.clone(),
            description,
            deployment_id,
            auto_deploy,
            created_date,
            last_updated_date: None,
        };

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        // Verify API exists
        if !state.apis.contains_key(api_id) {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            ));
        }

        // Check for duplicate stage
        if state
            .stages
            .get(api_id)
            .is_some_and(|stages| stages.contains_key(&stage_name))
        {
            return Err(AwsServiceError::aws_error(
                StatusCode::CONFLICT,
                "ConflictException",
                format!("Stage already exists: {}", stage_name),
            ));
        }

        state
            .stages
            .entry(api_id.to_string())
            .or_default()
            .insert(stage_name, stage.clone());

        Ok(AwsResponse::ok_json(json!(stage)))
    }

    fn get_stage(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
        stage_name: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let stage_name = stage_name.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "Stage name is required",
            )
        })?;

        let accounts = self.state.read();
        let empty = ApiGatewayV2State::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);

        let stages = state.stages.get(api_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            )
        })?;

        let stage = stages.get(stage_name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("Stage not found: {}", stage_name),
            )
        })?;

        Ok(AwsResponse::ok_json(json!(stage)))
    }

    fn get_stages(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let accounts = self.state.read();
        let empty = ApiGatewayV2State::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);

        // Verify API exists
        if !state.apis.contains_key(api_id) {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            ));
        }

        let stages: Vec<&Stage> = state
            .stages
            .get(api_id)
            .map(|s| s.values().collect())
            .unwrap_or_default();

        Ok(AwsResponse::ok_json(json!({
            "items": stages,
        })))
    }

    fn update_stage(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
        stage_name: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let stage_name = stage_name.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "Stage name is required",
            )
        })?;

        let body = req.json_body();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        let stages = state.stages.get_mut(api_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            )
        })?;

        let stage = stages.get_mut(stage_name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("Stage not found: {}", stage_name),
            )
        })?;

        if let Some(description) = body["description"].as_str() {
            stage.description = Some(description.to_string());
        }

        if let Some(auto_deploy) = body["autoDeploy"].as_bool() {
            stage.auto_deploy = auto_deploy;
        }

        if let Some(deployment_id) = body["deploymentId"].as_str() {
            stage.deployment_id = Some(deployment_id.to_string());
        }

        stage.last_updated_date = Some(chrono::Utc::now());

        Ok(AwsResponse::ok_json(json!(stage)))
    }

    fn delete_stage(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
        stage_name: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let stage_name = stage_name.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "Stage name is required",
            )
        })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        let stages = state.stages.get_mut(api_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            )
        })?;

        stages.remove(stage_name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("Stage not found: {}", stage_name),
            )
        })?;

        Ok(AwsResponse::json(StatusCode::NO_CONTENT, vec![]))
    }

    // ─── DEPLOYMENT CRUD ────────────────────────────────────────────────

    fn create_deployment(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let body = req.json_body();
        let description = body["description"].as_str().map(|s| s.to_string());
        let stage_name = body["stageName"].as_str();

        let deployment_id = generate_id("deployment");
        let created_date = chrono::Utc::now();

        let deployment = Deployment {
            deployment_id: deployment_id.clone(),
            description,
            created_date,
            auto_deployed: false,
        };

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        // Verify API exists
        if !state.apis.contains_key(api_id) {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            ));
        }

        state
            .deployments
            .entry(api_id.to_string())
            .or_default()
            .insert(deployment_id.clone(), deployment.clone());

        // If stage_name is provided, update the stage's deployment_id
        if let Some(stage_name) = stage_name {
            if let Some(stages) = state.stages.get_mut(api_id) {
                if let Some(stage) = stages.get_mut(stage_name) {
                    stage.deployment_id = Some(deployment_id);
                    stage.last_updated_date = Some(chrono::Utc::now());
                }
            }
        }

        Ok(AwsResponse::ok_json(json!(deployment)))
    }

    fn get_deployment(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
        deployment_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let deployment_id = deployment_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "Deployment ID is required",
            )
        })?;

        let accounts = self.state.read();
        let empty = ApiGatewayV2State::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);

        let deployments = state.deployments.get(api_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            )
        })?;

        let deployment = deployments.get(deployment_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("Deployment not found: {}", deployment_id),
            )
        })?;

        Ok(AwsResponse::ok_json(json!(deployment)))
    }

    fn get_deployments(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let accounts = self.state.read();
        let empty = ApiGatewayV2State::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);

        // Verify API exists
        if !state.apis.contains_key(api_id) {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            ));
        }

        let deployments: Vec<&Deployment> = state
            .deployments
            .get(api_id)
            .map(|d| d.values().collect())
            .unwrap_or_default();

        Ok(AwsResponse::ok_json(json!({
            "items": deployments,
        })))
    }

    // ─── AUTHORIZER CRUD ────────────────────────────────────────────────

    fn create_authorizer(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let body = req.json_body();

        validate_required("name", &body["name"])?;
        let name = body["name"]
            .as_str()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "name is required",
                )
            })?
            .to_string();

        validate_required("authorizerType", &body["authorizerType"])?;
        let authorizer_type = body["authorizerType"]
            .as_str()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "authorizerType is required",
                )
            })?
            .to_string();

        let authorizer_uri = body["authorizerUri"].as_str().map(|s| s.to_string());
        let identity_source = body["identitySource"].as_array().map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        });

        let jwt_configuration = if let Some(jwt) = body.get("jwtConfiguration") {
            Some(serde_json::from_value(jwt.clone()).map_err(|e| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    format!("Invalid jwtConfiguration: {}", e),
                )
            })?)
        } else {
            None
        };

        let authorizer_id = generate_id("auth");

        let authorizer = Authorizer {
            authorizer_id: authorizer_id.clone(),
            name,
            authorizer_type,
            authorizer_uri,
            identity_source,
            jwt_configuration,
        };

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        // Verify API exists
        if !state.apis.contains_key(api_id) {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            ));
        }

        state
            .authorizers
            .entry(api_id.to_string())
            .or_default()
            .insert(authorizer_id, authorizer.clone());

        Ok(AwsResponse::ok_json(json!(authorizer)))
    }

    fn get_authorizer(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
        authorizer_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let authorizer_id = authorizer_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "Authorizer ID is required",
            )
        })?;

        let accounts = self.state.read();
        let empty = ApiGatewayV2State::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);

        // Verify API exists
        if !state.apis.contains_key(api_id) {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            ));
        }

        let authorizer = state
            .authorizers
            .get(api_id)
            .and_then(|auths| auths.get(authorizer_id))
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "NotFoundException",
                    format!("Authorizer not found: {}", authorizer_id),
                )
            })?;

        Ok(AwsResponse::ok_json(json!(authorizer)))
    }

    fn get_authorizers(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let accounts = self.state.read();
        let empty = ApiGatewayV2State::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);

        // Verify API exists
        if !state.apis.contains_key(api_id) {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            ));
        }

        let authorizers: Vec<&Authorizer> = state
            .authorizers
            .get(api_id)
            .map(|auths| auths.values().collect())
            .unwrap_or_default();

        Ok(AwsResponse::ok_json(json!({
            "items": authorizers,
        })))
    }

    fn update_authorizer(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
        authorizer_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let authorizer_id = authorizer_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "Authorizer ID is required",
            )
        })?;

        let body = req.json_body();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        // Verify API exists
        if !state.apis.contains_key(api_id) {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            ));
        }

        let authorizer = state
            .authorizers
            .get_mut(api_id)
            .and_then(|auths| auths.get_mut(authorizer_id))
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "NotFoundException",
                    format!("Authorizer not found: {}", authorizer_id),
                )
            })?;

        if let Some(name) = body["name"].as_str() {
            authorizer.name = name.to_string();
        }

        if let Some(authorizer_uri) = body["authorizerUri"].as_str() {
            authorizer.authorizer_uri = Some(authorizer_uri.to_string());
        }

        if let Some(identity_source) = body["identitySource"].as_array() {
            authorizer.identity_source = Some(
                identity_source
                    .iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect(),
            );
        }

        if let Some(jwt) = body.get("jwtConfiguration") {
            authorizer.jwt_configuration =
                Some(serde_json::from_value(jwt.clone()).map_err(|e| {
                    AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "ValidationException",
                        format!("Invalid jwtConfiguration: {}", e),
                    )
                })?);
        }

        Ok(AwsResponse::ok_json(json!(authorizer)))
    }

    fn delete_authorizer(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
        authorizer_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api_id = api_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "API ID is required",
            )
        })?;

        let authorizer_id = authorizer_id.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BadRequestException",
                "Authorizer ID is required",
            )
        })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        // Verify API exists
        if !state.apis.contains_key(api_id) {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                format!("API not found: {}", api_id),
            ));
        }

        state
            .authorizers
            .get_mut(api_id)
            .and_then(|auths| auths.remove(authorizer_id))
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "NotFoundException",
                    format!("Authorizer not found: {}", authorizer_id),
                )
            })?;

        Ok(AwsResponse::json(StatusCode::NO_CONTENT, vec![]))
    }

    // ─── EXECUTE API ────────────────────────────────────────────────────

    async fn handle_execute_api(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        // Execute API format: /{stage}/{path...}
        if req.path_segments.is_empty() {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NotFoundException",
                "Stage not specified",
            ));
        }

        let stage_name = &req.path_segments[0];
        let resource_path = format!("/{}", req.path_segments[1..].join("/"));

        // Find the API for this stage and get CORS configuration
        let (api_id, routes, cors_config) = {
            let accounts = self.state.read();
            let empty = ApiGatewayV2State::new(&req.account_id, &req.region);
            let state = accounts.get(&req.account_id).unwrap_or(&empty);

            // Find which API has this stage (sort by API ID for deterministic resolution)
            let mut stage_entries: Vec<_> = state
                .stages
                .iter()
                .filter_map(|(api_id, stages)| {
                    stages
                        .get(stage_name)
                        .map(|stage| (api_id.clone(), stage.clone()))
                })
                .collect();
            stage_entries.sort_by(|a, b| a.0.cmp(&b.0));
            let (api_id, _stage) = stage_entries.into_iter().next().ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "NotFoundException",
                    format!("Stage not found: {}", stage_name),
                )
            })?;

            // Get routes for this API
            let routes = state
                .routes
                .get(&api_id)
                .map(|r| r.values().cloned().collect())
                .unwrap_or_default();

            // Get CORS configuration from API
            let cors_config = state
                .apis
                .get(&api_id)
                .and_then(|api| api.cors_configuration.clone());

            Ok::<_, AwsServiceError>((api_id, routes, cors_config))
        }?;

        // Handle CORS preflight requests
        if let Some(ref cors_cfg) = cors_config {
            if cors::is_preflight_request(&req) {
                return Ok(cors::handle_preflight(cors_cfg, &req));
            }
        }

        // Match the request against routes
        let router = Router::new(routes);
        let route_match = router
            .match_route(req.method.as_str(), &resource_path)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "NotFoundException",
                    format!("No route matches: {} {}", req.method, resource_path),
                )
            })?;

        // Get the integration for this route
        let integration_id = route_match
            .route
            .target
            .as_ref()
            .and_then(|target| target.strip_prefix("integrations/"))
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "Route has no integration",
                )
            })?;

        let integration = {
            let accounts = self.state.read();
            let empty = ApiGatewayV2State::new(&req.account_id, &req.region);
            let state = accounts.get(&req.account_id).unwrap_or(&empty);
            state
                .integrations
                .get(&api_id)
                .and_then(|integrations| integrations.get(integration_id))
                .ok_or_else(|| {
                    AwsServiceError::aws_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        format!("Integration not found: {}", integration_id),
                    )
                })?
                .clone()
        };

        // Handle based on integration type
        let mut response = match integration.integration_type.as_str() {
            "AWS_PROXY" => {
                // Lambda proxy integration
                let delivery = self.delivery.as_ref().ok_or_else(|| {
                    AwsServiceError::aws_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        "Lambda delivery not configured",
                    )
                })?;

                let function_arn = integration.integration_uri.as_ref().ok_or_else(|| {
                    AwsServiceError::aws_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        "Integration has no URI",
                    )
                })?;

                let event = lambda_proxy::construct_event(
                    &req,
                    &route_match.route.route_key,
                    stage_name,
                    route_match.path_parameters,
                );

                lambda_proxy::invoke_lambda(delivery, function_arn, event).await?
            }
            "HTTP_PROXY" => {
                // HTTP proxy integration
                let target_url = integration.integration_uri.as_ref().ok_or_else(|| {
                    AwsServiceError::aws_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        "Integration has no URI",
                    )
                })?;

                http_proxy::forward_request(target_url, &req, integration.timeout_in_millis).await?
            }
            "MOCK" => {
                // Mock integration
                mock::create_mock_response()
            }
            _ => {
                return Err(AwsServiceError::aws_error(
                    StatusCode::NOT_IMPLEMENTED,
                    "NotImplemented",
                    format!(
                        "Integration type not supported: {}",
                        integration.integration_type
                    ),
                ));
            }
        };

        // Add CORS headers if CORS is configured
        if let Some(ref cors_cfg) = cors_config {
            response = cors::add_cors_headers(response, cors_cfg);
        }

        // Record this request to history
        self.record_request(
            &req,
            &api_id,
            stage_name,
            &resource_path,
            response.status.as_u16(),
        );

        Ok(response)
    }

    fn record_request(
        &self,
        req: &AwsRequest,
        api_id: &str,
        stage: &str,
        path: &str,
        status_code: u16,
    ) {
        let headers_map: std::collections::BTreeMap<String, String> = req
            .headers
            .iter()
            .filter_map(|(k, v)| {
                v.to_str()
                    .ok()
                    .map(|v_str| (k.as_str().to_string(), v_str.to_string()))
            })
            .collect();

        let body_string = if req.body.is_empty() {
            None
        } else {
            String::from_utf8(req.body.to_vec()).ok()
        };

        let request_record = ApiRequest {
            request_id: uuid::Uuid::new_v4().to_string(),
            api_id: api_id.to_string(),
            stage: stage.to_string(),
            method: req.method.to_string(),
            path: path.to_string(),
            headers: headers_map,
            query_params: req.query_params.clone().into_iter().collect(),
            body: body_string,
            timestamp: chrono::Utc::now(),
            status_code,
        };

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state.request_history.push(request_record);
    }
}

#[path = "service_helpers.rs"]
mod service_helpers;
pub(crate) use service_helpers::*;

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
