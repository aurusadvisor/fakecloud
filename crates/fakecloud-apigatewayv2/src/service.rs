use async_trait::async_trait;
use http::{Method, StatusCode};
use serde_json::json;
use std::collections::BTreeMap;
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
use lambda_proxy::AuthorizerInfo;

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
    /// WAFv2 inspection wiring. When set together with
    /// `waf_rate_limiter`, the data plane evaluates each request
    /// against the WebACL associated with the matched stage's ARN
    /// before authorizer / integration dispatch.
    pub(crate) waf_state: Option<fakecloud_wafv2::SharedWafv2State>,
    pub(crate) waf_rate_limiter: Option<Arc<fakecloud_wafv2::RateLimiter>>,
    /// Per-(WebACL ARN, rule name) Count-action match counter. Keyed
    /// by `"<acl-arn>|<rule-name>"`.
    pub(crate) waf_count_metrics: Arc<parking_lot::Mutex<std::collections::BTreeMap<String, u64>>>,
}

impl ApiGatewayV2Service {
    pub fn new(state: SharedApiGatewayV2State) -> Self {
        Self {
            state,
            delivery: None,
            snapshot_store: None,
            snapshot_lock: Arc::new(AsyncMutex::new(())),
            waf_state: None,
            waf_rate_limiter: None,
            waf_count_metrics: Arc::new(parking_lot::Mutex::new(std::collections::BTreeMap::new())),
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

    /// Wire the shared WAFv2 state + rate limiter so the execute-API
    /// data plane can evaluate the WebACL associated with the matched
    /// stage's ARN. Pass the same `Wafv2Service::rate_limiter()`
    /// instance every dataplane uses so `RateBasedStatement` counters
    /// stay consistent.
    pub fn with_waf(
        mut self,
        state: fakecloud_wafv2::SharedWafv2State,
        rate_limiter: Arc<fakecloud_wafv2::RateLimiter>,
    ) -> Self {
        self.waf_state = Some(state);
        self.waf_rate_limiter = Some(rate_limiter);
        self
    }

    /// Snapshot of the WAF Count-action metrics. Keyed by
    /// `"<webacl-arn>|<rule-name>"`. Returns an empty map when WAF
    /// inspection is disabled.
    pub fn waf_count_metrics_snapshot(&self) -> std::collections::BTreeMap<String, u64> {
        self.waf_count_metrics.lock().clone()
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
        let stage_variables = body["stageVariables"].as_object().map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect::<BTreeMap<String, String>>()
        });

        let access_log_settings = body.get("accessLogSettings").and_then(|v| {
            if v.is_null() {
                return None;
            }
            let destination_arn = v.get("destinationArn")?.as_str()?.to_string();
            let format = v.get("format").and_then(|f| f.as_str().map(String::from));
            Some(crate::state::AccessLogSettings {
                destination_arn,
                format,
            })
        });

        let created_date = chrono::Utc::now();

        let stage = Stage {
            stage_name: stage_name.clone(),
            description,
            deployment_id,
            auto_deploy,
            created_date,
            last_updated_date: None,
            web_acl_arn: None,
            stage_variables,
            access_log_settings,
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

        if let Some(vars) = body["stageVariables"].as_object() {
            let mut map = BTreeMap::new();
            for (k, v) in vars.iter() {
                if let Some(s) = v.as_str() {
                    map.insert(k.clone(), s.to_string());
                }
            }
            stage.stage_variables = Some(map);
        }

        if let Some(settings) = body.get("accessLogSettings") {
            if settings.is_null() {
                stage.access_log_settings = None;
            } else {
                let destination_arn = settings["destinationArn"].as_str().map(String::from);
                let format = settings["format"].as_str().map(String::from);
                stage.access_log_settings =
                    destination_arn.map(|arn| crate::state::AccessLogSettings {
                        destination_arn: arn,
                        format,
                    });
            }
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

    async fn handle_execute_api(
        &self,
        mut req: AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut api_id = String::new();
        let mut stage_name = String::new();
        let mut resource_path = String::new();

        let result: Result<AwsResponse, AwsServiceError> = async {
            // Try custom domain resolution first.
            let (a, s, stage_vars) = {
                let accounts = self.state.read();
                let empty = ApiGatewayV2State::new(&req.account_id, &req.region);
                let state = accounts.get(&req.account_id).unwrap_or(&empty);

                if let Some((a, s, new_segs, new_raw_path)) = resolve_custom_domain(&req, state) {
                    req.path_segments = new_segs;
                    req.raw_path = new_raw_path;
                    let stage_vars = state
                        .stages
                        .get(&a)
                        .and_then(|stages| stages.get(&s))
                        .and_then(|st| st.stage_variables.clone())
                        .unwrap_or_default();
                    (a, s, stage_vars)
                } else {
                    // Execute API format: /{stage}/{path...}
                    if req.path_segments.is_empty() {
                        return Err(AwsServiceError::aws_error(
                            StatusCode::NOT_FOUND,
                            "NotFoundException",
                            "Stage not specified",
                        ));
                    }
                    let s = req.path_segments[0].clone();
                    // Strip the stage segment so route matching uses the resource path.
                    req.path_segments.remove(0);
                    let stage_vars = state
                        .stages
                        .iter()
                        .find_map(|(_, stages)| stages.get(&s))
                        .and_then(|st| st.stage_variables.clone())
                        .unwrap_or_default();
                    // Find which API has this stage (sort by API ID for deterministic resolution)
                    let mut stage_entries: Vec<_> = state
                        .stages
                        .iter()
                        .filter_map(|(api_id, stages)| {
                            stages.get(&s).map(|stage| (api_id.clone(), stage.clone()))
                        })
                        .collect();
                    stage_entries.sort_by(|a, b| a.0.cmp(&b.0));
                    let (a, _) = stage_entries.into_iter().next().ok_or_else(|| {
                        AwsServiceError::aws_error(
                            StatusCode::NOT_FOUND,
                            "NotFoundException",
                            format!("Stage not found: {}", s),
                        )
                    })?;
                    (a, s, stage_vars)
                }
            };

            api_id = a;
            stage_name = s;

            resource_path = if req.path_segments.is_empty() {
                "/".to_string()
            } else {
                format!("/{}", req.path_segments.join("/"))
            };

            let (routes, cors_config) = {
                let accounts = self.state.read();
                let empty = ApiGatewayV2State::new(&req.account_id, &req.region);
                let state = accounts.get(&req.account_id).unwrap_or(&empty);

                let routes = state
                    .routes
                    .get(&api_id)
                    .map(|r| r.values().cloned().collect())
                    .unwrap_or_default();

                let cors_config = state
                    .apis
                    .get(&api_id)
                    .and_then(|api| api.cors_configuration.clone());

                (routes, cors_config)
            };

            // Handle CORS preflight requests
            if let Some(ref cors_cfg) = cors_config {
                if cors::is_preflight_request(&req) {
                    return Ok(cors::handle_preflight(cors_cfg, &req));
                }
            }

            // WAFv2 inspection: when the matched stage's ARN is associated
            // with a WebACL and the service was wired with WAF state,
            // evaluate the request before route match / authorizer /
            // integration. Block / Captcha / Challenge short-circuit;
            // Count is recorded but lets the request continue.
            if let Some(resp) = self.evaluate_waf(&req, &api_id, &stage_name) {
                return Ok(resp);
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

            // Authorizer enforcement
            let authorizer_info = self
                .enforce_authorizer(&req, &api_id, &route_match.route)
                .await?;

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

            let mut integration = {
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

            // Substitute stage variables into the integration URI before dispatch.
            if let Some(ref uri) = integration.integration_uri {
                let substituted = substitute_stage_variables(uri, &stage_vars);
                if substituted != *uri {
                    integration.integration_uri = Some(substituted);
                }
            }

            // Handle based on integration type
            let mut response = match integration.integration_type.as_str() {
                "AWS_PROXY" => {
                    let delivery = self.delivery.as_ref().ok_or_else(|| {
                        AwsServiceError::aws_error(
                            StatusCode::INTERNAL_SERVER_ERROR,
                            "InternalError",
                            "Lambda delivery not configured",
                        )
                    })?;

                    let integration_uri =
                        integration.integration_uri.as_ref().ok_or_else(|| {
                            AwsServiceError::aws_error(
                                StatusCode::INTERNAL_SERVER_ERROR,
                                "InternalError",
                                "Integration has no URI",
                            )
                        })?;

                    if is_lambda_arn(integration_uri) {
                        let event = lambda_proxy::construct_event(
                            &req,
                            &route_match.route.route_key,
                            &stage_name,
                            route_match.path_parameters,
                            authorizer_info,
                        );
                        lambda_proxy::invoke_lambda(delivery, integration_uri, event).await?
                    } else {
                        dispatch_aws_service_integration(delivery, integration_uri, &req)?
                    }
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

                    http_proxy::forward_request(target_url, &req, integration.timeout_in_millis)
                        .await?
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

            Ok(response)
        }
        .await;

        let status_code = match &result {
            Ok(resp) => resp.status.as_u16(),
            Err(err) => err.status().as_u16(),
        };

        self.record_request(&req, &api_id, &stage_name, &resource_path, status_code);

        self.emit_access_log(&req, &api_id, &stage_name, &resource_path, status_code);

        result
    }

    /// Enforce the authorizer configured on a route. Returns an
    /// `AuthorizerInfo` when validation succeeds, or `None` when the route
    /// has no authorizer. Propagates `401 Unauthorized` on failure.
    async fn enforce_authorizer(
        &self,
        req: &AwsRequest,
        api_id: &str,
        route: &Route,
    ) -> Result<Option<AuthorizerInfo>, AwsServiceError> {
        let authorizer_id = match &route.authorizer_id {
            Some(id) => id,
            None => return Ok(None),
        };

        let authorizer = {
            let accounts = self.state.read();
            let empty = ApiGatewayV2State::new(&req.account_id, &req.region);
            let state = accounts.get(&req.account_id).unwrap_or(&empty);
            state
                .authorizers
                .get(api_id)
                .and_then(|a| a.get(authorizer_id))
                .cloned()
        };

        let Some(authorizer) = authorizer else {
            return Err(AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!("Authorizer not found: {}", authorizer_id),
            ));
        };

        match authorizer.authorizer_type.as_str() {
            "JWT" => self.enforce_jwt_authorizer(req, &authorizer).await,
            "REQUEST" => {
                self.enforce_lambda_authorizer(req, api_id, &authorizer)
                    .await
            }
            _ => Err(AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                format!(
                    "Unsupported authorizer type: {}",
                    authorizer.authorizer_type
                ),
            )),
        }
    }

    /// Validate a JWT token against the configured issuer and audience.
    async fn enforce_jwt_authorizer(
        &self,
        req: &AwsRequest,
        authorizer: &Authorizer,
    ) -> Result<Option<AuthorizerInfo>, AwsServiceError> {
        let identity_sources = authorizer.identity_source.as_ref().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::UNAUTHORIZED,
                "UnauthorizedException",
                "Authorizer has no identity source",
            )
        })?;

        let token_value = identity_sources
            .iter()
            .find_map(|source| extract_identity_source_value(req, source))
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::UNAUTHORIZED,
                    "UnauthorizedException",
                    "Missing required JWT",
                )
            })?;

        let token = token_value
            .strip_prefix("Bearer ")
            .or_else(|| token_value.strip_prefix("bearer "))
            .unwrap_or(&token_value)
            .trim();

        if token.is_empty() {
            return Err(AwsServiceError::aws_error(
                StatusCode::UNAUTHORIZED,
                "UnauthorizedException",
                "Empty Authorization header",
            ));
        }

        let jwt_config = authorizer.jwt_configuration.as_ref().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "JWT authorizer has no configuration",
            )
        })?;

        let issuer = jwt_config.issuer.as_ref().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "JWT authorizer has no issuer",
            )
        })?;

        let delivery = self.delivery.as_ref().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "JWT verifier not configured",
            )
        })?;

        let pool_arn =
            issuer_to_pool_arn(&req.account_id, &req.region, issuer).ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "Invalid JWT issuer format",
                )
            })?;

        let claims = delivery
            .verify_cognito_jwt(&req.account_id, &pool_arn, token)
            .map_err(|e| {
                AwsServiceError::aws_error(
                    StatusCode::UNAUTHORIZED,
                    "UnauthorizedException",
                    format!("Invalid JWT: {e}"),
                )
            })?;

        // Validate audience
        if let Some(audiences) = &jwt_config.audience {
            let token_aud = claims.get("aud").and_then(|v| v.as_str());
            let token_aud_array = claims.get("aud").and_then(|v| v.as_array());
            let matches = token_aud
                .map(|a| audiences.contains(&a.to_string()))
                .unwrap_or(false)
                || token_aud_array
                    .map(|arr| {
                        arr.iter().any(|v| {
                            v.as_str()
                                .map(|s| audiences.contains(&s.to_string()))
                                .unwrap_or(false)
                        })
                    })
                    .unwrap_or(false);
            if !matches {
                return Err(AwsServiceError::aws_error(
                    StatusCode::UNAUTHORIZED,
                    "UnauthorizedException",
                    "Invalid audience",
                ));
            }
        }

        Ok(Some(AuthorizerInfo::Jwt { claims }))
    }

    /// Invoke a Lambda authorizer (REQUEST type) and interpret the
    /// response. Supports both IAM-policy and simple-response formats.
    async fn enforce_lambda_authorizer(
        &self,
        req: &AwsRequest,
        api_id: &str,
        authorizer: &Authorizer,
    ) -> Result<Option<AuthorizerInfo>, AwsServiceError> {
        // Identity sources are optional for REQUEST authorizers.
        // When configured, every listed source must be present.
        if let Some(sources) = &authorizer.identity_source {
            for source in sources {
                if extract_identity_source_value(req, source)
                    .map(|v| v.is_empty())
                    .unwrap_or(true)
                {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::UNAUTHORIZED,
                        "UnauthorizedException",
                        "Missing required identity source",
                    ));
                }
            }
        }

        let auth_uri = authorizer.authorizer_uri.as_deref().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "Authorizer is missing authorizerUri; cannot invoke Lambda",
            )
        })?;
        let function_arn = extract_lambda_arn(auth_uri).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "authorizerUri must reference a Lambda function ARN",
            )
        })?;

        let method_arn = build_method_arn(req, api_id);

        let mut headers = serde_json::Map::new();
        for (k, v) in req.headers.iter() {
            if let Ok(s) = v.to_str() {
                headers.insert(
                    k.as_str().to_string(),
                    serde_json::Value::String(s.to_string()),
                );
            }
        }
        let mut query = serde_json::Map::new();
        for (k, v) in &req.query_params {
            query.insert(k.clone(), serde_json::Value::String(v.clone()));
        }

        let event = json!({
            "type": "REQUEST",
            "methodArn": method_arn,
            "resource": req.raw_path,
            "path": req.raw_path,
            "httpMethod": req.method.as_str(),
            "headers": headers,
            "queryStringParameters": query,
            "requestContext": {
                "apiId": api_id,
                "stage": req.path_segments.first().map(|s| s.as_str()).unwrap_or("$default"),
                "path": req.raw_path,
                "httpMethod": req.method.as_str(),
            },
        });

        let delivery = self.delivery.as_ref().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "Lambda delivery not configured",
            )
        })?;
        let response_bytes = delivery
            .invoke_lambda(&function_arn, &event.to_string())
            .await
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "Lambda delivery not configured",
                )
            })?
            .map_err(|e| {
                AwsServiceError::aws_error(
                    StatusCode::FORBIDDEN,
                    "ForbiddenException",
                    format!("Authorizer Lambda failed: {e}"),
                )
            })?;
        let response: serde_json::Value = serde_json::from_slice(&response_bytes).map_err(|e| {
            AwsServiceError::aws_error(
                StatusCode::FORBIDDEN,
                "ForbiddenException",
                format!("Authorizer returned invalid JSON: {e}"),
            )
        })?;

        // v2 simple response: { "isAuthorized": true/false, "context": {...} }
        if let Some(is_authorized) = response.get("isAuthorized").and_then(|v| v.as_bool()) {
            if !is_authorized {
                return Err(AwsServiceError::aws_error(
                    StatusCode::FORBIDDEN,
                    "ForbiddenException",
                    "User is not authorized to access this resource",
                ));
            }
            let mut ctx = response
                .get("context")
                .cloned()
                .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()))
                .as_object()
                .cloned()
                .unwrap_or_default();
            ctx.insert(
                "principalId".to_string(),
                response
                    .get("principalId")
                    .cloned()
                    .unwrap_or_else(|| serde_json::Value::String("user".to_string())),
            );
            return Ok(Some(AuthorizerInfo::Lambda {
                context: serde_json::Value::Object(ctx),
            }));
        }

        // IAM-policy format (same as v1 TOKEN/REQUEST)
        let effect = parse_policy_effect(&response, &method_arn);
        let principal_id = response
            .get("principalId")
            .and_then(|v| v.as_str())
            .unwrap_or("user")
            .to_string();
        let context = response
            .get("context")
            .cloned()
            .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));

        match effect {
            crate::state::AuthEffect::Allow => {
                let mut ctx = context.as_object().cloned().unwrap_or_default();
                ctx.insert(
                    "principalId".to_string(),
                    serde_json::Value::String(principal_id),
                );
                Ok(Some(AuthorizerInfo::Lambda {
                    context: serde_json::Value::Object(ctx),
                }))
            }
            crate::state::AuthEffect::Deny => Err(AwsServiceError::aws_error(
                StatusCode::FORBIDDEN,
                "ForbiddenException",
                "User is not authorized to access this resource",
            )),
        }
    }

    /// Build the resource ARN that callers use when associating a
    /// WebACL with an API Gateway v2 stage:
    /// `arn:aws:apigateway:<region>::/apis/<api>/stages/<stage>`.
    fn stage_resource_arn(&self, region: &str, api_id: &str, stage: &str) -> String {
        format!("arn:aws:apigateway:{region}::/apis/{api_id}/stages/{stage}")
    }

    /// Run WAFv2 inspection for one execute-API request. Returns
    /// `Some(response)` for a terminal action; returns `None` for
    /// `Allow` / `Count` / `NoAcl`.
    fn evaluate_waf(
        &self,
        req: &AwsRequest,
        api_id: &str,
        stage_name: &str,
    ) -> Option<AwsResponse> {
        let waf_state = self.waf_state.as_ref()?;
        let limiter = self.waf_rate_limiter.as_ref()?;
        let resource_arn = self.stage_resource_arn(&req.region, api_id, stage_name);
        let ctx = build_waf_context(req);
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0);
        let decision =
            fakecloud_wafv2::evaluate_request(waf_state, &resource_arn, &ctx, limiter, now);
        self.record_count_rules(&decision);
        decision_to_response(decision)
    }

    fn record_count_rules(&self, decision: &fakecloud_wafv2::Decision) {
        let rules = decision.count_rules();
        if rules.is_empty() {
            return;
        }
        let Some(arn) = decision.web_acl_arn() else {
            return;
        };
        let mut metrics = self.waf_count_metrics.lock();
        for rule in rules {
            let key = format!("{arn}|{rule}");
            *metrics.entry(key).or_insert(0) += 1;
        }
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

    fn emit_access_log(
        &self,
        req: &AwsRequest,
        api_id: &str,
        stage: &str,
        path: &str,
        status_code: u16,
    ) {
        let Some(delivery) = self.delivery.as_ref() else {
            return;
        };

        let access_log_settings = {
            let accounts = self.state.read();
            let empty = ApiGatewayV2State::new(&req.account_id, &req.region);
            let state = accounts.get(&req.account_id).unwrap_or(&empty);
            state
                .stages
                .get(api_id)
                .and_then(|stages| stages.get(stage))
                .and_then(|s| s.access_log_settings.clone())
        };

        let Some(settings) = access_log_settings else {
            return;
        };

        let log_group_name = settings
            .destination_arn
            .split(":log-group:")
            .nth(1)
            .map(|s| {
                if let Some(prefix) = s.strip_suffix(":*") {
                    prefix.to_string()
                } else {
                    s.to_string()
                }
            });

        let Some(log_group_name) = log_group_name else {
            return;
        };

        let request_time = chrono::Utc::now()
            .format("%d/%b/%Y:%H:%M:%S %z")
            .to_string();
        let source_ip = req
            .headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next().map(str::trim))
            .unwrap_or("-")
            .to_string();

        let format = settings.format.as_deref().unwrap_or(
            r#"{"requestId":"$context.requestId","ip":"$context.identity.sourceIp","requestTime":"$context.requestTime","httpMethod":"$context.httpMethod","routeKey":"$context.routeKey","status":"$context.status","protocol":"$context.protocol","responseLength":"$context.responseLength"}"#,
        );

        let log_line = format
            .replace("$context.requestId", &req.request_id)
            .replace("$context.apiId", api_id)
            .replace("$context.stage", stage)
            .replace("$context.identity.sourceIp", &source_ip)
            .replace("$context.requestTime", &request_time)
            .replace("$context.httpMethod", req.method.as_str())
            .replace("$context.routeKey", path)
            .replace("$context.status", &status_code.to_string())
            .replace("$context.protocol", "HTTP/1.1")
            .replace("$context.responseLength", "0");

        let timestamp = chrono::Utc::now().timestamp_millis();
        let log_stream_name = format!("{}/{}", api_id, stage);

        delivery.put_log_events(
            &req.account_id,
            &log_group_name,
            &log_stream_name,
            &[(timestamp, log_line)],
        );
    }
}

// ─── WAFv2 inspection helpers ─────────────────────────────────────

fn build_waf_context(req: &AwsRequest) -> fakecloud_wafv2::RequestContext {
    let headers: Vec<(String, String)> = req
        .headers
        .iter()
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_lowercase(), s.to_string()))
        })
        .collect();
    let source_ip = headers
        .iter()
        .find(|(k, _)| k == "x-forwarded-for")
        .and_then(|(_, v)| v.split(',').next().map(str::trim))
        .and_then(|s| s.parse::<std::net::IpAddr>().ok());
    let mut ctx =
        fakecloud_wafv2::RequestContext::new(req.method.as_str(), &req.raw_path, &req.raw_query)
            .with_headers(headers)
            .with_body(req.body.as_ref());
    if let Some(ip) = source_ip {
        ctx = ctx.with_source_ip(ip);
    }
    ctx
}

fn decision_to_response(decision: fakecloud_wafv2::Decision) -> Option<AwsResponse> {
    use fakecloud_wafv2::Decision;
    let (status, message) = match decision {
        Decision::NoAcl | Decision::Allow { .. } => return None,
        Decision::Block { status, .. } => (
            StatusCode::from_u16(status).unwrap_or(StatusCode::FORBIDDEN),
            "Forbidden".to_string(),
        ),
        // CAPTCHA / Challenge interstitials are out of scope for this
        // batch; surface a 403 with a discoverable description so
        // tests can distinguish from a plain Block.
        Decision::Captcha { .. } => (StatusCode::FORBIDDEN, "WAF requires CAPTCHA".to_string()),
        Decision::Challenge { .. } => (StatusCode::FORBIDDEN, "WAF requires challenge".to_string()),
    };
    let body = json!({"message": message});
    let mut resp = AwsResponse::json_value(status, body);
    resp.content_type = "application/json".to_string();
    Some(resp)
}

/// Parse an API Gateway v2 identity-source expression and extract
/// the corresponding value from the request.
fn extract_identity_source_value(req: &AwsRequest, source: &str) -> Option<String> {
    if let Some(header_name) = source.strip_prefix("$request.header.") {
        req.headers
            .get(header_name)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string())
    } else if let Some(param_name) = source.strip_prefix("$request.querystring.") {
        req.query_params.get(param_name).cloned()
    } else {
        None
    }
}

/// Map a Cognito issuer URL (`https://cognito-idp.<region>.amazonaws.com/<pool-id>`)
/// to the corresponding user-pool ARN.
fn issuer_to_pool_arn(account_id: &str, region: &str, issuer: &str) -> Option<String> {
    let pool_id = issuer.rsplit_once('/')?.1;
    Some(format!(
        "arn:aws:cognito-idp:{}:{}:userpool/{}",
        region, account_id, pool_id
    ))
}

/// Pull a Lambda function ARN out of an `authorizerUri` value.
fn extract_lambda_arn(uri: &str) -> Option<String> {
    // Expected: arn:aws:apigateway:<region>:lambda:path/2015-03-31/functions/<arn>/invocations
    let suffix = uri.strip_prefix("arn:aws:apigateway:")?;
    let rest = suffix.split_once("lambda:path/2015-03-31/functions/")?.1;
    let arn = rest.strip_suffix("/invocations")?;
    Some(arn.to_string())
}

/// Build the method ARN used in Lambda-authorizer policy documents.
/// AWS format: `arn:aws:execute-api:<region>:<account-id>:<api-id>/<stage>/<method>/<path>`.
fn build_method_arn(req: &AwsRequest, api_id: &str) -> String {
    let stage = req
        .path_segments
        .first()
        .map(|s| s.as_str())
        .unwrap_or("$default");
    let path = req
        .path_segments
        .iter()
        .skip(1)
        .map(|s| s.as_str())
        .collect::<Vec<_>>()
        .join("/");
    format!(
        "arn:aws:execute-api:{}:{}:{}/{}/{}/{}",
        req.region,
        req.account_id,
        api_id,
        stage,
        req.method.as_str(),
        path
    )
}

/// Walk `policyDocument.Statement` and resolve to a single Allow/Deny
/// effect. Multiple matching Allow statements collapse to Allow; any
/// Deny short-circuits to Deny.
fn parse_policy_effect(response: &serde_json::Value, method_arn: &str) -> crate::state::AuthEffect {
    let Some(stmts) = response
        .get("policyDocument")
        .and_then(|p| p.get("Statement"))
        .and_then(|s| s.as_array())
    else {
        return crate::state::AuthEffect::Deny;
    };
    let mut allow = false;
    for stmt in stmts {
        let effect = stmt.get("Effect").and_then(|v| v.as_str()).unwrap_or("");
        let matches = match stmt.get("Resource") {
            Some(serde_json::Value::String(s)) => arn_matches(s, method_arn),
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str())
                .any(|s| arn_matches(s, method_arn)),
            _ => false,
        };
        if !matches {
            continue;
        }
        match effect {
            "Deny" => return crate::state::AuthEffect::Deny,
            "Allow" => allow = true,
            _ => {}
        }
    }
    if allow {
        crate::state::AuthEffect::Allow
    } else {
        crate::state::AuthEffect::Deny
    }
}

/// Glob-match a policy resource expression (`arn:...:*` etc) against a
/// concrete method ARN. `*` matches any sequence inside a single
/// segment; `?` matches a single character.
fn arn_matches(pattern: &str, target: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let mut p_chars = pattern.chars().peekable();
    let mut t_chars = target.chars().peekable();
    loop {
        match (p_chars.peek().copied(), t_chars.peek().copied()) {
            (None, None) => return true,
            (Some('*'), _) => {
                p_chars.next();
                // Try matching * against 0, 1, 2, ... chars in target.
                // Simple recursive backtracking (patterns are tiny).
                let rest_p: String = p_chars.collect();
                let mut rest_t: String = t_chars.collect();
                loop {
                    if arn_matches(&rest_p, &rest_t) {
                        return true;
                    }
                    if rest_t.is_empty() {
                        return false;
                    }
                    rest_t.remove(0);
                }
            }
            (Some('?'), Some(_)) => {
                p_chars.next();
                t_chars.next();
            }
            (Some(pc), Some(tc)) if pc == tc => {
                p_chars.next();
                t_chars.next();
            }
            _ => return false,
        }
    }
}

/// Replace `${stageVariables.<name>}` placeholders in `uri` with values
/// from `stage_variables`. Unknown names are left as-is.
fn substitute_stage_variables(uri: &str, stage_variables: &BTreeMap<String, String>) -> String {
    let mut result = uri.to_string();
    for (k, v) in stage_variables {
        let placeholder = format!("${{stageVariables.{}}}", k);
        result = result.replace(&placeholder, v);
    }
    result
}

/// When the request Host header matches a custom domain name, look up
/// the ApiMapping for the base path and return `(api_id, stage_name,
/// remaining_path_segments, resource_path)`.
///
/// The returned `remaining_path_segments` is what should be used for
/// route matching (the base path prefix is stripped). `resource_path`
/// is the display path recorded in request history.
fn resolve_custom_domain(
    req: &AwsRequest,
    state: &ApiGatewayV2State,
) -> Option<(String, String, Vec<String>, String)> {
    let host = req.headers.get("host").and_then(|v| v.to_str().ok())?;

    // Only consider hosts that don't look like the default execute-api endpoint.
    if host.contains(".execute-api.") {
        return None;
    }

    let domain = state.domain_names.get(host)?;
    let domain_name = domain["DomainName"].as_str()?;

    let mappings = state.api_mappings.get(domain_name)?;
    if mappings.is_empty() {
        return None;
    }

    // Find the mapping whose ApiMappingKey matches the longest prefix of the path.
    let raw_path = &req.raw_path;
    let mut best: Option<(&str, &str, Vec<String>, String)> = None;

    for mapping in mappings.values() {
        let key = mapping["ApiMappingKey"].as_str().unwrap_or("");
        let api_id = mapping["ApiId"].as_str()?;
        let stage = mapping["Stage"].as_str()?;

        let (stripped_path, remaining) = if key.is_empty() {
            (raw_path.to_string(), raw_path.to_string())
        } else {
            let prefix = format!("/{}/", key);
            let prefix_root = format!("/{}", key);
            if *raw_path == *prefix_root || raw_path.starts_with(&prefix) {
                let rest = &raw_path[prefix_root.len()..];
                (rest.to_string(), rest.to_string())
            } else {
                continue;
            }
        };

        let segs: Vec<String> = if stripped_path.is_empty() || stripped_path == "/" {
            vec![]
        } else {
            stripped_path
                .split('/')
                .skip(1)
                .map(|s| s.to_string())
                .collect()
        };

        let best_key_len = best.as_ref().map(|(k, _, _, _)| k.len()).unwrap_or(0);
        if key.len() >= best_key_len {
            best = Some((api_id, stage, segs, remaining));
        }
    }

    best.map(|(api_id, stage, segs, resource_path)| {
        (api_id.to_string(), stage.to_string(), segs, resource_path)
    })
}

/// Returns true when `uri` is a Lambda function ARN.
fn is_lambda_arn(uri: &str) -> bool {
    uri.starts_with("arn:aws:lambda:") && uri.contains(":function:")
}

/// Dispatch a non-Lambda AWS_PROXY integration to the appropriate
/// AWS service via the delivery bus. Supported targets:
///   - SQS queue ARN
///   - SNS topic ARN
///   - StepFunctions state-machine ARN
fn dispatch_aws_service_integration(
    delivery: &DeliveryBus,
    integration_uri: &str,
    req: &AwsRequest,
) -> Result<AwsResponse, AwsServiceError> {
    if integration_uri.starts_with("arn:aws:sqs:") {
        let message = String::from_utf8_lossy(&req.body);
        delivery.send_to_sqs(integration_uri, &message, &std::collections::HashMap::new());
        return Ok(AwsResponse::ok_json(json!({
            "statusCode": 200,
            "body": json!({"MessageId": uuid::Uuid::new_v4().to_string()}).to_string()
        })));
    }

    if integration_uri.starts_with("arn:aws:sns:") {
        let message = String::from_utf8_lossy(&req.body);
        let subject = req
            .headers
            .get("x-amz-sns-subject")
            .and_then(|v| v.to_str().ok());
        delivery.publish_to_sns(integration_uri, &message, subject);
        return Ok(AwsResponse::ok_json(json!({
            "statusCode": 200,
            "body": json!({"MessageId": uuid::Uuid::new_v4().to_string()}).to_string()
        })));
    }

    if integration_uri.starts_with("arn:aws:states:") && integration_uri.contains(":stateMachine:")
    {
        let input = String::from_utf8_lossy(&req.body);
        let execution_name = format!("apigw-{}-{}", req.request_id, uuid::Uuid::new_v4().simple());
        delivery.start_stepfunctions_execution(integration_uri, &input);
        return Ok(AwsResponse::ok_json(json!({
            "statusCode": 200,
            "body": json!({
                "executionArn": format!("{}/execution/{}", integration_uri, execution_name),
                "startDate": chrono::Utc::now().to_rfc3339()
            }).to_string()
        })));
    }

    Err(AwsServiceError::aws_error(
        StatusCode::NOT_IMPLEMENTED,
        "NotImplemented",
        format!(
            "AWS_PROXY integration target not supported: {}",
            integration_uri
        ),
    ))
}

#[path = "service_helpers.rs"]
mod service_helpers;
pub(crate) use service_helpers::*;

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
