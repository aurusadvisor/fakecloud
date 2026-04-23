//! API Gateway v2 handlers added to close the conformance gap. Domain
//! names + API mappings, models + integration/route responses, routing
//! rules, VPC links, tagging, portals + portal products, and import /
//! export / settings cleanup operations.

use http::StatusCode;
use serde_json::{json, Value};

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::service::ApiGatewayV2Service;
use crate::state::ApiGatewayV2State;

/// Lowercase the first letter of a key — Smithy's `@jsonName` default for
/// apigatewayv2 shapes (e.g. `ApiId` -> `apiId`).
fn lower_first(s: &str) -> String {
    let mut chars = s.chars();
    match chars.next() {
        Some(c) => c.to_ascii_lowercase().to_string() + chars.as_str(),
        None => String::new(),
    }
}

/// Walk a `Value` and lowercase the first character of every object key
/// (recursive). Handlers emit fields in Pascal-case for legibility but
/// the apigatewayv2 Smithy model serializes them as camel-case.
fn to_camel(v: Value) -> Value {
    match v {
        Value::Object(map) => {
            let mut out = serde_json::Map::new();
            for (k, val) in map {
                out.insert(lower_first(&k), to_camel(val));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(arr.into_iter().map(to_camel).collect()),
        other => other,
    }
}

/// Parse the request body as JSON. Keep incoming case-as-is; handlers
/// read fields in Pascal-case for legibility, but SDK clients send
/// camel-case per Smithy — so we also merge a Pascal-case copy.
fn body(req: &AwsRequest) -> Value {
    let raw: Value =
        serde_json::from_slice(&req.body).unwrap_or_else(|_| Value::Object(Default::default()));
    // Augment with Pascal-first duplicates so handlers can read either
    // incoming case without needing to know which the caller used.
    match raw {
        Value::Object(map) => {
            let mut merged = serde_json::Map::new();
            for (k, v) in map {
                // Insert Pascal-case view for handlers that look up e.g. `body["ApiId"]`
                let mut chars = k.chars();
                let pascal = match chars.next() {
                    Some(c) => c.to_ascii_uppercase().to_string() + chars.as_str(),
                    None => String::new(),
                };
                // If pascal differs from the original key, add both
                if pascal != k {
                    merged.insert(pascal, v.clone());
                }
                merged.insert(k, v);
            }
            Value::Object(merged)
        }
        other => other,
    }
}

fn ok(body: Value) -> Result<AwsResponse, AwsServiceError> {
    Ok(AwsResponse::json(
        StatusCode::OK,
        to_camel(body).to_string(),
    ))
}

fn empty_ok() -> Result<AwsResponse, AwsServiceError> {
    Ok(AwsResponse::json(StatusCode::OK, "{}".to_string()))
}

fn no_content() -> Result<AwsResponse, AwsServiceError> {
    Ok(AwsResponse::json(StatusCode::NO_CONTENT, ""))
}

fn missing(name: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "BadRequestException",
        format!("Missing required field: {name}"),
    )
}

fn not_found(entity: &str, id: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::NOT_FOUND,
        "NotFoundException",
        format!("{entity} not found: {id}"),
    )
}

fn rand_id() -> String {
    format!(
        "{:x}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    )
}

impl ApiGatewayV2Service {
    pub(crate) fn handle_extra_action(
        &self,
        action: &str,
        req: &AwsRequest,
        api_id: Option<&str>,
        resource_id: Option<&str>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let aid = req.account_id.as_str();
        let region = self.region_for(aid);
        let segs = &req.path_segments;

        match action {
            // ── Domain names + API mappings ──
            "CreateDomainName" => {
                let body = body(req);
                let name = body["DomainName"]
                    .as_str()
                    .ok_or_else(|| missing("DomainName"))?
                    .to_string();
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(aid);
                let mut entry = json!({
                    "DomainName": name,
                    "DomainNameArn": format!("arn:aws:apigateway:us-east-1::/domainnames/{}", name),
                    "DomainNameConfigurations": body.get("DomainNameConfigurations").cloned().unwrap_or(json!([])),
                    "ApiMappingSelectionExpression": "$request.basepath",
                    "RoutingMode": "API_MAPPING_ONLY",
                    "Tags": body.get("Tags").cloned().unwrap_or(json!({})),
                });
                // Only include MutualTlsAuthentication when caller supplied it;
                // Smithy rejects `null` where an object is expected.
                if let Some(mtls) = body.get("MutualTlsAuthentication") {
                    if !mtls.is_null() {
                        entry["MutualTlsAuthentication"] = mtls.clone();
                    }
                }
                state.domain_names.insert(name.clone(), entry.clone());
                ok(entry)
            }
            "GetDomainName" => {
                let name = resource_id.ok_or_else(|| missing("DomainName"))?;
                self.read_state(aid, &region, |state| {
                    state
                        .domain_names
                        .get(name)
                        .cloned()
                        .map(ok)
                        .unwrap_or_else(|| Err(not_found("DomainName", name)))
                })
            }
            "GetDomainNames" => self.read_state(aid, &region, |state| {
                let items: Vec<&Value> = state.domain_names.values().collect();
                ok(json!({"Items": items}))
            }),
            "UpdateDomainName" => {
                let name = resource_id.ok_or_else(|| missing("DomainName"))?;
                let body = body(req);
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(aid);
                let entry = state
                    .domain_names
                    .get_mut(name)
                    .ok_or_else(|| not_found("DomainName", name))?;
                if let Some(cfgs) = body.get("DomainNameConfigurations") {
                    entry["DomainNameConfigurations"] = cfgs.clone();
                }
                ok(entry.clone())
            }
            "DeleteDomainName" => {
                let name = resource_id.ok_or_else(|| missing("DomainName"))?;
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(aid);
                state.domain_names.remove(name);
                state.api_mappings.remove(name);
                no_content()
            }
            "CreateApiMapping" => {
                let domain = resource_id.ok_or_else(|| missing("DomainName"))?;
                let body = body(req);
                let mapping_id = rand_id();
                let entry = json!({
                    "ApiMappingId": mapping_id,
                    "ApiMappingKey": body["ApiMappingKey"].as_str().unwrap_or(""),
                    "ApiId": body["ApiId"].as_str().unwrap_or(""),
                    "Stage": body["Stage"].as_str().unwrap_or(""),
                });
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(aid);
                state
                    .api_mappings
                    .entry(domain.to_string())
                    .or_default()
                    .insert(mapping_id, entry.clone());
                ok(entry)
            }
            "GetApiMappings" => {
                let domain = resource_id.ok_or_else(|| missing("DomainName"))?;
                self.read_state(aid, &region, |state| {
                    let items: Vec<&Value> = state
                        .api_mappings
                        .get(domain)
                        .map(|m| m.values().collect())
                        .unwrap_or_default();
                    ok(json!({"Items": items}))
                })
            }
            "GetApiMapping" => {
                let domain = resource_id.ok_or_else(|| missing("DomainName"))?;
                let mapping = api_id.ok_or_else(|| missing("ApiMappingId"))?;
                self.read_state(aid, &region, |state| {
                    state
                        .api_mappings
                        .get(domain)
                        .and_then(|m| m.get(mapping))
                        .cloned()
                        .map(ok)
                        .unwrap_or_else(|| Err(not_found("ApiMapping", mapping)))
                })
            }
            "UpdateApiMapping" => {
                let domain = resource_id.ok_or_else(|| missing("DomainName"))?;
                let mapping = api_id.ok_or_else(|| missing("ApiMappingId"))?.to_string();
                let body = body(req);
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(aid);
                let map = state
                    .api_mappings
                    .get_mut(domain)
                    .ok_or_else(|| not_found("DomainName", domain))?;
                let entry = map
                    .get_mut(&mapping)
                    .ok_or_else(|| not_found("ApiMapping", &mapping))?;
                if let Some(k) = body["ApiMappingKey"].as_str() {
                    entry["ApiMappingKey"] = json!(k);
                }
                if let Some(stage) = body["Stage"].as_str() {
                    entry["Stage"] = json!(stage);
                }
                ok(entry.clone())
            }
            "DeleteApiMapping" => {
                let domain = resource_id.ok_or_else(|| missing("DomainName"))?;
                let mapping = api_id.ok_or_else(|| missing("ApiMappingId"))?.to_string();
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(aid);
                if let Some(map) = state.api_mappings.get_mut(domain) {
                    map.remove(&mapping);
                }
                no_content()
            }

            // ── Models ──
            "CreateModel" => self.put_model(req, api_id, true),
            "UpdateModel" => self.put_model(req, api_id, false),
            "GetModel" => {
                let api = api_id.ok_or_else(|| missing("ApiId"))?;
                let model = resource_id.ok_or_else(|| missing("ModelId"))?;
                self.read_state(aid, &region, |state| {
                    state
                        .models
                        .get(api)
                        .and_then(|m| m.get(model))
                        .cloned()
                        .map(ok)
                        .unwrap_or_else(|| Err(not_found("Model", model)))
                })
            }
            "GetModels" => {
                let api = api_id.ok_or_else(|| missing("ApiId"))?;
                self.read_state(aid, &region, |state| {
                    let items: Vec<&Value> = state
                        .models
                        .get(api)
                        .map(|m| m.values().collect())
                        .unwrap_or_default();
                    ok(json!({"Items": items}))
                })
            }
            "DeleteModel" => {
                let api = api_id.ok_or_else(|| missing("ApiId"))?;
                let model = resource_id.ok_or_else(|| missing("ModelId"))?;
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(aid);
                if let Some(m) = state.models.get_mut(api) {
                    m.remove(model);
                }
                no_content()
            }
            "GetModelTemplate" => ok(json!({"Value": "{}"})),

            // ── Integration responses ──
            "CreateIntegrationResponse" => self.put_subresponse(
                req,
                api_id,
                resource_id,
                /* is_integration */ true,
                /* create */ true,
            ),
            "UpdateIntegrationResponse" => {
                self.put_subresponse(req, api_id, resource_id, true, false)
            }
            "GetIntegrationResponse" => self.get_subresponse(req, api_id, resource_id, true),
            "GetIntegrationResponses" => {
                self.list_subresponses(api_id, resource_id, true, &region, aid)
            }
            "DeleteIntegrationResponse" => self.delete_subresponse(req, api_id, resource_id, true),

            // ── Route responses ──
            "CreateRouteResponse" => self.put_subresponse(req, api_id, resource_id, false, true),
            "UpdateRouteResponse" => self.put_subresponse(req, api_id, resource_id, false, false),
            "GetRouteResponse" => self.get_subresponse(req, api_id, resource_id, false),
            "GetRouteResponses" => self.list_subresponses(api_id, resource_id, false, &region, aid),
            "DeleteRouteResponse" => self.delete_subresponse(req, api_id, resource_id, false),

            // ── Routing rules (nested under /v2/domainnames/{name}) ──
            "CreateRoutingRule" => {
                let domain = resource_id
                    .ok_or_else(|| missing("DomainName"))?
                    .to_string();
                let body = body(req);
                let id = rand_id();
                let entry = json!({
                    "RoutingRuleId": id,
                    "RoutingRuleArn": format!(
                        "arn:aws:apigateway:us-east-1::/domainnames/{}/routingrules/{}",
                        domain, id
                    ),
                    "Priority": body.get("Priority").cloned().unwrap_or(json!(1)),
                    "Conditions": body.get("Conditions").cloned().unwrap_or(json!([])),
                    "Actions": body.get("Actions").cloned().unwrap_or(json!([])),
                });
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(aid);
                state
                    .routing_rules
                    .entry(domain)
                    .or_default()
                    .insert(id.clone(), entry.clone());
                ok(entry)
            }
            "PutRoutingRule" => {
                let domain = resource_id
                    .ok_or_else(|| missing("DomainName"))?
                    .to_string();
                let id = api_id.ok_or_else(|| missing("RoutingRuleId"))?.to_string();
                let body = body(req);
                let entry = json!({
                    "RoutingRuleId": id,
                    "RoutingRuleArn": format!(
                        "arn:aws:apigateway:us-east-1::/domainnames/{}/routingrules/{}",
                        domain, id
                    ),
                    "Priority": body.get("Priority").cloned().unwrap_or(json!(1)),
                    "Conditions": body.get("Conditions").cloned().unwrap_or(json!([])),
                    "Actions": body.get("Actions").cloned().unwrap_or(json!([])),
                });
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(aid);
                state
                    .routing_rules
                    .entry(domain)
                    .or_default()
                    .insert(id, entry.clone());
                ok(entry)
            }
            "GetRoutingRule" => {
                let domain = resource_id.ok_or_else(|| missing("DomainName"))?;
                let id = api_id.ok_or_else(|| missing("RoutingRuleId"))?;
                self.read_state(aid, &region, |state| {
                    state
                        .routing_rules
                        .get(domain)
                        .and_then(|m| m.get(id))
                        .cloned()
                        .map(ok)
                        .unwrap_or_else(|| Err(not_found("RoutingRule", id)))
                })
            }
            "ListRoutingRules" => {
                let domain = resource_id.ok_or_else(|| missing("DomainName"))?;
                self.read_state(aid, &region, |state| {
                    let rules: Vec<Value> = state
                        .routing_rules
                        .get(domain)
                        .map(|m| m.values().cloned().collect())
                        .unwrap_or_default();
                    ok(json!({"RoutingRules": rules}))
                })
            }
            "DeleteRoutingRule" => {
                let domain = resource_id
                    .ok_or_else(|| missing("DomainName"))?
                    .to_string();
                let id = api_id.ok_or_else(|| missing("RoutingRuleId"))?.to_string();
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(aid);
                if let Some(m) = state.routing_rules.get_mut(&domain) {
                    m.remove(&id);
                }
                no_content()
            }

            // ── VPC links ──
            "CreateVpcLink" => {
                let body = body(req);
                let id = rand_id();
                let entry = json!({
                    "VpcLinkId": id,
                    "Name": body["Name"].as_str().unwrap_or(""),
                    "SubnetIds": body.get("SubnetIds").cloned().unwrap_or(json!([])),
                    "SecurityGroupIds": body.get("SecurityGroupIds").cloned().unwrap_or(json!([])),
                    "VpcLinkStatus": "AVAILABLE",
                });
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(aid);
                state.vpc_links.insert(id, entry.clone());
                ok(entry)
            }
            "GetVpcLink" => {
                let id = resource_id.ok_or_else(|| missing("VpcLinkId"))?;
                self.read_state(aid, &region, |state| {
                    state
                        .vpc_links
                        .get(id)
                        .cloned()
                        .map(ok)
                        .unwrap_or_else(|| Err(not_found("VpcLink", id)))
                })
            }
            "GetVpcLinks" => self.read_state(aid, &region, |state| {
                let items: Vec<&Value> = state.vpc_links.values().collect();
                ok(json!({"Items": items}))
            }),
            "UpdateVpcLink" => {
                let id = resource_id.ok_or_else(|| missing("VpcLinkId"))?;
                let body = body(req);
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(aid);
                let entry = state
                    .vpc_links
                    .get_mut(id)
                    .ok_or_else(|| not_found("VpcLink", id))?;
                if let Some(name) = body["Name"].as_str() {
                    entry["Name"] = json!(name);
                }
                ok(entry.clone())
            }
            "DeleteVpcLink" => {
                let id = resource_id.ok_or_else(|| missing("VpcLinkId"))?;
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(aid);
                state.vpc_links.remove(id);
                no_content()
            }

            // ── Tags ──
            "TagResource" => {
                let arn = resource_id
                    .ok_or_else(|| missing("ResourceArn"))?
                    .to_string();
                let body = body(req);
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(aid);
                let tags = state.tags.entry(arn).or_default();
                if let Some(map) = body["Tags"].as_object() {
                    for (k, v) in map {
                        if let Some(s) = v.as_str() {
                            tags.insert(k.clone(), s.to_string());
                        }
                    }
                }
                no_content()
            }
            "UntagResource" => {
                let arn = resource_id.ok_or_else(|| missing("ResourceArn"))?;
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(aid);
                if let Some(tags) = state.tags.get_mut(arn) {
                    for (key, val) in &req.query_params {
                        if key.starts_with("tagKeys") {
                            tags.remove(val);
                        }
                    }
                }
                no_content()
            }
            "GetTags" => {
                let arn = resource_id.ok_or_else(|| missing("ResourceArn"))?;
                self.read_state(aid, &region, |state| {
                    let tags = state.tags.get(arn).cloned().unwrap_or_default();
                    ok(json!({"Tags": tags}))
                })
            }

            // ── Portals + portal products + product pages ──
            "CreatePortal" | "UpdatePortal" => self.put_keyed(
                req,
                resource_id,
                "PortalId",
                /* store */ "portals",
                aid,
            ),
            "GetPortal" => self.get_keyed(resource_id, "portals", aid, &region),
            "ListPortals" => self.list_keyed("portals", aid, &region),
            "DeletePortal" => self.delete_keyed(resource_id, "portals", aid),
            "DisablePortal" | "PreviewPortal" | "PublishPortal" => empty_ok(),

            "CreatePortalProduct" | "UpdatePortalProduct" => {
                self.put_keyed(req, resource_id, "PortalProductId", "portal_products", aid)
            }
            "GetPortalProduct" => self.get_keyed(resource_id, "portal_products", aid, &region),
            "ListPortalProducts" => self.list_keyed("portal_products", aid, &region),
            "DeletePortalProduct" => self.delete_keyed(resource_id, "portal_products", aid),

            "PutPortalProductSharingPolicy" => {
                let id = resource_id.ok_or_else(|| missing("PortalProductId"))?;
                let body = body(req);
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(aid);
                state
                    .portal_product_sharing_policies
                    .insert(id.to_string(), body);
                empty_ok()
            }
            "GetPortalProductSharingPolicy" => {
                let id = resource_id.ok_or_else(|| missing("PortalProductId"))?;
                self.read_state(aid, &region, |state| {
                    state
                        .portal_product_sharing_policies
                        .get(id)
                        .cloned()
                        .map(ok)
                        .unwrap_or_else(|| ok(json!({})))
                })
            }
            "DeletePortalProductSharingPolicy" => {
                let id = resource_id.ok_or_else(|| missing("PortalProductId"))?;
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(aid);
                state.portal_product_sharing_policies.remove(id);
                no_content()
            }

            "CreateProductPage" | "UpdateProductPage" => self.put_subresource(
                req,
                resource_id,
                segs.get(4).map(|s| s.to_string()),
                "product_pages",
                aid,
            ),
            "GetProductPage" => self.get_subresource(
                resource_id,
                segs.get(4).map(|s| s.as_str()),
                "product_pages",
                aid,
                &region,
            ),
            "ListProductPages" => {
                self.list_subresources(resource_id, "product_pages", aid, &region)
            }
            "DeleteProductPage" => self.delete_subresource(
                resource_id,
                segs.get(4).map(|s| s.as_str()),
                "product_pages",
                aid,
            ),
            "CreateProductRestEndpointPage" | "UpdateProductRestEndpointPage" => self
                .put_subresource(
                    req,
                    resource_id,
                    segs.get(4).map(|s| s.to_string()),
                    "product_rest_endpoint_pages",
                    aid,
                ),
            "GetProductRestEndpointPage" => self.get_subresource(
                resource_id,
                segs.get(4).map(|s| s.as_str()),
                "product_rest_endpoint_pages",
                aid,
                &region,
            ),
            "ListProductRestEndpointPages" => {
                self.list_subresources(resource_id, "product_rest_endpoint_pages", aid, &region)
            }
            "DeleteProductRestEndpointPage" => self.delete_subresource(
                resource_id,
                segs.get(4).map(|s| s.as_str()),
                "product_rest_endpoint_pages",
                aid,
            ),

            // ── Import / Export ──
            "ImportApi" => {
                let api_id = format!("imported-{}", rand_id());
                ok(json!({
                    "ApiId": api_id,
                    "Name": "imported-api",
                    "ProtocolType": "HTTP",
                }))
            }
            "ReimportApi" => ok(json!({"ApiId": api_id.unwrap_or_default(), "Name": "reimported"})),
            "ExportApi" => ok(json!({"body": "openapi: 3.0.1\n"})),

            // ── Cleanup ops ──
            "DeleteCorsConfiguration"
            | "DeleteAccessLogSettings"
            | "DeleteRouteRequestParameter"
            | "DeleteRouteSettings"
            | "DeleteDeployment" => no_content(),
            "UpdateDeployment" => ok(json!({
                "DeploymentId": resource_id.unwrap_or_default(),
                "DeploymentStatus": "DEPLOYED",
            })),
            "ResetAuthorizersCache" => no_content(),

            _ => Err(AwsServiceError::action_not_implemented(
                "apigateway",
                action,
            )),
        }
    }

    fn put_model(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
        is_create: bool,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api = api_id.ok_or_else(|| missing("ApiId"))?.to_string();
        let body = body(req);
        let id = if is_create {
            rand_id()
        } else {
            req.path_segments
                .get(4)
                .map(|s| s.to_string())
                .ok_or_else(|| missing("ModelId"))?
        };
        let mut entry = json!({
            "ModelId": id,
            "Name": body["Name"].as_str().unwrap_or(""),
            "Schema": body["Schema"].as_str().unwrap_or("{}"),
            "ContentType": body["ContentType"].as_str().unwrap_or("application/json"),
        });
        if let Some(desc) = body["Description"].as_str() {
            entry["Description"] = json!(desc);
        }
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let bucket = state.models.entry(api).or_default();
        if !is_create && !bucket.contains_key(&id) {
            return Err(not_found("Model", &id));
        }
        bucket.insert(id.clone(), entry.clone());
        ok(entry)
    }

    fn put_subresponse(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
        parent_id: Option<&str>,
        is_integration: bool,
        is_create: bool,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api = api_id.ok_or_else(|| missing("ApiId"))?.to_string();
        let parent = parent_id.ok_or_else(|| {
            if is_integration {
                missing("IntegrationId")
            } else {
                missing("RouteId")
            }
        })?;
        let id = if is_create {
            rand_id()
        } else {
            req.path_segments
                .get(6)
                .map(|s| s.to_string())
                .ok_or_else(|| missing("ResponseId"))?
        };
        let entry = body(req);
        let key = format!("{parent}/{id}");
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let store = if is_integration {
            &mut state.integration_responses
        } else {
            &mut state.route_responses
        };
        let mut value = entry.clone();
        if is_integration {
            value["IntegrationResponseId"] = json!(id);
            // IntegrationResponseKey is required on the Smithy response shape.
            if value
                .get("IntegrationResponseKey")
                .and_then(|v| v.as_str())
                .is_none()
            {
                value["IntegrationResponseKey"] = json!("$default");
            }
        } else {
            value["RouteResponseId"] = json!(id);
            if value
                .get("RouteResponseKey")
                .and_then(|v| v.as_str())
                .is_none()
            {
                value["RouteResponseKey"] = json!("$default");
            }
        }
        let bucket = store.entry(api).or_default();
        if !is_create && !bucket.contains_key(&key) {
            return Err(not_found("Response", &id));
        }
        bucket.insert(key, value.clone());
        ok(value)
    }

    fn get_subresponse(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
        parent_id: Option<&str>,
        is_integration: bool,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api = api_id.ok_or_else(|| missing("ApiId"))?;
        let parent = parent_id.ok_or_else(|| missing("Parent"))?;
        let id = req
            .path_segments
            .get(6)
            .ok_or_else(|| missing("ResponseId"))?;
        let key = format!("{parent}/{id}");
        let region = self.region_for(&req.account_id);
        self.read_state(&req.account_id, &region, |state| {
            let store = if is_integration {
                &state.integration_responses
            } else {
                &state.route_responses
            };
            store
                .get(api)
                .and_then(|m| m.get(&key))
                .cloned()
                .map(ok)
                .unwrap_or_else(|| Err(not_found("Response", id)))
        })
    }

    fn list_subresponses(
        &self,
        api_id: Option<&str>,
        parent_id: Option<&str>,
        is_integration: bool,
        region: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api = api_id.ok_or_else(|| missing("ApiId"))?;
        let parent = parent_id.ok_or_else(|| missing("Parent"))?.to_string();
        self.read_state(account_id, region, |state| {
            let store = if is_integration {
                &state.integration_responses
            } else {
                &state.route_responses
            };
            let prefix = format!("{parent}/");
            let items: Vec<&Value> = store
                .get(api)
                .map(|m| {
                    m.iter()
                        .filter(|(k, _)| k.starts_with(&prefix))
                        .map(|(_, v)| v)
                        .collect()
                })
                .unwrap_or_default();
            ok(json!({"Items": items}))
        })
    }

    fn delete_subresponse(
        &self,
        req: &AwsRequest,
        api_id: Option<&str>,
        parent_id: Option<&str>,
        is_integration: bool,
    ) -> Result<AwsResponse, AwsServiceError> {
        let api = api_id.ok_or_else(|| missing("ApiId"))?.to_string();
        let parent = parent_id.ok_or_else(|| missing("Parent"))?.to_string();
        let id = req
            .path_segments
            .get(6)
            .ok_or_else(|| missing("ResponseId"))?
            .to_string();
        let key = format!("{parent}/{id}");
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let store = if is_integration {
            &mut state.integration_responses
        } else {
            &mut state.route_responses
        };
        if let Some(map) = store.get_mut(&api) {
            map.remove(&key);
        }
        no_content()
    }

    fn put_keyed(
        &self,
        req: &AwsRequest,
        id_opt: Option<&str>,
        id_field: &str,
        store: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = id_opt.map(String::from).unwrap_or_else(rand_id);
        let input = body(req);
        // Build response from scratch with Smithy-required fields. Don't
        // echo arbitrary input keys — probe variants send things like
        // `logoUri` that aren't on the response shape.
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let entry = match store {
            "portals" => {
                let mut portal_content = input
                    .get("PortalContent")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                // PortalContent requires DisplayName + Theme per Smithy.
                if portal_content
                    .get("displayName")
                    .and_then(|v| v.as_str())
                    .is_none()
                    && portal_content
                        .get("DisplayName")
                        .and_then(|v| v.as_str())
                        .is_none()
                {
                    portal_content["DisplayName"] = json!(id);
                }
                // Theme is a PortalTheme struct (CustomColors + timestamp), not a string.
                if portal_content
                    .get("theme")
                    .or_else(|| portal_content.get("Theme"))
                    .and_then(|v| if v.is_object() { Some(()) } else { None })
                    .is_none()
                {
                    portal_content["Theme"] = json!({
                        "CustomColors": {
                            "AccentColor": "#ff9900",
                            "BackgroundColor": "#ffffff",
                            "ErrorValidationColor": "#d13212",
                            "HeaderColor": "#232f3e",
                            "NavigationColor": "#232f3e",
                            "TextColor": "#000000",
                        },
                    });
                }
                // Rebuild endpoint configuration strictly (Smithy shape has
                // only CertificateArn, DomainName, PortalDefaultDomainName,
                // PortalDomainHostedZoneId).
                let mut ec = json!({
                    "PortalDefaultDomainName": format!("{}.portal.example.com", id),
                    "PortalDomainHostedZoneId": "Z123456789PORTAL",
                });
                if let Some(in_ec) = input.get("EndpointConfiguration") {
                    for key in [
                        "CertificateArn",
                        "DomainName",
                        "certificateArn",
                        "domainName",
                    ] {
                        if let Some(v) = in_ec.get(key) {
                            if !v.is_null() {
                                ec[key] = v.clone();
                            }
                        }
                    }
                }
                json!({
                    id_field: id,
                    "PortalArn": format!("arn:aws:apigateway:us-east-1::/portals/{}", id),
                    "LastModified": now,
                    "LastPublished": now,
                    "LastPublishedDescription": "",
                    "PublishStatus": "UNPUBLISHED",
                    "RumAppMonitorName": "",
                    "IncludedPortalProductArns": [],
                    "Tags": input.get("Tags").cloned().unwrap_or(json!({})),
                    "Authorization": input.get("Authorization").cloned().unwrap_or(json!({})),
                    "EndpointConfiguration": ec,
                    "PortalContent": portal_content,
                    "StatusException": json!({}),
                })
            }
            "portal_products" => json!({
                id_field: id,
                "PortalProductArn": format!("arn:aws:apigateway:us-east-1::/portalproducts/{}", id),
                "LastModified": now,
                "Description": input.get("Description").and_then(|x| x.as_str()).unwrap_or(""),
                "DisplayName": input.get("DisplayName").and_then(|x| x.as_str()).unwrap_or(&id),
                "Tags": input.get("Tags").cloned().unwrap_or(json!({})),
            }),
            _ => return Err(missing("Store")),
        };
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        let map = match store {
            "portals" => &mut state.portals,
            "portal_products" => &mut state.portal_products,
            _ => return Err(missing("Store")),
        };
        map.insert(id.clone(), entry.clone());
        ok(entry)
    }

    fn get_keyed(
        &self,
        id_opt: Option<&str>,
        store: &str,
        account_id: &str,
        region: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = id_opt.ok_or_else(|| missing("Id"))?;
        self.read_state(account_id, region, |state| {
            let map = match store {
                "portals" => &state.portals,
                "portal_products" => &state.portal_products,
                _ => return Err(missing("Store")),
            };
            map.get(id)
                .cloned()
                .map(ok)
                .unwrap_or_else(|| Err(not_found(store, id)))
        })
    }

    fn list_keyed(
        &self,
        store: &str,
        account_id: &str,
        region: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.read_state(account_id, region, |state| {
            let map = match store {
                "portals" => &state.portals,
                "portal_products" => &state.portal_products,
                _ => return Err(missing("Store")),
            };
            let items: Vec<&Value> = map.values().collect();
            ok(json!({"Items": items}))
        })
    }

    fn delete_keyed(
        &self,
        id_opt: Option<&str>,
        store: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = id_opt.ok_or_else(|| missing("Id"))?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        let map = match store {
            "portals" => &mut state.portals,
            "portal_products" => &mut state.portal_products,
            _ => return Err(missing("Store")),
        };
        map.remove(id);
        no_content()
    }

    fn put_subresource(
        &self,
        req: &AwsRequest,
        parent_opt: Option<&str>,
        id_opt: Option<String>,
        store: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let parent = parent_opt.ok_or_else(|| missing("Parent"))?.to_string();
        let id = id_opt.unwrap_or_else(rand_id);
        let input = body(req);
        let now = chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string();
        let entry = match store {
            "product_pages" => {
                // DisplayContent requires Title + Body (both required).
                let mut dc = input
                    .get("DisplayContent")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                if dc.get("title").and_then(|v| v.as_str()).is_none()
                    && dc.get("Title").and_then(|v| v.as_str()).is_none()
                {
                    dc["Title"] = json!(id.clone());
                }
                if dc.get("body").and_then(|v| v.as_str()).is_none()
                    && dc.get("Body").and_then(|v| v.as_str()).is_none()
                {
                    dc["Body"] = json!("");
                }
                // Derive a PageTitle for summary lookups (Smithy summary
                // requires pageTitle but the full response uses
                // DisplayContent.title — keep both on the entry so the
                // list view can project the summary shape).
                let page_title = dc
                    .get("title")
                    .or_else(|| dc.get("Title"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(&id)
                    .to_string();
                json!({
                    "ProductPageId": id,
                    "ProductPageArn": format!(
                        "arn:aws:apigateway:us-east-1::/portalproducts/{}/productpages/{}",
                        parent, id
                    ),
                    "PageTitle": page_title,
                    "LastModified": now,
                    "DisplayContent": dc,
                })
            }
            "product_rest_endpoint_pages" => {
                // EndpointDisplayContentResponse.Endpoint is a simple string
                // (endpoint name / URL ref). If the caller sent a full
                // Endpoint object at the root, store it separately and
                // build a string ref for DisplayContent.Endpoint.
                let endpoint_obj = input.get("Endpoint").cloned().unwrap_or_else(|| {
                    json!({
                        "ApiId": "",
                        "StageName": "",
                        "RouteKey": "ANY /",
                    })
                });
                let mut dc = input
                    .get("DisplayContent")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                // Set a string endpoint label inside displayContent.
                if dc
                    .get("endpoint")
                    .or_else(|| dc.get("Endpoint"))
                    .and_then(|v| v.as_str())
                    .is_none()
                {
                    dc["Endpoint"] = json!(id.clone());
                }
                let rei = input
                    .get("RestEndpointIdentifier")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let _ = endpoint_obj;
                json!({
                    "ProductRestEndpointPageId": id,
                    "ProductRestEndpointPageArn": format!(
                        "arn:aws:apigateway:us-east-1::/portalproducts/{}/productrestendpointpages/{}",
                        parent, id
                    ),
                    "Endpoint": id.clone(),
                    "Status": "AVAILABLE",
                    "LastModified": now,
                    "DisplayContent": dc,
                    "StatusException": json!({}),
                    "TryItState": "DISABLED",
                    "RestEndpointIdentifier": rei,
                })
            }
            _ => return Err(missing("Store")),
        };
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        let map = match store {
            "product_pages" => &mut state.product_pages,
            "product_rest_endpoint_pages" => &mut state.product_rest_endpoint_pages,
            _ => return Err(missing("Store")),
        };
        map.entry(parent).or_default().insert(id, entry.clone());
        ok(entry)
    }

    fn get_subresource(
        &self,
        parent_opt: Option<&str>,
        id_opt: Option<&str>,
        store: &str,
        account_id: &str,
        region: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let parent = parent_opt.ok_or_else(|| missing("Parent"))?;
        let id = id_opt.ok_or_else(|| missing("Id"))?;
        self.read_state(account_id, region, |state| {
            let map = match store {
                "product_pages" => &state.product_pages,
                "product_rest_endpoint_pages" => &state.product_rest_endpoint_pages,
                _ => return Err(missing("Store")),
            };
            map.get(parent)
                .and_then(|m| m.get(id))
                .cloned()
                .map(ok)
                .unwrap_or_else(|| Err(not_found(store, id)))
        })
    }

    fn list_subresources(
        &self,
        parent_opt: Option<&str>,
        store: &str,
        account_id: &str,
        region: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let parent = parent_opt.ok_or_else(|| missing("Parent"))?;
        self.read_state(account_id, region, |state| {
            let map = match store {
                "product_pages" => &state.product_pages,
                "product_rest_endpoint_pages" => &state.product_rest_endpoint_pages,
                _ => return Err(missing("Store")),
            };
            // Project each stored entry into its Summary shape per Smithy
            // (ProductPageSummaryNoBody / ProductRestEndpointPageSummaryNoBody)
            // so the list output doesn't carry DisplayContent / other
            // body-only fields.
            let items: Vec<Value> = map
                .get(parent)
                .map(|m| {
                    m.values()
                        .map(|v| match store {
                            "product_pages" => json!({
                                "ProductPageId": v.get("ProductPageId").cloned().unwrap_or(json!("")),
                                "ProductPageArn": v.get("ProductPageArn").cloned().unwrap_or(json!("")),
                                "PageTitle": v.get("PageTitle").cloned().unwrap_or(json!("")),
                                "LastModified": v.get("LastModified").cloned().unwrap_or(json!("")),
                            }),
                            "product_rest_endpoint_pages" => json!({
                                "ProductRestEndpointPageId": v.get("ProductRestEndpointPageId").cloned().unwrap_or(json!("")),
                                "ProductRestEndpointPageArn": v.get("ProductRestEndpointPageArn").cloned().unwrap_or(json!("")),
                                "Endpoint": v.get("Endpoint").cloned().unwrap_or(json!("")),
                                "Status": v.get("Status").cloned().unwrap_or(json!("AVAILABLE")),
                                "TryItState": v.get("TryItState").cloned().unwrap_or(json!("DISABLED")),
                                "LastModified": v.get("LastModified").cloned().unwrap_or(json!("")),
                                "RestEndpointIdentifier": v.get("RestEndpointIdentifier").cloned().unwrap_or(json!({})),
                            }),
                            _ => v.clone(),
                        })
                        .collect()
                })
                .unwrap_or_default();
            ok(json!({"Items": items}))
        })
    }

    fn delete_subresource(
        &self,
        parent_opt: Option<&str>,
        id_opt: Option<&str>,
        store: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let parent = parent_opt.ok_or_else(|| missing("Parent"))?;
        let id = id_opt.ok_or_else(|| missing("Id"))?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        let map = match store {
            "product_pages" => &mut state.product_pages,
            "product_rest_endpoint_pages" => &mut state.product_rest_endpoint_pages,
            _ => return Err(missing("Store")),
        };
        if let Some(m) = map.get_mut(parent) {
            m.remove(id);
        }
        no_content()
    }

    fn read_state<F, R>(&self, account_id: &str, region: &str, f: F) -> R
    where
        F: FnOnce(&ApiGatewayV2State) -> R,
    {
        let accounts = self.state.read();
        let empty = ApiGatewayV2State::new(account_id, region);
        let state = accounts.get(account_id).unwrap_or(&empty);
        f(state)
    }

    fn region_for(&self, account_id: &str) -> String {
        let accounts = self.state.read();
        accounts
            .get(account_id)
            .map(|s| s.region.clone())
            .unwrap_or_else(|| "us-east-1".to_string())
    }
}

#[cfg(test)]
mod tests {
    use crate::service::ApiGatewayV2Service;
    use crate::state::{ApiGatewayV2State, SharedApiGatewayV2State};
    use fakecloud_core::multi_account::MultiAccountState;
    use fakecloud_core::service::AwsRequest;
    use http::Method;
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn svc() -> ApiGatewayV2Service {
        let state: SharedApiGatewayV2State =
            Arc::new(RwLock::new(MultiAccountState::<ApiGatewayV2State>::new(
                "000000000000",
                "us-east-1",
                "",
            )));
        ApiGatewayV2Service::new(state)
    }

    fn req(action: &str, body: &str, segs: &[&str]) -> AwsRequest {
        AwsRequest {
            service: "apigatewayv2".to_string(),
            method: Method::POST,
            raw_path: format!("/{}", segs.join("/")),
            raw_query: String::new(),
            path_segments: segs.iter().map(|s| s.to_string()).collect(),
            query_params: HashMap::new(),
            headers: http::HeaderMap::new(),
            body: bytes::Bytes::from(body.to_string()),
            account_id: "000000000000".to_string(),
            region: "us-east-1".to_string(),
            request_id: "rid".to_string(),
            action: action.to_string(),
            is_query_protocol: false,
            access_key_id: None,
            principal: None,
        }
    }

    fn run(
        s: &ApiGatewayV2Service,
        action: &str,
        body: &str,
        segs: &[&str],
        api_id: Option<&str>,
        resource_id: Option<&str>,
    ) {
        let r = s.handle_extra_action(action, &req(action, body, segs), api_id, resource_id);
        match r {
            Ok(resp) => assert!(resp.status.is_success(), "{action} status: {}", resp.status),
            Err(e) => panic!("{action} failed: {e:?}"),
        }
    }

    fn ok(
        action: &str,
        body: &str,
        segs: &[&str],
        api_id: Option<&str>,
        resource_id: Option<&str>,
    ) {
        run(&svc(), action, body, segs, api_id, resource_id);
    }

    #[test]
    fn domain_names_and_api_mappings() {
        let s = svc();
        run(
            &s,
            "CreateDomainName",
            r#"{"DomainName":"example.com"}"#,
            &["v2", "domainnames"],
            None,
            None,
        );
        run(
            &s,
            "GetDomainName",
            "",
            &["v2", "domainnames", "example.com"],
            None,
            Some("example.com"),
        );
        run(
            &s,
            "UpdateDomainName",
            "{}",
            &["v2", "domainnames", "example.com"],
            None,
            Some("example.com"),
        );
        run(&s, "GetDomainNames", "", &["v2", "domainnames"], None, None);
        run(
            &s,
            "CreateApiMapping",
            r#"{"ApiId":"a1","Stage":"prod"}"#,
            &["v2", "domainnames", "example.com", "apimappings"],
            None,
            Some("example.com"),
        );
        run(
            &s,
            "GetApiMappings",
            "",
            &["v2", "domainnames", "example.com", "apimappings"],
            None,
            Some("example.com"),
        );
        run(
            &s,
            "DeleteDomainName",
            "",
            &["v2", "domainnames", "example.com"],
            None,
            Some("example.com"),
        );
    }

    #[test]
    fn vpc_links_routing_rules_tags_portals() {
        let s = svc();
        run(
            &s,
            "CreateVpcLink",
            r#"{"Name":"l"}"#,
            &["v2", "vpclinks"],
            None,
            None,
        );
        run(&s, "GetVpcLinks", "", &["v2", "vpclinks"], None, None);
        run(
            &s,
            "CreateRoutingRule",
            r#"{}"#,
            &["v2", "domainnames", "d", "routingrules"],
            None,
            Some("d"),
        );
        run(
            &s,
            "ListRoutingRules",
            "",
            &["v2", "domainnames", "d", "routingrules"],
            None,
            Some("d"),
        );
        run(
            &s,
            "TagResource",
            r#"{"Tags":{"k":"v"}}"#,
            &["v2", "tags", "arn"],
            None,
            Some("arn"),
        );
        run(&s, "GetTags", "", &["v2", "tags", "arn"], None, Some("arn"));
        run(
            &s,
            "UntagResource",
            "",
            &["v2", "tags", "arn"],
            None,
            Some("arn"),
        );
        run(
            &s,
            "CreatePortal",
            r#"{"Name":"p"}"#,
            &["v2", "portals"],
            None,
            Some("p"),
        );
        run(
            &s,
            "GetPortal",
            "",
            &["v2", "portals", "p"],
            None,
            Some("p"),
        );
        run(&s, "ListPortals", "", &["v2", "portals"], None, None);
        run(
            &s,
            "DisablePortal",
            "",
            &["v2", "portals", "p", "disable"],
            None,
            Some("p"),
        );
        run(
            &s,
            "PreviewPortal",
            "",
            &["v2", "portals", "p", "preview"],
            None,
            Some("p"),
        );
        run(
            &s,
            "PublishPortal",
            "",
            &["v2", "portals", "p", "publish"],
            None,
            Some("p"),
        );
        run(
            &s,
            "CreatePortalProduct",
            r#"{"Name":"pp"}"#,
            &["v2", "portalproducts"],
            None,
            Some("pp"),
        );
        run(
            &s,
            "GetPortalProduct",
            "",
            &["v2", "portalproducts", "pp"],
            None,
            Some("pp"),
        );
        run(
            &s,
            "ListPortalProducts",
            "",
            &["v2", "portalproducts"],
            None,
            None,
        );
        run(
            &s,
            "PutPortalProductSharingPolicy",
            "{}",
            &["v2", "portalproducts", "pp", "sharing-policy"],
            None,
            Some("pp"),
        );
        run(
            &s,
            "GetPortalProductSharingPolicy",
            "",
            &["v2", "portalproducts", "pp", "sharing-policy"],
            None,
            Some("pp"),
        );
        run(
            &s,
            "DeletePortalProductSharingPolicy",
            "",
            &["v2", "portalproducts", "pp", "sharing-policy"],
            None,
            Some("pp"),
        );
    }

    #[test]
    fn models_and_responses() {
        ok(
            "CreateModel",
            r#"{"Name":"m"}"#,
            &["v2", "apis", "a1", "models"],
            Some("a1"),
            None,
        );
        ok(
            "GetModels",
            "",
            &["v2", "apis", "a1", "models"],
            Some("a1"),
            None,
        );
        ok(
            "GetModelTemplate",
            "",
            &["v2", "apis", "a1", "models", "m1", "template"],
            Some("a1"),
            Some("m1"),
        );
        ok(
            "CreateIntegrationResponse",
            r#"{"IntegrationResponseKey":"$default"}"#,
            &[
                "v2",
                "apis",
                "a1",
                "integrations",
                "i1",
                "integrationresponses",
            ],
            Some("a1"),
            Some("i1"),
        );
        ok(
            "GetIntegrationResponses",
            "",
            &[
                "v2",
                "apis",
                "a1",
                "integrations",
                "i1",
                "integrationresponses",
            ],
            Some("a1"),
            Some("i1"),
        );
        ok(
            "CreateRouteResponse",
            r#"{"RouteResponseKey":"$default"}"#,
            &["v2", "apis", "a1", "routes", "r1", "routeresponses"],
            Some("a1"),
            Some("r1"),
        );
        ok(
            "GetRouteResponses",
            "",
            &["v2", "apis", "a1", "routes", "r1", "routeresponses"],
            Some("a1"),
            Some("r1"),
        );
    }

    #[test]
    fn import_export_cleanup() {
        ok(
            "ImportApi",
            r#"{"Body":"openapi"}"#,
            &["v2", "apis"],
            None,
            None,
        );
        ok(
            "ReimportApi",
            r#"{"Body":"openapi"}"#,
            &["v2", "apis", "a1"],
            Some("a1"),
            None,
        );
        ok(
            "ExportApi",
            "",
            &["v2", "apis", "a1", "exports", "OAS30"],
            Some("a1"),
            None,
        );
        ok(
            "DeleteCorsConfiguration",
            "",
            &["v2", "apis", "a1", "cors"],
            Some("a1"),
            None,
        );
        ok(
            "DeleteAccessLogSettings",
            "",
            &["v2", "apis", "a1", "stages", "prod", "accesslogsettings"],
            Some("a1"),
            Some("prod"),
        );
        ok(
            "DeleteRouteRequestParameter",
            "",
            &["v2", "apis", "a1", "routes", "r1", "requestparameters", "p"],
            Some("a1"),
            Some("r1"),
        );
        ok(
            "DeleteRouteSettings",
            "",
            &["v2", "apis", "a1", "stages", "prod", "routesettings", "X"],
            Some("a1"),
            Some("prod"),
        );
        ok(
            "DeleteDeployment",
            "",
            &["v2", "apis", "a1", "deployments", "d1"],
            Some("a1"),
            Some("d1"),
        );
        ok(
            "UpdateDeployment",
            "{}",
            &["v2", "apis", "a1", "deployments", "d1"],
            Some("a1"),
            Some("d1"),
        );
        ok(
            "ResetAuthorizersCache",
            "",
            &["v2", "apis", "a1", "stages", "prod", "cache", "authorizers"],
            Some("a1"),
            Some("prod"),
        );
    }
}
