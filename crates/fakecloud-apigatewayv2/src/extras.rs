//! API Gateway v2 handlers added to close the conformance gap. Domain
//! names + API mappings, models + integration/route responses, routing
//! rules, VPC links, tagging, portals + portal products, and import /
//! export / settings cleanup operations.

use http::StatusCode;
use serde_json::{json, Value};

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::service::ApiGatewayV2Service;
use crate::state::ApiGatewayV2State;

fn body(req: &AwsRequest) -> Value {
    serde_json::from_slice(&req.body).unwrap_or_else(|_| Value::Object(Default::default()))
}

fn ok(body: Value) -> Result<AwsResponse, AwsServiceError> {
    Ok(AwsResponse::json(StatusCode::OK, body.to_string()))
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
                let entry = json!({
                    "DomainName": name,
                    "DomainNameConfigurations": body.get("DomainNameConfigurations").cloned().unwrap_or(json!([])),
                    "MutualTlsAuthentication": body.get("MutualTlsAuthentication").cloned(),
                    "Tags": body.get("Tags").cloned().unwrap_or(json!({})),
                });
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

            // ── Routing rules ──
            "CreateRoutingRule" | "PutRoutingRule" => {
                let body = body(req);
                let domain = body["DomainName"]
                    .as_str()
                    .ok_or_else(|| missing("DomainName"))?
                    .to_string();
                let id = resource_id.map(String::from).unwrap_or_else(rand_id);
                let entry = json!({
                    "RoutingRuleId": id,
                    "DomainName": domain,
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
            "GetRoutingRule" => {
                let id = resource_id.ok_or_else(|| missing("RoutingRuleId"))?;
                self.read_state(aid, &region, |state| {
                    state
                        .routing_rules
                        .values()
                        .find_map(|m| m.get(id))
                        .cloned()
                        .map(ok)
                        .unwrap_or_else(|| Err(not_found("RoutingRule", id)))
                })
            }
            "ListRoutingRules" => self.read_state(aid, &region, |state| {
                let items: Vec<&Value> = state
                    .routing_rules
                    .values()
                    .flat_map(|m| m.values())
                    .collect();
                ok(json!({"Items": items}))
            }),
            "DeleteRoutingRule" => {
                let id = resource_id.ok_or_else(|| missing("RoutingRuleId"))?;
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(aid);
                for map in state.routing_rules.values_mut() {
                    map.remove(id);
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
        let entry = json!({
            "ModelId": id,
            "Name": body["Name"].as_str().unwrap_or(""),
            "Schema": body["Schema"].as_str().unwrap_or("{}"),
            "ContentType": body["ContentType"].as_str().unwrap_or("application/json"),
            "Description": body["Description"].as_str(),
        });
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
        } else {
            value["RouteResponseId"] = json!(id);
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
        let mut entry = body(req);
        entry[id_field] = json!(id);
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
        let mut entry = body(req);
        entry["Id"] = json!(id);
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
            let items: Vec<&Value> = map
                .get(parent)
                .map(|m| m.values().collect())
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
