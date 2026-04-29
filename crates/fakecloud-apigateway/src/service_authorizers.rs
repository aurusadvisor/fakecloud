// Auto-extracted from service.rs as part of carryover service.rs split.

#![allow(clippy::too_many_arguments)]

use serde_json::{json, Value};
use std::collections::BTreeMap;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use super::*;

impl ApiGatewayService {
    pub(super) fn create_authorizer(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn get_authorizer(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn get_authorizers(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn delete_authorizer(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn update_authorizer(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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
