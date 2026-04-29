// Auto-extracted from service.rs as part of carryover service.rs split.

#![allow(clippy::too_many_arguments)]

use serde_json::{json, Value};
use std::collections::BTreeMap;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use super::*;

impl ApiGatewayService {
    pub(super) fn create_model(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn get_model(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn get_models(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn delete_model(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn update_model(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn get_model_template(
        &self,
        _req: &AwsRequest,
        _params: &BTreeMap<String, String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        ok(json!({"value": "{}"}))
    }
}
