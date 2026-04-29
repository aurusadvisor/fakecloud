// Auto-extracted from service.rs as part of carryover service.rs split.

#![allow(clippy::too_many_arguments)]

use serde_json::{json, Value};
use std::collections::BTreeMap;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use super::*;

impl ApiGatewayService {
    pub(super) fn create_usage_plan(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
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

    pub(super) fn get_usage_plan(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn get_usage_plans(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let items: Vec<Value> = accounts
            .get(&request_account(req))
            .map(|s| s.usage_plans.values().map(usage_plan_to_json).collect())
            .unwrap_or_default();
        ok(json!({"item": items}))
    }

    pub(super) fn delete_usage_plan(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn update_usage_plan(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn create_usage_plan_key(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn get_usage_plan_key(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn get_usage_plan_keys(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn delete_usage_plan_key(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn get_usage(
        &self,
        _req: &AwsRequest,
        params: &BTreeMap<String, String>,
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
