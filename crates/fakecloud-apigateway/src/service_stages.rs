// Auto-extracted from service.rs as part of carryover service.rs split.

#![allow(clippy::too_many_arguments)]

use serde_json::{json, Value};
use std::collections::BTreeMap;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use super::*;

impl ApiGatewayService {
    pub(super) fn create_stage(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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
                        .collect::<BTreeMap<String, Value>>()
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

    pub(super) fn get_stage(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn get_stages(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn delete_stage(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn update_stage(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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
