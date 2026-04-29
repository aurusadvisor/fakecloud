// Auto-extracted from service.rs as part of carryover service.rs split.

#![allow(clippy::too_many_arguments)]

use serde_json::{json, Value};
use std::collections::BTreeMap;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use super::*;

impl ApiGatewayService {
    pub(super) fn create_deployment(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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
                    .collect::<BTreeMap<String, String>>()
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
                method_settings: BTreeMap::new(),
                created_date: now,
                last_updated_date: now,
                tracing_enabled: false,
                web_acl_arn: None,
                canary_settings: None,
                access_log_settings: None,
                tags: BTreeMap::new(),
            };
            state
                .stages
                .entry(api_id.clone())
                .or_default()
                .insert(name, stage);
        }
        ok_status(StatusCode::CREATED, deployment_to_json(&deployment))
    }

    pub(super) fn get_deployment(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn get_deployments(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn delete_deployment(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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

    pub(super) fn update_deployment(
        &self,
        req: &AwsRequest,
        params: &BTreeMap<String, String>,
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
