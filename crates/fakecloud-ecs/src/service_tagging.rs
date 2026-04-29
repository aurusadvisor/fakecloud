// Auto-extracted from service.rs as part of carryover service.rs split.

#![allow(clippy::too_many_arguments)]

use serde_json::json;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use super::*;

impl EcsService {
    pub(super) fn tag_resource(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let arn = req_str(&body, "resourceArn")?.to_string();
        let tags = parse_tags(&body);
        let (account, resource_type, tail) = decode_ecs_arn(&arn)?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        match resource_type.as_str() {
            "cluster" => {
                let cluster = state
                    .clusters
                    .get_mut(&tail)
                    .ok_or_else(|| resource_not_found(&arn))?;
                merge_tags(&mut cluster.tags, tags);
            }
            "task-definition" => {
                let (family, rev) = parse_family_revision(&tail);
                let rev = rev.ok_or_else(|| {
                    invalid_parameter("task-definition ARN must include revision")
                })?;
                let td = state
                    .task_definitions
                    .get_mut(&family)
                    .and_then(|m| m.get_mut(&rev))
                    .ok_or_else(|| resource_not_found(&arn))?;
                merge_tags(&mut td.tags, tags);
            }
            "service" => {
                let key =
                    resolve_service_key(state, &tail).ok_or_else(|| resource_not_found(&arn))?;
                let svc = state.services.get_mut(&key).expect("resolved key exists");
                merge_tags(&mut svc.tags, tags);
            }
            "task" => {
                let task_id = tail.rsplit('/').next().unwrap_or(&tail).to_string();
                let task = state
                    .tasks
                    .get_mut(&task_id)
                    .ok_or_else(|| resource_not_found(&arn))?;
                merge_tags(&mut task.tags, tags);
            }
            "task-set" => {
                let ts = state
                    .task_sets
                    .get_mut(&tail)
                    .ok_or_else(|| resource_not_found(&arn))?;
                merge_tags(&mut ts.tags, tags);
            }
            "container-instance" => {
                let key = resolve_container_instance_key(state, &tail)
                    .ok_or_else(|| resource_not_found(&arn))?;
                let ci = state
                    .container_instances
                    .get_mut(&key)
                    .expect("resolved key exists");
                merge_tags(&mut ci.tags, tags);
            }
            "capacity-provider" => {
                let cp = state
                    .capacity_providers
                    .get_mut(&tail)
                    .ok_or_else(|| resource_not_found(&arn))?;
                merge_tags(&mut cp.tags, tags);
            }
            other => {
                return Err(invalid_parameter(format!(
                    "Unknown ECS resource type: {other}"
                )));
            }
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    pub(super) fn untag_resource(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let arn = req_str(&body, "resourceArn")?.to_string();
        let keys: Vec<String> = body
            .get("tagKeys")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let (account, resource_type, tail) = decode_ecs_arn(&arn)?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&account);
        match resource_type.as_str() {
            "cluster" => {
                let cluster = state
                    .clusters
                    .get_mut(&tail)
                    .ok_or_else(|| resource_not_found(&arn))?;
                cluster.tags.retain(|t| !keys.contains(&t.key));
            }
            "task-definition" => {
                let (family, rev) = parse_family_revision(&tail);
                let rev = rev.ok_or_else(|| {
                    invalid_parameter("task-definition ARN must include revision")
                })?;
                let td = state
                    .task_definitions
                    .get_mut(&family)
                    .and_then(|m| m.get_mut(&rev))
                    .ok_or_else(|| resource_not_found(&arn))?;
                td.tags.retain(|t| !keys.contains(&t.key));
            }
            "service" => {
                let key =
                    resolve_service_key(state, &tail).ok_or_else(|| resource_not_found(&arn))?;
                let svc = state.services.get_mut(&key).expect("resolved key exists");
                svc.tags.retain(|t| !keys.contains(&t.key));
            }
            "task" => {
                let task_id = tail.rsplit('/').next().unwrap_or(&tail).to_string();
                let task = state
                    .tasks
                    .get_mut(&task_id)
                    .ok_or_else(|| resource_not_found(&arn))?;
                task.tags.retain(|t| !keys.contains(&t.key));
            }
            "task-set" => {
                let ts = state
                    .task_sets
                    .get_mut(&tail)
                    .ok_or_else(|| resource_not_found(&arn))?;
                ts.tags.retain(|t| !keys.contains(&t.key));
            }
            "container-instance" => {
                let key = resolve_container_instance_key(state, &tail)
                    .ok_or_else(|| resource_not_found(&arn))?;
                let ci = state
                    .container_instances
                    .get_mut(&key)
                    .expect("resolved key exists");
                ci.tags.retain(|t| !keys.contains(&t.key));
            }
            "capacity-provider" => {
                let cp = state
                    .capacity_providers
                    .get_mut(&tail)
                    .ok_or_else(|| resource_not_found(&arn))?;
                cp.tags.retain(|t| !keys.contains(&t.key));
            }
            other => {
                return Err(invalid_parameter(format!(
                    "Unknown ECS resource type: {other}"
                )));
            }
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    pub(super) fn list_tags_for_resource(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = request.json_body();
        let arn = req_str(&body, "resourceArn")?.to_string();
        let (account, resource_type, tail) = decode_ecs_arn(&arn)?;
        let accounts = self.state.read();
        let state = accounts
            .get(&account)
            .ok_or_else(|| resource_not_found(&arn))?;
        let tags = match resource_type.as_str() {
            "cluster" => state
                .clusters
                .get(&tail)
                .map(|c| c.tags.clone())
                .ok_or_else(|| resource_not_found(&arn))?,
            "task-definition" => {
                let (family, rev) = parse_family_revision(&tail);
                let rev = rev.ok_or_else(|| {
                    invalid_parameter("task-definition ARN must include revision")
                })?;
                state
                    .task_definitions
                    .get(&family)
                    .and_then(|m| m.get(&rev))
                    .map(|td| td.tags.clone())
                    .ok_or_else(|| resource_not_found(&arn))?
            }
            "service" => {
                let key =
                    resolve_service_key(state, &tail).ok_or_else(|| resource_not_found(&arn))?;
                state
                    .services
                    .get(&key)
                    .map(|s| s.tags.clone())
                    .expect("resolved key exists")
            }
            "task" => {
                let task_id = tail.rsplit('/').next().unwrap_or(&tail).to_string();
                state
                    .tasks
                    .get(&task_id)
                    .map(|t| t.tags.clone())
                    .ok_or_else(|| resource_not_found(&arn))?
            }
            "task-set" => state
                .task_sets
                .get(&tail)
                .map(|t| t.tags.clone())
                .ok_or_else(|| resource_not_found(&arn))?,
            "container-instance" => {
                let key = resolve_container_instance_key(state, &tail)
                    .ok_or_else(|| resource_not_found(&arn))?;
                state
                    .container_instances
                    .get(&key)
                    .map(|c| c.tags.clone())
                    .expect("resolved key exists")
            }
            "capacity-provider" => state
                .capacity_providers
                .get(&tail)
                .map(|c| c.tags.clone())
                .ok_or_else(|| resource_not_found(&arn))?,
            other => {
                return Err(invalid_parameter(format!(
                    "Unknown ECS resource type: {other}"
                )));
            }
        };
        Ok(AwsResponse::ok_json(json!({"tags": tags_json(&tags)})))
    }
}
