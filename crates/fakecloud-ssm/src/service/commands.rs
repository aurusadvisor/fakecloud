use std::collections::BTreeMap;

use chrono::Utc;
use http::StatusCode;
use serde_json::{json, Value};

use fakecloud_core::pagination::paginate;
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};
use fakecloud_core::validation::*;

use crate::state::{SsmCommand, SsmState};

use super::{missing, SsmService};

/// All fields of a `SendCommand` request, parsed and validated.
struct SendCommandInput {
    document_name: String,
    instance_ids: Vec<String>,
    targets: Vec<Value>,
    parameters: BTreeMap<String, Vec<String>>,
    comment: Option<String>,
    output_s3_bucket: Option<String>,
    output_s3_prefix: Option<String>,
    output_s3_region: Option<String>,
    timeout: Option<i64>,
    max_concurrency: Option<String>,
    max_errors: Option<String>,
    service_role: Option<String>,
    notification: Option<Value>,
    document_hash: Option<String>,
    document_hash_type: Option<String>,
}

impl SendCommandInput {
    fn from_body(body: &Value) -> Result<Self, AwsServiceError> {
        let document_name = body["DocumentName"]
            .as_str()
            .ok_or_else(|| missing("DocumentName"))?
            .to_string();

        validate_optional_string_length("DocumentHash", body["DocumentHash"].as_str(), 0, 256)?;
        validate_optional_enum(
            "DocumentHashType",
            body["DocumentHashType"].as_str(),
            &["Sha256", "Sha1"],
        )?;
        validate_optional_range_i64(
            "TimeoutSeconds",
            body["TimeoutSeconds"].as_i64(),
            30,
            2592000,
        )?;
        validate_optional_string_length("Comment", body["Comment"].as_str(), 0, 100)?;
        validate_optional_string_length("OutputS3Region", body["OutputS3Region"].as_str(), 3, 20)?;
        validate_optional_string_length(
            "OutputS3BucketName",
            body["OutputS3BucketName"].as_str(),
            3,
            63,
        )?;
        validate_optional_string_length(
            "OutputS3KeyPrefix",
            body["OutputS3KeyPrefix"].as_str(),
            0,
            500,
        )?;
        validate_optional_string_length("MaxConcurrency", body["MaxConcurrency"].as_str(), 1, 7)?;
        validate_optional_string_length("MaxErrors", body["MaxErrors"].as_str(), 1, 7)?;

        let instance_ids: Vec<String> = body["InstanceIds"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let targets: Vec<Value> = body["Targets"].as_array().cloned().unwrap_or_default();
        let parameters: BTreeMap<String, Vec<String>> = body["Parameters"]
            .as_object()
            .map(|obj| {
                obj.iter()
                    .map(|(k, v)| {
                        let vals = v
                            .as_array()
                            .map(|a| {
                                a.iter()
                                    .filter_map(|x| x.as_str().map(|s| s.to_string()))
                                    .collect()
                            })
                            .unwrap_or_default();
                        (k.clone(), vals)
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            document_name,
            instance_ids,
            targets,
            parameters,
            comment: body["Comment"].as_str().map(|s| s.to_string()),
            output_s3_bucket: body["OutputS3BucketName"].as_str().map(|s| s.to_string()),
            output_s3_prefix: body["OutputS3KeyPrefix"].as_str().map(|s| s.to_string()),
            output_s3_region: body["OutputS3Region"].as_str().map(|s| s.to_string()),
            timeout: body["TimeoutSeconds"].as_i64(),
            max_concurrency: body["MaxConcurrency"].as_str().map(|s| s.to_string()),
            max_errors: body["MaxErrors"].as_str().map(|s| s.to_string()),
            service_role: body["ServiceRoleArn"].as_str().map(|s| s.to_string()),
            notification: body.get("NotificationConfig").cloned(),
            document_hash: body["DocumentHash"].as_str().map(|s| s.to_string()),
            document_hash_type: body["DocumentHashType"].as_str().map(|s| s.to_string()),
        })
    }
}

impl SsmService {
    pub(super) fn send_command(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let input = SendCommandInput::from_body(&req.json_body())?;

        let command_id = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        // Tag-based targets are not modelled in fakecloud, so we surface a
        // single placeholder instance for them. Direct InstanceIds requests
        // pass through unchanged.
        let effective_instance_ids = if input.instance_ids.is_empty() && !input.targets.is_empty() {
            vec!["i-placeholder".to_string()]
        } else {
            input.instance_ids.clone()
        };

        let cmd = SsmCommand {
            command_id: command_id.clone(),
            document_name: input.document_name.clone(),
            instance_ids: effective_instance_ids.clone(),
            parameters: input.parameters.clone(),
            // Real SSM returns `Pending` on submit; transitions to
            // `InProgress` and then `Success` (or `Failed`) as the
            // agent reports back. fakecloud auto-advances the state
            // on each read so callers see realistic lifecycle.
            status: "Pending".to_string(),
            requested_date_time: now,
            comment: input.comment.clone(),
            output_s3_bucket_name: input.output_s3_bucket.clone(),
            output_s3_key_prefix: input.output_s3_prefix.clone(),
            output_s3_region: input.output_s3_region.clone(),
            timeout_seconds: input.timeout,
            service_role_arn: input.service_role.clone(),
            notification_config: input.notification.clone(),
            targets: input.targets.clone(),
            document_hash: input.document_hash.clone(),
            document_hash_type: input.document_hash_type.clone(),
        };

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state.commands.push(cmd);

        let expires = now + chrono::Duration::seconds(input.timeout.unwrap_or(3600));
        let mut cmd_obj = json!({
            "CommandId": command_id,
            "DocumentName": input.document_name,
            "InstanceIds": effective_instance_ids,
            "Targets": input.targets,
            "Parameters": input.parameters,
            "Status": "Pending",
            "StatusDetails": "Pending",
            "RequestedDateTime": now.timestamp_millis() as f64 / 1000.0,
            "ExpiresAfter": expires.timestamp_millis() as f64 / 1000.0,
            "MaxConcurrency": input.max_concurrency.clone().unwrap_or_default(),
            "MaxErrors": input.max_errors.clone().unwrap_or_default(),
            "DeliveryTimedOutCount": 0,
        });
        if let Some(ref c) = input.comment {
            cmd_obj["Comment"] = json!(c);
        }
        if let Some(ref r) = input.output_s3_region {
            cmd_obj["OutputS3Region"] = json!(r);
        }
        if let Some(ref b) = input.output_s3_bucket {
            cmd_obj["OutputS3BucketName"] = json!(b);
        }
        if let Some(ref p) = input.output_s3_prefix {
            cmd_obj["OutputS3KeyPrefix"] = json!(p);
        }
        if let Some(t) = input.timeout {
            cmd_obj["TimeoutSeconds"] = json!(t);
        }

        Ok(AwsResponse::ok_json(json!({ "Command": cmd_obj })))
    }

    pub(super) fn list_commands(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_optional_string_length("CommandId", body["CommandId"].as_str(), 36, 36)?;
        validate_optional_range_i64("MaxResults", body["MaxResults"].as_i64(), 1, 50)?;
        let max_results = body["MaxResults"].as_i64().unwrap_or(50) as usize;
        let command_id = body["CommandId"].as_str();
        let instance_id = body["InstanceId"].as_str();

        let accounts = self.state.read();
        let empty = SsmState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let all_commands: Vec<Value> = state
            .commands
            .iter()
            .filter(|c| {
                if let Some(cid) = command_id {
                    if c.command_id != cid {
                        return false;
                    }
                }
                if let Some(iid) = instance_id {
                    if !c.instance_ids.contains(&iid.to_string()) {
                        return false;
                    }
                }
                true
            })
            .map(|c| {
                let expires = c.requested_date_time
                    + chrono::Duration::seconds(c.timeout_seconds.unwrap_or(3600));
                let v = json!({
                    "CommandId": c.command_id,
                    "DocumentName": c.document_name,
                    "InstanceIds": c.instance_ids,
                    "Targets": c.targets,
                    "Parameters": c.parameters,
                    "Status": c.status,
                    "StatusDetails": c.status,
                    "RequestedDateTime": c.requested_date_time.timestamp_millis() as f64 / 1000.0,
                    "ExpiresAfter": expires.timestamp_millis() as f64 / 1000.0,
                    "Comment": c.comment,
                    "OutputS3Region": c.output_s3_region,
                    "OutputS3BucketName": c.output_s3_bucket_name,
                    "OutputS3KeyPrefix": c.output_s3_key_prefix,
                    "DeliveryTimedOutCount": 0,
                });
                v
            })
            .collect();

        // If a specific CommandId was requested and not found, return an error
        if let Some(cid) = command_id {
            if all_commands.is_empty() {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidCommandId",
                    format!("Command with id {cid} does not exist."),
                ));
            }
        }

        let (commands, next_token) =
            paginate(&all_commands, body["NextToken"].as_str(), max_results);
        let mut resp = json!({ "Commands": commands });
        if let Some(token) = next_token {
            resp["NextToken"] = json!(token);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    pub(super) fn get_command_invocation(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let command_id = body["CommandId"]
            .as_str()
            .ok_or_else(|| missing("CommandId"))?;
        validate_string_length("CommandId", command_id, 36, 36)?;
        let instance_id = body["InstanceId"]
            .as_str()
            .ok_or_else(|| missing("InstanceId"))?;
        let plugin_name = body["PluginName"].as_str();
        validate_optional_string_length("PluginName", plugin_name, 4, 500)?;

        // Auto-advance lifecycle so callers polling Get see Pending
        // -> InProgress -> Success across successive reads. This runs
        // under the write lock to avoid clobbering admin-set
        // `Failed` / `Cancelled` statuses.
        {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&req.account_id);
            if let Some(c) = state
                .commands
                .iter_mut()
                .find(|c| c.command_id == command_id)
            {
                c.status = match c.status.as_str() {
                    "Pending" => "InProgress".to_string(),
                    "InProgress" => "Success".to_string(),
                    other => other.to_string(),
                };
            }
        }

        let accounts = self.state.read();
        let empty = SsmState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let cmd = state
            .commands
            .iter()
            .find(|c| c.command_id == command_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvocationDoesNotExist",
                    format!("Command {command_id} not found"),
                )
            })?;

        // Check instance is part of the command
        if !cmd.instance_ids.contains(&instance_id.to_string()) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvocationDoesNotExist",
                "An error occurred (InvocationDoesNotExist) when calling the GetCommandInvocation operation",
            ));
        }

        // Validate plugin name if provided
        if let Some(pn) = plugin_name {
            let known_plugins = ["aws:runShellScript", "aws:runPowerShellScript"];
            if !known_plugins.contains(&pn) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvocationDoesNotExist",
                    "An error occurred (InvocationDoesNotExist) when calling the GetCommandInvocation operation",
                ));
            }
        }

        let response_code = match cmd.status.as_str() {
            "Success" => 0,
            "Failed" => 1,
            _ => -1,
        };
        Ok(AwsResponse::ok_json(json!({
            "CommandId": cmd.command_id,
            "InstanceId": instance_id,
            "DocumentName": cmd.document_name,
            "Status": cmd.status,
            "StatusDetails": cmd.status,
            "ResponseCode": response_code,
            "StandardOutputContent": "",
            "StandardOutputUrl": "",
            "StandardErrorContent": "",
            "StandardErrorUrl": "",
        })))
    }

    pub(super) fn list_command_invocations(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_optional_string_length("CommandId", body["CommandId"].as_str(), 36, 36)?;
        validate_optional_range_i64("MaxResults", body["MaxResults"].as_i64(), 1, 50)?;
        let max_results = body["MaxResults"].as_i64().unwrap_or(50) as usize;
        let command_id = body["CommandId"].as_str();

        let accounts = self.state.read();
        let empty = SsmState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let all_invocations: Vec<Value> = state
            .commands
            .iter()
            .filter(|c| {
                if let Some(cid) = command_id {
                    c.command_id == cid
                } else {
                    true
                }
            })
            .flat_map(|c| {
                c.instance_ids.iter().map(|iid| {
                    json!({
                        "CommandId": c.command_id,
                        "InstanceId": iid,
                        "DocumentName": c.document_name,
                        "Status": c.status,
                        "StatusDetails": c.status,
                        "RequestedDateTime": c.requested_date_time.timestamp_millis() as f64 / 1000.0,
                        "Comment": c.comment,
                    })
                })
            })
            .collect();

        let (invocations, next_token) =
            paginate(&all_invocations, body["NextToken"].as_str(), max_results);
        let mut resp = json!({ "CommandInvocations": invocations });
        if let Some(token) = next_token {
            resp["NextToken"] = json!(token);
        }

        Ok(AwsResponse::ok_json(resp))
    }

    pub(super) fn cancel_command(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let command_id = body["CommandId"]
            .as_str()
            .ok_or_else(|| missing("CommandId"))?;
        validate_string_length("CommandId", command_id, 36, 36)?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if let Some(cmd) = state
            .commands
            .iter_mut()
            .find(|c| c.command_id == command_id)
        {
            cmd.status = "Cancelled".to_string();
        }

        Ok(AwsResponse::ok_json(json!({})))
    }

    // ===== Maintenance Window operations =====
}
