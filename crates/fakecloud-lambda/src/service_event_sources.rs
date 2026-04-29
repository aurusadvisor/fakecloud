// Auto-extracted from service.rs as part of carryover service.rs split.

#![allow(clippy::too_many_arguments)]

use chrono::Utc;
use http::StatusCode;
use serde_json::{json, Value};

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use super::*;

impl LambdaService {
    pub(super) fn create_event_source_mapping(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body: Value = serde_json::from_slice(&req.body).unwrap_or_default();
        let event_source_arn = body["EventSourceArn"]
            .as_str()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValueException",
                    "EventSourceArn is required",
                )
            })?
            .to_string();

        let function_name = body["FunctionName"]
            .as_str()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValueException",
                    "FunctionName is required",
                )
            })?
            .to_string();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        // Resolve function name to ARN
        let function_arn = if function_name.starts_with("arn:") {
            function_name.clone()
        } else {
            let func = state.functions.get(&function_name).ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "ResourceNotFoundException",
                    format!(
                        "Function not found: arn:aws:lambda:{}:{}:function:{}",
                        state.region, state.account_id, function_name
                    ),
                )
            })?;
            func.function_arn.clone()
        };

        let batch_size = body["BatchSize"].as_i64().unwrap_or(10);
        let enabled = body["Enabled"].as_bool().unwrap_or(true);
        let mapping_uuid = uuid::Uuid::new_v4().to_string();
        let now = Utc::now();

        // Extract Filters[].Pattern strictly: any entry where
        // `Pattern` is missing or not a string is a hard error,
        // matching AWS. Doing this before `validate` keeps malformed
        // values from being silently dropped by the lossy serializer.
        // FilterCriteria itself must be an object (or absent) — non-
        // object values would otherwise be silently dropped by
        // `Value::get`, masking client bugs.
        let filter_patterns: Vec<String> = match body.get("FilterCriteria") {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Object(_)) => {
                match body.get("FilterCriteria").and_then(|v| v.get("Filters")) {
                    None => Vec::new(),
                    Some(Value::Array(arr)) => {
                        let mut out = Vec::with_capacity(arr.len());
                        for f in arr {
                            match f.get("Pattern") {
                                Some(Value::String(s)) => out.push(s.clone()),
                                _ => {
                                    return Err(AwsServiceError::aws_error(
                                        StatusCode::BAD_REQUEST,
                                        "InvalidParameterValueException",
                                        "FilterCriteria.Filters[].Pattern must be a string",
                                    ));
                                }
                            }
                        }
                        out
                    }
                    Some(_) => {
                        return Err(AwsServiceError::aws_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidParameterValueException",
                            "FilterCriteria.Filters must be an array",
                        ));
                    }
                }
            }
            Some(_) => {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValueException",
                    "FilterCriteria must be an object",
                ));
            }
        };
        // AWS rejects malformed FilterCriteria at create time.
        if let Err(err) = crate::filter::FilterSet::validate(filter_patterns.iter()) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValueException",
                err,
            ));
        }
        let function_response_types: Vec<String> = body
            .get("FunctionResponseTypes")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            })
            .unwrap_or_default();
        let starting_position = body
            .get("StartingPosition")
            .and_then(|v| v.as_str())
            .map(String::from);
        let starting_position_timestamp = body
            .get("StartingPositionTimestamp")
            .and_then(|v| v.as_f64());
        let parallelization_factor = body.get("ParallelizationFactor").and_then(|v| v.as_i64());
        let maximum_batching_window_in_seconds = body
            .get("MaximumBatchingWindowInSeconds")
            .and_then(|v| v.as_i64());

        let mapping = EventSourceMapping {
            uuid: mapping_uuid.clone(),
            function_arn: function_arn.clone(),
            event_source_arn: event_source_arn.clone(),
            batch_size,
            enabled,
            state: if enabled {
                "Enabled".to_string()
            } else {
                "Disabled".to_string()
            },
            last_modified: now,
            filter_patterns,
            maximum_batching_window_in_seconds,
            starting_position,
            starting_position_timestamp,
            parallelization_factor,
            function_response_types,
        };

        let response = self.event_source_mapping_json(&mapping);
        state.event_source_mappings.insert(mapping_uuid, mapping);

        Ok(AwsResponse::json(
            StatusCode::ACCEPTED,
            response.to_string(),
        ))
    }

    pub(super) fn list_event_source_mappings(
        &self,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let empty = LambdaState::new(account_id, "");
        let state = accounts.get(account_id).unwrap_or(&empty);
        let mappings: Vec<Value> = state
            .event_source_mappings
            .values()
            .map(|m| self.event_source_mapping_json(m))
            .collect();

        let response = json!({
            "EventSourceMappings": mappings,
        });

        Ok(AwsResponse::json(StatusCode::OK, response.to_string()))
    }

    pub(super) fn get_event_source_mapping(
        &self,
        uuid: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let empty = LambdaState::new(account_id, "");
        let state = accounts.get(account_id).unwrap_or(&empty);
        let mapping = state.event_source_mappings.get(uuid).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!("The resource you requested does not exist. (Service: Lambda, Status Code: 404, Request ID: {uuid})"),
            )
        })?;

        let response = self.event_source_mapping_json(mapping);
        Ok(AwsResponse::json(StatusCode::OK, response.to_string()))
    }

    pub(super) fn delete_event_source_mapping(
        &self,
        uuid: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        let mapping = state.event_source_mappings.remove(uuid).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!("The resource you requested does not exist. (Service: Lambda, Status Code: 404, Request ID: {uuid})"),
            )
        })?;

        let mut response = self.event_source_mapping_json(&mapping);
        response["State"] = json!("Deleting");
        Ok(AwsResponse::json(
            StatusCode::ACCEPTED,
            response.to_string(),
        ))
    }

    pub(super) fn event_source_mapping_json(&self, mapping: &EventSourceMapping) -> Value {
        let mut out = json!({
            "UUID": mapping.uuid,
            "FunctionArn": mapping.function_arn,
            "EventSourceArn": mapping.event_source_arn,
            "BatchSize": mapping.batch_size,
            "State": mapping.state,
            "LastModified": mapping.last_modified.timestamp_millis() as f64 / 1000.0,
        });
        let obj = out.as_object_mut().expect("json! built object");
        if !mapping.filter_patterns.is_empty() {
            obj.insert(
                "FilterCriteria".into(),
                json!({
                    "Filters": mapping.filter_patterns.iter().map(|p| json!({"Pattern": p})).collect::<Vec<_>>(),
                }),
            );
        }
        if !mapping.function_response_types.is_empty() {
            obj.insert(
                "FunctionResponseTypes".into(),
                json!(mapping.function_response_types),
            );
        }
        if let Some(sp) = &mapping.starting_position {
            obj.insert("StartingPosition".into(), json!(sp));
        }
        if let Some(ts) = mapping.starting_position_timestamp {
            obj.insert("StartingPositionTimestamp".into(), json!(ts));
        }
        if let Some(pf) = mapping.parallelization_factor {
            obj.insert("ParallelizationFactor".into(), json!(pf));
        }
        if let Some(w) = mapping.maximum_batching_window_in_seconds {
            obj.insert("MaximumBatchingWindowInSeconds".into(), json!(w));
        }
        out
    }
}
