// Auto-extracted from service.rs as part of carryover service.rs split.

#![allow(clippy::too_many_arguments)]

use http::StatusCode;
use serde_json::{json, Value};

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use super::*;

impl LambdaService {
    /// Grant a permission on a Lambda function by appending a
    /// statement to its resource-based policy.
    ///
    /// Mirrors AWS: the caller passes `(StatementId, Action,
    /// Principal, SourceArn?, SourceAccount?)` and the service
    /// composes a canonical policy document so that the existing
    /// evaluator can read it without a Lambda-specific fork. Per the
    /// S3 rollout's #427 evaluator, `SourceArn` becomes an `ArnLike`
    /// Condition and `SourceAccount` becomes a `StringEquals`
    /// Condition — both are already supported by the Phase 2 operator
    /// set, so the permission gate behaves end-to-end without any new
    /// evaluator code.
    pub(super) fn add_permission(
        &self,
        function_name: &str,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body: Value = serde_json::from_slice(&req.body).unwrap_or_default();
        let statement_id = body
            .get("StatementId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValueException",
                    "StatementId is required",
                )
            })?
            .to_string();
        let action = body
            .get("Action")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValueException",
                    "Action is required",
                )
            })?
            .to_string();
        let principal_raw = body
            .get("Principal")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValueException",
                    "Principal is required",
                )
            })?
            .to_string();
        let source_arn = body
            .get("SourceArn")
            .and_then(|v| v.as_str())
            .map(str::to_string);
        let source_account = body
            .get("SourceAccount")
            .and_then(|v| v.as_str())
            .map(str::to_string);

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let func = state.functions.get_mut(function_name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!("Function not found: {function_name}"),
            )
        })?;

        // Load current policy or seed a fresh canonical doc. Any
        // stored blob that doesn't parse as a JSON object is treated
        // as corrupt and replaced — `AddPermission` is the only
        // mutation path for this field and it always writes valid
        // JSON, so seeing a non-object here means something else
        // wrote garbage, and silently propagating it would make
        // later reads harder to debug.
        let mut doc: Value = func
            .policy
            .as_deref()
            .and_then(|s| serde_json::from_str::<Value>(s).ok())
            .filter(|v| v.is_object())
            .unwrap_or_else(|| json!({"Version": "2012-10-17", "Statement": []}));

        // Ensure Statement is an array so we can push into it.
        if !doc.get("Statement").map(|s| s.is_array()).unwrap_or(false) {
            doc["Statement"] = json!([]);
        }
        let statements = doc["Statement"].as_array_mut().unwrap();

        // Reject duplicate StatementId — matches AWS's
        // ResourceConflictException.
        if statements
            .iter()
            .any(|s| s.get("Sid").and_then(|v| v.as_str()) == Some(statement_id.as_str()))
        {
            return Err(AwsServiceError::aws_error(
                StatusCode::CONFLICT,
                "ResourceConflictException",
                format!("The statement id ({statement_id}) provided already exists"),
            ));
        }

        // Canonicalize Principal: a service host string becomes
        // `{"Service": "<host>"}`, an account-id or ARN becomes
        // `{"AWS": "<raw>"}`. AWS accepts both shapes on the wire;
        // storing the object form uniformly means the existing
        // evaluator path handles everything without reading back the
        // raw input.
        let principal_value =
            if principal_raw.ends_with(".amazonaws.com") || principal_raw.contains(".amazon") {
                json!({ "Service": principal_raw })
            } else {
                json!({ "AWS": principal_raw })
            };

        // Emit SourceArn / SourceAccount as Condition keys so the
        // existing Phase 2 ArnLike / StringEquals operators gate the
        // grant without new evaluator code.
        let mut condition = serde_json::Map::new();
        if let Some(arn) = source_arn.as_ref() {
            condition.insert("ArnLike".to_string(), json!({ "aws:SourceArn": arn }));
        }
        if let Some(acct) = source_account.as_ref() {
            condition.insert(
                "StringEquals".to_string(),
                json!({ "aws:SourceAccount": acct }),
            );
        }

        // Normalize Action: callers commonly pass either `InvokeFunction`
        // or `lambda:InvokeFunction`. Always store as `lambda:<verb>` —
        // double-prefixing (`lambda:lambda:InvokeFunction`) breaks the
        // evaluator's resource-action matcher and confuses any client
        // that round-trips the policy doc.
        let normalized_action = if action.contains(':') {
            action.clone()
        } else {
            format!("lambda:{action}")
        };
        let mut new_statement = serde_json::Map::new();
        new_statement.insert("Sid".to_string(), json!(statement_id));
        new_statement.insert("Effect".to_string(), json!("Allow"));
        new_statement.insert("Principal".to_string(), principal_value);
        new_statement.insert("Action".to_string(), json!(normalized_action));
        new_statement.insert("Resource".to_string(), json!(func.function_arn));
        if !condition.is_empty() {
            new_statement.insert("Condition".to_string(), Value::Object(condition));
        }
        let statement_json = Value::Object(new_statement);
        statements.push(statement_json.clone());

        func.policy = Some(serde_json::to_string(&doc).unwrap());

        Ok(AwsResponse::json(
            StatusCode::CREATED,
            json!({ "Statement": serde_json::to_string(&statement_json).unwrap() }).to_string(),
        ))
    }

    pub(super) fn remove_permission(
        &self,
        function_name: &str,
        statement_id: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        let func = state.functions.get_mut(function_name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!("Function not found: {function_name}"),
            )
        })?;
        let policy_str = func.policy.as_deref().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!("No policy is associated with function {function_name}"),
            )
        })?;
        let mut doc: Value = serde_json::from_str(policy_str).map_err(|_| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "InternalError",
                "stored resource policy is not valid JSON",
            )
        })?;
        let statements = doc
            .get_mut("Statement")
            .and_then(|s| s.as_array_mut())
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "stored resource policy has no Statement array",
                )
            })?;
        let before = statements.len();
        statements.retain(|s| s.get("Sid").and_then(|v| v.as_str()) != Some(statement_id));
        if statements.len() == before {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!("Statement {statement_id} is not found in resource policy"),
            ));
        }
        // Leave an empty {"Statement":[]} behind rather than clearing
        // the field to None — AWS's GetPolicy keeps returning the
        // (empty) doc until the function itself is deleted.
        func.policy = Some(serde_json::to_string(&doc).unwrap());
        Ok(AwsResponse::json(StatusCode::NO_CONTENT, String::new()))
    }

    pub(super) fn get_policy(
        &self,
        function_name: &str,
        account_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let empty = LambdaState::new(account_id, "");
        let state = accounts.get(account_id).unwrap_or(&empty);
        let func = state.functions.get(function_name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!("Function not found: {function_name}"),
            )
        })?;
        let policy = func.policy.as_deref().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!("No policy is associated with function {function_name}"),
            )
        })?;
        Ok(AwsResponse::json(
            StatusCode::OK,
            json!({
                "Policy": policy,
                "RevisionId": uuid::Uuid::new_v4().to_string(),
            })
            .to_string(),
        ))
    }
}
