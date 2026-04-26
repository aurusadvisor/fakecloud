use chrono::Utc;
use http::StatusCode;
use serde_json::{json, Value};
use uuid::Uuid;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::state::{AsyncInvocation, SharedBedrockState};

pub fn start_async_invoke(
    state: &SharedBedrockState,
    req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let model_id = body["modelId"].as_str().ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "modelId is required",
        )
    })?;

    let output_data_config = body.get("outputDataConfig").ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "outputDataConfig is required",
        )
    })?;

    let model_input = body.get("modelInput").ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "modelInput is required",
        )
    })?;

    let invocation_id = Uuid::new_v4().to_string();
    let invocation_arn = format!(
        "arn:aws:bedrock:{}:{}:async-invoke/{}",
        req.region, req.account_id, invocation_id
    );

    let model_arn = if model_id.starts_with("arn:") {
        model_id.to_string()
    } else {
        format!(
            "arn:aws:bedrock:{}::foundation-model/{}",
            req.region, model_id
        )
    };

    let now = Utc::now();
    let invocation = AsyncInvocation {
        invocation_arn: invocation_arn.clone(),
        model_arn,
        model_input: model_input.clone(),
        output_data_config: output_data_config.clone(),
        client_request_token: body["clientRequestToken"].as_str().map(|s| s.to_string()),
        status: "Completed".to_string(),
        submit_time: now,
        last_modified_time: now,
        end_time: Some(now),
    };

    let mut accts = state.write();
    let s = accts.get_or_create(&req.account_id);
    s.async_invocations
        .insert(invocation_arn.clone(), invocation);

    Ok(AwsResponse::json(
        StatusCode::OK,
        serde_json::to_string(&json!({ "invocationArn": invocation_arn })).unwrap(),
    ))
}

pub fn get_async_invoke(
    state: &SharedBedrockState,
    req: &AwsRequest,
    invocation_id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let accts = state.read();
    let empty = crate::state::BedrockState::new(&req.account_id, &req.region);
    let s = accts.get(&req.account_id).unwrap_or(&empty);
    // Look up by full ARN or by the UUID suffix
    let invocation = s
        .async_invocations
        .get(invocation_id)
        .or_else(|| {
            s.async_invocations
                .values()
                .find(|inv| inv.invocation_arn.ends_with(invocation_id))
        })
        .ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!("Async invocation {invocation_id} not found"),
            )
        })?;

    Ok(AwsResponse::ok_json(invocation_to_json(invocation)))
}

pub fn list_async_invokes(
    state: &SharedBedrockState,
    req: &AwsRequest,
) -> Result<AwsResponse, AwsServiceError> {
    let max_results = req
        .query_params
        .get("maxResults")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(100)
        .max(1);
    let next_token = req.query_params.get("nextToken");
    let status_filter = req.query_params.get("statusEquals");

    let accts = state.read();
    let empty = crate::state::BedrockState::new(&req.account_id, &req.region);
    let s = accts.get(&req.account_id).unwrap_or(&empty);
    let mut items: Vec<&AsyncInvocation> = s
        .async_invocations
        .values()
        .filter(|inv| {
            if let Some(status) = status_filter {
                inv.status == *status
            } else {
                true
            }
        })
        .collect();
    items.sort_by_key(|i| std::cmp::Reverse(i.submit_time));

    let start = if let Some(token) = next_token {
        items
            .iter()
            .position(|inv| inv.invocation_arn.as_str() == token.as_str())
            .map(|p| p + 1)
            .unwrap_or(0)
    } else {
        0
    };

    let page: Vec<Value> = items
        .iter()
        .skip(start)
        .take(max_results)
        .map(|inv| invocation_summary_json(inv))
        .collect();

    let mut resp = json!({ "asyncInvokeSummaries": page });
    let end = start.saturating_add(max_results);
    if end < items.len() {
        if let Some(last) = items.get(end - 1) {
            resp["nextToken"] = json!(last.invocation_arn);
        }
    }

    Ok(AwsResponse::ok_json(resp))
}

fn invocation_to_json(inv: &AsyncInvocation) -> Value {
    let mut obj = json!({
        "invocationArn": inv.invocation_arn,
        "modelArn": inv.model_arn,
        "status": inv.status,
        "submitTime": inv.submit_time.to_rfc3339(),
        "lastModifiedTime": inv.last_modified_time.to_rfc3339(),
        "outputDataConfig": inv.output_data_config,
    });
    if let Some(ref token) = inv.client_request_token {
        obj["clientRequestToken"] = json!(token);
    }
    if let Some(ref end_time) = inv.end_time {
        obj["endTime"] = json!(end_time.to_rfc3339());
    }
    obj
}

fn invocation_summary_json(inv: &AsyncInvocation) -> Value {
    let mut obj = json!({
        "invocationArn": inv.invocation_arn,
        "modelArn": inv.model_arn,
        "status": inv.status,
        "submitTime": inv.submit_time.to_rfc3339(),
        "lastModifiedTime": inv.last_modified_time.to_rfc3339(),
        "outputDataConfig": inv.output_data_config,
    });
    if let Some(ref end_time) = inv.end_time {
        obj["endTime"] = json!(end_time.to_rfc3339());
    }
    obj
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::BedrockState;
    use bytes::Bytes;
    use fakecloud_core::multi_account::MultiAccountState;
    use http::{HeaderMap, Method};
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn shared() -> SharedBedrockState {
        let multi: MultiAccountState<BedrockState> =
            MultiAccountState::new("123456789012", "us-east-1", "http://x");
        Arc::new(RwLock::new(multi))
    }

    fn req() -> AwsRequest {
        AwsRequest {
            service: "bedrock".to_string(),
            action: "a".to_string(),
            method: Method::POST,
            raw_path: "/".to_string(),
            raw_query: String::new(),
            path_segments: vec![],
            query_params: HashMap::new(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            body_stream: parking_lot::Mutex::new(None),
            account_id: "123456789012".to_string(),
            region: "us-east-1".to_string(),
            request_id: "r".to_string(),
            is_query_protocol: false,
            access_key_id: None,
            principal: None,
        }
    }

    fn valid_body(model_id: &str) -> Value {
        json!({
            "modelId": model_id,
            "outputDataConfig": {"s3OutputDataConfig": {"s3Uri": "s3://b/p"}},
            "modelInput": {"text": "hello"}
        })
    }

    #[test]
    fn start_missing_model_id_errors() {
        let s = shared();
        let err = start_async_invoke(&s, &req(), &json!({})).err().unwrap();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn start_missing_output_data_config_errors() {
        let s = shared();
        let err = start_async_invoke(&s, &req(), &json!({"modelId": "m"}))
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn start_missing_model_input_errors() {
        let s = shared();
        let err = start_async_invoke(&s, &req(), &json!({"modelId": "m", "outputDataConfig": {}}))
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn start_builds_foundation_model_arn_when_plain_id() {
        let s = shared();
        start_async_invoke(&s, &req(), &valid_body("anthropic.claude")).unwrap();
        let st = s.read();
        let inv = st
            .default_ref()
            .async_invocations
            .values()
            .next()
            .unwrap()
            .clone();
        assert!(inv.model_arn.contains("foundation-model/anthropic.claude"));
    }

    #[test]
    fn start_preserves_model_arn_when_already_arn() {
        let s = shared();
        let arn = "arn:aws:bedrock:us-east-1::foundation-model/my-model";
        start_async_invoke(&s, &req(), &valid_body(arn)).unwrap();
        let st = s.read();
        let inv = st.default_ref().async_invocations.values().next().unwrap();
        assert_eq!(inv.model_arn, arn);
    }

    #[test]
    fn get_by_arn_or_by_id_suffix() {
        let s = shared();
        start_async_invoke(&s, &req(), &valid_body("m")).unwrap();
        let arn = s
            .read()
            .default_ref()
            .async_invocations
            .keys()
            .next()
            .unwrap()
            .clone();
        let id = arn.rsplit('/').next().unwrap().to_string();
        assert!(get_async_invoke(&s, &req(), &arn).is_ok());
        assert!(get_async_invoke(&s, &req(), &id).is_ok());
    }

    #[test]
    fn get_unknown_returns_not_found() {
        let s = shared();
        let err = get_async_invoke(&s, &req(), "missing").err().unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn list_filters_by_status() {
        let s = shared();
        for _ in 0..2 {
            start_async_invoke(&s, &req(), &valid_body("m")).unwrap();
        }
        // Mark one as Failed
        {
            let mut st = s.write();
            let acct = st.default_mut();
            let arn = acct.async_invocations.keys().next().unwrap().clone();
            acct.async_invocations.get_mut(&arn).unwrap().status = "Failed".to_string();
        }
        let mut r = req();
        r.query_params
            .insert("statusEquals".to_string(), "Failed".to_string());
        let resp = list_async_invokes(&s, &r).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["asyncInvokeSummaries"].as_array().unwrap().len(), 1);
    }

    #[test]
    fn list_paginates() {
        let s = shared();
        for _ in 0..3 {
            start_async_invoke(&s, &req(), &valid_body("m")).unwrap();
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let mut r = req();
        r.query_params
            .insert("maxResults".to_string(), "2".to_string());
        let resp = list_async_invokes(&s, &r).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["asyncInvokeSummaries"].as_array().unwrap().len(), 2);
        assert!(v["nextToken"].is_string());
    }

    #[test]
    fn start_stores_client_request_token_when_provided() {
        let s = shared();
        let mut body = valid_body("m");
        body["clientRequestToken"] = json!("unique-token");
        start_async_invoke(&s, &req(), &body).unwrap();
        let st = s.read();
        let inv = st.default_ref().async_invocations.values().next().unwrap();
        assert_eq!(inv.client_request_token.as_deref(), Some("unique-token"));
    }
}
