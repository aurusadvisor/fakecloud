use http::StatusCode;
use serde_json::{json, Value};
use uuid::Uuid;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::state::SharedBedrockState;

pub fn put_resource_policy(
    state: &SharedBedrockState,
    req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let resource_arn = body["resourceArn"].as_str().ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "resourceArn is required",
        )
    })?;

    let policy = body["resourcePolicy"].as_str().ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "resourcePolicy is required",
        )
    })?;

    let revision_id = Uuid::new_v4().to_string();

    let mut accts = state.write();
    let s = accts.get_or_create(&req.account_id);
    s.resource_policies
        .insert(resource_arn.to_string(), policy.to_string());

    Ok(AwsResponse::ok_json(json!({
        "resourceArn": resource_arn,
        "revisionId": revision_id,
    })))
}

pub fn get_resource_policy(
    state: &SharedBedrockState,
    req: &AwsRequest,
    resource_arn: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let accts = state.read();
    let empty = crate::state::BedrockState::new(&req.account_id, &req.region);
    let s = accts.get(&req.account_id).unwrap_or(&empty);
    let policy = s
        .resource_policies
        .get(resource_arn)
        .or_else(|| {
            s.resource_policies
                .iter()
                .find(|(k, _)| k.ends_with(&format!("/{resource_arn}")))
                .map(|(_, v)| v)
        })
        .ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!("Resource policy for {resource_arn} not found"),
            )
        })?;

    let revision_id = Uuid::new_v4().to_string();

    Ok(AwsResponse::ok_json(json!({
        "resourcePolicy": policy,
        "revisionId": revision_id,
    })))
}

pub fn delete_resource_policy(
    state: &SharedBedrockState,
    req: &AwsRequest,
    resource_arn: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let mut accts = state.write();
    let s = accts.get_or_create(&req.account_id);

    let key = if s.resource_policies.contains_key(resource_arn) {
        Some(resource_arn.to_string())
    } else {
        s.resource_policies
            .keys()
            .find(|k| k.ends_with(&format!("/{resource_arn}")))
            .cloned()
    };

    match key {
        Some(k) => {
            s.resource_policies.remove(&k);
            Ok(AwsResponse::json(StatusCode::OK, "{}".to_string()))
        }
        None => Err(AwsServiceError::aws_error(
            StatusCode::NOT_FOUND,
            "ResourceNotFoundException",
            format!("Resource policy for {resource_arn} not found"),
        )),
    }
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

    const ARN: &str = "arn:aws:bedrock:us-east-1:123:agent/my-agent";

    fn put(state: &SharedBedrockState, arn: &str) {
        put_resource_policy(
            state,
            &req(),
            &json!({"resourceArn": arn, "resourcePolicy": "{\"Version\":\"2012-10-17\"}"}),
        )
        .unwrap();
    }

    #[test]
    fn put_missing_resource_arn_errors() {
        let s = shared();
        let err = put_resource_policy(&s, &req(), &json!({"resourcePolicy": "{}"}))
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn put_missing_policy_errors() {
        let s = shared();
        let err = put_resource_policy(&s, &req(), &json!({"resourceArn": ARN}))
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn get_by_full_arn() {
        let s = shared();
        put(&s, ARN);
        let resp = get_resource_policy(&s, &req(), ARN).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert!(v["resourcePolicy"].is_string());
        assert!(v["revisionId"].is_string());
    }

    #[test]
    fn get_by_suffix_id() {
        let s = shared();
        put(&s, ARN);
        assert!(get_resource_policy(&s, &req(), "my-agent").is_ok());
    }

    #[test]
    fn get_unknown_returns_not_found() {
        let s = shared();
        let err = get_resource_policy(&s, &req(), "missing").err().unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn delete_by_full_arn_then_by_suffix() {
        let s = shared();
        put(&s, ARN);
        delete_resource_policy(&s, &req(), ARN).unwrap();
        put(&s, ARN);
        delete_resource_policy(&s, &req(), "my-agent").unwrap();
        assert!(s.read().default_ref().resource_policies.is_empty());
    }

    #[test]
    fn delete_unknown_returns_not_found() {
        let s = shared();
        let err = delete_resource_policy(&s, &req(), "missing").err().unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }
}
