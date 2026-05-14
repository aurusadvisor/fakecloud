use http::StatusCode;
use serde_json::{json, Value};
use uuid::Uuid;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::state::SharedBedrockState;

pub(crate) fn put_enforced_guardrail_configuration(
    state: &SharedBedrockState,
    req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let config_id = Uuid::new_v4().to_string();

    let mut accts = state.write();
    let s = accts.get_or_create(&req.account_id);
    s.enforced_guardrail_configs
        .insert(config_id.clone(), body.clone());

    Ok(AwsResponse::ok_json(json!({
        "configId": config_id,
    })))
}

pub(crate) fn list_enforced_guardrails_configuration(
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

    let accts = state.read();
    let empty = crate::state::BedrockState::new(&req.account_id, &req.region);
    let s = accts.get(&req.account_id).unwrap_or(&empty);
    let mut items: Vec<(&String, &Value)> = s.enforced_guardrail_configs.iter().collect();
    items.sort_by(|a, b| a.0.cmp(b.0));

    let start = if let Some(token) = next_token {
        items
            .iter()
            .position(|(k, _)| k.as_str() > token.as_str())
            .unwrap_or(items.len())
    } else {
        0
    };

    let page: Vec<Value> = items
        .iter()
        .skip(start)
        .take(max_results)
        .map(|(k, v)| {
            let mut entry = (*v).clone();
            if let Some(obj) = entry.as_object_mut() {
                obj.insert("configId".to_string(), json!(k));
            }
            entry
        })
        .collect();

    let mut resp = json!({ "guardrailsConfig": page });
    let end = start.saturating_add(max_results);
    if end < items.len() {
        if let Some(last) = items.get(end - 1) {
            resp["nextToken"] = json!(last.0);
        }
    }

    Ok(AwsResponse::ok_json(resp))
}

pub(crate) fn delete_enforced_guardrail_configuration(
    state: &SharedBedrockState,
    req: &AwsRequest,
    config_id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let mut accts = state.write();
    let s = accts.get_or_create(&req.account_id);

    match s.enforced_guardrail_configs.remove(config_id) {
        Some(_) => Ok(AwsResponse::json(StatusCode::OK, "{}".to_string())),
        None => Err(AwsServiceError::aws_error(
            StatusCode::NOT_FOUND,
            "ResourceNotFoundException",
            format!("Enforced guardrail configuration {config_id} not found"),
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

    #[test]
    fn put_stores_config_with_id() {
        let s = shared();
        let resp =
            put_enforced_guardrail_configuration(&s, &req(), &json!({"policy": "p"})).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert!(v["configId"].is_string());
        assert_eq!(s.read().default_ref().enforced_guardrail_configs.len(), 1);
    }

    #[test]
    fn list_returns_configs_with_ids() {
        let s = shared();
        put_enforced_guardrail_configuration(&s, &req(), &json!({"k": "a"})).unwrap();
        put_enforced_guardrail_configuration(&s, &req(), &json!({"k": "b"})).unwrap();
        let resp = list_enforced_guardrails_configuration(&s, &req()).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        let arr = v["guardrailsConfig"].as_array().unwrap();
        assert_eq!(arr.len(), 2);
        for item in arr {
            assert!(item["configId"].is_string());
        }
    }

    #[test]
    fn list_paginates() {
        let s = shared();
        for i in 0..3 {
            put_enforced_guardrail_configuration(&s, &req(), &json!({"idx": i})).unwrap();
        }
        let mut r = req();
        r.query_params
            .insert("maxResults".to_string(), "2".to_string());
        let resp = list_enforced_guardrails_configuration(&s, &r).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["guardrailsConfig"].as_array().unwrap().len(), 2);
        assert!(v["nextToken"].is_string());
    }

    #[test]
    fn delete_removes_entry() {
        let s = shared();
        let resp = put_enforced_guardrail_configuration(&s, &req(), &json!({"k": "v"})).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        let id = v["configId"].as_str().unwrap().to_string();
        delete_enforced_guardrail_configuration(&s, &req(), &id).unwrap();
        assert!(s.read().default_ref().enforced_guardrail_configs.is_empty());
    }

    #[test]
    fn delete_unknown_returns_not_found() {
        let s = shared();
        let err = delete_enforced_guardrail_configuration(&s, &req(), "missing")
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }
}
