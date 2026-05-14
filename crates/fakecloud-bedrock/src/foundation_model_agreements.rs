use chrono::Utc;
use http::StatusCode;
use serde_json::{json, Value};
use uuid::Uuid;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::state::{FoundationModelAgreement, SharedBedrockState};

pub(crate) fn create_foundation_model_agreement(
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

    let agreement_id = Uuid::new_v4().to_string();

    let agreement = FoundationModelAgreement {
        agreement_id: agreement_id.clone(),
        model_id: model_id.to_string(),
        created_at: Utc::now(),
    };

    let mut accts = state.write();
    let s = accts.get_or_create(&req.account_id);
    s.foundation_model_agreements
        .insert(agreement_id, agreement);

    Ok(AwsResponse::ok_json(json!({
        "modelId": model_id,
    })))
}

pub(crate) fn delete_foundation_model_agreement(
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

    let mut accts = state.write();
    let s = accts.get_or_create(&req.account_id);
    let key = s
        .foundation_model_agreements
        .iter()
        .find(|(_, a)| a.model_id == model_id)
        .map(|(k, _)| k.clone());

    match key {
        Some(k) => {
            s.foundation_model_agreements.remove(&k);
            Ok(AwsResponse::json(StatusCode::OK, "{}".to_string()))
        }
        None => Err(AwsServiceError::aws_error(
            StatusCode::NOT_FOUND,
            "ResourceNotFoundException",
            format!("Foundation model agreement for {model_id} not found"),
        )),
    }
}

pub(crate) fn list_foundation_model_agreement_offers(
    _state: &SharedBedrockState,
    _req: &AwsRequest,
    model_id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    Ok(AwsResponse::ok_json(json!({
        "modelId": model_id,
        "offers": [],
    })))
}

pub(crate) fn get_foundation_model_availability(
    state: &SharedBedrockState,
    req: &AwsRequest,
    model_id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let accts = state.read();
    let empty = crate::state::BedrockState::new(&req.account_id, &req.region);
    let s = accts.get(&req.account_id).unwrap_or(&empty);
    let has_agreement = s
        .foundation_model_agreements
        .values()
        .any(|a| a.model_id == model_id);

    Ok(AwsResponse::ok_json(json!({
        "modelId": model_id,
        "agreementAvailability": {
            "status": if has_agreement { "AVAILABLE" } else { "NOT_AVAILABLE" },
        },
        "authorizationStatus": if has_agreement { "AUTHORIZED" } else { "NOT_AUTHORIZED" },
        "entitlementAvailability": if has_agreement { "AVAILABLE" } else { "NOT_AVAILABLE" },
        "regionAvailability": "AVAILABLE",
    })))
}

pub(crate) fn get_use_case_for_model_access(
    state: &SharedBedrockState,
    req: &AwsRequest,
) -> Result<AwsResponse, AwsServiceError> {
    let accts = state.read();
    let empty = crate::state::BedrockState::new(&req.account_id, &req.region);
    let s = accts.get(&req.account_id).unwrap_or(&empty);
    // Smithy declares `formData` as a required blob with min length 10. When
    // the caller hasn't seeded one, emit a base64-encoded placeholder so the
    // wire shape stays valid; otherwise relay whatever was stored. The legacy
    // `useCase` field stays for backwards compatibility with older callers.
    let use_case = s.use_case_for_model_access.clone();
    let form_data = match &use_case {
        Some(v) => {
            use base64::Engine;
            base64::engine::general_purpose::STANDARD.encode(v.to_string().as_bytes())
        }
        None => {
            // 16 bytes of zero placeholder, satisfies length >= 10.
            "AAAAAAAAAAAAAAAAAAAAAA==".to_string()
        }
    };

    Ok(AwsResponse::ok_json(json!({
        "formData": form_data,
    })))
}

pub(crate) fn put_use_case_for_model_access(
    state: &SharedBedrockState,
    req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let use_case = body.get("useCase").cloned().ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "useCase is required",
        )
    })?;

    let mut accts = state.write();
    let s = accts.get_or_create(&req.account_id);
    s.use_case_for_model_access = Some(use_case);

    Ok(AwsResponse::json(StatusCode::OK, "{}".to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, Method};
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn shared() -> SharedBedrockState {
        Arc::new(RwLock::new(
            fakecloud_core::multi_account::MultiAccountState::new(
                "123456789012",
                "us-east-1",
                "http://localhost:4566",
            ),
        ))
    }

    fn req() -> AwsRequest {
        AwsRequest {
            service: "bedrock".to_string(),
            action: "Create".to_string(),
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
            request_id: "req".to_string(),
            is_query_protocol: false,
            access_key_id: None,
            principal: None,
        }
    }

    #[test]
    fn create_agreement_missing_model_id_errors() {
        let s = shared();
        let err = create_foundation_model_agreement(&s, &req(), &json!({}))
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn create_agreement_persists_entry() {
        let s = shared();
        create_foundation_model_agreement(&s, &req(), &json!({"modelId": "anthropic.claude"}))
            .unwrap();
        assert_eq!(s.read().default_ref().foundation_model_agreements.len(), 1);
    }

    #[test]
    fn delete_agreement_missing_model_id_errors() {
        let s = shared();
        let err = delete_foundation_model_agreement(&s, &req(), &json!({}))
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn delete_agreement_unknown_returns_not_found() {
        let s = shared();
        let err = delete_foundation_model_agreement(&s, &req(), &json!({"modelId": "m"}))
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn delete_agreement_removes_entry() {
        let s = shared();
        create_foundation_model_agreement(&s, &req(), &json!({"modelId": "m"})).unwrap();
        delete_foundation_model_agreement(&s, &req(), &json!({"modelId": "m"})).unwrap();
        assert!(s
            .read()
            .default_ref()
            .foundation_model_agreements
            .is_empty());
    }

    #[test]
    fn list_offers_returns_empty_list() {
        let s = shared();
        let resp = list_foundation_model_agreement_offers(&s, &req(), "m").unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["modelId"], "m");
        assert_eq!(v["offers"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn availability_reflects_agreement_state() {
        let s = shared();
        let resp = get_foundation_model_availability(&s, &req(), "m").unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["agreementAvailability"]["status"], "NOT_AVAILABLE");

        create_foundation_model_agreement(&s, &req(), &json!({"modelId": "m"})).unwrap();
        let resp = get_foundation_model_availability(&s, &req(), "m").unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["agreementAvailability"]["status"], "AVAILABLE");
    }

    #[test]
    fn use_case_roundtrip() {
        let s = shared();
        let resp = get_use_case_for_model_access(&s, &req()).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        // Placeholder formData when nothing has been stored.
        assert!(v["formData"].as_str().unwrap().len() >= 10);

        put_use_case_for_model_access(&s, &req(), &json!({"useCase": {"purpose": "research"}}))
            .unwrap();
        let resp = get_use_case_for_model_access(&s, &req()).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        // Stored value is base64-encoded back to the caller.
        use base64::Engine;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(v["formData"].as_str().unwrap())
            .unwrap();
        let s = String::from_utf8(decoded).unwrap();
        assert!(s.contains("research"));
    }

    #[test]
    fn put_use_case_missing_field_errors() {
        let s = shared();
        let err = put_use_case_for_model_access(&s, &req(), &json!({}))
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }
}
