use http::StatusCode;
use serde_json::{json, Value};

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::state::SharedBedrockState;

pub(crate) fn put_model_invocation_logging_configuration(
    state: &SharedBedrockState,
    req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let logging_config = body.get("loggingConfig").ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "loggingConfig is required",
        )
    })?;

    let config = crate::state::LoggingConfig {
        cloud_watch_config: logging_config.get("cloudWatchConfig").cloned(),
        s3_config: logging_config.get("s3Config").cloned(),
        text_data_delivery_enabled: logging_config["textDataDeliveryEnabled"]
            .as_bool()
            .unwrap_or(true),
        image_data_delivery_enabled: logging_config["imageDataDeliveryEnabled"]
            .as_bool()
            .unwrap_or(true),
        embedding_data_delivery_enabled: logging_config["embeddingDataDeliveryEnabled"]
            .as_bool()
            .unwrap_or(true),
    };

    let mut accts = state.write();
    let s = accts.get_or_create(&req.account_id);
    s.logging_config = Some(config);

    Ok(AwsResponse::json(StatusCode::OK, "{}".to_string()))
}

pub(crate) fn get_model_invocation_logging_configuration(
    state: &SharedBedrockState,
    req: &AwsRequest,
) -> Result<AwsResponse, AwsServiceError> {
    let accts = state.read();
    let empty = crate::state::BedrockState::new(&req.account_id, &req.region);
    let s = accts.get(&req.account_id).unwrap_or(&empty);
    match &s.logging_config {
        Some(config) => {
            let mut logging_config = json!({
                "textDataDeliveryEnabled": config.text_data_delivery_enabled,
                "imageDataDeliveryEnabled": config.image_data_delivery_enabled,
                "embeddingDataDeliveryEnabled": config.embedding_data_delivery_enabled,
            });
            if let Some(ref cw) = config.cloud_watch_config {
                logging_config["cloudWatchConfig"] = cw.clone();
            }
            if let Some(ref s3) = config.s3_config {
                logging_config["s3Config"] = s3.clone();
            }
            Ok(AwsResponse::ok_json(
                json!({ "loggingConfig": logging_config }),
            ))
        }
        None => Ok(AwsResponse::ok_json(json!({}))),
    }
}

pub(crate) fn delete_model_invocation_logging_configuration(
    state: &SharedBedrockState,
    req: &AwsRequest,
) -> Result<AwsResponse, AwsServiceError> {
    let mut accts = state.write();
    let s = accts.get_or_create(&req.account_id);
    s.logging_config = None;
    Ok(AwsResponse::json(StatusCode::OK, "{}".to_string()))
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
    fn put_requires_logging_config() {
        let s = shared();
        let err = put_model_invocation_logging_configuration(&s, &req(), &json!({}))
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn put_stores_cloudwatch_and_s3_and_defaults_flags_true() {
        let s = shared();
        let body = json!({
            "loggingConfig": {
                "cloudWatchConfig": {"logGroupName": "lg"},
                "s3Config": {"bucketName": "b"}
            }
        });
        put_model_invocation_logging_configuration(&s, &req(), &body).unwrap();
        let st = s.read();
        let c = st.default_ref().logging_config.as_ref().unwrap();
        assert!(c.text_data_delivery_enabled);
        assert!(c.image_data_delivery_enabled);
        assert!(c.embedding_data_delivery_enabled);
        assert!(c.cloud_watch_config.is_some());
        assert!(c.s3_config.is_some());
    }

    #[test]
    fn put_honors_explicit_flags() {
        let s = shared();
        let body = json!({
            "loggingConfig": {
                "textDataDeliveryEnabled": false,
                "imageDataDeliveryEnabled": false,
                "embeddingDataDeliveryEnabled": false
            }
        });
        put_model_invocation_logging_configuration(&s, &req(), &body).unwrap();
        let st = s.read();
        let c = st.default_ref().logging_config.as_ref().unwrap();
        assert!(!c.text_data_delivery_enabled);
        assert!(!c.image_data_delivery_enabled);
        assert!(!c.embedding_data_delivery_enabled);
    }

    #[test]
    fn get_returns_empty_when_not_configured() {
        let s = shared();
        let resp = get_model_invocation_logging_configuration(&s, &req()).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert!(v["loggingConfig"].is_null());
    }

    #[test]
    fn get_returns_stored_config() {
        let s = shared();
        let body = json!({
            "loggingConfig": {
                "cloudWatchConfig": {"logGroupName": "lg"},
                "s3Config": {"bucketName": "b"}
            }
        });
        put_model_invocation_logging_configuration(&s, &req(), &body).unwrap();
        let resp = get_model_invocation_logging_configuration(&s, &req()).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["loggingConfig"]["cloudWatchConfig"]["logGroupName"], "lg");
        assert_eq!(v["loggingConfig"]["s3Config"]["bucketName"], "b");
    }

    #[test]
    fn delete_clears_config() {
        let s = shared();
        let body = json!({"loggingConfig": {}});
        put_model_invocation_logging_configuration(&s, &req(), &body).unwrap();
        delete_model_invocation_logging_configuration(&s, &req()).unwrap();
        assert!(s.read().default_ref().logging_config.is_none());
    }
}
