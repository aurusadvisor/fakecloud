use chrono::Utc;
use http::StatusCode;
use serde_json::{json, Value};

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::state::SharedBedrockState;

/// Invoke a model and return a provider-specific canned response.
/// If a custom response has been configured via simulation endpoint, use that instead.
pub(crate) fn invoke_model(
    state: &SharedBedrockState,
    req: &AwsRequest,
    model_id: &str,
    body: &[u8],
) -> Result<AwsResponse, AwsServiceError> {
    // Validate model ID
    if model_id.is_empty() {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "modelId is required",
        ));
    }

    // Fault injection: if a matching rule is queued, record the attempt and fail.
    if let Some(fault) = crate::faults::take_matching_fault(state, req, model_id, "InvokeModel") {
        crate::faults::record_faulted_invocation(state, req, model_id, body, &fault);
        return Err(crate::faults::fault_to_error(&fault));
    }

    let input: Value = serde_json::from_slice(body).unwrap_or_default();

    let response_body = crate::prompt::resolve_override(state, req, model_id, body)
        .unwrap_or_else(|| generate_canned_response(model_id, &input));

    // Record invocation for introspection
    {
        let mut accts = state.write();
        let s = accts.get_or_create(&req.account_id);
        s.invocations.push(crate::state::ModelInvocation {
            model_id: model_id.to_string(),
            input: String::from_utf8_lossy(body).to_string(),
            output: response_body.clone(),
            timestamp: Utc::now(),
            error: None,
        });
    }

    let mut headers = http::HeaderMap::new();
    headers.insert(
        "x-amzn-bedrock-input-token-count",
        http::HeaderValue::from_static("10"),
    );
    headers.insert(
        "x-amzn-bedrock-output-token-count",
        http::HeaderValue::from_static("20"),
    );
    headers.insert(
        "x-amzn-bedrock-performanceconfig-latency",
        http::HeaderValue::from_static("standard"),
    );

    Ok(AwsResponse {
        status: StatusCode::OK,
        content_type: "application/json".to_string(),
        body: bytes::Bytes::from(response_body).into(),
        headers,
    })
}

/// Count tokens for the given input text (rough approximation).
pub(crate) fn count_tokens(
    _state: &SharedBedrockState,
    _req: &AwsRequest,
    model_id: &str,
    body: &[u8],
) -> Result<AwsResponse, AwsServiceError> {
    if model_id.is_empty() {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "modelId is required",
        ));
    }

    let input: Value = serde_json::from_slice(body).unwrap_or_default();

    // Extract text from either invokeModel or converse format
    let text = if let Some(invoke_input) = input.get("input") {
        if let Some(invoke_model) = invoke_input.get("invokeModel") {
            // InvokeModel format — body is a document
            if let Some(body_doc) = invoke_model.get("body") {
                serde_json::to_string(body_doc).unwrap_or_default()
            } else {
                String::new()
            }
        } else if let Some(converse) = invoke_input.get("converse") {
            // Converse format — extract messages and system text
            let mut all_text = String::new();
            if let Some(system) = converse.get("system").and_then(|s| s.as_array()) {
                for block in system {
                    if let Some(t) = block["text"].as_str() {
                        all_text.push_str(t);
                        all_text.push(' ');
                    }
                }
            }
            if let Some(messages) = converse.get("messages").and_then(|m| m.as_array()) {
                for msg in messages {
                    if let Some(content) = msg.get("content").and_then(|c| c.as_array()) {
                        for block in content {
                            if let Some(t) = block["text"].as_str() {
                                all_text.push_str(t);
                                all_text.push(' ');
                            }
                        }
                    }
                }
            }
            all_text
        } else {
            serde_json::to_string(&input).unwrap_or_default()
        }
    } else {
        serde_json::to_string(&input).unwrap_or_default()
    };

    // Rough token count: split by whitespace
    let token_count = if text.is_empty() {
        0
    } else {
        text.split_whitespace().count()
    };

    Ok(AwsResponse::ok_json(json!({
        "inputTokens": token_count
    })))
}

/// Generate a deterministic canned response based on the model provider.
fn generate_canned_response(model_id: &str, input: &Value) -> String {
    let provider = if model_id.starts_with("anthropic.") {
        "anthropic"
    } else if model_id.starts_with("amazon.") {
        "amazon"
    } else if model_id.starts_with("meta.") {
        "meta"
    } else if model_id.starts_with("cohere.") {
        "cohere"
    } else if model_id.starts_with("mistral.") {
        "mistral"
    } else {
        "generic"
    };

    match provider {
        "anthropic" => anthropic_response(model_id, input),
        "amazon" => amazon_titan_response(model_id, input),
        "meta" => meta_llama_response(input),
        "cohere" => cohere_response(input),
        "mistral" => mistral_response(input),
        _ => generic_response(input),
    }
}

fn anthropic_response(model_id: &str, _input: &Value) -> String {
    serde_json::to_string(&json!({
        "id": "msg_fakecloudtest01",
        "type": "message",
        "role": "assistant",
        "content": [
            {
                "type": "text",
                "text": "This is a test response from the emulated model."
            }
        ],
        "model": model_id,
        "stop_reason": "end_turn",
        "stop_sequence": null,
        "usage": {
            "input_tokens": 10,
            "output_tokens": 20
        }
    }))
    .expect("serde_json::Value serialization is infallible")
}

fn amazon_titan_response(model_id: &str, _input: &Value) -> String {
    // Titan embed models return embedding vectors, not text completions
    if model_id.starts_with("amazon.titan-embed") {
        let embedding: Vec<f64> = (0..256).map(|i| (i as f64 * 0.001).sin()).collect();
        return serde_json::to_string(&json!({
            "embedding": embedding,
            "inputTextTokenCount": 10
        }))
        .expect("serde_json::Value serialization is infallible");
    }

    serde_json::to_string(&json!({
        "inputTextTokenCount": 10,
        "results": [
            {
                "tokenCount": 20,
                "outputText": "This is a test response from the emulated model.",
                "completionReason": "FINISH"
            }
        ]
    }))
    .expect("serde_json::Value serialization is infallible")
}

fn meta_llama_response(_input: &Value) -> String {
    serde_json::to_string(&json!({
        "generation": "This is a test response from the emulated model.",
        "prompt_logprobs": null,
        "generation_logprobs": null,
        "stop_reason": "stop",
        "generation_token_count": 20,
        "prompt_token_count": 10
    }))
    .expect("serde_json::Value serialization is infallible")
}

fn cohere_response(_input: &Value) -> String {
    serde_json::to_string(&json!({
        "generations": [
            {
                "id": "gen-fakecloud-01",
                "text": "This is a test response from the emulated model.",
                "finish_reason": "COMPLETE",
                "token_likelihoods": []
            }
        ],
        "prompt": ""
    }))
    .expect("serde_json::Value serialization is infallible")
}

fn mistral_response(_input: &Value) -> String {
    serde_json::to_string(&json!({
        "outputs": [
            {
                "text": "This is a test response from the emulated model.",
                "stop_reason": "stop"
            }
        ]
    }))
    .expect("serde_json::Value serialization is infallible")
}

fn generic_response(_input: &Value) -> String {
    serde_json::to_string(&json!({
        "output": "This is a test response from the emulated model."
    }))
    .expect("serde_json::Value serialization is infallible")
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
            action: "InvokeModel".to_string(),
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
    fn invoke_empty_model_id_errors() {
        let s = shared();
        let err = invoke_model(&s, &req(), "", b"{}").err().unwrap();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn invoke_anthropic_returns_message_format() {
        let s = shared();
        let resp = invoke_model(&s, &req(), "anthropic.claude-3", b"{}").unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["type"], "message");
        assert_eq!(v["role"], "assistant");
        assert_eq!(v["model"], "anthropic.claude-3");
    }

    #[test]
    fn invoke_amazon_titan_text_returns_results() {
        let s = shared();
        let resp = invoke_model(&s, &req(), "amazon.titan-text-express-v1", b"{}").unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert!(v["results"].is_array());
    }

    #[test]
    fn invoke_amazon_titan_embed_returns_vector() {
        let s = shared();
        let resp = invoke_model(&s, &req(), "amazon.titan-embed-text-v1", b"{}").unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert!(v["embedding"].is_array());
    }

    #[test]
    fn invoke_meta_returns_generation() {
        let s = shared();
        let resp = invoke_model(&s, &req(), "meta.llama3", b"{}").unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert!(v["generation"].is_string());
    }

    #[test]
    fn invoke_cohere_returns_generations() {
        let s = shared();
        let resp = invoke_model(&s, &req(), "cohere.command", b"{}").unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert!(v["generations"].is_array());
    }

    #[test]
    fn invoke_mistral_returns_outputs() {
        let s = shared();
        let resp = invoke_model(&s, &req(), "mistral.7b", b"{}").unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert!(v["outputs"].is_array());
    }

    #[test]
    fn invoke_unknown_provider_returns_generic() {
        let s = shared();
        let resp = invoke_model(&s, &req(), "stability.diffusion", b"{}").unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(
            v["output"],
            "This is a test response from the emulated model."
        );
    }

    #[test]
    fn invoke_records_invocation_entry() {
        let s = shared();
        invoke_model(&s, &req(), "anthropic.claude", b"{}").unwrap();
        let state = s.read();
        assert_eq!(state.default_ref().invocations.len(), 1);
    }

    #[test]
    fn invoke_returns_bedrock_headers() {
        let s = shared();
        let resp = invoke_model(&s, &req(), "anthropic.claude", b"{}").unwrap();
        assert!(resp
            .headers
            .get("x-amzn-bedrock-input-token-count")
            .is_some());
        assert!(resp
            .headers
            .get("x-amzn-bedrock-output-token-count")
            .is_some());
    }

    #[test]
    fn invoke_fault_injected_records_error() {
        let s = shared();
        s.write()
            .default_mut()
            .fault_rules
            .push(crate::state::FaultRule {
                error_type: "Throttle".to_string(),
                message: "slow".to_string(),
                http_status: 429,
                remaining: 1,
                model_id: None,
                operation: None,
            });
        let err = invoke_model(&s, &req(), "m", b"{}").err().unwrap();
        assert_eq!(err.status(), StatusCode::TOO_MANY_REQUESTS);
        let state = s.read();
        let acct = state.default_ref();
        assert_eq!(acct.invocations.len(), 1);
        assert!(acct.invocations[0].error.is_some());
    }

    #[test]
    fn count_tokens_empty_model_id_errors() {
        let s = shared();
        let err = count_tokens(&s, &req(), "", b"{}").err().unwrap();
        assert_eq!(err.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn count_tokens_invoke_model_body_docs() {
        let s = shared();
        let body = br#"{"input":{"invokeModel":{"body":{"prompt":"hello world foo bar"}}}}"#;
        let resp = count_tokens(&s, &req(), "m", body).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert!(v["inputTokens"].as_u64().unwrap() > 0);
    }

    #[test]
    fn count_tokens_converse_format() {
        let s = shared();
        let body = br#"{"input":{"converse":{"system":[{"text":"sys prompt"}],"messages":[{"content":[{"text":"hello world"}]}]}}}"#;
        let resp = count_tokens(&s, &req(), "m", body).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["inputTokens"].as_u64().unwrap(), 4);
    }

    #[test]
    fn count_tokens_unknown_input_falls_back_to_raw_json_count() {
        let s = shared();
        let body = br#"{"other":"field"}"#;
        let resp = count_tokens(&s, &req(), "m", body).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert!(v["inputTokens"].as_u64().unwrap() >= 1);
    }

    #[test]
    fn count_tokens_empty_body_parses_cleanly() {
        let s = shared();
        let body = b"";
        let resp = count_tokens(&s, &req(), "m", body).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        // Empty body produces Null JSON serialized to "null" (4 chars, 1 token)
        assert!(v["inputTokens"].is_u64());
    }
}
