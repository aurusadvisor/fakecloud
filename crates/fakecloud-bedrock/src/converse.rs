use chrono::Utc;
use http::StatusCode;
use serde_json::{json, Value};

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::state::SharedBedrockState;

/// Handle the Converse API — unified conversation format across all models.
pub fn converse(
    state: &SharedBedrockState,
    req: &AwsRequest,
    model_id: &str,
    body: &[u8],
) -> Result<AwsResponse, AwsServiceError> {
    if let Some(fault) = crate::faults::take_matching_fault(state, req, model_id, "Converse") {
        crate::faults::record_faulted_invocation(state, req, model_id, body, &fault);
        return Err(crate::faults::fault_to_error(&fault));
    }

    let input: Value = serde_json::from_slice(body).unwrap_or_default();

    let inference_config = input.get("inferenceConfig");
    let max_tokens = inference_config
        .and_then(|c| c["maxTokens"].as_u64())
        .unwrap_or(u64::MAX);
    let tool_config = input.get("toolConfig");

    let response_text = match crate::prompt::resolve_override(state, req, model_id, body) {
        Some(custom) => {
            let parsed: Value = serde_json::from_str(&custom).unwrap_or_default();
            if let Some(text) = parsed["output"]["message"]["content"][0]["text"].as_str() {
                text.to_string()
            } else {
                custom
            }
        }
        None => "This is a test response from the emulated model.".to_string(),
    };

    // Respect maxTokens by truncating (rough approximation: 1 token ~= 4 chars)
    let truncated_text = if max_tokens < u64::MAX {
        let char_limit = (max_tokens as usize) * 4;
        if response_text.chars().count() > char_limit {
            response_text.chars().take(char_limit).collect::<String>()
        } else {
            response_text
        }
    } else {
        response_text
    };

    // Build content blocks
    let mut content = vec![json!({"text": truncated_text})];

    // If toolConfig is provided with tools, include a toolUse block
    if let Some(tc) = tool_config {
        if let Some(tools) = tc["tools"].as_array() {
            if let Some(first_tool) = tools.first() {
                if let Some(tool_spec) = first_tool.get("toolSpec") {
                    let tool_name = tool_spec["name"].as_str().unwrap_or("tool");
                    content.push(json!({
                        "toolUse": {
                            "toolUseId": "tooluse_fakecloud_01",
                            "name": tool_name,
                            "input": {}
                        }
                    }));
                }
            }
        }
    }

    let stop_reason = if tool_config.is_some()
        && content.len() > 1
        && content
            .last()
            .map(|c| c.get("toolUse").is_some())
            .unwrap_or(false)
    {
        "tool_use"
    } else {
        "end_turn"
    };

    let input_tokens = estimate_tokens(&input);
    let output_tokens = truncated_text.split_whitespace().count().max(1) as u64;

    let response = json!({
        "output": {
            "message": {
                "role": "assistant",
                "content": content
            }
        },
        "stopReason": stop_reason,
        "usage": {
            "inputTokens": input_tokens,
            "outputTokens": output_tokens,
            "totalTokens": input_tokens + output_tokens
        },
        "metrics": {
            "latencyMs": 100
        }
    });

    let response_str = serde_json::to_string(&response).unwrap();

    // Record invocation for introspection
    {
        let mut accts = state.write();
        let s = accts.get_or_create(&req.account_id);
        s.invocations.push(crate::state::ModelInvocation {
            model_id: model_id.to_string(),
            input: String::from_utf8_lossy(body).to_string(),
            output: response_str.clone(),
            timestamp: Utc::now(),
            error: None,
        });
    }

    Ok(AwsResponse::json(StatusCode::OK, response_str))
}

fn estimate_tokens(input: &Value) -> u64 {
    let mut text_len = 0usize;

    // Count system prompt tokens
    if let Some(system) = input.get("system").and_then(|s| s.as_array()) {
        for block in system {
            if let Some(text) = block["text"].as_str() {
                text_len += text.len();
            }
        }
    }

    // Count message tokens
    if let Some(messages) = input.get("messages").and_then(|m| m.as_array()) {
        for msg in messages {
            if let Some(content) = msg.get("content").and_then(|c| c.as_array()) {
                for block in content {
                    if let Some(text) = block["text"].as_str() {
                        text_len += text.len();
                    }
                }
            }
        }
    }

    // Rough approximation: 1 token ~= 4 characters, minimum 1
    (text_len / 4).max(1) as u64
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
            action: "Converse".to_string(),
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
    fn estimate_tokens_empty_returns_min_one() {
        let v = json!({});
        assert_eq!(estimate_tokens(&v), 1);
    }

    #[test]
    fn estimate_tokens_counts_system_and_messages() {
        let v = json!({
            "system": [{"text": "12345678"}],
            "messages": [{"content": [{"text": "abcdefgh"}]}]
        });
        assert_eq!(estimate_tokens(&v), 4); // 16 chars / 4
    }

    #[test]
    fn converse_default_response_no_fault_no_override() {
        let s = shared();
        let body = br#"{"messages":[{"content":[{"text":"hi"}]}]}"#;
        let resp = converse(&s, &req(), "anthropic.claude-v2", body).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["output"]["message"]["role"], "assistant");
        assert_eq!(v["stopReason"], "end_turn");
        assert!(v["usage"]["totalTokens"].is_u64());
    }

    #[test]
    fn converse_truncates_via_max_tokens() {
        let s = shared();
        let body = br#"{"messages":[], "inferenceConfig": {"maxTokens": 2}}"#;
        let resp = converse(&s, &req(), "m", body).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        let text = v["output"]["message"]["content"][0]["text"]
            .as_str()
            .unwrap();
        // 2 tokens * 4 chars = 8-char cap
        assert!(text.len() <= 8);
    }

    #[test]
    fn converse_tool_config_adds_tool_use_block_and_stop_reason() {
        let s = shared();
        let body = br#"{
            "messages": [],
            "toolConfig": {"tools": [{"toolSpec": {"name": "calculator"}}]}
        }"#;
        let resp = converse(&s, &req(), "m", body).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["stopReason"], "tool_use");
        let content = v["output"]["message"]["content"].as_array().unwrap();
        assert_eq!(content.len(), 2);
        assert_eq!(content[1]["toolUse"]["name"], "calculator");
    }

    #[test]
    fn converse_records_invocation() {
        let s = shared();
        let body = br#"{"messages":[]}"#;
        converse(&s, &req(), "model-x", body).unwrap();
        let state = s.read();
        let acct = state.default_ref();
        assert_eq!(acct.invocations.len(), 1);
        assert_eq!(acct.invocations[0].model_id, "model-x");
        assert!(acct.invocations[0].error.is_none());
    }

    #[test]
    fn converse_uses_response_rule_override() {
        let s = shared();
        s.write()
            .default_mut()
            .custom_responses
            .insert("model-y".to_string(), "override-output".to_string());
        let body = br#"{"messages":[]}"#;
        let resp = converse(&s, &req(), "model-y", body).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(
            v["output"]["message"]["content"][0]["text"],
            "override-output"
        );
    }

    #[test]
    fn converse_override_with_nested_text_extracts_from_json() {
        let s = shared();
        let payload = r#"{"output":{"message":{"content":[{"text":"nested-hello"}]}}}"#;
        s.write()
            .default_mut()
            .custom_responses
            .insert("model-z".to_string(), payload.to_string());
        let body = br#"{"messages":[]}"#;
        let resp = converse(&s, &req(), "model-z", body).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["output"]["message"]["content"][0]["text"], "nested-hello");
    }

    #[test]
    fn converse_returns_fault_when_matched_and_records_error_invocation() {
        let s = shared();
        s.write()
            .default_mut()
            .fault_rules
            .push(crate::state::FaultRule {
                error_type: "Throttled".to_string(),
                message: "slow".to_string(),
                http_status: 429,
                remaining: 1,
                model_id: None,
                operation: None,
            });
        let body = br#"{"messages":[]}"#;
        let err = converse(&s, &req(), "m", body).err().unwrap();
        assert_eq!(err.status(), StatusCode::TOO_MANY_REQUESTS);
        let state = s.read();
        let acct = state.default_ref();
        assert_eq!(acct.invocations.len(), 1);
        assert!(acct.invocations[0].error.is_some());
    }
}
