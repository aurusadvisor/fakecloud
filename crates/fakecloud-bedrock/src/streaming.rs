use serde_json::{json, Value};

/// Encode data as an AWS event-stream message.
/// The event stream binary format:
///   [total_byte_length:4] [headers_byte_length:4] [prelude_crc:4]
///   [headers:*] [payload:*] [message_crc:4]
pub(crate) fn encode_event(event_type: &str, content_type: &str, payload: &[u8]) -> Vec<u8> {
    let headers = encode_headers(event_type, content_type);
    let headers_len = headers.len() as u32;

    // Total = 4 (total len) + 4 (headers len) + 4 (prelude CRC) + headers + payload + 4 (msg CRC)
    let total_len = 12 + headers_len + payload.len() as u32 + 4;

    let mut buf = Vec::with_capacity(total_len as usize);

    // Prelude
    buf.extend_from_slice(&total_len.to_be_bytes());
    buf.extend_from_slice(&headers_len.to_be_bytes());

    // Prelude CRC
    let prelude_crc = crc32(&buf[..8]);
    buf.extend_from_slice(&prelude_crc.to_be_bytes());

    // Headers
    buf.extend_from_slice(&headers);

    // Payload
    buf.extend_from_slice(payload);

    // Message CRC
    let msg_crc = crc32(&buf);
    buf.extend_from_slice(&msg_crc.to_be_bytes());

    buf
}

fn encode_headers(event_type: &str, content_type: &str) -> Vec<u8> {
    let mut headers = Vec::new();

    // :event-type header
    encode_string_header(&mut headers, ":event-type", event_type);

    // :content-type header
    encode_string_header(&mut headers, ":content-type", content_type);

    // :message-type header
    encode_string_header(&mut headers, ":message-type", "event");

    headers
}

fn encode_string_header(buf: &mut Vec<u8>, name: &str, value: &str) {
    // Header name: 1 byte length + name bytes
    buf.push(name.len() as u8);
    buf.extend_from_slice(name.as_bytes());

    // Header value type: 7 = string
    buf.push(7);

    // String value: 2 byte length + value bytes
    let value_len = value.len() as u16;
    buf.extend_from_slice(&value_len.to_be_bytes());
    buf.extend_from_slice(value.as_bytes());
}

/// CRC-32 (IEEE/CRC-32C is used by AWS but standard CRC-32 works for compatibility)
fn crc32(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in data {
        crc ^= byte as u32;
        for _ in 0..8 {
            if crc & 1 == 1 {
                crc = (crc >> 1) ^ 0xEDB8_8320;
            } else {
                crc >>= 1;
            }
        }
    }
    !crc
}

/// Build the complete event stream body for InvokeModelWithResponseStream.
/// Returns the full body as a single chunk containing all events.
pub(crate) fn build_invoke_stream_response(model_id: &str, response_text: &str) -> Vec<u8> {
    let mut body = Vec::new();

    // For Anthropic models, emit message_start, content_block_start, content_block_delta,
    // content_block_stop, message_delta, message_stop
    if model_id.starts_with("anthropic.") {
        // chunk event with the response
        let chunk = json!({
            "type": "content_block_delta",
            "index": 0,
            "delta": {
                "type": "text_delta",
                "text": response_text
            }
        });
        let payload = serde_json::to_vec(
            &json!({ "bytes": base64_encode(&serde_json::to_vec(&chunk).unwrap()) }),
        )
        .unwrap();
        body.extend(encode_event("chunk", "application/json", &payload));
    } else {
        // Generic: single chunk with the full response
        let chunk = json!({
            "outputText": response_text
        });
        let payload = serde_json::to_vec(
            &json!({ "bytes": base64_encode(&serde_json::to_vec(&chunk).unwrap()) }),
        )
        .unwrap();
        body.extend(encode_event("chunk", "application/json", &payload));
    }

    body
}

/// Build the complete event stream body for ConverseStream.
pub(crate) fn build_converse_stream_response(response_text: &str) -> Vec<u8> {
    let mut body = Vec::new();

    // messageStart event
    let start = json!({ "role": "assistant" });
    let payload = serde_json::to_vec(&json!({ "messageStart": start })).unwrap();
    body.extend(encode_event("messageStart", "application/json", &payload));

    // contentBlockStart event
    let block_start = json!({ "contentBlockIndex": 0, "start": {} });
    let payload = serde_json::to_vec(&json!({ "contentBlockStart": block_start })).unwrap();
    body.extend(encode_event(
        "contentBlockStart",
        "application/json",
        &payload,
    ));

    // contentBlockDelta event with the text
    let delta = json!({
        "contentBlockIndex": 0,
        "delta": {
            "text": response_text
        }
    });
    let payload = serde_json::to_vec(&json!({ "contentBlockDelta": delta })).unwrap();
    body.extend(encode_event(
        "contentBlockDelta",
        "application/json",
        &payload,
    ));

    // contentBlockStop event
    let block_stop = json!({ "contentBlockIndex": 0 });
    let payload = serde_json::to_vec(&json!({ "contentBlockStop": block_stop })).unwrap();
    body.extend(encode_event(
        "contentBlockStop",
        "application/json",
        &payload,
    ));

    // messageStop event
    let stop = json!({
        "stopReason": "end_turn"
    });
    let payload = serde_json::to_vec(&json!({ "messageStop": stop })).unwrap();
    body.extend(encode_event("messageStop", "application/json", &payload));

    // metadata event
    let metadata = json!({
        "usage": {
            "inputTokens": 10,
            "outputTokens": 20,
            "totalTokens": 30
        },
        "metrics": {
            "latencyMs": 100
        }
    });
    let payload = serde_json::to_vec(&json!({ "metadata": metadata })).unwrap();
    body.extend(encode_event("metadata", "application/json", &payload));

    body
}

fn base64_encode(data: &[u8]) -> String {
    use base64::Engine;
    base64::engine::general_purpose::STANDARD.encode(data)
}

/// Wrap response text for non-streaming provider fallback
pub(crate) fn default_stream_text() -> &'static str {
    "This is a test response from the emulated model."
}

/// Generate the canned response text, checking for prompt-conditional and
/// legacy custom overrides for the given call.
pub(crate) fn get_response_text(
    state: &crate::state::SharedBedrockState,
    req: &fakecloud_core::service::AwsRequest,
    model_id: &str,
    body: &[u8],
) -> String {
    let Some(custom) = crate::prompt::resolve_override(state, req, model_id, body) else {
        return default_stream_text().to_string();
    };
    // Try to extract text from a JSON response body.
    if let Ok(parsed) = serde_json::from_str::<Value>(&custom) {
        // Anthropic format
        if let Some(text) = parsed["content"][0]["text"].as_str() {
            return text.to_string();
        }
        // Converse format
        if let Some(text) = parsed["output"]["message"]["content"][0]["text"].as_str() {
            return text.to_string();
        }
    }
    custom
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::BedrockState;
    use bytes::Bytes;
    use fakecloud_core::multi_account::MultiAccountState;
    use fakecloud_core::service::AwsRequest;
    use http::{HeaderMap, Method};
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn shared() -> crate::state::SharedBedrockState {
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

    /// Parse prelude to verify framing and sizes.
    fn parse_prelude(buf: &[u8]) -> (u32, u32) {
        let total = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
        let headers = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
        (total, headers)
    }

    #[test]
    fn encode_event_produces_well_formed_frame() {
        let payload = b"{\"x\":1}";
        let buf = encode_event("chunk", "application/json", payload);
        let (total, headers_len) = parse_prelude(&buf);
        assert_eq!(total as usize, buf.len());
        let expected_headers = 1
            + ":event-type".len()
            + 1
            + 2
            + "chunk".len()
            + 1
            + ":content-type".len()
            + 1
            + 2
            + "application/json".len()
            + 1
            + ":message-type".len()
            + 1
            + 2
            + "event".len();
        assert_eq!(headers_len as usize, expected_headers);
        let start = 12 + headers_len as usize;
        assert_eq!(&buf[start..start + payload.len()], payload);
    }

    fn decode_inner_chunk(frame: &[u8]) -> Value {
        use base64::Engine;
        let s = String::from_utf8_lossy(frame);
        let bytes_start = s.find("\"bytes\":").unwrap() + "\"bytes\":".len();
        let after = &s[bytes_start..];
        let quote = after.find('"').unwrap();
        let end = after[quote + 1..].find('"').unwrap();
        let b64 = &after[quote + 1..quote + 1 + end];
        let raw = base64::engine::general_purpose::STANDARD
            .decode(b64)
            .unwrap();
        serde_json::from_slice(&raw).unwrap()
    }

    #[test]
    fn build_invoke_stream_response_anthropic_uses_content_block_delta() {
        let out = build_invoke_stream_response("anthropic.claude-3", "hello");
        let inner = decode_inner_chunk(&out);
        assert_eq!(inner["type"], "content_block_delta");
        assert_eq!(inner["delta"]["text"], "hello");
    }

    #[test]
    fn build_invoke_stream_response_generic_uses_output_text() {
        let out = build_invoke_stream_response("amazon.titan-text-lite", "hi");
        let inner = decode_inner_chunk(&out);
        assert_eq!(inner["outputText"], "hi");
    }

    #[test]
    fn build_converse_stream_emits_all_events() {
        let out = build_converse_stream_response("hello world");
        let s = String::from_utf8_lossy(&out);
        for marker in [
            "messageStart",
            "contentBlockStart",
            "contentBlockDelta",
            "contentBlockStop",
            "messageStop",
            "metadata",
            "end_turn",
        ] {
            assert!(s.contains(marker), "missing marker {marker}");
        }
    }

    #[test]
    fn default_stream_text_is_non_empty() {
        assert!(!default_stream_text().is_empty());
    }

    #[test]
    fn get_response_text_returns_default_without_override() {
        let s = shared();
        let out = get_response_text(&s, &req(), "anthropic.claude", b"{}");
        assert_eq!(out, default_stream_text());
    }

    fn install_rule(state: &crate::state::SharedBedrockState, model: &str, response: &str) {
        let mut st = state.write();
        let acct = st.get_or_create("123456789012");
        acct.response_rules.insert(
            model.to_string(),
            vec![crate::state::ResponseRule {
                prompt_contains: None,
                response: response.to_string(),
            }],
        );
    }

    #[test]
    fn get_response_text_extracts_anthropic_content_when_override_present() {
        let s = shared();
        install_rule(
            &s,
            "anthropic.claude",
            &json!({ "content": [{"text": "FROM-RULE"}] }).to_string(),
        );
        let out = get_response_text(&s, &req(), "anthropic.claude", b"{}");
        assert_eq!(out, "FROM-RULE");
    }

    #[test]
    fn get_response_text_extracts_converse_output_when_override_present() {
        let s = shared();
        install_rule(
            &s,
            "anthropic.claude",
            &json!({
                "output": {"message": {"content": [{"text": "CONV-TEXT"}]}}
            })
            .to_string(),
        );
        let out = get_response_text(&s, &req(), "anthropic.claude", b"{}");
        assert_eq!(out, "CONV-TEXT");
    }

    #[test]
    fn get_response_text_returns_raw_string_when_not_parseable() {
        let s = shared();
        install_rule(&s, "anthropic.claude", "plain raw");
        let out = get_response_text(&s, &req(), "anthropic.claude", b"{}");
        assert_eq!(out, "plain raw");
    }
}
