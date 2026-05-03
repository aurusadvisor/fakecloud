//! Encode and decode the opaque deny-reason token returned to clients
//! when an IAM check denies a request, and consumed by
//! `sts:DecodeAuthorizationMessage`.
//!
//! AWS treats the encoded message as an opaque blob; the documented
//! contract is "pass it back to DecodeAuthorizationMessage and you'll
//! get JSON describing why the request was denied". We do the same:
//! the token is a deflate-compressed JSON document, base64-encoded.
//! The decoder reverses the transformation, so any deny-time site that
//! calls [`encode_deny`] gets a real round-trip without needing a
//! separate state map.

use base64::Engine;
use flate2::read::ZlibDecoder;
use flate2::write::ZlibEncoder;
use flate2::Compression;
use serde_json::{json, Value};
use std::io::{Read, Write};

/// Build an encoded authorization message describing a deny decision.
/// The shape mirrors what AWS returns from
/// `DecodeAuthorizationMessage`: an `allowed` flag, an `explicitDeny`
/// flag, and a `matchedStatements.items` array. Optional supplementary
/// keys (`action`, `principal`, `context`) are included so an operator
/// inspecting the decoded blob can see why the request failed.
pub fn encode_deny(
    explicit: bool,
    action: Option<&str>,
    principal_arn: Option<&str>,
    matched_statements: Vec<Value>,
    context: Option<Value>,
) -> String {
    let mut payload = json!({
        "allowed": false,
        "explicitDeny": explicit,
        "matchedStatements": { "items": matched_statements },
    });
    if let Some(a) = action {
        payload["action"] = json!(a);
    }
    if let Some(p) = principal_arn {
        payload["principal"] = json!(p);
    }
    if let Some(c) = context {
        payload["context"] = c;
    }
    let json_bytes = serde_json::to_vec(&payload).unwrap_or_default();
    let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(&json_bytes).ok();
    let compressed = encoder.finish().unwrap_or_default();
    base64::engine::general_purpose::STANDARD.encode(compressed)
}

/// Reverse [`encode_deny`]. Returns the JSON document the encoder
/// stashed, or an `InvalidAuthorizationMessageException`-shaped error
/// when the token isn't recognizable. Tokens that decode but don't
/// look like deny payloads are still returned verbatim — AWS's
/// behavior is to hand back whatever JSON it finds rather than try to
/// interpret it.
pub fn decode_message(encoded: &str) -> Result<String, &'static str> {
    let compressed = base64::engine::general_purpose::STANDARD
        .decode(encoded.as_bytes())
        .map_err(|_| "EncodedMessage is not valid base64")?;
    let mut decoder = ZlibDecoder::new(&compressed[..]);
    let mut json_bytes = Vec::new();
    decoder
        .read_to_end(&mut json_bytes)
        .map_err(|_| "EncodedMessage is not a valid deny token")?;
    String::from_utf8(json_bytes).map_err(|_| "EncodedMessage payload is not valid UTF-8")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_explicit_deny() {
        let token = encode_deny(
            true,
            Some("s3:GetObject"),
            Some("arn:aws:iam::111122223333:user/alice"),
            vec![json!({"sourcePolicyId": "PolicyA"})],
            Some(json!({"aws:SourceIp": "1.2.3.4"})),
        );
        let decoded = decode_message(&token).unwrap();
        let parsed: Value = serde_json::from_str(&decoded).unwrap();
        assert_eq!(parsed["allowed"], false);
        assert_eq!(parsed["explicitDeny"], true);
        assert_eq!(parsed["action"], "s3:GetObject");
        assert_eq!(parsed["principal"], "arn:aws:iam::111122223333:user/alice");
        assert_eq!(
            parsed["matchedStatements"]["items"][0]["sourcePolicyId"],
            "PolicyA"
        );
    }

    #[test]
    fn round_trip_implicit_deny_with_no_extras() {
        let token = encode_deny(false, None, None, Vec::new(), None);
        let decoded = decode_message(&token).unwrap();
        let parsed: Value = serde_json::from_str(&decoded).unwrap();
        assert_eq!(parsed["allowed"], false);
        assert_eq!(parsed["explicitDeny"], false);
        assert!(parsed["matchedStatements"]["items"]
            .as_array()
            .unwrap()
            .is_empty());
        assert!(parsed.get("action").is_none());
    }

    #[test]
    fn rejects_garbage_base64() {
        assert!(decode_message("not!!!base64!!").is_err());
    }

    #[test]
    fn rejects_base64_that_is_not_zlib() {
        let token = base64::engine::general_purpose::STANDARD.encode(b"not zlib data");
        assert!(decode_message(&token).is_err());
    }
}
