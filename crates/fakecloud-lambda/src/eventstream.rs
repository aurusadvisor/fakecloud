//! Minimal `application/vnd.amazon.eventstream` frame encoder.
//!
//! This is the wire format AWS uses for streaming responses on
//! `InvokeWithResponseStream`, S3 SelectObjectContent, Kinesis
//! SubscribeToShard, Transcribe, etc. Each frame is:
//!
//! ```text
//! +-----------------------------------+
//! | total length        (u32 BE)      |
//! | headers length      (u32 BE)      |
//! | prelude CRC32       (u32 BE)      |  CRC of the two preceding u32s
//! | headers bytes       (raw)         |
//! | payload bytes       (raw)         |
//! | message CRC32       (u32 BE)      |  CRC of the whole frame so far
//! +-----------------------------------+
//! ```
//!
//! Each header is encoded as:
//!
//! ```text
//! +---------------------------------------+
//! | name length     (u8)                  |
//! | name bytes                            |
//! | value type      (u8)                  |  7 = string
//! | value length    (u16 BE) [for strings]|
//! | value bytes                           |
//! +---------------------------------------+
//! ```
//!
//! Only the string header type (7) is needed for Lambda's response
//! stream — `:event-type`, `:content-type`, `:message-type` are all
//! short ASCII strings. Other value types (bool, int, byte_array,
//! timestamp, uuid) aren't required here and are intentionally omitted
//! to keep the surface minimal.

const HEADER_TYPE_STRING: u8 = 7;

/// Encode a single eventstream frame from a list of `(name, value)`
/// string headers and a payload byte slice. Returns the bytes ready to
/// be written to the response body.
pub fn encode_frame(headers: &[(&str, &str)], payload: &[u8]) -> Vec<u8> {
    let headers_bytes = encode_headers(headers);
    let headers_len = headers_bytes.len() as u32;
    // total = 4 (total) + 4 (headers_len) + 4 (prelude CRC) + headers + payload + 4 (msg CRC)
    let total_len = 12u32 + headers_len + payload.len() as u32 + 4;

    let mut out = Vec::with_capacity(total_len as usize);
    out.extend_from_slice(&total_len.to_be_bytes());
    out.extend_from_slice(&headers_len.to_be_bytes());

    let prelude_crc = crc32fast::hash(&out[..8]);
    out.extend_from_slice(&prelude_crc.to_be_bytes());

    out.extend_from_slice(&headers_bytes);
    out.extend_from_slice(payload);

    let msg_crc = crc32fast::hash(&out);
    out.extend_from_slice(&msg_crc.to_be_bytes());

    out
}

fn encode_headers(headers: &[(&str, &str)]) -> Vec<u8> {
    let mut buf = Vec::new();
    for (name, value) in headers {
        let name_bytes = name.as_bytes();
        let value_bytes = value.as_bytes();
        debug_assert!(name_bytes.len() <= u8::MAX as usize, "header name too long");
        debug_assert!(
            value_bytes.len() <= u16::MAX as usize,
            "header value too long"
        );
        buf.push(name_bytes.len() as u8);
        buf.extend_from_slice(name_bytes);
        buf.push(HEADER_TYPE_STRING);
        buf.extend_from_slice(&(value_bytes.len() as u16).to_be_bytes());
        buf.extend_from_slice(value_bytes);
    }
    buf
}

/// Build a `PayloadChunk` event frame carrying a slice of the function's
/// streamed response. AWS sends one of these per logical chunk emitted
/// by the function (e.g. each `responseStream.write(...)` call in a
/// Node.js streaming handler). The body is the raw chunk bytes — AWS
/// does **not** wrap them in JSON; clients reconstruct the response by
/// concatenating the payloads of every `PayloadChunk` event.
pub fn payload_chunk_frame(chunk: &[u8]) -> Vec<u8> {
    encode_frame(
        &[
            (":event-type", "PayloadChunk"),
            (":content-type", "application/octet-stream"),
            (":message-type", "event"),
        ],
        chunk,
    )
}

/// Build the terminal `InvokeComplete` event frame. `error_code` /
/// `error_details` are `None` on success; `log_result_b64` is the
/// base64-encoded last 4 KiB of the function's tail log (empty string
/// when no log was captured).
pub fn invoke_complete_frame(
    error_code: Option<&str>,
    error_details: Option<&str>,
    log_result_b64: &str,
) -> Vec<u8> {
    let payload = serde_json::json!({
        "ErrorCode": error_code,
        "ErrorDetails": error_details,
        "LogResult": log_result_b64,
    });
    let body = serde_json::to_vec(&payload).expect("static JSON shape never fails to serialize");
    encode_frame(
        &[
            (":event-type", "InvokeComplete"),
            (":content-type", "application/json"),
            (":message-type", "event"),
        ],
        &body,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Decode a single eventstream frame back into `(headers, payload)`,
    /// validating both CRCs. Used by the tests below to round-trip the
    /// encoder; mirrors what an AWS SDK does when parsing the response.
    fn decode_frame(buf: &[u8]) -> (Vec<(String, String)>, Vec<u8>) {
        assert!(buf.len() >= 16, "frame too short");
        let total_len = u32::from_be_bytes(buf[0..4].try_into().unwrap()) as usize;
        assert_eq!(total_len, buf.len(), "total length mismatch");
        let headers_len = u32::from_be_bytes(buf[4..8].try_into().unwrap()) as usize;
        let prelude_crc = u32::from_be_bytes(buf[8..12].try_into().unwrap());
        assert_eq!(prelude_crc, crc32fast::hash(&buf[0..8]), "prelude CRC bad");

        let headers_start = 12;
        let headers_end = headers_start + headers_len;
        let payload_end = total_len - 4;
        let msg_crc = u32::from_be_bytes(buf[payload_end..total_len].try_into().unwrap());
        assert_eq!(msg_crc, crc32fast::hash(&buf[..payload_end]), "msg CRC bad");

        let mut headers = Vec::new();
        let hbuf = &buf[headers_start..headers_end];
        let mut i = 0;
        while i < hbuf.len() {
            let nl = hbuf[i] as usize;
            i += 1;
            let name = std::str::from_utf8(&hbuf[i..i + nl]).unwrap().to_string();
            i += nl;
            let vt = hbuf[i];
            i += 1;
            assert_eq!(vt, HEADER_TYPE_STRING, "only string headers supported");
            let vl = u16::from_be_bytes(hbuf[i..i + 2].try_into().unwrap()) as usize;
            i += 2;
            let value = std::str::from_utf8(&hbuf[i..i + vl]).unwrap().to_string();
            i += vl;
            headers.push((name, value));
        }

        let payload = buf[headers_end..payload_end].to_vec();
        (headers, payload)
    }

    #[test]
    fn round_trip_payload_chunk() {
        let frame = payload_chunk_frame(b"hello world");
        let (headers, payload) = decode_frame(&frame);
        assert_eq!(payload, b"hello world");
        assert!(headers
            .iter()
            .any(|(k, v)| k == ":event-type" && v == "PayloadChunk"));
        assert!(headers
            .iter()
            .any(|(k, v)| k == ":message-type" && v == "event"));
    }

    #[test]
    fn round_trip_invoke_complete_success() {
        let frame = invoke_complete_frame(None, None, "");
        let (headers, payload) = decode_frame(&frame);
        assert!(headers
            .iter()
            .any(|(k, v)| k == ":event-type" && v == "InvokeComplete"));
        let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert!(v["ErrorCode"].is_null());
        assert!(v["ErrorDetails"].is_null());
        assert_eq!(v["LogResult"], "");
    }

    #[test]
    fn round_trip_invoke_complete_error() {
        let frame = invoke_complete_frame(Some("Runtime.UserError"), Some("boom"), "bG9n");
        let (headers, payload) = decode_frame(&frame);
        assert!(headers
            .iter()
            .any(|(k, v)| k == ":event-type" && v == "InvokeComplete"));
        let v: serde_json::Value = serde_json::from_slice(&payload).unwrap();
        assert_eq!(v["ErrorCode"], "Runtime.UserError");
        assert_eq!(v["ErrorDetails"], "boom");
        assert_eq!(v["LogResult"], "bG9n");
    }

    #[test]
    fn empty_chunk_still_well_formed() {
        let frame = payload_chunk_frame(b"");
        let (_headers, payload) = decode_frame(&frame);
        assert!(payload.is_empty());
    }

    #[test]
    fn multiple_frames_concatenate_cleanly() {
        let mut out = Vec::new();
        out.extend(payload_chunk_frame(b"chunk-1"));
        out.extend(payload_chunk_frame(b"chunk-2"));
        out.extend(invoke_complete_frame(None, None, ""));

        // Decode each frame in sequence by reading total_len.
        let mut frames = Vec::new();
        let mut cursor = 0;
        while cursor < out.len() {
            let total = u32::from_be_bytes(out[cursor..cursor + 4].try_into().unwrap()) as usize;
            frames.push(decode_frame(&out[cursor..cursor + total]));
            cursor += total;
        }
        assert_eq!(frames.len(), 3);
        assert_eq!(frames[0].1, b"chunk-1");
        assert_eq!(frames[1].1, b"chunk-2");
        // Last is InvokeComplete with JSON body
        let v: serde_json::Value = serde_json::from_slice(&frames[2].1).unwrap();
        assert!(v["ErrorCode"].is_null());
    }
}
