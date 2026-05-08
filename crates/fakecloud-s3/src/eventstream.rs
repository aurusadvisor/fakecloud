//! Minimal `application/vnd.amazon.eventstream` frame encoder for S3 Select.
//!
//! Reuses the same wire format as Lambda's eventstream (prelude + headers +
//! payload + CRCs) but defines S3-specific event types.

const HEADER_TYPE_STRING: u8 = 7;

/// Encode a single eventstream frame.
pub fn encode_frame(headers: &[(&str, &str)], payload: &[u8]) -> Vec<u8> {
    let headers_bytes = encode_headers(headers);
    let headers_len = headers_bytes.len() as u32;
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

/// `Records` event carrying the query result payload.
pub fn records_event_frame(payload: &[u8]) -> Vec<u8> {
    encode_frame(
        &[
            (":event-type", "Records"),
            (":content-type", "application/octet-stream"),
            (":message-type", "event"),
        ],
        payload,
    )
}

/// `Stats` event with byte counters.
pub fn stats_event_frame(bytes_scanned: u64, bytes_processed: u64, bytes_returned: u64) -> Vec<u8> {
    let payload = serde_json::json!({
        "BytesScanned": bytes_scanned,
        "BytesProcessed": bytes_processed,
        "BytesReturned": bytes_returned,
    });
    let body = serde_json::to_vec(&payload).expect("static JSON shape never fails to serialize");
    encode_frame(
        &[
            (":event-type", "Stats"),
            (":content-type", "application/json"),
            (":message-type", "event"),
        ],
        &body,
    )
}

/// `End` event signalling the stream is complete.
pub fn end_event_frame() -> Vec<u8> {
    encode_frame(
        &[
            (":event-type", "End"),
            (":content-type", "application/xml"),
            (":message-type", "event"),
        ],
        b"",
    )
}
