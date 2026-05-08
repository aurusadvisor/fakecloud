//! Minimal `application/vnd.amazon.eventstream` frame encoder for S3 Select.
//!
//! Reuses the same wire format as Lambda's eventstream (prelude + headers +
//! payload + CRCs) but defines S3-specific event types.

const HEADER_TYPE_STRING: u8 = 7;

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

pub fn stats_event_frame(bytes_scanned: u64, bytes_processed: u64, bytes_returned: u64) -> Vec<u8> {
    let payload = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n<Stats>\n  <BytesScanned>{}</BytesScanned>\n  <BytesProcessed>{}</BytesProcessed>\n  <BytesReturned>{}</BytesReturned>\n</Stats>\n",
        bytes_scanned, bytes_processed, bytes_returned
    );
    encode_frame(
        &[
            (":event-type", "Stats"),
            (":content-type", "application/xml"),
            (":message-type", "event"),
        ],
        payload.as_bytes(),
    )
}

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

#[cfg(test)]
mod tests {
    use super::*;
    use aws_smithy_eventstream::frame::read_message_from;
    use bytes::Bytes;

    #[test]
    fn records_frame_decodes_with_sdk() {
        let frame = records_event_frame(b"hello");
        let msg = read_message_from(&mut Bytes::from(frame)).unwrap();
        assert_eq!(msg.payload().as_ref(), b"hello");
        let headers: Vec<_> = msg
            .headers()
            .iter()
            .map(|h| {
                (
                    h.name().as_str().to_string(),
                    h.value().as_string().unwrap().as_str().to_string(),
                )
            })
            .collect();
        assert!(headers
            .iter()
            .any(|(k, v)| k == ":event-type" && v == "Records"));
        assert!(headers
            .iter()
            .any(|(k, v)| k == ":message-type" && v == "event"));
    }

    #[test]
    fn stats_frame_decodes_with_sdk() {
        let frame = stats_event_frame(100, 50, 25);
        let msg = read_message_from(&mut Bytes::from(frame)).unwrap();
        let payload = std::str::from_utf8(msg.payload().as_ref()).unwrap();
        assert!(payload.contains("BytesScanned"));
        assert!(payload.contains("100"));
    }

    #[test]
    fn end_frame_decodes_with_sdk() {
        let frame = end_event_frame();
        let msg = read_message_from(&mut Bytes::from(frame)).unwrap();
        assert!(msg.payload().is_empty());
        let headers: Vec<_> = msg
            .headers()
            .iter()
            .map(|h| {
                (
                    h.name().as_str().to_string(),
                    h.value().as_string().unwrap().as_str().to_string(),
                )
            })
            .collect();
        assert!(headers
            .iter()
            .any(|(k, v)| k == ":event-type" && v == "End"));
    }

    #[test]
    fn concatenated_frames_decode_with_sdk_decoder() {
        let records = records_event_frame(b"hello");
        let stats = stats_event_frame(100, 50, 25);
        let end = end_event_frame();

        let mut combined = Vec::new();
        combined.extend_from_slice(&records);
        combined.extend_from_slice(&stats);
        combined.extend_from_slice(&end);

        let mut decoder = aws_smithy_eventstream::frame::MessageFrameDecoder::new();
        let mut buf = bytes_utils::SegmentedBuf::new();
        buf.push(Bytes::from(combined));

        let mut count = 0;
        while let aws_smithy_eventstream::frame::DecodedFrame::Complete(_) =
            decoder.decode_frame(&mut buf).unwrap()
        {
            count += 1;
        }
        assert_eq!(count, 3, "Expected 3 decoded frames");
    }
}
