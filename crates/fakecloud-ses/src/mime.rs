//! Hand-rolled RFC 5322 / MIME builder for fakecloud SES.
//!
//! AWS SES `TestRenderEmailTemplate` returns the fully-formed MIME message
//! that would be sent on `SendTemplatedEmail`. The previous implementation
//! emitted only `Subject` + `MIME-Version` + `Content-Type` + body, which
//! standard parsers (`mail-parser`, Python `email`, Node `mailparser`)
//! accept loosely but reject for missing `Date`, `Message-ID`, and proper
//! multipart structure when both text and HTML bodies are present.
//!
//! This module produces RFC-5322-compliant messages with:
//! - `Date` (RFC 2822), `Message-ID` (UUID), `MIME-Version: 1.0`
//! - `Subject` (RFC 2047 encoded-word when non-ASCII)
//! - `multipart/alternative` with proper boundary when both `text` and
//!   `html` parts are present, single-part otherwise
//! - `Content-Transfer-Encoding: quoted-printable` for non-ASCII bodies
//!   or HTML, `7bit` for plain ASCII text

use base64::Engine;
use chrono::Utc;
use uuid::Uuid;

/// Inputs for `build_message`.
pub struct MimeInputs<'a> {
    pub subject: &'a str,
    pub text: Option<&'a str>,
    pub html: Option<&'a str>,
}

/// Build an RFC 5322 / MIME message from the given subject and bodies.
pub fn build_message(input: &MimeInputs<'_>) -> String {
    let mut headers = String::new();
    headers.push_str(&format!("Date: {}\r\n", rfc2822_now()));
    headers.push_str(&format!(
        "Message-ID: <{}@fakecloud.local>\r\n",
        Uuid::new_v4().simple()
    ));
    headers.push_str(&format!("Subject: {}\r\n", encode_header(input.subject)));
    headers.push_str("MIME-Version: 1.0\r\n");

    match (input.text, input.html) {
        (Some(text), Some(html)) => {
            let boundary = format!("=_fakecloud_{}", Uuid::new_v4().simple());
            headers.push_str(&format!(
                "Content-Type: multipart/alternative; boundary=\"{}\"\r\n\r\n",
                boundary
            ));
            let mut body = String::new();
            push_part(&mut body, &boundary, "text/plain; charset=UTF-8", text);
            push_part(&mut body, &boundary, "text/html; charset=UTF-8", html);
            body.push_str(&format!("--{}--\r\n", boundary));
            headers + &body
        }
        (None, Some(html)) => single_part(headers, "text/html; charset=UTF-8", html),
        (Some(text), None) => single_part(headers, "text/plain; charset=UTF-8", text),
        (None, None) => single_part(headers, "text/plain; charset=UTF-8", ""),
    }
}

fn single_part(mut headers: String, content_type: &str, body: &str) -> String {
    let (encoded_body, encoding) = encode_body(body);
    headers.push_str(&format!("Content-Type: {}\r\n", content_type));
    headers.push_str(&format!("Content-Transfer-Encoding: {}\r\n\r\n", encoding));
    headers.push_str(&encoded_body);
    headers
}

fn push_part(out: &mut String, boundary: &str, content_type: &str, body: &str) {
    let (encoded_body, encoding) = encode_body(body);
    out.push_str(&format!("--{}\r\n", boundary));
    out.push_str(&format!("Content-Type: {}\r\n", content_type));
    out.push_str(&format!("Content-Transfer-Encoding: {}\r\n\r\n", encoding));
    out.push_str(&encoded_body);
    if !encoded_body.ends_with("\r\n") {
        out.push_str("\r\n");
    }
}

/// Quoted-printable for any non-ASCII body or HTML; 7bit for plain ASCII text.
fn encode_body(body: &str) -> (String, &'static str) {
    if body.is_ascii() {
        (body.replace('\n', "\r\n"), "7bit")
    } else {
        (quoted_printable_encode(body), "quoted-printable")
    }
}

fn quoted_printable_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut line_len = 0;
    for byte in input.as_bytes() {
        let needs_encoding = matches!(byte, 0..=31 | 61 | 127..=255) && *byte != b'\t';
        let chunk: String = if needs_encoding {
            format!("={:02X}", byte)
        } else {
            (*byte as char).to_string()
        };
        if line_len + chunk.len() > 75 {
            out.push_str("=\r\n");
            line_len = 0;
        }
        out.push_str(&chunk);
        line_len += chunk.len();
        if *byte == b'\n' {
            line_len = 0;
        }
    }
    out
}

/// RFC 2047 encoded-word for non-ASCII headers; raw otherwise.
fn encode_header(value: &str) -> String {
    if value.is_ascii() {
        value.to_string()
    } else {
        let b64 = base64::engine::general_purpose::STANDARD.encode(value.as_bytes());
        format!("=?UTF-8?B?{}?=", b64)
    }
}

fn rfc2822_now() -> String {
    Utc::now().format("%a, %d %b %Y %H:%M:%S +0000").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ascii_text_only_uses_7bit() {
        let mime = build_message(&MimeInputs {
            subject: "hello",
            text: Some("plain body"),
            html: None,
        });
        assert!(mime.contains("Subject: hello\r\n"));
        assert!(mime.contains("Content-Type: text/plain; charset=UTF-8\r\n"));
        assert!(mime.contains("Content-Transfer-Encoding: 7bit\r\n"));
        assert!(mime.contains("plain body"));
        assert!(mime.contains("Date: "));
        assert!(mime.contains("Message-ID: <"));
    }

    #[test]
    fn ascii_html_only_uses_html_part() {
        let mime = build_message(&MimeInputs {
            subject: "hi",
            text: None,
            html: Some("<p>x</p>"),
        });
        assert!(mime.contains("Content-Type: text/html; charset=UTF-8\r\n"));
        assert!(mime.contains("<p>x</p>"));
    }

    #[test]
    fn both_parts_use_multipart_alternative() {
        let mime = build_message(&MimeInputs {
            subject: "hi",
            text: Some("plain"),
            html: Some("<p>x</p>"),
        });
        assert!(mime.contains("multipart/alternative; boundary=\"=_fakecloud_"));
        assert!(mime.contains("Content-Type: text/plain; charset=UTF-8\r\n"));
        assert!(mime.contains("Content-Type: text/html; charset=UTF-8\r\n"));
        assert!(mime.contains("plain"));
        assert!(mime.contains("<p>x</p>"));
    }

    #[test]
    fn non_ascii_subject_uses_encoded_word() {
        let mime = build_message(&MimeInputs {
            subject: "héllo",
            text: Some("body"),
            html: None,
        });
        assert!(mime.contains("Subject: =?UTF-8?B?"));
    }

    #[test]
    fn non_ascii_body_uses_quoted_printable() {
        let mime = build_message(&MimeInputs {
            subject: "x",
            text: Some("café"),
            html: None,
        });
        assert!(mime.contains("Content-Transfer-Encoding: quoted-printable\r\n"));
        // 'é' is two bytes in UTF-8 (0xC3 0xA9), each must be percent-escaped.
        assert!(mime.contains("=C3=A9"));
    }
}
