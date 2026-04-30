//! DKIM signing for outbound email.
//!
//! When an `EmailIdentity` has DKIM enabled and a private key configured,
//! every email sent through that identity gets a `DKIM-Signature` header
//! computed over the message headers + body using simple/simple
//! canonicalization with RSA-SHA256. Real receivers can verify against
//! the matching public key (Easy DKIM publishes generated public keys via
//! the per-identity `DkimTokens`; BYODKIM uses the caller-supplied key).

use base64::Engine;
use rsa::pkcs1::DecodeRsaPrivateKey;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::{DecodePrivateKey, EncodePrivateKey, EncodePublicKey, LineEnding};
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::{Digest, Sha256};

use crate::state::{SentEmail, SesState};

const DEFAULT_KEY_BITS: usize = 2048;
const SIGNED_HEADERS: &[&str] = &["from", "to", "subject", "date", "message-id"];

/// Generate a fresh RSA-2048 keypair for Easy DKIM. Returns the PEM-encoded
/// PKCS#8 private key and the SubjectPublicKeyInfo DER as base64
/// (the format SES publishes via the `*.dkim.amazonses.com` CNAME chain).
pub fn generate_easy_dkim_keypair() -> (String, String) {
    let mut rng = rand::thread_rng();
    let priv_key = RsaPrivateKey::new(&mut rng, DEFAULT_KEY_BITS).expect("rsa keypair generation");
    let pub_key = RsaPublicKey::from(&priv_key);
    let priv_pem = priv_key
        .to_pkcs8_pem(LineEnding::LF)
        .expect("encode pkcs8 pem")
        .to_string();
    let pub_der = pub_key
        .to_public_key_der()
        .expect("encode spki der")
        .as_bytes()
        .to_vec();
    let pub_b64 = base64::engine::general_purpose::STANDARD.encode(pub_der);
    (priv_pem, pub_b64)
}

/// Sign the given message and return a fully-formed `DKIM-Signature`
/// header value (without the leading `DKIM-Signature: ` prefix). Returns
/// `None` when the private key cannot be parsed.
pub fn sign_message(
    private_key_pem: &str,
    domain: &str,
    selector: &str,
    headers: &[(String, String)],
    body: &str,
) -> Option<String> {
    let priv_key = parse_private_key(private_key_pem)?;
    let signing_key = SigningKey::<Sha256>::new(priv_key);

    let canonical_body = canonicalize_body_simple(body);
    let mut body_hasher = Sha256::new();
    body_hasher.update(canonical_body.as_bytes());
    let bh = base64::engine::general_purpose::STANDARD.encode(body_hasher.finalize());

    let signed_headers: Vec<&(String, String)> = SIGNED_HEADERS
        .iter()
        .filter_map(|name| headers.iter().find(|(h, _)| h.eq_ignore_ascii_case(name)))
        .collect();
    let header_list = signed_headers
        .iter()
        .map(|(h, _)| h.to_lowercase())
        .collect::<Vec<_>>()
        .join(":");

    let mut header_block = String::new();
    for (h, v) in &signed_headers {
        header_block.push_str(&format!("{}: {}\r\n", h, v.trim()));
    }
    let dkim_unsigned = format!(
        "v=1; a=rsa-sha256; c=simple/simple; d={}; s={}; h={}; bh={}; b=",
        domain, selector, header_list, bh
    );
    header_block.push_str(&format!("DKIM-Signature: {}", dkim_unsigned));

    let signature = signing_key.sign(header_block.as_bytes());
    let b = base64::engine::general_purpose::STANDARD.encode(signature.to_bytes());
    Some(format!("{}{}", dkim_unsigned, b))
}

/// Look up the verified identity covering `sent.from` (full address first,
/// then domain) and compute the `DKIM-Signature` header value if signing
/// is enabled and a key is on file. Returns `None` if no matching identity
/// has DKIM signing wired.
pub fn signature_for_sent_email(state: &SesState, sent: &SentEmail) -> Option<String> {
    let address = address_part(&sent.from);
    let domain = address.split('@').nth(1)?;
    let identity = state
        .identities
        .get(&address)
        .or_else(|| state.identities.get(domain))?;
    if !identity.dkim_signing_enabled {
        return None;
    }
    let private_key = identity.dkim_domain_signing_private_key.as_deref()?;
    let selector = identity
        .dkim_domain_signing_selector
        .as_deref()
        .unwrap_or("fakecloudses");
    let body_text = sent
        .raw_data
        .clone()
        .or_else(|| sent.html_body.clone())
        .or_else(|| sent.text_body.clone())
        .unwrap_or_default();
    let to_header = sent.to.join(", ");
    let date = sent
        .timestamp
        .format("%a, %d %b %Y %H:%M:%S +0000")
        .to_string();
    let headers = vec![
        ("From".to_string(), sent.from.clone()),
        ("To".to_string(), to_header),
        (
            "Subject".to_string(),
            sent.subject.clone().unwrap_or_default(),
        ),
        ("Date".to_string(), date),
        (
            "Message-ID".to_string(),
            format!("<{}@fakecloud.local>", sent.message_id),
        ),
    ];
    sign_message(private_key, domain, selector, &headers, &body_text)
}

fn address_part(from: &str) -> String {
    if let (Some(open), Some(close)) = (from.find('<'), from.rfind('>')) {
        if open < close {
            return from[open + 1..close].trim().to_lowercase();
        }
    }
    from.trim().to_lowercase()
}

fn parse_private_key(pem: &str) -> Option<RsaPrivateKey> {
    RsaPrivateKey::from_pkcs8_pem(pem)
        .ok()
        .or_else(|| RsaPrivateKey::from_pkcs1_pem(pem).ok())
}

fn canonicalize_body_simple(body: &str) -> String {
    let normalized = body.replace("\r\n", "\n").replace('\r', "\n");
    let trimmed = normalized.trim_end_matches('\n');
    if trimmed.is_empty() {
        "\r\n".to_string()
    } else {
        format!("{}\r\n", trimmed.replace('\n', "\r\n"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_returns_parseable_pem_and_b64_pubkey() {
        let (pem, pub_b64) = generate_easy_dkim_keypair();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));
        assert!(parse_private_key(&pem).is_some());
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(pub_b64.as_bytes())
            .unwrap();
        assert!(!bytes.is_empty());
    }

    #[test]
    fn sign_message_emits_dkim_signature_header_value() {
        let (pem, _) = generate_easy_dkim_keypair();
        let headers = vec![
            ("From".to_string(), "alice@example.com".to_string()),
            ("To".to_string(), "bob@example.com".to_string()),
            ("Subject".to_string(), "hi".to_string()),
            (
                "Date".to_string(),
                "Mon, 01 Jan 2024 00:00:00 +0000".to_string(),
            ),
            ("Message-ID".to_string(), "<x@example.com>".to_string()),
        ];
        let sig = sign_message(&pem, "example.com", "sel1", &headers, "hello world").unwrap();
        assert!(sig.contains("v=1"));
        assert!(sig.contains("a=rsa-sha256"));
        assert!(sig.contains("d=example.com"));
        assert!(sig.contains("s=sel1"));
        assert!(sig.contains("h=from:to:subject:date:message-id"));
        assert!(sig.contains("bh="));
        assert!(sig.contains("b="));
    }

    #[test]
    fn sign_returns_none_for_garbage_pem() {
        let headers = vec![("From".to_string(), "x".to_string())];
        assert!(sign_message("not a key", "d", "s", &headers, "body").is_none());
    }

    #[test]
    fn canonicalize_body_simple_normalizes_line_endings() {
        assert_eq!(canonicalize_body_simple(""), "\r\n");
        assert_eq!(canonicalize_body_simple("a"), "a\r\n");
        assert_eq!(canonicalize_body_simple("a\nb\n\n\n"), "a\r\nb\r\n");
    }
}
