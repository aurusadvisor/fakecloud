//! Real RSA-2048 keypair generation + RS256 JWT signing for User Pools.
//!
//! Each pool gets one keypair on creation; we sign every issued JWT with
//! the pool's private key and publish the public half at the pool's
//! JWKS endpoint so SDKs that verify tokens against the discovery URL
//! (the AWS-recommended path) get a real, verifiable signature.

use base64::Engine as _;
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::EncodePrivateKey;
use rsa::pkcs8::EncodePublicKey;
use rsa::sha2::Sha256;
use rsa::signature::{RandomizedSigner, SignatureEncoding};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde_json::Value;

/// Generate a fresh RSA-2048 keypair, returning the PKCS#8 PEM-encoded
/// private key (which embeds the public half).
pub fn generate_pool_signing_key() -> String {
    let mut rng = rand::thread_rng();
    // 2048 bits matches what Cognito issues today; the PKCS#8 encoding
    // round-trips through `RsaPrivateKey::from_pkcs8_pem` for sign-time
    // recovery.
    let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("RSA-2048 keygen should not fail");
    private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .expect("PKCS#8 PEM encode")
        .to_string()
}

/// Sign `header`+`payload` with `private_key_pem` using PKCS#1 v1.5 RS256
/// and return the compact-serialized JWT (`<header>.<payload>.<sig>`).
/// Falls back to an unsigned token only if the PEM fails to decode, so
/// callers always get a structurally valid three-part token.
pub(crate) fn sign_rs256(header: &Value, payload: &Value, private_key_pem: &str) -> String {
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let header_b64 = b64.encode(header.to_string().as_bytes());
    let payload_b64 = b64.encode(payload.to_string().as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");

    use rsa::pkcs8::DecodePrivateKey;
    let Ok(private_key) = RsaPrivateKey::from_pkcs8_pem(private_key_pem) else {
        // Fallback: emit a placeholder signature so the token still
        // parses; legitimately-created pools always have a valid PEM.
        let sig_b64 = b64.encode(signing_input.as_bytes());
        return format!("{header_b64}.{payload_b64}.{sig_b64}");
    };
    let signing_key = SigningKey::<Sha256>::new(private_key);
    let mut rng = rand::thread_rng();
    let signature = signing_key.sign_with_rng(&mut rng, signing_input.as_bytes());
    let sig_b64 = b64.encode(signature.to_bytes());
    format!("{header_b64}.{payload_b64}.{sig_b64}")
}

/// Render the pool's RSA public key as a single-key JWKS document
/// (`{"keys": [<jwk>]}`) with the `kid` baked in. Matches the shape the
/// AWS-published `/.well-known/jwks.json` endpoints serve. Used by the
/// JWKS HTTP endpoint (Y2) which is wired in fakecloud-server.
pub fn jwks_document(private_key_pem: &str, kid: &str) -> Value {
    use rsa::pkcs8::DecodePrivateKey;
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let Ok(private_key) = RsaPrivateKey::from_pkcs8_pem(private_key_pem) else {
        return serde_json::json!({"keys": []});
    };
    let public_key = RsaPublicKey::from(&private_key);
    let n_b64 = b64.encode(public_key.n().to_bytes_be());
    let e_b64 = b64.encode(public_key.e().to_bytes_be());
    serde_json::json!({
        "keys": [
            {
                "alg": "RS256",
                "e": e_b64,
                "kid": kid,
                "kty": "RSA",
                "n": n_b64,
                "use": "sig",
            }
        ]
    })
}

/// Verify an RS256-signed compact JWT against the public half of
/// `private_key_pem` (the pool's stored signing PEM embeds both halves).
/// Returns the decoded `(header, payload)` pair on success, or an error
/// string the caller can surface in a 401 response.
///
/// Only validates the cryptographic signature here; expiry/issuer/audience
/// are the caller's responsibility because policy varies by use case
/// (API Gateway v1 wants `iss` + `aud`/`client_id`; userinfo just wants
/// not-expired).
pub fn verify_rs256(token: &str, private_key_pem: &str) -> Result<(Value, Value), String> {
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::Verifier;

    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 3 {
        return Err("malformed JWT (expected three dot-separated parts)".to_string());
    }
    let header_bytes = b64
        .decode(parts[0])
        .map_err(|e| format!("invalid header base64url: {e}"))?;
    let payload_bytes = b64
        .decode(parts[1])
        .map_err(|e| format!("invalid payload base64url: {e}"))?;
    let sig_bytes = b64
        .decode(parts[2])
        .map_err(|e| format!("invalid signature base64url: {e}"))?;
    let header: Value =
        serde_json::from_slice(&header_bytes).map_err(|e| format!("invalid header JSON: {e}"))?;
    let payload: Value =
        serde_json::from_slice(&payload_bytes).map_err(|e| format!("invalid payload JSON: {e}"))?;

    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem)
        .map_err(|e| format!("invalid signing PEM: {e}"))?;
    let public_key = RsaPublicKey::from(&private_key);
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    let signature = Signature::try_from(sig_bytes.as_slice())
        .map_err(|e| format!("invalid signature bytes: {e}"))?;
    let signing_input = format!("{}.{}", parts[0], parts[1]);
    verifying_key
        .verify(signing_input.as_bytes(), &signature)
        .map_err(|e| format!("signature verification failed: {e}"))?;
    Ok((header, payload))
}

/// SubjectPublicKeyInfo PEM for callers that want the raw public half
/// without parsing the JWKS document.
#[allow(dead_code)]
pub(crate) fn public_key_pem(private_key_pem: &str) -> Option<String> {
    use rsa::pkcs8::DecodePrivateKey;
    let private_key = RsaPrivateKey::from_pkcs8_pem(private_key_pem).ok()?;
    let public_key = RsaPublicKey::from(&private_key);
    public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rsa::pkcs1v15::{Signature, VerifyingKey};
    use rsa::pkcs8::DecodePrivateKey;
    use rsa::signature::Verifier;

    #[test]
    fn signed_jwt_verifies_with_pool_public_key() {
        let pem = generate_pool_signing_key();
        let header = serde_json::json!({"alg": "RS256", "kid": "pool-1", "typ": "JWT"});
        let payload = serde_json::json!({"sub": "user-1"});
        let token = sign_rs256(&header, &payload, &pem);

        let parts: Vec<&str> = token.split('.').collect();
        assert_eq!(parts.len(), 3);

        let private_key = RsaPrivateKey::from_pkcs8_pem(&pem).unwrap();
        let public_key = RsaPublicKey::from(&private_key);
        let verifying_key = VerifyingKey::<Sha256>::new(public_key);

        let signing_input = format!("{}.{}", parts[0], parts[1]);
        let sig_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .decode(parts[2])
            .unwrap();
        let signature = Signature::try_from(sig_bytes.as_slice()).unwrap();
        verifying_key
            .verify(signing_input.as_bytes(), &signature)
            .expect("token must verify against pool's public key");
    }

    #[test]
    fn jwks_document_emits_n_and_e() {
        let pem = generate_pool_signing_key();
        let jwks = jwks_document(&pem, "pool-1");
        let key = &jwks["keys"][0];
        assert_eq!(key["kid"], "pool-1");
        assert_eq!(key["alg"], "RS256");
        assert_eq!(key["kty"], "RSA");
        assert!(key["n"].as_str().unwrap().len() > 100);
        assert!(!key["e"].as_str().unwrap().is_empty());
    }
}
