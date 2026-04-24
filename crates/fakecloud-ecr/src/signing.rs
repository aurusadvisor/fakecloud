//! Real OCI image signature verification via cosign (keyed mode).
//!
//! Cosign stores signatures as a companion manifest tagged
//! `sha256-<image-digest>.sig`. That manifest has one layer with
//! `mediaType: application/vnd.dev.cosign.simplesigning.v1+json`
//! whose blob is a JSON "simple-signing payload" that names the
//! signed image. The cosign signature (ECDSA) is attached as an
//! annotation on the layer descriptor with key
//! `dev.cosignproject.cosign/signature`, and the signed bytes are
//! the layer blob itself.
//!
//! This module supports the common case: ECDSA-P256 keys encoded as
//! PEM (PKCS8 SubjectPublicKeyInfo). No sigstore transparency log,
//! no keyless / Fulcio / Rekor — that's scoped out until fakecloud
//! grows a Rekor shim.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use p256::ecdsa::signature::Verifier;
use p256::ecdsa::{Signature, VerifyingKey};
use p256::pkcs8::DecodePublicKey;
use serde::{Deserialize, Serialize};

/// Companion tag convention: `sha256-<hex>.sig` sits in the same repo
/// as the signed image and points at a cosign simple-signing manifest.
pub fn companion_sig_tag(image_digest: &str) -> Option<String> {
    image_digest
        .strip_prefix("sha256:")
        .map(|hex| format!("sha256-{hex}.sig"))
}

/// Structured form of a trusted public key. Stored inside
/// `SigningConfiguration.trusted_keys` so `PutSigningConfiguration`
/// validates PEMs up front and `DescribeImageSigningStatus` doesn't
/// re-parse on every call.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct TrustedKey {
    pub key_id: String,
    pub pem: String,
    /// Cosmetic label for the key-usage algorithm. Only ECDSA-P256 is
    /// supported for verification today; other values are stored
    /// round-trippably but won't match a signature.
    pub algorithm: String,
}

#[derive(Debug)]
pub enum VerifyError {
    InvalidPemKey,
    SignatureDecode,
    SignatureVerify,
}

/// Verify `signature_b64` (base64 DER ECDSA signature) over `payload`
/// using `key_pem` (PEM-wrapped PKCS8 SubjectPublicKeyInfo for
/// ECDSA-P256). Matches cosign's default verification flow.
pub fn verify_cosign_signature(
    key_pem: &str,
    payload: &[u8],
    signature_b64: &str,
) -> Result<(), VerifyError> {
    let verifying_key =
        VerifyingKey::from_public_key_pem(key_pem).map_err(|_| VerifyError::InvalidPemKey)?;
    let sig_bytes = B64
        .decode(signature_b64.trim().as_bytes())
        .map_err(|_| VerifyError::SignatureDecode)?;
    let sig = Signature::from_der(&sig_bytes).map_err(|_| VerifyError::SignatureDecode)?;
    verifying_key
        .verify(payload, &sig)
        .map_err(|_| VerifyError::SignatureVerify)
}

/// Walk the layers of a cosign signature manifest and pull the
/// `dev.cosignproject.cosign/signature` annotation plus the layer
/// digest. Returns the layer whose blob is the simple-signing
/// payload.
pub fn extract_signature_annotation(manifest_json: &serde_json::Value) -> Option<(String, String)> {
    let layer = manifest_json.get("layers")?.as_array()?.first()?;
    let digest = layer.get("digest")?.as_str()?.to_string();
    let sig = layer
        .get("annotations")?
        .as_object()?
        .get("dev.cosignproject.cosign/signature")?
        .as_str()?
        .to_string();
    Some((digest, sig))
}

/// Parse cosign's simple-signing payload and pull the referenced
/// image manifest digest. Used to verify the signed payload names
/// the image we're checking.
pub fn referenced_image_digest(payload_bytes: &[u8]) -> Option<String> {
    let v: serde_json::Value = serde_json::from_slice(payload_bytes).ok()?;
    v.get("critical")?
        .get("image")?
        .get("docker-manifest-digest")?
        .as_str()
        .map(String::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;
    use p256::ecdsa::SigningKey;
    use p256::pkcs8::EncodePublicKey;

    fn keypair_pem() -> (SigningKey, String) {
        // Deterministic P-256 key — fakecloud doesn't need real
        // entropy for unit tests.
        let bytes = [7u8; 32];
        let sk = SigningKey::from_bytes((&bytes).into()).unwrap();
        let pem = sk
            .verifying_key()
            .to_public_key_pem(Default::default())
            .unwrap();
        (sk, pem)
    }

    #[test]
    fn verify_roundtrip() {
        let (sk, pem) = keypair_pem();
        let payload = br#"{"critical":{"image":{"docker-manifest-digest":"sha256:abc"}}}"#;
        let sig: Signature = sk.sign(payload);
        let sig_b64 = B64.encode(sig.to_der());
        verify_cosign_signature(&pem, payload, &sig_b64).unwrap();
    }

    #[test]
    fn wrong_payload_fails() {
        let (sk, pem) = keypair_pem();
        let payload = b"original";
        let sig: Signature = sk.sign(payload);
        let sig_b64 = B64.encode(sig.to_der());
        assert!(matches!(
            verify_cosign_signature(&pem, b"tampered", &sig_b64),
            Err(VerifyError::SignatureVerify)
        ));
    }

    #[test]
    fn malformed_pem_rejected() {
        assert!(matches!(
            verify_cosign_signature("not a pem", b"payload", "ignored"),
            Err(VerifyError::InvalidPemKey)
        ));
    }

    #[test]
    fn companion_tag_shape() {
        assert_eq!(
            companion_sig_tag("sha256:abc123"),
            Some("sha256-abc123.sig".to_string())
        );
        assert_eq!(companion_sig_tag("bare-tag"), None);
    }

    #[test]
    fn extracts_layer_annotation() {
        let m = serde_json::json!({
            "layers": [{
                "digest": "sha256:deadbeef",
                "annotations": {
                    "dev.cosignproject.cosign/signature": "sig-b64"
                }
            }]
        });
        assert_eq!(
            extract_signature_annotation(&m),
            Some(("sha256:deadbeef".into(), "sig-b64".into()))
        );
    }

    #[test]
    fn parses_payload_referenced_digest() {
        let p = br#"{"critical":{"image":{"docker-manifest-digest":"sha256:target"}}}"#;
        assert_eq!(referenced_image_digest(p).as_deref(), Some("sha256:target"));
    }
}
