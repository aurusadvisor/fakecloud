use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use chrono::Utc;
use http::StatusCode;
use serde_json::{json, Value};
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use fakecloud_aws::arn::Arn;
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
use fakecloud_core::validation::*;
use fakecloud_persistence::SnapshotStore;

use crate::state::{
    CustomKeyStore, KeyRotation, KmsAlias, KmsGrant, KmsKey, KmsSnapshot, KmsState, SharedKmsState,
    KMS_SNAPSHOT_SCHEMA_VERSION,
};

const FAKE_ENVELOPE_PREFIX: &str = "fakecloud-kms:";
const IMPORTED_ENVELOPE_PREFIX: &str = "fakecloud-imported:";

/// Result of decoding a FakeCloud KMS ciphertext blob. We carry the
/// plaintext as base64 so the two callers that care (`Decrypt` returns
/// it to the client, `ReEncrypt` re-wraps it with a new key) can both
/// hand it straight to the response builder without an extra encode.
struct DecodedCiphertext {
    source_arn: String,
    plaintext_b64: String,
}

/// Decode a FakeCloud KMS ciphertext envelope back into its plaintext.
///
/// Ciphertexts come in two flavours: `fakecloud-kms:<key-id>:<b64>`
/// stores the plaintext directly (we're a simulator, not a real KMS),
/// and `fakecloud-imported:<key-id>:<b64>` stores bytes XOR'd with
/// caller-provided imported key material which we un-XOR here. Both
/// flavours look up the source key to return its ARN, so `Decrypt`
/// and `ReEncrypt` can surface the same `KeyId` / `SourceKeyId` the
/// real service does.
fn decode_ciphertext_envelope(
    state: &KmsState,
    ciphertext_b64: &str,
) -> Result<DecodedCiphertext, AwsServiceError> {
    let ciphertext_bytes = base64::engine::general_purpose::STANDARD
        .decode(ciphertext_b64)
        .map_err(|_| invalid_ciphertext())?;

    // Modern AWS-shaped blob (AES-256-GCM under the per-account master
    // key) — try this first. Older textual envelopes fall through.
    if let Some(decoded) = crate::blob::decode(&state.master_key_bytes, &ciphertext_bytes) {
        let key = state.keys.get(&decoded.key_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "NotFoundException",
                format!("Key '{}' does not exist", decoded.key_id),
            )
        })?;
        return Ok(DecodedCiphertext {
            source_arn: key.arn.clone(),
            plaintext_b64: base64::engine::general_purpose::STANDARD.encode(&decoded.plaintext),
        });
    }

    // Legacy textual envelopes: `fakecloud-kms:<key>:<b64>` and
    // `fakecloud-imported:<key>:<xored-b64>`. Kept for back-compat with
    // ciphertexts persisted before the binary blob format shipped.
    let envelope = String::from_utf8(ciphertext_bytes).map_err(|_| invalid_ciphertext())?;

    if let Some(rest) = envelope.strip_prefix(IMPORTED_ENVELOPE_PREFIX) {
        let (key_id, xored_b64) = rest.split_once(':').ok_or_else(invalid_ciphertext)?;
        let xored_bytes = base64::engine::general_purpose::STANDARD
            .decode(xored_b64)
            .map_err(|_| invalid_ciphertext())?;

        let key = state.keys.get(key_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "NotFoundException",
                format!("Key '{key_id}' does not exist"),
            )
        })?;

        let material = key.imported_material_bytes.as_ref().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidCiphertextException",
                "Key material has been deleted",
            )
        })?;

        let plaintext_bytes: Vec<u8> = xored_bytes
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ material[i % material.len()])
            .collect();
        return Ok(DecodedCiphertext {
            source_arn: key.arn.clone(),
            plaintext_b64: base64::engine::general_purpose::STANDARD.encode(&plaintext_bytes),
        });
    }

    if let Some(rest) = envelope.strip_prefix(FAKE_ENVELOPE_PREFIX) {
        let (key_id, plaintext_b64) = rest.split_once(':').ok_or_else(invalid_ciphertext)?;
        let key = state.keys.get(key_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "NotFoundException",
                format!("Key '{key_id}' does not exist"),
            )
        })?;
        return Ok(DecodedCiphertext {
            source_arn: key.arn.clone(),
            plaintext_b64: plaintext_b64.to_string(),
        });
    }

    Err(AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "InvalidCiphertextException",
        "The ciphertext is not a valid FakeCloud KMS ciphertext",
    ))
}

fn invalid_ciphertext() -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "InvalidCiphertextException",
        "The ciphertext is invalid",
    )
}

const VALID_KEY_SPECS: &[&str] = &[
    "ECC_NIST_P256",
    "ECC_NIST_P384",
    "ECC_NIST_P521",
    "ECC_SECG_P256K1",
    "HMAC_224",
    "HMAC_256",
    "HMAC_384",
    "HMAC_512",
    "RSA_2048",
    "RSA_3072",
    "RSA_4096",
    "SM2",
    "SYMMETRIC_DEFAULT",
];

const VALID_SIGNING_ALGORITHMS: &[&str] = &[
    "RSASSA_PKCS1_V1_5_SHA_256",
    "RSASSA_PKCS1_V1_5_SHA_384",
    "RSASSA_PKCS1_V1_5_SHA_512",
    "RSASSA_PSS_SHA_256",
    "RSASSA_PSS_SHA_384",
    "RSASSA_PSS_SHA_512",
    "ECDSA_SHA_256",
    "ECDSA_SHA_384",
    "ECDSA_SHA_512",
];

/// Actions that mutate KMS state.
fn is_mutating_action(action: &str) -> bool {
    matches!(
        action,
        "CreateKey"
            | "EnableKey"
            | "DisableKey"
            | "ScheduleKeyDeletion"
            | "CancelKeyDeletion"
            | "CreateAlias"
            | "DeleteAlias"
            | "UpdateAlias"
            | "TagResource"
            | "UntagResource"
            | "UpdateKeyDescription"
            | "PutKeyPolicy"
            | "EnableKeyRotation"
            | "DisableKeyRotation"
            | "RotateKeyOnDemand"
            | "CreateGrant"
            | "RevokeGrant"
            | "RetireGrant"
            | "ReplicateKey"
            | "ImportKeyMaterial"
            | "DeleteImportedKeyMaterial"
            | "UpdatePrimaryRegion"
            | "CreateCustomKeyStore"
            | "DeleteCustomKeyStore"
            | "ConnectCustomKeyStore"
            | "DisconnectCustomKeyStore"
            | "UpdateCustomKeyStore"
    )
}

/// Single source of truth for supported KMS actions. Referenced by both
/// `supported_actions()` (used by the dispatch layer) and
/// `iam_action_for()` (used by the IAM enforcement layer).
static KMS_ACTIONS: &[&str] = &[
    "CreateKey",
    "DescribeKey",
    "ListKeys",
    "EnableKey",
    "DisableKey",
    "ScheduleKeyDeletion",
    "CancelKeyDeletion",
    "Encrypt",
    "Decrypt",
    "ReEncrypt",
    "GenerateDataKey",
    "GenerateDataKeyWithoutPlaintext",
    "GenerateRandom",
    "CreateAlias",
    "DeleteAlias",
    "UpdateAlias",
    "ListAliases",
    "TagResource",
    "UntagResource",
    "ListResourceTags",
    "UpdateKeyDescription",
    "GetKeyPolicy",
    "PutKeyPolicy",
    "ListKeyPolicies",
    "GetKeyRotationStatus",
    "EnableKeyRotation",
    "DisableKeyRotation",
    "RotateKeyOnDemand",
    "ListKeyRotations",
    "Sign",
    "Verify",
    "GetPublicKey",
    "CreateGrant",
    "ListGrants",
    "ListRetirableGrants",
    "RevokeGrant",
    "RetireGrant",
    "GenerateMac",
    "VerifyMac",
    "ReplicateKey",
    "GenerateDataKeyPair",
    "GenerateDataKeyPairWithoutPlaintext",
    "DeriveSharedSecret",
    "GetParametersForImport",
    "ImportKeyMaterial",
    "DeleteImportedKeyMaterial",
    "UpdatePrimaryRegion",
    "CreateCustomKeyStore",
    "DeleteCustomKeyStore",
    "DescribeCustomKeyStores",
    "ConnectCustomKeyStore",
    "DisconnectCustomKeyStore",
    "UpdateCustomKeyStore",
];

pub struct KmsService {
    state: SharedKmsState,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    snapshot_lock: Arc<AsyncMutex<()>>,
}

impl KmsService {
    pub fn new(state: SharedKmsState) -> Self {
        Self {
            state,
            snapshot_store: None,
            snapshot_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    pub fn with_snapshot_store(mut self, store: Arc<dyn SnapshotStore>) -> Self {
        self.snapshot_store = Some(store);
        self
    }

    /// Persist current state as a snapshot. Held across the
    /// clone-serialize-write sequence to prevent stale-last writes,
    /// with serde + file I/O offloaded to the blocking pool.
    async fn save_snapshot(&self) {
        let Some(store) = self.snapshot_store.clone() else {
            return;
        };
        let _guard = self.snapshot_lock.lock().await;
        let snapshot = KmsSnapshot {
            schema_version: KMS_SNAPSHOT_SCHEMA_VERSION,
            state: None,
            accounts: Some(self.state.read().clone()),
        };
        let join = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let bytes = serde_json::to_vec(&snapshot)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            store.save(&bytes)
        })
        .await;
        match join {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(%err, "failed to write kms snapshot"),
            Err(err) => tracing::error!(%err, "kms snapshot task panicked"),
        }
    }
}

#[async_trait]
impl AwsService for KmsService {
    fn service_name(&self) -> &str {
        "kms"
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mutates = is_mutating_action(req.action.as_str());
        let result = match req.action.as_str() {
            "CreateKey" => self.create_key(&req),
            "DescribeKey" => self.describe_key(&req),
            "ListKeys" => self.list_keys(&req),
            "EnableKey" => self.enable_key(&req),
            "DisableKey" => self.disable_key(&req),
            "ScheduleKeyDeletion" => self.schedule_key_deletion(&req),
            "CancelKeyDeletion" => self.cancel_key_deletion(&req),
            "Encrypt" => self.encrypt(&req),
            "Decrypt" => self.decrypt(&req),
            "ReEncrypt" => self.re_encrypt(&req),
            "GenerateDataKey" => self.generate_data_key(&req),
            "GenerateDataKeyWithoutPlaintext" => self.generate_data_key_without_plaintext(&req),
            "GenerateRandom" => self.generate_random(&req),
            "CreateAlias" => self.create_alias(&req),
            "DeleteAlias" => self.delete_alias(&req),
            "UpdateAlias" => self.update_alias(&req),
            "ListAliases" => self.list_aliases(&req),
            "TagResource" => self.tag_resource(&req),
            "UntagResource" => self.untag_resource(&req),
            "ListResourceTags" => self.list_resource_tags(&req),
            "UpdateKeyDescription" => self.update_key_description(&req),
            "GetKeyPolicy" => self.get_key_policy(&req),
            "PutKeyPolicy" => self.put_key_policy(&req),
            "ListKeyPolicies" => self.list_key_policies(&req),
            "GetKeyRotationStatus" => self.get_key_rotation_status(&req),
            "EnableKeyRotation" => self.enable_key_rotation(&req),
            "DisableKeyRotation" => self.disable_key_rotation(&req),
            "RotateKeyOnDemand" => self.rotate_key_on_demand(&req),
            "ListKeyRotations" => self.list_key_rotations(&req),
            "Sign" => self.sign(&req),
            "Verify" => self.verify(&req),
            "GetPublicKey" => self.get_public_key(&req),
            "CreateGrant" => self.create_grant(&req),
            "ListGrants" => self.list_grants(&req),
            "ListRetirableGrants" => self.list_retirable_grants(&req),
            "RevokeGrant" => self.revoke_grant(&req),
            "RetireGrant" => self.retire_grant(&req),
            "GenerateMac" => self.generate_mac(&req),
            "VerifyMac" => self.verify_mac(&req),
            "ReplicateKey" => self.replicate_key(&req),
            "GenerateDataKeyPair" => self.generate_data_key_pair(&req),
            "GenerateDataKeyPairWithoutPlaintext" => {
                self.generate_data_key_pair_without_plaintext(&req)
            }
            "DeriveSharedSecret" => self.derive_shared_secret(&req),
            "GetParametersForImport" => self.get_parameters_for_import(&req),
            "ImportKeyMaterial" => self.import_key_material(&req),
            "DeleteImportedKeyMaterial" => self.delete_imported_key_material(&req),
            "UpdatePrimaryRegion" => self.update_primary_region(&req),
            "CreateCustomKeyStore" => self.create_custom_key_store(&req),
            "DeleteCustomKeyStore" => self.delete_custom_key_store(&req),
            "DescribeCustomKeyStores" => self.describe_custom_key_stores(&req),
            "ConnectCustomKeyStore" => self.connect_custom_key_store(&req),
            "DisconnectCustomKeyStore" => self.disconnect_custom_key_store(&req),
            "UpdateCustomKeyStore" => self.update_custom_key_store(&req),
            _ => Err(AwsServiceError::action_not_implemented("kms", &req.action)),
        };
        if mutates && matches!(result.as_ref(), Ok(resp) if resp.status.is_success()) {
            self.save_snapshot().await;
        }
        result
    }

    fn supported_actions(&self) -> &[&str] {
        KMS_ACTIONS
    }

    fn iam_enforceable(&self) -> bool {
        true
    }

    fn iam_action_for(&self, request: &AwsRequest) -> Option<fakecloud_core::auth::IamAction> {
        let action = KMS_ACTIONS.iter().copied().find(|a| *a == request.action)?;
        let resource = kms_resource_for(action, &self.state, request);
        Some(fakecloud_core::auth::IamAction {
            service: "kms",
            action,
            resource,
        })
    }

    fn resource_tags_for(
        &self,
        resource_arn: &str,
    ) -> Option<std::collections::HashMap<String, String>> {
        if resource_arn == "*" {
            return Some(std::collections::HashMap::new());
        }
        let key_id = resource_arn.rsplit_once(":key/")?.1;
        let account_id = resource_arn.split(':').nth(4).unwrap_or("").to_string();
        let accounts = self.state.read();
        let state = accounts.get(&account_id)?;
        let key = state.keys.get(key_id)?;
        Some(
            key.tags
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        )
    }

    fn request_tags_from(
        &self,
        request: &AwsRequest,
        action: &str,
    ) -> Option<std::collections::HashMap<String, String>> {
        match action {
            "CreateKey" | "TagResource" => {
                let body = request.json_body();
                let mut tags = std::collections::HashMap::new();
                if let Some(arr) = body["Tags"].as_array() {
                    for tag in arr {
                        if let (Some(k), Some(v)) =
                            (tag["TagKey"].as_str(), tag["TagValue"].as_str())
                        {
                            tags.insert(k.to_string(), v.to_string());
                        }
                    }
                }
                Some(tags)
            }
            _ => Some(std::collections::HashMap::new()),
        }
    }
}

/// Derive the resource ARN for a KMS IAM action.
///
/// Key-targeted operations resolve their `KeyId` parameter (which may
/// be a UUID, ARN, or alias) to the key's canonical ARN. Operations
/// that don't target a specific key (CreateKey, ListKeys, etc.) use `*`.
fn kms_resource_for(action: &str, state: &SharedKmsState, request: &AwsRequest) -> String {
    // Operations that don't target a specific key.
    if matches!(
        action,
        "CreateKey"
            | "ListKeys"
            | "ListAliases"
            | "GenerateRandom"
            | "ListRetirableGrants"
            | "CreateCustomKeyStore"
            | "DeleteCustomKeyStore"
            | "DescribeCustomKeyStores"
            | "ConnectCustomKeyStore"
            | "DisconnectCustomKeyStore"
            | "UpdateCustomKeyStore"
    ) {
        return "*".to_string();
    }

    // Alias-targeted operations carry an AliasName instead of KeyId.
    if matches!(action, "CreateAlias" | "DeleteAlias" | "UpdateAlias") {
        let body = request.json_body();
        // Resolve alias -> key ARN when possible.
        if let Some(alias_name) = body["AliasName"].as_str() {
            let accts = state.read();
            let empty = KmsState::new(&request.account_id, &request.region);
            let s = accts.get(&request.account_id).unwrap_or(&empty);
            if let Some(alias) = s.aliases.get(alias_name) {
                if let Some(key) = s.keys.get(&alias.target_key_id) {
                    return key.arn.clone();
                }
            }
            // For CreateAlias the target may be in TargetKeyId.
            if let Some(target) = body["TargetKeyId"].as_str() {
                if let Some(key_id) = KmsService::resolve_key_id_with_state(s, target) {
                    if let Some(key) = s.keys.get(&key_id) {
                        return key.arn.clone();
                    }
                }
            }
        }
        return "*".to_string();
    }

    // All remaining operations carry a KeyId parameter.
    let body = request.json_body();
    if let Some(key_id_input) = body["KeyId"].as_str() {
        let accts = state.read();
        let empty = KmsState::new(&request.account_id, &request.region);
        let s = accts.get(&request.account_id).unwrap_or(&empty);
        if let Some(key_id) = KmsService::resolve_key_id_with_state(s, key_id_input) {
            if let Some(key) = s.keys.get(&key_id) {
                return key.arn.clone();
            }
        }
    }
    // Key not found or no KeyId — fall back to wildcard. The handler
    // will return NotFoundException anyway; this avoids blocking the
    // request at the IAM layer with a confusing error.
    "*".to_string()
}

fn default_key_policy(account_id: &str) -> String {
    serde_json::to_string(&json!({
        "Version": "2012-10-17",
        "Id": "key-default-1",
        "Statement": [
            {
                "Sid": "Enable IAM User Permissions",
                "Effect": "Allow",
                "Principal": {"AWS": Arn::global("iam", account_id, "root").to_string()},
                "Action": "kms:*",
                "Resource": "*",
            }
        ],
    }))
    .unwrap()
}

fn signing_algorithms_for_key_spec(key_spec: &str) -> Option<Vec<String>> {
    match key_spec {
        "RSA_2048" | "RSA_3072" | "RSA_4096" => Some(vec![
            "RSASSA_PKCS1_V1_5_SHA_256".into(),
            "RSASSA_PKCS1_V1_5_SHA_384".into(),
            "RSASSA_PKCS1_V1_5_SHA_512".into(),
            "RSASSA_PSS_SHA_256".into(),
            "RSASSA_PSS_SHA_384".into(),
            "RSASSA_PSS_SHA_512".into(),
        ]),
        "ECC_NIST_P256" | "ECC_SECG_P256K1" => Some(vec!["ECDSA_SHA_256".into()]),
        "ECC_NIST_P384" => Some(vec!["ECDSA_SHA_384".into()]),
        "ECC_NIST_P521" => Some(vec!["ECDSA_SHA_512".into()]),
        _ => None,
    }
}

/// Parsed + validated inputs for `CreateKey`.
struct CreateKeyInput {
    custom_key_store_id: Option<String>,
    description: String,
    key_usage: String,
    key_spec: String,
    origin: String,
    multi_region: bool,
    policy: Option<String>,
    tags: BTreeMap<String, String>,
}

impl CreateKeyInput {
    fn from_body(body: &Value) -> Result<Self, AwsServiceError> {
        validate_optional_string_length(
            "customKeyStoreId",
            body["CustomKeyStoreId"].as_str(),
            1,
            64,
        )?;
        validate_optional_string_length("description", body["Description"].as_str(), 0, 8192)?;
        validate_optional_enum(
            "keyUsage",
            body["KeyUsage"].as_str(),
            &[
                "SIGN_VERIFY",
                "ENCRYPT_DECRYPT",
                "GENERATE_VERIFY_MAC",
                "KEY_AGREEMENT",
            ],
        )?;
        validate_optional_enum(
            "origin",
            body["Origin"].as_str(),
            &["AWS_KMS", "EXTERNAL", "AWS_CLOUDHSM", "EXTERNAL_KEY_STORE"],
        )?;
        validate_optional_string_length("policy", body["Policy"].as_str(), 1, 131072)?;
        validate_optional_string_length("xksKeyId", body["XksKeyId"].as_str(), 1, 64)?;

        let key_spec = body["KeySpec"]
            .as_str()
            .or_else(|| body["CustomerMasterKeySpec"].as_str())
            .unwrap_or("SYMMETRIC_DEFAULT")
            .to_string();
        if !VALID_KEY_SPECS.contains(&key_spec.as_str()) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                format!(
                    "1 validation error detected: Value '{key_spec}' at 'KeySpec' failed to satisfy constraint: Member must satisfy enum value set: {}",
                    fmt_enum_set(&VALID_KEY_SPECS.iter().map(|s| s.to_string()).collect::<Vec<_>>())
                ),
            ));
        }

        let tags: BTreeMap<String, String> = body["Tags"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|t| {
                        let k = t["TagKey"].as_str()?;
                        let v = t["TagValue"].as_str()?;
                        Some((k.to_string(), v.to_string()))
                    })
                    .collect()
            })
            .unwrap_or_default();

        Ok(Self {
            custom_key_store_id: body["CustomKeyStoreId"].as_str().map(|s| s.to_string()),
            description: body["Description"].as_str().unwrap_or("").to_string(),
            key_usage: body["KeyUsage"]
                .as_str()
                .unwrap_or("ENCRYPT_DECRYPT")
                .to_string(),
            key_spec,
            origin: body["Origin"].as_str().unwrap_or("AWS_KMS").to_string(),
            multi_region: body["MultiRegion"].as_bool().unwrap_or(false),
            policy: body["Policy"].as_str().map(|s| s.to_string()),
            tags,
        })
    }
}

fn require_string_field(body: &Value, field: &str) -> Result<String, AwsServiceError> {
    body[field].as_str().map(|s| s.to_string()).ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            format!("{field} is required"),
        )
    })
}

fn validate_alias_name(alias_name: &str) -> Result<(), AwsServiceError> {
    if !alias_name.starts_with("alias/") {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "Invalid identifier",
        ));
    }
    if alias_name.starts_with("alias/aws/") {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "NotAuthorizedException",
            "",
        ));
    }
    let alias_suffix = &alias_name["alias/".len()..];
    if alias_suffix.contains(':') {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            format!("{alias_name} contains invalid characters for an alias"),
        ));
    }
    let valid_chars = alias_name
        .chars()
        .all(|c| c.is_alphanumeric() || c == '/' || c == '_' || c == '-' || c == ':');
    if !valid_chars {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            format!(
                "1 validation error detected: Value '{alias_name}' at 'aliasName' failed to satisfy constraint: Member must satisfy regular expression pattern: ^[a-zA-Z0-9:/_-]+$"
            ),
        ));
    }
    Ok(())
}

fn validate_alias_target(target_key_id: &str) -> Result<(), AwsServiceError> {
    if target_key_id.starts_with("alias/") {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "Aliases must refer to keys. Not aliases",
        ));
    }
    Ok(())
}

/// Decode + length-check an Encrypt plaintext: must be 1..=4096 bytes.
fn decode_plaintext(plaintext_b64: &str) -> Result<Vec<u8>, AwsServiceError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(plaintext_b64)
        .unwrap_or_default();
    if bytes.is_empty() {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "1 validation error detected: Value at 'plaintext' failed to satisfy constraint: Member must have length greater than or equal to 1",
        ));
    }
    if bytes.len() > 4096 {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "1 validation error detected: Value at 'plaintext' failed to satisfy constraint: Member must have length less than or equal to 4096",
        ));
    }
    Ok(bytes)
}

/// Build the base64-encoded ciphertext envelope for `Encrypt`. Two
/// shapes: when imported key material is present, XOR the plaintext
/// against the material so the ciphertext is deterministic in the
/// imported key; otherwise the fakecloud envelope just wraps the
/// original base64 plaintext under a fixed prefix.
fn build_encrypt_ciphertext(
    state: &KmsState,
    key: &KmsKey,
    plaintext_b64: &str,
    plaintext_bytes: &[u8],
) -> String {
    let _ = plaintext_b64;
    if let Some(ref material) = key.imported_material_bytes {
        // Imported key material path: legacy XOR envelope wrapped in the
        // textual `fakecloud-imported:<key>:<b64>` form, base64-encoded for
        // wire transport. This format is preserved for back-compat with
        // snapshots and external callers that may already have stored
        // ciphertexts produced before the AES-GCM blob format landed.
        let xored: Vec<u8> = plaintext_bytes
            .iter()
            .enumerate()
            .map(|(i, b)| b ^ material[i % material.len()])
            .collect();
        let xored_b64 = base64::engine::general_purpose::STANDARD.encode(&xored);
        let envelope = format!("fakecloud-imported:{}:{xored_b64}", key.key_id);
        return base64::engine::general_purpose::STANDARD.encode(envelope.as_bytes());
    }
    // Default path: AWS-shaped binary blob with AES-256-GCM under the
    // per-account master key persisted in `KmsState`. Round-trips through
    // real SDKs and does not leak plaintext to anyone inspecting the bytes.
    let blob = crate::blob::encode(&state.master_key_bytes, &key.key_id, plaintext_bytes);
    base64::engine::general_purpose::STANDARD.encode(&blob)
}

/// Reject empty/undecodable base64 for `Verify`'s Message and Signature.
fn require_non_empty_b64(field: &str, b64: &str) -> Result<(), AwsServiceError> {
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(b64)
        .unwrap_or_default();
    if bytes.is_empty() {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            format!(
                "1 validation error detected: Value at '{field}' failed to satisfy constraint: Member must have length greater than or equal to 1"
            ),
        ));
    }
    Ok(())
}

fn validate_key_usage_signing(key: &KmsKey, resolved: &str) -> Result<(), AwsServiceError> {
    if key.key_usage != "SIGN_VERIFY" {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            format!(
                "1 validation error detected: Value '{resolved}' at 'KeyId' failed to satisfy constraint: Member must point to a key with usage: 'SIGN_VERIFY'"
            ),
        ));
    }
    Ok(())
}

fn validate_signing_algorithm(
    key: &KmsKey,
    signing_algorithm: &str,
) -> Result<(), AwsServiceError> {
    let valid_algs = key.signing_algorithms.as_deref().unwrap_or(&[]);
    if !valid_algs.iter().any(|a| a == signing_algorithm) {
        let set: Vec<String> = if valid_algs.is_empty() {
            VALID_SIGNING_ALGORITHMS
                .iter()
                .map(|s| s.to_string())
                .collect()
        } else {
            valid_algs.to_vec()
        };
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            format!(
                "1 validation error detected: Value '{signing_algorithm}' at 'SigningAlgorithm' failed to satisfy constraint: Member must satisfy enum value set: {}",
                fmt_enum_set(&set)
            ),
        ));
    }
    Ok(())
}

fn encryption_algorithms_for_key(key_usage: &str, key_spec: &str) -> Option<Vec<String>> {
    if key_usage == "ENCRYPT_DECRYPT" {
        match key_spec {
            "SYMMETRIC_DEFAULT" => Some(vec!["SYMMETRIC_DEFAULT".into()]),
            "RSA_2048" | "RSA_3072" | "RSA_4096" => {
                Some(vec!["RSAES_OAEP_SHA_1".into(), "RSAES_OAEP_SHA_256".into()])
            }
            _ => None,
        }
    } else {
        None
    }
}

fn mac_algorithms_for_key_spec(key_spec: &str) -> Option<Vec<String>> {
    match key_spec {
        "HMAC_224" => Some(vec!["HMAC_SHA_224".into()]),
        "HMAC_256" => Some(vec!["HMAC_SHA_256".into()]),
        "HMAC_384" => Some(vec!["HMAC_SHA_384".into()]),
        "HMAC_512" => Some(vec!["HMAC_SHA_512".into()]),
        _ => None,
    }
}

fn rand_bytes(n: usize) -> Vec<u8> {
    (0..n)
        .map(|_| {
            let u = Uuid::new_v4();
            u.as_bytes()[0]
        })
        .collect()
}

impl KmsService {
    fn resolve_key_id_for(
        &self,
        account_id: &str,
        region: &str,
        key_id_or_arn: &str,
    ) -> Option<String> {
        let accounts = self.state.read();
        let empty = KmsState::new(account_id, region);
        let state = accounts.get(account_id).unwrap_or(&empty);
        Self::resolve_key_id_with_state(state, key_id_or_arn)
    }

    pub(crate) fn resolve_key_id_with_state(
        state: &crate::state::KmsState,
        key_id_or_arn: &str,
    ) -> Option<String> {
        // Direct key ID
        if state.keys.contains_key(key_id_or_arn) {
            return Some(key_id_or_arn.to_string());
        }

        // ARN for key
        if key_id_or_arn.starts_with("arn:aws:kms:") {
            // Could be key ARN or alias ARN
            if key_id_or_arn.contains(":key/") {
                if let Some(id) = key_id_or_arn.rsplit('/').next() {
                    if state.keys.contains_key(id) {
                        return Some(id.to_string());
                    }
                }
            }
            // alias ARN: arn:aws:kms:region:account:alias/name
            if key_id_or_arn.contains(":alias/") {
                if let Some(alias_part) = key_id_or_arn.split(':').next_back() {
                    if let Some(alias) = state.aliases.get(alias_part) {
                        return Some(alias.target_key_id.clone());
                    }
                }
            }
        }

        // Alias name
        if key_id_or_arn.starts_with("alias/") {
            if let Some(alias) = state.aliases.get(key_id_or_arn) {
                return Some(alias.target_key_id.clone());
            }
        }

        None
    }

    fn require_key_id(body: &Value) -> Result<String, AwsServiceError> {
        body["KeyId"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "KeyId is required",
                )
            })
    }

    fn resolve_required_key(
        &self,
        req: &AwsRequest,
        body: &Value,
    ) -> Result<String, AwsServiceError> {
        let key_id_input = Self::require_key_id(body)?;
        self.resolve_key_id_for(&req.account_id, &req.region, &key_id_input)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id_input}' does not exist"),
                )
            })
    }

    fn create_key(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let input = CreateKeyInput::from_body(&req.json_body())?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        let key_id = if input.multi_region {
            format!("mrk-{}", Uuid::new_v4().as_simple())
        } else {
            Uuid::new_v4().to_string()
        };

        let arn = format!(
            "arn:aws:kms:{}:{}:key/{}",
            state.region, state.account_id, key_id
        );
        let now = Utc::now().timestamp() as f64;

        let signing_algs = if input.key_usage == "SIGN_VERIFY" {
            signing_algorithms_for_key_spec(&input.key_spec)
        } else {
            None
        };
        let encryption_algs = encryption_algorithms_for_key(&input.key_usage, &input.key_spec);
        let mac_algs = if input.key_usage == "GENERATE_VERIFY_MAC" {
            mac_algorithms_for_key_spec(&input.key_spec)
        } else {
            None
        };

        let key_policy = input
            .policy
            .unwrap_or_else(|| default_key_policy(&state.account_id));

        let key = KmsKey {
            key_id: key_id.clone(),
            arn: arn.clone(),
            creation_date: now,
            description: input.description,
            enabled: true,
            key_usage: input.key_usage,
            key_spec: input.key_spec,
            key_manager: "CUSTOMER".to_string(),
            key_state: "Enabled".to_string(),
            deletion_date: None,
            tags: input.tags,
            policy: key_policy,
            key_rotation_enabled: false,
            origin: input.origin,
            multi_region: input.multi_region,
            rotations: Vec::new(),
            signing_algorithms: signing_algs,
            encryption_algorithms: encryption_algs,
            mac_algorithms: mac_algs,
            custom_key_store_id: input.custom_key_store_id,
            imported_key_material: false,
            imported_material_bytes: None,
            private_key_seed: rand_bytes(32),
            primary_region: None,
        };

        let metadata = key_metadata_json(&key, &state.account_id);
        state.keys.insert(key_id, key);

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({ "KeyMetadata": metadata })).unwrap(),
        ))
    }

    fn describe_key(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id_input = body["KeyId"].as_str().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "KeyId is required",
            )
        })?;

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);

        // Check key policy for Deny rules
        let resolved = Self::resolve_key_id_with_state(state, key_id_input).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "NotFoundException",
                format!("Key '{key_id_input}' does not exist"),
            )
        })?;

        let key = state.keys.get(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "NotFoundException",
                format!("Key '{key_id_input}' does not exist"),
            )
        })?;

        // Check policy for Deny on DescribeKey
        check_policy_deny(key, "kms:DescribeKey")?;

        let metadata = key_metadata_json(key, &state.account_id);
        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({ "KeyMetadata": metadata })).unwrap(),
        ))
    }

    fn list_keys(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();

        validate_optional_json_range("limit", &body["Limit"], 1, 1000)?;
        validate_optional_string_length("marker", body["Marker"].as_str(), 1, 320)?;

        let limit = body["Limit"].as_i64().unwrap_or(1000) as usize;
        let marker = body["Marker"].as_str();

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let all_keys: Vec<Value> = state
            .keys
            .values()
            .map(|k| {
                json!({
                    "KeyId": k.key_id,
                    "KeyArn": k.arn,
                })
            })
            .collect();

        let start = if let Some(m) = marker {
            all_keys
                .iter()
                .position(|k| k["KeyId"].as_str() == Some(m))
                .map(|pos| pos + 1)
                .unwrap_or(0)
        } else {
            0
        };

        let page = &all_keys[start..all_keys.len().min(start + limit)];
        let truncated = start + limit < all_keys.len();

        let mut result = json!({
            "Keys": page,
            "Truncated": truncated,
        });

        if truncated {
            if let Some(last) = page.last() {
                result["NextMarker"] = last["KeyId"].clone();
            }
        }

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&result).unwrap(),
        ))
    }

    fn enable_key(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let resolved = self.resolve_required_key(req, &body)?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let key = state.keys.get_mut(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;
        key.enabled = true;
        key.key_state = "Enabled".to_string();

        Ok(AwsResponse::json(StatusCode::OK, "{}"))
    }

    fn disable_key(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let resolved = self.resolve_required_key(req, &body)?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let key = state.keys.get_mut(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;
        key.enabled = false;
        key.key_state = "Disabled".to_string();

        Ok(AwsResponse::json(StatusCode::OK, "{}"))
    }

    fn schedule_key_deletion(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let resolved = self.resolve_required_key(req, &body)?;
        let pending_days = body["PendingWindowInDays"].as_i64().unwrap_or(30);

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let key = state.keys.get_mut(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;
        let deletion_date =
            Utc::now().timestamp() as f64 + (pending_days as f64 * 24.0 * 60.0 * 60.0);
        key.key_state = "PendingDeletion".to_string();
        key.enabled = false;
        key.deletion_date = Some(deletion_date);

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "KeyId": key.key_id,
                "DeletionDate": deletion_date,
                "KeyState": "PendingDeletion",
                "PendingWindowInDays": pending_days,
            }))
            .unwrap(),
        ))
    }

    fn cancel_key_deletion(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let resolved = self.resolve_required_key(req, &body)?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let key = state.keys.get_mut(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;
        key.key_state = "Disabled".to_string();
        key.deletion_date = None;

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "KeyId": key.key_id,
            }))
            .unwrap(),
        ))
    }

    fn encrypt(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;
        let plaintext_b64 = body["Plaintext"].as_str().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "Plaintext is required",
            )
        })?;
        let plaintext_bytes = decode_plaintext(plaintext_b64)?;

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let key = state.keys.get(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;
        if !key.enabled {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "DisabledException",
                format!("Key '{}' is disabled", key.arn),
            ));
        }

        let ciphertext_b64 = build_encrypt_ciphertext(state, key, plaintext_b64, &plaintext_bytes);

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "CiphertextBlob": ciphertext_b64,
                "KeyId": key.arn,
                "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
            }))
            .unwrap(),
        ))
    }

    fn decrypt(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let ciphertext_b64 = body["CiphertextBlob"].as_str().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "CiphertextBlob is required",
            )
        })?;

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let decoded = decode_ciphertext_envelope(state, ciphertext_b64)?;

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "Plaintext": decoded.plaintext_b64,
                "KeyId": decoded.source_arn,
                "EncryptionAlgorithm": "SYMMETRIC_DEFAULT",
            }))
            .unwrap(),
        ))
    }

    fn re_encrypt(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let ciphertext_b64 = body["CiphertextBlob"].as_str().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "CiphertextBlob is required",
            )
        })?;
        let dest_key_id = body["DestinationKeyId"].as_str().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "DestinationKeyId is required",
            )
        })?;

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let decoded = decode_ciphertext_envelope(state, ciphertext_b64)?;

        let dest_resolved =
            Self::resolve_key_id_with_state(state, dest_key_id).ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{dest_key_id}' does not exist"),
                )
            })?;

        let dest_key = state.keys.get(&dest_resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;

        let plaintext_bytes = base64::engine::general_purpose::STANDARD
            .decode(&decoded.plaintext_b64)
            .unwrap_or_default();
        let new_ciphertext_b64 = if let Some(ref material) = dest_key.imported_material_bytes {
            // Imported-key path: keep the legacy XOR envelope so consumers
            // that already round-trip via key material can still decrypt.
            let xored: Vec<u8> = plaintext_bytes
                .iter()
                .enumerate()
                .map(|(i, b)| b ^ material[i % material.len()])
                .collect();
            let xored_b64 = base64::engine::general_purpose::STANDARD.encode(&xored);
            let envelope = format!("fakecloud-imported:{}:{xored_b64}", dest_key.key_id);
            base64::engine::general_purpose::STANDARD.encode(envelope.as_bytes())
        } else {
            // Default path: wrap the recovered plaintext under the
            // destination key with the AWS-shaped binary blob.
            let blob =
                crate::blob::encode(&state.master_key_bytes, &dest_key.key_id, &plaintext_bytes);
            base64::engine::general_purpose::STANDARD.encode(&blob)
        };

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "CiphertextBlob": new_ciphertext_b64,
                "KeyId": dest_key.arn,
                "SourceKeyId": decoded.source_arn,
                "SourceEncryptionAlgorithm": "SYMMETRIC_DEFAULT",
                "DestinationEncryptionAlgorithm": "SYMMETRIC_DEFAULT",
            }))
            .unwrap(),
        ))
    }

    fn generate_data_key(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let key = state.keys.get(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;
        if !key.enabled {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "DisabledException",
                format!("Key '{}' is disabled", key.arn),
            ));
        }

        let num_bytes = data_key_size_from_body(&body)?;

        let data_key_bytes: Vec<u8> = rand_bytes(num_bytes);
        let plaintext_b64 = base64::engine::general_purpose::STANDARD.encode(&data_key_bytes);

        // Wrap the data key in the AWS-shaped binary blob.
        let blob = crate::blob::encode(&state.master_key_bytes, &key.key_id, &data_key_bytes);
        let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(&blob);

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "Plaintext": plaintext_b64,
                "CiphertextBlob": ciphertext_b64,
                "KeyId": key.arn,
            }))
            .unwrap(),
        ))
    }

    fn generate_data_key_without_plaintext(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let key = state.keys.get(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;
        if !key.enabled {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "DisabledException",
                format!("Key '{}' is disabled", key.arn),
            ));
        }

        let num_bytes = data_key_size_from_body(&body)?;
        let data_key_bytes: Vec<u8> = rand_bytes(num_bytes);
        let _ = base64::engine::general_purpose::STANDARD.encode(&data_key_bytes);
        let blob = crate::blob::encode(&state.master_key_bytes, &key.key_id, &data_key_bytes);
        let ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(&blob);

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "CiphertextBlob": ciphertext_b64,
                "KeyId": key.arn,
            }))
            .unwrap(),
        ))
    }

    fn generate_random(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();

        // CustomKeyStoreId is accepted for API compatibility but has no effect on
        // random number generation in this emulator.
        validate_optional_string_length(
            "customKeyStoreId",
            body["CustomKeyStoreId"].as_str(),
            1,
            64,
        )?;

        let num_bytes = body["NumberOfBytes"].as_u64().unwrap_or(32) as usize;

        validate_range_i64("numberOfBytes", num_bytes as i64, 1, 1024)?;

        let random_bytes = rand_bytes(num_bytes);
        let b64 = base64::engine::general_purpose::STANDARD.encode(&random_bytes);

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "Plaintext": b64,
            }))
            .unwrap(),
        ))
    }

    fn create_alias(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let alias_name = require_string_field(&body, "AliasName")?;
        let target_key_id = require_string_field(&body, "TargetKeyId")?;

        validate_alias_name(&alias_name)?;
        validate_alias_target(&target_key_id)?;

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &target_key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{target_key_id}' does not exist"),
                )
            })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        if state.aliases.contains_key(&alias_name) {
            let alias_arn = format!(
                "arn:aws:kms:{}:{}:{}",
                state.region, state.account_id, alias_name
            );
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "AlreadyExistsException",
                format!("An alias with the name {alias_arn} already exists"),
            ));
        }

        let alias_arn = format!(
            "arn:aws:kms:{}:{}:{}",
            state.region, state.account_id, alias_name
        );

        state.aliases.insert(
            alias_name.clone(),
            KmsAlias {
                alias_name,
                alias_arn,
                target_key_id: resolved,
                creation_date: Utc::now().timestamp() as f64,
            },
        );

        Ok(AwsResponse::json(StatusCode::OK, "{}"))
    }

    fn delete_alias(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let alias_name = body["AliasName"].as_str().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "AliasName is required",
            )
        })?;

        if !alias_name.starts_with("alias/") {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "Invalid identifier",
            ));
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if state.aliases.remove(alias_name).is_none() {
            let alias_arn = format!(
                "arn:aws:kms:{}:{}:{}",
                state.region, state.account_id, alias_name
            );
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "NotFoundException",
                format!("Alias {alias_arn} is not found."),
            ));
        }

        Ok(AwsResponse::json(StatusCode::OK, "{}"))
    }

    fn update_alias(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let alias_name = body["AliasName"].as_str().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "AliasName is required",
            )
        })?;
        let target_key_id = body["TargetKeyId"].as_str().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "TargetKeyId is required",
            )
        })?;

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, target_key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{target_key_id}' does not exist"),
                )
            })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let alias = state.aliases.get_mut(alias_name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "NotFoundException",
                format!("Alias '{alias_name}' does not exist"),
            )
        })?;

        alias.target_key_id = resolved;

        Ok(AwsResponse::json(StatusCode::OK, "{}"))
    }

    fn list_aliases(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();

        validate_optional_json_range("limit", &body["Limit"], 1, 100)?;
        validate_optional_string_length("marker", body["Marker"].as_str(), 1, 320)?;

        if !body["KeyId"].is_null() && !body["KeyId"].is_string() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "KeyId must be a string",
            ));
        }
        validate_optional_string_length("keyId", body["KeyId"].as_str(), 1, 2048)?;

        let key_id_filter = body["KeyId"].as_str();

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);

        // Resolve key_id_filter to actual key ID if needed
        let resolved_filter =
            key_id_filter.and_then(|kid| Self::resolve_key_id_with_state(state, kid));

        let aliases: Vec<Value> = state
            .aliases
            .values()
            .filter(|a| match (&resolved_filter, key_id_filter) {
                (Some(r), _) => a.target_key_id == *r,
                (None, Some(_)) => false,
                (None, None) => true,
            })
            .map(|a| {
                json!({
                    "AliasName": a.alias_name,
                    "AliasArn": a.alias_arn,
                    "TargetKeyId": a.target_key_id,
                })
            })
            .collect();

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "Aliases": aliases,
                "Truncated": false,
            }))
            .unwrap(),
        ))
    }

    fn tag_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Invalid keyId {key_id}"),
                )
            })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let key = state.keys.get_mut(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;

        fakecloud_core::tags::apply_tags(&mut key.tags, &body, "Tags", "TagKey", "TagValue")
            .map_err(|f| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    format!("{f} must be a list"),
                )
            })?;

        Ok(AwsResponse::json(StatusCode::OK, "{}"))
    }

    fn untag_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Invalid keyId {key_id}"),
                )
            })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let key = state.keys.get_mut(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;

        fakecloud_core::tags::remove_tags(&mut key.tags, &body, "TagKeys").map_err(|f| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                format!("{f} must be a list"),
            )
        })?;

        Ok(AwsResponse::json(StatusCode::OK, "{}"))
    }

    fn list_resource_tags(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Invalid keyId {key_id}"),
                )
            })?;

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let key = state.keys.get(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;
        let tags = fakecloud_core::tags::tags_to_json(&key.tags, "TagKey", "TagValue");

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "Tags": tags,
                "Truncated": false,
            }))
            .unwrap(),
        ))
    }

    fn update_key_description(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let resolved = self.resolve_required_key(req, &body)?;
        let description = body["Description"].as_str().unwrap_or("").to_string();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let key = state.keys.get_mut(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;
        key.description = description;

        Ok(AwsResponse::json(StatusCode::OK, "{}"))
    }

    fn get_key_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;

        // For key policy operations, aliases should not work
        if key_id.starts_with("alias/") {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "NotFoundException",
                format!("Invalid keyId {key_id}"),
            ));
        }

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let key = state.keys.get(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "Policy": key.policy,
            }))
            .unwrap(),
        ))
    }

    fn put_key_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;

        // For key policy operations, aliases should not work
        if key_id.starts_with("alias/") {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "NotFoundException",
                format!("Invalid keyId {key_id}"),
            ));
        }

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let policy = body["Policy"].as_str().unwrap_or("").to_string();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let key = state.keys.get_mut(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;
        key.policy = policy;

        Ok(AwsResponse::json(StatusCode::OK, "{}"))
    }

    fn list_key_policies(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let _resolved = self.resolve_required_key(req, &body)?;

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "PolicyNames": ["default"],
                "Truncated": false,
            }))
            .unwrap(),
        ))
    }

    fn get_key_rotation_status(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;

        // Aliases should fail for rotation operations
        if key_id.starts_with("alias/") {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "NotFoundException",
                format!("Invalid keyId {key_id}"),
            ));
        }

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let key = state.keys.get(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "KeyRotationEnabled": key.key_rotation_enabled,
            }))
            .unwrap(),
        ))
    }

    fn enable_key_rotation(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;

        if key_id.starts_with("alias/") {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "NotFoundException",
                format!("Invalid keyId {key_id}"),
            ));
        }

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let key = state.keys.get_mut(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;
        key.key_rotation_enabled = true;

        Ok(AwsResponse::json(StatusCode::OK, "{}"))
    }

    fn disable_key_rotation(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;

        if key_id.starts_with("alias/") {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "NotFoundException",
                format!("Invalid keyId {key_id}"),
            ));
        }

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let key = state.keys.get_mut(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;
        key.key_rotation_enabled = false;

        Ok(AwsResponse::json(StatusCode::OK, "{}"))
    }

    fn rotate_key_on_demand(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let resolved = self.resolve_required_key(req, &body)?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let key = state.keys.get_mut(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;

        let rotation = KeyRotation {
            key_id: key.key_id.clone(),
            rotation_date: Utc::now().timestamp() as f64,
            rotation_type: "ON_DEMAND".to_string(),
        };
        key.rotations.push(rotation);

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "KeyId": key.key_id,
            }))
            .unwrap(),
        ))
    }

    fn list_key_rotations(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let resolved = self.resolve_required_key(req, &body)?;
        validate_optional_json_range("limit", &body["Limit"], 1, 1000)?;
        let limit = body["Limit"].as_i64().unwrap_or(1000) as usize;
        let marker = body["Marker"].as_str();

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let key = state.keys.get(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;

        let start_index = if let Some(marker) = marker {
            marker.parse::<usize>().unwrap_or(0)
        } else {
            0
        };

        let rotations: Vec<Value> = key
            .rotations
            .iter()
            .skip(start_index)
            .take(limit)
            .map(|r| {
                json!({
                    "KeyId": r.key_id,
                    "RotationDate": r.rotation_date,
                    "RotationType": r.rotation_type,
                })
            })
            .collect();

        let total_after_start = key.rotations.len().saturating_sub(start_index);
        let truncated = total_after_start > limit;

        let mut response = json!({
            "Rotations": rotations,
            "Truncated": truncated,
        });

        if truncated {
            response["NextMarker"] = json!((start_index + limit).to_string());
        }

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&response).unwrap(),
        ))
    }

    fn sign(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;
        let message_b64 = body["Message"].as_str().unwrap_or("");
        let signing_algorithm = body["SigningAlgorithm"].as_str().unwrap_or("");

        // Validate message
        let message_bytes = base64::engine::general_purpose::STANDARD
            .decode(message_b64)
            .unwrap_or_default();

        if message_bytes.is_empty() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "1 validation error detected: Value at 'Message' failed to satisfy constraint: Member must have length greater than or equal to 1",
            ));
        }

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let key = state.keys.get(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;

        // Validate key usage
        if key.key_usage != "SIGN_VERIFY" {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                format!(
                    "1 validation error detected: Value '{}' at 'KeyId' failed to satisfy constraint: Member must point to a key with usage: 'SIGN_VERIFY'",
                    resolved
                ),
            ));
        }

        // Validate signing algorithm against key's supported algorithms
        let valid_algs = key.signing_algorithms.as_deref().unwrap_or(&[]);
        if !valid_algs.iter().any(|a| a == signing_algorithm) {
            let set: Vec<String> = if valid_algs.is_empty() {
                VALID_SIGNING_ALGORITHMS
                    .iter()
                    .map(|s| s.to_string())
                    .collect()
            } else {
                valid_algs.to_vec()
            };
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                format!(
                    "1 validation error detected: Value '{}' at 'SigningAlgorithm' failed to satisfy constraint: Member must satisfy enum value set: {}",
                    signing_algorithm, fmt_enum_set(&set)
                ),
            ));
        }

        // Generate a fake signature
        let sig_data = format!(
            "fakecloud-sig:{}:{}:{}",
            key.key_id, signing_algorithm, message_b64
        );
        let signature_b64 = base64::engine::general_purpose::STANDARD.encode(sig_data.as_bytes());

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "Signature": signature_b64,
                "SigningAlgorithm": signing_algorithm,
                "KeyId": key.arn,
            }))
            .unwrap(),
        ))
    }

    fn verify(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;
        let message_b64 = body["Message"].as_str().unwrap_or("");
        let signature_b64 = body["Signature"].as_str().unwrap_or("");
        let signing_algorithm = body["SigningAlgorithm"].as_str().unwrap_or("");

        require_non_empty_b64("Message", message_b64)?;
        require_non_empty_b64("Signature", signature_b64)?;

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let key = state.keys.get(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;

        validate_key_usage_signing(key, &resolved)?;
        validate_signing_algorithm(key, signing_algorithm)?;

        // Check if signature matches the deterministic fakecloud signature.
        let expected_sig_data = format!(
            "fakecloud-sig:{}:{}:{}",
            key.key_id, signing_algorithm, message_b64
        );
        let expected_signature_b64 =
            base64::engine::general_purpose::STANDARD.encode(expected_sig_data.as_bytes());

        let signature_valid = signature_b64 == expected_signature_b64;

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "SignatureValid": signature_valid,
                "SigningAlgorithm": signing_algorithm,
                "KeyId": key.arn,
            }))
            .unwrap(),
        ))
    }

    fn get_public_key(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let key = state.keys.get(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;

        // Generate a fake DER-encoded public key
        let fake_public_key = generate_fake_public_key(&key.key_spec);
        let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(&fake_public_key);

        let mut response = json!({
            "KeyId": key.arn,
            "KeySpec": key.key_spec,
            "KeyUsage": key.key_usage,
            "PublicKey": public_key_b64,
            "CustomerMasterKeySpec": key.key_spec,
        });

        if let Some(ref signing_algs) = key.signing_algorithms {
            response["SigningAlgorithms"] = json!(signing_algs);
        }
        if let Some(ref enc_algs) = key.encryption_algorithms {
            response["EncryptionAlgorithms"] = json!(enc_algs);
        }

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&response).unwrap(),
        ))
    }

    fn create_grant(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let grantee_principal = body["GranteePrincipal"].as_str().unwrap_or("").to_string();
        let retiring_principal = body["RetiringPrincipal"].as_str().map(|s| s.to_string());
        let operations: Vec<String> = body["Operations"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let constraints = if body["Constraints"].is_null() {
            None
        } else {
            Some(body["Constraints"].clone())
        };
        let name = body["Name"].as_str().map(|s| s.to_string());

        let grant_id = Uuid::new_v4().to_string();
        let grant_token = Uuid::new_v4().to_string();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state.grants.push(KmsGrant {
            grant_id: grant_id.clone(),
            grant_token: grant_token.clone(),
            key_id: resolved,
            grantee_principal,
            retiring_principal,
            operations,
            constraints,
            name,
            creation_date: Utc::now().timestamp() as f64,
        });

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "GrantId": grant_id,
                "GrantToken": grant_token,
            }))
            .unwrap(),
        ))
    }

    fn list_grants(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let grant_id_filter = body["GrantId"].as_str();

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let grants: Vec<Value> = state
            .grants
            .iter()
            .filter(|g| g.key_id == resolved)
            .filter(|g| {
                if let Some(gid) = grant_id_filter {
                    g.grant_id == gid
                } else {
                    true
                }
            })
            .map(|g| grant_to_json(g, &req.account_id))
            .collect();

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "Grants": grants,
                "Truncated": false,
            }))
            .unwrap(),
        ))
    }

    fn list_retirable_grants(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();

        validate_required("RetiringPrincipal", &body["RetiringPrincipal"])?;
        let retiring_principal = body["RetiringPrincipal"].as_str().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "RetiringPrincipal must be a string",
            )
        })?;
        validate_string_length("retiringPrincipal", retiring_principal, 1, 256)?;
        validate_optional_json_range("limit", &body["Limit"], 1, 1000)?;
        validate_optional_string_length("marker", body["Marker"].as_str(), 1, 320)?;

        let limit = body["Limit"].as_i64().unwrap_or(1000) as usize;
        let marker = body["Marker"].as_str();

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let all_grants: Vec<Value> = state
            .grants
            .iter()
            .filter(|g| {
                g.retiring_principal
                    .as_deref()
                    .is_some_and(|rp| rp == retiring_principal)
            })
            .map(|g| grant_to_json(g, &req.account_id))
            .collect();

        let start = if let Some(m) = marker {
            all_grants
                .iter()
                .position(|g| g["GrantId"].as_str() == Some(m))
                .map(|pos| pos + 1)
                .unwrap_or(0)
        } else {
            0
        };

        let page = &all_grants[start..all_grants.len().min(start + limit)];
        let truncated = start + limit < all_grants.len();

        let mut result = json!({
            "Grants": page,
            "Truncated": truncated,
        });

        if truncated {
            if let Some(last) = page.last() {
                result["NextMarker"] = last["GrantId"].clone();
            }
        }

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&result).unwrap(),
        ))
    }

    fn revoke_grant(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;
        let grant_id = body["GrantId"].as_str().unwrap_or("");

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let idx = state
            .grants
            .iter()
            .position(|g| g.key_id == resolved && g.grant_id == grant_id);

        match idx {
            Some(i) => {
                state.grants.remove(i);
                Ok(AwsResponse::json(StatusCode::OK, "{}"))
            }
            None => Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "NotFoundException",
                format!("Grant ID {grant_id} not found"),
            )),
        }
    }

    fn retire_grant(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let grant_token = body["GrantToken"].as_str();
        let grant_id = body["GrantId"].as_str();
        let key_id = body["KeyId"].as_str();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        let idx = if let Some(token) = grant_token {
            state.grants.iter().position(|g| g.grant_token == token)
        } else if let (Some(kid), Some(gid)) = (key_id, grant_id) {
            let resolved = Self::resolve_key_id_with_state(state, kid);
            resolved.and_then(|r| {
                state
                    .grants
                    .iter()
                    .position(|g| g.key_id == r && g.grant_id == gid)
            })
        } else {
            None
        };

        match idx {
            Some(i) => {
                state.grants.remove(i);
                Ok(AwsResponse::json(StatusCode::OK, "{}"))
            }
            None => Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "NotFoundException",
                "Grant not found",
            )),
        }
    }

    fn generate_mac(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;
        let mac_algorithm = body["MacAlgorithm"].as_str().unwrap_or("").to_string();
        let message_b64 = body["Message"].as_str().unwrap_or("");

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let key = state.keys.get(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;

        // Validate key usage
        if key.key_usage != "GENERATE_VERIFY_MAC" {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidKeyUsageException",
                format!("Key '{}' is not a GENERATE_VERIFY_MAC key", key.arn),
            ));
        }

        // Validate key spec supports MAC
        if key.mac_algorithms.is_none() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidKeyUsageException",
                format!("Key '{}' does not support MAC operations", key.arn),
            ));
        }

        // Generate fake MAC
        let mac_data = format!(
            "fakecloud-mac:{}:{}:{}",
            key.key_id, mac_algorithm, message_b64
        );
        let mac_b64 = base64::engine::general_purpose::STANDARD.encode(mac_data.as_bytes());

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "Mac": mac_b64,
                "KeyId": key.key_id,
                "MacAlgorithm": mac_algorithm,
            }))
            .unwrap(),
        ))
    }

    fn verify_mac(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;
        let mac_algorithm = body["MacAlgorithm"].as_str().unwrap_or("").to_string();
        let message_b64 = body["Message"].as_str().unwrap_or("");
        let mac_b64 = body["Mac"].as_str().unwrap_or("");

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let key = state.keys.get(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;

        // Validate key usage
        if key.key_usage != "GENERATE_VERIFY_MAC" {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidKeyUsageException",
                format!("Key '{}' is not a GENERATE_VERIFY_MAC key", key.arn),
            ));
        }

        // Check if MAC matches
        let expected_mac_data = format!(
            "fakecloud-mac:{}:{}:{}",
            key.key_id, mac_algorithm, message_b64
        );
        let expected_mac_b64 =
            base64::engine::general_purpose::STANDARD.encode(expected_mac_data.as_bytes());

        let mac_valid = mac_b64 == expected_mac_b64;

        if !mac_valid {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "KMSInvalidMacException",
                "MAC verification failed",
            ));
        }

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "KeyId": key.key_id,
                "MacAlgorithm": mac_algorithm,
                "MacValid": true,
            }))
            .unwrap(),
        ))
    }

    fn replicate_key(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;
        let replica_region = body["ReplicaRegion"].as_str().unwrap_or("").to_string();

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        // Clone the source key once and drop the borrow — the replica reuses
        // every field except the region-dependent ones.
        let source_key = state
            .keys
            .get(&resolved)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "KMSInternalException",
                    "Key state became inconsistent",
                )
            })?
            .clone();
        let account_id = state.account_id.clone();
        let source_region = state.region.clone();

        let replica_arn = format!(
            "arn:aws:kms:{}:{}:key/{}",
            replica_region, account_id, source_key.key_id
        );

        let metadata = json!({
            "KeyId": source_key.key_id,
            "Arn": replica_arn,
            "AWSAccountId": account_id,
            "CreationDate": source_key.creation_date,
            "Description": source_key.description,
            "Enabled": source_key.enabled,
            "KeyUsage": source_key.key_usage,
            "KeySpec": source_key.key_spec,
            "CustomerMasterKeySpec": source_key.key_spec,
            "KeyManager": source_key.key_manager,
            "KeyState": source_key.key_state,
            "Origin": source_key.origin,
            "MultiRegion": true,
            "MultiRegionConfiguration": {
                "MultiRegionKeyType": "REPLICA",
                "PrimaryKey": {
                    "Arn": source_key.arn,
                    "Region": source_region,
                },
                "ReplicaKeys": [],
            },
        });

        let replica_storage_key = format!("{}:{}", replica_region, source_key.key_id);
        let source_policy = source_key.policy.clone();
        let replica_key = KmsKey {
            arn: replica_arn,
            deletion_date: None,
            key_rotation_enabled: false,
            multi_region: true,
            rotations: Vec::new(),
            custom_key_store_id: None,
            imported_key_material: false,
            imported_material_bytes: None,
            private_key_seed: rand_bytes(32),
            primary_region: None,
            ..source_key
        };

        state.keys.insert(replica_storage_key, replica_key);

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "ReplicaKeyMetadata": metadata,
                "ReplicaPolicy": source_policy,
            }))
            .unwrap(),
        ))
    }

    fn generate_data_key_pair(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;
        let key_pair_spec = body["KeyPairSpec"]
            .as_str()
            .unwrap_or("RSA_2048")
            .to_string();

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let key = state.keys.get(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;
        if !key.enabled {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "DisabledException",
                format!("Key '{}' is disabled", key.arn),
            ));
        }

        let public_key_bytes = generate_fake_public_key(&key_pair_spec);
        let private_key_bytes = rand_bytes(256);
        let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(&public_key_bytes);
        let private_plaintext_b64 =
            base64::engine::general_purpose::STANDARD.encode(&private_key_bytes);

        // Wrap the private key in the AWS-shaped binary blob.
        let blob = crate::blob::encode(&state.master_key_bytes, &key.key_id, &private_key_bytes);
        let private_ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(&blob);

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "KeyId": key.arn,
                "KeyPairSpec": key_pair_spec,
                "PublicKey": public_key_b64,
                "PrivateKeyPlaintext": private_plaintext_b64,
                "PrivateKeyCiphertextBlob": private_ciphertext_b64,
            }))
            .unwrap(),
        ))
    }

    fn generate_data_key_pair_without_plaintext(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;
        let key_pair_spec = body["KeyPairSpec"]
            .as_str()
            .unwrap_or("RSA_2048")
            .to_string();

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let key = state.keys.get(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;
        if !key.enabled {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "DisabledException",
                format!("Key '{}' is disabled", key.arn),
            ));
        }

        let public_key_bytes = generate_fake_public_key(&key_pair_spec);
        let private_key_bytes = rand_bytes(256);
        let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(&public_key_bytes);

        let blob = crate::blob::encode(&state.master_key_bytes, &key.key_id, &private_key_bytes);
        let private_ciphertext_b64 = base64::engine::general_purpose::STANDARD.encode(&blob);

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "KeyId": key.arn,
                "KeyPairSpec": key_pair_spec,
                "PublicKey": public_key_b64,
                "PrivateKeyCiphertextBlob": private_ciphertext_b64,
            }))
            .unwrap(),
        ))
    }

    fn derive_shared_secret(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;
        let _key_agreement_algorithm = body["KeyAgreementAlgorithm"]
            .as_str()
            .unwrap_or("ECDH")
            .to_string();
        let _public_key = body["PublicKey"].as_str().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "PublicKey is required",
            )
        })?;

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let key = state.keys.get(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;

        if !key.enabled {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "DisabledException",
                format!("Key '{}' is disabled", key.arn),
            ));
        }

        // Key must be asymmetric (KEY_AGREEMENT usage)
        if key.key_usage != "KEY_AGREEMENT" {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidKeyUsageException",
                format!(
                    "Key '{}' usage is '{}', not KEY_AGREEMENT",
                    key.arn, key.key_usage
                ),
            ));
        }

        // Deterministic shared secret: SHA-256(private_key_seed || public_key_bytes)
        // Both parties using the correct keys will derive the same result.
        let public_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(_public_key)
            .unwrap_or_default();

        use sha2::{Digest, Sha256};
        let mut hasher = Sha256::new();
        hasher.update(&key.private_key_seed);
        hasher.update(&public_key_bytes);
        let shared_secret_bytes = hasher.finalize();
        let shared_secret_b64 =
            base64::engine::general_purpose::STANDARD.encode(shared_secret_bytes);

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "KeyId": key.arn,
                "SharedSecret": shared_secret_b64,
                "KeyAgreementAlgorithm": "ECDH",
                "KeyOrigin": key.origin,
            }))
            .unwrap(),
        ))
    }

    fn get_parameters_for_import(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let key = state.keys.get(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMSInternalException",
                "Key state became inconsistent",
            )
        })?;

        if key.origin != "EXTERNAL" {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "UnsupportedOperationException",
                format!("Key '{}' origin is '{}', not EXTERNAL", key.arn, key.origin),
            ));
        }

        let import_token_bytes = rand_bytes(64);
        let import_token_b64 =
            base64::engine::general_purpose::STANDARD.encode(&import_token_bytes);
        let public_key_bytes = generate_fake_public_key("RSA_2048");
        let public_key_b64 = base64::engine::general_purpose::STANDARD.encode(&public_key_bytes);

        // Valid for 24 hours
        let parameters_valid_to = Utc::now().timestamp() as f64 + 86400.0;

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({
                "KeyId": key.arn,
                "ImportToken": import_token_b64,
                "PublicKey": public_key_b64,
                "ParametersValidTo": parameters_valid_to,
            }))
            .unwrap(),
        ))
    }

    fn import_key_material(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;

        let _import_token = body["ImportToken"].as_str().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "ImportToken is required",
            )
        })?;

        let encrypted_key_material = body["EncryptedKeyMaterial"].as_str().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "EncryptedKeyMaterial is required",
            )
        })?;

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let key = state.keys.get_mut(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "NotFoundException",
                format!("Key '{key_id}' does not exist"),
            )
        })?;

        if key.origin != "EXTERNAL" {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "UnsupportedOperationException",
                format!("Key '{}' origin is '{}', not EXTERNAL", key.arn, key.origin),
            ));
        }

        // Store the imported material bytes for use in encrypt/decrypt.
        // In real AWS, the material is unwrapped with the import RSA key.
        // Here we treat the EncryptedKeyMaterial as the raw key (base64-decoded).
        let material_bytes = base64::engine::general_purpose::STANDARD
            .decode(encrypted_key_material)
            .map_err(|_| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "EncryptedKeyMaterial is not valid base64",
                )
            })?;
        if material_bytes.is_empty() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "EncryptedKeyMaterial must not be empty",
            ));
        }
        key.imported_key_material = true;
        key.imported_material_bytes = Some(material_bytes);
        key.enabled = true;
        key.key_state = "Enabled".to_string();

        Ok(AwsResponse::json(StatusCode::OK, "{}"))
    }

    fn delete_imported_key_material(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let key = state.keys.get_mut(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "NotFoundException",
                format!("Key '{key_id}' does not exist"),
            )
        })?;

        if key.origin != "EXTERNAL" {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "UnsupportedOperationException",
                format!("Key '{}' origin is '{}', not EXTERNAL", key.arn, key.origin),
            ));
        }

        key.imported_key_material = false;
        key.imported_material_bytes = None;
        key.enabled = false;
        key.key_state = "PendingImport".to_string();

        Ok(AwsResponse::json(StatusCode::OK, "{}"))
    }

    fn update_primary_region(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let key_id = Self::require_key_id(&body)?;
        let primary_region = body["PrimaryRegion"]
            .as_str()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "PrimaryRegion is required",
                )
            })?
            .to_string();

        let resolved = self
            .resolve_key_id_for(&req.account_id, &req.region, &key_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "NotFoundException",
                    format!("Key '{key_id}' does not exist"),
                )
            })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let account_id = state.account_id.clone();
        let key = state.keys.get_mut(&resolved).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "NotFoundException",
                format!("Key '{key_id}' does not exist"),
            )
        })?;

        if !key.multi_region {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "UnsupportedOperationException",
                format!("Key '{}' is not a multi-Region key", key.arn),
            ));
        }
        key.primary_region = Some(primary_region.clone());
        // Update the ARN to reflect the new region
        key.arn = format!(
            "arn:aws:kms:{}:{}:key/{}",
            primary_region, account_id, key.key_id
        );

        Ok(AwsResponse::json(StatusCode::OK, "{}"))
    }

    fn create_custom_key_store(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();

        let name = body["CustomKeyStoreName"]
            .as_str()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "CustomKeyStoreName is required",
                )
            })?
            .to_string();

        validate_string_length("customKeyStoreName", &name, 1, 256)?;

        let store_type = body["CustomKeyStoreType"]
            .as_str()
            .unwrap_or("AWS_CLOUDHSM")
            .to_string();

        validate_optional_enum(
            "customKeyStoreType",
            Some(store_type.as_str()),
            &["AWS_CLOUDHSM", "EXTERNAL_KEY_STORE"],
        )?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        // Name must be unique
        if state
            .custom_key_stores
            .values()
            .any(|s| s.custom_key_store_name == name)
        {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "CustomKeyStoreNameInUseException",
                format!("Custom key store name '{name}' is already in use"),
            ));
        }

        let store_id = format!("cks-{}", Uuid::new_v4().as_simple());
        let now = Utc::now().timestamp() as f64;

        let store = CustomKeyStore {
            custom_key_store_id: store_id.clone(),
            custom_key_store_name: name,
            custom_key_store_type: store_type,
            cloud_hsm_cluster_id: body["CloudHsmClusterId"].as_str().map(|s| s.to_string()),
            trust_anchor_certificate: body["TrustAnchorCertificate"]
                .as_str()
                .map(|s| s.to_string()),
            connection_state: "DISCONNECTED".to_string(),
            creation_date: now,
            xks_proxy_uri_endpoint: body["XksProxyUriEndpoint"].as_str().map(|s| s.to_string()),
            xks_proxy_uri_path: body["XksProxyUriPath"].as_str().map(|s| s.to_string()),
            xks_proxy_vpc_endpoint_service_name: body["XksProxyVpcEndpointServiceName"]
                .as_str()
                .map(|s| s.to_string()),
            xks_proxy_connectivity: body["XksProxyConnectivity"].as_str().map(|s| s.to_string()),
        };

        state.custom_key_stores.insert(store_id.clone(), store);

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&json!({ "CustomKeyStoreId": store_id })).unwrap(),
        ))
    }

    fn delete_custom_key_store(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();

        let store_id = body["CustomKeyStoreId"]
            .as_str()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "CustomKeyStoreId is required",
                )
            })?
            .to_string();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        let store = state.custom_key_stores.get(&store_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "CustomKeyStoreNotFoundException",
                format!("Custom key store '{store_id}' does not exist"),
            )
        })?;

        if store.connection_state == "CONNECTED" {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "CustomKeyStoreHasCMKsException",
                "Cannot delete a connected custom key store. Disconnect it first.",
            ));
        }

        state.custom_key_stores.remove(&store_id);

        Ok(AwsResponse::json(StatusCode::OK, "{}"))
    }

    fn describe_custom_key_stores(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        validate_optional_string_length(
            "customKeyStoreName",
            body["CustomKeyStoreName"].as_str(),
            1,
            256,
        )?;
        validate_optional_json_range("limit", &body["Limit"], 1, 1000)?;
        validate_optional_string_length("marker", body["Marker"].as_str(), 1, 1024)?;

        let filter_id = body["CustomKeyStoreId"].as_str();
        let filter_name = body["CustomKeyStoreName"].as_str();
        let limit = body["Limit"].as_i64().unwrap_or(1000) as usize;
        let marker = body["Marker"].as_str();

        let accounts = self.state.read();
        let empty = KmsState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);

        let mut stores: Vec<&CustomKeyStore> = state
            .custom_key_stores
            .values()
            .filter(|s| {
                if let Some(id) = filter_id {
                    return s.custom_key_store_id == id;
                }
                if let Some(name) = filter_name {
                    return s.custom_key_store_name == name;
                }
                true
            })
            .collect();

        stores.sort_by(|a, b| a.custom_key_store_id.cmp(&b.custom_key_store_id));

        // If filtering by ID and not found, return error
        if let Some(id) = filter_id {
            if stores.is_empty() {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "CustomKeyStoreNotFoundException",
                    format!("Custom key store '{id}' does not exist"),
                ));
            }
        }

        let start = marker
            .and_then(|m| {
                stores
                    .iter()
                    .position(|s| s.custom_key_store_id == m)
                    .map(|p| p + 1)
            })
            .unwrap_or(0);

        let page: Vec<_> = stores.iter().skip(start).take(limit).collect();
        let truncated = start + page.len() < stores.len();

        let entries: Vec<Value> = page.iter().map(|s| custom_key_store_json(s)).collect();

        let mut resp = json!({ "CustomKeyStores": entries, "Truncated": truncated });
        if truncated {
            if let Some(last) = page.last() {
                resp["NextMarker"] = json!(last.custom_key_store_id);
            }
        }

        Ok(AwsResponse::json(
            StatusCode::OK,
            serde_json::to_string(&resp).unwrap(),
        ))
    }

    fn connect_custom_key_store(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();

        let store_id = body["CustomKeyStoreId"]
            .as_str()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "CustomKeyStoreId is required",
                )
            })?
            .to_string();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        let store = state.custom_key_stores.get_mut(&store_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "CustomKeyStoreNotFoundException",
                format!("Custom key store '{store_id}' does not exist"),
            )
        })?;

        store.connection_state = "CONNECTED".to_string();

        Ok(AwsResponse::json(StatusCode::OK, "{}"))
    }

    fn disconnect_custom_key_store(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();

        let store_id = body["CustomKeyStoreId"]
            .as_str()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "CustomKeyStoreId is required",
                )
            })?
            .to_string();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        let store = state.custom_key_stores.get_mut(&store_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "CustomKeyStoreNotFoundException",
                format!("Custom key store '{store_id}' does not exist"),
            )
        })?;

        store.connection_state = "DISCONNECTED".to_string();

        Ok(AwsResponse::json(StatusCode::OK, "{}"))
    }

    fn update_custom_key_store(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();

        let store_id = body["CustomKeyStoreId"]
            .as_str()
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    "CustomKeyStoreId is required",
                )
            })?
            .to_string();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        // Check uniqueness of new name before borrowing store mutably
        if let Some(new_name) = body["NewCustomKeyStoreName"].as_str() {
            if state
                .custom_key_stores
                .values()
                .any(|s| s.custom_key_store_name == new_name && s.custom_key_store_id != store_id)
            {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "CustomKeyStoreNameInUseException",
                    format!("Custom key store name '{new_name}' is already in use"),
                ));
            }
        }

        let store = state.custom_key_stores.get_mut(&store_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "CustomKeyStoreNotFoundException",
                format!("Custom key store '{store_id}' does not exist"),
            )
        })?;

        if let Some(new_name) = body["NewCustomKeyStoreName"].as_str() {
            store.custom_key_store_name = new_name.to_string();
        }
        if let Some(v) = body["CloudHsmClusterId"].as_str() {
            store.cloud_hsm_cluster_id = Some(v.to_string());
        }
        if let Some(v) = body["KeyStorePassword"].as_str() {
            // In a real implementation this would update the password;
            // we just accept it silently.
            let _ = v;
        }
        if let Some(v) = body["XksProxyUriEndpoint"].as_str() {
            store.xks_proxy_uri_endpoint = Some(v.to_string());
        }
        if let Some(v) = body["XksProxyUriPath"].as_str() {
            store.xks_proxy_uri_path = Some(v.to_string());
        }
        if let Some(v) = body["XksProxyVpcEndpointServiceName"].as_str() {
            store.xks_proxy_vpc_endpoint_service_name = Some(v.to_string());
        }
        if let Some(v) = body["XksProxyConnectivity"].as_str() {
            store.xks_proxy_connectivity = Some(v.to_string());
        }

        Ok(AwsResponse::json(StatusCode::OK, "{}"))
    }
}

fn custom_key_store_json(store: &CustomKeyStore) -> Value {
    let mut obj = json!({
        "CustomKeyStoreId": store.custom_key_store_id,
        "CustomKeyStoreName": store.custom_key_store_name,
        "CustomKeyStoreType": store.custom_key_store_type,
        "ConnectionState": store.connection_state,
        "CreationDate": store.creation_date,
    });
    if let Some(ref v) = store.cloud_hsm_cluster_id {
        obj["CloudHsmClusterId"] = json!(v);
    }
    if let Some(ref v) = store.trust_anchor_certificate {
        obj["TrustAnchorCertificate"] = json!(v);
    }
    if let Some(ref v) = store.xks_proxy_uri_endpoint {
        obj["XksProxyConfiguration"] = json!({});
        obj["XksProxyConfiguration"]["UriEndpoint"] = json!(v);
        if let Some(ref p) = store.xks_proxy_uri_path {
            obj["XksProxyConfiguration"]["UriPath"] = json!(p);
        }
        if let Some(ref c) = store.xks_proxy_connectivity {
            obj["XksProxyConfiguration"]["Connectivity"] = json!(c);
        }
        if let Some(ref s) = store.xks_proxy_vpc_endpoint_service_name {
            obj["XksProxyConfiguration"]["VpcEndpointServiceName"] = json!(s);
        }
    }
    obj
}

fn key_metadata_json(key: &KmsKey, account_id: &str) -> Value {
    let mut meta = json!({
        "KeyId": key.key_id,
        "Arn": key.arn,
        "AWSAccountId": account_id,
        "CreationDate": key.creation_date,
        "Description": key.description,
        "Enabled": key.enabled,
        "KeyUsage": key.key_usage,
        "KeySpec": key.key_spec,
        "CustomerMasterKeySpec": key.key_spec,
        "KeyManager": key.key_manager,
        "KeyState": key.key_state,
        "Origin": key.origin,
        "MultiRegion": key.multi_region,
    });

    if let Some(ref enc_algs) = key.encryption_algorithms {
        meta["EncryptionAlgorithms"] = json!(enc_algs);
    }
    if let Some(ref sig_algs) = key.signing_algorithms {
        meta["SigningAlgorithms"] = json!(sig_algs);
    }
    if let Some(ref mac_algs) = key.mac_algorithms {
        meta["MacAlgorithms"] = json!(mac_algs);
    }
    if let Some(dd) = key.deletion_date {
        meta["DeletionDate"] = json!(dd);
    }
    if let Some(ref cks_id) = key.custom_key_store_id {
        meta["CustomKeyStoreId"] = json!(cks_id);
    }

    if key.multi_region {
        // Add MultiRegionConfiguration for primary keys
        meta["MultiRegionConfiguration"] = json!({
            "MultiRegionKeyType": "PRIMARY",
            "PrimaryKey": {
                "Arn": key.arn,
                "Region": key.arn.split(':').nth(3).unwrap_or("us-east-1"),
            },
            "ReplicaKeys": [],
        });
    }

    meta
}

fn fmt_enum_set(items: &[String]) -> String {
    let inner: Vec<String> = items.iter().map(|s| format!("'{s}'")).collect();
    format!("[{}]", inner.join(", "))
}

fn grant_to_json(grant: &KmsGrant, account_id: &str) -> Value {
    let mut v = json!({
        "KeyId": grant.key_id,
        "GrantId": grant.grant_id,
        "GranteePrincipal": grant.grantee_principal,
        "Operations": grant.operations,
        "IssuingAccount": fakecloud_aws::arn::Arn::global("iam", account_id, "root").to_string(),
        "CreationDate": grant.creation_date,
    });

    if let Some(ref rp) = grant.retiring_principal {
        v["RetiringPrincipal"] = json!(rp);
    }
    if let Some(ref c) = grant.constraints {
        v["Constraints"] = c.clone();
    }
    if let Some(ref n) = grant.name {
        v["Name"] = json!(n);
    }

    v
}

fn data_key_size_from_body(body: &Value) -> Result<usize, AwsServiceError> {
    let key_spec = body["KeySpec"].as_str();
    let number_of_bytes = body["NumberOfBytes"].as_u64();

    match (key_spec, number_of_bytes) {
        (Some(_), Some(_)) => Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "KeySpec and NumberOfBytes are mutually exclusive",
        )),
        (Some("AES_256"), None) => Ok(32),
        (Some("AES_128"), None) => Ok(16),
        (Some(spec), None) => Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            format!("1 validation error detected: Value '{spec}' at 'keySpec' failed to satisfy constraint: Member must satisfy enum value set: [AES_256, AES_128]"),
        )),
        (None, Some(n)) => {
            if n > 1024 {
                Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationException",
                    format!("1 validation error detected: Value '{n}' at 'numberOfBytes' failed to satisfy constraint: Member must have value less than or equal to 1024"),
                ))
            } else {
                Ok(n as usize)
            }
        }
        (None, None) => Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "KeySpec or NumberOfBytes is required",
        )),
    }
}

fn generate_fake_public_key(key_spec: &str) -> Vec<u8> {
    // Return a minimal but valid-looking DER-encoded SubjectPublicKeyInfo
    // This is a fake RSA 2048-bit public key structure for testing
    match key_spec {
        "RSA_2048" | "RSA_3072" | "RSA_4096" => {
            // A minimal ASN.1 DER structure for RSA public key
            let mut key = vec![
                0x30, 0x82, 0x01, 0x22, // SEQUENCE, length 290
                0x30, 0x0d, // SEQUENCE, length 13
                0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01,
                0x01, // OID rsaEncryption
                0x05, 0x00, // NULL
                0x03, 0x82, 0x01, 0x0f, // BIT STRING, length 271
                0x00, // unused bits
                0x30, 0x82, 0x01, 0x0a, // SEQUENCE, length 266
                0x02, 0x82, 0x01, 0x01, // INTEGER, length 257
            ];
            // Fake modulus (257 bytes: 0x00 + 256 bytes of random-looking data)
            key.push(0x00);
            key.extend_from_slice(&rand_bytes(256));
            // Exponent
            key.extend_from_slice(&[0x02, 0x03, 0x01, 0x00, 0x01]); // 65537
            key
        }
        "ECC_NIST_P256" | "ECC_SECG_P256K1" => {
            // Minimal EC public key for P-256
            let mut key = vec![
                0x30, 0x59, // SEQUENCE, length 89
                0x30, 0x13, // SEQUENCE, length 19
                0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID ecPublicKey
                0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07, // OID prime256v1
                0x03, 0x42, // BIT STRING, length 66
                0x00, // unused bits
                0x04, // uncompressed point
            ];
            key.extend_from_slice(&rand_bytes(64)); // x and y coordinates
            key
        }
        "ECC_NIST_P384" => {
            let mut key = vec![
                0x30, 0x76, // SEQUENCE, length 118
                0x30, 0x10, // SEQUENCE, length 16
                0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID ecPublicKey
                0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22, // OID secp384r1
                0x03, 0x62, // BIT STRING, length 98
                0x00, // unused bits
                0x04, // uncompressed point
            ];
            key.extend_from_slice(&rand_bytes(96)); // x and y coordinates
            key
        }
        "ECC_NIST_P521" => {
            let mut key = vec![
                0x30, 0x81, 0x9b, // SEQUENCE, length 155
                0x30, 0x10, // SEQUENCE, length 16
                0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01, // OID ecPublicKey
                0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x23, // OID secp521r1
                0x03, 0x81, 0x86, // BIT STRING, length 134
                0x00, // unused bits
                0x04, // uncompressed point
            ];
            key.extend_from_slice(&rand_bytes(132)); // x and y coordinates
            key
        }
        _ => rand_bytes(32),
    }
}

fn check_policy_deny(key: &KmsKey, action: &str) -> Result<(), AwsServiceError> {
    // Parse the policy and check for Deny statements
    let policy: Value = match serde_json::from_str(&key.policy) {
        Ok(v) => v,
        Err(_) => return Ok(()), // If policy can't be parsed, allow
    };

    let statements = match policy["Statement"].as_array() {
        Some(s) => s,
        None => return Ok(()),
    };

    for stmt in statements {
        let effect = stmt["Effect"].as_str().unwrap_or("");
        if !effect.eq_ignore_ascii_case("deny") {
            continue;
        }

        // Check Resource - only deny if resource is "*"
        let resource = &stmt["Resource"];
        let resource_matches = if let Some(r) = resource.as_str() {
            r == "*"
        } else if let Some(arr) = resource.as_array() {
            arr.iter().any(|r| r.as_str() == Some("*"))
        } else {
            false
        };

        if !resource_matches {
            continue;
        }

        // Check Action
        let actions = if let Some(a) = stmt["Action"].as_str() {
            vec![a.to_string()]
        } else if let Some(arr) = stmt["Action"].as_array() {
            arr.iter()
                .filter_map(|a| a.as_str().map(|s| s.to_string()))
                .collect()
        } else {
            continue;
        };

        for policy_action in &actions {
            if action_matches(policy_action, action) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "AccessDeniedException",
                    format!(
                        "User is not authorized to perform: {} on resource: {}",
                        action, key.arn
                    ),
                ));
            }
        }
    }

    Ok(())
}

fn action_matches(policy_action: &str, requested_action: &str) -> bool {
    if policy_action == "kms:*" {
        return true;
    }
    if policy_action == requested_action {
        return true;
    }
    // Wildcard matching: "kms:Describe*" matches "kms:DescribeKey"
    if let Some(prefix) = policy_action.strip_suffix('*') {
        if requested_action.starts_with(prefix) {
            return true;
        }
    }
    false
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
