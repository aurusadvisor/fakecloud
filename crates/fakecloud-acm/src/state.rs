//! In-memory state for ACM certificates.

use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

pub type SharedAcmState = Arc<RwLock<AcmAccounts>>;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AcmAccounts {
    pub accounts: HashMap<String, AccountState>,
}

impl AcmAccounts {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AccountState {
    /// Keyed by full certificate ARN.
    pub certificates: HashMap<String, StoredCertificate>,
    pub account_config: AccountConfig,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AccountConfig {
    pub expiry_events_days_before_expiry: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredCertificate {
    pub arn: String,
    pub domain_name: String,
    pub subject_alternative_names: Vec<String>,
    pub status: String,
    pub cert_type: String,
    /// Stored when present so we can round-trip it on `GetCertificate`.
    pub certificate_pem: Option<String>,
    pub certificate_chain_pem: Option<String>,
    /// Imported certs only — held in memory but never returned
    /// (matches real ACM, which never returns the private key).
    pub private_key_pem: Option<String>,
    pub idempotency_token: Option<String>,
    pub serial: String,
    pub subject: String,
    pub issuer: String,
    pub key_algorithm: String,
    pub signature_algorithm: String,
    pub created_at: DateTime<Utc>,
    pub issued_at: Option<DateTime<Utc>>,
    pub imported_at: Option<DateTime<Utc>>,
    pub revoked_at: Option<DateTime<Utc>>,
    pub revocation_reason: Option<String>,
    pub not_before: DateTime<Utc>,
    pub not_after: DateTime<Utc>,
    pub validation_method: Option<String>,
    pub domain_validation: Vec<DomainValidation>,
    pub options: CertificateOptions,
    pub renewal_eligibility: String,
    pub managed_by: Option<String>,
    pub certificate_authority_arn: Option<String>,
    pub tags: HashMap<String, String>,
    pub in_use_by: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainValidation {
    pub domain_name: String,
    pub validation_status: String,
    pub validation_method: String,
    pub resource_record_name: Option<String>,
    pub resource_record_type: Option<String>,
    pub resource_record_value: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CertificateOptions {
    pub certificate_transparency_logging_preference: String,
    pub export: String,
}
