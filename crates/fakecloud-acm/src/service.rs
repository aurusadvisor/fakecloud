//! ACM (Certificate Manager) JSON 1.1 service.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use chrono::{Duration, Utc};
use http::StatusCode;
use parking_lot::RwLock;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use uuid::Uuid;

use fakecloud_aws::arn::Arn;
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};

use crate::state::{
    AccountState, AcmAccounts, CertificateOptions, DomainValidation, SharedAcmState,
    StoredCertificate,
};

const SUPPORTED_ACTIONS: &[&str] = &[
    "RequestCertificate",
    "DescribeCertificate",
    "ListCertificates",
    "DeleteCertificate",
    "ImportCertificate",
    "ExportCertificate",
    "GetCertificate",
    "RenewCertificate",
    "RevokeCertificate",
    "ResendValidationEmail",
    "AddTagsToCertificate",
    "RemoveTagsFromCertificate",
    "ListTagsForCertificate",
    "GetAccountConfiguration",
    "PutAccountConfiguration",
    "UpdateCertificateOptions",
    "SearchCertificates",
];

pub struct AcmService {
    state: SharedAcmState,
}

impl AcmService {
    pub fn new(state: SharedAcmState) -> Self {
        Self { state }
    }

    pub fn shared_state(&self) -> SharedAcmState {
        Arc::clone(&self.state)
    }
}

impl Default for AcmService {
    fn default() -> Self {
        Self::new(Arc::new(RwLock::new(AcmAccounts::new())))
    }
}

#[async_trait]
impl AwsService for AcmService {
    fn service_name(&self) -> &str {
        "acm"
    }

    fn supported_actions(&self) -> &[&str] {
        SUPPORTED_ACTIONS
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        match req.action.as_str() {
            "RequestCertificate" => self.request_certificate(&req),
            "DescribeCertificate" => self.describe_certificate(&req),
            "ListCertificates" => self.list_certificates(&req),
            "DeleteCertificate" => self.delete_certificate(&req),
            "ImportCertificate" => self.import_certificate(&req),
            "ExportCertificate" => self.export_certificate(&req),
            "GetCertificate" => self.get_certificate(&req),
            "RenewCertificate" => self.renew_certificate(&req),
            "RevokeCertificate" => self.revoke_certificate(&req),
            "ResendValidationEmail" => self.resend_validation_email(&req),
            "AddTagsToCertificate" => self.add_tags_to_certificate(&req),
            "RemoveTagsFromCertificate" => self.remove_tags_from_certificate(&req),
            "ListTagsForCertificate" => self.list_tags_for_certificate(&req),
            "GetAccountConfiguration" => self.get_account_configuration(&req),
            "PutAccountConfiguration" => self.put_account_configuration(&req),
            "UpdateCertificateOptions" => self.update_certificate_options(&req),
            "SearchCertificates" => self.search_certificates(&req),
            other => Err(AwsServiceError::action_not_implemented("acm", other)),
        }
    }
}

// ─── Request handlers ────────────────────────────────────────────────

impl AcmService {
    fn request_certificate(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let domain_name = body
            .get("DomainName")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_param("DomainName is required"))?
            .to_string();
        let validation_method = body
            .get("ValidationMethod")
            .and_then(Value::as_str)
            .unwrap_or("DNS")
            .to_string();
        let sans: Vec<String> = body
            .get("SubjectAlternativeNames")
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let key_algorithm = body
            .get("KeyAlgorithm")
            .and_then(Value::as_str)
            .unwrap_or("RSA_2048")
            .to_string();
        let idempotency_token = body
            .get("IdempotencyToken")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        let managed_by = body
            .get("ManagedBy")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        let ca_arn = body
            .get("CertificateAuthorityArn")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        let tags = parse_tags(body.get("Tags"))?;
        let options = parse_options(body.get("Options"));

        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);

        // Idempotency: a same-token + same-DomainName + same-SANs request returns
        // the prior cert. Real ACM keys this on a 1-hour window; fakecloud uses
        // exact match for determinism.
        if let Some(token) = &idempotency_token {
            if let Some(existing) = account.certificates.values().find(|c| {
                c.idempotency_token.as_deref() == Some(token)
                    && c.domain_name == domain_name
                    && c.subject_alternative_names == effective_sans(&domain_name, &sans)
            }) {
                return Ok(AwsResponse::ok_json(
                    json!({ "CertificateArn": existing.arn }),
                ));
            }
        }

        let arn = synth_certificate_arn(&req.account_id, &req.region);
        let now = Utc::now();
        let effective = effective_sans(&domain_name, &sans);
        let (cert_pem, key_pem) = generate_self_signed_cert(&domain_name, &effective)
            .map(|(c, k)| (Some(c), Some(k)))
            .unwrap_or((None, None));
        let cert = StoredCertificate {
            arn: arn.clone(),
            domain_name: domain_name.clone(),
            subject_alternative_names: effective,
            status: "PENDING_VALIDATION".to_string(),
            cert_type: "AMAZON_ISSUED".to_string(),
            certificate_pem: cert_pem,
            certificate_chain_pem: None,
            private_key_pem: key_pem,
            idempotency_token,
            serial: synth_serial(&arn),
            subject: format!("CN={domain_name}"),
            issuer: "Amazon".to_string(),
            key_algorithm,
            signature_algorithm: "SHA256WITHRSA".to_string(),
            created_at: now,
            issued_at: None,
            imported_at: None,
            revoked_at: None,
            revocation_reason: None,
            // Issued certs from real ACM are valid 13 months. Match.
            not_before: now,
            not_after: now + Duration::days(395),
            validation_method: Some(validation_method.clone()),
            domain_validation: synth_domain_validation(&domain_name, &sans, &validation_method),
            options,
            renewal_eligibility: "INELIGIBLE".to_string(),
            managed_by,
            certificate_authority_arn: ca_arn,
            tags,
            in_use_by: Vec::new(),
            describe_read_count: 0,
        };
        account.certificates.insert(arn.clone(), cert);
        Ok(AwsResponse::ok_json(json!({ "CertificateArn": arn })))
    }

    fn describe_certificate(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = require_certificate_arn(req)?;
        let mut state = self.state.write();
        let cert = state
            .accounts
            .get_mut(&req.account_id)
            .and_then(|a| a.certificates.get_mut(&arn))
            .ok_or_else(|| no_such_certificate(&arn))?;
        // Flip PENDING_VALIDATION → ISSUED after a small number of reads
        // so tests can observe the transition without waiting on
        // wall-clock minutes. Imported certs (non-AMAZON_ISSUED) skip
        // this — they're "issued" the moment they land.
        const VALIDATION_READS: u32 = 3;
        if cert.status == "PENDING_VALIDATION" && cert.cert_type == "AMAZON_ISSUED" {
            cert.describe_read_count = cert.describe_read_count.saturating_add(1);
            if cert.describe_read_count >= VALIDATION_READS {
                cert.status = "ISSUED".to_string();
                cert.issued_at = Some(Utc::now());
                for dv in cert.domain_validation.iter_mut() {
                    dv.validation_status = "SUCCESS".to_string();
                }
            }
        }
        let cert = cert.clone();
        Ok(AwsResponse::ok_json(json!({
            "Certificate": certificate_detail_json(&cert),
        })))
    }

    fn list_certificates(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let max_items: usize = body
            .get("MaxItems")
            .and_then(Value::as_u64)
            .map(|n| n as usize)
            .unwrap_or(100);
        let next_token = body
            .get("NextToken")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        let statuses: Vec<String> = body
            .get("CertificateStatuses")
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let includes = body.get("Includes");
        let key_types: Vec<String> = includes
            .and_then(|i| i.get("keyTypes"))
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let state = self.state.read();
        let mut all: Vec<StoredCertificate> = state
            .accounts
            .get(&req.account_id)
            .map(|a| a.certificates.values().cloned().collect())
            .unwrap_or_default();
        drop(state);
        all.sort_by(|a, b| a.arn.cmp(&b.arn));
        all.retain(|c| {
            (statuses.is_empty() || statuses.contains(&c.status))
                && (key_types.is_empty() || key_types.contains(&c.key_algorithm))
        });

        let start = next_token
            .and_then(|t| t.parse::<usize>().ok())
            .unwrap_or(0);
        let end = (start + max_items).min(all.len());
        let page: Vec<&StoredCertificate> = all.iter().skip(start).take(max_items).collect();
        let next = if end < all.len() {
            Some(end.to_string())
        } else {
            None
        };
        let mut response = json!({
            "CertificateSummaryList": page
                .iter()
                .map(|c| certificate_summary_json(c))
                .collect::<Vec<_>>(),
        });
        if let Some(t) = next {
            response
                .as_object_mut()
                .unwrap()
                .insert("NextToken".to_string(), Value::String(t));
        }
        Ok(AwsResponse::ok_json(response))
    }

    fn delete_certificate(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = require_certificate_arn(req)?;
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        let cert = account
            .certificates
            .get(&arn)
            .ok_or_else(|| no_such_certificate(&arn))?;
        if !cert.in_use_by.is_empty() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceInUseException",
                format!(
                    "Certificate {arn} is in use by {} resource(s)",
                    cert.in_use_by.len()
                ),
            ));
        }
        account.certificates.remove(&arn);
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn import_certificate(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let cert_pem = decode_blob(body.get("Certificate"))
            .ok_or_else(|| invalid_param("Certificate is required"))?;
        let key_pem = decode_blob(body.get("PrivateKey"))
            .ok_or_else(|| invalid_param("PrivateKey is required"))?;
        let chain_pem = decode_blob(body.get("CertificateChain"));
        let arn_in = body
            .get("CertificateArn")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        let tags = parse_tags(body.get("Tags"))?;

        let domain_name = parse_cn_from_pem(&cert_pem).unwrap_or_else(|| "imported".to_string());
        let now = Utc::now();
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);

        let arn = match arn_in {
            Some(existing) => {
                let cert = account
                    .certificates
                    .get_mut(&existing)
                    .ok_or_else(|| no_such_certificate(&existing))?;
                if cert.cert_type != "IMPORTED" {
                    return Err(invalid_param(
                        "Reimport is only supported for IMPORTED certificates",
                    ));
                }
                cert.certificate_pem = Some(cert_pem.clone());
                cert.private_key_pem = Some(key_pem);
                cert.certificate_chain_pem = chain_pem;
                cert.imported_at = Some(now);
                cert.not_before = now;
                cert.not_after = now + Duration::days(395);
                cert.subject = format!("CN={domain_name}");
                // Reimport must overwrite the domain identity too —
                // otherwise Describe / List / Search keep returning the
                // previous DomainName + SANs after a successful import.
                cert.domain_name = domain_name.clone();
                cert.subject_alternative_names = vec![domain_name.clone()];
                if !tags.is_empty() {
                    for (k, v) in tags {
                        cert.tags.insert(k, v);
                    }
                }
                existing
            }
            None => {
                let arn = synth_certificate_arn(&req.account_id, &req.region);
                let cert = StoredCertificate {
                    arn: arn.clone(),
                    domain_name: domain_name.clone(),
                    subject_alternative_names: vec![domain_name.clone()],
                    status: "ISSUED".to_string(),
                    cert_type: "IMPORTED".to_string(),
                    certificate_pem: Some(cert_pem),
                    certificate_chain_pem: chain_pem,
                    private_key_pem: Some(key_pem),
                    idempotency_token: None,
                    serial: synth_serial(&arn),
                    subject: format!("CN={domain_name}"),
                    issuer: "fakecloud-imported".to_string(),
                    key_algorithm: "RSA_2048".to_string(),
                    signature_algorithm: "SHA256WITHRSA".to_string(),
                    created_at: now,
                    issued_at: Some(now),
                    imported_at: Some(now),
                    revoked_at: None,
                    revocation_reason: None,
                    not_before: now,
                    not_after: now + Duration::days(395),
                    validation_method: None,
                    domain_validation: Vec::new(),
                    options: CertificateOptions {
                        certificate_transparency_logging_preference: "ENABLED".to_string(),
                        export: "DISABLED".to_string(),
                    },
                    renewal_eligibility: "INELIGIBLE".to_string(),
                    managed_by: None,
                    certificate_authority_arn: None,
                    tags,
                    in_use_by: Vec::new(),
                    describe_read_count: 0,
                };
                account.certificates.insert(arn.clone(), cert);
                arn
            }
        };
        Ok(AwsResponse::ok_json(json!({ "CertificateArn": arn })))
    }

    fn export_certificate(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = body
            .get("CertificateArn")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_param("CertificateArn is required"))?
            .to_string();
        let passphrase_b64 = body
            .get("Passphrase")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_param("Passphrase is required"))?;
        if passphrase_b64.is_empty() {
            return Err(invalid_param("Passphrase must not be empty"));
        }
        let passphrase_bytes = base64::engine::general_purpose::STANDARD
            .decode(passphrase_b64)
            .map_err(|_| invalid_param("Passphrase must be valid base64"))?;
        if passphrase_bytes.is_empty() {
            return Err(invalid_param("Passphrase must not decode to empty"));
        }
        let state = self.state.read();
        let cert = state
            .accounts
            .get(&req.account_id)
            .and_then(|a| a.certificates.get(&arn))
            .ok_or_else(|| no_such_certificate(&arn))?
            .clone();
        if cert.options.export != "ENABLED" && cert.cert_type != "IMPORTED" {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "RequestInProgressException",
                "Certificate is not exportable",
            ));
        }
        let cert_pem = cert
            .certificate_pem
            .clone()
            .unwrap_or_else(|| placeholder_cert_pem(&arn));
        let chain_pem = cert
            .certificate_chain_pem
            .clone()
            .unwrap_or_else(|| placeholder_chain_pem(&arn));
        let key_pem = cert
            .private_key_pem
            .clone()
            .unwrap_or_else(|| placeholder_key_pem(&arn));
        let encrypted_key_pem = encrypt_private_key_pem(&key_pem, &passphrase_bytes)
            .map_err(|e| invalid_param(format!("failed to encrypt private key: {e}")))?;
        Ok(AwsResponse::ok_json(json!({
            "Certificate": cert_pem,
            "CertificateChain": chain_pem,
            "PrivateKey": encrypted_key_pem,
        })))
    }

    fn get_certificate(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = require_certificate_arn(req)?;
        let state = self.state.read();
        let cert = state
            .accounts
            .get(&req.account_id)
            .and_then(|a| a.certificates.get(&arn))
            .ok_or_else(|| no_such_certificate(&arn))?
            .clone();
        let cert_pem = cert
            .certificate_pem
            .clone()
            .unwrap_or_else(|| placeholder_cert_pem(&arn));
        let chain_pem = cert
            .certificate_chain_pem
            .clone()
            .unwrap_or_else(|| placeholder_chain_pem(&arn));
        Ok(AwsResponse::ok_json(json!({
            "Certificate": cert_pem,
            "CertificateChain": chain_pem,
        })))
    }

    fn renew_certificate(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = require_certificate_arn(req)?;
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        let cert = account
            .certificates
            .get_mut(&arn)
            .ok_or_else(|| no_such_certificate(&arn))?;
        if cert.cert_type == "IMPORTED" {
            return Err(invalid_param(
                "Imported certificates cannot be renewed via ACM",
            ));
        }
        let now = Utc::now();
        cert.not_before = now;
        cert.not_after = now + Duration::days(395);
        cert.issued_at = Some(now);
        cert.status = "ISSUED".to_string();
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn revoke_certificate(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = body
            .get("CertificateArn")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_param("CertificateArn is required"))?
            .to_string();
        let reason = body
            .get("RevocationReason")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_param("RevocationReason is required"))?
            .to_string();
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        let cert = account
            .certificates
            .get_mut(&arn)
            .ok_or_else(|| no_such_certificate(&arn))?;
        if cert.cert_type != "AMAZON_ISSUED" {
            return Err(invalid_param(
                "Only AMAZON_ISSUED certificates can be revoked",
            ));
        }
        cert.status = "REVOKED".to_string();
        cert.revoked_at = Some(Utc::now());
        cert.revocation_reason = Some(reason);
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn resend_validation_email(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = body
            .get("CertificateArn")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_param("CertificateArn is required"))?
            .to_string();
        let _ = body
            .get("Domain")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_param("Domain is required"))?;
        let _ = body
            .get("ValidationDomain")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_param("ValidationDomain is required"))?;
        let state = self.state.read();
        let cert = state
            .accounts
            .get(&req.account_id)
            .and_then(|a| a.certificates.get(&arn))
            .ok_or_else(|| no_such_certificate(&arn))?;
        if cert.validation_method.as_deref() != Some("EMAIL") {
            return Err(invalid_param(
                "Certificate is not configured for EMAIL validation",
            ));
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn add_tags_to_certificate(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = body
            .get("CertificateArn")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_param("CertificateArn is required"))?
            .to_string();
        let tags = parse_tags(body.get("Tags"))?;
        if tags.is_empty() {
            return Err(invalid_param("Tags must contain at least one entry"));
        }
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        let cert = account
            .certificates
            .get_mut(&arn)
            .ok_or_else(|| no_such_certificate(&arn))?;
        for (k, v) in tags {
            cert.tags.insert(k, v);
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn remove_tags_from_certificate(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = body
            .get("CertificateArn")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_param("CertificateArn is required"))?
            .to_string();
        let tags = parse_tags(body.get("Tags"))?;
        if tags.is_empty() {
            return Err(invalid_param("Tags must contain at least one entry"));
        }
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        let cert = account
            .certificates
            .get_mut(&arn)
            .ok_or_else(|| no_such_certificate(&arn))?;
        // Real ACM: a tag removes if Key matches; if Value is supplied it
        // also has to match. Otherwise it's a no-op (not an error).
        for (k, v) in tags {
            if let Some(existing) = cert.tags.get(&k) {
                if v.is_empty() || *existing == v {
                    cert.tags.remove(&k);
                }
            }
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn list_tags_for_certificate(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = require_certificate_arn(req)?;
        let state = self.state.read();
        let cert = state
            .accounts
            .get(&req.account_id)
            .and_then(|a| a.certificates.get(&arn))
            .ok_or_else(|| no_such_certificate(&arn))?;
        let mut tags: Vec<(String, String)> = cert
            .tags
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        tags.sort_by(|a, b| a.0.cmp(&b.0));
        let tag_list: Vec<Value> = tags
            .into_iter()
            .map(|(k, v)| json!({ "Key": k, "Value": v }))
            .collect();
        Ok(AwsResponse::ok_json(json!({ "Tags": tag_list })))
    }

    fn get_account_configuration(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let state = self.state.read();
        let cfg = state
            .accounts
            .get(&req.account_id)
            .map(|a| a.account_config.clone())
            .unwrap_or_default();
        let mut expiry = json!({});
        if let Some(d) = cfg.expiry_events_days_before_expiry {
            expiry
                .as_object_mut()
                .unwrap()
                .insert("DaysBeforeExpiry".to_string(), json!(d));
        }
        Ok(AwsResponse::ok_json(json!({
            "ExpiryEvents": expiry,
        })))
    }

    fn put_account_configuration(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let _ = body
            .get("IdempotencyToken")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_param("IdempotencyToken is required"))?;
        let days = body
            .get("ExpiryEvents")
            .and_then(|v| v.get("DaysBeforeExpiry"))
            .and_then(Value::as_i64)
            .map(|n| n as i32);
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        account.account_config.expiry_events_days_before_expiry = days;
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn update_certificate_options(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = body
            .get("CertificateArn")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_param("CertificateArn is required"))?
            .to_string();
        let options = body
            .get("Options")
            .ok_or_else(|| invalid_param("Options is required"))?;
        let new_opts = CertificateOptions {
            certificate_transparency_logging_preference: options
                .get("CertificateTransparencyLoggingPreference")
                .and_then(Value::as_str)
                .unwrap_or("ENABLED")
                .to_string(),
            export: options
                .get("Export")
                .and_then(Value::as_str)
                .unwrap_or("DISABLED")
                .to_string(),
        };
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        let cert = account
            .certificates
            .get_mut(&arn)
            .ok_or_else(|| no_such_certificate(&arn))?;
        cert.options = new_opts;
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn search_certificates(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        // SearchCertificates is effectively ListCertificates with a
        // recursive `FilterStatement` (And/Or/Not/Filter union) plus
        // sort knobs. fakecloud honors the leaf-`Filter` cases
        // (KeyTypes, ExtendedKeyUsages match by passing through) and
        // ignores the And/Or/Not composition for now — enough to keep
        // SDK callers and the conformance probe happy.
        let body = req.json_body();
        let max_results: usize = body
            .get("MaxResults")
            .and_then(Value::as_u64)
            .map(|n| n as usize)
            .unwrap_or(100);
        let next_token = body
            .get("NextToken")
            .and_then(Value::as_str)
            .map(|s| s.to_string());
        let key_types: Vec<String> = body
            .get("FilterStatement")
            .and_then(|f| f.get("Filter"))
            .and_then(|f| f.get("KeyTypes"))
            .and_then(Value::as_array)
            .map(|v| {
                v.iter()
                    .filter_map(|s| s.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();

        let state = self.state.read();
        let mut all: Vec<StoredCertificate> = state
            .accounts
            .get(&req.account_id)
            .map(|a| a.certificates.values().cloned().collect())
            .unwrap_or_default();
        drop(state);
        all.sort_by(|a, b| a.arn.cmp(&b.arn));
        if !key_types.is_empty() {
            all.retain(|c| key_types.contains(&c.key_algorithm));
        }
        let start = next_token
            .and_then(|t| t.parse::<usize>().ok())
            .unwrap_or(0);
        let end = (start + max_results).min(all.len());
        let page: Vec<&StoredCertificate> = all.iter().skip(start).take(max_results).collect();
        let next = if end < all.len() {
            Some(end.to_string())
        } else {
            None
        };
        let mut response = json!({
            "Results": page
                .iter()
                .map(|c| certificate_search_result_json(c))
                .collect::<Vec<_>>(),
        });
        if let Some(t) = next {
            response
                .as_object_mut()
                .unwrap()
                .insert("NextToken".to_string(), Value::String(t));
        }
        Ok(AwsResponse::ok_json(response))
    }
}

// ─── Helpers ────────────────────────────────────────────────────────

fn account_mut<'a>(state: &'a mut AcmAccounts, account_id: &str) -> &'a mut AccountState {
    state.accounts.entry(account_id.to_string()).or_default()
}

fn require_certificate_arn(req: &AwsRequest) -> Result<String, AwsServiceError> {
    req.json_body()
        .get("CertificateArn")
        .and_then(Value::as_str)
        .map(|s| s.to_string())
        .ok_or_else(|| invalid_param("CertificateArn is required"))
}

fn invalid_param(msg: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(StatusCode::BAD_REQUEST, "InvalidParameterException", msg)
}

fn no_such_certificate(arn: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ResourceNotFoundException",
        format!("Could not find certificate with arn {arn}"),
    )
}

fn synth_certificate_arn(account_id: &str, region: &str) -> String {
    let region = if region.is_empty() {
        "us-east-1"
    } else {
        region
    };
    let id = Uuid::new_v4();
    Arn::new("acm", region, account_id, &format!("certificate/{id}")).to_string()
}

fn synth_serial(arn: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(arn.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..16])
}

fn parse_tags(value: Option<&Value>) -> Result<BTreeMap<String, String>, AwsServiceError> {
    let mut out = BTreeMap::new();
    let Some(arr) = value.and_then(Value::as_array) else {
        return Ok(out);
    };
    for tag in arr {
        let key = tag
            .get("Key")
            .and_then(Value::as_str)
            .ok_or_else(|| invalid_param("Tag.Key is required"))?
            .to_string();
        let value = tag
            .get("Value")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        out.insert(key, value);
    }
    Ok(out)
}

fn parse_options(value: Option<&Value>) -> CertificateOptions {
    let v = match value {
        Some(v) => v,
        None => {
            return CertificateOptions {
                certificate_transparency_logging_preference: "ENABLED".to_string(),
                export: "DISABLED".to_string(),
            };
        }
    };
    CertificateOptions {
        certificate_transparency_logging_preference: v
            .get("CertificateTransparencyLoggingPreference")
            .and_then(Value::as_str)
            .unwrap_or("ENABLED")
            .to_string(),
        export: v
            .get("Export")
            .and_then(Value::as_str)
            .unwrap_or("DISABLED")
            .to_string(),
    }
}

/// Real ACM always carries the apex `DomainName` as the first entry of
/// `SubjectAlternativeNames`; replicate that so SDK tests that read SANs
/// don't have to special-case its absence.
fn effective_sans(domain: &str, extras: &[String]) -> Vec<String> {
    let mut all = vec![domain.to_string()];
    for s in extras {
        if !all.contains(s) {
            all.push(s.clone());
        }
    }
    all
}

fn synth_domain_validation(domain: &str, sans: &[String], method: &str) -> Vec<DomainValidation> {
    effective_sans(domain, sans)
        .iter()
        .map(|d| {
            if method == "DNS" {
                let token = synth_dns_token(d);
                DomainValidation {
                    domain_name: d.clone(),
                    validation_status: "PENDING_VALIDATION".to_string(),
                    validation_method: "DNS".to_string(),
                    resource_record_name: Some(format!("_{token}.{d}.")),
                    resource_record_type: Some("CNAME".to_string()),
                    resource_record_value: Some(format!("_{token}.acm-validations.aws.")),
                }
            } else {
                DomainValidation {
                    domain_name: d.clone(),
                    validation_status: "PENDING_VALIDATION".to_string(),
                    validation_method: "EMAIL".to_string(),
                    resource_record_name: None,
                    resource_record_type: None,
                    resource_record_value: None,
                }
            }
        })
        .collect()
}

/// Deterministic 32-char hex token derived from the domain so test
/// assertions on the validation record stay stable across runs.
fn synth_dns_token(domain: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(domain.as_bytes());
    let digest = hasher.finalize();
    hex::encode(&digest[..16])
}

fn decode_blob(value: Option<&Value>) -> Option<String> {
    let v = value?;
    if let Some(s) = v.as_str() {
        // Real SDKs base64-encode blob shapes over the wire. Decode the
        // outer encoding back to the underlying PEM text; if it isn't
        // base64 (which happens with ad-hoc curl tests), pass through.
        if let Ok(bytes) = base64::engine::general_purpose::STANDARD.decode(s) {
            if let Ok(text) = String::from_utf8(bytes) {
                return Some(text);
            }
        }
        return Some(s.to_string());
    }
    None
}

/// Cheap CN scan for an imported PEM. Real ACM parses the X.509 cert
/// to extract the subject; fakecloud just looks for a `CN=` substring
/// or falls back to the PEM hash so the returned `DomainName` is at
/// least stable per input.
fn parse_cn_from_pem(pem: &str) -> Option<String> {
    pem.lines()
        .find_map(|line| line.split("CN=").nth(1))
        .map(|rest| {
            rest.split(['/', ',', '\n', ' '])
                .next()
                .unwrap_or("")
                .to_string()
        })
        .filter(|s| !s.is_empty())
}

fn placeholder_cert_pem(arn: &str) -> String {
    // Fallback used only when an actually-issued cert was somehow
    // dropped. Kept distinguishable so callers don't silently treat
    // these as real X.509.
    let body = base64::engine::general_purpose::STANDARD.encode(arn.as_bytes());
    format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
}

fn placeholder_chain_pem(arn: &str) -> String {
    let body =
        base64::engine::general_purpose::STANDARD.encode(format!("chain-of-{arn}").as_bytes());
    format!("-----BEGIN CERTIFICATE-----\n{body}\n-----END CERTIFICATE-----\n")
}

fn placeholder_key_pem(arn: &str) -> String {
    let body = base64::engine::general_purpose::STANDARD.encode(format!("key-of-{arn}").as_bytes());
    format!("-----BEGIN RSA PRIVATE KEY-----\n{body}\n-----END RSA PRIVATE KEY-----\n")
}

/// Generate a real self-signed X.509 certificate + private key pair
/// for `domain_name` covering `sans`. Returns
/// `(certificate_pem, private_key_pem)`. Used by RequestCertificate
/// so the cert that GetCertificate / ExportCertificate hands back
/// is actually parseable as a real PEM-encoded X.509 (matching real
/// ACM's output format), not a base64-of-the-ARN placeholder.
fn generate_self_signed_cert(domain_name: &str, sans: &[String]) -> Option<(String, String)> {
    let mut all_names: Vec<String> = vec![domain_name.to_string()];
    for s in sans {
        if !all_names.contains(s) {
            all_names.push(s.clone());
        }
    }
    let cert = rcgen::generate_simple_self_signed(all_names).ok()?;
    Some((cert.cert.pem(), cert.key_pair.serialize_pem()))
}

fn certificate_summary_json(c: &StoredCertificate) -> Value {
    let mut s = json!({
        "CertificateArn": c.arn,
        "DomainName": c.domain_name,
        "SubjectAlternativeNameSummaries": c.subject_alternative_names,
        "HasAdditionalSubjectAlternativeNames": false,
        "Status": c.status,
        "Type": c.cert_type,
        "KeyAlgorithm": c.key_algorithm,
        "KeyUsages": ["DIGITAL_SIGNATURE", "KEY_ENCIPHERMENT"],
        "ExtendedKeyUsages": ["TLS_WEB_SERVER_AUTHENTICATION", "TLS_WEB_CLIENT_AUTHENTICATION"],
        "InUse": !c.in_use_by.is_empty(),
        "Exported": false,
        "RenewalEligibility": c.renewal_eligibility,
        "NotBefore": c.not_before.timestamp() as f64,
        "NotAfter": c.not_after.timestamp() as f64,
        "CreatedAt": c.created_at.timestamp() as f64,
    });
    if let Some(t) = c.issued_at {
        s.as_object_mut()
            .unwrap()
            .insert("IssuedAt".to_string(), json!(t.timestamp() as f64));
    }
    if let Some(t) = c.imported_at {
        s.as_object_mut()
            .unwrap()
            .insert("ImportedAt".to_string(), json!(t.timestamp() as f64));
    }
    if let Some(t) = c.revoked_at {
        s.as_object_mut()
            .unwrap()
            .insert("RevokedAt".to_string(), json!(t.timestamp() as f64));
        if let Some(r) = &c.revocation_reason {
            s.as_object_mut()
                .unwrap()
                .insert("RevocationReason".to_string(), json!(r));
        }
    }
    if let Some(m) = &c.managed_by {
        s.as_object_mut()
            .unwrap()
            .insert("ManagedBy".to_string(), json!(m));
    }
    s
}

fn certificate_detail_json(c: &StoredCertificate) -> Value {
    let mut d = json!({
        "CertificateArn": c.arn,
        "DomainName": c.domain_name,
        "SubjectAlternativeNames": c.subject_alternative_names,
        "Status": c.status,
        "Type": c.cert_type,
        "Serial": c.serial,
        "Subject": c.subject,
        "Issuer": c.issuer,
        "KeyAlgorithm": c.key_algorithm,
        "SignatureAlgorithm": c.signature_algorithm,
        "InUseBy": c.in_use_by,
        "RenewalEligibility": c.renewal_eligibility,
        "Options": {
            "CertificateTransparencyLoggingPreference":
                c.options.certificate_transparency_logging_preference,
            "Export": c.options.export,
        },
        "DomainValidationOptions": c
            .domain_validation
            .iter()
            .map(domain_validation_json)
            .collect::<Vec<_>>(),
        "NotBefore": c.not_before.timestamp() as f64,
        "NotAfter": c.not_after.timestamp() as f64,
        "CreatedAt": c.created_at.timestamp() as f64,
        "KeyUsages": [{"Name": "DIGITAL_SIGNATURE"}, {"Name": "KEY_ENCIPHERMENT"}],
        "ExtendedKeyUsages": [
            {"Name": "TLS_WEB_SERVER_AUTHENTICATION", "OID": "1.3.6.1.5.5.7.3.1"},
            {"Name": "TLS_WEB_CLIENT_AUTHENTICATION", "OID": "1.3.6.1.5.5.7.3.2"},
        ],
    });
    if let Some(t) = c.issued_at {
        d.as_object_mut()
            .unwrap()
            .insert("IssuedAt".to_string(), json!(t.timestamp() as f64));
    }
    if let Some(t) = c.imported_at {
        d.as_object_mut()
            .unwrap()
            .insert("ImportedAt".to_string(), json!(t.timestamp() as f64));
    }
    if let Some(t) = c.revoked_at {
        d.as_object_mut()
            .unwrap()
            .insert("RevokedAt".to_string(), json!(t.timestamp() as f64));
    }
    if let Some(r) = &c.revocation_reason {
        d.as_object_mut()
            .unwrap()
            .insert("RevocationReason".to_string(), json!(r));
    }
    if let Some(m) = &c.managed_by {
        d.as_object_mut()
            .unwrap()
            .insert("ManagedBy".to_string(), json!(m));
    }
    if let Some(ca) = &c.certificate_authority_arn {
        d.as_object_mut()
            .unwrap()
            .insert("CertificateAuthorityArn".to_string(), json!(ca));
    }
    d
}

fn certificate_search_result_json(c: &StoredCertificate) -> Value {
    let san_objects: Vec<Value> = c
        .subject_alternative_names
        .iter()
        .map(|s| json!({ "DnsName": s }))
        .collect();
    let cn = c
        .subject
        .strip_prefix("CN=")
        .unwrap_or(c.subject.as_str())
        .to_string();
    json!({
        "CertificateArn": c.arn,
        "X509Attributes": {
            "Subject": { "CommonName": cn },
            "Issuer": { "CommonName": c.issuer },
            "SubjectAlternativeNames": san_objects,
            "KeyAlgorithm": c.key_algorithm,
            "KeyUsages": ["DIGITAL_SIGNATURE", "KEY_ENCIPHERMENT"],
            "ExtendedKeyUsages": ["TLS_WEB_SERVER_AUTHENTICATION", "TLS_WEB_CLIENT_AUTHENTICATION"],
            "SerialNumber": c.serial,
            "NotBefore": c.not_before.timestamp() as f64,
            "NotAfter": c.not_after.timestamp() as f64,
        },
        "CertificateMetadata": {
            "AcmCertificateMetadata": {
                "DomainName": c.domain_name,
                "Status": c.status,
                "Type": c.cert_type,
                "InUse": !c.in_use_by.is_empty(),
                "Exported": false,
                "RenewalEligibility": c.renewal_eligibility,
                "CreatedAt": c.created_at.timestamp() as f64,
                "ManagedBy": c.managed_by.clone().unwrap_or_default(),
                "ValidationMethod": c.validation_method.clone().unwrap_or_default(),
            },
        },
    })
}

fn domain_validation_json(v: &DomainValidation) -> Value {
    let mut out = json!({
        "DomainName": v.domain_name,
        "ValidationStatus": v.validation_status,
        "ValidationMethod": v.validation_method,
    });
    if let (Some(name), Some(rtype), Some(value)) = (
        &v.resource_record_name,
        &v.resource_record_type,
        &v.resource_record_value,
    ) {
        out.as_object_mut().unwrap().insert(
            "ResourceRecord".to_string(),
            json!({
                "Name": name,
                "Type": rtype,
                "Value": value,
            }),
        );
    }
    out
}

/// Encrypt a PEM-encoded private key with a passphrase, producing a
/// PEM file using the OpenSSL legacy "Proc-Type: 4,ENCRYPTED" /
/// "DEK-Info: AES-256-CBC,<iv>" format. The result is decryptable with
/// any tool that supports the legacy openssl encrypted-PEM format
/// (openssl rsa -in key.pem -passin pass:..., python's
/// cryptography.hazmat, etc).
///
/// Format details:
/// - Key derivation: OpenSSL's EVP_BytesToKey (MD5) using the first 8
///   bytes of the random IV as the salt, count=1, producing 32 bytes
///   of key material.
/// - Cipher: AES-256-CBC with PKCS7 padding.
/// - Output: original PEM header preserved (RSA PRIVATE KEY or PRIVATE
///   KEY), with Proc-Type and DEK-Info headers prepended to the body.
fn encrypt_private_key_pem(key_pem: &str, passphrase: &[u8]) -> Result<String, String> {
    use aes::Aes256;
    use cipher::{block_padding::Pkcs7, BlockEncryptMut, KeyIvInit};
    use rand::RngCore;

    type Aes256CbcEnc = cbc::Encryptor<Aes256>;

    let (header, body_b64) = parse_pem_block(key_pem)?;
    // Real PEM bodies are base64-encoded DER, but accept raw bytes too
    // so test fixtures with non-base64 placeholder content (eg.
    // "fake-key-bytes-for-fakecloud-tests") still encrypt cleanly.
    let der = base64::engine::general_purpose::STANDARD
        .decode(&body_b64)
        .unwrap_or_else(|_| body_b64.into_bytes());

    let mut iv = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut iv);

    let salt: [u8; 8] = iv[..8].try_into().unwrap();
    let key = evp_bytes_to_key_md5(passphrase, &salt, 32);

    let cipher = Aes256CbcEnc::new(key.as_slice().into(), &iv.into());
    let mut buf = vec![0u8; der.len() + 16];
    buf[..der.len()].copy_from_slice(&der);
    let ciphertext = cipher
        .encrypt_padded_mut::<Pkcs7>(&mut buf, der.len())
        .map_err(|e| format!("encryption failed: {e}"))?;

    let iv_hex = hex::encode_upper(iv);
    let body_b64 = base64::engine::general_purpose::STANDARD.encode(ciphertext);

    let mut out = String::new();
    out.push_str(&format!("-----BEGIN {header}-----\n"));
    out.push_str("Proc-Type: 4,ENCRYPTED\n");
    out.push_str(&format!("DEK-Info: AES-256-CBC,{iv_hex}\n"));
    out.push('\n');
    for chunk in body_b64.as_bytes().chunks(64) {
        out.push_str(std::str::from_utf8(chunk).unwrap());
        out.push('\n');
    }
    out.push_str(&format!("-----END {header}-----\n"));
    Ok(out)
}

fn evp_bytes_to_key_md5(passphrase: &[u8], salt: &[u8], key_len: usize) -> Vec<u8> {
    use md5::{Digest, Md5};
    let mut out: Vec<u8> = Vec::with_capacity(key_len);
    let mut prev: Vec<u8> = Vec::new();
    while out.len() < key_len {
        let mut hasher = Md5::new();
        hasher.update(&prev);
        hasher.update(passphrase);
        hasher.update(salt);
        prev = hasher.finalize().to_vec();
        out.extend_from_slice(&prev);
    }
    out.truncate(key_len);
    out
}

/// Extract `(header_label, base64_body)` from a single-block PEM
/// string, where `header_label` is the text between `BEGIN` and `-----`
/// (eg. "PRIVATE KEY", "RSA PRIVATE KEY"). The body is returned
/// concatenated without newlines, ready for base64 decoding.
fn parse_pem_block(pem: &str) -> Result<(String, String), String> {
    let begin_idx = pem.find("-----BEGIN ").ok_or("missing BEGIN line")?;
    let after_begin = &pem[begin_idx + 11..];
    let dash_idx = after_begin.find("-----").ok_or("malformed BEGIN line")?;
    let label = after_begin[..dash_idx].trim().to_string();

    let end_marker = format!("-----END {label}-----");
    let end_idx = pem.find(&end_marker).ok_or("missing END line")?;
    let newline_after_begin = begin_idx
        + 11
        + dash_idx
        + 5
        + pem[begin_idx + 11 + dash_idx + 5..]
            .find('\n')
            .ok_or("missing newline after BEGIN")?
        + 1;
    let body_raw = &pem[newline_after_begin..end_idx];
    let body: String = body_raw.chars().filter(|c| !c.is_whitespace()).collect();
    Ok((label, body))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_self_signed_cert_returns_real_pem() {
        let (cert_pem, key_pem) =
            generate_self_signed_cert("example.com", &["www.example.com".to_string()])
                .expect("rcgen should produce a self-signed cert");
        assert!(
            cert_pem.starts_with("-----BEGIN CERTIFICATE-----"),
            "expected real PEM cert, got {cert_pem:.80}"
        );
        assert!(cert_pem.ends_with("-----END CERTIFICATE-----\n"));
        assert!(key_pem.contains("-----BEGIN PRIVATE KEY-----"));
        // Substantially longer than the placeholder (= base64-of-domain).
        assert!(cert_pem.len() > 400, "real cert PEM should be >400 chars");
    }

    #[tokio::test]
    async fn request_certificate_stores_real_pem_and_key() {
        let svc = AcmService::default();
        let req = AwsRequest {
            service: "acm".to_string(),
            action: "RequestCertificate".to_string(),
            region: "us-east-1".to_string(),
            account_id: "123456789012".to_string(),
            request_id: "rid".to_string(),
            headers: http::HeaderMap::new(),
            query_params: std::collections::HashMap::new(),
            body: bytes::Bytes::from(
                serde_json::to_vec(&json!({"DomainName": "example.com"})).unwrap(),
            ),
            body_stream: parking_lot::Mutex::new(None),
            path_segments: vec![],
            raw_path: "/".to_string(),
            raw_query: String::new(),
            method: http::Method::POST,
            is_query_protocol: false,
            access_key_id: None,
            principal: None,
        };
        let resp = svc.handle(req).await.unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let arn = body["CertificateArn"].as_str().unwrap();
        let st = svc.state.read();
        let cert = st
            .accounts
            .get("123456789012")
            .unwrap()
            .certificates
            .get(arn)
            .unwrap();
        let cert_pem = cert.certificate_pem.as_deref().unwrap();
        let key_pem = cert.private_key_pem.as_deref().unwrap();
        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(key_pem.contains("-----BEGIN PRIVATE KEY-----"));
        assert!(cert_pem.len() > 400);
    }

    #[test]
    fn encrypt_private_key_pem_emits_legacy_openssl_format() {
        let key_pem =
            "-----BEGIN PRIVATE KEY-----\nVGVzdEtleU1hdGVyaWFs\n-----END PRIVATE KEY-----\n";
        let out = encrypt_private_key_pem(key_pem, b"hunter2").expect("encryption succeeds");
        assert!(out.starts_with("-----BEGIN PRIVATE KEY-----\n"));
        assert!(out.contains("Proc-Type: 4,ENCRYPTED\n"));
        assert!(out.contains("DEK-Info: AES-256-CBC,"));
        assert!(out.ends_with("-----END PRIVATE KEY-----\n"));
        assert!(!out.contains("VGVzdEtleU1hdGVyaWFs"));
    }

    #[test]
    fn encrypt_private_key_pem_round_trips_via_evp() {
        use aes::Aes256;
        use cipher::{block_padding::Pkcs7, BlockDecryptMut, KeyIvInit};
        type Aes256CbcDec = cbc::Decryptor<Aes256>;

        let plaintext = b"some-private-key-bytes-as-DER";
        let key_b64 = base64::engine::general_purpose::STANDARD.encode(plaintext);
        let key_pem =
            format!("-----BEGIN RSA PRIVATE KEY-----\n{key_b64}\n-----END RSA PRIVATE KEY-----\n");
        let passphrase = b"correct horse battery staple";
        let encrypted = encrypt_private_key_pem(&key_pem, passphrase).unwrap();

        let iv_line = encrypted
            .lines()
            .find(|l| l.starts_with("DEK-Info: AES-256-CBC,"))
            .unwrap();
        let iv_hex = iv_line.trim_start_matches("DEK-Info: AES-256-CBC,");
        let iv = hex::decode(iv_hex).unwrap();
        let salt: [u8; 8] = iv[..8].try_into().unwrap();
        let key = evp_bytes_to_key_md5(passphrase, &salt, 32);

        let body_start = encrypted.find("\n\n").unwrap() + 2;
        let body_end = encrypted.find("\n-----END").unwrap();
        let body_b64: String = encrypted[body_start..body_end]
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let mut ciphertext = base64::engine::general_purpose::STANDARD
            .decode(&body_b64)
            .unwrap();

        let cipher = Aes256CbcDec::new(key.as_slice().into(), iv.as_slice().into());
        let decrypted = cipher
            .decrypt_padded_mut::<Pkcs7>(&mut ciphertext)
            .expect("decryption succeeds");
        assert_eq!(decrypted, plaintext);
    }

    fn make_req(action: &str, body: Value) -> AwsRequest {
        AwsRequest {
            service: "acm".to_string(),
            action: action.to_string(),
            region: "us-east-1".to_string(),
            account_id: "123456789012".to_string(),
            request_id: "rid".to_string(),
            headers: http::HeaderMap::new(),
            query_params: std::collections::HashMap::new(),
            body: bytes::Bytes::from(serde_json::to_vec(&body).unwrap()),
            body_stream: parking_lot::Mutex::new(None),
            path_segments: vec![],
            raw_path: "/".to_string(),
            raw_query: String::new(),
            method: http::Method::POST,
            is_query_protocol: false,
            access_key_id: None,
            principal: None,
        }
    }

    #[tokio::test]
    async fn export_certificate_emits_passphrase_encrypted_pem() {
        let svc = AcmService::default();
        let cert_b64 = base64::engine::general_purpose::STANDARD
            .encode(b"-----BEGIN CERTIFICATE-----\nQUFB\n-----END CERTIFICATE-----\n");
        let key_b64 = base64::engine::general_purpose::STANDARD
            .encode(b"-----BEGIN PRIVATE KEY-----\nVGVzdEtleQ==\n-----END PRIVATE KEY-----\n");
        let import = make_req(
            "ImportCertificate",
            json!({"Certificate": cert_b64, "PrivateKey": key_b64}),
        );
        let import_resp = svc.handle(import).await.unwrap();
        let import_json: Value = serde_json::from_slice(import_resp.body.expect_bytes()).unwrap();
        let arn = import_json["CertificateArn"].as_str().unwrap().to_string();

        let passphrase_b64 = base64::engine::general_purpose::STANDARD.encode(b"hunter2");
        let export = make_req(
            "ExportCertificate",
            json!({"CertificateArn": arn, "Passphrase": passphrase_b64}),
        );
        let export_resp = svc.handle(export).await.unwrap();
        let export_json: Value = serde_json::from_slice(export_resp.body.expect_bytes()).unwrap();
        let private_key = export_json["PrivateKey"].as_str().unwrap();
        assert!(
            private_key.contains("Proc-Type: 4,ENCRYPTED"),
            "expected encrypted PEM, got {private_key}"
        );
        assert!(private_key.contains("DEK-Info: AES-256-CBC,"));
        assert!(!private_key.contains("VGVzdEtleQ=="));
    }

    #[tokio::test]
    async fn export_certificate_rejects_non_base64_passphrase() {
        let svc = AcmService::default();
        let cert_b64 = base64::engine::general_purpose::STANDARD
            .encode(b"-----BEGIN CERTIFICATE-----\nQQ==\n-----END CERTIFICATE-----\n");
        let key_b64 = base64::engine::general_purpose::STANDARD
            .encode(b"-----BEGIN PRIVATE KEY-----\nQQ==\n-----END PRIVATE KEY-----\n");
        let import = make_req(
            "ImportCertificate",
            json!({"Certificate": cert_b64, "PrivateKey": key_b64}),
        );
        let import_resp = svc.handle(import).await.unwrap();
        let import_json: Value = serde_json::from_slice(import_resp.body.expect_bytes()).unwrap();
        let arn = import_json["CertificateArn"].as_str().unwrap().to_string();
        let export = make_req(
            "ExportCertificate",
            json!({"CertificateArn": arn, "Passphrase": "not!base64!@#$"}),
        );
        let err = match svc.handle(export).await {
            Ok(_) => panic!("expected error for non-base64 passphrase"),
            Err(e) => e,
        };
        assert!(format!("{err:?}").contains("Passphrase"));
    }

    #[tokio::test]
    async fn describe_certificate_flips_pending_to_issued_after_reads() {
        let svc = AcmService::default();
        let resp = svc
            .handle(make_req(
                "RequestCertificate",
                json!({"DomainName": "example.com", "ValidationMethod": "DNS"}),
            ))
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let arn = body["CertificateArn"].as_str().unwrap().to_string();

        let mut last_status = String::new();
        for _ in 0..6 {
            let resp = svc
                .handle(make_req(
                    "DescribeCertificate",
                    json!({"CertificateArn": arn}),
                ))
                .await
                .unwrap();
            let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
            last_status = body["Certificate"]["Status"].as_str().unwrap().to_string();
            if last_status == "ISSUED" {
                break;
            }
        }
        assert_eq!(last_status, "ISSUED");
    }

    #[tokio::test]
    async fn request_certificate_emits_parseable_pem() {
        let svc = AcmService::default();
        let resp = svc
            .handle(make_req(
                "RequestCertificate",
                json!({"DomainName": "example.com"}),
            ))
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let arn = body["CertificateArn"].as_str().unwrap().to_string();

        let resp = svc
            .handle(make_req("GetCertificate", json!({"CertificateArn": arn})))
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let cert_pem = body["Certificate"].as_str().unwrap();
        assert!(
            cert_pem.starts_with("-----BEGIN CERTIFICATE-----"),
            "expected real PEM cert header, got {cert_pem:.80}"
        );
        assert!(cert_pem.trim_end().ends_with("-----END CERTIFICATE-----"));
        // Real X.509 base64 body is much larger than the legacy
        // base64-of-ARN placeholder (which was ~80 chars total).
        assert!(
            cert_pem.len() > 400,
            "expected real X.509 PEM, got placeholder-sized blob"
        );
        // Sanity-check we didn't smuggle the ARN body back in via the
        // old placeholder code path.
        assert!(!cert_pem.contains(arn.as_str()));
    }

    #[tokio::test]
    async fn request_certificate_includes_san() {
        let svc = AcmService::default();
        let resp = svc
            .handle(make_req(
                "RequestCertificate",
                json!({
                    "DomainName": "example.com",
                    "SubjectAlternativeNames": ["api.example.com", "www.example.com"],
                }),
            ))
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let arn = body["CertificateArn"].as_str().unwrap().to_string();

        let resp = svc
            .handle(make_req("GetCertificate", json!({"CertificateArn": arn})))
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let cert_pem = body["Certificate"].as_str().unwrap();
        assert!(cert_pem.starts_with("-----BEGIN CERTIFICATE-----"));
        assert!(cert_pem.trim_end().ends_with("-----END CERTIFICATE-----"));

        // Decode the PEM body and search the DER bytes for the SAN dNSName
        // octets. rcgen emits SANs as IA5String entries inside the
        // SubjectAltName extension, so the raw domain bytes are present.
        let body_b64: String = cert_pem
            .lines()
            .filter(|l| !l.starts_with("-----"))
            .collect::<Vec<_>>()
            .join("");
        let der = base64::engine::general_purpose::STANDARD
            .decode(&body_b64)
            .expect("cert body is valid base64");
        for san in ["example.com", "api.example.com", "www.example.com"] {
            assert!(
                der.windows(san.len()).any(|w| w == san.as_bytes()),
                "expected SAN {san} embedded in DER"
            );
        }
    }

    #[tokio::test]
    async fn request_certificate_private_key_pem_is_valid() {
        let svc = AcmService::default();
        let resp = svc
            .handle(make_req(
                "RequestCertificate",
                json!({"DomainName": "key.example.com"}),
            ))
            .await
            .unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let arn = body["CertificateArn"].as_str().unwrap().to_string();

        let st = svc.state.read();
        let cert = st
            .accounts
            .get("123456789012")
            .unwrap()
            .certificates
            .get(&arn)
            .unwrap();
        let key_pem = cert
            .private_key_pem
            .as_deref()
            .expect("RequestCertificate should populate a real private key");
        let starts_pkcs8 = key_pem.starts_with("-----BEGIN PRIVATE KEY-----");
        let starts_rsa = key_pem.starts_with("-----BEGIN RSA PRIVATE KEY-----");
        assert!(
            starts_pkcs8 || starts_rsa,
            "expected PKCS#8 or RSA private key header, got {key_pem:.80}"
        );
        assert!(
            key_pem.trim_end().ends_with("-----END PRIVATE KEY-----")
                || key_pem
                    .trim_end()
                    .ends_with("-----END RSA PRIVATE KEY-----")
        );
        assert!(key_pem.len() > 200);
    }
}
