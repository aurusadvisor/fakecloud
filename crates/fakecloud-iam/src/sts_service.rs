use std::sync::Arc;

use async_trait::async_trait;
use chrono::{DateTime, Utc};
use http::StatusCode;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
use fakecloud_core::validation::*;
use fakecloud_persistence::SnapshotStore;

use crate::persistence::{save_iam_snapshot, IamSnapshotLock};
use crate::state::{CredentialIdentity, IamState, SharedIamState, StsTempCredential};
use crate::xml_responses::{self, StsCredentials};

/// Default duration for AssumeRole and similar operations (1 hour).
const DEFAULT_ASSUME_ROLE_DURATION: i64 = 3600;

/// Default duration for GetSessionToken (12 hours).
const DEFAULT_SESSION_TOKEN_DURATION: i64 = 43200;

/// Default duration for GetFederationToken (12 hours).
const DEFAULT_FEDERATION_TOKEN_DURATION: i64 = 43200;

/// Compute an absolute expiration timestamp from an optional DurationSeconds parameter.
fn compute_expiration_at(
    req: &AwsRequest,
    default_duration: i64,
) -> Result<DateTime<Utc>, AwsServiceError> {
    let duration = if let Some(ds) = req.query_params.get("DurationSeconds") {
        ds.parse::<i64>().map_err(|_| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationError",
                format!(
                    "Value '{}' at 'durationSeconds' failed to satisfy constraint: \
                     Member must be a valid integer",
                    ds
                ),
            )
        })?
    } else {
        default_duration
    };
    Ok(Utc::now() + chrono::Duration::seconds(duration))
}

/// Format an expiration timestamp as the ISO 8601 string AWS returns.
fn format_expiration(ts: DateTime<Utc>) -> String {
    ts.format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Test-only wrapper around [`compute_expiration_at`] used by the existing
/// duration unit tests.
#[cfg(test)]
fn compute_expiration(req: &AwsRequest, default_duration: i64) -> Result<String, AwsServiceError> {
    Ok(format_expiration(compute_expiration_at(
        req,
        default_duration,
    )?))
}

pub struct StsService {
    state: SharedIamState,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    snapshot_lock: IamSnapshotLock,
}

impl StsService {
    pub fn new(state: SharedIamState) -> Self {
        Self {
            state,
            snapshot_store: None,
            snapshot_lock: crate::persistence::new_snapshot_lock(),
        }
    }

    pub fn with_snapshot_store(mut self, store: Arc<dyn SnapshotStore>) -> Self {
        self.snapshot_store = Some(store);
        self
    }

    pub fn with_snapshot_lock(mut self, lock: IamSnapshotLock) -> Self {
        self.snapshot_lock = lock;
        self
    }
}

/// STS actions that mutate IAM state (by adding new entries to
/// `sts_temp_credentials` or `credential_identities`).
fn is_mutating_action(action: &str) -> bool {
    matches!(
        action,
        "AssumeRole"
            | "AssumeRoleWithWebIdentity"
            | "AssumeRoleWithSAML"
            | "GetSessionToken"
            | "GetFederationToken"
            | "AssumeRoot"
    )
}

#[async_trait]
impl AwsService for StsService {
    fn service_name(&self) -> &str {
        "sts"
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mutates = is_mutating_action(req.action.as_str());
        let result = match req.action.as_str() {
            "GetCallerIdentity" => self.get_caller_identity(&req),
            "AssumeRole" => self.assume_role(&req),
            "AssumeRoleWithWebIdentity" => self.assume_role_with_web_identity(&req),
            "AssumeRoleWithSAML" => self.assume_role_with_saml(&req),
            "GetSessionToken" => self.get_session_token(&req),
            "GetFederationToken" => self.get_federation_token(&req),
            "GetAccessKeyInfo" => self.get_access_key_info(&req),
            "DecodeAuthorizationMessage" => self.decode_authorization_message(&req),
            "AssumeRoot" => self.assume_root(&req),
            _ => Err(AwsServiceError::action_not_implemented("sts", &req.action)),
        };
        if mutates && matches!(result.as_ref(), Ok(resp) if resp.status.is_success()) {
            save_iam_snapshot(
                &self.state,
                self.snapshot_store.clone(),
                &self.snapshot_lock,
            )
            .await;
        }
        result
    }

    fn supported_actions(&self) -> &[&str] {
        &[
            "GetCallerIdentity",
            "AssumeRole",
            "AssumeRoleWithWebIdentity",
            "AssumeRoleWithSAML",
            "GetSessionToken",
            "GetFederationToken",
            "GetAccessKeyInfo",
            "DecodeAuthorizationMessage",
            "AssumeRoot",
        ]
    }

    /// STS opts into Phase 1 IAM enforcement.
    fn iam_enforceable(&self) -> bool {
        true
    }

    /// STS actions operate on `*` per AWS — see
    /// <https://docs.aws.amazon.com/service-authorization/latest/reference/list_awssecuritytokenservice.html>.
    /// `AssumeRole*` variants additionally carry a role ARN as the
    /// target resource so policies can scope by role name.
    fn iam_action_for(
        &self,
        request: &fakecloud_core::service::AwsRequest,
    ) -> Option<fakecloud_core::auth::IamAction> {
        let action: &'static str = match request.action.as_str() {
            "GetCallerIdentity" => "GetCallerIdentity",
            "AssumeRole" => "AssumeRole",
            "AssumeRoleWithWebIdentity" => "AssumeRoleWithWebIdentity",
            "AssumeRoleWithSAML" => "AssumeRoleWithSAML",
            "GetSessionToken" => "GetSessionToken",
            "GetFederationToken" => "GetFederationToken",
            "GetAccessKeyInfo" => "GetAccessKeyInfo",
            "DecodeAuthorizationMessage" => "DecodeAuthorizationMessage",
            "AssumeRoot" => "AssumeRoot",
            _ => return None,
        };
        let resource = match action {
            "AssumeRole" | "AssumeRoleWithWebIdentity" | "AssumeRoleWithSAML" => request
                .query_params
                .get("RoleArn")
                .cloned()
                .unwrap_or_else(|| "*".to_string()),
            "AssumeRoot" => request
                .query_params
                .get("TargetPrincipal")
                .cloned()
                .unwrap_or_else(|| "*".to_string()),
            _ => "*".to_string(),
        };
        Some(fakecloud_core::auth::IamAction {
            service: "sts",
            action,
            resource,
        })
    }
}

/// Get the AWS partition from a region string.
fn partition_for_region(region: &str) -> &str {
    if region.starts_with("cn-") {
        "aws-cn"
    } else if region.starts_with("us-iso-") {
        "aws-iso"
    } else if region.starts_with("us-isob-") {
        "aws-iso-b"
    } else if region.starts_with("us-isof-") {
        "aws-iso-f"
    } else if region.starts_with("eu-isoe-") {
        "aws-iso-e"
    } else {
        "aws"
    }
}

/// Collect session policies from the STS request parameters.
///
/// Reads the `Policy` parameter (inline JSON) and `PolicyArns.member.N`
/// (managed-policy ARNs, resolved against `state.policies` at mint time).
/// Returns the raw JSON documents. Dangling `PolicyArns` entries are stored
/// as empty strings so they produce `ImplicitDeny` at evaluate time,
/// matching boundary dangling-ARN semantics.
fn collect_session_policies(req: &AwsRequest, state: &IamState) -> Vec<String> {
    let mut docs = Vec::new();
    if let Some(inline) = req.query_params.get("Policy") {
        docs.push(inline.clone());
    }
    // PolicyArns.member.1, PolicyArns.member.2, ...
    for i in 1..=12 {
        let key = format!("PolicyArns.member.{i}.arn");
        let arn = match req.query_params.get(&key) {
            Some(a) => a,
            None => break,
        };
        match state
            .policies
            .get(arn.as_str())
            .and_then(|p| {
                p.versions
                    .iter()
                    .find(|v| v.is_default)
                    .or_else(|| p.versions.first())
            })
            .map(|v| v.document.clone())
        {
            Some(doc) => docs.push(doc),
            None => {
                tracing::debug!(
                    target: "fakecloud::iam::audit",
                    arn = %arn,
                    "PolicyArns entry does not resolve to a known managed policy; \
                     session will deny all actions covered by this entry"
                );
                docs.push(String::new());
            }
        }
    }
    docs
}

/// Extract the caller's access key from the SigV4 Authorization header.
fn extract_access_key(req: &AwsRequest) -> Option<String> {
    let auth = req.headers.get("authorization")?.to_str().ok()?;
    let info = fakecloud_aws::sigv4::parse_sigv4(auth)?;
    Some(info.access_key)
}

impl StsService {
    fn get_caller_identity(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        // Prefer the pre-resolved principal that dispatch attached via the
        // credential resolver — avoids re-parsing the Authorization header
        // and re-walking IamState. Falls back to the account-root identity
        // when the caller didn't present resolvable credentials (e.g. the
        // `test` root bypass, or no auth header at all).
        if let Some(principal) = req.principal.as_ref() {
            let xml = xml_responses::get_caller_identity_response(
                &principal.account_id,
                &principal.arn,
                &principal.user_id,
                &req.request_id,
            );
            return Ok(AwsResponse::xml(StatusCode::OK, xml));
        }

        let accounts = self.state.read();
        let account_id = accounts.default_account_id();
        let partition = partition_for_region(&req.region);
        let arn = format!("arn:{}:iam::{}:root", partition, account_id);
        let user_id = "FKIAIOSFODNN7EXAMPLE";
        let xml =
            xml_responses::get_caller_identity_response(account_id, &arn, user_id, &req.request_id);
        Ok(AwsResponse::xml(StatusCode::OK, xml))
    }

    fn assume_role(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let role_arn = req.query_params.get("RoleArn").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "The request must contain the parameter RoleArn",
            )
        })?;
        validate_string_length("roleArn", role_arn, 20, 2048)?;

        let role_session_name = req.query_params.get("RoleSessionName").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "The request must contain the parameter RoleSessionName",
            )
        })?;
        validate_string_length("roleSessionName", role_session_name, 2, 64)?;

        // Validate optional DurationSeconds (used below for expiration)
        if let Some(ds) = req.query_params.get("DurationSeconds") {
            let v = ds.parse::<i64>().map_err(|_| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationError",
                    format!(
                        "Value '{}' at 'durationSeconds' failed to satisfy constraint: \
                         Member must be a valid integer",
                        ds
                    ),
                )
            })?;
            validate_range_i64("durationSeconds", v, 900, 43200)?;
        }

        // Validate optional ExternalId
        validate_optional_string_length(
            "externalId",
            req.query_params.get("ExternalId").map(|s| s.as_str()),
            2,
            1224,
        )?;

        // Validate optional Policy
        validate_optional_string_length(
            "policy",
            req.query_params.get("Policy").map(|s| s.as_str()),
            1,
            2048,
        )?;

        // Validate optional SourceIdentity
        validate_optional_string_length(
            "sourceIdentity",
            req.query_params.get("SourceIdentity").map(|s| s.as_str()),
            2,
            64,
        )?;

        // Validate and accept optional MFA SerialNumber
        validate_optional_string_length(
            "serialNumber",
            req.query_params.get("SerialNumber").map(|s| s.as_str()),
            9,
            256,
        )?;
        let serial_number = req.query_params.get("SerialNumber").cloned();

        // Validate and accept optional MFA TokenCode
        validate_optional_string_length(
            "tokenCode",
            req.query_params.get("TokenCode").map(|s| s.as_str()),
            6,
            6,
        )?;
        let token_code = req.query_params.get("TokenCode").cloned();

        // Compute expiration from DurationSeconds (default 3600s)
        let expiration_at = compute_expiration_at(req, DEFAULT_ASSUME_ROLE_DURATION)?;
        let expiration = format_expiration(expiration_at);

        // Accept MFA parameters without verification (emulator behavior)
        let _mfa_serial = serial_number;
        let _mfa_token = token_code;

        let partition = partition_for_region(&req.region);
        let creds = StsCredentials::generate();

        let mut accounts = self.state.write();

        // Resolve session policies from the caller's account
        let caller_state = accounts.get_or_create(&req.account_id);
        let session_policies = collect_session_policies(req, caller_state);

        // Extract account ID from role ARN if present, otherwise use caller's account
        let account_id =
            extract_account_from_arn(role_arn).unwrap_or_else(|| req.account_id.clone());

        // Look up role in the TARGET account's state to get its role_id
        let target_state = accounts.get_or_create(&account_id);
        let role_name = role_arn.rsplit('/').next().unwrap_or("unknown");

        // Enforce the role's trust policy `sts:ExternalId` Condition
        // before minting credentials. AWS rejects with `AccessDenied`
        // when the policy demands an ExternalId and the caller didn't
        // supply one (or supplied a wrong one). Other Conditions
        // (PrincipalOrgID / SourceAccount / MFA) follow in subsequent
        // batches; this batch closes the most-cited security gap.
        if let Some(role) = target_state.roles.get(role_name) {
            if let Some(required) = required_external_id(&role.assume_role_policy_document) {
                let supplied = req.query_params.get("ExternalId");
                if supplied.map(String::as_str) != Some(required.as_str()) {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::FORBIDDEN,
                        "AccessDenied",
                        format!(
                            "User: {} is not authorized to perform: sts:AssumeRole on resource: {} because the role's trust policy requires a matching ExternalId",
                            req.account_id, role_arn
                        ),
                    ));
                }
            }
        }

        let role_id = target_state
            .roles
            .get(role_name)
            .map(|r| r.role_id.clone())
            .unwrap_or_else(xml_responses::generate_role_id);

        let assumed_role_arn = format!(
            "arn:{}:sts::{}:assumed-role/{}/{}",
            partition, account_id, role_name, role_session_name
        );
        let assumed_role_id = format!("{}:{}", role_id, role_session_name);

        // Store credential in the target account's state so the credential
        // resolver finds it when the caller uses these temporary credentials.
        let target_state = accounts.get_or_create(&account_id);
        target_state.credential_identities.insert(
            creds.access_key_id.clone(),
            CredentialIdentity {
                arn: assumed_role_arn.clone(),
                user_id: assumed_role_id.clone(),
                account_id: account_id.clone(),
            },
        );
        target_state.sts_temp_credentials.insert(
            creds.access_key_id.clone(),
            StsTempCredential {
                access_key_id: creds.access_key_id.clone(),
                secret_access_key: creds.secret_access_key.clone(),
                session_token: creds.session_token.clone(),
                principal_arn: assumed_role_arn,
                user_id: assumed_role_id,
                account_id: account_id.clone(),
                expiration: expiration_at,
                session_policies,
            },
        );

        let xml = xml_responses::assume_role_response(&xml_responses::AssumedRoleInfo {
            role_arn,
            role_session_name,
            assumed_role_id: &role_id,
            account_id: &account_id,
            partition,
            creds: &creds,
            expiration: &expiration,
            request_id: &req.request_id,
        });
        Ok(AwsResponse::xml(StatusCode::OK, xml))
    }

    fn assume_role_with_web_identity(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let role_arn = req.query_params.get("RoleArn").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "The request must contain the parameter RoleArn",
            )
        })?;
        validate_string_length("roleArn", role_arn, 20, 2048)?;

        let role_session_name = req.query_params.get("RoleSessionName").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "The request must contain the parameter RoleSessionName",
            )
        })?;
        validate_string_length("roleSessionName", role_session_name, 2, 64)?;

        // WebIdentityToken is required
        let web_identity_token = req.query_params.get("WebIdentityToken").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "The request must contain the parameter WebIdentityToken",
            )
        })?;
        validate_string_length("webIdentityToken", web_identity_token, 4, 20000)?;
        let _web_identity_token = web_identity_token.clone();

        // Validate optional Policy
        validate_optional_string_length(
            "policy",
            req.query_params.get("Policy").map(|s| s.as_str()),
            1,
            2048,
        )?;

        // Validate optional ProviderId
        validate_optional_string_length(
            "providerId",
            req.query_params.get("ProviderId").map(|s| s.as_str()),
            4,
            2048,
        )?;

        // Validate optional DurationSeconds (used below for expiration)
        if let Some(ds) = req.query_params.get("DurationSeconds") {
            let v = ds.parse::<i64>().map_err(|_| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationError",
                    format!(
                        "Value '{}' at 'durationSeconds' failed to satisfy constraint: \
                         Member must be a valid integer",
                        ds
                    ),
                )
            })?;
            validate_range_i64("durationSeconds", v, 900, 43200)?;
        }

        // Compute expiration from DurationSeconds (default 3600s)
        let expiration_at = compute_expiration_at(req, DEFAULT_ASSUME_ROLE_DURATION)?;
        let expiration = format_expiration(expiration_at);

        let partition = partition_for_region(&req.region);
        let creds = StsCredentials::generate();
        let role_id = xml_responses::generate_role_id();

        let mut accounts = self.state.write();
        let caller_state = accounts.get_or_create(&req.account_id);
        let session_policies = collect_session_policies(req, caller_state);
        let account_id =
            extract_account_from_arn(role_arn).unwrap_or_else(|| req.account_id.clone());

        let role_name = role_arn.rsplit('/').next().unwrap_or("unknown");
        let assumed_role_arn = format!(
            "arn:{}:sts::{}:assumed-role/{}/{}",
            partition, account_id, role_name, role_session_name
        );
        let assumed_role_id_str = format!("{}:{}", role_id, role_session_name);

        let target_state = accounts.get_or_create(&account_id);
        target_state.credential_identities.insert(
            creds.access_key_id.clone(),
            CredentialIdentity {
                arn: assumed_role_arn.clone(),
                user_id: assumed_role_id_str.clone(),
                account_id: account_id.clone(),
            },
        );
        target_state.sts_temp_credentials.insert(
            creds.access_key_id.clone(),
            StsTempCredential {
                access_key_id: creds.access_key_id.clone(),
                secret_access_key: creds.secret_access_key.clone(),
                session_token: creds.session_token.clone(),
                principal_arn: assumed_role_arn,
                user_id: assumed_role_id_str,
                account_id: account_id.clone(),
                expiration: expiration_at,
                session_policies,
            },
        );

        let xml = xml_responses::assume_role_with_web_identity_response(
            &xml_responses::AssumedRoleInfo {
                role_arn,
                role_session_name,
                assumed_role_id: &role_id,
                account_id: &account_id,
                partition,
                creds: &creds,
                expiration: &expiration,
                request_id: &req.request_id,
            },
        );
        Ok(AwsResponse::xml(StatusCode::OK, xml))
    }

    fn assume_role_with_saml(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let role_arn = req.query_params.get("RoleArn").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "The request must contain the parameter RoleArn",
            )
        })?;
        validate_string_length("roleArn", role_arn, 20, 2048)?;

        // PrincipalArn is required
        let principal_arn = req.query_params.get("PrincipalArn").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "The request must contain the parameter PrincipalArn",
            )
        })?;
        validate_string_length("principalArn", principal_arn, 20, 2048)?;
        let _principal_arn = principal_arn.clone();

        // SAMLAssertion is required but we just need to extract session name from it
        let saml_assertion = req.query_params.get("SAMLAssertion").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "The request must contain the parameter SAMLAssertion",
            )
        })?;
        validate_string_length("sAMLAssertion", saml_assertion, 4, 100000)?;

        // Validate optional Policy
        validate_optional_string_length(
            "policy",
            req.query_params.get("Policy").map(|s| s.as_str()),
            1,
            2048,
        )?;

        // Validate optional DurationSeconds (used below for expiration)
        if let Some(ds) = req.query_params.get("DurationSeconds") {
            let v = ds.parse::<i64>().map_err(|_| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationError",
                    format!(
                        "Value '{}' at 'durationSeconds' failed to satisfy constraint: \
                         Member must be a valid integer",
                        ds
                    ),
                )
            })?;
            validate_range_i64("durationSeconds", v, 900, 43200)?;
        }

        // Compute expiration from DurationSeconds (default 3600s)
        let expiration_at = compute_expiration_at(req, DEFAULT_ASSUME_ROLE_DURATION)?;
        let expiration = format_expiration(expiration_at);

        // Decode the SAML assertion to extract the RoleSessionName
        let role_session_name =
            extract_saml_session_name(saml_assertion).unwrap_or_else(|| "saml-session".to_string());

        let partition = partition_for_region(&req.region);
        let creds = StsCredentials::generate();
        let role_id = xml_responses::generate_role_id();

        let mut accounts = self.state.write();
        let caller_state = accounts.get_or_create(&req.account_id);
        let session_policies = collect_session_policies(req, caller_state);
        let account_id =
            extract_account_from_arn(role_arn).unwrap_or_else(|| req.account_id.clone());

        let role_name = role_arn.rsplit('/').next().unwrap_or("unknown");
        let assumed_role_arn = format!(
            "arn:{}:sts::{}:assumed-role/{}/{}",
            partition, account_id, role_name, &role_session_name
        );
        let assumed_role_id_str = format!("{}:{}", role_id, role_session_name);

        let target_state = accounts.get_or_create(&account_id);
        target_state.credential_identities.insert(
            creds.access_key_id.clone(),
            CredentialIdentity {
                arn: assumed_role_arn.clone(),
                user_id: assumed_role_id_str.clone(),
                account_id: account_id.clone(),
            },
        );
        target_state.sts_temp_credentials.insert(
            creds.access_key_id.clone(),
            StsTempCredential {
                access_key_id: creds.access_key_id.clone(),
                secret_access_key: creds.secret_access_key.clone(),
                session_token: creds.session_token.clone(),
                principal_arn: assumed_role_arn,
                user_id: assumed_role_id_str,
                account_id: account_id.clone(),
                expiration: expiration_at,
                session_policies,
            },
        );

        let xml = xml_responses::assume_role_with_saml_response(&xml_responses::AssumedRoleInfo {
            role_arn,
            role_session_name: &role_session_name,
            assumed_role_id: &role_id,
            account_id: &account_id,
            partition,
            creds: &creds,
            expiration: &expiration,
            request_id: &req.request_id,
        });
        Ok(AwsResponse::xml(StatusCode::OK, xml))
    }

    fn get_session_token(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        // Validate optional DurationSeconds (used below for expiration)
        if let Some(ds) = req.query_params.get("DurationSeconds") {
            let v = ds.parse::<i64>().map_err(|_| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationError",
                    format!(
                        "Value '{}' at 'durationSeconds' failed to satisfy constraint: \
                         Member must be a valid integer",
                        ds
                    ),
                )
            })?;
            validate_range_i64("durationSeconds", v, 900, 129600)?;
        }

        // Validate and accept optional MFA SerialNumber (no verification in emulator)
        validate_optional_string_length(
            "serialNumber",
            req.query_params.get("SerialNumber").map(|s| s.as_str()),
            9,
            256,
        )?;
        let _serial_number = req.query_params.get("SerialNumber").cloned();

        // Validate and accept optional MFA TokenCode (no verification in emulator)
        validate_optional_string_length(
            "tokenCode",
            req.query_params.get("TokenCode").map(|s| s.as_str()),
            6,
            6,
        )?;
        let _token_code = req.query_params.get("TokenCode").cloned();

        // Compute expiration from DurationSeconds (default 43200s / 12 hours)
        let expiration_at = compute_expiration_at(req, DEFAULT_SESSION_TOKEN_DURATION)?;
        let expiration = format_expiration(expiration_at);

        // Resolve the calling principal so the temporary credential is tied
        // to a real identity that SigV4 verification and IAM enforcement can
        // look up later. Falls back to the account root when the caller
        // isn't a known IAM user — matches how `GetSessionToken` behaves
        // against AWS with root credentials.
        let partition = partition_for_region(&req.region);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let (principal_arn, user_id, account_id) =
            if let Some(akid) = extract_access_key(req).as_deref() {
                if let Some(lookup) = state.credential_secret_readonly(akid) {
                    (lookup.principal_arn, lookup.user_id, lookup.account_id)
                } else {
                    (
                        format!("arn:{}:iam::{}:root", partition, state.account_id),
                        state.account_id.clone(),
                        state.account_id.clone(),
                    )
                }
            } else {
                (
                    format!("arn:{}:iam::{}:root", partition, state.account_id),
                    state.account_id.clone(),
                    state.account_id.clone(),
                )
            };

        let creds = StsCredentials::generate();
        state.credential_identities.insert(
            creds.access_key_id.clone(),
            CredentialIdentity {
                arn: principal_arn.clone(),
                user_id: user_id.clone(),
                account_id: account_id.clone(),
            },
        );
        // GetSessionToken does not accept a Policy parameter per AWS
        // docs, so session_policies is always empty for this operation.
        state.sts_temp_credentials.insert(
            creds.access_key_id.clone(),
            StsTempCredential {
                access_key_id: creds.access_key_id.clone(),
                secret_access_key: creds.secret_access_key.clone(),
                session_token: creds.session_token.clone(),
                principal_arn,
                user_id,
                account_id,
                expiration: expiration_at,
                session_policies: Vec::new(),
            },
        );

        let xml = xml_responses::get_session_token_response(&creds, &expiration, &req.request_id);
        Ok(AwsResponse::xml(StatusCode::OK, xml))
    }

    fn get_federation_token(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let name = req.query_params.get("Name").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "The request must contain the parameter Name",
            )
        })?;
        validate_string_length("name", name, 2, 32)?;

        // Validate optional DurationSeconds (used below for expiration)
        if let Some(ds) = req.query_params.get("DurationSeconds") {
            let v = ds.parse::<i64>().map_err(|_| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationError",
                    format!(
                        "Value '{}' at 'durationSeconds' failed to satisfy constraint: \
                         Member must be a valid integer",
                        ds
                    ),
                )
            })?;
            validate_range_i64("durationSeconds", v, 900, 129600)?;
        }

        // Validate and store optional policy
        validate_optional_string_length(
            "policy",
            req.query_params.get("Policy").map(|s| s.as_str()),
            1,
            2048,
        )?;
        let policy = req.query_params.get("Policy").cloned();

        // Compute expiration from DurationSeconds (default 43200s / 12 hours)
        let expiration_at = compute_expiration_at(req, DEFAULT_FEDERATION_TOKEN_DURATION)?;
        let expiration = format_expiration(expiration_at);

        let partition = partition_for_region(&req.region);
        let creds = StsCredentials::generate();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let session_policies = collect_session_policies(req, state);
        let account_id = state.account_id.clone();
        let federated_user_arn = format!(
            "arn:{}:sts::{}:federated-user/{}",
            partition, account_id, name
        );
        let federated_user_id = format!("{}:{}", account_id, name);

        state.credential_identities.insert(
            creds.access_key_id.clone(),
            CredentialIdentity {
                arn: federated_user_arn.clone(),
                user_id: federated_user_id.clone(),
                account_id: account_id.clone(),
            },
        );
        state.sts_temp_credentials.insert(
            creds.access_key_id.clone(),
            StsTempCredential {
                access_key_id: creds.access_key_id.clone(),
                secret_access_key: creds.secret_access_key.clone(),
                session_token: creds.session_token.clone(),
                principal_arn: federated_user_arn,
                user_id: federated_user_id,
                account_id: account_id.clone(),
                expiration: expiration_at,
                session_policies,
            },
        );

        let xml = xml_responses::get_federation_token_response(
            &creds,
            name,
            &account_id,
            partition,
            &expiration,
            policy.as_deref(),
            &req.request_id,
        );
        Ok(AwsResponse::xml(StatusCode::OK, xml))
    }

    fn decode_authorization_message(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let encoded_message = req.query_params.get("EncodedMessage").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "The request must contain the parameter EncodedMessage",
            )
        })?;
        validate_string_length("encodedMessage", encoded_message, 1, 10240)?;

        let decoded_message =
            r#"{"allowed":true,"explicitDeny":false,"matchedStatements":{"items":[]}}"#;
        let xml =
            xml_responses::decode_authorization_message_response(decoded_message, &req.request_id);
        Ok(AwsResponse::xml(StatusCode::OK, xml))
    }

    fn get_access_key_info(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let access_key_id = req.query_params.get("AccessKeyId").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "The request must contain the parameter AccessKeyId",
            )
        })?;
        validate_string_length("accessKeyId", access_key_id, 16, 128)?;

        // Try to resolve account from known access keys across all accounts
        let accounts = self.state.read();
        let mut resolved_account_id = None;
        for (acct_id, acct_state) in accounts.iter() {
            if acct_state
                .access_keys
                .values()
                .flatten()
                .any(|k| k.access_key_id == *access_key_id)
            {
                resolved_account_id = Some(acct_id.to_string());
                break;
            }
            if let Some(ci) = acct_state.credential_identities.get(access_key_id.as_str()) {
                resolved_account_id = Some(ci.account_id.clone());
                break;
            }
        }
        let account_id =
            resolved_account_id.unwrap_or_else(|| accounts.default_account_id().to_string());

        let xml = xml_responses::get_access_key_info_response(&account_id, &req.request_id);
        Ok(AwsResponse::xml(StatusCode::OK, xml))
    }

    /// AssumeRoot: returns short-lived privileged credentials scoped to a
    /// member-account root principal. Caller must be from the management
    /// account; we mint and persist credentials so subsequent calls under
    /// them resolve to the target account's root identity.
    fn assume_root(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let target_principal = req.query_params.get("TargetPrincipal").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "The request must contain the parameter TargetPrincipal",
            )
        })?;
        let task_policy_arn = req
            .query_params
            .get("TaskPolicyArn.arn")
            .or_else(|| req.query_params.get("TaskPolicyArn"))
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "MissingParameter",
                    "The request must contain the parameter TaskPolicyArn",
                )
            })?;
        validate_string_length("taskPolicyArn", task_policy_arn, 20, 2048)?;

        if let Some(ds) = req.query_params.get("DurationSeconds") {
            let v = ds.parse::<i64>().map_err(|_| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationError",
                    format!(
                        "Value '{}' at 'durationSeconds' failed to satisfy constraint: \
                         Member must be a valid integer",
                        ds
                    ),
                )
            })?;
            validate_range_i64("durationSeconds", v, 0, 900)?;
        }

        // Target principal can be an ARN (arn:aws:iam::123:root) or a 12-digit
        // account id; normalize to (account_id, principal_arn).
        let partition = partition_for_region(&req.region);
        let (target_account, target_arn) = if target_principal.starts_with("arn:") {
            let acct = extract_account_from_arn(target_principal).ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationError",
                    "TargetPrincipal ARN is malformed",
                )
            })?;
            (acct, target_principal.to_string())
        } else if target_principal.len() == 12
            && target_principal.chars().all(|c| c.is_ascii_digit())
        {
            (
                target_principal.to_string(),
                format!("arn:{}:iam::{}:root", partition, target_principal),
            )
        } else {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationError",
                "TargetPrincipal must be a member account ID or root ARN",
            ));
        };

        let expiration_at = compute_expiration_at(req, 900)?;
        let expiration = format_expiration(expiration_at);
        let creds = StsCredentials::generate();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&target_account);
        state.credential_identities.insert(
            creds.access_key_id.clone(),
            CredentialIdentity {
                arn: target_arn.clone(),
                user_id: target_account.clone(),
                account_id: target_account.clone(),
            },
        );
        state.sts_temp_credentials.insert(
            creds.access_key_id.clone(),
            StsTempCredential {
                access_key_id: creds.access_key_id.clone(),
                secret_access_key: creds.secret_access_key.clone(),
                session_token: creds.session_token.clone(),
                principal_arn: target_arn.clone(),
                user_id: target_account.clone(),
                account_id: target_account.clone(),
                expiration: expiration_at,
                session_policies: Vec::new(),
            },
        );

        let source_identity = req.query_params.get("SourceIdentity").map(|s| s.as_str());
        let xml = xml_responses::assume_root_response(
            &creds,
            &expiration,
            source_identity,
            &req.request_id,
        );
        Ok(AwsResponse::xml(StatusCode::OK, xml))
    }
}

/// Extract account ID from an ARN like `arn:aws:iam::123456789012:role/name`.
/// Extract the `sts:ExternalId` value from any Allow statement in
/// the role's trust policy that has a `StringEquals` or
/// `StringEqualsIgnoreCase` Condition naming `sts:ExternalId`. The
/// caller's AssumeRole request must supply a matching ExternalId or
/// AWS rejects with AccessDenied. Returns `None` when no statement
/// requires an ExternalId — that's the unconditioned case where
/// AssumeRole proceeds without further check.
fn required_external_id(policy_doc: &str) -> Option<String> {
    let parsed: serde_json::Value = serde_json::from_str(policy_doc).ok()?;
    let statements = match parsed.get("Statement") {
        Some(serde_json::Value::Array(arr)) => arr.clone(),
        Some(stmt) => vec![stmt.clone()],
        None => return None,
    };
    for stmt in &statements {
        if stmt
            .get("Effect")
            .and_then(|v| v.as_str())
            .map(|s| !s.eq_ignore_ascii_case("Allow"))
            .unwrap_or(false)
        {
            continue;
        }
        let Some(condition) = stmt.get("Condition") else {
            continue;
        };
        for op in ["StringEquals", "StringEqualsIgnoreCase"] {
            let Some(map) = condition.get(op).and_then(|v| v.as_object()) else {
                continue;
            };
            for (key, val) in map {
                if !key.eq_ignore_ascii_case("sts:ExternalId") {
                    continue;
                }
                if let Some(s) = val.as_str() {
                    return Some(s.to_string());
                }
                if let Some(arr) = val.as_array() {
                    if let Some(first) = arr.iter().find_map(|v| v.as_str()) {
                        return Some(first.to_string());
                    }
                }
            }
        }
    }
    None
}

fn extract_account_from_arn(arn: &str) -> Option<String> {
    let parts: Vec<&str> = arn.split(':').collect();
    if parts.len() >= 5 && !parts[4].is_empty() {
        Some(parts[4].to_string())
    } else {
        None
    }
}

/// Extract the RoleSessionName from a base64-encoded SAML assertion.
fn extract_saml_session_name(saml_b64: &str) -> Option<String> {
    use base64::Engine;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(saml_b64)
        .ok()?;
    let xml_str = String::from_utf8(decoded).ok()?;

    // Look for the RoleSessionName attribute value in the SAML XML.
    let role_session_attr = "https://aws.amazon.com/SAML/Attributes/RoleSessionName";
    let pos = xml_str.find(role_session_attr)?;

    // Find the AttributeValue after this position
    let after = &xml_str[pos..];
    let av_start = after.find("AttributeValue")?;
    let after_av = &after[av_start..];
    // Skip past the closing >
    let gt_pos = after_av.find('>')?;
    let value_start = &after_av[gt_pos + 1..];
    // Find end of value (next < which starts the closing tag)
    let lt_pos = value_start.find('<')?;
    let value = value_start[..lt_pos].trim();

    if value.is_empty() {
        None
    } else {
        Some(value.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_partition_for_region() {
        assert_eq!(partition_for_region("us-east-1"), "aws");
        assert_eq!(partition_for_region("eu-west-1"), "aws");
        assert_eq!(partition_for_region("cn-north-1"), "aws-cn");
        assert_eq!(partition_for_region("cn-northwest-1"), "aws-cn");
        assert_eq!(partition_for_region("us-isob-east-1"), "aws-iso-b");
        assert_eq!(partition_for_region("us-iso-east-1"), "aws-iso");
    }

    #[test]
    fn test_extract_account_from_arn() {
        assert_eq!(
            extract_account_from_arn("arn:aws:iam::123456789012:role/test"),
            Some("123456789012".to_string())
        );
        assert_eq!(
            extract_account_from_arn("arn:aws:iam::111111111111:role/test"),
            Some("111111111111".to_string())
        );
        assert_eq!(extract_account_from_arn("invalid"), None);
    }

    #[test]
    fn test_extract_saml_session_name() {
        use base64::Engine;
        let xml = r#"<?xml version="1.0"?><samlp:Response><Assertion><AttributeStatement><Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName"><AttributeValue>testuser</AttributeValue></Attribute></AttributeStatement></Assertion></samlp:Response>"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(xml.as_bytes());
        assert_eq!(
            extract_saml_session_name(&encoded),
            Some("testuser".to_string())
        );
    }

    #[test]
    fn test_extract_saml_session_name_with_namespace() {
        use base64::Engine;
        let xml = r#"<?xml version="1.0"?><samlp:Response><saml:Assertion><saml:AttributeStatement><saml:Attribute Name="https://aws.amazon.com/SAML/Attributes/RoleSessionName"><saml:AttributeValue>testuser</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion></samlp:Response>"#;
        let encoded = base64::engine::general_purpose::STANDARD.encode(xml.as_bytes());
        assert_eq!(
            extract_saml_session_name(&encoded),
            Some("testuser".to_string())
        );
    }

    #[test]
    fn test_session_token_format() {
        let token = xml_responses::generate_session_token();
        assert_eq!(token.len(), 356);
        assert!(token.starts_with("FQoGZXIvYXdzE"));
    }

    #[test]
    fn test_access_key_id_format() {
        let key = xml_responses::generate_access_key_id();
        assert_eq!(key.len(), 20);
        assert!(key.starts_with("FSIA"));
    }

    #[test]
    fn test_secret_access_key_format() {
        let key = xml_responses::generate_secret_access_key();
        assert_eq!(key.len(), 40);
    }

    #[test]
    fn test_role_id_format() {
        let id = xml_responses::generate_role_id();
        assert_eq!(id.len(), 21);
        assert!(id.starts_with("AROA"));
    }

    #[test]
    fn test_decode_authorization_message() {
        use parking_lot::RwLock;
        use std::collections::HashMap;
        use std::sync::Arc;

        let state: SharedIamState = Arc::new(RwLock::new(
            fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", ""),
        ));
        let service = StsService::new(state);

        let mut params = HashMap::new();
        params.insert(
            "EncodedMessage".to_string(),
            "some-encoded-message".to_string(),
        );

        let req = make_test_request(params);
        let resp = service.decode_authorization_message(&req).unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("DecodedMessage"));
        assert!(body.contains("allowed"));
        assert!(body.contains("matchedStatements"));
    }

    #[test]
    fn test_decode_authorization_message_missing_param() {
        use parking_lot::RwLock;
        use std::collections::HashMap;
        use std::sync::Arc;

        let state: SharedIamState = Arc::new(RwLock::new(
            fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", ""),
        ));
        let service = StsService::new(state);

        let req = make_test_request(HashMap::new());
        let result = service.decode_authorization_message(&req);
        assert!(result.is_err());
        let err = result.err().unwrap();
        let msg = format!("{:?}", err);
        assert!(msg.contains("EncodedMessage"));
    }

    fn make_test_request(params: std::collections::HashMap<String, String>) -> AwsRequest {
        AwsRequest {
            service: "sts".into(),
            action: "Test".into(),
            region: "us-east-1".into(),
            account_id: "123456789012".into(),
            request_id: "test".into(),
            headers: http::HeaderMap::new(),
            query_params: params,
            body: Default::default(),
            body_stream: parking_lot::Mutex::new(None),
            path_segments: vec![],
            raw_path: "/".into(),
            raw_query: String::new(),
            method: http::Method::POST,
            is_query_protocol: true,
            access_key_id: None,
            principal: None,
        }
    }

    fn parse_expiration(s: &str) -> chrono::DateTime<Utc> {
        chrono::NaiveDateTime::parse_from_str(s, "%Y-%m-%dT%H:%M:%SZ")
            .expect("valid timestamp")
            .and_utc()
    }

    #[test]
    fn test_compute_expiration_with_duration() {
        use std::collections::HashMap;

        let mut params = HashMap::new();
        params.insert("DurationSeconds".to_string(), "1800".to_string());
        let req = make_test_request(params);

        let now = Utc::now();
        let exp_str = compute_expiration(&req, 3600).unwrap();
        let exp_utc = parse_expiration(&exp_str);

        // Should be ~1800s from now (using provided DurationSeconds, not default)
        let diff = (exp_utc - now).num_seconds();
        assert!(
            (1798..=1802).contains(&diff),
            "expected ~1800s duration, got {diff}s"
        );
    }

    #[test]
    fn test_compute_expiration_default() {
        use std::collections::HashMap;

        let req = make_test_request(HashMap::new());

        let now = Utc::now();
        let exp_str = compute_expiration(&req, 43200).unwrap();
        let exp_utc = parse_expiration(&exp_str);

        // Should be ~43200s (12 hours) from now using default
        let diff = (exp_utc - now).num_seconds();
        assert!(
            (43198..=43202).contains(&diff),
            "expected ~43200s duration, got {diff}s"
        );
    }

    #[test]
    fn test_compute_expiration_uses_provided_not_default() {
        use std::collections::HashMap;

        let mut params = HashMap::new();
        params.insert("DurationSeconds".to_string(), "900".to_string());
        let req = make_test_request(params);

        let before = Utc::now();
        let exp_str = compute_expiration(&req, 43200).unwrap();
        let exp_utc = parse_expiration(&exp_str);

        // Should use 900s, not the default 43200s
        let expected = before + chrono::Duration::seconds(900);
        let diff = (exp_utc - expected).num_seconds().abs();
        assert!(
            diff <= 2,
            "expected ~900s duration, got diff={diff}s from expected"
        );
    }

    fn make_sts_service() -> (StsService, SharedIamState) {
        use parking_lot::RwLock;
        use std::sync::Arc;

        let state: SharedIamState = Arc::new(RwLock::new(
            fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", ""),
        ));
        let sts = StsService::new(state.clone());
        (sts, state)
    }

    fn sts_request(action: &str, params: Vec<(&str, &str)>) -> AwsRequest {
        let mut qp = std::collections::HashMap::new();
        qp.insert("Action".to_string(), action.to_string());
        for (k, v) in params {
            qp.insert(k.to_string(), v.to_string());
        }
        let mut req = make_test_request(qp);
        req.action = action.to_string();
        req
    }

    fn create_role_in_state(state: &SharedIamState, name: &str) -> String {
        create_role_in_state_with_trust(state, name, "{}")
    }

    fn create_role_in_state_with_trust(
        state: &SharedIamState,
        name: &str,
        trust_policy: &str,
    ) -> String {
        let arn = fakecloud_aws::arn::Arn::global("iam", "123456789012", &format!("role/{name}"))
            .to_string();
        let mut accounts = state.write();
        let s = accounts.get_or_create("123456789012");
        // Real CreateRole inserts by role_name; assume_role looks up
        // by role_name too, so the map key must match for the trust
        // policy gate to actually fire.
        s.roles.insert(
            name.to_string(),
            crate::state::IamRole {
                role_name: name.to_string(),
                role_id: format!("AROA{}", &uuid::Uuid::new_v4().to_string()[..17]),
                arn: arn.clone(),
                path: "/".to_string(),
                assume_role_policy_document: trust_policy.to_string(),
                created_at: Utc::now(),
                description: None,
                max_session_duration: 3600,
                tags: Vec::new(),
                permissions_boundary: None,
            },
        );
        arn
    }

    // ── GetCallerIdentity ──

    #[tokio::test]
    async fn get_caller_identity() {
        let (svc, _) = make_sts_service();
        let req = sts_request("GetCallerIdentity", vec![]);
        let resp = svc.handle(req).await.unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<Account>123456789012</Account>"));
        assert!(body.contains("<Arn>"));
    }

    // ── AssumeRole ──

    #[tokio::test]
    async fn assume_role_basic() {
        let (svc, state) = make_sts_service();
        let role_arn = create_role_in_state(&state, "test-role");

        let req = sts_request(
            "AssumeRole",
            vec![("RoleArn", &role_arn), ("RoleSessionName", "test-session")],
        );
        let resp = svc.handle(req).await.unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<AccessKeyId>"));
        assert!(body.contains("<SecretAccessKey>"));
        assert!(body.contains("<SessionToken>"));
    }

    #[tokio::test]
    async fn assume_role_not_found() {
        let (svc, _) = make_sts_service();
        let req = sts_request(
            "AssumeRole",
            vec![
                ("RoleArn", "arn:aws:iam::123456789012:role/nonexistent"),
                ("RoleSessionName", "s"),
            ],
        );
        assert!(svc.handle(req).await.is_err());
    }

    #[tokio::test]
    async fn assume_role_missing_session_name() {
        let (svc, _) = make_sts_service();
        let req = sts_request(
            "AssumeRole",
            vec![("RoleArn", "arn:aws:iam::123456789012:role/r")],
        );
        assert!(svc.handle(req).await.is_err());
    }

    // ── AssumeRoleWithWebIdentity ──

    #[tokio::test]
    async fn assume_role_with_web_identity() {
        let (svc, state) = make_sts_service();
        let role_arn = create_role_in_state(&state, "web-role");

        let req = sts_request(
            "AssumeRoleWithWebIdentity",
            vec![
                ("RoleArn", &role_arn),
                ("RoleSessionName", "web-session"),
                ("WebIdentityToken", "fake-jwt-token"),
            ],
        );
        let resp = svc.handle(req).await.unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<AccessKeyId>"));
    }

    // ── GetSessionToken ──

    #[tokio::test]
    async fn get_session_token() {
        let (svc, _) = make_sts_service();
        let req = sts_request("GetSessionToken", vec![]);
        let resp = svc.handle(req).await.unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<AccessKeyId>"));
        assert!(body.contains("<SessionToken>"));
    }

    #[tokio::test]
    async fn get_session_token_with_duration() {
        let (svc, _) = make_sts_service();
        let req = sts_request("GetSessionToken", vec![("DurationSeconds", "1800")]);
        let resp = svc.handle(req).await.unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<Expiration>"));
    }

    // ── GetFederationToken ──

    #[tokio::test]
    async fn get_federation_token() {
        let (svc, _) = make_sts_service();
        let req = sts_request("GetFederationToken", vec![("Name", "feduser")]);
        let resp = svc.handle(req).await.unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<AccessKeyId>"));
        assert!(body.contains("<FederatedUserId>"));
    }

    // ── GetAccessKeyInfo ──

    #[tokio::test]
    async fn get_access_key_info() {
        let (svc, _) = make_sts_service();
        let req = sts_request(
            "GetAccessKeyInfo",
            vec![("AccessKeyId", "AKIAIOSFODNN7EXAMPLE")],
        );
        let resp = svc.handle(req).await.unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<Account>"));
    }

    // ── Trust policy: ExternalId enforcement ──

    #[tokio::test]
    async fn assume_role_rejects_when_external_id_missing() {
        // Trust policy demands sts:ExternalId; caller didn't supply
        // one — AssumeRole must 403.
        let (svc, state) = make_sts_service();
        let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"secret-handshake"}}}]}"#;
        let role_arn = create_role_in_state_with_trust(&state, "third-party", trust);
        let req = sts_request(
            "AssumeRole",
            vec![("RoleArn", &role_arn), ("RoleSessionName", "sess")],
        );
        let err = match svc.handle(req).await {
            Err(e) => e,
            Ok(_) => panic!("expected AccessDenied when ExternalId missing"),
        };
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn assume_role_rejects_when_external_id_mismatches() {
        let (svc, state) = make_sts_service();
        let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"secret-handshake"}}}]}"#;
        let role_arn = create_role_in_state_with_trust(&state, "third-party", trust);
        let req = sts_request(
            "AssumeRole",
            vec![
                ("RoleArn", &role_arn),
                ("RoleSessionName", "sess"),
                ("ExternalId", "wrongguess"),
            ],
        );
        let err = match svc.handle(req).await {
            Err(e) => e,
            Ok(_) => panic!("expected AccessDenied when ExternalId mismatches"),
        };
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn assume_role_succeeds_when_external_id_matches() {
        let (svc, state) = make_sts_service();
        let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole","Condition":{"StringEquals":{"sts:ExternalId":"secret-handshake"}}}]}"#;
        let role_arn = create_role_in_state_with_trust(&state, "third-party", trust);
        let req = sts_request(
            "AssumeRole",
            vec![
                ("RoleArn", &role_arn),
                ("RoleSessionName", "sess"),
                ("ExternalId", "secret-handshake"),
            ],
        );
        let resp = svc.handle(req).await.unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("<AccessKeyId>"));
    }

    #[tokio::test]
    async fn assume_role_proceeds_when_no_external_id_required() {
        // No ExternalId Condition in the trust policy — caller doesn't
        // need to supply one.
        let (svc, state) = make_sts_service();
        let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}"#;
        let role_arn = create_role_in_state_with_trust(&state, "open-role", trust);
        let req = sts_request(
            "AssumeRole",
            vec![("RoleArn", &role_arn), ("RoleSessionName", "sess")],
        );
        svc.handle(req).await.unwrap();
    }

    // ── Unsupported action ──

    #[tokio::test]
    async fn unsupported_sts_action() {
        let (svc, _) = make_sts_service();
        let req = sts_request("BogusAction", vec![]);
        assert!(svc.handle(req).await.is_err());
    }

    #[tokio::test]
    async fn assume_role_missing_role_arn_errors() {
        let (svc, _) = make_sts_service();
        let req = sts_request("AssumeRole", vec![("RoleSessionName", "sess")]);
        assert!(svc.assume_role(&req).is_err());
    }

    #[tokio::test]
    async fn assume_role_with_web_identity_missing_token_errors() {
        let (svc, _) = make_sts_service();
        let req = sts_request(
            "AssumeRoleWithWebIdentity",
            vec![
                ("RoleArn", "arn:aws:iam::123:role/r"),
                ("RoleSessionName", "s"),
            ],
        );
        assert!(svc.assume_role_with_web_identity(&req).is_err());
    }

    #[tokio::test]
    async fn assume_role_with_saml_missing_assertion_errors() {
        let (svc, _) = make_sts_service();
        let req = sts_request(
            "AssumeRoleWithSAML",
            vec![
                ("RoleArn", "arn:aws:iam::123:role/r"),
                ("PrincipalArn", "arn:aws:iam::123:saml-provider/p"),
            ],
        );
        assert!(svc.assume_role_with_saml(&req).is_err());
    }

    #[tokio::test]
    async fn get_session_token_returns_ok() {
        let (svc, _) = make_sts_service();
        let req = sts_request("GetSessionToken", vec![]);
        let resp = svc.get_session_token(&req).unwrap();
        assert_eq!(resp.status, http::StatusCode::OK);
    }

    #[tokio::test]
    async fn get_federation_token_returns_ok() {
        let (svc, _) = make_sts_service();
        let req = sts_request("GetFederationToken", vec![("Name", "test-user")]);
        let resp = svc.get_federation_token(&req).unwrap();
        assert_eq!(resp.status, http::StatusCode::OK);
    }

    #[tokio::test]
    async fn get_federation_token_missing_name_errors() {
        let (svc, _) = make_sts_service();
        let req = sts_request("GetFederationToken", vec![]);
        assert!(svc.get_federation_token(&req).is_err());
    }

    // ── AssumeRoot ──

    #[tokio::test]
    async fn assume_root_with_account_id_succeeds() {
        let (svc, _) = make_sts_service();
        let req = sts_request(
            "AssumeRoot",
            vec![
                ("TargetPrincipal", "111122223333"),
                (
                    "TaskPolicyArn.arn",
                    "arn:aws:iam::aws:policy/IAMAuditRootUserCredentials",
                ),
            ],
        );
        let resp = svc.assume_root(&req).unwrap();
        assert_eq!(resp.status, http::StatusCode::OK);
        let body = String::from_utf8(resp.body.expect_bytes().to_vec()).unwrap();
        assert!(body.contains("AccessKeyId"), "{body}");
    }

    #[tokio::test]
    async fn assume_root_with_arn_succeeds() {
        let (svc, _) = make_sts_service();
        let req = sts_request(
            "AssumeRoot",
            vec![
                ("TargetPrincipal", "arn:aws:iam::444455556666:root"),
                (
                    "TaskPolicyArn.arn",
                    "arn:aws:iam::aws:policy/IAMAuditRootUserCredentials",
                ),
                ("DurationSeconds", "600"),
                ("SourceIdentity", "alice"),
            ],
        );
        let resp = svc.assume_root(&req).unwrap();
        let body = String::from_utf8(resp.body.expect_bytes().to_vec()).unwrap();
        assert!(
            body.contains("<SourceIdentity>alice</SourceIdentity>"),
            "{body}"
        );
    }

    #[tokio::test]
    async fn assume_root_missing_task_policy_errors() {
        let (svc, _) = make_sts_service();
        let req = sts_request("AssumeRoot", vec![("TargetPrincipal", "111122223333")]);
        let err = match svc.assume_root(&req) {
            Err(e) => e,
            Ok(_) => panic!("expected err"),
        };
        assert!(err.to_string().contains("TaskPolicyArn"));
    }

    #[tokio::test]
    async fn assume_root_invalid_principal_errors() {
        let (svc, _) = make_sts_service();
        let req = sts_request(
            "AssumeRoot",
            vec![
                ("TargetPrincipal", "not-an-id"),
                ("TaskPolicyArn.arn", "arn:aws:iam::aws:policy/X"),
            ],
        );
        assert!(svc.assume_root(&req).is_err());
    }

    #[tokio::test]
    async fn assume_root_duration_above_max_errors() {
        let (svc, _) = make_sts_service();
        let req = sts_request(
            "AssumeRoot",
            vec![
                ("TargetPrincipal", "111122223333"),
                ("TaskPolicyArn.arn", "arn:aws:iam::aws:policy/X"),
                ("DurationSeconds", "1800"),
            ],
        );
        assert!(svc.assume_root(&req).is_err());
    }
}
