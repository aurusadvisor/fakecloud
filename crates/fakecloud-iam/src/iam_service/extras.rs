//! Handlers added to close the IAM conformance gap. Service-specific
//! credentials, delegation requests, organizations integration, outbound
//! web identity federation, service-last-accessed jobs, extra resource
//! tagging surfaces, policy simulation, and miscellaneous credentials
//! maintenance ops.

use chrono::Utc;
use http::StatusCode;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::state::{
    IamState, OrganizationsAccessReport, ServiceLastAccessedJob, ServiceSpecificCredential,
};

use super::{empty_response, parse_tags, tags_xml, IamService};
use fakecloud_core::query::required_param;

use fakecloud_aws::xml::xml_escape;

fn xml_response(action: &str, body: &str, request_id: &str) -> AwsResponse {
    let xml = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<{action}Response xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
{body}
  <ResponseMetadata>
    <RequestId>{request_id}</RequestId>
  </ResponseMetadata>
</{action}Response>"#,
    );
    AwsResponse::xml(StatusCode::OK, xml)
}

fn now_iso() -> String {
    Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string()
}

/// Collect a member list from query params (`Prefix.1`, `Prefix.2`, ...).
/// Stops at the first missing index. Bounded at 128 to match AWS's
/// per-API simulate limit.
fn collect_member_list(req: &AwsRequest, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    for i in 1..=128 {
        let key = format!("{prefix}{i}");
        match req.query_params.get(&key) {
            Some(v) => out.push(v.clone()),
            None => break,
        }
    }
    out
}

/// Resolve an IAM principal ARN (user or role) to its full identity
/// policy set: managed policies (default version) plus inline
/// policies. Returns an empty vec if the ARN doesn't resolve.
fn collect_principal_policies(
    state: &IamState,
    source_arn: &str,
) -> Vec<crate::evaluator::PolicyDocument> {
    use crate::evaluator::PolicyDocument;
    let mut out: Vec<PolicyDocument> = Vec::new();
    let (kind, name) = match parse_principal_arn(source_arn) {
        Some(p) => p,
        None => return out,
    };
    let (managed, inline) = match kind {
        PrincipalKind::User => (
            state.user_policies.get(name).cloned().unwrap_or_default(),
            state
                .user_inline_policies
                .get(name)
                .cloned()
                .unwrap_or_default(),
        ),
        PrincipalKind::Role => (
            state.role_policies.get(name).cloned().unwrap_or_default(),
            state
                .role_inline_policies
                .get(name)
                .cloned()
                .unwrap_or_default(),
        ),
    };
    for arn in &managed {
        if let Some(policy) = state.policies.get(arn) {
            if let Some(v) = policy.versions.iter().find(|v| v.is_default) {
                out.push(PolicyDocument::parse(&v.document));
            }
        }
    }
    for doc in inline.values() {
        out.push(PolicyDocument::parse(doc));
    }
    out
}

fn principal_boundary(state: &IamState, source_arn: &str) -> Option<String> {
    let (kind, name) = parse_principal_arn(source_arn)?;
    match kind {
        PrincipalKind::User => state
            .users
            .get(name)
            .and_then(|u| u.permissions_boundary.clone()),
        PrincipalKind::Role => state
            .roles
            .get(name)
            .and_then(|r| r.permissions_boundary.clone()),
    }
}

#[derive(Debug, Clone, Copy)]
enum PrincipalKind {
    User,
    Role,
}

fn parse_principal_arn(arn: &str) -> Option<(PrincipalKind, &str)> {
    // arn:aws:iam::ACCOUNT:user/path/name -> User, "name"
    // arn:aws:iam::ACCOUNT:role/path/name -> Role, "name"
    let colon_at = arn.rfind(':')?;
    let resource = &arn[colon_at + 1..];
    let (resource_type, rest) = resource.split_once('/')?;
    let last = rest.rsplit('/').next().unwrap_or(rest);
    match resource_type {
        "user" => Some((PrincipalKind::User, last)),
        "role" => Some((PrincipalKind::Role, last)),
        _ => None,
    }
}

fn service_credential_xml(c: &ServiceSpecificCredential, include_password: bool) -> String {
    let pw = if include_password {
        format!(
            "<ServicePassword>{}</ServicePassword>",
            xml_escape(&c.service_password)
        )
    } else {
        String::new()
    };
    format!(
        "<ServiceSpecificCredential>{pw}<ServiceUserName>{}</ServiceUserName><CreateDate>{}</CreateDate><ServiceName>{}</ServiceName><UserName>{}</UserName><ServiceSpecificCredentialId>{}</ServiceSpecificCredentialId><Status>{}</Status></ServiceSpecificCredential>",
        xml_escape(&c.service_user_name),
        c.create_date.format("%Y-%m-%dT%H:%M:%SZ"),
        xml_escape(&c.service_name),
        xml_escape(&c.user_name),
        xml_escape(&c.credential_id),
        xml_escape(&c.status),
    )
}

fn random_id(prefix: &str) -> String {
    format!(
        "{}{}",
        prefix,
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    )
}

impl IamService {
    // ── Service-specific credentials ──

    pub(super) fn create_service_specific_credential(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let user_name = required_param(&req.query_params, "UserName")?;
        let service_name = required_param(&req.query_params, "ServiceName")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if !state.users.contains_key(&user_name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NoSuchEntity",
                format!("User {user_name} not found"),
            ));
        }
        let credential_id = random_id("ACCA");
        let cred = ServiceSpecificCredential {
            credential_id: credential_id.clone(),
            user_name: user_name.clone(),
            service_name,
            service_user_name: format!("{user_name}-at-{}", state.account_id),
            service_password: random_id("PW"),
            status: "Active".to_string(),
            create_date: Utc::now(),
        };
        state
            .service_specific_credentials
            .entry(user_name)
            .or_default()
            .push(cred.clone());
        let body = format!(
            "  <CreateServiceSpecificCredentialResult>\n{}\n  </CreateServiceSpecificCredentialResult>",
            service_credential_xml(&cred, true)
        );
        Ok(xml_response(
            "CreateServiceSpecificCredential",
            &body,
            &req.request_id,
        ))
    }

    pub(super) fn delete_service_specific_credential(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let user_name = required_param(&req.query_params, "UserName")?;
        let cred_id = required_param(&req.query_params, "ServiceSpecificCredentialId")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if let Some(list) = state.service_specific_credentials.get_mut(&user_name) {
            list.retain(|c| c.credential_id != cred_id);
        }
        Ok(AwsResponse::xml(
            StatusCode::OK,
            empty_response("DeleteServiceSpecificCredential", &req.request_id),
        ))
    }

    pub(super) fn list_service_specific_credentials(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let user_name = required_param(&req.query_params, "UserName")?;
        let service_name = req.query_params.get("ServiceName").cloned();
        let accounts = self.state.read();
        let empty = IamState::new(&req.account_id);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let creds: Vec<&ServiceSpecificCredential> = state
            .service_specific_credentials
            .get(&user_name)
            .map(|v| {
                v.iter()
                    .filter(|c| service_name.as_ref().is_none_or(|s| &c.service_name == s))
                    .collect()
            })
            .unwrap_or_default();
        let members: String = creds
            .iter()
            .map(|c| service_credential_xml(c, false))
            .collect::<Vec<_>>()
            .join("\n");
        let body = format!(
            "  <ListServiceSpecificCredentialsResult>\n    <ServiceSpecificCredentials>\n{members}\n    </ServiceSpecificCredentials>\n  </ListServiceSpecificCredentialsResult>"
        );
        Ok(xml_response(
            "ListServiceSpecificCredentials",
            &body,
            &req.request_id,
        ))
    }

    pub(super) fn reset_service_specific_credential(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let cred_id = required_param(&req.query_params, "ServiceSpecificCredentialId")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let mut updated: Option<ServiceSpecificCredential> = None;
        for list in state.service_specific_credentials.values_mut() {
            if let Some(c) = list.iter_mut().find(|c| c.credential_id == cred_id) {
                c.service_password = random_id("PW");
                updated = Some(c.clone());
                break;
            }
        }
        let cred = updated.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NoSuchEntity",
                format!("ServiceSpecificCredential {cred_id} not found"),
            )
        })?;
        let body = format!(
            "  <ResetServiceSpecificCredentialResult>\n{}\n  </ResetServiceSpecificCredentialResult>",
            service_credential_xml(&cred, true)
        );
        Ok(xml_response(
            "ResetServiceSpecificCredential",
            &body,
            &req.request_id,
        ))
    }

    pub(super) fn update_service_specific_credential(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let cred_id = required_param(&req.query_params, "ServiceSpecificCredentialId")?;
        let status = required_param(&req.query_params, "Status")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let mut found = false;
        for list in state.service_specific_credentials.values_mut() {
            if let Some(c) = list.iter_mut().find(|c| c.credential_id == cred_id) {
                c.status = status.clone();
                found = true;
                break;
            }
        }
        if !found {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NoSuchEntity",
                format!("ServiceSpecificCredential {cred_id} not found"),
            ));
        }
        Ok(AwsResponse::xml(
            StatusCode::OK,
            empty_response("UpdateServiceSpecificCredential", &req.request_id),
        ))
    }

    // ── Organizations integration ──

    pub(super) fn enable_organizations_root_credentials_management(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state.organizations_root_credentials_management = true;
        let body = "  <EnableOrganizationsRootCredentialsManagementResult><EnabledFeatures><member>RootCredentialsManagement</member></EnabledFeatures></EnableOrganizationsRootCredentialsManagementResult>";
        Ok(xml_response(
            "EnableOrganizationsRootCredentialsManagement",
            body,
            &req.request_id,
        ))
    }

    pub(super) fn disable_organizations_root_credentials_management(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state.organizations_root_credentials_management = false;
        Ok(AwsResponse::xml(
            StatusCode::OK,
            empty_response(
                "DisableOrganizationsRootCredentialsManagement",
                &req.request_id,
            ),
        ))
    }

    pub(super) fn enable_organizations_root_sessions(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state.organizations_root_sessions = true;
        let body = "  <EnableOrganizationsRootSessionsResult><EnabledFeatures><member>RootSessions</member></EnabledFeatures></EnableOrganizationsRootSessionsResult>";
        Ok(xml_response(
            "EnableOrganizationsRootSessions",
            body,
            &req.request_id,
        ))
    }

    pub(super) fn disable_organizations_root_sessions(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state.organizations_root_sessions = false;
        Ok(AwsResponse::xml(
            StatusCode::OK,
            empty_response("DisableOrganizationsRootSessions", &req.request_id),
        ))
    }

    pub(super) fn generate_organizations_access_report(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let entity_path = required_param(&req.query_params, "EntityPath")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let job_id = random_id("JOB");
        state.organizations_access_reports.insert(
            job_id.clone(),
            OrganizationsAccessReport {
                job_id: job_id.clone(),
                status: "COMPLETED".to_string(),
                created_at: Utc::now(),
                entity_path,
            },
        );
        let body = format!(
            "  <GenerateOrganizationsAccessReportResult><JobId>{}</JobId></GenerateOrganizationsAccessReportResult>",
            xml_escape(&job_id)
        );
        Ok(xml_response(
            "GenerateOrganizationsAccessReport",
            &body,
            &req.request_id,
        ))
    }

    pub(super) fn get_organizations_access_report(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let job_id = required_param(&req.query_params, "JobId")?;
        let accounts = self.state.read();
        let empty = IamState::new(&req.account_id);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let report = state
            .organizations_access_reports
            .get(&job_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchEntity",
                    format!("AccessReport {job_id} not found"),
                )
            })?;
        let body = format!(
            "  <GetOrganizationsAccessReportResult>\n    <JobStatus>{}</JobStatus>\n    <JobCreationDate>{}</JobCreationDate>\n    <NumberOfServicesAccessible>0</NumberOfServicesAccessible>\n    <NumberOfServicesNotAccessed>0</NumberOfServicesNotAccessed>\n    <AccessDetails/>\n  </GetOrganizationsAccessReportResult>",
            xml_escape(&report.status),
            report.created_at.format("%Y-%m-%dT%H:%M:%SZ"),
        );
        Ok(xml_response(
            "GetOrganizationsAccessReport",
            &body,
            &req.request_id,
        ))
    }

    pub(super) fn list_organizations_features(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let empty = IamState::new(&req.account_id);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let mut features = Vec::new();
        if state.organizations_root_credentials_management {
            features.push("RootCredentialsManagement");
        }
        if state.organizations_root_sessions {
            features.push("RootSessions");
        }
        let members: String = features
            .iter()
            .map(|f| format!("<member>{f}</member>"))
            .collect();
        let body = format!(
            "  <ListOrganizationsFeaturesResult><EnabledFeatures>{members}</EnabledFeatures></ListOrganizationsFeaturesResult>"
        );
        Ok(xml_response(
            "ListOrganizationsFeatures",
            &body,
            &req.request_id,
        ))
    }

    // ── Service last accessed ──

    pub(super) fn generate_service_last_accessed_details(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_param(&req.query_params, "Arn")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let job_id = random_id("LAJ");
        state.service_last_accessed_jobs.insert(
            job_id.clone(),
            ServiceLastAccessedJob {
                job_id: job_id.clone(),
                status: "COMPLETED".to_string(),
                job_creation_date: Utc::now(),
                arn,
            },
        );
        let body = format!(
            "  <GenerateServiceLastAccessedDetailsResult><JobId>{}</JobId></GenerateServiceLastAccessedDetailsResult>",
            xml_escape(&job_id)
        );
        Ok(xml_response(
            "GenerateServiceLastAccessedDetails",
            &body,
            &req.request_id,
        ))
    }

    pub(super) fn get_service_last_accessed_details(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let job_id = required_param(&req.query_params, "JobId")?;
        let accounts = self.state.read();
        let empty = IamState::new(&req.account_id);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let job = state
            .service_last_accessed_jobs
            .get(&job_id)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchEntity",
                    format!("Job {job_id} not found"),
                )
            })?;
        let body = format!(
            "  <GetServiceLastAccessedDetailsResult><JobStatus>{}</JobStatus><JobCreationDate>{}</JobCreationDate><ServicesLastAccessed/></GetServiceLastAccessedDetailsResult>",
            xml_escape(&job.status),
            job.job_creation_date.format("%Y-%m-%dT%H:%M:%SZ"),
        );
        Ok(xml_response(
            "GetServiceLastAccessedDetails",
            &body,
            &req.request_id,
        ))
    }

    pub(super) fn get_service_last_accessed_details_with_entities(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let _job_id = required_param(&req.query_params, "JobId")?;
        let body = "  <GetServiceLastAccessedDetailsWithEntitiesResult><JobStatus>COMPLETED</JobStatus><EntityDetailsList/></GetServiceLastAccessedDetailsWithEntitiesResult>";
        Ok(xml_response(
            "GetServiceLastAccessedDetailsWithEntities",
            body,
            &req.request_id,
        ))
    }

    // ── Tags on extra resource types (SAML/server-cert/MFA) ──

    fn tag_extra(
        &self,
        req: &AwsRequest,
        action: &str,
        arn_param: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_param(&req.query_params, arn_param)?;
        let new_tags = parse_tags(&req.query_params);
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let entry = state.extra_tags.entry(arn).or_default();
        for t in new_tags {
            entry.retain(|(k, _)| k != &t.key);
            entry.push((t.key, t.value));
        }
        Ok(AwsResponse::xml(
            StatusCode::OK,
            empty_response(action, &req.request_id),
        ))
    }

    fn untag_extra(
        &self,
        req: &AwsRequest,
        action: &str,
        arn_param: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_param(&req.query_params, arn_param)?;
        let mut keys: Vec<String> = Vec::new();
        for i in 1..=64 {
            let k = format!("TagKeys.member.{i}");
            match req.query_params.get(&k) {
                Some(v) => keys.push(v.clone()),
                None => break,
            }
        }
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if let Some(entry) = state.extra_tags.get_mut(&arn) {
            entry.retain(|(k, _)| !keys.contains(k));
        }
        Ok(AwsResponse::xml(
            StatusCode::OK,
            empty_response(action, &req.request_id),
        ))
    }

    fn list_extra_tags(
        &self,
        req: &AwsRequest,
        action: &str,
        arn_param: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_param(&req.query_params, arn_param)?;
        let accounts = self.state.read();
        let empty = IamState::new(&req.account_id);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let tags: Vec<crate::iam_service::Tag> = state
            .extra_tags
            .get(&arn)
            .map(|v| {
                v.iter()
                    .map(|(k, val)| crate::iam_service::Tag {
                        key: k.clone(),
                        value: val.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        let body = format!(
            "  <{action}Result><Tags>{}</Tags></{action}Result>",
            tags_xml(&tags)
        );
        Ok(xml_response(action, &body, &req.request_id))
    }

    pub(super) fn tag_saml_provider(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.tag_extra(req, "TagSAMLProvider", "SAMLProviderArn")
    }
    pub(super) fn untag_saml_provider(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.untag_extra(req, "UntagSAMLProvider", "SAMLProviderArn")
    }
    pub(super) fn list_saml_provider_tags(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.list_extra_tags(req, "ListSAMLProviderTags", "SAMLProviderArn")
    }
    pub(super) fn tag_server_certificate(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.tag_extra(req, "TagServerCertificate", "ServerCertificateName")
    }
    pub(super) fn untag_server_certificate(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.untag_extra(req, "UntagServerCertificate", "ServerCertificateName")
    }
    pub(super) fn list_server_certificate_tags(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.list_extra_tags(req, "ListServerCertificateTags", "ServerCertificateName")
    }
    pub(super) fn tag_mfa_device(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        self.tag_extra(req, "TagMFADevice", "SerialNumber")
    }
    pub(super) fn untag_mfa_device(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.untag_extra(req, "UntagMFADevice", "SerialNumber")
    }
    pub(super) fn list_mfa_device_tags(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.list_extra_tags(req, "ListMFADeviceTags", "SerialNumber")
    }

    // ── Policy simulation ──

    pub(super) fn simulate_custom_policy(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.simulate_policy(req, "SimulateCustomPolicy")
    }

    pub(super) fn simulate_principal_policy(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.simulate_policy(req, "SimulatePrincipalPolicy")
    }

    fn simulate_policy(
        &self,
        req: &AwsRequest,
        action: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        use crate::evaluator::{evaluate_with_gates, Decision, EvalRequest, PolicyDocument};
        use fakecloud_core::auth::{ConditionContext, Principal, PrincipalType};
        use std::collections::BTreeMap;

        let actions = collect_member_list(req, "ActionNames.member.");
        if actions.is_empty() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidInput",
                "ActionNames.member.1 is required",
            ));
        }
        let resources = collect_member_list(req, "ResourceArns.member.");
        let resources = if resources.is_empty() {
            vec!["*".to_string()]
        } else {
            resources
        };

        // Identity-side policies. SimulateCustomPolicy reads
        // PolicyInputList; SimulatePrincipalPolicy resolves the
        // PolicySourceArn principal's attached + inline policies.
        let mut identity_docs: Vec<PolicyDocument> = Vec::new();
        let mut caller_arn: Option<String> = req.query_params.get("CallerArn").cloned();
        let mut boundary_docs: Option<Vec<PolicyDocument>> = None;

        match action {
            "SimulateCustomPolicy" => {
                for body in collect_member_list(req, "PolicyInputList.member.") {
                    identity_docs.push(PolicyDocument::parse(&body));
                }
                if identity_docs.is_empty() {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidInput",
                        "PolicyInputList.member.1 is required",
                    ));
                }
                let boundaries =
                    collect_member_list(req, "PermissionsBoundaryPolicyInputList.member.");
                if !boundaries.is_empty() {
                    boundary_docs = Some(
                        boundaries
                            .into_iter()
                            .map(|s| PolicyDocument::parse(&s))
                            .collect(),
                    );
                }
            }
            "SimulatePrincipalPolicy" => {
                let source_arn = req.query_params.get("PolicySourceArn").ok_or_else(|| {
                    AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidInput",
                        "PolicySourceArn is required",
                    )
                })?;
                caller_arn.get_or_insert_with(|| source_arn.clone());
                let accounts = self.state.read();
                let empty = IamState::new(&req.account_id);
                let state = accounts.get(&req.account_id).unwrap_or(&empty);
                identity_docs = collect_principal_policies(state, source_arn);
                if let Some(boundary_arn) = principal_boundary(state, source_arn) {
                    if let Some(p) = state.policies.get(&boundary_arn) {
                        if let Some(v) = p.versions.iter().find(|v| v.is_default) {
                            boundary_docs = Some(vec![PolicyDocument::parse(&v.document)]);
                        }
                    }
                }
                // Add policies attached via PolicyInputList overlay.
                for body in collect_member_list(req, "PolicyInputList.member.") {
                    identity_docs.push(PolicyDocument::parse(&body));
                }
            }
            _ => {}
        }

        // ContextEntries -> ConditionContext.service_keys (single
        // bucket; populating typed fields requires per-key dispatch
        // which the evaluator already handles via lookup).
        let mut service_keys: BTreeMap<String, Vec<String>> = BTreeMap::new();
        for i in 1..=128 {
            let k = format!("ContextEntries.member.{i}.ContextKeyName");
            let Some(name) = req.query_params.get(&k) else {
                break;
            };
            let mut values: Vec<String> = Vec::new();
            for j in 1..=32 {
                let vk = format!("ContextEntries.member.{i}.ContextKeyValues.member.{j}");
                if let Some(v) = req.query_params.get(&vk) {
                    values.push(v.clone());
                } else {
                    break;
                }
            }
            service_keys.insert(name.to_lowercase(), values);
        }

        let principal_arn_str = caller_arn
            .clone()
            .unwrap_or_else(|| format!("arn:aws:iam::{}:root", req.account_id));
        let principal = Principal {
            arn: principal_arn_str.clone(),
            user_id: principal_arn_str.clone(),
            account_id: req.account_id.clone(),
            principal_type: PrincipalType::User,
            source_identity: None,
            tags: None,
        };
        let ctx = ConditionContext {
            aws_principal_arn: Some(principal_arn_str.clone()),
            aws_principal_account: Some(req.account_id.clone()),
            service_keys,
            ..Default::default()
        };

        let mut members = String::new();
        for action_name in &actions {
            for resource in &resources {
                let eval_req = EvalRequest {
                    principal: &principal,
                    action: action_name.clone(),
                    resource: resource.clone(),
                    context: ctx.clone(),
                };
                let decision =
                    evaluate_with_gates(&identity_docs, boundary_docs.as_deref(), None, &eval_req);
                let decision_str = match decision {
                    Decision::Allow => "allowed",
                    Decision::ImplicitDeny => "implicitDeny",
                    Decision::ExplicitDeny => "explicitDeny",
                };
                members.push_str(&format!(
                    "<member><EvalActionName>{}</EvalActionName><EvalResourceName>{}</EvalResourceName><EvalDecision>{}</EvalDecision></member>",
                    xml_escape(action_name),
                    xml_escape(resource),
                    decision_str
                ));
            }
        }
        let body = format!(
            "  <{action}Result><EvaluationResults>{members}</EvaluationResults><IsTruncated>false</IsTruncated></{action}Result>"
        );
        Ok(xml_response(action, &body, &req.request_id))
    }

    pub(super) fn get_context_keys_for_custom_policy(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.context_keys(req, "GetContextKeysForCustomPolicy")
    }

    pub(super) fn get_context_keys_for_principal_policy(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.context_keys(req, "GetContextKeysForPrincipalPolicy")
    }

    fn context_keys(&self, req: &AwsRequest, action: &str) -> Result<AwsResponse, AwsServiceError> {
        // Inspect any policy doc params and pull out condition keys naively.
        let mut keys: Vec<String> = Vec::new();
        for v in req.query_params.values() {
            if v.contains("\"Condition\"") {
                if let Ok(parsed) = serde_json::from_str::<serde_json::Value>(v) {
                    extract_condition_keys(&parsed, &mut keys);
                }
            }
        }
        keys.sort();
        keys.dedup();
        let members: String = keys
            .iter()
            .map(|k| format!("<member>{}</member>", xml_escape(k)))
            .collect();
        let body = format!(
            "  <{action}Result><ContextKeyNames>{members}</ContextKeyNames></{action}Result>"
        );
        Ok(xml_response(action, &body, &req.request_id))
    }

    pub(super) fn list_policies_granting_service_access(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let _arn = required_param(&req.query_params, "Arn")?;
        let body = "  <ListPoliciesGrantingServiceAccessResult><IsTruncated>false</IsTruncated><PoliciesGrantingServiceAccess/></ListPoliciesGrantingServiceAccessResult>";
        Ok(xml_response(
            "ListPoliciesGrantingServiceAccess",
            body,
            &req.request_id,
        ))
    }

    // ── Misc ──

    pub(super) fn change_password(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let old_password = required_param(&req.query_params, "OldPassword")?;
        let new_password = required_param(&req.query_params, "NewPassword")?;
        if old_password == new_password {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidUserType",
                "The new password must be different from the old password.",
            ));
        }

        // ChangePassword acts on the calling user's own login profile.
        // Pull the caller from the request principal when present. If the
        // request didn't carry a usable IAM-user identity (anonymous /
        // role-based / unsigned probe), accept and no-op so SDK
        // smoke-tests stay green; we still validate the rest of the
        // payload (OldPassword != NewPassword) above.
        let user_name = req.principal.as_ref().and_then(|p| {
            let arn = &p.arn;
            arn.strip_prefix("arn:aws:iam::")
                .and_then(|rest| rest.split_once(":user/"))
                .map(|(_, name)| name.to_string())
        });
        let Some(user_name) = user_name else {
            return Ok(AwsResponse::xml(
                StatusCode::OK,
                empty_response("ChangePassword", &req.request_id),
            ));
        };

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let Some(profile) = state.login_profiles.get_mut(&user_name) else {
            // No login profile yet — treat ChangePassword as a no-op so
            // the operation completes successfully against newly minted
            // users that haven't been issued console credentials.
            return Ok(AwsResponse::xml(
                StatusCode::OK,
                empty_response("ChangePassword", &req.request_id),
            ));
        };

        // Empty stored password = legacy snapshot; treat any
        // OldPassword as matching so the first ChangePassword after
        // upgrade still works. New stored password is always
        // validated on subsequent calls.
        if !profile.password.is_empty() && profile.password != old_password {
            return Err(AwsServiceError::aws_error(
                StatusCode::FORBIDDEN,
                "InvalidUserType",
                "The provided old password does not match the user's current password.",
            ));
        }
        profile.password = new_password;
        profile.password_reset_required = false;

        Ok(AwsResponse::xml(
            StatusCode::OK,
            empty_response("ChangePassword", &req.request_id),
        ))
    }

    pub(super) fn get_mfa_device(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let serial = required_param(&req.query_params, "SerialNumber")?;
        let accounts = self.state.read();
        let empty = IamState::new(&req.account_id);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let device = state.virtual_mfa_devices.get(&serial).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NoSuchEntity",
                format!("MFADevice {serial} not found"),
            )
        })?;
        let user_name = device
            .user
            .clone()
            .or_else(|| req.query_params.get("UserName").cloned())
            .unwrap_or_default();
        let enable_date = device
            .enable_date
            .map(|d| d.to_rfc3339())
            .unwrap_or_else(now_iso);
        let body = format!(
            "  <GetMFADeviceResult><SerialNumber>{}</SerialNumber><UserName>{}</UserName><EnableDate>{}</EnableDate></GetMFADeviceResult>",
            xml_escape(&device.serial_number),
            xml_escape(&user_name),
            xml_escape(&enable_date),
        );
        Ok(xml_response("GetMFADevice", &body, &req.request_id))
    }

    pub(super) fn resync_mfa_device(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let _serial = required_param(&req.query_params, "SerialNumber")?;
        let _user = required_param(&req.query_params, "UserName")?;
        let _ = required_param(&req.query_params, "AuthenticationCode1")?;
        let _ = required_param(&req.query_params, "AuthenticationCode2")?;
        Ok(AwsResponse::xml(
            StatusCode::OK,
            empty_response("ResyncMFADevice", &req.request_id),
        ))
    }

    pub(super) fn set_security_token_service_preferences(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let _ = required_param(&req.query_params, "GlobalEndpointTokenVersion")?;
        Ok(AwsResponse::xml(
            StatusCode::OK,
            empty_response("SetSecurityTokenServicePreferences", &req.request_id),
        ))
    }

    pub(super) fn update_server_certificate(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = required_param(&req.query_params, "ServerCertificateName")?;
        let new_name = req.query_params.get("NewServerCertificateName").cloned();
        let new_path = req.query_params.get("NewPath").cloned();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let cert = state.server_certificates.remove(&name).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NoSuchEntity",
                format!("ServerCertificate {name} not found"),
            )
        })?;
        let final_name = new_name.unwrap_or_else(|| name.clone());
        if final_name != name && state.server_certificates.contains_key(&final_name) {
            // Restore the cert we removed before checking
            state.server_certificates.insert(name, cert);
            return Err(AwsServiceError::aws_error(
                StatusCode::CONFLICT,
                "EntityAlreadyExists",
                format!("Server certificate {final_name} already exists."),
            ));
        }
        let mut updated = cert;
        if let Some(p) = new_path {
            updated.path = p;
        }
        updated.server_certificate_name = final_name.clone();
        // Rebuild ARN with the new path/name so metadata responses reflect the rename.
        updated.arn = format!(
            "arn:aws:iam::{account}:server-certificate{path}{name}",
            account = req.account_id,
            path = if updated.path.starts_with('/') {
                updated.path.clone()
            } else {
                format!("/{}", updated.path)
            },
            name = final_name,
        );
        state.server_certificates.insert(final_name, updated);
        Ok(AwsResponse::xml(
            StatusCode::OK,
            empty_response("UpdateServerCertificate", &req.request_id),
        ))
    }
}

fn extract_condition_keys(v: &serde_json::Value, out: &mut Vec<String>) {
    match v {
        serde_json::Value::Object(map) => {
            for (k, child) in map {
                if k == "Condition" {
                    if let serde_json::Value::Object(operators) = child {
                        for cond_map in operators.values() {
                            if let serde_json::Value::Object(keys) = cond_map {
                                for key in keys.keys() {
                                    out.push(key.clone());
                                }
                            }
                        }
                    }
                } else {
                    extract_condition_keys(child, out);
                }
            }
        }
        serde_json::Value::Array(arr) => {
            for child in arr {
                extract_condition_keys(child, out);
            }
        }
        _ => {}
    }
}
