//! Handlers added to close the IAM conformance gap. Service-specific
//! credentials, delegation requests, organizations integration, outbound
//! web identity federation, service-last-accessed jobs, extra resource
//! tagging surfaces, policy simulation, and miscellaneous credentials
//! maintenance ops.

use chrono::Utc;
use http::StatusCode;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::state::{
    DelegationRequest, IamState, OrganizationsAccessReport, OutboundWebIdentityFederation,
    ServiceLastAccessedJob, ServiceSpecificCredential,
};

use super::{empty_response, parse_tags, required_param, tags_xml, IamService};

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

fn delegation_request_xml(d: &DelegationRequest) -> String {
    let perms: String = d
        .permissions
        .iter()
        .map(|p| format!("      <member>{}</member>", xml_escape(p)))
        .collect::<Vec<_>>()
        .join("\n");
    format!(
        "<DelegationRequest>\
         <DelegationRequestId>{}</DelegationRequestId>\
         <SourceAccount>{}</SourceAccount>\
         <TargetAccount>{}</TargetAccount>\
         <Status>{}</Status>\
         <CreateDate>{}</CreateDate>\
         <Permissions>{}</Permissions>\
         </DelegationRequest>",
        xml_escape(&d.id),
        xml_escape(&d.source_account),
        xml_escape(&d.target_account),
        xml_escape(&d.status),
        d.create_date.format("%Y-%m-%dT%H:%M:%SZ"),
        perms,
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

    // ── Delegation requests ──

    pub(super) fn create_delegation_request(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let target = required_param(&req.query_params, "TargetAccount")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let id = random_id("DR-");
        let dr = DelegationRequest {
            id: id.clone(),
            source_account: state.account_id.clone(),
            target_account: target,
            status: "Pending".to_string(),
            create_date: Utc::now(),
            permissions: Vec::new(),
        };
        state.delegation_requests.insert(id.clone(), dr.clone());
        let body = format!(
            "  <CreateDelegationRequestResult>{}</CreateDelegationRequestResult>",
            delegation_request_xml(&dr)
        );
        Ok(xml_response(
            "CreateDelegationRequest",
            &body,
            &req.request_id,
        ))
    }

    pub(super) fn accept_delegation_request(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.update_delegation_status(req, "AcceptDelegationRequest", "Accepted")
    }

    pub(super) fn reject_delegation_request(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.update_delegation_status(req, "RejectDelegationRequest", "Rejected")
    }

    pub(super) fn associate_delegation_request(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        self.update_delegation_status(req, "AssociateDelegationRequest", "Associated")
    }

    pub(super) fn update_delegation_request(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = required_param(&req.query_params, "DelegationRequestId")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let dr = state.delegation_requests.get_mut(&id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NoSuchEntity",
                format!("DelegationRequest {id} not found"),
            )
        })?;
        if let Some(s) = req.query_params.get("Status") {
            dr.status = s.clone();
        }
        Ok(AwsResponse::xml(
            StatusCode::OK,
            empty_response("UpdateDelegationRequest", &req.request_id),
        ))
    }

    fn update_delegation_status(
        &self,
        req: &AwsRequest,
        action: &str,
        new_status: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = required_param(&req.query_params, "DelegationRequestId")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let dr = state.delegation_requests.get_mut(&id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NoSuchEntity",
                format!("DelegationRequest {id} not found"),
            )
        })?;
        dr.status = new_status.to_string();
        Ok(AwsResponse::xml(
            StatusCode::OK,
            empty_response(action, &req.request_id),
        ))
    }

    pub(super) fn get_delegation_request(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = required_param(&req.query_params, "DelegationRequestId")?;
        let accounts = self.state.read();
        let empty = IamState::new(&req.account_id);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let dr = state.delegation_requests.get(&id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "NoSuchEntity",
                format!("DelegationRequest {id} not found"),
            )
        })?;
        let body = format!(
            "  <GetDelegationRequestResult>{}</GetDelegationRequestResult>",
            delegation_request_xml(dr)
        );
        Ok(xml_response("GetDelegationRequest", &body, &req.request_id))
    }

    pub(super) fn list_delegation_requests(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let empty = IamState::new(&req.account_id);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let members: String = state
            .delegation_requests
            .values()
            .map(delegation_request_xml)
            .collect::<Vec<_>>()
            .join("\n");
        let body = format!(
            "  <ListDelegationRequestsResult>\n    <DelegationRequests>{members}</DelegationRequests>\n  </ListDelegationRequestsResult>"
        );
        Ok(xml_response(
            "ListDelegationRequests",
            &body,
            &req.request_id,
        ))
    }

    pub(super) fn send_delegation_token(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let _id = required_param(&req.query_params, "DelegationRequestId")?;
        let body = format!(
            "  <SendDelegationTokenResult><Token>{}</Token></SendDelegationTokenResult>",
            random_id("TOK")
        );
        Ok(xml_response("SendDelegationToken", &body, &req.request_id))
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

    // ── Outbound web identity federation ──

    pub(super) fn enable_outbound_web_identity_federation(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let issuer = req
            .query_params
            .get("IssuerUrl")
            .cloned()
            .unwrap_or_default();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state.outbound_web_identity_federation = Some(OutboundWebIdentityFederation {
            enabled: true,
            issuer_url: issuer,
            audience: Vec::new(),
        });
        Ok(AwsResponse::xml(
            StatusCode::OK,
            empty_response("EnableOutboundWebIdentityFederation", &req.request_id),
        ))
    }

    pub(super) fn disable_outbound_web_identity_federation(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if let Some(ref mut cfg) = state.outbound_web_identity_federation {
            cfg.enabled = false;
        }
        Ok(AwsResponse::xml(
            StatusCode::OK,
            empty_response("DisableOutboundWebIdentityFederation", &req.request_id),
        ))
    }

    pub(super) fn get_outbound_web_identity_federation_info(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let empty = IamState::new(&req.account_id);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let (enabled, issuer) = state
            .outbound_web_identity_federation
            .as_ref()
            .map(|c| (c.enabled, c.issuer_url.clone()))
            .unwrap_or((false, String::new()));
        let body = format!(
            "  <GetOutboundWebIdentityFederationInfoResult><Enabled>{enabled}</Enabled><IssuerUrl>{}</IssuerUrl></GetOutboundWebIdentityFederationInfoResult>",
            xml_escape(&issuer)
        );
        Ok(xml_response(
            "GetOutboundWebIdentityFederationInfo",
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
        // Collect ActionNames to echo back as evaluation results.
        let mut actions: Vec<String> = Vec::new();
        for i in 1..=64 {
            let k = format!("ActionNames.member.{i}");
            match req.query_params.get(&k) {
                Some(v) => actions.push(v.clone()),
                None => break,
            }
        }
        let results: String = actions
            .iter()
            .map(|a| {
                format!(
                    "<member><EvalActionName>{}</EvalActionName><EvalDecision>allowed</EvalDecision><EvalResourceName>*</EvalResourceName></member>",
                    xml_escape(a)
                )
            })
            .collect();
        let body = format!(
            "  <{action}Result><EvaluationResults>{results}</EvaluationResults><IsTruncated>false</IsTruncated></{action}Result>"
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
        let _ = required_param(&req.query_params, "OldPassword")?;
        let _ = required_param(&req.query_params, "NewPassword")?;
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

    pub(super) fn get_human_readable_summary(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = "  <GetHumanReadableSummaryResult><Summary>FakeCloud IAM emulator account summary</Summary></GetHumanReadableSummaryResult>";
        Ok(xml_response(
            "GetHumanReadableSummary",
            body,
            &req.request_id,
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
