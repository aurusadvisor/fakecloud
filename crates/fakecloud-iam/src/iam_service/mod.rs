mod account;
mod extras;
mod groups;
mod instance_profiles;
mod oidc;
mod policies;
mod roles;
mod users;

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use http::StatusCode;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
// NOTE: The shared validation helpers use ValidationException error codes, but real IAM
// typically returns InvalidInput or ValidationError for input validation failures. This is
// a known simplification — the validators are reused across services for consistency.
use fakecloud_core::validation::*;
use fakecloud_persistence::SnapshotStore;

use crate::persistence::{save_iam_snapshot, IamSnapshotLock};
use crate::state::{AccessKeyLastUsed, SharedIamState, Tag};

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

pub struct IamService {
    state: SharedIamState,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    snapshot_lock: IamSnapshotLock,
}

impl IamService {
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

    /// Share the snapshot lock with another service (e.g. `StsService`)
    /// so writes from both services are mutually serialized. Without
    /// this, STS-issued credentials and IAM mutations could race and
    /// leave stale bytes on disk.
    pub fn with_snapshot_lock(mut self, lock: IamSnapshotLock) -> Self {
        self.snapshot_lock = lock;
        self
    }

    pub fn snapshot_lock(&self) -> IamSnapshotLock {
        self.snapshot_lock.clone()
    }

    pub fn snapshot_store(&self) -> Option<Arc<dyn SnapshotStore>> {
        self.snapshot_store.clone()
    }
}

/// Actions on the IAM service that mutate state. Kept in sync with the
/// dispatch table in `handle`.
fn is_mutating_action(action: &str) -> bool {
    matches!(
        action,
        "CreateUser"
            | "DeleteUser"
            | "UpdateUser"
            | "TagUser"
            | "UntagUser"
            | "CreateAccessKey"
            | "DeleteAccessKey"
            | "UpdateAccessKey"
            | "CreateRole"
            | "DeleteRole"
            | "UpdateRole"
            | "UpdateRoleDescription"
            | "UpdateAssumeRolePolicy"
            | "TagRole"
            | "UntagRole"
            | "PutRolePermissionsBoundary"
            | "DeleteRolePermissionsBoundary"
            | "CreatePolicy"
            | "DeletePolicy"
            | "TagPolicy"
            | "UntagPolicy"
            | "CreatePolicyVersion"
            | "DeletePolicyVersion"
            | "SetDefaultPolicyVersion"
            | "AttachRolePolicy"
            | "DetachRolePolicy"
            | "PutRolePolicy"
            | "DeleteRolePolicy"
            | "AttachUserPolicy"
            | "DetachUserPolicy"
            | "PutUserPolicy"
            | "DeleteUserPolicy"
            | "PutUserPermissionsBoundary"
            | "DeleteUserPermissionsBoundary"
            | "CreateGroup"
            | "DeleteGroup"
            | "UpdateGroup"
            | "AddUserToGroup"
            | "RemoveUserFromGroup"
            | "PutGroupPolicy"
            | "DeleteGroupPolicy"
            | "AttachGroupPolicy"
            | "DetachGroupPolicy"
            | "CreateInstanceProfile"
            | "DeleteInstanceProfile"
            | "AddRoleToInstanceProfile"
            | "RemoveRoleFromInstanceProfile"
            | "TagInstanceProfile"
            | "UntagInstanceProfile"
            | "CreateLoginProfile"
            | "UpdateLoginProfile"
            | "DeleteLoginProfile"
            | "CreateSAMLProvider"
            | "DeleteSAMLProvider"
            | "UpdateSAMLProvider"
            | "CreateOpenIDConnectProvider"
            | "DeleteOpenIDConnectProvider"
            | "UpdateOpenIDConnectProviderThumbprint"
            | "AddClientIDToOpenIDConnectProvider"
            | "RemoveClientIDFromOpenIDConnectProvider"
            | "TagOpenIDConnectProvider"
            | "UntagOpenIDConnectProvider"
            | "UploadServerCertificate"
            | "DeleteServerCertificate"
            | "UploadSigningCertificate"
            | "UpdateSigningCertificate"
            | "DeleteSigningCertificate"
            | "UploadSSHPublicKey"
            | "UpdateSSHPublicKey"
            | "DeleteSSHPublicKey"
            | "CreateServiceLinkedRole"
            | "DeleteServiceLinkedRole"
            | "CreateAccountAlias"
            | "DeleteAccountAlias"
            | "UpdateAccountPasswordPolicy"
            | "DeleteAccountPasswordPolicy"
            | "GenerateCredentialReport"
            | "CreateVirtualMFADevice"
            | "DeleteVirtualMFADevice"
            | "EnableMFADevice"
            | "DeactivateMFADevice"
            | "UpdateServerCertificate"
            | "ChangePassword"
            | "ResyncMFADevice"
            | "SetSecurityTokenServicePreferences"
            | "TagSAMLProvider"
            | "UntagSAMLProvider"
            | "TagServerCertificate"
            | "UntagServerCertificate"
            | "TagMFADevice"
            | "UntagMFADevice"
            | "CreateServiceSpecificCredential"
            | "DeleteServiceSpecificCredential"
            | "ResetServiceSpecificCredential"
            | "UpdateServiceSpecificCredential"
            | "CreateDelegationRequest"
            | "AcceptDelegationRequest"
            | "RejectDelegationRequest"
            | "AssociateDelegationRequest"
            | "UpdateDelegationRequest"
            | "SendDelegationToken"
            | "EnableOrganizationsRootCredentialsManagement"
            | "DisableOrganizationsRootCredentialsManagement"
            | "EnableOrganizationsRootSessions"
            | "DisableOrganizationsRootSessions"
            | "GenerateOrganizationsAccessReport"
            | "EnableOutboundWebIdentityFederation"
            | "DisableOutboundWebIdentityFederation"
            | "GenerateServiceLastAccessedDetails"
    )
}

#[async_trait]
impl AwsService for IamService {
    fn service_name(&self) -> &str {
        "iam"
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        // Track access key usage for GetAccessKeyLastUsed. This is itself
        // a state mutation, so we have to flag it for snapshot persistence
        // even though the action itself may be read-only (e.g. `ListUsers`).
        // Without this, `access_key_last_used` drifts between in-memory
        // and on-disk state and reads after a restart lose the timestamp.
        let mut last_used_updated = false;
        if let Some(ref key_id) = req.access_key_id {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&req.account_id);
            let is_known = state
                .access_keys
                .values()
                .any(|keys| keys.iter().any(|k| k.access_key_id == *key_id));
            if is_known {
                state.access_key_last_used.insert(
                    key_id.clone(),
                    AccessKeyLastUsed {
                        last_used_date: Utc::now(),
                        service_name: "iam".to_string(),
                        region: req.region.clone(),
                    },
                );
                last_used_updated = true;
            }
            drop(accounts);
        }

        let mutates = is_mutating_action(req.action.as_str()) || last_used_updated;
        let result = match req.action.as_str() {
            // Users
            "CreateUser" => self.create_user(&req),
            "GetUser" => self.get_user(&req),
            "DeleteUser" => self.delete_user(&req),
            "ListUsers" => self.list_users(&req),
            "UpdateUser" => self.update_user(&req),
            "TagUser" => self.tag_user(&req),
            "UntagUser" => self.untag_user(&req),
            "ListUserTags" => self.list_user_tags(&req),

            // Access Keys
            "CreateAccessKey" => self.create_access_key(&req),
            "DeleteAccessKey" => self.delete_access_key(&req),
            "ListAccessKeys" => self.list_access_keys(&req),
            "UpdateAccessKey" => self.update_access_key(&req),
            "GetAccessKeyLastUsed" => self.get_access_key_last_used(&req),

            // Roles
            "CreateRole" => self.create_role(&req),
            "GetRole" => self.get_role(&req),
            "DeleteRole" => self.delete_role(&req),
            "ListRoles" => self.list_roles(&req),
            "UpdateRole" => self.update_role(&req),
            "UpdateRoleDescription" => self.update_role_description(&req),
            "UpdateAssumeRolePolicy" => self.update_assume_role_policy(&req),
            "TagRole" => self.tag_role(&req),
            "UntagRole" => self.untag_role(&req),
            "ListRoleTags" => self.list_role_tags(&req),
            "PutRolePermissionsBoundary" => self.put_role_permissions_boundary(&req),
            "DeleteRolePermissionsBoundary" => self.delete_role_permissions_boundary(&req),

            // Policies (managed)
            "CreatePolicy" => self.create_policy(&req),
            "GetPolicy" => self.get_policy(&req),
            "DeletePolicy" => self.delete_policy(&req),
            "ListPolicies" => self.list_policies(&req),
            "TagPolicy" => self.tag_policy(&req),
            "UntagPolicy" => self.untag_policy(&req),
            "ListPolicyTags" => self.list_policy_tags(&req),

            // Policy Versions
            "CreatePolicyVersion" => self.create_policy_version(&req),
            "GetPolicyVersion" => self.get_policy_version(&req),
            "ListPolicyVersions" => self.list_policy_versions(&req),
            "DeletePolicyVersion" => self.delete_policy_version(&req),
            "SetDefaultPolicyVersion" => self.set_default_policy_version(&req),

            // Role policy attachments (managed)
            "AttachRolePolicy" => self.attach_role_policy(&req),
            "DetachRolePolicy" => self.detach_role_policy(&req),
            "ListAttachedRolePolicies" => self.list_attached_role_policies(&req),

            // Role inline policies
            "PutRolePolicy" => self.put_role_policy(&req),
            "GetRolePolicy" => self.get_role_policy(&req),
            "DeleteRolePolicy" => self.delete_role_policy(&req),
            "ListRolePolicies" => self.list_role_policies(&req),

            // User policy attachments (managed)
            "AttachUserPolicy" => self.attach_user_policy(&req),
            "DetachUserPolicy" => self.detach_user_policy(&req),
            "ListAttachedUserPolicies" => self.list_attached_user_policies(&req),

            // User inline policies
            "PutUserPolicy" => self.put_user_policy(&req),
            "GetUserPolicy" => self.get_user_policy(&req),
            "DeleteUserPolicy" => self.delete_user_policy(&req),
            "ListUserPolicies" => self.list_user_policies(&req),
            "PutUserPermissionsBoundary" => self.put_user_permissions_boundary(&req),
            "DeleteUserPermissionsBoundary" => self.delete_user_permissions_boundary(&req),

            // Groups
            "CreateGroup" => self.create_group(&req),
            "GetGroup" => self.get_group(&req),
            "DeleteGroup" => self.delete_group(&req),
            "ListGroups" => self.list_groups(&req),
            "UpdateGroup" => self.update_group(&req),
            "AddUserToGroup" => self.add_user_to_group(&req),
            "RemoveUserFromGroup" => self.remove_user_from_group(&req),
            "ListGroupsForUser" => self.list_groups_for_user(&req),

            // Group policies
            "PutGroupPolicy" => self.put_group_policy(&req),
            "GetGroupPolicy" => self.get_group_policy(&req),
            "DeleteGroupPolicy" => self.delete_group_policy(&req),
            "ListGroupPolicies" => self.list_group_policies(&req),
            "AttachGroupPolicy" => self.attach_group_policy(&req),
            "DetachGroupPolicy" => self.detach_group_policy(&req),
            "ListAttachedGroupPolicies" => self.list_attached_group_policies(&req),

            // Instance Profiles
            "CreateInstanceProfile" => self.create_instance_profile(&req),
            "GetInstanceProfile" => self.get_instance_profile(&req),
            "DeleteInstanceProfile" => self.delete_instance_profile(&req),
            "ListInstanceProfiles" => self.list_instance_profiles(&req),
            "AddRoleToInstanceProfile" => self.add_role_to_instance_profile(&req),
            "RemoveRoleFromInstanceProfile" => self.remove_role_from_instance_profile(&req),
            "ListInstanceProfilesForRole" => self.list_instance_profiles_for_role(&req),
            "TagInstanceProfile" => self.tag_instance_profile(&req),
            "UntagInstanceProfile" => self.untag_instance_profile(&req),
            "ListInstanceProfileTags" => self.list_instance_profile_tags(&req),

            // Login Profiles
            "CreateLoginProfile" => self.create_login_profile(&req),
            "GetLoginProfile" => self.get_login_profile(&req),
            "UpdateLoginProfile" => self.update_login_profile(&req),
            "DeleteLoginProfile" => self.delete_login_profile(&req),

            // SAML Providers
            "CreateSAMLProvider" => self.create_saml_provider(&req),
            "GetSAMLProvider" => self.get_saml_provider(&req),
            "DeleteSAMLProvider" => self.delete_saml_provider(&req),
            "ListSAMLProviders" => self.list_saml_providers(&req),
            "UpdateSAMLProvider" => self.update_saml_provider(&req),

            // OIDC Providers
            "CreateOpenIDConnectProvider" => self.create_oidc_provider(&req),
            "GetOpenIDConnectProvider" => self.get_oidc_provider(&req),
            "DeleteOpenIDConnectProvider" => self.delete_oidc_provider(&req),
            "ListOpenIDConnectProviders" => self.list_oidc_providers(&req),
            "UpdateOpenIDConnectProviderThumbprint" => self.update_oidc_thumbprint(&req),
            "AddClientIDToOpenIDConnectProvider" => self.add_client_id_to_oidc(&req),
            "RemoveClientIDFromOpenIDConnectProvider" => self.remove_client_id_from_oidc(&req),
            "TagOpenIDConnectProvider" => self.tag_oidc_provider(&req),
            "UntagOpenIDConnectProvider" => self.untag_oidc_provider(&req),
            "ListOpenIDConnectProviderTags" => self.list_oidc_provider_tags(&req),

            // Server Certificates
            "UploadServerCertificate" => self.upload_server_certificate(&req),
            "GetServerCertificate" => self.get_server_certificate(&req),
            "DeleteServerCertificate" => self.delete_server_certificate(&req),
            "ListServerCertificates" => self.list_server_certificates(&req),

            // Signing Certificates
            "UploadSigningCertificate" => self.upload_signing_certificate(&req),
            "ListSigningCertificates" => self.list_signing_certificates(&req),
            "UpdateSigningCertificate" => self.update_signing_certificate(&req),
            "DeleteSigningCertificate" => self.delete_signing_certificate(&req),

            // SSH Public Keys
            "UploadSSHPublicKey" => self.upload_ssh_public_key(&req),
            "GetSSHPublicKey" => self.get_ssh_public_key(&req),
            "ListSSHPublicKeys" => self.list_ssh_public_keys(&req),
            "UpdateSSHPublicKey" => self.update_ssh_public_key(&req),
            "DeleteSSHPublicKey" => self.delete_ssh_public_key(&req),

            // Service Linked Roles
            "CreateServiceLinkedRole" => self.create_service_linked_role(&req),
            "DeleteServiceLinkedRole" => self.delete_service_linked_role(&req),
            "GetServiceLinkedRoleDeletionStatus" => {
                self.get_service_linked_role_deletion_status(&req)
            }

            // Account
            "GetAccountSummary" => self.get_account_summary(&req),
            "GetAccountAuthorizationDetails" => self.get_account_authorization_details(&req),
            "CreateAccountAlias" => self.create_account_alias(&req),
            "DeleteAccountAlias" => self.delete_account_alias(&req),
            "ListAccountAliases" => self.list_account_aliases(&req),
            "UpdateAccountPasswordPolicy" => self.update_account_password_policy(&req),
            "GetAccountPasswordPolicy" => self.get_account_password_policy(&req),
            "DeleteAccountPasswordPolicy" => self.delete_account_password_policy(&req),

            // Credential Report
            "GenerateCredentialReport" => self.generate_credential_report(&req),
            "GetCredentialReport" => self.get_credential_report(&req),

            // Virtual MFA Devices
            "CreateVirtualMFADevice" => self.create_virtual_mfa_device(&req),
            "DeleteVirtualMFADevice" => self.delete_virtual_mfa_device(&req),
            "ListVirtualMFADevices" => self.list_virtual_mfa_devices(&req),
            "EnableMFADevice" => self.enable_mfa_device(&req),
            "DeactivateMFADevice" => self.deactivate_mfa_device(&req),
            "ListMFADevices" => self.list_mfa_devices(&req),

            // Entities for policy
            "ListEntitiesForPolicy" => self.list_entities_for_policy(&req),

            // Service-specific credentials
            "CreateServiceSpecificCredential" => self.create_service_specific_credential(&req),
            "DeleteServiceSpecificCredential" => self.delete_service_specific_credential(&req),
            "ListServiceSpecificCredentials" => self.list_service_specific_credentials(&req),
            "ResetServiceSpecificCredential" => self.reset_service_specific_credential(&req),
            "UpdateServiceSpecificCredential" => self.update_service_specific_credential(&req),

            // Delegation requests
            "CreateDelegationRequest" => self.create_delegation_request(&req),
            "AcceptDelegationRequest" => self.accept_delegation_request(&req),
            "RejectDelegationRequest" => self.reject_delegation_request(&req),
            "AssociateDelegationRequest" => self.associate_delegation_request(&req),
            "GetDelegationRequest" => self.get_delegation_request(&req),
            "ListDelegationRequests" => self.list_delegation_requests(&req),
            "UpdateDelegationRequest" => self.update_delegation_request(&req),
            "SendDelegationToken" => self.send_delegation_token(&req),

            // Organizations integration
            "EnableOrganizationsRootCredentialsManagement" => {
                self.enable_organizations_root_credentials_management(&req)
            }
            "DisableOrganizationsRootCredentialsManagement" => {
                self.disable_organizations_root_credentials_management(&req)
            }
            "EnableOrganizationsRootSessions" => self.enable_organizations_root_sessions(&req),
            "DisableOrganizationsRootSessions" => self.disable_organizations_root_sessions(&req),
            "GenerateOrganizationsAccessReport" => self.generate_organizations_access_report(&req),
            "GetOrganizationsAccessReport" => self.get_organizations_access_report(&req),
            "ListOrganizationsFeatures" => self.list_organizations_features(&req),

            // Outbound web identity federation
            "EnableOutboundWebIdentityFederation" => {
                self.enable_outbound_web_identity_federation(&req)
            }
            "DisableOutboundWebIdentityFederation" => {
                self.disable_outbound_web_identity_federation(&req)
            }
            "GetOutboundWebIdentityFederationInfo" => {
                self.get_outbound_web_identity_federation_info(&req)
            }

            // Service last accessed details
            "GenerateServiceLastAccessedDetails" => {
                self.generate_service_last_accessed_details(&req)
            }
            "GetServiceLastAccessedDetails" => self.get_service_last_accessed_details(&req),
            "GetServiceLastAccessedDetailsWithEntities" => {
                self.get_service_last_accessed_details_with_entities(&req)
            }

            // Tags on more resource types
            "TagSAMLProvider" => self.tag_saml_provider(&req),
            "UntagSAMLProvider" => self.untag_saml_provider(&req),
            "ListSAMLProviderTags" => self.list_saml_provider_tags(&req),
            "TagServerCertificate" => self.tag_server_certificate(&req),
            "UntagServerCertificate" => self.untag_server_certificate(&req),
            "ListServerCertificateTags" => self.list_server_certificate_tags(&req),
            "TagMFADevice" => self.tag_mfa_device(&req),
            "UntagMFADevice" => self.untag_mfa_device(&req),
            "ListMFADeviceTags" => self.list_mfa_device_tags(&req),

            // Policy simulation
            "SimulateCustomPolicy" => self.simulate_custom_policy(&req),
            "SimulatePrincipalPolicy" => self.simulate_principal_policy(&req),
            "GetContextKeysForCustomPolicy" => self.get_context_keys_for_custom_policy(&req),
            "GetContextKeysForPrincipalPolicy" => self.get_context_keys_for_principal_policy(&req),
            "ListPoliciesGrantingServiceAccess" => self.list_policies_granting_service_access(&req),

            // Misc
            "ChangePassword" => self.change_password(&req),
            "GetMFADevice" => self.get_mfa_device(&req),
            "ResyncMFADevice" => self.resync_mfa_device(&req),
            "GetHumanReadableSummary" => self.get_human_readable_summary(&req),
            "SetSecurityTokenServicePreferences" => {
                self.set_security_token_service_preferences(&req)
            }
            "UpdateServerCertificate" => self.update_server_certificate(&req),

            _ => Err(AwsServiceError::action_not_implemented("iam", &req.action)),
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
        SUPPORTED_ACTIONS
    }

    /// IAM opts into Phase 1 enforcement. Every action in
    /// [`SUPPORTED_ACTIONS`] maps to a concrete `IamAction` — see
    /// [`iam_action_resource`] for the resource-ARN extraction logic.
    fn iam_enforceable(&self) -> bool {
        true
    }

    fn iam_action_for(&self, request: &AwsRequest) -> Option<fakecloud_core::auth::IamAction> {
        // The action list is small enough to reuse SUPPORTED_ACTIONS as
        // the whitelist: anything we didn't declare support for isn't
        // enforced (and would be handled as action_not_implemented by
        // the match in `handle()`).
        let static_action = SUPPORTED_ACTIONS
            .iter()
            .copied()
            .find(|a| *a == request.action)?;
        let account = request
            .principal
            .as_ref()
            .map(|p| p.account_id.as_str())
            .unwrap_or(request.account_id.as_str());
        let partition = partition_for_region(&request.region);
        Some(fakecloud_core::auth::IamAction {
            service: "iam",
            action: static_action,
            resource: iam_action_resource(static_action, partition, account, request),
        })
    }

    fn resource_tags_for(
        &self,
        resource_arn: &str,
    ) -> Option<std::collections::HashMap<String, String>> {
        iam_resource_tags(&self.state, resource_arn)
    }

    fn request_tags_from(
        &self,
        request: &AwsRequest,
        action: &str,
    ) -> Option<std::collections::HashMap<String, String>> {
        iam_request_tags(request, action)
    }
}

/// Look up resource tags for an IAM ARN.
///
/// IAM ARN formats:
/// - `arn:{p}:iam::{account}:user/{path/}name`
/// - `arn:{p}:iam::{account}:role/{path/}name`
/// - `arn:{p}:iam::{account}:policy/{path/}name`
/// - `arn:{p}:iam::{account}:instance-profile/{path/}name`
/// - `*` for account-level operations
fn iam_resource_tags(
    state: &SharedIamState,
    resource_arn: &str,
) -> Option<std::collections::HashMap<String, String>> {
    if resource_arn == "*" {
        return Some(std::collections::HashMap::new());
    }
    // Parse the resource segment after the 6th colon
    let parts: Vec<&str> = resource_arn.split(':').collect();
    if parts.len() < 6 {
        return None;
    }
    let resource = parts[5];
    let account_id = parts.get(4).copied().unwrap_or("");
    let accounts = state.read();
    let state = accounts.get(account_id)?;
    if let Some(rest) = resource.strip_prefix("user/") {
        let name = rest.rsplit('/').next().unwrap_or(rest);
        state
            .users
            .get(name)
            .map(|u| tags_to_hashmap_or_empty(&u.tags))
    } else if let Some(rest) = resource.strip_prefix("role/") {
        let name = rest.rsplit('/').next().unwrap_or(rest);
        state
            .roles
            .get(name)
            .map(|r| tags_to_hashmap_or_empty(&r.tags))
    } else if resource.starts_with("policy/") {
        // Policies are keyed by full ARN
        state
            .policies
            .get(resource_arn)
            .map(|p| tags_to_hashmap_or_empty(&p.tags))
    } else if let Some(rest) = resource.strip_prefix("instance-profile/") {
        let name = rest.rsplit('/').next().unwrap_or(rest);
        state
            .instance_profiles
            .get(name)
            .map(|ip| tags_to_hashmap_or_empty(&ip.tags))
    } else {
        Some(std::collections::HashMap::new())
    }
}

fn tags_to_hashmap_or_empty(tags: &[Tag]) -> std::collections::HashMap<String, String> {
    tags.iter()
        .map(|t| (t.key.clone(), t.value.clone()))
        .collect()
}

/// Extract request tags from IAM operations that accept tags.
fn iam_request_tags(
    request: &AwsRequest,
    action: &str,
) -> Option<std::collections::HashMap<String, String>> {
    const TAG_ACTIONS: &[&str] = &[
        "CreateUser",
        "TagUser",
        "CreateRole",
        "TagRole",
        "CreatePolicy",
        "TagPolicy",
        "CreateInstanceProfile",
        "TagInstanceProfile",
        "CreateOpenIDConnectProvider",
        "TagOpenIDConnectProvider",
        "CreateSAMLProvider",
        "TagSAMLProvider",
        "UploadServerCertificate",
        "TagServerCertificate",
    ];
    if TAG_ACTIONS.contains(&action) {
        let tags = parse_tags(&request.query_params);
        Some(tags.into_iter().map(|t| (t.key, t.value)).collect())
    } else {
        Some(std::collections::HashMap::new())
    }
}

/// Derive the fully-qualified IAM resource ARN for a given action +
/// request. Reads the relevant parameter (UserName, RoleName, PolicyArn,
/// etc.) from the request's query params or body. Falls back to `*` when
/// the action targets no specific resource (e.g. `ListUsers`,
/// `GetAccountSummary`) or the parameter is missing.
///
/// IAM resources follow a small set of shapes
/// (`user/`, `role/`, `group/`, `policy/`, `instance-profile/`,
/// `mfa/`, `server-certificate/`, `saml-provider/`, `oidc-provider/`).
/// Each action is classified by which shape it targets.
fn iam_action_resource(
    action: &str,
    partition: &str,
    account: &str,
    request: &AwsRequest,
) -> String {
    let params = &request.query_params;
    let wildcard = || "*".to_string();
    let user_arn = |name: &str| format!("arn:{}:iam::{}:user/{}", partition, account, name);
    let role_arn = |name: &str| format!("arn:{}:iam::{}:role/{}", partition, account, name);
    let group_arn = |name: &str| format!("arn:{}:iam::{}:group/{}", partition, account, name);
    let policy_arn = |name: &str| format!("arn:{}:iam::{}:policy/{}", partition, account, name);
    let profile_arn = |name: &str| {
        format!(
            "arn:{}:iam::{}:instance-profile/{}",
            partition, account, name
        )
    };
    let mfa_arn = |name: &str| format!("arn:{}:iam::{}:mfa/{}", partition, account, name);
    let server_cert_arn = |name: &str| {
        format!(
            "arn:{}:iam::{}:server-certificate/{}",
            partition, account, name
        )
    };

    // User-scoped actions: read `UserName` from params. Missing -> wildcard.
    let user_scoped: &[&str] = &[
        "CreateUser",
        "GetUser",
        "DeleteUser",
        "UpdateUser",
        "TagUser",
        "UntagUser",
        "ListUserTags",
        "CreateAccessKey",
        "DeleteAccessKey",
        "ListAccessKeys",
        "UpdateAccessKey",
        "GetAccessKeyLastUsed",
        "CreateLoginProfile",
        "GetLoginProfile",
        "DeleteLoginProfile",
        "UpdateLoginProfile",
        "AttachUserPolicy",
        "DetachUserPolicy",
        "ListAttachedUserPolicies",
        "PutUserPolicy",
        "GetUserPolicy",
        "DeleteUserPolicy",
        "ListUserPolicies",
        "PutUserPermissionsBoundary",
        "DeleteUserPermissionsBoundary",
        "AddUserToGroup",
        "RemoveUserFromGroup",
        "ListGroupsForUser",
        "EnableMFADevice",
        "DeactivateMFADevice",
        "ListMFADevices",
        "UploadSSHPublicKey",
        "GetSSHPublicKey",
        "UpdateSSHPublicKey",
        "DeleteSSHPublicKey",
        "ListSSHPublicKeys",
        "UploadSigningCertificate",
        "UpdateSigningCertificate",
        "DeleteSigningCertificate",
        "ListSigningCertificates",
    ];

    // Role-scoped actions: read `RoleName` from params.
    let role_scoped: &[&str] = &[
        "CreateRole",
        "GetRole",
        "DeleteRole",
        "UpdateRole",
        "UpdateRoleDescription",
        "UpdateAssumeRolePolicy",
        "TagRole",
        "UntagRole",
        "ListRoleTags",
        "PutRolePermissionsBoundary",
        "DeleteRolePermissionsBoundary",
        "AttachRolePolicy",
        "DetachRolePolicy",
        "ListAttachedRolePolicies",
        "PutRolePolicy",
        "GetRolePolicy",
        "DeleteRolePolicy",
        "ListRolePolicies",
        // NOTE: CreateServiceLinkedRole excluded — its target resource is
        // built from `AWSServiceName`, not `RoleName`, and is handled in
        // the match block below (identified by cubic on PR #395).
        // GetServiceLinkedRoleDeletionStatus is also excluded — it
        // operates on a deletion-task id rather than a role name; it
        // falls through to the wildcard branch below.
        "DeleteServiceLinkedRole",
        "ListInstanceProfilesForRole",
    ];

    // Group-scoped actions: read `GroupName` from params.
    let group_scoped: &[&str] = &[
        "CreateGroup",
        "GetGroup",
        "DeleteGroup",
        "UpdateGroup",
        "PutGroupPolicy",
        "GetGroupPolicy",
        "DeleteGroupPolicy",
        "ListGroupPolicies",
        "AttachGroupPolicy",
        "DetachGroupPolicy",
        "ListAttachedGroupPolicies",
    ];

    // Policy-scoped actions: read `PolicyArn` from params (ARN in place).
    let policy_scoped_arn: &[&str] = &[
        "GetPolicy",
        "DeletePolicy",
        "TagPolicy",
        "UntagPolicy",
        "ListPolicyTags",
        "CreatePolicyVersion",
        "GetPolicyVersion",
        "ListPolicyVersions",
        "DeletePolicyVersion",
        "SetDefaultPolicyVersion",
        "ListEntitiesForPolicy",
    ];

    // Instance-profile-scoped actions: read `InstanceProfileName`.
    let profile_scoped: &[&str] = &[
        "CreateInstanceProfile",
        "GetInstanceProfile",
        "DeleteInstanceProfile",
        "TagInstanceProfile",
        "UntagInstanceProfile",
        "ListInstanceProfileTags",
        "AddRoleToInstanceProfile",
        "RemoveRoleFromInstanceProfile",
    ];

    if user_scoped.contains(&action) {
        return params
            .get("UserName")
            .map(|n| user_arn(n))
            .unwrap_or_else(wildcard);
    }
    if role_scoped.contains(&action) {
        return params
            .get("RoleName")
            .map(|n| role_arn(n))
            .unwrap_or_else(wildcard);
    }
    if group_scoped.contains(&action) {
        return params
            .get("GroupName")
            .map(|n| group_arn(n))
            .unwrap_or_else(wildcard);
    }
    if policy_scoped_arn.contains(&action) {
        return params.get("PolicyArn").cloned().unwrap_or_else(wildcard);
    }
    if profile_scoped.contains(&action) {
        return params
            .get("InstanceProfileName")
            .map(|n| profile_arn(n))
            .unwrap_or_else(wildcard);
    }

    match action {
        // CreatePolicy: target ARN is the to-be-created policy.
        "CreatePolicy" => params
            .get("PolicyName")
            .map(|n| policy_arn(n))
            .unwrap_or_else(wildcard),
        // Service-linked roles are created by AWS service name, not
        // role name. Their ARNs follow the `role/aws-service-role/<svc>`
        // convention (identified by cubic on PR #395).
        "CreateServiceLinkedRole" => params
            .get("AWSServiceName")
            .map(|svc| {
                format!(
                    "arn:{}:iam::{}:role/aws-service-role/{}",
                    partition, account, svc
                )
            })
            .unwrap_or_else(wildcard),
        // MFA actions keyed by SerialNumber (which is the mfa ARN itself
        // for virtual devices, a plain string for hardware devices).
        "CreateVirtualMFADevice" => params
            .get("VirtualMFADeviceName")
            .map(|n| mfa_arn(n))
            .unwrap_or_else(wildcard),
        "DeleteVirtualMFADevice" => params.get("SerialNumber").cloned().unwrap_or_else(wildcard),
        // Note: ResyncMFADevice is not in SUPPORTED_ACTIONS and so
        // never reaches this match — if it's added later, handle
        // `SerialNumber` here.
        // Server certificates keyed by ServerCertificateName.
        "UploadServerCertificate" | "GetServerCertificate" | "DeleteServerCertificate" => params
            .get("ServerCertificateName")
            .map(|n| server_cert_arn(n))
            .unwrap_or_else(wildcard),
        // SAML / OIDC providers reference their ARN directly.
        "CreateSAMLProvider" => params
            .get("Name")
            .map(|n| format!("arn:{}:iam::{}:saml-provider/{}", partition, account, n))
            .unwrap_or_else(wildcard),
        "UpdateSAMLProvider" | "DeleteSAMLProvider" | "GetSAMLProvider" => params
            .get("SAMLProviderArn")
            .cloned()
            .unwrap_or_else(wildcard),
        "CreateOpenIDConnectProvider" => params
            .get("Url")
            .map(|u| {
                format!(
                    "arn:{}:iam::{}:oidc-provider/{}",
                    partition,
                    account,
                    u.trim_start_matches("https://")
                )
            })
            .unwrap_or_else(wildcard),
        "GetOpenIDConnectProvider"
        | "DeleteOpenIDConnectProvider"
        | "AddClientIDToOpenIDConnectProvider"
        | "RemoveClientIDFromOpenIDConnectProvider"
        | "UpdateOpenIDConnectProviderThumbprint"
        | "TagOpenIDConnectProvider"
        | "UntagOpenIDConnectProvider"
        | "ListOpenIDConnectProviderTags" => params
            .get("OpenIDConnectProviderArn")
            .cloned()
            .unwrap_or_else(wildcard),
        // Account-scoped / listing actions have no per-resource target.
        "ListUsers"
        | "ListRoles"
        | "ListGroups"
        | "ListPolicies"
        | "ListInstanceProfiles"
        | "ListVirtualMFADevices"
        | "ListServerCertificates"
        | "ListSAMLProviders"
        | "ListOpenIDConnectProviders"
        | "ListAccountAliases"
        | "CreateAccountAlias"
        | "DeleteAccountAlias"
        | "GetAccountSummary"
        | "GetAccountAuthorizationDetails"
        | "GenerateCredentialReport"
        | "GetCredentialReport"
        | "GetAccountPasswordPolicy"
        | "UpdateAccountPasswordPolicy"
        | "DeleteAccountPasswordPolicy" => wildcard(),
        // Anything we didn't classify above — be conservative.
        _ => wildcard(),
    }
}

/// All IAM actions fakecloud handles. Promoted to a file-level const so
/// the `supported_actions()` method body is one line and the action
/// list is easy to grep / diff over time. Same shape as the logs
/// equivalent introduced in PR #336.
const SUPPORTED_ACTIONS: &[&str] = &[
    "CreateUser",
    "GetUser",
    "DeleteUser",
    "ListUsers",
    "UpdateUser",
    "TagUser",
    "UntagUser",
    "ListUserTags",
    "CreateAccessKey",
    "DeleteAccessKey",
    "ListAccessKeys",
    "UpdateAccessKey",
    "GetAccessKeyLastUsed",
    "CreateRole",
    "GetRole",
    "DeleteRole",
    "ListRoles",
    "UpdateRole",
    "UpdateRoleDescription",
    "UpdateAssumeRolePolicy",
    "TagRole",
    "UntagRole",
    "ListRoleTags",
    "PutRolePermissionsBoundary",
    "DeleteRolePermissionsBoundary",
    "CreatePolicy",
    "GetPolicy",
    "DeletePolicy",
    "ListPolicies",
    "TagPolicy",
    "UntagPolicy",
    "ListPolicyTags",
    "CreatePolicyVersion",
    "GetPolicyVersion",
    "ListPolicyVersions",
    "DeletePolicyVersion",
    "SetDefaultPolicyVersion",
    "AttachRolePolicy",
    "DetachRolePolicy",
    "ListAttachedRolePolicies",
    "PutRolePolicy",
    "GetRolePolicy",
    "DeleteRolePolicy",
    "ListRolePolicies",
    "AttachUserPolicy",
    "DetachUserPolicy",
    "ListAttachedUserPolicies",
    "PutUserPolicy",
    "GetUserPolicy",
    "DeleteUserPolicy",
    "ListUserPolicies",
    "PutUserPermissionsBoundary",
    "DeleteUserPermissionsBoundary",
    "CreateGroup",
    "GetGroup",
    "DeleteGroup",
    "ListGroups",
    "UpdateGroup",
    "AddUserToGroup",
    "RemoveUserFromGroup",
    "ListGroupsForUser",
    "PutGroupPolicy",
    "GetGroupPolicy",
    "DeleteGroupPolicy",
    "ListGroupPolicies",
    "AttachGroupPolicy",
    "DetachGroupPolicy",
    "ListAttachedGroupPolicies",
    "CreateInstanceProfile",
    "GetInstanceProfile",
    "DeleteInstanceProfile",
    "ListInstanceProfiles",
    "AddRoleToInstanceProfile",
    "RemoveRoleFromInstanceProfile",
    "ListInstanceProfilesForRole",
    "TagInstanceProfile",
    "UntagInstanceProfile",
    "ListInstanceProfileTags",
    "CreateLoginProfile",
    "GetLoginProfile",
    "UpdateLoginProfile",
    "DeleteLoginProfile",
    "CreateSAMLProvider",
    "GetSAMLProvider",
    "DeleteSAMLProvider",
    "ListSAMLProviders",
    "UpdateSAMLProvider",
    "CreateOpenIDConnectProvider",
    "GetOpenIDConnectProvider",
    "DeleteOpenIDConnectProvider",
    "ListOpenIDConnectProviders",
    "UpdateOpenIDConnectProviderThumbprint",
    "AddClientIDToOpenIDConnectProvider",
    "RemoveClientIDFromOpenIDConnectProvider",
    "TagOpenIDConnectProvider",
    "UntagOpenIDConnectProvider",
    "ListOpenIDConnectProviderTags",
    "UploadServerCertificate",
    "GetServerCertificate",
    "DeleteServerCertificate",
    "ListServerCertificates",
    "UploadSigningCertificate",
    "ListSigningCertificates",
    "UpdateSigningCertificate",
    "DeleteSigningCertificate",
    "CreateServiceLinkedRole",
    "DeleteServiceLinkedRole",
    "GetServiceLinkedRoleDeletionStatus",
    "GetAccountSummary",
    "GetAccountAuthorizationDetails",
    "CreateAccountAlias",
    "DeleteAccountAlias",
    "ListAccountAliases",
    "UpdateAccountPasswordPolicy",
    "GetAccountPasswordPolicy",
    "DeleteAccountPasswordPolicy",
    "GenerateCredentialReport",
    "GetCredentialReport",
    "CreateVirtualMFADevice",
    "DeleteVirtualMFADevice",
    "ListVirtualMFADevices",
    "EnableMFADevice",
    "DeactivateMFADevice",
    "ListMFADevices",
    "ListEntitiesForPolicy",
    "UploadSSHPublicKey",
    "GetSSHPublicKey",
    "ListSSHPublicKeys",
    "UpdateSSHPublicKey",
    "DeleteSSHPublicKey",
    "CreateServiceSpecificCredential",
    "DeleteServiceSpecificCredential",
    "ListServiceSpecificCredentials",
    "ResetServiceSpecificCredential",
    "UpdateServiceSpecificCredential",
    "CreateDelegationRequest",
    "AcceptDelegationRequest",
    "RejectDelegationRequest",
    "AssociateDelegationRequest",
    "GetDelegationRequest",
    "ListDelegationRequests",
    "UpdateDelegationRequest",
    "SendDelegationToken",
    "EnableOrganizationsRootCredentialsManagement",
    "DisableOrganizationsRootCredentialsManagement",
    "EnableOrganizationsRootSessions",
    "DisableOrganizationsRootSessions",
    "GenerateOrganizationsAccessReport",
    "GetOrganizationsAccessReport",
    "ListOrganizationsFeatures",
    "EnableOutboundWebIdentityFederation",
    "DisableOutboundWebIdentityFederation",
    "GetOutboundWebIdentityFederationInfo",
    "GenerateServiceLastAccessedDetails",
    "GetServiceLastAccessedDetails",
    "GetServiceLastAccessedDetailsWithEntities",
    "TagSAMLProvider",
    "UntagSAMLProvider",
    "ListSAMLProviderTags",
    "TagServerCertificate",
    "UntagServerCertificate",
    "ListServerCertificateTags",
    "TagMFADevice",
    "UntagMFADevice",
    "ListMFADeviceTags",
    "SimulateCustomPolicy",
    "SimulatePrincipalPolicy",
    "GetContextKeysForCustomPolicy",
    "GetContextKeysForPrincipalPolicy",
    "ListPoliciesGrantingServiceAccess",
    "ChangePassword",
    "GetMFADevice",
    "ResyncMFADevice",
    "GetHumanReadableSummary",
    "SetSecurityTokenServicePreferences",
    "UpdateServerCertificate",
];

/// Extract the caller's access key from the request's Authorization header.
fn extract_access_key(req: &AwsRequest) -> Option<String> {
    let auth = req.headers.get("authorization")?.to_str().ok()?;
    let info = fakecloud_aws::sigv4::parse_sigv4(auth)?;
    Some(info.access_key)
}

// ========= Helper functions =========

/// Convert a hyphenated service name to title case, handling known abbreviations.
fn title_case_service(s: &str) -> String {
    s.split('-')
        .map(|w| {
            // Known abbreviation mappings
            match w {
                "autoscaling" => "AutoScaling".to_string(),
                "loadbalancing" => "LoadBalancing".to_string(),
                "mapreduce" => "MapReduce".to_string(),
                "beanstalk" => "Beanstalk".to_string(),
                _ => {
                    let mut c = w.chars();
                    match c.next() {
                        None => String::new(),
                        Some(ch) => ch.to_uppercase().to_string() + c.as_str(),
                    }
                }
            }
        })
        .collect::<String>()
}

use fakecloud_aws::xml::xml_escape;

fn url_encode(s: &str) -> String {
    use std::fmt::Write;
    let mut result = String::new();
    for byte in s.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                result.push(byte as char);
            }
            _ => {
                write!(result, "%{:02X}", byte).unwrap();
            }
        }
    }
    result
}

fn required_param(
    params: &std::collections::HashMap<String, String>,
    name: &str,
) -> Result<String, AwsServiceError> {
    fakecloud_core::query::required_param(params, name)
}

/// Resolve the calling user when UserName is not provided.
/// Returns the first user found or a default "default" name.
fn resolve_calling_user(state: &crate::state::IamState, _account_id: &str) -> String {
    // In a real implementation, we'd look up the user from the access key.
    // For simplicity, return the first user or "default".
    state
        .users
        .keys()
        .next()
        .cloned()
        .unwrap_or_else(|| "default".to_string())
}

fn generate_id() -> String {
    // Generate 16 uppercase hex chars (used with 4-char prefixes like FKIA, AIDA = 20 chars)
    uuid::Uuid::new_v4()
        .to_string()
        .replace('-', "")
        .to_uppercase()[..16]
        .to_string()
}

fn generate_long_id() -> String {
    // Generate 21 uppercase hex chars (used with 3-char prefixes like ASC = 24 chars).
    // CertificateId requires minimum 24 characters.
    uuid::Uuid::new_v4()
        .to_string()
        .replace('-', "")
        .to_uppercase()[..21]
        .to_string()
}

fn parse_tags(params: &std::collections::HashMap<String, String>) -> Vec<Tag> {
    let mut tags = Vec::new();
    let mut i = 1;
    loop {
        let key_param = format!("Tags.member.{i}.Key");
        let value_param = format!("Tags.member.{i}.Value");
        match params.get(&key_param) {
            Some(key) => {
                let value = params.get(&value_param).cloned().unwrap_or_default();
                tags.push(Tag {
                    key: key.clone(),
                    value,
                });
                i += 1;
            }
            None => break,
        }
    }
    tags
}

fn parse_tag_keys(params: &std::collections::HashMap<String, String>) -> Vec<String> {
    let mut keys = Vec::new();
    let mut i = 1;
    loop {
        let key_param = format!("TagKeys.member.{i}");
        match params.get(&key_param) {
            Some(key) => {
                keys.push(key.clone());
                i += 1;
            }
            None => break,
        }
    }
    keys
}

fn tags_xml(tags: &[Tag]) -> String {
    tags.iter()
        .map(|t| {
            format!(
                "        <member>\n          <Key>{}</Key>\n          <Value>{}</Value>\n        </member>",
                xml_escape(&t.key),
                xml_escape(&t.value)
            )
        })
        .collect::<Vec<_>>()
        .join("\n")
}

fn paginated_tags_response(
    action: &str,
    tags: &[Tag],
    req: &AwsRequest,
) -> Result<String, AwsServiceError> {
    let max_items_i64 = parse_optional_i64_param(
        "maxItems",
        req.query_params.get("MaxItems").map(|s| s.as_str()),
    )?;
    validate_optional_range_i64("maxItems", max_items_i64, 1, 1000)?;
    let max_items: usize = max_items_i64.unwrap_or(100) as usize;
    let offset: usize = req
        .query_params
        .get("Marker")
        .and_then(|v| v.parse().ok())
        .unwrap_or(0);

    let offset = offset.min(tags.len());
    let page = &tags[offset..tags.len().min(offset + max_items)];
    let is_truncated = offset + max_items < tags.len();
    let members = tags_xml(page);
    let marker = if is_truncated {
        format!("<Marker>{}</Marker>", offset + max_items)
    } else {
        String::new()
    };

    Ok(format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<{action}Response xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <{action}Result>
    <IsTruncated>{is_truncated}</IsTruncated>
    <Tags>
{members}
    </Tags>
    {marker}
  </{action}Result>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</{action}Response>"#,
        req.request_id
    ))
}

fn validate_tags(tags: &[Tag], existing_count: usize) -> Result<(), AwsServiceError> {
    // Check total tag count
    if tags.len() + existing_count > 50 {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidInput",
            "1 validation error detected: Value at 'tags' failed to satisfy constraint: Member must have length less than or equal to 50.".to_string(),
        ));
    }

    // Check for duplicate keys
    let mut seen_keys = std::collections::HashSet::new();
    for tag in tags {
        let lower = tag.key.to_lowercase();
        if !seen_keys.insert(lower) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidInput",
                "Duplicate tag keys found. Please note that Tag keys are case insensitive."
                    .to_string(),
            ));
        }

        // Key length
        if tag.key.len() > 128 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidInput",
                format!(
                    "1 validation error detected: Value at 'tags.{}.member.key' failed to satisfy constraint: Member must have length less than or equal to 128.",
                    seen_keys.len()
                ),
            ));
        }

        // Value length
        if tag.value.len() > 256 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidInput",
                format!(
                    "1 validation error detected: Value at 'tags.{}.member.value' failed to satisfy constraint: Member must have length less than or equal to 256.",
                    seen_keys.len()
                ),
            ));
        }

        // Invalid characters in key
        if !tag.key.chars().all(|c| {
            c.is_alphanumeric()
                || c == ' '
                || c == '+'
                || c == '-'
                || c == '='
                || c == '.'
                || c == '_'
                || c == ':'
                || c == '/'
                || c == '@'
        }) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidInput",
                format!(
                    "1 validation error detected: Value at 'tags.{}.member.key' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{{L}}\\p{{Z}}\\p{{N}}_.:/=+\\-@]+",
                    seen_keys.len()
                ),
            ));
        }
    }

    Ok(())
}

fn validate_untag_keys(keys: &[String]) -> Result<(), AwsServiceError> {
    if keys.len() > 50 {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationError",
            "1 validation error detected: Value at 'tagKeys' failed to satisfy constraint: Member must have length less than or equal to 50.".to_string(),
        ));
    }
    for key in keys {
        if key.len() > 128 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationError",
                "1 validation error detected: Value at 'tagKeys' failed to satisfy constraint: Member must have length less than or equal to 128.".to_string(),
            ));
        }
        if !key.chars().all(|c| {
            c.is_alphanumeric()
                || c == ' '
                || c == '+'
                || c == '-'
                || c == '='
                || c == '.'
                || c == '_'
                || c == ':'
                || c == '/'
                || c == '@'
        }) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationError",
                "1 validation error detected: Value at 'tagKeys' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\p{L}\\p{Z}\\p{N}_.:/=+\\-@]+".to_string(),
            ));
        }
    }
    Ok(())
}

fn empty_response(action: &str, request_id: &str) -> String {
    format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<{action}Response xmlns="https://iam.amazonaws.com/doc/2010-05-08/">
  <{action}Result/>
  <ResponseMetadata>
    <RequestId>{request_id}</RequestId>
  </ResponseMetadata>
</{action}Response>"#,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn make_service() -> IamService {
        let state: SharedIamState = Arc::new(RwLock::new(
            fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", ""),
        ));
        IamService::new(state)
    }

    fn make_request(action: &str, params: Vec<(&str, &str)>) -> AwsRequest {
        let mut query_params = HashMap::new();
        query_params.insert("Action".to_string(), action.to_string());
        for (k, v) in params {
            query_params.insert(k.to_string(), v.to_string());
        }
        AwsRequest {
            service: "iam".to_string(),
            action: action.to_string(),
            region: "us-east-1".to_string(),
            account_id: "123456789012".to_string(),
            request_id: "test-id".to_string(),
            headers: http::HeaderMap::new(),
            query_params,
            body: bytes::Bytes::new(),
            body_stream: parking_lot::Mutex::new(None),
            path_segments: vec![],
            raw_path: "/".to_string(),
            raw_query: String::new(),
            method: http::Method::POST,
            is_query_protocol: true,
            access_key_id: None,
            principal: None,
        }
    }

    /// Pull the text inside the first ``<tag>...</tag>`` element of ``body``.
    /// Used by IAM tests to fish an ARN out of a create-* response without
    /// pulling in a real XML parser.
    fn extract_xml_tag<'a>(body: &'a str, tag: &str) -> &'a str {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let start = body
            .find(&open)
            .unwrap_or_else(|| panic!("tag <{tag}> not found"))
            + open.len();
        let end = body
            .find(&close)
            .unwrap_or_else(|| panic!("tag </{tag}> not found"));
        &body[start..end]
    }

    #[test]
    fn list_access_keys_max_items_zero_returns_error() {
        let svc = make_service();

        // Create a user first
        let req = make_request("CreateUser", vec![("UserName", "testuser")]);
        svc.create_user(&req).unwrap();

        // Try listing access keys with MaxItems=0
        let req = make_request(
            "ListAccessKeys",
            vec![("UserName", "testuser"), ("MaxItems", "0")],
        );
        let result = svc.list_access_keys(&req);
        assert!(result.is_err(), "MaxItems=0 should return an error");
    }

    #[test]
    fn list_users_rejects_non_numeric_max_items() {
        let svc = make_service();
        let req = make_request("ListUsers", vec![("MaxItems", "abc")]);
        let result = svc.list_users(&req);
        assert!(
            result.is_err(),
            "non-numeric MaxItems should return an error"
        );
    }

    #[test]
    fn list_roles_rejects_non_numeric_max_items() {
        let svc = make_service();
        let req = make_request("ListRoles", vec![("MaxItems", "xyz")]);
        let result = svc.list_roles(&req);
        assert!(
            result.is_err(),
            "non-numeric MaxItems should return an error"
        );
    }

    #[test]
    fn list_policies_rejects_non_numeric_max_items() {
        let svc = make_service();
        let req = make_request("ListPolicies", vec![("MaxItems", "notanumber")]);
        let result = svc.list_policies(&req);
        assert!(
            result.is_err(),
            "non-numeric MaxItems should return an error"
        );
    }

    // ---- Group inline policy tests ----

    #[test]
    fn put_and_get_group_policy() {
        let svc = make_service();
        let policy_doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;

        // Create group
        svc.handle_sync("CreateGroup", vec![("GroupName", "devs")]);

        // Put inline policy
        svc.handle_sync(
            "PutGroupPolicy",
            vec![
                ("GroupName", "devs"),
                ("PolicyName", "s3-access"),
                ("PolicyDocument", policy_doc),
            ],
        );

        // Get inline policy
        let resp = svc.handle_sync(
            "GetGroupPolicy",
            vec![("GroupName", "devs"), ("PolicyName", "s3-access")],
        );
        assert!(resp.contains("s3-access"));
        assert!(resp.contains("devs"));
    }

    #[test]
    fn list_group_policies() {
        let svc = make_service();
        let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;

        svc.handle_sync("CreateGroup", vec![("GroupName", "ops")]);
        svc.handle_sync(
            "PutGroupPolicy",
            vec![
                ("GroupName", "ops"),
                ("PolicyName", "pol-a"),
                ("PolicyDocument", doc),
            ],
        );
        svc.handle_sync(
            "PutGroupPolicy",
            vec![
                ("GroupName", "ops"),
                ("PolicyName", "pol-b"),
                ("PolicyDocument", doc),
            ],
        );

        let resp = svc.handle_sync("ListGroupPolicies", vec![("GroupName", "ops")]);
        assert!(resp.contains("pol-a"));
        assert!(resp.contains("pol-b"));
    }

    #[test]
    fn delete_group_policy() {
        let svc = make_service();
        let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;

        svc.handle_sync("CreateGroup", vec![("GroupName", "team")]);
        svc.handle_sync(
            "PutGroupPolicy",
            vec![
                ("GroupName", "team"),
                ("PolicyName", "temp"),
                ("PolicyDocument", doc),
            ],
        );

        // Delete
        svc.handle_sync(
            "DeleteGroupPolicy",
            vec![("GroupName", "team"), ("PolicyName", "temp")],
        );

        // List should be empty
        let resp = svc.handle_sync("ListGroupPolicies", vec![("GroupName", "team")]);
        assert!(!resp.contains("temp"));
    }

    #[test]
    fn get_group_policy_not_found() {
        let svc = make_service();
        svc.handle_sync("CreateGroup", vec![("GroupName", "g1")]);

        let req = make_request(
            "GetGroupPolicy",
            vec![("GroupName", "g1"), ("PolicyName", "nope")],
        );
        let result = svc.get_group_policy(&req);
        assert!(result.is_err());
    }

    // ---- Group managed policy attachment tests ----

    #[test]
    fn attach_and_list_group_policies_managed() {
        let svc = make_service();
        let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;

        svc.handle_sync("CreateGroup", vec![("GroupName", "eng")]);
        svc.handle_sync(
            "CreatePolicy",
            vec![("PolicyName", "read-policy"), ("PolicyDocument", doc)],
        );

        let create_resp = svc.handle_sync(
            "CreatePolicy",
            vec![("PolicyName", "write-policy"), ("PolicyDocument", doc)],
        );
        // Extract the ARN from the second policy
        let arn_start = create_resp.find("<Arn>").unwrap() + 5;
        let arn_end = create_resp.find("</Arn>").unwrap();
        let write_arn = &create_resp[arn_start..arn_end];

        // Attach both policies - for the first one, extract its ARN too
        // Just use the write_arn which we already have
        svc.handle_sync(
            "AttachGroupPolicy",
            vec![("GroupName", "eng"), ("PolicyArn", write_arn)],
        );

        let list = svc.handle_sync("ListAttachedGroupPolicies", vec![("GroupName", "eng")]);
        assert!(list.contains("write-policy"));
    }

    #[test]
    fn detach_group_policy() {
        let svc = make_service();
        let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;

        svc.handle_sync("CreateGroup", vec![("GroupName", "detach-grp")]);
        let resp = svc.handle_sync(
            "CreatePolicy",
            vec![("PolicyName", "detach-pol"), ("PolicyDocument", doc)],
        );
        let arn = extract_xml_value(&resp, "Arn");

        svc.handle_sync(
            "AttachGroupPolicy",
            vec![("GroupName", "detach-grp"), ("PolicyArn", &arn)],
        );

        // Detach
        svc.handle_sync(
            "DetachGroupPolicy",
            vec![("GroupName", "detach-grp"), ("PolicyArn", &arn)],
        );

        let list = svc.handle_sync(
            "ListAttachedGroupPolicies",
            vec![("GroupName", "detach-grp")],
        );
        assert!(!list.contains("detach-pol"));
    }

    #[test]
    fn detach_group_policy_not_attached_fails() {
        let svc = make_service();
        svc.handle_sync("CreateGroup", vec![("GroupName", "grp-err")]);

        let req = make_request(
            "DetachGroupPolicy",
            vec![
                ("GroupName", "grp-err"),
                ("PolicyArn", "arn:aws:iam::123456789012:policy/nope"),
            ],
        );
        let result = svc.detach_group_policy(&req);
        assert!(result.is_err());
    }

    // ---- User inline policy tests ----

    #[test]
    fn put_get_delete_user_inline_policy() {
        let svc = make_service();
        let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"sqs:*","Resource":"*"}]}"#;

        svc.handle_sync("CreateUser", vec![("UserName", "alice")]);

        // Put
        svc.handle_sync(
            "PutUserPolicy",
            vec![
                ("UserName", "alice"),
                ("PolicyName", "sqs-access"),
                ("PolicyDocument", doc),
            ],
        );

        // Get
        let resp = svc.handle_sync(
            "GetUserPolicy",
            vec![("UserName", "alice"), ("PolicyName", "sqs-access")],
        );
        assert!(resp.contains("sqs-access"));
        assert!(resp.contains("alice"));

        // List
        let list = svc.handle_sync("ListUserPolicies", vec![("UserName", "alice")]);
        assert!(list.contains("sqs-access"));

        // Delete
        svc.handle_sync(
            "DeleteUserPolicy",
            vec![("UserName", "alice"), ("PolicyName", "sqs-access")],
        );

        let list = svc.handle_sync("ListUserPolicies", vec![("UserName", "alice")]);
        assert!(!list.contains("sqs-access"));
    }

    #[test]
    fn get_user_policy_not_found() {
        let svc = make_service();
        svc.handle_sync("CreateUser", vec![("UserName", "bob")]);

        let req = make_request(
            "GetUserPolicy",
            vec![("UserName", "bob"), ("PolicyName", "ghost")],
        );
        let result = svc.get_user_policy(&req);
        assert!(result.is_err());
    }

    // ---- User managed policy attachment tests ----

    #[test]
    fn attach_detach_list_user_policies_managed() {
        let svc = make_service();
        let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;

        svc.handle_sync("CreateUser", vec![("UserName", "carol")]);
        let resp = svc.handle_sync(
            "CreatePolicy",
            vec![("PolicyName", "user-pol"), ("PolicyDocument", doc)],
        );
        let arn = extract_xml_value(&resp, "Arn");

        // Attach
        svc.handle_sync(
            "AttachUserPolicy",
            vec![("UserName", "carol"), ("PolicyArn", &arn)],
        );

        // List attached
        let list = svc.handle_sync("ListAttachedUserPolicies", vec![("UserName", "carol")]);
        assert!(list.contains("user-pol"));

        // Detach
        svc.handle_sync(
            "DetachUserPolicy",
            vec![("UserName", "carol"), ("PolicyArn", &arn)],
        );

        let list = svc.handle_sync("ListAttachedUserPolicies", vec![("UserName", "carol")]);
        assert!(!list.contains("user-pol"));
    }

    #[test]
    fn attach_user_policy_nonexistent_user_fails() {
        let svc = make_service();
        let req = make_request(
            "AttachUserPolicy",
            vec![
                ("UserName", "nobody"),
                ("PolicyArn", "arn:aws:iam::123456789012:policy/x"),
            ],
        );
        let result = svc.attach_user_policy(&req);
        assert!(result.is_err());
    }

    #[test]
    fn detach_user_policy_not_attached_fails() {
        let svc = make_service();
        svc.handle_sync("CreateUser", vec![("UserName", "dave")]);

        let req = make_request(
            "DetachUserPolicy",
            vec![
                ("UserName", "dave"),
                ("PolicyArn", "arn:aws:iam::123456789012:policy/nope"),
            ],
        );
        let result = svc.detach_user_policy(&req);
        assert!(result.is_err());
    }

    // ---- Login profile tests ----

    #[test]
    fn login_profile_lifecycle() {
        let svc = make_service();
        svc.handle_sync("CreateUser", vec![("UserName", "loginuser")]);

        // Create login profile
        let resp = svc.handle_sync(
            "CreateLoginProfile",
            vec![
                ("UserName", "loginuser"),
                ("Password", "S3cureP@ss!"),
                ("PasswordResetRequired", "true"),
            ],
        );
        assert!(resp.contains("loginuser"));
        assert!(resp.contains("<PasswordResetRequired>true</PasswordResetRequired>"));

        // Get login profile
        let resp = svc.handle_sync("GetLoginProfile", vec![("UserName", "loginuser")]);
        assert!(resp.contains("loginuser"));
        assert!(resp.contains("<PasswordResetRequired>true</PasswordResetRequired>"));

        // Update login profile
        svc.handle_sync(
            "UpdateLoginProfile",
            vec![
                ("UserName", "loginuser"),
                ("PasswordResetRequired", "false"),
            ],
        );

        let resp = svc.handle_sync("GetLoginProfile", vec![("UserName", "loginuser")]);
        assert!(resp.contains("<PasswordResetRequired>false</PasswordResetRequired>"));

        // Delete login profile
        svc.handle_sync("DeleteLoginProfile", vec![("UserName", "loginuser")]);

        // Should fail now
        let req = make_request("GetLoginProfile", vec![("UserName", "loginuser")]);
        assert!(svc.get_login_profile(&req).is_err());
    }

    #[test]
    fn create_login_profile_duplicate_fails() {
        let svc = make_service();
        svc.handle_sync("CreateUser", vec![("UserName", "dupuser")]);
        svc.handle_sync(
            "CreateLoginProfile",
            vec![("UserName", "dupuser"), ("Password", "pass1")],
        );

        let req = make_request(
            "CreateLoginProfile",
            vec![("UserName", "dupuser"), ("Password", "pass2")],
        );
        assert!(svc.create_login_profile(&req).is_err());
    }

    #[test]
    fn delete_login_profile_nonexistent_fails() {
        let svc = make_service();
        svc.handle_sync("CreateUser", vec![("UserName", "nologin")]);

        let req = make_request("DeleteLoginProfile", vec![("UserName", "nologin")]);
        assert!(svc.delete_login_profile(&req).is_err());
    }

    // ---- MFA tests ----

    #[test]
    fn virtual_mfa_device_lifecycle() {
        let svc = make_service();

        // Create virtual MFA device
        let resp = svc.handle_sync(
            "CreateVirtualMFADevice",
            vec![("VirtualMFADeviceName", "my-mfa")],
        );
        assert!(resp.contains("my-mfa"));
        assert!(resp.contains("<Base32StringSeed>"));
        assert!(resp.contains("<QRCodePNG>"));
        let serial = extract_xml_value(&resp, "SerialNumber");

        // List should include it
        let list = svc.handle_sync("ListVirtualMFADevices", vec![]);
        assert!(list.contains("my-mfa"));

        // Delete
        svc.handle_sync("DeleteVirtualMFADevice", vec![("SerialNumber", &serial)]);

        // List should be empty
        let list = svc.handle_sync("ListVirtualMFADevices", vec![]);
        assert!(!list.contains("my-mfa"));
    }

    #[test]
    fn delete_virtual_mfa_device_not_found() {
        let svc = make_service();
        let req = make_request(
            "DeleteVirtualMFADevice",
            vec![("SerialNumber", "arn:aws:iam::123456789012:mfa/ghost")],
        );
        assert!(svc.delete_virtual_mfa_device(&req).is_err());
    }

    #[test]
    fn enable_and_list_mfa_devices() {
        let svc = make_service();
        svc.handle_sync("CreateUser", vec![("UserName", "mfauser")]);

        // Create virtual MFA
        let resp = svc.handle_sync(
            "CreateVirtualMFADevice",
            vec![("VirtualMFADeviceName", "dev-mfa")],
        );
        let serial = extract_xml_value(&resp, "SerialNumber");

        // Enable MFA device for user
        svc.handle_sync(
            "EnableMFADevice",
            vec![
                ("UserName", "mfauser"),
                ("SerialNumber", &serial),
                ("AuthenticationCode1", "123456"),
                ("AuthenticationCode2", "654321"),
            ],
        );

        // List MFA devices for user
        let list = svc.handle_sync("ListMFADevices", vec![("UserName", "mfauser")]);
        assert!(list.contains(&serial));
        assert!(list.contains("mfauser"));
    }

    #[test]
    fn deactivate_mfa_device() {
        let svc = make_service();
        svc.handle_sync("CreateUser", vec![("UserName", "deactuser")]);

        let resp = svc.handle_sync(
            "CreateVirtualMFADevice",
            vec![("VirtualMFADeviceName", "deact-mfa")],
        );
        let serial = extract_xml_value(&resp, "SerialNumber");

        svc.handle_sync(
            "EnableMFADevice",
            vec![
                ("UserName", "deactuser"),
                ("SerialNumber", &serial),
                ("AuthenticationCode1", "111111"),
                ("AuthenticationCode2", "222222"),
            ],
        );

        // Deactivate
        svc.handle_sync(
            "DeactivateMFADevice",
            vec![("UserName", "deactuser"), ("SerialNumber", &serial)],
        );

        // Should no longer appear in user's MFA device list
        let list = svc.handle_sync("ListMFADevices", vec![("UserName", "deactuser")]);
        assert!(!list.contains(&serial));
    }

    #[test]
    fn list_virtual_mfa_devices_assignment_filter() {
        let svc = make_service();
        svc.handle_sync("CreateUser", vec![("UserName", "filteruser")]);

        // Create two MFA devices with distinct names
        let resp1 = svc.handle_sync(
            "CreateVirtualMFADevice",
            vec![("VirtualMFADeviceName", "enabled-device")],
        );
        let serial1 = extract_xml_value(&resp1, "SerialNumber");
        svc.handle_sync(
            "CreateVirtualMFADevice",
            vec![("VirtualMFADeviceName", "spare-device")],
        );

        // Enable only the first
        svc.handle_sync(
            "EnableMFADevice",
            vec![
                ("UserName", "filteruser"),
                ("SerialNumber", &serial1),
                ("AuthenticationCode1", "123456"),
                ("AuthenticationCode2", "654321"),
            ],
        );

        // Filter by Assigned
        let assigned = svc.handle_sync(
            "ListVirtualMFADevices",
            vec![("AssignmentStatus", "Assigned")],
        );
        assert!(assigned.contains("enabled-device"));
        assert!(!assigned.contains("spare-device"));

        // Filter by Unassigned
        let unassigned = svc.handle_sync(
            "ListVirtualMFADevices",
            vec![("AssignmentStatus", "Unassigned")],
        );
        assert!(!unassigned.contains("enabled-device"));
        assert!(unassigned.contains("spare-device"));
    }

    // ---- Account tests ----

    #[test]
    fn get_account_summary() {
        let svc = make_service();

        // Create some resources to verify counts
        svc.handle_sync("CreateUser", vec![("UserName", "u1")]);
        svc.handle_sync("CreateUser", vec![("UserName", "u2")]);
        svc.handle_sync("CreateGroup", vec![("GroupName", "g1")]);

        let resp = svc.handle_sync("GetAccountSummary", vec![]);
        assert!(resp.contains("<key>Users</key><value>2</value>"));
        assert!(resp.contains("<key>Groups</key><value>1</value>"));
        assert!(resp.contains("<key>UsersQuota</key><value>5000</value>"));
    }

    #[test]
    fn account_alias_lifecycle() {
        let svc = make_service();

        // Create alias
        svc.handle_sync("CreateAccountAlias", vec![("AccountAlias", "my-org")]);

        // List aliases
        let list = svc.handle_sync("ListAccountAliases", vec![]);
        assert!(list.contains("my-org"));

        // Delete alias
        svc.handle_sync("DeleteAccountAlias", vec![("AccountAlias", "my-org")]);

        let list = svc.handle_sync("ListAccountAliases", vec![]);
        assert!(!list.contains("my-org"));
    }

    #[test]
    fn create_account_alias_idempotent() {
        let svc = make_service();
        svc.handle_sync("CreateAccountAlias", vec![("AccountAlias", "test-alias")]);
        svc.handle_sync("CreateAccountAlias", vec![("AccountAlias", "test-alias")]);

        let list = svc.handle_sync("ListAccountAliases", vec![]);
        // Should only appear once
        let count = list.matches("test-alias").count();
        assert_eq!(count, 1, "alias should appear exactly once");
    }

    // ---- Helper methods for tests ----

    fn extract_xml_value(xml: &str, tag: &str) -> String {
        let open = format!("<{tag}>");
        let close = format!("</{tag}>");
        let start = xml.find(&open).unwrap() + open.len();
        let end = xml.find(&close).unwrap();
        xml[start..end].to_string()
    }

    impl IamService {
        /// Synchronous helper for unit tests: dispatches to the correct method
        fn handle_sync(&self, action: &str, params: Vec<(&str, &str)>) -> String {
            let req = make_request(action, params);
            let resp = match action {
                "CreateUser" => self.create_user(&req),
                "CreateGroup" => self.create_group(&req),
                "CreatePolicy" => self.create_policy(&req),
                "ListPolicies" => self.list_policies(&req),
                "PutGroupPolicy" => self.put_group_policy(&req),
                "GetGroupPolicy" => self.get_group_policy(&req),
                "DeleteGroupPolicy" => self.delete_group_policy(&req),
                "ListGroupPolicies" => self.list_group_policies(&req),
                "AttachGroupPolicy" => self.attach_group_policy(&req),
                "DetachGroupPolicy" => self.detach_group_policy(&req),
                "ListAttachedGroupPolicies" => self.list_attached_group_policies(&req),
                "PutUserPolicy" => self.put_user_policy(&req),
                "GetUserPolicy" => self.get_user_policy(&req),
                "DeleteUserPolicy" => self.delete_user_policy(&req),
                "ListUserPolicies" => self.list_user_policies(&req),
                "AttachUserPolicy" => self.attach_user_policy(&req),
                "DetachUserPolicy" => self.detach_user_policy(&req),
                "ListAttachedUserPolicies" => self.list_attached_user_policies(&req),
                "CreateLoginProfile" => self.create_login_profile(&req),
                "GetLoginProfile" => self.get_login_profile(&req),
                "UpdateLoginProfile" => self.update_login_profile(&req),
                "DeleteLoginProfile" => self.delete_login_profile(&req),
                "CreateVirtualMFADevice" => self.create_virtual_mfa_device(&req),
                "DeleteVirtualMFADevice" => self.delete_virtual_mfa_device(&req),
                "ListVirtualMFADevices" => self.list_virtual_mfa_devices(&req),
                "EnableMFADevice" => self.enable_mfa_device(&req),
                "DeactivateMFADevice" => self.deactivate_mfa_device(&req),
                "ListMFADevices" => self.list_mfa_devices(&req),
                "GetAccountSummary" => self.get_account_summary(&req),
                "CreateAccountAlias" => self.create_account_alias(&req),
                "DeleteAccountAlias" => self.delete_account_alias(&req),
                "ListAccountAliases" => self.list_account_aliases(&req),
                other => panic!("handle_sync: unhandled action {other}"),
            }
            .unwrap();
            String::from_utf8(resp.body.expect_bytes().to_vec()).unwrap()
        }
    }

    // ---- Policy Version Tests ----

    #[test]
    fn create_and_get_policy_version() {
        let svc = make_service();
        let policy_doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
        let req = make_request(
            "CreatePolicy",
            vec![("PolicyName", "test-pol"), ("PolicyDocument", policy_doc)],
        );
        let resp = svc.create_policy(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        // Extract policy ARN
        let policy_arn = extract_xml_tag(&body, "Arn");

        // Create v2
        let new_doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":["s3:GetObject","s3:PutObject"],"Resource":"*"}]}"#;
        let req = make_request(
            "CreatePolicyVersion",
            vec![
                ("PolicyArn", policy_arn),
                ("PolicyDocument", new_doc),
                ("SetAsDefault", "true"),
            ],
        );
        let resp = svc.create_policy_version(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<VersionId>v2</VersionId>"));
        assert!(body.contains("<IsDefaultVersion>true</IsDefaultVersion>"));

        // Get v2
        let req = make_request(
            "GetPolicyVersion",
            vec![("PolicyArn", policy_arn), ("VersionId", "v2")],
        );
        let resp = svc.get_policy_version(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<VersionId>v2</VersionId>"));
        assert!(body.contains("<IsDefaultVersion>true</IsDefaultVersion>"));
    }

    #[test]
    fn list_policy_versions() {
        let svc = make_service();
        let policy_doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;
        let req = make_request(
            "CreatePolicy",
            vec![("PolicyName", "ver-pol"), ("PolicyDocument", policy_doc)],
        );
        let resp = svc.create_policy(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        let policy_arn = extract_xml_tag(&body, "Arn");

        // Create v2
        let req = make_request(
            "CreatePolicyVersion",
            vec![("PolicyArn", policy_arn), ("PolicyDocument", policy_doc)],
        );
        svc.create_policy_version(&req).unwrap();

        let req = make_request("ListPolicyVersions", vec![("PolicyArn", policy_arn)]);
        let resp = svc.list_policy_versions(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        // Should have v1 and v2
        assert!(body.contains("<VersionId>v1</VersionId>"));
        assert!(body.contains("<VersionId>v2</VersionId>"));
    }

    #[test]
    fn delete_default_policy_version_fails() {
        let svc = make_service();
        let policy_doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;
        let req = make_request(
            "CreatePolicy",
            vec![("PolicyName", "def-pol"), ("PolicyDocument", policy_doc)],
        );
        let resp = svc.create_policy(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        let policy_arn = extract_xml_tag(&body, "Arn");

        // v1 is the default; deleting it should fail
        let req = make_request(
            "DeletePolicyVersion",
            vec![("PolicyArn", policy_arn), ("VersionId", "v1")],
        );
        let result = svc.delete_policy_version(&req);
        assert!(result.is_err(), "deleting default version should fail");
    }

    #[test]
    fn set_default_policy_version() {
        let svc = make_service();
        let policy_doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;
        let req = make_request(
            "CreatePolicy",
            vec![("PolicyName", "sd-pol"), ("PolicyDocument", policy_doc)],
        );
        let resp = svc.create_policy(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        let policy_arn = extract_xml_tag(&body, "Arn");

        // Create v2
        let req = make_request(
            "CreatePolicyVersion",
            vec![("PolicyArn", policy_arn), ("PolicyDocument", policy_doc)],
        );
        svc.create_policy_version(&req).unwrap();

        // Set v2 as default
        let req = make_request(
            "SetDefaultPolicyVersion",
            vec![("PolicyArn", policy_arn), ("VersionId", "v2")],
        );
        svc.set_default_policy_version(&req).unwrap();

        // Verify v2 is now default
        let req = make_request(
            "GetPolicyVersion",
            vec![("PolicyArn", policy_arn), ("VersionId", "v2")],
        );
        let resp = svc.get_policy_version(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<IsDefaultVersion>true</IsDefaultVersion>"));

        // v1 should no longer be default
        let req = make_request(
            "GetPolicyVersion",
            vec![("PolicyArn", policy_arn), ("VersionId", "v1")],
        );
        let resp = svc.get_policy_version(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<IsDefaultVersion>false</IsDefaultVersion>"));
    }

    // ---- Server Certificate Tests ----

    #[test]
    fn server_certificate_lifecycle() {
        let svc = make_service();

        // Upload
        let req = make_request(
            "UploadServerCertificate",
            vec![
                ("ServerCertificateName", "my-cert"),
                (
                    "CertificateBody",
                    "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
                ),
                (
                    "PrivateKey",
                    "-----BEGIN RSA PRIVATE KEY-----\ntest\n-----END RSA PRIVATE KEY-----",
                ),
            ],
        );
        let resp = svc.upload_server_certificate(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<ServerCertificateName>my-cert</ServerCertificateName>"));
        assert!(body.contains("ASCA"));

        // Get
        let req = make_request(
            "GetServerCertificate",
            vec![("ServerCertificateName", "my-cert")],
        );
        let resp = svc.get_server_certificate(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<ServerCertificateName>my-cert</ServerCertificateName>"));

        // List
        let req = make_request("ListServerCertificates", vec![]);
        let resp = svc.list_server_certificates(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("my-cert"));

        // Delete
        let req = make_request(
            "DeleteServerCertificate",
            vec![("ServerCertificateName", "my-cert")],
        );
        svc.delete_server_certificate(&req).unwrap();

        // Should be gone
        let req = make_request(
            "GetServerCertificate",
            vec![("ServerCertificateName", "my-cert")],
        );
        assert!(svc.get_server_certificate(&req).is_err());
    }

    #[test]
    fn server_certificate_duplicate_fails() {
        let svc = make_service();
        let req = make_request(
            "UploadServerCertificate",
            vec![
                ("ServerCertificateName", "dup-cert"),
                ("CertificateBody", "cert-body"),
                ("PrivateKey", "key-body"),
            ],
        );
        svc.upload_server_certificate(&req).unwrap();

        let req = make_request(
            "UploadServerCertificate",
            vec![
                ("ServerCertificateName", "dup-cert"),
                ("CertificateBody", "cert-body"),
                ("PrivateKey", "key-body"),
            ],
        );
        assert!(svc.upload_server_certificate(&req).is_err());
    }

    // ---- SSH Public Key Tests ----

    #[test]
    fn ssh_public_key_lifecycle() {
        let svc = make_service();
        svc.create_user(&make_request("CreateUser", vec![("UserName", "sshuser")]))
            .unwrap();

        // Upload
        let req = make_request(
            "UploadSSHPublicKey",
            vec![
                ("UserName", "sshuser"),
                (
                    "SSHPublicKeyBody",
                    "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ test@example",
                ),
            ],
        );
        let resp = svc.upload_ssh_public_key(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<Status>Active</Status>"));
        assert!(body.contains("APKA"));
        // Extract key ID
        let kid_start = body.find("<SSHPublicKeyId>").unwrap() + 16;
        let kid_end = body.find("</SSHPublicKeyId>").unwrap();
        let key_id = &body[kid_start..kid_end];

        // Get
        let req = make_request(
            "GetSSHPublicKey",
            vec![("UserName", "sshuser"), ("SSHPublicKeyId", key_id)],
        );
        let resp = svc.get_ssh_public_key(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains(key_id));
        assert!(body.contains("<Status>Active</Status>"));

        // List
        let req = make_request("ListSSHPublicKeys", vec![("UserName", "sshuser")]);
        let resp = svc.list_ssh_public_keys(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains(key_id));

        // Update status to Inactive
        let req = make_request(
            "UpdateSSHPublicKey",
            vec![
                ("UserName", "sshuser"),
                ("SSHPublicKeyId", key_id),
                ("Status", "Inactive"),
            ],
        );
        svc.update_ssh_public_key(&req).unwrap();

        // Verify status changed
        let req = make_request(
            "GetSSHPublicKey",
            vec![("UserName", "sshuser"), ("SSHPublicKeyId", key_id)],
        );
        let resp = svc.get_ssh_public_key(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<Status>Inactive</Status>"));

        // Delete
        let req = make_request(
            "DeleteSSHPublicKey",
            vec![("UserName", "sshuser"), ("SSHPublicKeyId", key_id)],
        );
        svc.delete_ssh_public_key(&req).unwrap();

        // Should be empty now
        let req = make_request("ListSSHPublicKeys", vec![("UserName", "sshuser")]);
        let resp = svc.list_ssh_public_keys(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(!body.contains(key_id));
    }

    // ---- Signing Certificate Tests ----

    #[test]
    fn signing_certificate_lifecycle() {
        let svc = make_service();
        svc.create_user(&make_request("CreateUser", vec![("UserName", "certuser")]))
            .unwrap();

        let pem = "-----BEGIN CERTIFICATE-----\nMIIBxTCCAW4=\n-----END CERTIFICATE-----";

        // Upload
        let req = make_request(
            "UploadSigningCertificate",
            vec![("UserName", "certuser"), ("CertificateBody", pem)],
        );
        let resp = svc.upload_signing_certificate(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<Status>Active</Status>"));
        assert!(body.contains("<UserName>certuser</UserName>"));
        let cid_start = body.find("<CertificateId>").unwrap() + 15;
        let cid_end = body.find("</CertificateId>").unwrap();
        let cert_id = &body[cid_start..cid_end];

        // List
        let req = make_request("ListSigningCertificates", vec![("UserName", "certuser")]);
        let resp = svc.list_signing_certificates(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains(cert_id));

        // Update to Inactive
        let req = make_request(
            "UpdateSigningCertificate",
            vec![
                ("UserName", "certuser"),
                ("CertificateId", cert_id),
                ("Status", "Inactive"),
            ],
        );
        svc.update_signing_certificate(&req).unwrap();

        // Delete
        let req = make_request(
            "DeleteSigningCertificate",
            vec![("UserName", "certuser"), ("CertificateId", cert_id)],
        );
        svc.delete_signing_certificate(&req).unwrap();

        // Should be empty
        let req = make_request("ListSigningCertificates", vec![("UserName", "certuser")]);
        let resp = svc.list_signing_certificates(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(!body.contains(cert_id));
    }

    #[test]
    fn signing_certificate_malformed_pem_fails() {
        let svc = make_service();
        svc.create_user(&make_request("CreateUser", vec![("UserName", "badcert")]))
            .unwrap();

        let req = make_request(
            "UploadSigningCertificate",
            vec![
                ("UserName", "badcert"),
                ("CertificateBody", "not-a-pem-cert"),
            ],
        );
        assert!(svc.upload_signing_certificate(&req).is_err());
    }

    // ---- Credential Report Tests ----

    #[test]
    fn credential_report_lifecycle() {
        let svc = make_service();

        // GetCredentialReport without generating first should fail
        let req = make_request("GetCredentialReport", vec![]);
        assert!(svc.get_credential_report(&req).is_err());

        // Generate
        let req = make_request("GenerateCredentialReport", vec![]);
        let resp = svc.generate_credential_report(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<State>STARTED</State>"));

        // Generate again returns COMPLETE
        let req = make_request("GenerateCredentialReport", vec![]);
        let resp = svc.generate_credential_report(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<State>COMPLETE</State>"));

        // Get credential report
        let req = make_request("GetCredentialReport", vec![]);
        let resp = svc.get_credential_report(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<ReportFormat>text/csv</ReportFormat>"));
        assert!(body.contains("<Content>"));
    }

    // ---- Service Linked Role Tests ----

    #[test]
    fn service_linked_role_lifecycle() {
        let svc = make_service();

        // Create
        let req = make_request(
            "CreateServiceLinkedRole",
            vec![("AWSServiceName", "elasticloadbalancing.amazonaws.com")],
        );
        let resp = svc.create_service_linked_role(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("AWSServiceRoleForElasticLoadBalancing"));
        assert!(body.contains("/aws-service-role/elasticloadbalancing.amazonaws.com/"));

        // Delete
        let req = make_request(
            "DeleteServiceLinkedRole",
            vec![("RoleName", "AWSServiceRoleForElasticLoadBalancing")],
        );
        let resp = svc.delete_service_linked_role(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<DeletionTaskId>"));
        let tid_start = body.find("<DeletionTaskId>").unwrap() + 16;
        let tid_end = body.find("</DeletionTaskId>").unwrap();
        let task_id = &body[tid_start..tid_end];

        // Check deletion status
        let req = make_request(
            "GetServiceLinkedRoleDeletionStatus",
            vec![("DeletionTaskId", task_id)],
        );
        let resp = svc.get_service_linked_role_deletion_status(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<Status>SUCCEEDED</Status>"));
    }

    // ---- Permission Boundary Tests ----

    #[test]
    fn role_permissions_boundary() {
        let svc = make_service();
        let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
        svc.create_role(&make_request(
            "CreateRole",
            vec![
                ("RoleName", "bound-role"),
                ("AssumeRolePolicyDocument", trust),
            ],
        ))
        .unwrap();

        // Put boundary
        let boundary_arn = "arn:aws:iam::123456789012:policy/boundary-policy";
        let req = make_request(
            "PutRolePermissionsBoundary",
            vec![
                ("RoleName", "bound-role"),
                ("PermissionsBoundary", boundary_arn),
            ],
        );
        svc.put_role_permissions_boundary(&req).unwrap();

        // Verify via GetRole
        let req = make_request("GetRole", vec![("RoleName", "bound-role")]);
        let resp = svc.get_role(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains(boundary_arn));

        // Delete boundary
        let req = make_request(
            "DeleteRolePermissionsBoundary",
            vec![("RoleName", "bound-role")],
        );
        svc.delete_role_permissions_boundary(&req).unwrap();

        // Verify removed
        let req = make_request("GetRole", vec![("RoleName", "bound-role")]);
        let resp = svc.get_role(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(!body.contains(boundary_arn));
    }

    // ---- Tag Role Tests ----

    #[test]
    fn tag_untag_role() {
        let svc = make_service();
        let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
        svc.create_role(&make_request(
            "CreateRole",
            vec![
                ("RoleName", "tag-role"),
                ("AssumeRolePolicyDocument", trust),
            ],
        ))
        .unwrap();

        // Tag
        let req = make_request(
            "TagRole",
            vec![
                ("RoleName", "tag-role"),
                ("Tags.member.1.Key", "env"),
                ("Tags.member.1.Value", "prod"),
            ],
        );
        svc.tag_role(&req).unwrap();

        // List tags
        let req = make_request("ListRoleTags", vec![("RoleName", "tag-role")]);
        let resp = svc.list_role_tags(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<Key>env</Key>"));
        assert!(body.contains("<Value>prod</Value>"));

        // Untag
        let req = make_request(
            "UntagRole",
            vec![("RoleName", "tag-role"), ("TagKeys.member.1", "env")],
        );
        svc.untag_role(&req).unwrap();

        let req = make_request("ListRoleTags", vec![("RoleName", "tag-role")]);
        let resp = svc.list_role_tags(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(!body.contains("<Key>env</Key>"));
    }

    // ---- Tag Policy Tests ----

    #[test]
    fn tag_untag_policy() {
        let svc = make_service();
        let policy_doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;
        let req = make_request(
            "CreatePolicy",
            vec![("PolicyName", "tag-pol"), ("PolicyDocument", policy_doc)],
        );
        let resp = svc.create_policy(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        let policy_arn = extract_xml_tag(&body, "Arn").to_string();

        let req = make_request(
            "TagPolicy",
            vec![
                ("PolicyArn", &policy_arn),
                ("Tags.member.1.Key", "team"),
                ("Tags.member.1.Value", "platform"),
            ],
        );
        svc.tag_policy(&req).unwrap();

        let req = make_request("ListPolicyTags", vec![("PolicyArn", &policy_arn)]);
        let resp = svc.list_policy_tags(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<Key>team</Key>"));

        let req = make_request(
            "UntagPolicy",
            vec![("PolicyArn", &policy_arn), ("TagKeys.member.1", "team")],
        );
        svc.untag_policy(&req).unwrap();

        let req = make_request("ListPolicyTags", vec![("PolicyArn", &policy_arn)]);
        let resp = svc.list_policy_tags(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(!body.contains("<Key>team</Key>"));
    }

    // ---- Tag Instance Profile Tests ----

    #[test]
    fn tag_untag_instance_profile() {
        let svc = make_service();
        svc.create_instance_profile(&make_request(
            "CreateInstanceProfile",
            vec![("InstanceProfileName", "tag-ip")],
        ))
        .unwrap();

        let req = make_request(
            "TagInstanceProfile",
            vec![
                ("InstanceProfileName", "tag-ip"),
                ("Tags.member.1.Key", "dept"),
                ("Tags.member.1.Value", "eng"),
            ],
        );
        svc.tag_instance_profile(&req).unwrap();

        let req = make_request(
            "ListInstanceProfileTags",
            vec![("InstanceProfileName", "tag-ip")],
        );
        let resp = svc.list_instance_profile_tags(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<Key>dept</Key>"));

        let req = make_request(
            "UntagInstanceProfile",
            vec![
                ("InstanceProfileName", "tag-ip"),
                ("TagKeys.member.1", "dept"),
            ],
        );
        svc.untag_instance_profile(&req).unwrap();

        let req = make_request(
            "ListInstanceProfileTags",
            vec![("InstanceProfileName", "tag-ip")],
        );
        let resp = svc.list_instance_profile_tags(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(!body.contains("<Key>dept</Key>"));
    }

    // ---- Tag OIDC Provider Tests ----

    #[test]
    fn tag_untag_oidc_provider() {
        let svc = make_service();
        let req = make_request(
            "CreateOpenIDConnectProvider",
            vec![
                ("Url", "https://oidc.example.com"),
                (
                    "ThumbprintList.member.1",
                    "abcdef1234567890abcdef1234567890abcdef12",
                ),
            ],
        );
        let resp = svc.create_oidc_provider(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        let arn_start =
            body.find("<OpenIDConnectProviderArn>").unwrap() + "<OpenIDConnectProviderArn>".len();
        let arn_end = body.find("</OpenIDConnectProviderArn>").unwrap();
        let oidc_arn = body[arn_start..arn_end].to_string();

        let req = make_request(
            "TagOpenIDConnectProvider",
            vec![
                ("OpenIDConnectProviderArn", &oidc_arn),
                ("Tags.member.1.Key", "stage"),
                ("Tags.member.1.Value", "dev"),
            ],
        );
        svc.tag_oidc_provider(&req).unwrap();

        let req = make_request(
            "ListOpenIDConnectProviderTags",
            vec![("OpenIDConnectProviderArn", &oidc_arn)],
        );
        let resp = svc.list_oidc_provider_tags(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<Key>stage</Key>"));

        let req = make_request(
            "UntagOpenIDConnectProvider",
            vec![
                ("OpenIDConnectProviderArn", &oidc_arn),
                ("TagKeys.member.1", "stage"),
            ],
        );
        svc.untag_oidc_provider(&req).unwrap();

        let req = make_request(
            "ListOpenIDConnectProviderTags",
            vec![("OpenIDConnectProviderArn", &oidc_arn)],
        );
        let resp = svc.list_oidc_provider_tags(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(!body.contains("<Key>stage</Key>"));
    }

    // ---- Update Role Tests ----

    #[test]
    fn update_role_description_and_max_session() {
        let svc = make_service();
        let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
        svc.create_role(&make_request(
            "CreateRole",
            vec![
                ("RoleName", "upd-role"),
                ("AssumeRolePolicyDocument", trust),
            ],
        ))
        .unwrap();

        // UpdateRole with Description and MaxSessionDuration
        let req = make_request(
            "UpdateRole",
            vec![
                ("RoleName", "upd-role"),
                ("Description", "new description"),
                ("MaxSessionDuration", "7200"),
            ],
        );
        svc.update_role(&req).unwrap();

        // UpdateRoleDescription
        let req = make_request(
            "UpdateRoleDescription",
            vec![("RoleName", "upd-role"), ("Description", "updated desc")],
        );
        let resp = svc.update_role_description(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<Description>updated desc</Description>"));
    }

    // ---- UpdateAssumeRolePolicy Tests ----

    #[test]
    fn update_assume_role_policy() {
        let svc = make_service();
        let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
        svc.create_role(&make_request(
            "CreateRole",
            vec![
                ("RoleName", "arp-role"),
                ("AssumeRolePolicyDocument", trust),
            ],
        ))
        .unwrap();

        let new_trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
        let req = make_request(
            "UpdateAssumeRolePolicy",
            vec![("RoleName", "arp-role"), ("PolicyDocument", new_trust)],
        );
        svc.update_assume_role_policy(&req).unwrap();

        // Verify by GetRole
        let req = make_request("GetRole", vec![("RoleName", "arp-role")]);
        let resp = svc.get_role(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("lambda.amazonaws.com"));
    }

    // ---- UpdateGroup Tests ----

    #[test]
    fn update_group_rename() {
        let svc = make_service();
        svc.create_group(&make_request("CreateGroup", vec![("GroupName", "old-grp")]))
            .unwrap();

        let req = make_request(
            "UpdateGroup",
            vec![("GroupName", "old-grp"), ("NewGroupName", "new-grp")],
        );
        svc.update_group(&req).unwrap();

        // Old name should not exist
        assert!(svc
            .get_group(&make_request("GetGroup", vec![("GroupName", "old-grp")]))
            .is_err());

        // New name should exist
        let resp = svc
            .get_group(&make_request("GetGroup", vec![("GroupName", "new-grp")]))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<GroupName>new-grp</GroupName>"));
    }

    // ---- UpdateUser Tests ----

    #[test]
    fn update_user_rename() {
        let svc = make_service();
        svc.create_user(&make_request("CreateUser", vec![("UserName", "old-user")]))
            .unwrap();

        let req = make_request(
            "UpdateUser",
            vec![("UserName", "old-user"), ("NewUserName", "new-user")],
        );
        svc.update_user(&req).unwrap();

        assert!(svc
            .get_user(&make_request("GetUser", vec![("UserName", "old-user")]))
            .is_err());

        let resp = svc
            .get_user(&make_request("GetUser", vec![("UserName", "new-user")]))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<UserName>new-user</UserName>"));
    }

    // ---- Account Password Policy Tests ----

    #[test]
    fn account_password_policy_lifecycle() {
        let svc = make_service();

        // Get before setting returns error
        let req = make_request("GetAccountPasswordPolicy", vec![]);
        assert!(svc.get_account_password_policy(&req).is_err());

        // Update (creates the policy)
        let req = make_request(
            "UpdateAccountPasswordPolicy",
            vec![
                ("MinimumPasswordLength", "12"),
                ("RequireSymbols", "true"),
                ("RequireNumbers", "true"),
            ],
        );
        svc.update_account_password_policy(&req).unwrap();

        // Get
        let req = make_request("GetAccountPasswordPolicy", vec![]);
        let resp = svc.get_account_password_policy(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<MinimumPasswordLength>12</MinimumPasswordLength>"));
        assert!(body.contains("<RequireSymbols>true</RequireSymbols>"));

        // Delete
        let req = make_request("DeleteAccountPasswordPolicy", vec![]);
        svc.delete_account_password_policy(&req).unwrap();

        // Should be gone
        let req = make_request("GetAccountPasswordPolicy", vec![]);
        assert!(svc.get_account_password_policy(&req).is_err());
    }

    // ---- GetAccountAuthorizationDetails Tests ----

    #[test]
    fn get_account_authorization_details() {
        let svc = make_service();

        // Create a user and role
        svc.create_user(&make_request("CreateUser", vec![("UserName", "auth-user")]))
            .unwrap();
        let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
        svc.create_role(&make_request(
            "CreateRole",
            vec![
                ("RoleName", "auth-role"),
                ("AssumeRolePolicyDocument", trust),
            ],
        ))
        .unwrap();

        let req = make_request("GetAccountAuthorizationDetails", vec![]);
        let resp = svc.get_account_authorization_details(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<UserName>auth-user</UserName>"));
        assert!(body.contains("<RoleName>auth-role</RoleName>"));
    }

    // ---- ListEntitiesForPolicy Tests ----

    #[test]
    fn list_entities_for_policy() {
        let svc = make_service();

        // Create policy
        let policy_doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;
        let req = make_request(
            "CreatePolicy",
            vec![("PolicyName", "ent-pol"), ("PolicyDocument", policy_doc)],
        );
        let resp = svc.create_policy(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        let policy_arn = extract_xml_tag(&body, "Arn").to_string();

        // Create role and attach policy
        let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
        svc.create_role(&make_request(
            "CreateRole",
            vec![
                ("RoleName", "ent-role"),
                ("AssumeRolePolicyDocument", trust),
            ],
        ))
        .unwrap();
        svc.attach_role_policy(&make_request(
            "AttachRolePolicy",
            vec![("RoleName", "ent-role"), ("PolicyArn", &policy_arn)],
        ))
        .unwrap();

        // Create user and attach policy
        svc.create_user(&make_request("CreateUser", vec![("UserName", "ent-user")]))
            .unwrap();
        svc.attach_user_policy(&make_request(
            "AttachUserPolicy",
            vec![("UserName", "ent-user"), ("PolicyArn", &policy_arn)],
        ))
        .unwrap();

        let req = make_request("ListEntitiesForPolicy", vec![("PolicyArn", &policy_arn)]);
        let resp = svc.list_entities_for_policy(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<RoleName>ent-role</RoleName>"));
        assert!(body.contains("<UserName>ent-user</UserName>"));
    }

    // ---- GetAccessKeyLastUsed Tests ----

    #[test]
    fn get_access_key_last_used() {
        let svc = make_service();
        svc.create_user(&make_request("CreateUser", vec![("UserName", "keyuser")]))
            .unwrap();

        let req = make_request("CreateAccessKey", vec![("UserName", "keyuser")]);
        let resp = svc.create_access_key(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        let kid_start = body.find("<AccessKeyId>").unwrap() + 13;
        let kid_end = body.find("</AccessKeyId>").unwrap();
        let key_id = body[kid_start..kid_end].to_string();

        let req = make_request("GetAccessKeyLastUsed", vec![("AccessKeyId", &key_id)]);
        let resp = svc.get_access_key_last_used(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes());
        assert!(body.contains("<UserName>keyuser</UserName>"));
        // No last used info yet -- should show N/A
        assert!(body.contains("<ServiceName>N/A</ServiceName>"));
    }

    fn expect_err(result: Result<AwsResponse, AwsServiceError>) -> AwsServiceError {
        match result {
            Err(e) => e,
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    // ── User CRUD ──

    #[test]
    fn create_get_delete_user() {
        let svc = make_service();

        let req = make_request("CreateUser", vec![("UserName", "alice")]);
        let resp = svc.create_user(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("<UserName>alice</UserName>"));
        assert!(body.contains("<Arn>"));

        // Get
        let req = make_request("GetUser", vec![("UserName", "alice")]);
        let resp = svc.get_user(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("<UserName>alice</UserName>"));

        // Delete
        let req = make_request("DeleteUser", vec![("UserName", "alice")]);
        svc.delete_user(&req).unwrap();

        // Get should fail
        let req = make_request("GetUser", vec![("UserName", "alice")]);
        let err = expect_err(svc.get_user(&req));
        assert!(err.to_string().contains("NoSuchEntity"));
    }

    #[test]
    fn create_user_duplicate_fails() {
        let svc = make_service();
        svc.create_user(&make_request("CreateUser", vec![("UserName", "dup")]))
            .unwrap();

        let err =
            expect_err(svc.create_user(&make_request("CreateUser", vec![("UserName", "dup")])));
        assert!(err.to_string().contains("EntityAlreadyExists"));
    }

    #[test]
    fn list_users_basic() {
        let svc = make_service();
        svc.create_user(&make_request("CreateUser", vec![("UserName", "u1")]))
            .unwrap();
        svc.create_user(&make_request("CreateUser", vec![("UserName", "u2")]))
            .unwrap();

        let req = make_request("ListUsers", vec![]);
        let resp = svc.list_users(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("<UserName>u1</UserName>"));
        assert!(body.contains("<UserName>u2</UserName>"));
    }

    #[test]
    fn create_user_with_path_and_tags() {
        let svc = make_service();
        let req = make_request(
            "CreateUser",
            vec![
                ("UserName", "tagged-user"),
                ("Path", "/engineering/"),
                ("Tags.member.1.Key", "team"),
                ("Tags.member.1.Value", "backend"),
            ],
        );
        let resp = svc.create_user(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("/engineering/"));
    }

    #[test]
    fn user_permissions_boundary() {
        let svc = make_service();
        svc.create_user(&make_request("CreateUser", vec![("UserName", "bounded")]))
            .unwrap();

        let policy_arn = "arn:aws:iam::123456789012:policy/boundary";
        let req = make_request(
            "PutUserPermissionsBoundary",
            vec![("UserName", "bounded"), ("PermissionsBoundary", policy_arn)],
        );
        svc.put_user_permissions_boundary(&req).unwrap();

        let req = make_request("GetUser", vec![("UserName", "bounded")]);
        let resp = svc.get_user(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains(policy_arn));

        let req = make_request(
            "DeleteUserPermissionsBoundary",
            vec![("UserName", "bounded")],
        );
        svc.delete_user_permissions_boundary(&req).unwrap();
    }

    // ── Role CRUD ──

    #[test]
    fn create_get_delete_role() {
        let svc = make_service();

        let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
        let req = make_request(
            "CreateRole",
            vec![
                ("RoleName", "test-role"),
                ("AssumeRolePolicyDocument", trust),
            ],
        );
        let resp = svc.create_role(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("<RoleName>test-role</RoleName>"));

        // Get
        let req = make_request("GetRole", vec![("RoleName", "test-role")]);
        let resp = svc.get_role(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("<RoleName>test-role</RoleName>"));

        // Delete
        let req = make_request("DeleteRole", vec![("RoleName", "test-role")]);
        svc.delete_role(&req).unwrap();

        let err =
            expect_err(svc.get_role(&make_request("GetRole", vec![("RoleName", "test-role")])));
        assert!(err.to_string().contains("NoSuchEntity"));
    }

    #[test]
    fn list_roles_basic() {
        let svc = make_service();
        let trust = r#"{"Version":"2012-10-17"}"#;
        svc.create_role(&make_request(
            "CreateRole",
            vec![("RoleName", "r1"), ("AssumeRolePolicyDocument", trust)],
        ))
        .unwrap();
        svc.create_role(&make_request(
            "CreateRole",
            vec![("RoleName", "r2"), ("AssumeRolePolicyDocument", trust)],
        ))
        .unwrap();

        let resp = svc.list_roles(&make_request("ListRoles", vec![])).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("<RoleName>r1</RoleName>"));
        assert!(body.contains("<RoleName>r2</RoleName>"));
    }

    #[test]
    fn role_inline_policy_lifecycle() {
        let svc = make_service();
        let trust = r#"{"Version":"2012-10-17"}"#;
        svc.create_role(&make_request(
            "CreateRole",
            vec![("RoleName", "ip-role"), ("AssumeRolePolicyDocument", trust)],
        ))
        .unwrap();

        let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;
        svc.put_role_policy(&make_request(
            "PutRolePolicy",
            vec![
                ("RoleName", "ip-role"),
                ("PolicyName", "s3-access"),
                ("PolicyDocument", policy),
            ],
        ))
        .unwrap();

        let resp = svc
            .get_role_policy(&make_request(
                "GetRolePolicy",
                vec![("RoleName", "ip-role"), ("PolicyName", "s3-access")],
            ))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("<PolicyName>s3-access</PolicyName>"));

        let resp = svc
            .list_role_policies(&make_request(
                "ListRolePolicies",
                vec![("RoleName", "ip-role")],
            ))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("s3-access"));

        svc.delete_role_policy(&make_request(
            "DeleteRolePolicy",
            vec![("RoleName", "ip-role"), ("PolicyName", "s3-access")],
        ))
        .unwrap();
    }

    // ── Policy CRUD ──

    #[test]
    fn create_get_delete_policy() {
        let svc = make_service();

        let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
        let req = make_request(
            "CreatePolicy",
            vec![("PolicyName", "test-pol"), ("PolicyDocument", doc)],
        );
        let resp = svc.create_policy(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("<PolicyName>test-pol</PolicyName>"));
        let arn = extract_xml_tag(&body, "Arn");

        // Get
        let resp = svc
            .get_policy(&make_request("GetPolicy", vec![("PolicyArn", arn)]))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("<PolicyName>test-pol</PolicyName>"));

        // Delete
        svc.delete_policy(&make_request("DeletePolicy", vec![("PolicyArn", arn)]))
            .unwrap();

        let err = expect_err(svc.get_policy(&make_request("GetPolicy", vec![("PolicyArn", arn)])));
        assert!(err.to_string().contains("NoSuchEntity"));
    }

    #[test]
    fn list_policies_basic() {
        let svc = make_service();
        let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
        svc.create_policy(&make_request(
            "CreatePolicy",
            vec![("PolicyName", "p1"), ("PolicyDocument", doc)],
        ))
        .unwrap();

        let resp = svc
            .list_policies(&make_request("ListPolicies", vec![("Scope", "Local")]))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("<PolicyName>p1</PolicyName>"));
    }

    // ── Group CRUD ──

    #[test]
    fn create_get_delete_group() {
        let svc = make_service();

        svc.create_group(&make_request("CreateGroup", vec![("GroupName", "devs")]))
            .unwrap();

        let resp = svc
            .get_group(&make_request("GetGroup", vec![("GroupName", "devs")]))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("<GroupName>devs</GroupName>"));

        svc.delete_group(&make_request("DeleteGroup", vec![("GroupName", "devs")]))
            .unwrap();

        let err = expect_err(svc.get_group(&make_request("GetGroup", vec![("GroupName", "devs")])));
        assert!(err.to_string().contains("NoSuchEntity"));
    }

    #[test]
    fn group_user_membership() {
        let svc = make_service();
        svc.create_group(&make_request("CreateGroup", vec![("GroupName", "team")]))
            .unwrap();
        svc.create_user(&make_request("CreateUser", vec![("UserName", "member")]))
            .unwrap();

        svc.add_user_to_group(&make_request(
            "AddUserToGroup",
            vec![("GroupName", "team"), ("UserName", "member")],
        ))
        .unwrap();

        let resp = svc
            .get_group(&make_request("GetGroup", vec![("GroupName", "team")]))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("<UserName>member</UserName>"));

        svc.remove_user_from_group(&make_request(
            "RemoveUserFromGroup",
            vec![("GroupName", "team"), ("UserName", "member")],
        ))
        .unwrap();
    }

    #[test]
    fn list_groups_basic() {
        let svc = make_service();
        svc.create_group(&make_request("CreateGroup", vec![("GroupName", "g1")]))
            .unwrap();
        svc.create_group(&make_request("CreateGroup", vec![("GroupName", "g2")]))
            .unwrap();

        let resp = svc
            .list_groups(&make_request("ListGroups", vec![]))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("g1"));
        assert!(body.contains("g2"));
    }

    // ── Instance Profile CRUD ──

    #[test]
    fn instance_profile_lifecycle() {
        let svc = make_service();

        svc.create_instance_profile(&make_request(
            "CreateInstanceProfile",
            vec![("InstanceProfileName", "web-ip")],
        ))
        .unwrap();

        let resp = svc
            .get_instance_profile(&make_request(
                "GetInstanceProfile",
                vec![("InstanceProfileName", "web-ip")],
            ))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("<InstanceProfileName>web-ip</InstanceProfileName>"));

        // Add role
        let trust = r#"{"Version":"2012-10-17"}"#;
        svc.create_role(&make_request(
            "CreateRole",
            vec![
                ("RoleName", "ip-role2"),
                ("AssumeRolePolicyDocument", trust),
            ],
        ))
        .unwrap();
        svc.add_role_to_instance_profile(&make_request(
            "AddRoleToInstanceProfile",
            vec![("InstanceProfileName", "web-ip"), ("RoleName", "ip-role2")],
        ))
        .unwrap();

        // List
        let resp = svc
            .list_instance_profiles(&make_request("ListInstanceProfiles", vec![]))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("web-ip"));

        // Remove role and delete
        svc.remove_role_from_instance_profile(&make_request(
            "RemoveRoleFromInstanceProfile",
            vec![("InstanceProfileName", "web-ip"), ("RoleName", "ip-role2")],
        ))
        .unwrap();
        svc.delete_instance_profile(&make_request(
            "DeleteInstanceProfile",
            vec![("InstanceProfileName", "web-ip")],
        ))
        .unwrap();
    }

    // ── OIDC Provider CRUD ──

    #[test]
    fn oidc_provider_lifecycle() {
        let svc = make_service();

        let req = make_request(
            "CreateOpenIDConnectProvider",
            vec![
                ("Url", "https://oidc.example.com"),
                (
                    "ThumbprintList.member.1",
                    "aabbccddeeff00112233aabbccddeeff00112233",
                ),
                ("ClientIDList.member.1", "my-client"),
            ],
        );
        let resp = svc.create_oidc_provider(&req).unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        let arn = extract_xml_tag(&body, "OpenIDConnectProviderArn");

        let resp = svc
            .get_oidc_provider(&make_request(
                "GetOpenIDConnectProvider",
                vec![("OpenIDConnectProviderArn", arn)],
            ))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("oidc.example.com"));
        assert!(body.contains("my-client"));

        let resp = svc
            .list_oidc_providers(&make_request("ListOpenIDConnectProviders", vec![]))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains(arn));

        svc.delete_oidc_provider(&make_request(
            "DeleteOpenIDConnectProvider",
            vec![("OpenIDConnectProviderArn", arn)],
        ))
        .unwrap();
    }

    // ── Access Key lifecycle ──

    #[test]
    fn access_key_create_update_delete() {
        let svc = make_service();
        svc.create_user(&make_request("CreateUser", vec![("UserName", "akuser")]))
            .unwrap();

        let resp = svc
            .create_access_key(&make_request(
                "CreateAccessKey",
                vec![("UserName", "akuser")],
            ))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        let key_id = extract_xml_tag(&body, "AccessKeyId");
        assert!(body.contains("<Status>Active</Status>"));

        // Update to Inactive
        svc.update_access_key(&make_request(
            "UpdateAccessKey",
            vec![
                ("UserName", "akuser"),
                ("AccessKeyId", key_id),
                ("Status", "Inactive"),
            ],
        ))
        .unwrap();

        // List and verify
        let resp = svc
            .list_access_keys(&make_request(
                "ListAccessKeys",
                vec![("UserName", "akuser")],
            ))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("<Status>Inactive</Status>"));

        // Delete
        svc.delete_access_key(&make_request(
            "DeleteAccessKey",
            vec![("UserName", "akuser"), ("AccessKeyId", key_id)],
        ))
        .unwrap();

        let resp = svc
            .list_access_keys(&make_request(
                "ListAccessKeys",
                vec![("UserName", "akuser")],
            ))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(!body.contains("<AccessKeyId>"));
    }

    // ── Tag/Untag User ──

    #[test]
    fn tag_untag_list_user_tags() {
        let svc = make_service();
        svc.create_user(&make_request("CreateUser", vec![("UserName", "tuser")]))
            .unwrap();

        svc.tag_user(&make_request(
            "TagUser",
            vec![
                ("UserName", "tuser"),
                ("Tags.member.1.Key", "dept"),
                ("Tags.member.1.Value", "eng"),
            ],
        ))
        .unwrap();

        let resp = svc
            .list_user_tags(&make_request("ListUserTags", vec![("UserName", "tuser")]))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("<Key>dept</Key>"));
        assert!(body.contains("<Value>eng</Value>"));

        svc.untag_user(&make_request(
            "UntagUser",
            vec![("UserName", "tuser"), ("TagKeys.member.1", "dept")],
        ))
        .unwrap();

        let resp = svc
            .list_user_tags(&make_request("ListUserTags", vec![("UserName", "tuser")]))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(!body.contains("<Key>dept</Key>"));
    }

    // ── Attach/Detach role policy ──

    #[test]
    fn attach_detach_list_role_policies_managed() {
        let svc = make_service();
        let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
        svc.create_role(&make_request(
            "CreateRole",
            vec![
                ("RoleName", "pol-role"),
                ("AssumeRolePolicyDocument", trust),
            ],
        ))
        .unwrap();

        // Create a local policy to attach
        let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:*","Resource":"*"}]}"#;
        let resp = svc
            .create_policy(&make_request(
                "CreatePolicy",
                vec![("PolicyName", "role-pol"), ("PolicyDocument", doc)],
            ))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        let policy_arn = extract_xml_tag(&body, "Arn").to_string();

        svc.attach_role_policy(&make_request(
            "AttachRolePolicy",
            vec![("RoleName", "pol-role"), ("PolicyArn", &policy_arn)],
        ))
        .unwrap();

        let resp = svc
            .list_attached_role_policies(&make_request(
                "ListAttachedRolePolicies",
                vec![("RoleName", "pol-role")],
            ))
            .unwrap();
        let body = String::from_utf8_lossy(resp.body.expect_bytes()).to_string();
        assert!(body.contains("role-pol"));

        svc.detach_role_policy(&make_request(
            "DetachRolePolicy",
            vec![("RoleName", "pol-role"), ("PolicyArn", &policy_arn)],
        ))
        .unwrap();
    }

    // ── users.rs additional coverage ──

    #[test]
    fn create_user_missing_name_errors() {
        let svc = make_service();
        let req = make_request("CreateUser", vec![]);
        assert!(svc.create_user(&req).is_err());
    }

    #[test]
    fn create_user_duplicate_errors() {
        let svc = make_service();
        let req = make_request("CreateUser", vec![("UserName", "dup")]);
        svc.create_user(&req).unwrap();
        assert!(svc.create_user(&req).is_err());
    }

    #[test]
    fn get_user_unknown_errors() {
        let svc = make_service();
        let req = make_request("GetUser", vec![("UserName", "ghost")]);
        assert!(svc.get_user(&req).is_err());
    }

    #[test]
    fn delete_user_unknown_errors() {
        let svc = make_service();
        let req = make_request("DeleteUser", vec![("UserName", "ghost")]);
        assert!(svc.delete_user(&req).is_err());
    }

    #[test]
    fn update_user_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "UpdateUser",
            vec![("UserName", "ghost"), ("NewUserName", "new")],
        );
        assert!(svc.update_user(&req).is_err());
    }

    #[test]
    fn tag_user_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "TagUser",
            vec![
                ("UserName", "ghost"),
                ("Tags.member.1.Key", "k"),
                ("Tags.member.1.Value", "v"),
            ],
        );
        assert!(svc.tag_user(&req).is_err());
    }

    #[test]
    fn list_user_tags_unknown_errors() {
        let svc = make_service();
        let req = make_request("ListUserTags", vec![("UserName", "ghost")]);
        assert!(svc.list_user_tags(&req).is_err());
    }

    #[test]
    fn create_access_key_unknown_user_errors() {
        let svc = make_service();
        let req = make_request("CreateAccessKey", vec![("UserName", "ghost")]);
        assert!(svc.create_access_key(&req).is_err());
    }

    #[test]
    fn delete_access_key_unknown_user_errors() {
        let svc = make_service();
        let req = make_request(
            "DeleteAccessKey",
            vec![("UserName", "ghost"), ("AccessKeyId", "AKIAEXAMPLE")],
        );
        assert!(svc.delete_access_key(&req).is_err());
    }

    #[test]
    fn create_login_profile_unknown_user_errors() {
        let svc = make_service();
        let req = make_request(
            "CreateLoginProfile",
            vec![("UserName", "ghost"), ("Password", "Pass123!")],
        );
        assert!(svc.create_login_profile(&req).is_err());
    }

    #[test]
    fn get_login_profile_not_found() {
        let svc = make_service();
        svc.create_user(&make_request("CreateUser", vec![("UserName", "lp")]))
            .unwrap();
        let req = make_request("GetLoginProfile", vec![("UserName", "lp")]);
        assert!(svc.get_login_profile(&req).is_err());
    }

    #[test]
    fn delete_login_profile_not_found() {
        let svc = make_service();
        let req = make_request("DeleteLoginProfile", vec![("UserName", "ghost")]);
        assert!(svc.delete_login_profile(&req).is_err());
    }

    #[test]
    fn upload_signing_cert_unknown_user_errors() {
        let svc = make_service();
        let req = make_request(
            "UploadSigningCertificate",
            vec![
                ("UserName", "ghost"),
                ("CertificateBody", "-----BEGIN CERT-----"),
            ],
        );
        assert!(svc.upload_signing_certificate(&req).is_err());
    }

    #[test]
    fn upload_ssh_public_key_unknown_user_errors() {
        let svc = make_service();
        let req = make_request(
            "UploadSSHPublicKey",
            vec![("UserName", "ghost"), ("SSHPublicKeyBody", "ssh-rsa AAA")],
        );
        assert!(svc.upload_ssh_public_key(&req).is_err());
    }

    #[test]
    fn get_ssh_public_key_not_found() {
        let svc = make_service();
        let req = make_request(
            "GetSSHPublicKey",
            vec![
                ("UserName", "ghost"),
                ("SSHPublicKeyId", "ASDF"),
                ("Encoding", "SSH"),
            ],
        );
        assert!(svc.get_ssh_public_key(&req).is_err());
    }

    #[test]
    fn delete_ssh_public_key_not_found() {
        let svc = make_service();
        let req = make_request(
            "DeleteSSHPublicKey",
            vec![("UserName", "ghost"), ("SSHPublicKeyId", "ASDF")],
        );
        assert!(svc.delete_ssh_public_key(&req).is_err());
    }

    #[test]
    fn attach_user_policy_unknown_user_errors() {
        let svc = make_service();
        let req = make_request(
            "AttachUserPolicy",
            vec![
                ("UserName", "ghost"),
                ("PolicyArn", "arn:aws:iam::aws:policy/ReadOnlyAccess"),
            ],
        );
        assert!(svc.attach_user_policy(&req).is_err());
    }

    #[test]
    fn detach_user_policy_unknown_user_errors() {
        let svc = make_service();
        let req = make_request(
            "DetachUserPolicy",
            vec![
                ("UserName", "ghost"),
                ("PolicyArn", "arn:aws:iam::aws:policy/ReadOnlyAccess"),
            ],
        );
        assert!(svc.detach_user_policy(&req).is_err());
    }

    #[test]
    fn list_attached_user_policies_unknown_user_errors() {
        let svc = make_service();
        let req = make_request("ListAttachedUserPolicies", vec![("UserName", "ghost")]);
        assert!(svc.list_attached_user_policies(&req).is_err());
    }

    // ── roles.rs additional ──

    #[test]
    fn create_role_missing_trust_errors() {
        let svc = make_service();
        let req = make_request("CreateRole", vec![("RoleName", "r1")]);
        assert!(svc.create_role(&req).is_err());
    }

    #[test]
    fn create_role_duplicate_errors() {
        let svc = make_service();
        let trust = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}"#;
        let req = make_request(
            "CreateRole",
            vec![("RoleName", "rd"), ("AssumeRolePolicyDocument", trust)],
        );
        svc.create_role(&req).unwrap();
        assert!(svc.create_role(&req).is_err());
    }

    #[test]
    fn get_role_unknown_errors() {
        let svc = make_service();
        let req = make_request("GetRole", vec![("RoleName", "ghost")]);
        assert!(svc.get_role(&req).is_err());
    }

    #[test]
    fn delete_role_unknown_errors() {
        let svc = make_service();
        let req = make_request("DeleteRole", vec![("RoleName", "ghost")]);
        assert!(svc.delete_role(&req).is_err());
    }

    #[test]
    fn update_assume_role_policy_unknown_role_errors() {
        let svc = make_service();
        let req = make_request(
            "UpdateAssumeRolePolicy",
            vec![("RoleName", "ghost"), ("PolicyDocument", "{}")],
        );
        assert!(svc.update_assume_role_policy(&req).is_err());
    }

    #[test]
    fn tag_role_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "TagRole",
            vec![
                ("RoleName", "ghost"),
                ("Tags.member.1.Key", "k"),
                ("Tags.member.1.Value", "v"),
            ],
        );
        assert!(svc.tag_role(&req).is_err());
    }

    // ── groups.rs additional ──

    #[test]
    fn create_group_duplicate_errors() {
        let svc = make_service();
        let req = make_request("CreateGroup", vec![("GroupName", "g1")]);
        svc.create_group(&req).unwrap();
        assert!(svc.create_group(&req).is_err());
    }

    #[test]
    fn get_group_unknown_errors() {
        let svc = make_service();
        let req = make_request("GetGroup", vec![("GroupName", "ghost")]);
        assert!(svc.get_group(&req).is_err());
    }

    #[test]
    fn delete_group_unknown_errors() {
        let svc = make_service();
        let req = make_request("DeleteGroup", vec![("GroupName", "ghost")]);
        assert!(svc.delete_group(&req).is_err());
    }

    #[test]
    fn add_user_to_unknown_group_errors() {
        let svc = make_service();
        svc.create_user(&make_request("CreateUser", vec![("UserName", "u1")]))
            .unwrap();
        let req = make_request(
            "AddUserToGroup",
            vec![("GroupName", "ghost"), ("UserName", "u1")],
        );
        assert!(svc.add_user_to_group(&req).is_err());
    }

    #[test]
    fn add_unknown_user_to_group_errors() {
        let svc = make_service();
        svc.create_group(&make_request("CreateGroup", vec![("GroupName", "ug")]))
            .unwrap();
        let req = make_request(
            "AddUserToGroup",
            vec![("GroupName", "ug"), ("UserName", "ghost")],
        );
        assert!(svc.add_user_to_group(&req).is_err());
    }

    // ── policies.rs additional ──

    #[test]
    fn create_policy_duplicate_errors() {
        let svc = make_service();
        let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
        let req = make_request(
            "CreatePolicy",
            vec![("PolicyName", "dp"), ("PolicyDocument", doc)],
        );
        svc.create_policy(&req).unwrap();
        assert!(svc.create_policy(&req).is_err());
    }

    #[test]
    fn delete_policy_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "DeletePolicy",
            vec![("PolicyArn", "arn:aws:iam::123456789012:policy/ghost")],
        );
        assert!(svc.delete_policy(&req).is_err());
    }

    #[test]
    fn get_policy_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "GetPolicy",
            vec![("PolicyArn", "arn:aws:iam::123456789012:policy/ghost")],
        );
        assert!(svc.get_policy(&req).is_err());
    }

    // ── instance profiles ──

    #[test]
    fn create_instance_profile_duplicate() {
        let svc = make_service();
        let req = make_request(
            "CreateInstanceProfile",
            vec![("InstanceProfileName", "ip1")],
        );
        svc.create_instance_profile(&req).unwrap();
        assert!(svc.create_instance_profile(&req).is_err());
    }

    #[test]
    fn delete_instance_profile_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "DeleteInstanceProfile",
            vec![("InstanceProfileName", "ghost")],
        );
        assert!(svc.delete_instance_profile(&req).is_err());
    }

    // ── instance_profiles additional ──

    #[test]
    fn get_instance_profile_unknown_errors() {
        let svc = make_service();
        let req = make_request("GetInstanceProfile", vec![("InstanceProfileName", "ghost")]);
        assert!(svc.get_instance_profile(&req).is_err());
    }

    #[test]
    fn list_instance_profiles_empty_returns_ok() {
        let svc = make_service();
        let req = make_request("ListInstanceProfiles", vec![]);
        let resp = svc.list_instance_profiles(&req).unwrap();
        assert_eq!(resp.status, http::StatusCode::OK);
    }

    #[test]
    fn add_role_to_instance_profile_unknown_profile_errors() {
        let svc = make_service();
        let req = make_request(
            "AddRoleToInstanceProfile",
            vec![("InstanceProfileName", "ghost"), ("RoleName", "r")],
        );
        assert!(svc.add_role_to_instance_profile(&req).is_err());
    }

    #[test]
    fn remove_role_from_instance_profile_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "RemoveRoleFromInstanceProfile",
            vec![("InstanceProfileName", "ghost"), ("RoleName", "r")],
        );
        assert!(svc.remove_role_from_instance_profile(&req).is_err());
    }

    #[test]
    fn list_instance_profiles_for_role_unknown_errors() {
        let svc = make_service();
        let req = make_request("ListInstanceProfilesForRole", vec![("RoleName", "ghost")]);
        assert!(svc.list_instance_profiles_for_role(&req).is_err());
    }

    #[test]
    fn list_instance_profile_tags_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "ListInstanceProfileTags",
            vec![("InstanceProfileName", "ghost")],
        );
        assert!(svc.list_instance_profile_tags(&req).is_err());
    }

    // ── OIDC/SAML error branches ──

    #[test]
    fn get_saml_provider_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "GetSAMLProvider",
            vec![(
                "SAMLProviderArn",
                "arn:aws:iam::123456789012:saml-provider/ghost",
            )],
        );
        assert!(svc.get_saml_provider(&req).is_err());
    }

    #[test]
    fn delete_saml_provider_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "DeleteSAMLProvider",
            vec![(
                "SAMLProviderArn",
                "arn:aws:iam::123456789012:saml-provider/ghost",
            )],
        );
        assert!(svc.delete_saml_provider(&req).is_err());
    }

    #[test]
    fn update_saml_provider_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "UpdateSAMLProvider",
            vec![
                (
                    "SAMLProviderArn",
                    "arn:aws:iam::123456789012:saml-provider/ghost",
                ),
                ("SAMLMetadataDocument", "<xml/>"),
            ],
        );
        assert!(svc.update_saml_provider(&req).is_err());
    }

    #[test]
    fn get_oidc_provider_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "GetOpenIDConnectProvider",
            vec![(
                "OpenIDConnectProviderArn",
                "arn:aws:iam::123456789012:oidc-provider/ghost",
            )],
        );
        assert!(svc.get_oidc_provider(&req).is_err());
    }

    // ── policies: version operations ──

    #[test]
    fn create_policy_version_unknown_errors() {
        let svc = make_service();
        let doc = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;
        let req = make_request(
            "CreatePolicyVersion",
            vec![
                ("PolicyArn", "arn:aws:iam::123456789012:policy/ghost"),
                ("PolicyDocument", doc),
            ],
        );
        assert!(svc.create_policy_version(&req).is_err());
    }

    #[test]
    fn list_policy_versions_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "ListPolicyVersions",
            vec![("PolicyArn", "arn:aws:iam::123456789012:policy/ghost")],
        );
        assert!(svc.list_policy_versions(&req).is_err());
    }

    #[test]
    fn get_policy_version_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "GetPolicyVersion",
            vec![
                ("PolicyArn", "arn:aws:iam::123456789012:policy/ghost"),
                ("VersionId", "v1"),
            ],
        );
        assert!(svc.get_policy_version(&req).is_err());
    }

    #[test]
    fn delete_policy_version_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "DeletePolicyVersion",
            vec![
                ("PolicyArn", "arn:aws:iam::123456789012:policy/ghost"),
                ("VersionId", "v1"),
            ],
        );
        assert!(svc.delete_policy_version(&req).is_err());
    }

    // ── roles: put/get/delete_role_policy inline ──

    #[test]
    fn put_role_policy_unknown_role_errors() {
        let svc = make_service();
        let req = make_request(
            "PutRolePolicy",
            vec![
                ("RoleName", "ghost"),
                ("PolicyName", "p1"),
                ("PolicyDocument", "{}"),
            ],
        );
        assert!(svc.put_role_policy(&req).is_err());
    }

    #[test]
    fn get_role_policy_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "GetRolePolicy",
            vec![("RoleName", "ghost"), ("PolicyName", "p1")],
        );
        assert!(svc.get_role_policy(&req).is_err());
    }

    #[test]
    fn delete_role_policy_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "DeleteRolePolicy",
            vec![("RoleName", "ghost"), ("PolicyName", "p1")],
        );
        assert!(svc.delete_role_policy(&req).is_err());
    }

    #[test]
    fn list_role_policies_unknown_errors() {
        let svc = make_service();
        let req = make_request("ListRolePolicies", vec![("RoleName", "ghost")]);
        assert!(svc.list_role_policies(&req).is_err());
    }

    // ── user inline policies ──

    #[test]
    fn put_user_policy_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "PutUserPolicy",
            vec![
                ("UserName", "ghost"),
                ("PolicyName", "p"),
                ("PolicyDocument", "{}"),
            ],
        );
        assert!(svc.put_user_policy(&req).is_err());
    }

    #[test]
    fn list_user_policies_unknown_errors() {
        let svc = make_service();
        let req = make_request("ListUserPolicies", vec![("UserName", "ghost")]);
        assert!(svc.list_user_policies(&req).is_err());
    }

    #[test]
    fn get_user_policy_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "GetUserPolicy",
            vec![("UserName", "ghost"), ("PolicyName", "p")],
        );
        assert!(svc.get_user_policy(&req).is_err());
    }

    #[test]
    fn delete_user_policy_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "DeleteUserPolicy",
            vec![("UserName", "ghost"), ("PolicyName", "p")],
        );
        assert!(svc.delete_user_policy(&req).is_err());
    }

    #[test]
    fn put_group_policy_unknown_group_errors() {
        let svc = make_service();
        let req = make_request(
            "PutGroupPolicy",
            vec![
                ("GroupName", "ghost"),
                ("PolicyName", "p"),
                ("PolicyDocument", "{}"),
            ],
        );
        assert!(svc.put_group_policy(&req).is_err());
    }

    #[test]
    fn get_group_policy_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "GetGroupPolicy",
            vec![("GroupName", "ghost"), ("PolicyName", "p")],
        );
        assert!(svc.get_group_policy(&req).is_err());
    }

    #[test]
    fn delete_group_policy_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "DeleteGroupPolicy",
            vec![("GroupName", "ghost"), ("PolicyName", "p")],
        );
        assert!(svc.delete_group_policy(&req).is_err());
    }

    #[test]
    fn list_group_policies_unknown_errors() {
        let svc = make_service();
        let req = make_request("ListGroupPolicies", vec![("GroupName", "ghost")]);
        assert!(svc.list_group_policies(&req).is_err());
    }

    #[test]
    fn attach_group_policy_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "AttachGroupPolicy",
            vec![
                ("GroupName", "ghost"),
                ("PolicyArn", "arn:aws:iam::aws:policy/ReadOnlyAccess"),
            ],
        );
        assert!(svc.attach_group_policy(&req).is_err());
    }

    #[test]
    fn detach_group_policy_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "DetachGroupPolicy",
            vec![
                ("GroupName", "ghost"),
                ("PolicyArn", "arn:aws:iam::aws:policy/ReadOnlyAccess"),
            ],
        );
        assert!(svc.detach_group_policy(&req).is_err());
    }

    #[test]
    fn list_attached_group_policies_unknown_errors() {
        let svc = make_service();
        let req = make_request("ListAttachedGroupPolicies", vec![("GroupName", "ghost")]);
        assert!(svc.list_attached_group_policies(&req).is_err());
    }

    #[test]
    fn list_groups_for_user_unknown_errors() {
        let svc = make_service();
        let req = make_request("ListGroupsForUser", vec![("UserName", "ghost")]);
        assert!(svc.list_groups_for_user(&req).is_err());
    }

    #[test]
    fn get_account_summary_returns_ok() {
        let svc = make_service();
        let req = make_request("GetAccountSummary", vec![]);
        let resp = svc.get_account_summary(&req).unwrap();
        assert_eq!(resp.status, http::StatusCode::OK);
    }

    #[test]
    fn list_policies_empty_ok() {
        let svc = make_service();
        let req = make_request("ListPolicies", vec![]);
        let resp = svc.list_policies(&req).unwrap();
        assert_eq!(resp.status, http::StatusCode::OK);
    }

    #[test]
    fn list_users_empty_ok() {
        let svc = make_service();
        let req = make_request("ListUsers", vec![]);
        let resp = svc.list_users(&req).unwrap();
        assert_eq!(resp.status, http::StatusCode::OK);
    }

    #[test]
    fn list_roles_empty_ok() {
        let svc = make_service();
        let req = make_request("ListRoles", vec![]);
        let resp = svc.list_roles(&req).unwrap();
        assert_eq!(resp.status, http::StatusCode::OK);
    }

    #[test]
    fn list_groups_empty_ok() {
        let svc = make_service();
        let req = make_request("ListGroups", vec![]);
        let resp = svc.list_groups(&req).unwrap();
        assert_eq!(resp.status, http::StatusCode::OK);
    }

    #[test]
    fn list_attached_role_policies_unknown_errors() {
        let svc = make_service();
        let req = make_request("ListAttachedRolePolicies", vec![("RoleName", "ghost")]);
        assert!(svc.list_attached_role_policies(&req).is_err());
    }

    #[test]
    fn attach_role_policy_unknown_role_errors() {
        let svc = make_service();
        let req = make_request(
            "AttachRolePolicy",
            vec![
                ("RoleName", "ghost"),
                ("PolicyArn", "arn:aws:iam::aws:policy/ReadOnlyAccess"),
            ],
        );
        assert!(svc.attach_role_policy(&req).is_err());
    }

    #[test]
    fn detach_role_policy_unknown_role_errors() {
        let svc = make_service();
        let req = make_request(
            "DetachRolePolicy",
            vec![
                ("RoleName", "ghost"),
                ("PolicyArn", "arn:aws:iam::aws:policy/ReadOnlyAccess"),
            ],
        );
        assert!(svc.detach_role_policy(&req).is_err());
    }

    #[test]
    fn update_role_description_unknown_errors() {
        let svc = make_service();
        let req = make_request(
            "UpdateRole",
            vec![("RoleName", "ghost"), ("Description", "new")],
        );
        assert!(svc.update_role(&req).is_err());
    }

    // ── SAML / OIDC providers + update paths (oidc.rs) ────────────────

    #[test]
    fn saml_provider_full_lifecycle() {
        let svc = make_service();

        let create = svc
            .create_saml_provider(&make_request(
                "CreateSAMLProvider",
                vec![
                    ("Name", "my-saml"),
                    ("SAMLMetadataDocument", "<EntityDescriptor/>"),
                ],
            ))
            .unwrap();
        let body = std::str::from_utf8(create.body.expect_bytes()).unwrap();
        let arn = extract_xml_tag(body, "SAMLProviderArn").to_string();
        assert!(arn.ends_with(":saml-provider/my-saml"));

        let get = svc
            .get_saml_provider(&make_request(
                "GetSAMLProvider",
                vec![("SAMLProviderArn", &arn)],
            ))
            .unwrap();
        let get_body = std::str::from_utf8(get.body.expect_bytes()).unwrap();
        assert!(get_body.contains("&lt;EntityDescriptor/&gt;"));

        let list = svc
            .list_saml_providers(&make_request("ListSAMLProviders", vec![]))
            .unwrap();
        let list_body = std::str::from_utf8(list.body.expect_bytes()).unwrap();
        assert!(list_body.contains(&arn));

        let update = svc
            .update_saml_provider(&make_request(
                "UpdateSAMLProvider",
                vec![
                    ("SAMLProviderArn", &arn),
                    ("SAMLMetadataDocument", "<NewMetadata/>"),
                ],
            ))
            .unwrap();
        let update_body = std::str::from_utf8(update.body.expect_bytes()).unwrap();
        assert!(update_body.contains(&arn));

        svc.delete_saml_provider(&make_request(
            "DeleteSAMLProvider",
            vec![("SAMLProviderArn", &arn)],
        ))
        .unwrap();
        assert!(svc
            .get_saml_provider(&make_request(
                "GetSAMLProvider",
                vec![("SAMLProviderArn", &arn)]
            ))
            .is_err());
    }

    #[test]
    fn oidc_provider_duplicate_rejected() {
        let svc = make_service();
        let params = vec![
            ("Url", "https://example.com"),
            (
                "ThumbprintList.member.1",
                "abcdef1234567890abcdef1234567890abcdef12",
            ),
            ("ClientIDList.member.1", "client-1"),
        ];
        svc.create_oidc_provider(&make_request("CreateOpenIDConnectProvider", params.clone()))
            .unwrap();
        let err = svc
            .create_oidc_provider(&make_request("CreateOpenIDConnectProvider", params))
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::CONFLICT);
    }

    #[test]
    fn oidc_add_and_remove_client_id() {
        let svc = make_service();
        let create = svc
            .create_oidc_provider(&make_request(
                "CreateOpenIDConnectProvider",
                vec![
                    ("Url", "https://client-ops.example.com"),
                    (
                        "ThumbprintList.member.1",
                        "abcdef1234567890abcdef1234567890abcdef12",
                    ),
                    ("ClientIDList.member.1", "original-client"),
                ],
            ))
            .unwrap();
        let body = std::str::from_utf8(create.body.expect_bytes()).unwrap();
        let arn = extract_xml_tag(body, "OpenIDConnectProviderArn").to_string();

        svc.add_client_id_to_oidc(&make_request(
            "AddClientIDToOpenIDConnectProvider",
            vec![
                ("OpenIDConnectProviderArn", &arn),
                ("ClientID", "new-client"),
            ],
        ))
        .unwrap();

        let get = svc
            .get_oidc_provider(&make_request(
                "GetOpenIDConnectProvider",
                vec![("OpenIDConnectProviderArn", &arn)],
            ))
            .unwrap();
        let get_body = std::str::from_utf8(get.body.expect_bytes()).unwrap();
        assert!(get_body.contains("new-client"));

        svc.remove_client_id_from_oidc(&make_request(
            "RemoveClientIDFromOpenIDConnectProvider",
            vec![
                ("OpenIDConnectProviderArn", &arn),
                ("ClientID", "new-client"),
            ],
        ))
        .unwrap();
        let get2 = svc
            .get_oidc_provider(&make_request(
                "GetOpenIDConnectProvider",
                vec![("OpenIDConnectProviderArn", &arn)],
            ))
            .unwrap();
        let get2_body = std::str::from_utf8(get2.body.expect_bytes()).unwrap();
        assert!(!get2_body.contains("new-client"));
    }

    #[test]
    fn oidc_add_client_id_unknown_arn_errors() {
        let svc = make_service();
        let err = svc
            .add_client_id_to_oidc(&make_request(
                "AddClientIDToOpenIDConnectProvider",
                vec![
                    (
                        "OpenIDConnectProviderArn",
                        "arn:aws:iam::123:oidc-provider/ghost",
                    ),
                    ("ClientID", "c"),
                ],
            ))
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn oidc_remove_client_id_unknown_arn_errors() {
        let svc = make_service();
        let err = svc
            .remove_client_id_from_oidc(&make_request(
                "RemoveClientIDFromOpenIDConnectProvider",
                vec![
                    (
                        "OpenIDConnectProviderArn",
                        "arn:aws:iam::123:oidc-provider/ghost",
                    ),
                    ("ClientID", "c"),
                ],
            ))
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn oidc_update_thumbprint_unknown_arn_errors() {
        let svc = make_service();
        let err = svc
            .update_oidc_thumbprint(&make_request(
                "UpdateOpenIDConnectProviderThumbprint",
                vec![
                    (
                        "OpenIDConnectProviderArn",
                        "arn:aws:iam::123:oidc-provider/ghost",
                    ),
                    (
                        "ThumbprintList.member.1",
                        "abcdef1234567890abcdef1234567890abcdef12",
                    ),
                ],
            ))
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn oidc_update_thumbprint_succeeds() {
        let svc = make_service();
        let create = svc
            .create_oidc_provider(&make_request(
                "CreateOpenIDConnectProvider",
                vec![
                    ("Url", "https://thumb.example.com"),
                    (
                        "ThumbprintList.member.1",
                        "abcdef1234567890abcdef1234567890abcdef12",
                    ),
                    ("ClientIDList.member.1", "c"),
                ],
            ))
            .unwrap();
        let body = std::str::from_utf8(create.body.expect_bytes()).unwrap();
        let arn = extract_xml_tag(body, "OpenIDConnectProviderArn").to_string();

        svc.update_oidc_thumbprint(&make_request(
            "UpdateOpenIDConnectProviderThumbprint",
            vec![
                ("OpenIDConnectProviderArn", &arn),
                (
                    "ThumbprintList.member.1",
                    "fedcba0987654321fedcba0987654321fedcba09",
                ),
            ],
        ))
        .unwrap();

        let get = svc
            .get_oidc_provider(&make_request(
                "GetOpenIDConnectProvider",
                vec![("OpenIDConnectProviderArn", &arn)],
            ))
            .unwrap();
        let get_body = std::str::from_utf8(get.body.expect_bytes()).unwrap();
        assert!(get_body.contains("fedcba0987654321"));
    }

    #[test]
    fn list_oidc_providers_includes_created() {
        let svc = make_service();
        svc.create_oidc_provider(&make_request(
            "CreateOpenIDConnectProvider",
            vec![
                ("Url", "https://list.example.com"),
                (
                    "ThumbprintList.member.1",
                    "abcdef1234567890abcdef1234567890abcdef12",
                ),
                ("ClientIDList.member.1", "cx"),
            ],
        ))
        .unwrap();

        let list = svc
            .list_oidc_providers(&make_request("ListOpenIDConnectProviders", vec![]))
            .unwrap();
        let list_body = std::str::from_utf8(list.body.expect_bytes()).unwrap();
        assert!(list_body.contains("list.example.com"));
    }

    // ── Tests for extras handlers (new ops added to close conformance gap) ──

    #[test]
    fn service_specific_credentials_lifecycle() {
        let svc = make_service();
        svc.create_user(&make_request("CreateUser", vec![("UserName", "u1")]))
            .unwrap();
        svc.create_service_specific_credential(&make_request(
            "CreateServiceSpecificCredential",
            vec![
                ("UserName", "u1"),
                ("ServiceName", "codecommit.amazonaws.com"),
            ],
        ))
        .unwrap();
        svc.list_service_specific_credentials(&make_request(
            "ListServiceSpecificCredentials",
            vec![("UserName", "u1")],
        ))
        .unwrap();
    }

    #[test]
    fn delegation_request_lifecycle() {
        let svc = make_service();
        let resp = svc
            .create_delegation_request(&make_request(
                "CreateDelegationRequest",
                vec![
                    ("TargetAccount", "999999999999"),
                    ("Permissions.member.1", "s3:Get*"),
                ],
            ))
            .unwrap();
        let body = String::from_utf8(resp.body.expect_bytes().to_vec()).unwrap();
        let id = extract_xml_tag(&body, "DelegationRequestId");
        svc.get_delegation_request(&make_request(
            "GetDelegationRequest",
            vec![("DelegationRequestId", id)],
        ))
        .unwrap();
        svc.list_delegation_requests(&make_request("ListDelegationRequests", vec![]))
            .unwrap();
    }

    #[test]
    fn organizations_root_creds_and_sessions() {
        let svc = make_service();
        svc.enable_organizations_root_credentials_management(&make_request(
            "EnableOrganizationsRootCredentialsManagement",
            vec![],
        ))
        .unwrap();
        svc.disable_organizations_root_credentials_management(&make_request(
            "DisableOrganizationsRootCredentialsManagement",
            vec![],
        ))
        .unwrap();
        svc.enable_organizations_root_sessions(&make_request(
            "EnableOrganizationsRootSessions",
            vec![],
        ))
        .unwrap();
        svc.disable_organizations_root_sessions(&make_request(
            "DisableOrganizationsRootSessions",
            vec![],
        ))
        .unwrap();
        svc.list_organizations_features(&make_request("ListOrganizationsFeatures", vec![]))
            .unwrap();
    }

    #[test]
    fn outbound_wif_round_trip() {
        let svc = make_service();
        svc.enable_outbound_web_identity_federation(&make_request(
            "EnableOutboundWebIdentityFederation",
            vec![],
        ))
        .unwrap();
        svc.get_outbound_web_identity_federation_info(&make_request(
            "GetOutboundWebIdentityFederationInfo",
            vec![],
        ))
        .unwrap();
        svc.disable_outbound_web_identity_federation(&make_request(
            "DisableOutboundWebIdentityFederation",
            vec![],
        ))
        .unwrap();
    }

    #[test]
    fn service_last_accessed_jobs() {
        let svc = make_service();
        let resp = svc
            .generate_service_last_accessed_details(&make_request(
                "GenerateServiceLastAccessedDetails",
                vec![("Arn", "arn:aws:iam::123456789012:user/u1")],
            ))
            .unwrap();
        let body = String::from_utf8(resp.body.expect_bytes().to_vec()).unwrap();
        let job_id = extract_xml_tag(&body, "JobId");
        svc.get_service_last_accessed_details(&make_request(
            "GetServiceLastAccessedDetails",
            vec![("JobId", job_id)],
        ))
        .unwrap();
        svc.get_service_last_accessed_details_with_entities(&make_request(
            "GetServiceLastAccessedDetailsWithEntities",
            vec![("JobId", job_id), ("ServiceNamespace", "s3")],
        ))
        .unwrap();
    }

    #[test]
    fn extra_tagging_surfaces() {
        let svc = make_service();
        // Pre-create entities the tag handlers expect
        svc.create_saml_provider(&make_request(
            "CreateSAMLProvider",
            vec![
                ("Name", "sp1"),
                ("SAMLMetadataDocument", "<EntityDescriptor/>"),
            ],
        ))
        .unwrap();
        svc.tag_saml_provider(&make_request(
            "TagSAMLProvider",
            vec![
                (
                    "SAMLProviderArn",
                    "arn:aws:iam::123456789012:saml-provider/sp1",
                ),
                ("Tags.member.1.Key", "k"),
                ("Tags.member.1.Value", "v"),
            ],
        ))
        .unwrap();
        svc.list_saml_provider_tags(&make_request(
            "ListSAMLProviderTags",
            vec![(
                "SAMLProviderArn",
                "arn:aws:iam::123456789012:saml-provider/sp1",
            )],
        ))
        .unwrap();
        svc.untag_saml_provider(&make_request(
            "UntagSAMLProvider",
            vec![
                (
                    "SAMLProviderArn",
                    "arn:aws:iam::123456789012:saml-provider/sp1",
                ),
                ("TagKeys.member.1", "k"),
            ],
        ))
        .unwrap();
    }

    #[test]
    fn policy_simulation_smoke() {
        let svc = make_service();
        let policy = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;
        svc.simulate_custom_policy(&make_request(
            "SimulateCustomPolicy",
            vec![
                ("PolicyInputList.member.1", policy),
                ("ActionNames.member.1", "s3:GetObject"),
                ("ResourceArns.member.1", "arn:aws:s3:::b/k"),
            ],
        ))
        .unwrap();
        svc.get_context_keys_for_custom_policy(&make_request(
            "GetContextKeysForCustomPolicy",
            vec![("PolicyInputList.member.1", policy)],
        ))
        .unwrap();
    }

    #[test]
    fn misc_extras_smoke() {
        let svc = make_service();
        svc.create_user(&make_request("CreateUser", vec![("UserName", "u1")]))
            .unwrap();
        svc.create_login_profile(&make_request(
            "CreateLoginProfile",
            vec![("UserName", "u1"), ("Password", "p")],
        ))
        .unwrap();
        svc.change_password(&make_request(
            "ChangePassword",
            vec![("OldPassword", "p"), ("NewPassword", "q")],
        ))
        .unwrap();
        svc.get_human_readable_summary(&make_request("GetHumanReadableSummary", vec![]))
            .unwrap();
        svc.set_security_token_service_preferences(&make_request(
            "SetSecurityTokenServicePreferences",
            vec![("GlobalEndpointTokenVersion", "v2Token")],
        ))
        .unwrap();
    }
}
