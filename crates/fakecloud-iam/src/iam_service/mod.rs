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

use fakecloud_core::pagination::paginate;
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

    let next_token = req.query_params.get("Marker").map(|s| s.as_str());
    let (page, next_marker) = paginate(tags, next_token, max_items);

    let is_truncated = next_marker.is_some();
    let members = tags_xml(&page);
    let marker = match &next_marker {
        Some(m) => format!("<Marker>{m}</Marker>"),
        None => String::new(),
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
mod tests;
