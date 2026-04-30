mod auth;
mod branding;
mod config;
mod groups;
mod identity_providers;
mod legacy;
mod mfa;
mod misc;
mod resource_servers;
mod user_pools;
mod users;

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use chrono::Utc;
use http::StatusCode;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex as AsyncMutex;
use uuid::Uuid;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
use fakecloud_persistence::SnapshotStore;

use crate::state::{
    AccountRecoverySetting, AdminCreateUserConfig, CognitoSnapshot, Device, EmailConfiguration,
    Group, IdentityProvider, InviteMessageTemplate, PasswordPolicy, RecoveryOption, ResourceServer,
    ResourceServerScope, SchemaAttribute, SharedCognitoState, SignInPolicy, SmsConfiguration,
    StringAttributeConstraints, TokenValidityUnits, User, UserAttribute, UserImportJob, UserPool,
    UserPoolClient, UserPoolDomain, VerificationMessageTemplate, COGNITO_SNAPSHOT_SCHEMA_VERSION,
};
use crate::triggers::CognitoDeliveryContext;

pub struct CognitoService {
    state: SharedCognitoState,
    delivery_ctx: Option<CognitoDeliveryContext>,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    snapshot_lock: Arc<AsyncMutex<()>>,
}

impl CognitoService {
    pub fn new(state: SharedCognitoState) -> Self {
        Self {
            state,
            delivery_ctx: None,
            snapshot_store: None,
            snapshot_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    /// Attach a delivery context for Lambda trigger invocation.
    pub fn with_delivery(mut self, ctx: CognitoDeliveryContext) -> Self {
        self.delivery_ctx = Some(ctx);
        self
    }

    pub fn with_snapshot_store(mut self, store: Arc<dyn SnapshotStore>) -> Self {
        self.snapshot_store = Some(store);
        self
    }

    /// Dispatch a Cognito verification email. Routes through the
    /// CustomEmailSender Lambda when configured on the pool; otherwise
    /// invokes the CustomMessage trigger (synchronously, so its response
    /// can override subject+body) and then sends through the wired SES
    /// dispatcher. No-op when neither is wired. Returns immediately —
    /// all work happens in a spawned task.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_verification_email(
        &self,
        pool_id: &str,
        client_id: Option<&str>,
        username: &str,
        user_attributes: &[crate::state::UserAttribute],
        to_email: &str,
        code: &str,
        custom_message_trigger: crate::triggers::TriggerSource,
        custom_sender_trigger: crate::triggers::TriggerSource,
        region: &str,
        account_id: &str,
    ) {
        let Some(ref ctx) = self.delivery_ctx else {
            return;
        };

        // Custom sender path takes precedence per AWS behavior.
        if let Some(function_arn) =
            crate::triggers::get_trigger_arn(&self.state, pool_id, custom_sender_trigger)
        {
            let event = crate::triggers::build_custom_sender_event(
                custom_sender_trigger,
                pool_id,
                client_id,
                username,
                user_attributes,
                code,
                region,
                account_id,
            );
            crate::triggers::invoke_trigger_fire_and_forget(ctx, function_arn, event);
            return;
        }

        let Some(ref dispatcher) = ctx.email else {
            return;
        };
        let custom_message_arn =
            crate::triggers::get_trigger_arn(&self.state, pool_id, custom_message_trigger);
        let pool_settings = {
            let accounts = self.state.read();
            accounts
                .default_ref()
                .user_pools
                .get(pool_id)
                .map(|p| {
                    let from = p
                        .email_configuration
                        .as_ref()
                        .and_then(|c| c.from_email_address.clone());
                    let template = p.verification_message_template.clone();
                    (from, template)
                })
                .unwrap_or((None, None))
        };
        let (from_addr, vmt) = pool_settings;
        let (subject_tpl_default, msg_tpl_default) = vmt
            .map(|t| (t.email_subject, t.email_message))
            .unwrap_or((None, None));

        let dispatcher = dispatcher.clone();
        let ctx = ctx.clone();
        let username_owned = username.to_string();
        let client_id_owned = client_id.map(|s| s.to_string());
        let pool_id_owned = pool_id.to_string();
        let region_owned = region.to_string();
        let account_id_owned = account_id.to_string();
        let user_attrs_owned: Vec<crate::state::UserAttribute> = user_attributes.to_vec();
        let to_email_owned = to_email.to_string();
        let code_owned = code.to_string();
        tokio::spawn(async move {
            let mut subject_tpl = subject_tpl_default;
            let mut msg_tpl = msg_tpl_default;
            if let Some(function_arn) = custom_message_arn {
                let mut event = crate::triggers::build_trigger_event(
                    custom_message_trigger,
                    &pool_id_owned,
                    client_id_owned.as_deref(),
                    &username_owned,
                    &user_attrs_owned,
                    &region_owned,
                    &account_id_owned,
                );
                event["request"]["codeParameter"] = serde_json::json!("{####}");
                event["request"]["usernameParameter"] = serde_json::json!(username_owned);
                if let Some(resp) =
                    crate::triggers::invoke_trigger(&ctx, &function_arn, &event).await
                {
                    if let Some(s) = resp["response"]["emailSubject"].as_str() {
                        subject_tpl = Some(s.to_string());
                    }
                    if let Some(m) = resp["response"]["emailMessage"].as_str() {
                        msg_tpl = Some(m.to_string());
                    }
                }
            }
            let rendered = crate::triggers::render_verification_email(
                from_addr.as_deref(),
                subject_tpl.as_deref(),
                msg_tpl.as_deref(),
                &username_owned,
                &code_owned,
            );
            dispatcher.send_email(
                &account_id_owned,
                &rendered.from,
                &to_email_owned,
                &rendered.subject,
                &rendered.body_text,
                rendered.body_html.as_deref(),
            );
        });
    }

    /// Dispatch a Cognito verification SMS. Routes through the
    /// CustomSMSSender Lambda when configured, otherwise through the
    /// wired SNS dispatcher. No-op when neither is wired.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn dispatch_verification_sms(
        &self,
        pool_id: &str,
        client_id: Option<&str>,
        username: &str,
        user_attributes: &[crate::state::UserAttribute],
        phone_number: &str,
        code: &str,
        custom_sender_trigger: crate::triggers::TriggerSource,
        region: &str,
        account_id: &str,
    ) {
        let Some(ref ctx) = self.delivery_ctx else {
            return;
        };

        if let Some(function_arn) =
            crate::triggers::get_trigger_arn(&self.state, pool_id, custom_sender_trigger)
        {
            let event = crate::triggers::build_custom_sender_event(
                custom_sender_trigger,
                pool_id,
                client_id,
                username,
                user_attributes,
                code,
                region,
                account_id,
            );
            crate::triggers::invoke_trigger_fire_and_forget(ctx, function_arn, event);
            return;
        }

        let Some(ref dispatcher) = ctx.sms else {
            return;
        };
        let sms_template = {
            let accounts = self.state.read();
            accounts
                .default_ref()
                .user_pools
                .get(pool_id)
                .and_then(|p| {
                    p.verification_message_template
                        .as_ref()
                        .and_then(|t| t.sms_message.clone())
                })
        };
        let message =
            crate::triggers::render_verification_sms(sms_template.as_deref(), username, code);
        let dispatcher = dispatcher.clone();
        let acct = account_id.to_string();
        let phone = phone_number.to_string();
        tokio::spawn(async move {
            dispatcher.send_sms(&acct, &phone, &message);
        });
    }

    /// Persist current state as a snapshot. Held across the
    /// clone-serialize-write sequence to prevent stale-last writes,
    /// with serde + file I/O offloaded to the blocking pool.
    async fn save_snapshot(&self) {
        let Some(store) = self.snapshot_store.clone() else {
            return;
        };
        let _guard = self.snapshot_lock.lock().await;
        let snapshot = CognitoSnapshot {
            schema_version: COGNITO_SNAPSHOT_SCHEMA_VERSION,
            accounts: Some(self.state.read().clone()),
            state: None,
        };
        let join = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let bytes = serde_json::to_vec(&snapshot)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            store.save(&bytes)
        })
        .await;
        match join {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(%err, "failed to write cognito snapshot"),
            Err(err) => tracing::error!(%err, "cognito snapshot task panicked"),
        }
    }
}

/// Actions that mutate persistent state. List excludes pure reads
/// (`Describe*`, `List*`, `Get*`, `AdminGet*`, `AdminList*`) and any
/// other action that doesn't change state stored in `CognitoState`.
fn is_mutating_action(action: &str) -> bool {
    !matches!(
        action,
        "DescribeUserPool"
            | "DescribeUserPoolClient"
            | "DescribeUserPoolDomain"
            | "DescribeIdentityProvider"
            | "DescribeResourceServer"
            | "DescribeRiskConfiguration"
            | "DescribeManagedLoginBranding"
            | "DescribeManagedLoginBrandingByClient"
            | "DescribeUserImportJob"
            | "DescribeTerms"
            | "ListUserPools"
            | "ListUserPoolClients"
            | "ListUserPoolClientSecrets"
            | "ListUsers"
            | "ListUsersInGroup"
            | "ListGroups"
            | "ListIdentityProviders"
            | "ListResourceServers"
            | "ListDevices"
            | "ListTagsForResource"
            | "ListUserImportJobs"
            | "ListTerms"
            | "ListWebAuthnCredentials"
            | "AdminGetUser"
            | "AdminGetDevice"
            | "AdminListDevices"
            | "AdminListGroupsForUser"
            | "AdminListUserAuthEvents"
            | "GetUser"
            | "GetGroup"
            | "GetDevice"
            | "GetUserPoolMfaConfig"
            | "GetUserAuthFactors"
            | "GetUICustomization"
            | "GetLogDeliveryConfiguration"
            | "GetSigningCertificate"
            | "GetCSVHeader"
            | "GetIdentityProviderByIdentifier"
    )
}

#[async_trait]
impl AwsService for CognitoService {
    fn service_name(&self) -> &str {
        "cognito-idp"
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mutates = is_mutating_action(req.action.as_str());
        let result = match req.action.as_str() {
            "CreateUserPool" => self.create_user_pool(&req),
            "DescribeUserPool" => self.describe_user_pool(&req),
            "UpdateUserPool" => self.update_user_pool(&req),
            "DeleteUserPool" => self.delete_user_pool(&req),
            "ListUserPools" => self.list_user_pools(&req),
            "CreateUserPoolClient" => self.create_user_pool_client(&req),
            "DescribeUserPoolClient" => self.describe_user_pool_client(&req),
            "UpdateUserPoolClient" => self.update_user_pool_client(&req),
            "DeleteUserPoolClient" => self.delete_user_pool_client(&req),
            "ListUserPoolClients" => self.list_user_pool_clients(&req),
            "AddCustomAttributes" => self.add_custom_attributes(&req),
            "AddUserPoolClientSecret" => self.add_user_pool_client_secret(&req),
            "DeleteUserPoolClientSecret" => self.delete_user_pool_client_secret(&req),
            "ListUserPoolClientSecrets" => self.list_user_pool_client_secrets(&req),
            "GetSigningCertificate" => self.get_signing_certificate(&req),
            "AdminCreateUser" => self.admin_create_user(&req).await,
            "AdminGetUser" => self.admin_get_user(&req),
            "AdminDeleteUser" => self.admin_delete_user(&req),
            "AdminDisableUser" => self.admin_disable_user(&req),
            "AdminEnableUser" => self.admin_enable_user(&req),
            "AdminUpdateUserAttributes" => self.admin_update_user_attributes(&req),
            "AdminDeleteUserAttributes" => self.admin_delete_user_attributes(&req),
            "ListUsers" => self.list_users(&req),
            "AdminSetUserPassword" => self.admin_set_user_password(&req),
            "AdminInitiateAuth" => self.admin_initiate_auth(&req).await,
            "InitiateAuth" => self.initiate_auth(&req).await,
            "RespondToAuthChallenge" => self.respond_to_auth_challenge(&req).await,
            "AdminRespondToAuthChallenge" => self.admin_respond_to_auth_challenge(&req).await,
            "SignUp" => self.sign_up(&req).await,
            "ConfirmSignUp" => self.confirm_sign_up(&req).await,
            "AdminConfirmSignUp" => self.admin_confirm_sign_up(&req).await,
            "ChangePassword" => self.change_password(&req),
            "ForgotPassword" => self.forgot_password(&req).await,
            "ConfirmForgotPassword" => self.confirm_forgot_password(&req),
            "AdminResetUserPassword" => self.admin_reset_user_password(&req),
            "GlobalSignOut" => self.global_sign_out(&req),
            "AdminUserGlobalSignOut" => self.admin_user_global_sign_out(&req),
            "CreateGroup" => self.create_group(&req),
            "DeleteGroup" => self.delete_group(&req),
            "GetGroup" => self.get_group(&req),
            "UpdateGroup" => self.update_group(&req),
            "ListGroups" => self.list_groups(&req),
            "AdminAddUserToGroup" => self.admin_add_user_to_group(&req),
            "AdminRemoveUserFromGroup" => self.admin_remove_user_from_group(&req),
            "AdminListGroupsForUser" => self.admin_list_groups_for_user(&req),
            "ListUsersInGroup" => self.list_users_in_group(&req),
            "GetUser" => self.get_user(&req),
            "DeleteUser" => self.delete_user(&req),
            "UpdateUserAttributes" => self.update_user_attributes(&req),
            "DeleteUserAttributes" => self.delete_user_attributes(&req),
            "GetUserAttributeVerificationCode" => self.get_user_attribute_verification_code(&req),
            "VerifyUserAttribute" => self.verify_user_attribute(&req),
            "ResendConfirmationCode" => self.resend_confirmation_code(&req),
            "SetUserPoolMfaConfig" => self.set_user_pool_mfa_config(&req),
            "GetUserPoolMfaConfig" => self.get_user_pool_mfa_config(&req),
            "AdminSetUserMFAPreference" => self.admin_set_user_mfa_preference(&req),
            "SetUserMFAPreference" => self.set_user_mfa_preference(&req),
            "AssociateSoftwareToken" => self.associate_software_token(&req),
            "VerifySoftwareToken" => self.verify_software_token(&req),
            "GetUserAuthFactors" => self.get_user_auth_factors(&req),
            "CreateIdentityProvider" => self.create_identity_provider(&req),
            "DescribeIdentityProvider" => self.describe_identity_provider(&req),
            "UpdateIdentityProvider" => self.update_identity_provider(&req),
            "DeleteIdentityProvider" => self.delete_identity_provider(&req),
            "ListIdentityProviders" => self.list_identity_providers(&req),
            "GetIdentityProviderByIdentifier" => self.get_identity_provider_by_identifier(&req),
            "CreateResourceServer" => self.create_resource_server(&req),
            "DescribeResourceServer" => self.describe_resource_server(&req),
            "UpdateResourceServer" => self.update_resource_server(&req),
            "DeleteResourceServer" => self.delete_resource_server(&req),
            "ListResourceServers" => self.list_resource_servers(&req),
            "CreateUserPoolDomain" => self.create_user_pool_domain(&req),
            "DescribeUserPoolDomain" => self.describe_user_pool_domain(&req),
            "UpdateUserPoolDomain" => self.update_user_pool_domain(&req),
            "DeleteUserPoolDomain" => self.delete_user_pool_domain(&req),
            "AdminGetDevice" => self.admin_get_device(&req),
            "AdminListDevices" => self.admin_list_devices(&req),
            "AdminForgetDevice" => self.admin_forget_device(&req),
            "AdminUpdateDeviceStatus" => self.admin_update_device_status(&req),
            "ConfirmDevice" => self.confirm_device(&req),
            "ForgetDevice" => self.forget_device(&req),
            "GetDevice" => self.get_device(&req),
            "ListDevices" => self.list_devices(&req),
            "UpdateDeviceStatus" => self.update_device_status(&req),
            "RevokeToken" => self.revoke_token(&req),
            "GetTokensFromRefreshToken" => self.get_tokens_from_refresh_token(&req),
            "TagResource" => self.tag_resource(&req),
            "UntagResource" => self.untag_resource(&req),
            "ListTagsForResource" => self.list_tags_for_resource(&req),
            "GetCSVHeader" => self.get_csv_header(&req),
            "CreateUserImportJob" => self.create_user_import_job(&req),
            "DescribeUserImportJob" => self.describe_user_import_job(&req),
            "ListUserImportJobs" => self.list_user_import_jobs(&req),
            "AdminSetUserSettings" => self.admin_set_user_settings(&req),
            "SetUserSettings" => self.set_user_settings(&req),
            "AdminDisableProviderForUser" => self.admin_disable_provider_for_user(&req),
            "AdminLinkProviderForUser" => self.admin_link_provider_for_user(&req),
            "AdminListUserAuthEvents" => self.admin_list_user_auth_events(&req),
            "AdminUpdateAuthEventFeedback" => self.admin_update_auth_event_feedback(&req),
            "UpdateAuthEventFeedback" => self.update_auth_event_feedback(&req),
            "StartUserImportJob" => self.start_user_import_job(&req),
            "StopUserImportJob" => self.stop_user_import_job(&req),
            "GetUICustomization" => self.get_ui_customization(&req),
            "SetUICustomization" => self.set_ui_customization(&req),
            "GetLogDeliveryConfiguration" => self.get_log_delivery_configuration(&req),
            "SetLogDeliveryConfiguration" => self.set_log_delivery_configuration(&req),
            "DescribeRiskConfiguration" => self.describe_risk_configuration(&req),
            "SetRiskConfiguration" => self.set_risk_configuration(&req),
            "CreateManagedLoginBranding" => self.create_managed_login_branding(&req),
            "DeleteManagedLoginBranding" => self.delete_managed_login_branding(&req),
            "DescribeManagedLoginBranding" => self.describe_managed_login_branding(&req),
            "DescribeManagedLoginBrandingByClient" => {
                self.describe_managed_login_branding_by_client(&req)
            }
            "UpdateManagedLoginBranding" => self.update_managed_login_branding(&req),
            "CreateTerms" => self.create_terms(&req),
            "DeleteTerms" => self.delete_terms(&req),
            "DescribeTerms" => self.describe_terms(&req),
            "ListTerms" => self.list_terms(&req),
            "UpdateTerms" => self.update_terms(&req),
            "StartWebAuthnRegistration" => self.start_web_authn_registration(&req),
            "CompleteWebAuthnRegistration" => self.complete_web_authn_registration(&req),
            "DeleteWebAuthnCredential" => self.delete_web_authn_credential(&req),
            "ListWebAuthnCredentials" => self.list_web_authn_credentials(&req),
            _ => Err(AwsServiceError::action_not_implemented(
                "cognito-idp",
                &req.action,
            )),
        };
        if mutates && matches!(result.as_ref(), Ok(resp) if resp.status.is_success()) {
            self.save_snapshot().await;
        }
        result
    }

    fn supported_actions(&self) -> &[&str] {
        &[
            "CreateUserPool",
            "DescribeUserPool",
            "UpdateUserPool",
            "DeleteUserPool",
            "ListUserPools",
            "CreateUserPoolClient",
            "DescribeUserPoolClient",
            "UpdateUserPoolClient",
            "DeleteUserPoolClient",
            "ListUserPoolClients",
            "AddCustomAttributes",
            "AddUserPoolClientSecret",
            "DeleteUserPoolClientSecret",
            "ListUserPoolClientSecrets",
            "GetSigningCertificate",
            "AdminCreateUser",
            "AdminGetUser",
            "AdminDeleteUser",
            "AdminDisableUser",
            "AdminEnableUser",
            "AdminUpdateUserAttributes",
            "AdminDeleteUserAttributes",
            "ListUsers",
            "AdminSetUserPassword",
            "AdminInitiateAuth",
            "InitiateAuth",
            "RespondToAuthChallenge",
            "AdminRespondToAuthChallenge",
            "SignUp",
            "ConfirmSignUp",
            "AdminConfirmSignUp",
            "ChangePassword",
            "ForgotPassword",
            "ConfirmForgotPassword",
            "AdminResetUserPassword",
            "GlobalSignOut",
            "AdminUserGlobalSignOut",
            "CreateGroup",
            "DeleteGroup",
            "GetGroup",
            "UpdateGroup",
            "ListGroups",
            "AdminAddUserToGroup",
            "AdminRemoveUserFromGroup",
            "AdminListGroupsForUser",
            "ListUsersInGroup",
            "GetUser",
            "DeleteUser",
            "UpdateUserAttributes",
            "DeleteUserAttributes",
            "GetUserAttributeVerificationCode",
            "VerifyUserAttribute",
            "ResendConfirmationCode",
            "SetUserPoolMfaConfig",
            "GetUserPoolMfaConfig",
            "AdminSetUserMFAPreference",
            "SetUserMFAPreference",
            "AssociateSoftwareToken",
            "VerifySoftwareToken",
            "GetUserAuthFactors",
            "CreateIdentityProvider",
            "DescribeIdentityProvider",
            "UpdateIdentityProvider",
            "DeleteIdentityProvider",
            "ListIdentityProviders",
            "GetIdentityProviderByIdentifier",
            "CreateResourceServer",
            "DescribeResourceServer",
            "UpdateResourceServer",
            "DeleteResourceServer",
            "ListResourceServers",
            "CreateUserPoolDomain",
            "DescribeUserPoolDomain",
            "UpdateUserPoolDomain",
            "DeleteUserPoolDomain",
            "AdminGetDevice",
            "AdminListDevices",
            "AdminForgetDevice",
            "AdminUpdateDeviceStatus",
            "ConfirmDevice",
            "ForgetDevice",
            "GetDevice",
            "ListDevices",
            "UpdateDeviceStatus",
            "RevokeToken",
            "GetTokensFromRefreshToken",
            "TagResource",
            "UntagResource",
            "ListTagsForResource",
            "GetCSVHeader",
            "CreateUserImportJob",
            "DescribeUserImportJob",
            "ListUserImportJobs",
            "AdminSetUserSettings",
            "SetUserSettings",
            "AdminDisableProviderForUser",
            "AdminLinkProviderForUser",
            "AdminListUserAuthEvents",
            "AdminUpdateAuthEventFeedback",
            "UpdateAuthEventFeedback",
            "StartUserImportJob",
            "StopUserImportJob",
            "GetUICustomization",
            "SetUICustomization",
            "GetLogDeliveryConfiguration",
            "SetLogDeliveryConfiguration",
            "DescribeRiskConfiguration",
            "SetRiskConfiguration",
            "CreateManagedLoginBranding",
            "DeleteManagedLoginBranding",
            "DescribeManagedLoginBranding",
            "DescribeManagedLoginBrandingByClient",
            "UpdateManagedLoginBranding",
            "CreateTerms",
            "DeleteTerms",
            "DescribeTerms",
            "ListTerms",
            "UpdateTerms",
            "StartWebAuthnRegistration",
            "CompleteWebAuthnRegistration",
            "DeleteWebAuthnCredential",
            "ListWebAuthnCredentials",
        ]
    }
}

/// Confirm that ``pool_id`` refers to a known user pool, returning the standard
/// ``ResourceNotFoundException`` otherwise. Most ``CognitoService`` operations
/// take a ``UserPoolId`` and validate it before touching any other state, so
/// this helper collapses what would otherwise be the same 7-line guard written
/// at every call site.
fn ensure_user_pool_exists(
    state: &crate::state::CognitoState,
    pool_id: &str,
) -> Result<(), AwsServiceError> {
    if state.user_pools.contains_key(pool_id) {
        Ok(())
    } else {
        Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ResourceNotFoundException",
            format!("User pool {pool_id} does not exist."),
        ))
    }
}

fn device_to_json(device: &Device) -> Value {
    let attrs: Vec<Value> = device
        .device_attributes
        .iter()
        .map(|(k, v)| json!({"Name": k, "Value": v}))
        .collect();

    let mut obj = json!({
        "DeviceKey": device.device_key,
        "DeviceAttributes": attrs,
        "DeviceCreateDate": device.device_create_date.timestamp() as f64,
        "DeviceLastModifiedDate": device.device_last_modified_date.timestamp() as f64,
    });
    if let Some(auth_date) = device.device_last_authenticated_date {
        obj["DeviceLastAuthenticatedDate"] = json!(auth_date.timestamp() as f64);
    }
    if let Some(ref status) = device.device_remembered_status {
        obj["DeviceRememberedStatus"] = json!(status);
    }
    obj
}

fn import_job_to_json(job: &UserImportJob) -> Value {
    let mut obj = json!({
        "JobId": job.job_id,
        "JobName": job.job_name,
        "UserPoolId": job.user_pool_id,
        "CloudWatchLogsRoleArn": job.cloud_watch_logs_role_arn,
        "Status": job.status,
        "CreationDate": job.creation_date.timestamp() as f64,
    });
    if let Some(url) = &job.pre_signed_url {
        obj["PreSignedUrl"] = json!(url);
    }
    if let Some(d) = job.start_date {
        obj["StartDate"] = json!(d.timestamp() as f64);
    }
    if let Some(d) = job.completion_date {
        obj["CompletionDate"] = json!(d.timestamp() as f64);
    }
    obj
}

/// Generate a pool ID in the format `{region}_{9 random alphanumeric chars}`.
fn generate_pool_id(region: &str) -> String {
    let random_part: String = Uuid::new_v4()
        .to_string()
        .replace('-', "")
        .chars()
        .filter(|c| c.is_alphanumeric())
        .take(9)
        .collect();
    // Ensure we always have exactly 9 chars (UUID v4 hex is 32 chars, so this is safe)
    format!("{}_{}", region, random_part)
}

/// Generate a client ID: 26 lowercase alphanumeric characters (like AWS).
fn generate_client_id() -> String {
    // Use two UUIDs to get enough alphanumeric chars (each UUID gives 32 hex chars)
    let uuid1 = Uuid::new_v4().to_string().replace('-', "");
    let uuid2 = Uuid::new_v4().to_string().replace('-', "");
    format!("{}{}", uuid1, uuid2)
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .take(26)
        .collect::<String>()
        .to_lowercase()
}

/// Generate a 6-digit confirmation code for password reset flows.
fn generate_confirmation_code() -> String {
    // Use UUID bytes to generate a numeric code
    let uuid = Uuid::new_v4();
    let bytes = uuid.as_bytes();
    let num = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    format!("{:06}", num % 1_000_000)
}

/// Generate a TOTP secret key: 32 base32 characters (like AWS).
fn generate_totp_secret() -> String {
    // Base32 alphabet (RFC 4648)
    const BASE32_ALPHABET: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut result = String::with_capacity(32);
    // Use UUID bytes as random source
    let mut bytes = Vec::with_capacity(32);
    for _ in 0..2 {
        bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    }
    for &b in bytes.iter().take(32) {
        let idx = (b as usize) % BASE32_ALPHABET.len();
        result.push(BASE32_ALPHABET[idx] as char);
    }
    result
}

/// Generate a client secret: 51 base64 characters (like AWS).
fn generate_client_secret() -> String {
    use base64::Engine;
    // Generate enough random bytes via UUIDs to produce 51+ base64 chars
    let mut bytes = Vec::with_capacity(48);
    for _ in 0..3 {
        bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    }
    let encoded = base64::engine::general_purpose::STANDARD.encode(&bytes);
    encoded.chars().take(51).collect()
}

fn parse_token_validity_units(val: &Value) -> Option<TokenValidityUnits> {
    if !val.is_object() {
        return None;
    }
    Some(TokenValidityUnits {
        access_token: val["AccessToken"].as_str().map(|s| s.to_string()),
        id_token: val["IdToken"].as_str().map(|s| s.to_string()),
        refresh_token: val["RefreshToken"].as_str().map(|s| s.to_string()),
    })
}

/// Convert a UserPoolClient to the JSON format AWS returns.
fn user_pool_client_to_json(client: &UserPoolClient) -> Value {
    let mut obj = json!({
        "ClientId": client.client_id,
        "ClientName": client.client_name,
        "UserPoolId": client.user_pool_id,
        "CreationDate": client.creation_date.timestamp() as f64,
        "LastModifiedDate": client.last_modified_date.timestamp() as f64,
        "ExplicitAuthFlows": client.explicit_auth_flows,
        "AllowedOAuthFlowsUserPoolClient": client.allowed_o_auth_flows_user_pool_client,
        "EnableTokenRevocation": client.enable_token_revocation,
    });

    if let Some(ref secret) = client.client_secret {
        obj["ClientSecret"] = json!(secret);
    }
    if let Some(ref tvu) = client.token_validity_units {
        let mut units = json!({});
        if let Some(ref v) = tvu.access_token {
            units["AccessToken"] = json!(v);
        }
        if let Some(ref v) = tvu.id_token {
            units["IdToken"] = json!(v);
        }
        if let Some(ref v) = tvu.refresh_token {
            units["RefreshToken"] = json!(v);
        }
        obj["TokenValidityUnits"] = units;
    }
    if let Some(v) = client.access_token_validity {
        obj["AccessTokenValidity"] = json!(v);
    }
    if let Some(v) = client.id_token_validity {
        obj["IdTokenValidity"] = json!(v);
    }
    if let Some(v) = client.refresh_token_validity {
        obj["RefreshTokenValidity"] = json!(v);
    }
    if !client.callback_urls.is_empty() {
        obj["CallbackURLs"] = json!(client.callback_urls);
    }
    if !client.logout_urls.is_empty() {
        obj["LogoutURLs"] = json!(client.logout_urls);
    }
    if !client.supported_identity_providers.is_empty() {
        obj["SupportedIdentityProviders"] = json!(client.supported_identity_providers);
    }
    if !client.allowed_o_auth_flows.is_empty() {
        obj["AllowedOAuthFlows"] = json!(client.allowed_o_auth_flows);
    }
    if !client.allowed_o_auth_scopes.is_empty() {
        obj["AllowedOAuthScopes"] = json!(client.allowed_o_auth_scopes);
    }
    if let Some(ref v) = client.prevent_user_existence_errors {
        obj["PreventUserExistenceErrors"] = json!(v);
    }
    if !client.read_attributes.is_empty() {
        obj["ReadAttributes"] = json!(client.read_attributes);
    }
    if !client.write_attributes.is_empty() {
        obj["WriteAttributes"] = json!(client.write_attributes);
    }
    if let Some(v) = client.auth_session_validity {
        obj["AuthSessionValidity"] = json!(v);
    }

    obj
}

fn parse_password_policy(val: &Value) -> PasswordPolicy {
    if val.is_null() || !val.is_object() {
        return PasswordPolicy::default();
    }

    PasswordPolicy {
        minimum_length: val["MinimumLength"].as_i64().unwrap_or(8),
        require_uppercase: val["RequireUppercase"].as_bool().unwrap_or(false),
        require_lowercase: val["RequireLowercase"].as_bool().unwrap_or(false),
        require_numbers: val["RequireNumbers"].as_bool().unwrap_or(false),
        require_symbols: val["RequireSymbols"].as_bool().unwrap_or(false),
        temporary_password_validity_days: val["TemporaryPasswordValidityDays"]
            .as_i64()
            .unwrap_or(7),
    }
}

fn default_sign_in_policy() -> SignInPolicy {
    SignInPolicy {
        allowed_first_auth_factors: vec!["PASSWORD".to_string()],
    }
}

pub(super) fn parse_sign_in_policy(val: &Value) -> SignInPolicy {
    if !val.is_object() {
        return default_sign_in_policy();
    }
    let factors = val["AllowedFirstAuthFactors"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if factors.is_empty() {
        default_sign_in_policy()
    } else {
        SignInPolicy {
            allowed_first_auth_factors: factors,
        }
    }
}

pub(super) fn parse_verification_message_template(
    val: &Value,
) -> Option<VerificationMessageTemplate> {
    if !val.is_object() {
        return None;
    }
    Some(VerificationMessageTemplate {
        default_email_option: val["DefaultEmailOption"]
            .as_str()
            .unwrap_or("CONFIRM_WITH_CODE")
            .to_string(),
        email_message: val["EmailMessage"].as_str().map(|s| s.to_string()),
        email_subject: val["EmailSubject"].as_str().map(|s| s.to_string()),
        email_message_by_link: val["EmailMessageByLink"].as_str().map(|s| s.to_string()),
        email_subject_by_link: val["EmailSubjectByLink"].as_str().map(|s| s.to_string()),
        sms_message: val["SmsMessage"].as_str().map(|s| s.to_string()),
    })
}

fn parse_string_array(val: &Value) -> Vec<String> {
    val.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_schema_attribute(val: &Value) -> Option<SchemaAttribute> {
    let name = val["Name"].as_str()?;
    Some(SchemaAttribute {
        name: name.to_string(),
        attribute_data_type: val["AttributeDataType"]
            .as_str()
            .unwrap_or("String")
            .to_string(),
        developer_only_attribute: val["DeveloperOnlyAttribute"].as_bool().unwrap_or(false),
        mutable: val["Mutable"].as_bool().unwrap_or(true),
        required: val["Required"].as_bool().unwrap_or(false),
        string_attribute_constraints: if val["StringAttributeConstraints"].is_object() {
            Some(StringAttributeConstraints {
                min_length: val["StringAttributeConstraints"]["MinLength"]
                    .as_str()
                    .map(|s| s.to_string()),
                max_length: val["StringAttributeConstraints"]["MaxLength"]
                    .as_str()
                    .map(|s| s.to_string()),
            })
        } else {
            None
        },
        number_attribute_constraints: None,
    })
}

fn parse_email_configuration(val: &Value) -> Option<EmailConfiguration> {
    if !val.is_object() {
        return None;
    }
    Some(EmailConfiguration {
        source_arn: val["SourceArn"].as_str().map(|s| s.to_string()),
        reply_to_email_address: val["ReplyToEmailAddress"].as_str().map(|s| s.to_string()),
        email_sending_account: val["EmailSendingAccount"].as_str().map(|s| s.to_string()),
        from_email_address: val["From"].as_str().map(|s| s.to_string()),
        configuration_set: val["ConfigurationSet"].as_str().map(|s| s.to_string()),
    })
}

fn parse_sms_configuration(val: &Value) -> Option<SmsConfiguration> {
    if !val.is_object() {
        return None;
    }
    Some(SmsConfiguration {
        sns_caller_arn: val["SnsCallerArn"].as_str().map(|s| s.to_string()),
        external_id: val["ExternalId"].as_str().map(|s| s.to_string()),
        sns_region: val["SnsRegion"].as_str().map(|s| s.to_string()),
    })
}

fn parse_admin_create_user_config(val: &Value) -> Option<AdminCreateUserConfig> {
    if !val.is_object() {
        return None;
    }
    let invite = if val["InviteMessageTemplate"].is_object() {
        Some(InviteMessageTemplate {
            email_message: val["InviteMessageTemplate"]["EmailMessage"]
                .as_str()
                .map(|s| s.to_string()),
            email_subject: val["InviteMessageTemplate"]["EmailSubject"]
                .as_str()
                .map(|s| s.to_string()),
            sms_message: val["InviteMessageTemplate"]["SMSMessage"]
                .as_str()
                .map(|s| s.to_string()),
        })
    } else {
        None
    };
    Some(AdminCreateUserConfig {
        allow_admin_create_user_only: val["AllowAdminCreateUserOnly"].as_bool(),
        invite_message_template: invite,
        unused_account_validity_days: val["UnusedAccountValidityDays"].as_i64(),
    })
}

fn parse_tags(val: &Value) -> std::collections::BTreeMap<String, String> {
    let mut tags = std::collections::BTreeMap::new();
    if let Some(obj) = val.as_object() {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                tags.insert(k.clone(), s.to_string());
            }
        }
    }
    tags
}

fn parse_account_recovery_setting(val: &Value) -> Option<AccountRecoverySetting> {
    if !val.is_object() {
        return None;
    }
    let mechanisms = val["RecoveryMechanisms"]
        .as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    Some(RecoveryOption {
                        name: v["Name"].as_str()?.to_string(),
                        priority: v["Priority"].as_i64().unwrap_or(1),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    Some(AccountRecoverySetting {
        recovery_mechanisms: mechanisms,
    })
}

fn parse_user_attributes(val: &Value) -> Vec<UserAttribute> {
    val.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    let name = v["Name"].as_str()?;
                    let value = v["Value"].as_str().unwrap_or("");
                    Some(UserAttribute {
                        name: name.to_string(),
                        value: value.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

/// Convert a Group to the JSON format AWS returns.
fn group_to_json(group: &Group) -> Value {
    let mut val = json!({
        "GroupName": group.group_name,
        "UserPoolId": group.user_pool_id,
        "CreationDate": group.creation_date.timestamp() as f64,
        "LastModifiedDate": group.last_modified_date.timestamp() as f64,
    });
    if let Some(ref desc) = group.description {
        val["Description"] = json!(desc);
    }
    if let Some(prec) = group.precedence {
        val["Precedence"] = json!(prec);
    }
    if let Some(ref arn) = group.role_arn {
        val["RoleArn"] = json!(arn);
    }
    val
}

fn identity_provider_to_json(idp: &IdentityProvider) -> Value {
    let mut val = json!({
        "UserPoolId": idp.user_pool_id,
        "ProviderName": idp.provider_name,
        "ProviderType": idp.provider_type,
        "CreationDate": idp.creation_date.timestamp() as f64,
        "LastModifiedDate": idp.last_modified_date.timestamp() as f64,
    });
    if !idp.provider_details.is_empty() {
        val["ProviderDetails"] = json!(idp.provider_details);
    }
    if !idp.attribute_mapping.is_empty() {
        val["AttributeMapping"] = json!(idp.attribute_mapping);
    }
    if !idp.idp_identifiers.is_empty() {
        val["IdpIdentifiers"] = json!(idp.idp_identifiers);
    }
    val
}

const VALID_PROVIDER_TYPES: &[&str] = &[
    "SAML",
    "Facebook",
    "Google",
    "LoginWithAmazon",
    "SignInWithApple",
    "OIDC",
];

fn validate_provider_type(provider_type: &str) -> Result<(), AwsServiceError> {
    if !VALID_PROVIDER_TYPES.contains(&provider_type) {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterException",
            format!(
                "Invalid ProviderType: {provider_type}. Must be one of: SAML, Facebook, Google, LoginWithAmazon, SignInWithApple, OIDC"
            ),
        ));
    }
    Ok(())
}

fn parse_string_map(val: &Value) -> BTreeMap<String, String> {
    val.as_object()
        .map(|obj| {
            obj.iter()
                .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_resource_server_scopes(val: &Value) -> Vec<ResourceServerScope> {
    val.as_array()
        .map(|arr| {
            arr.iter()
                .filter_map(|v| {
                    let name = v["ScopeName"].as_str()?;
                    let desc = v["ScopeDescription"].as_str().unwrap_or("");
                    Some(ResourceServerScope {
                        scope_name: name.to_string(),
                        scope_description: desc.to_string(),
                    })
                })
                .collect()
        })
        .unwrap_or_default()
}

fn resource_server_to_json(rs: &ResourceServer) -> Value {
    let scopes: Vec<Value> = rs
        .scopes
        .iter()
        .map(|s| {
            json!({
                "ScopeName": s.scope_name,
                "ScopeDescription": s.scope_description,
            })
        })
        .collect();

    json!({
        "UserPoolId": rs.user_pool_id,
        "Identifier": rs.identifier,
        "Name": rs.name,
        "Scopes": scopes,
    })
}

fn domain_description_to_json(d: &UserPoolDomain, account_id: &str) -> Value {
    let mut val = json!({
        "UserPoolId": d.user_pool_id,
        "AWSAccountId": account_id,
        "Domain": d.domain,
        "Status": d.status,
        "Version": "20130630",
    });
    if let Some(ref config) = d.custom_domain_config {
        val["CustomDomainConfig"] = json!({
            "CertificateArn": config.certificate_arn,
        });
        val["CloudFrontDistribution"] = json!(format!("d111111abcdef8.cloudfront.net"));
    }
    val
}

/// Convert a User to the JSON format AWS returns (for ListUsers and AdminCreateUser response).
fn user_to_json(user: &User) -> Value {
    json!({
        "Username": user.username,
        "Attributes": user.attributes.iter().map(|a| {
            json!({ "Name": a.name, "Value": a.value })
        }).collect::<Vec<Value>>(),
        "UserCreateDate": user.user_create_date.timestamp() as f64,
        "UserLastModifiedDate": user.user_last_modified_date.timestamp() as f64,
        "UserStatus": user.user_status,
        "Enabled": user.enabled,
    })
}

/// A parsed filter expression for ListUsers.
#[derive(Debug)]
struct FilterExpression {
    attribute: String,
    operator: FilterOp,
    value: String,
}

#[derive(Debug)]
enum FilterOp {
    Equals,
    StartsWith,
}

/// Parse a Cognito ListUsers filter expression like `email = "foo@bar.com"` or `email ^= "foo"`.
fn parse_filter_expression(filter: &str) -> Option<FilterExpression> {
    let filter = filter.trim();

    // Try ^= first (starts with)
    if let Some((attr, val)) = filter.split_once("^=") {
        let attribute = attr.trim().trim_matches('"').to_string();
        let value = val.trim().trim_matches('"').to_string();
        return Some(FilterExpression {
            attribute,
            operator: FilterOp::StartsWith,
            value,
        });
    }

    // Try = (equals)
    if let Some((attr, val)) = filter.split_once('=') {
        let attribute = attr.trim().trim_matches('"').to_string();
        let value = val.trim().trim_matches('"').to_string();
        return Some(FilterExpression {
            attribute,
            operator: FilterOp::Equals,
            value,
        });
    }

    None
}

/// Check if a user matches a filter expression.
fn matches_filter(user: &User, filter: &FilterExpression) -> bool {
    let user_value = match filter.attribute.as_str() {
        "username" => Some(user.username.as_str()),
        "sub" => Some(user.sub.as_str()),
        "cognito:user_status" | "status" => Some(user.user_status.as_str()),
        attr => user
            .attributes
            .iter()
            .find(|a| a.name == attr)
            .map(|a| a.value.as_str()),
    };

    match (&filter.operator, user_value) {
        (FilterOp::Equals, Some(v)) => v == filter.value,
        (FilterOp::StartsWith, Some(v)) => v.starts_with(&filter.value),
        _ => false,
    }
}

/// Convert a UserPool to the JSON format AWS returns.
fn user_pool_to_json(pool: &UserPool) -> Value {
    let mut obj = json!({
        "Id": pool.id,
        "Name": pool.name,
        "Arn": pool.arn,
        "Status": pool.status,
        "CreationDate": pool.creation_date.timestamp() as f64,
        "LastModifiedDate": pool.last_modified_date.timestamp() as f64,
        "Policies": {
            "PasswordPolicy": {
                "MinimumLength": pool.policies.password_policy.minimum_length,
                "RequireUppercase": pool.policies.password_policy.require_uppercase,
                "RequireLowercase": pool.policies.password_policy.require_lowercase,
                "RequireNumbers": pool.policies.password_policy.require_numbers,
                "RequireSymbols": pool.policies.password_policy.require_symbols,
                "TemporaryPasswordValidityDays": pool.policies.password_policy.temporary_password_validity_days,
            },
            "SignInPolicy": {
                "AllowedFirstAuthFactors": pool.policies.sign_in_policy.allowed_first_auth_factors,
            },
        },
        "AutoVerifiedAttributes": pool.auto_verified_attributes,
        "MfaConfiguration": pool.mfa_configuration,
        "EstimatedNumberOfUsers": pool.estimated_number_of_users,
        "UserPoolTags": pool.user_pool_tags,
        "UserPoolTier": pool.user_pool_tier,
        "SchemaAttributes": pool.schema_attributes.iter().map(|a| {
            let mut attr = json!({
                "Name": a.name,
                "AttributeDataType": a.attribute_data_type,
                "DeveloperOnlyAttribute": a.developer_only_attribute,
                "Mutable": a.mutable,
                "Required": a.required,
            });
            if let Some(ref sc) = a.string_attribute_constraints {
                attr["StringAttributeConstraints"] = json!({});
                if let Some(ref min) = sc.min_length {
                    attr["StringAttributeConstraints"]["MinLength"] = json!(min);
                }
                if let Some(ref max) = sc.max_length {
                    attr["StringAttributeConstraints"]["MaxLength"] = json!(max);
                }
            }
            if let Some(ref nc) = a.number_attribute_constraints {
                attr["NumberAttributeConstraints"] = json!({});
                if let Some(ref min) = nc.min_value {
                    attr["NumberAttributeConstraints"]["MinValue"] = json!(min);
                }
                if let Some(ref max) = nc.max_value {
                    attr["NumberAttributeConstraints"]["MaxValue"] = json!(max);
                }
            }
            attr
        }).collect::<Vec<Value>>(),
    });

    if let Some(ref ua) = pool.username_attributes {
        obj["UsernameAttributes"] = json!(ua);
    }
    if let Some(ref aa) = pool.alias_attributes {
        obj["AliasAttributes"] = json!(aa);
    }
    if let Some(ref lc) = pool.lambda_config {
        obj["LambdaConfig"] = lc.clone();
    }
    {
        let mut email = json!({
            "EmailSendingAccount": "COGNITO_DEFAULT",
        });
        if let Some(ref ec) = pool.email_configuration {
            if let Some(ref v) = ec.source_arn {
                email["SourceArn"] = json!(v);
            }
            if let Some(ref v) = ec.reply_to_email_address {
                email["ReplyToEmailAddress"] = json!(v);
            }
            if let Some(ref v) = ec.email_sending_account {
                email["EmailSendingAccount"] = json!(v);
            }
            if let Some(ref v) = ec.from_email_address {
                email["From"] = json!(v);
            }
            if let Some(ref v) = ec.configuration_set {
                email["ConfigurationSet"] = json!(v);
            }
        }
        obj["EmailConfiguration"] = email;
    }
    if let Some(ref sc) = pool.sms_configuration {
        let mut sms = json!({});
        if let Some(ref v) = sc.sns_caller_arn {
            sms["SnsCallerArn"] = json!(v);
        }
        if let Some(ref v) = sc.external_id {
            sms["ExternalId"] = json!(v);
        }
        if let Some(ref v) = sc.sns_region {
            sms["SnsRegion"] = json!(v);
        }
        obj["SmsConfiguration"] = sms;
    }
    {
        let mut admin = json!({
            "AllowAdminCreateUserOnly": false,
        });
        if let Some(ref ac) = pool.admin_create_user_config {
            if let Some(v) = ac.allow_admin_create_user_only {
                admin["AllowAdminCreateUserOnly"] = json!(v);
            }
            if let Some(ref imt) = ac.invite_message_template {
                let mut tmpl = json!({});
                if let Some(ref v) = imt.email_message {
                    tmpl["EmailMessage"] = json!(v);
                }
                if let Some(ref v) = imt.email_subject {
                    tmpl["EmailSubject"] = json!(v);
                }
                if let Some(ref v) = imt.sms_message {
                    tmpl["SMSMessage"] = json!(v);
                }
                admin["InviteMessageTemplate"] = tmpl;
            }
            if let Some(v) = ac.unused_account_validity_days {
                admin["UnusedAccountValidityDays"] = json!(v);
            }
        }
        obj["AdminCreateUserConfig"] = admin;
    }
    {
        let mechanisms: Vec<Value> = match pool.account_recovery_setting {
            Some(ref ars) if !ars.recovery_mechanisms.is_empty() => ars
                .recovery_mechanisms
                .iter()
                .map(|r| {
                    json!({
                        "Name": r.name,
                        "Priority": r.priority,
                    })
                })
                .collect(),
            _ => vec![json!({ "Name": "verified_email", "Priority": 1 })],
        };
        obj["AccountRecoverySetting"] = json!({ "RecoveryMechanisms": mechanisms });
    }
    {
        let mut vmt = json!({
            "DefaultEmailOption": "CONFIRM_WITH_CODE",
        });
        if let Some(ref t) = pool.verification_message_template {
            vmt["DefaultEmailOption"] = json!(t.default_email_option);
            if let Some(ref v) = t.email_message {
                vmt["EmailMessage"] = json!(v);
            }
            if let Some(ref v) = t.email_subject {
                vmt["EmailSubject"] = json!(v);
            }
            if let Some(ref v) = t.email_message_by_link {
                vmt["EmailMessageByLink"] = json!(v);
            }
            if let Some(ref v) = t.email_subject_by_link {
                vmt["EmailSubjectByLink"] = json!(v);
            }
            if let Some(ref v) = t.sms_message {
                vmt["SmsMessage"] = json!(v);
            }
        }
        obj["VerificationMessageTemplate"] = vmt;
    }
    obj["DeletionProtection"] = json!(pool.deletion_protection.as_deref().unwrap_or("INACTIVE"));

    obj
}

/// Helper to extract a required string field from JSON.
fn require_str<'a>(body: &'a Value, field: &str) -> Result<&'a str, AwsServiceError> {
    body[field]
        .as_str()
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterException",
                format!("{field} is required"),
            )
        })
}

/// Validate a password against a pool's password policy.
fn validate_password(password: &str, policy: &PasswordPolicy) -> Result<(), AwsServiceError> {
    if (password.len() as i64) < policy.minimum_length {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidPasswordException",
            format!(
                "Password did not conform with policy: Password not long enough (minimum {})",
                policy.minimum_length
            ),
        ));
    }
    if policy.require_uppercase && !password.chars().any(|c| c.is_ascii_uppercase()) {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidPasswordException",
            "Password did not conform with policy: Password must have uppercase characters",
        ));
    }
    if policy.require_lowercase && !password.chars().any(|c| c.is_ascii_lowercase()) {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidPasswordException",
            "Password did not conform with policy: Password must have lowercase characters",
        ));
    }
    if policy.require_numbers && !password.chars().any(|c| c.is_ascii_digit()) {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidPasswordException",
            "Password did not conform with policy: Password must have numeric characters",
        ));
    }
    if policy.require_symbols
        && !password
            .chars()
            .any(|c| !c.is_ascii_alphanumeric() && c.is_ascii())
    {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidPasswordException",
            "Password did not conform with policy: Password must have symbol characters",
        ));
    }
    Ok(())
}

/// Validate that a string value is one of the allowed enum values.
fn validate_enum(value: &str, field: &str, allowed: &[&str]) -> Result<(), AwsServiceError> {
    if !allowed.contains(&value) {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterException",
            format!(
                "1 validation error detected: Value '{}' at '{}' failed to satisfy constraint: Member must satisfy enum value set: [{}]",
                value, field, allowed.join(", ")
            ),
        ));
    }
    Ok(())
}

/// Validate string length is within min..=max bounds.
fn validate_string_length(
    value: &str,
    field: &str,
    min: usize,
    max: usize,
) -> Result<(), AwsServiceError> {
    let len = value.len();
    if len < min {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterException",
            format!(
                "1 validation error detected: Value '{}' at '{}' failed to satisfy constraint: Member must have length greater than or equal to {}",
                value, field, min
            ),
        ));
    }
    if len > max {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterException",
            format!(
                "1 validation error detected: Value at '{}' failed to satisfy constraint: Member must have length less than or equal to {}",
                field, max
            ),
        ));
    }
    Ok(())
}

/// Validate an integer is within min..=max bounds.
fn validate_range(value: i64, field: &str, min: i64, max: i64) -> Result<(), AwsServiceError> {
    if value < min || value > max {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterException",
            format!(
                "1 validation error detected: Value '{}' at '{}' failed to satisfy constraint: Member must have value between {} and {}",
                value, field, min, max
            ),
        ));
    }
    Ok(())
}

struct TokenSet {
    id_token: String,
    access_token: String,
    refresh_token: String,
}

/// Generate Cognito ID/Access/Refresh tokens. When `signing` is supplied
/// (the pool's PKCS#8 PEM + stable kid), the JWTs are signed with real
/// RS256 so SDK-side JWKS verification round-trips. Pre-existing pools
/// without a stored key fall back to a placeholder signature so test
/// fixtures keep parsing.
fn generate_tokens(
    pool_id: &str,
    client_id: &str,
    sub: &str,
    username: &str,
    region: &str,
    signing: Option<(&str, &str)>,
) -> TokenSet {
    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let now = Utc::now().timestamp();
    let jti = Uuid::new_v4().to_string();
    let iss = format!("https://cognito-idp.{region}.amazonaws.com/{pool_id}");
    let kid = signing
        .map(|(_, k)| k.to_string())
        .unwrap_or_else(|| "fakecloud-key-1".to_string());

    let id_header = json!({"kid": kid, "alg": "RS256", "typ": "JWT"});
    let id_payload = json!({
        "sub": sub,
        "iss": iss,
        "aud": client_id,
        "cognito:username": username,
        "token_use": "id",
        "auth_time": now,
        "exp": now + 3600,
        "iat": now,
        "jti": jti,
    });
    let id_token = sign_jwt(&id_header, &id_payload, &b64url, signing.map(|(p, _)| p));

    let access_jti = Uuid::new_v4().to_string();
    let access_header = json!({"kid": kid, "alg": "RS256", "typ": "JWT"});
    let access_payload = json!({
        "sub": sub,
        "iss": iss,
        "client_id": client_id,
        "token_use": "access",
        "scope": "aws.cognito.signin.user.admin",
        "jti": access_jti,
        "exp": now + 3600,
        "iat": now,
    });
    let access_token = sign_jwt(
        &access_header,
        &access_payload,
        &b64url,
        signing.map(|(p, _)| p),
    );

    let mut refresh_bytes = Vec::with_capacity(72);
    for _ in 0..5 {
        refresh_bytes.extend_from_slice(Uuid::new_v4().as_bytes());
    }
    let refresh_token = b64url.encode(&refresh_bytes);

    TokenSet {
        id_token,
        access_token,
        refresh_token,
    }
}

fn sign_jwt(
    header: &Value,
    payload: &Value,
    engine: &base64::engine::general_purpose::GeneralPurpose,
    private_key_pem: Option<&str>,
) -> String {
    if let Some(pem) = private_key_pem {
        return crate::jwt::sign_rs256(header, payload, pem);
    }
    let header_b64 = engine.encode(header.to_string().as_bytes());
    let payload_b64 = engine.encode(payload.to_string().as_bytes());
    let signing_input = format!("{header_b64}.{payload_b64}");
    let mut hasher = Sha256::new();
    hasher.update(signing_input.as_bytes());
    let signature = hasher.finalize();
    let sig_b64 = engine.encode(signature);
    format!("{header_b64}.{payload_b64}.{sig_b64}")
}

/// Look up a pool's signing key, generating one off the runtime thread if
/// missing. Returns `(pkcs8_pem, kid)` for callers that need to sign a
/// JWT or render a JWKS document. The expensive RSA-2048 keygen only
/// runs once per pool — subsequent calls hit the cache.
pub async fn ensure_pool_signing_key(
    state: &SharedCognitoState,
    pool_id: &str,
) -> Option<(String, String)> {
    {
        let mas = state.read();
        for (_, account) in mas.iter() {
            if let Some(pool) = account.user_pools.get(pool_id) {
                if let (Some(p), Some(k)) = (&pool.signing_key_pem, &pool.signing_kid) {
                    return Some((p.clone(), k.clone()));
                }
                break;
            }
        }
    }
    let generated = tokio::task::spawn_blocking(crate::jwt::generate_pool_signing_key)
        .await
        .ok()?;
    let mut mas = state.write();
    let mut result = None;
    for (_, account) in mas.iter_mut() {
        if let Some(pool) = account.user_pools.get_mut(pool_id) {
            if pool.signing_key_pem.is_none() {
                pool.signing_key_pem = Some(generated.clone());
            }
            if let (Some(p), Some(k)) = (&pool.signing_key_pem, &pool.signing_kid) {
                result = Some((p.clone(), k.clone()));
            }
            break;
        }
    }
    result
}

/// JWKS document for a pool (`{"keys": [<jwk>]}`). Triggers lazy keypair
/// generation when the pool was created before any sign call ran.
pub async fn pool_jwks_document(state: &SharedCognitoState, pool_id: &str) -> Option<Value> {
    let (pem, kid) = ensure_pool_signing_key(state, pool_id).await?;
    Some(crate::jwt::jwks_document(&pem, &kid))
}

/// Cognito-shaped OpenID-Connect discovery document for a pool. Mirrors
/// the document AWS publishes at
/// `https://cognito-idp.<region>.amazonaws.com/<pool>/.well-known/openid-configuration`.
/// `base_url` is the externally-reachable origin (scheme+host+port) that
/// clients use to reach fakecloud, so the URLs we hand back resolve.
pub fn oidc_discovery_document(pool_id: &str, region: &str, base_url: &str) -> Value {
    let issuer = format!("https://cognito-idp.{region}.amazonaws.com/{pool_id}");
    let trimmed = base_url.trim_end_matches('/');
    serde_json::json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{trimmed}/oauth2/authorize"),
        "token_endpoint": format!("{trimmed}/oauth2/token"),
        "userinfo_endpoint": format!("{trimmed}/oauth2/userInfo"),
        "revocation_endpoint": format!("{trimmed}/oauth2/revoke"),
        "jwks_uri": format!("{trimmed}/{pool_id}/.well-known/jwks.json"),
        "response_types_supported": ["code", "token"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "token_endpoint_auth_methods_supported": [
            "client_secret_basic",
            "client_secret_post",
            "none",
        ],
        "scopes_supported": ["openid", "email", "phone", "profile", "aws.cognito.signin.user.admin"],
        "claims_supported": [
            "sub",
            "iss",
            "aud",
            "name",
            "email",
            "email_verified",
            "phone_number",
            "phone_number_verified",
            "cognito:username",
            "cognito:groups",
            "auth_time",
            "exp",
            "iat",
            "token_use",
            "jti",
        ],
        "code_challenge_methods_supported": ["S256", "plain"],
        "grant_types_supported": ["authorization_code", "implicit", "refresh_token", "client_credentials"],
    })
}

/// Result of `/oauth2/token` handling. The HTTP wrapper translates
/// `Err(OAuthTokenError)` into the OAuth2-shaped JSON `{"error": ...}`
/// body with the appropriate HTTP status (400 for client errors, 401
/// for auth failures).
#[derive(Debug)]
pub enum OAuthTokenError {
    InvalidRequest(&'static str),
    UnsupportedGrantType,
    InvalidClient,
    InvalidGrant,
}

impl OAuthTokenError {
    pub fn status_code(&self) -> u16 {
        match self {
            OAuthTokenError::InvalidClient => 401,
            _ => 400,
        }
    }

    pub fn as_oauth_code(&self) -> &'static str {
        match self {
            OAuthTokenError::InvalidRequest(_) => "invalid_request",
            OAuthTokenError::UnsupportedGrantType => "unsupported_grant_type",
            OAuthTokenError::InvalidClient => "invalid_client",
            OAuthTokenError::InvalidGrant => "invalid_grant",
        }
    }

    pub fn description(&self) -> Option<&'static str> {
        match self {
            OAuthTokenError::InvalidRequest(msg) => Some(msg),
            _ => None,
        }
    }
}

/// Cognito-shaped `/oauth2/token` response body.
#[derive(Debug)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    pub id_token: Option<String>,
    pub refresh_token: Option<String>,
    pub expires_in: i64,
    pub token_type: String,
}

impl OAuthTokenResponse {
    pub fn to_json(&self) -> Value {
        let mut obj = serde_json::Map::new();
        obj.insert("access_token".into(), json!(self.access_token));
        if let Some(ref id) = self.id_token {
            obj.insert("id_token".into(), json!(id));
        }
        if let Some(ref rt) = self.refresh_token {
            obj.insert("refresh_token".into(), json!(rt));
        }
        obj.insert("expires_in".into(), json!(self.expires_in));
        obj.insert("token_type".into(), json!(self.token_type));
        Value::Object(obj)
    }
}

/// Handle a Cognito `/oauth2/token` POST. Implements the
/// `refresh_token` and `client_credentials` grants. The
/// `authorization_code` grant lands in Y4 alongside the
/// `/oauth2/authorize` endpoint.
///
/// `params` is the form-decoded body (Cognito uses
/// `application/x-www-form-urlencoded`). `region` is the AWS region
/// for `iss` claim composition.
pub async fn handle_oauth2_token(
    state: &SharedCognitoState,
    params: &BTreeMap<String, String>,
    region: &str,
) -> Result<OAuthTokenResponse, OAuthTokenError> {
    let grant_type = params
        .get("grant_type")
        .map(String::as_str)
        .ok_or(OAuthTokenError::InvalidRequest("grant_type is required"))?;
    let client_id = params
        .get("client_id")
        .map(String::as_str)
        .ok_or(OAuthTokenError::InvalidRequest("client_id is required"))?;

    let (pool_id, stored_secret) = {
        let mas = state.read();
        let mut found = None;
        for (_, account) in mas.iter() {
            if let Some(client) = account.user_pool_clients.get(client_id) {
                found = Some((client.user_pool_id.clone(), client.client_secret.clone()));
                break;
            }
        }
        found.ok_or(OAuthTokenError::InvalidClient)?
    };

    if let Some(secret) = stored_secret.as_ref() {
        let supplied = params.get("client_secret").map(String::as_str);
        if supplied != Some(secret.as_str()) {
            return Err(OAuthTokenError::InvalidClient);
        }
    }

    match grant_type {
        "refresh_token" => {
            let refresh_token = params
                .get("refresh_token")
                .map(String::as_str)
                .ok_or(OAuthTokenError::InvalidRequest("refresh_token is required"))?;
            let (username, sub) = {
                let mas = state.read();
                let mut found = Err(OAuthTokenError::InvalidGrant);
                for (_, account) in mas.iter() {
                    if let Some(rt) = account.refresh_tokens.get(refresh_token) {
                        if rt.client_id != client_id {
                            found = Err(OAuthTokenError::InvalidGrant);
                            break;
                        }
                        let sub = account
                            .users
                            .get(&rt.user_pool_id)
                            .and_then(|users| users.get(&rt.username))
                            .map(|u| u.sub.clone())
                            .unwrap_or_default();
                        found = Ok((rt.username.clone(), sub));
                        break;
                    }
                }
                found?
            };
            let signing = ensure_pool_signing_key(state, &pool_id).await;
            let signing_ref = signing.as_ref().map(|(p, k)| (p.as_str(), k.as_str()));
            let tokens = generate_tokens(&pool_id, client_id, &sub, &username, region, signing_ref);
            {
                let mut mas = state.write();
                for (_, account) in mas.iter_mut() {
                    if account.user_pool_clients.contains_key(client_id) {
                        account.access_tokens.insert(
                            tokens.access_token.clone(),
                            crate::state::AccessTokenData {
                                user_pool_id: pool_id.clone(),
                                username: username.clone(),
                                client_id: client_id.to_string(),
                                issued_at: Utc::now(),
                            },
                        );
                        break;
                    }
                }
            }
            Ok(OAuthTokenResponse {
                access_token: tokens.access_token,
                id_token: Some(tokens.id_token),
                refresh_token: None,
                expires_in: 3600,
                token_type: "Bearer".to_string(),
            })
        }
        "client_credentials" => {
            // Machine-to-machine: just an access token, no id_token,
            // no refresh_token. `sub` is the client_id per OIDC core.
            let signing = ensure_pool_signing_key(state, &pool_id).await;
            let signing_ref = signing.as_ref().map(|(p, k)| (p.as_str(), k.as_str()));
            let scope = params.get("scope").cloned();
            let access_token = build_client_credentials_access_token(
                &pool_id,
                client_id,
                scope.as_deref(),
                region,
                signing_ref,
            );
            Ok(OAuthTokenResponse {
                access_token,
                id_token: None,
                refresh_token: None,
                expires_in: 3600,
                token_type: "Bearer".to_string(),
            })
        }
        "authorization_code" => Err(OAuthTokenError::UnsupportedGrantType),
        _ => Err(OAuthTokenError::UnsupportedGrantType),
    }
}

fn build_client_credentials_access_token(
    pool_id: &str,
    client_id: &str,
    scope: Option<&str>,
    region: &str,
    signing: Option<(&str, &str)>,
) -> String {
    let b64url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
    let now = Utc::now().timestamp();
    let jti = Uuid::new_v4().to_string();
    let iss = format!("https://cognito-idp.{region}.amazonaws.com/{pool_id}");
    let kid = signing
        .map(|(_, k)| k.to_string())
        .unwrap_or_else(|| "fakecloud-key-1".to_string());
    let header = json!({"kid": kid, "alg": "RS256", "typ": "JWT"});
    let payload = json!({
        "sub": client_id,
        "iss": iss,
        "client_id": client_id,
        "token_use": "access",
        "scope": scope.unwrap_or(""),
        "jti": jti,
        "exp": now + 3600,
        "iat": now,
    });
    sign_jwt(&header, &payload, &b64url, signing.map(|(p, _)| p))
}

#[derive(Debug, Clone)]
pub enum OAuthUserInfoError {
    InvalidToken,
}

/// RFC 7662-style userInfo. Resolves bearer access token in
/// state.access_tokens, returns OIDC standard claims sourced from the
/// user's attributes.
pub fn handle_oauth2_userinfo(
    state: &SharedCognitoState,
    bearer_token: &str,
) -> Result<Value, OAuthUserInfoError> {
    let mas = state.read();
    for (_, account) in mas.iter() {
        let Some(token_data) = account.access_tokens.get(bearer_token) else {
            continue;
        };
        let user = account
            .users
            .get(&token_data.user_pool_id)
            .and_then(|users| users.get(&token_data.username))
            .ok_or(OAuthUserInfoError::InvalidToken)?;
        let mut info = serde_json::Map::new();
        info.insert("sub".to_string(), Value::String(user.sub.clone()));
        info.insert("username".to_string(), Value::String(user.username.clone()));
        for attr in &user.attributes {
            info.insert(attr.name.clone(), Value::String(attr.value.clone()));
        }
        return Ok(Value::Object(info));
    }
    Err(OAuthUserInfoError::InvalidToken)
}

#[derive(Debug, Clone)]
pub enum OAuthRevokeError {
    InvalidClient,
    UnsupportedTokenType,
}

/// RFC 7009 token revocation. Cognito accepts refresh tokens; revoking a
/// refresh token also invalidates every access token issued from it
/// (matched by client_id + username + issued_at >= refresh issued_at).
/// Per RFC 7009 §2.2, revoking an unknown token is a 200, not an error.
pub fn handle_oauth2_revoke(
    state: &SharedCognitoState,
    params: &BTreeMap<String, String>,
) -> Result<(), OAuthRevokeError> {
    let token = match params.get("token") {
        Some(t) => t.clone(),
        None => return Ok(()),
    };
    if let Some(hint) = params.get("token_type_hint") {
        if hint != "refresh_token" {
            return Err(OAuthRevokeError::UnsupportedTokenType);
        }
    }
    let client_id = params
        .get("client_id")
        .map(String::as_str)
        .ok_or(OAuthRevokeError::InvalidClient)?;

    let stored_secret = {
        let mas = state.read();
        let mut found = None;
        for (_, account) in mas.iter() {
            if let Some(client) = account.user_pool_clients.get(client_id) {
                found = Some(client.client_secret.clone());
                break;
            }
        }
        found.ok_or(OAuthRevokeError::InvalidClient)?
    };
    if let Some(secret) = stored_secret.as_ref() {
        let supplied = params.get("client_secret").map(String::as_str);
        if supplied != Some(secret.as_str()) {
            return Err(OAuthRevokeError::InvalidClient);
        }
    }

    let mut mas = state.write();
    for (_, account) in mas.iter_mut() {
        if let Some(rt) = account.refresh_tokens.get(&token).cloned() {
            if rt.client_id != client_id {
                return Err(OAuthRevokeError::InvalidClient);
            }
            account.refresh_tokens.remove(&token);
            account.access_tokens.retain(|_, at| {
                !(at.client_id == rt.client_id
                    && at.username == rt.username
                    && at.user_pool_id == rt.user_pool_id
                    && at.issued_at >= rt.issued_at)
            });
            return Ok(());
        }
        if let Some(at) = account.access_tokens.get(&token).cloned() {
            if at.client_id != client_id {
                return Err(OAuthRevokeError::InvalidClient);
            }
            account.access_tokens.remove(&token);
            return Ok(());
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
