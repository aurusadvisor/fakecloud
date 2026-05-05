use std::sync::Arc;
use std::time::Duration;

use async_trait::async_trait;
use chrono::Utc;
use fakecloud_core::pagination::paginate;
use http::StatusCode;
use rand::Rng;
use serde_json::{json, Value};

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};

use crate::state::{
    MemberAccount, OrgError, OrganizationState, OrganizationalUnit, Policy,
    SharedOrganizationsState, FEATURE_SET_ALL, POLICY_TYPE_SCP,
};

/// Bounds for the synthetic delay before a `CreateAccount` request
/// flips from `IN_PROGRESS` to `SUCCEEDED`. Real AWS takes minutes; a
/// 1-2s window is enough for SDK callers to observe the IN_PROGRESS
/// phase via at least one poll without making tests slow.
const CREATE_ACCOUNT_MIN_DELAY: Duration = Duration::from_millis(1000);
const CREATE_ACCOUNT_MAX_DELAY: Duration = Duration::from_millis(2000);

/// Single source of truth for supported Organizations actions.
/// Enforcement of attached SCPs ships in Batch 4.
pub static ORGANIZATIONS_ACTIONS: &[&str] = &[
    "CreateOrganization",
    "DescribeOrganization",
    "DeleteOrganization",
    "ListRoots",
    "CreateOrganizationalUnit",
    "UpdateOrganizationalUnit",
    "DeleteOrganizationalUnit",
    "DescribeOrganizationalUnit",
    "ListOrganizationalUnitsForParent",
    "ListAccounts",
    "ListAccountsForParent",
    "DescribeAccount",
    "MoveAccount",
    "CreatePolicy",
    "UpdatePolicy",
    "DeletePolicy",
    "DescribePolicy",
    "ListPolicies",
    "AttachPolicy",
    "DetachPolicy",
    "ListPoliciesForTarget",
    "ListTargetsForPolicy",
    "CreateAccount",
    "CreateGovCloudAccount",
    "DescribeCreateAccountStatus",
    "ListCreateAccountStatus",
    "CloseAccount",
    "RemoveAccountFromOrganization",
    "InviteAccountToOrganization",
    "AcceptHandshake",
    "DeclineHandshake",
    "CancelHandshake",
    "DescribeHandshake",
    "ListHandshakesForAccount",
    "ListHandshakesForOrganization",
    "EnableAWSServiceAccess",
    "DisableAWSServiceAccess",
    "ListAWSServiceAccessForOrganization",
    "RegisterDelegatedAdministrator",
    "DeregisterDelegatedAdministrator",
    "ListDelegatedAdministrators",
    "ListDelegatedServicesForAccount",
    "EnableAllFeatures",
    "EnablePolicyType",
    "DisablePolicyType",
    "TagResource",
    "UntagResource",
    "ListTagsForResource",
    "ListParents",
    "ListChildren",
    "DescribeEffectivePolicy",
    "PutResourcePolicy",
    "DeleteResourcePolicy",
    "DescribeResourcePolicy",
];

pub struct OrganizationsService {
    state: SharedOrganizationsState,
}

impl OrganizationsService {
    pub fn new(state: SharedOrganizationsState) -> Self {
        Self { state }
    }

    pub fn shared() -> (Arc<Self>, SharedOrganizationsState) {
        let state: SharedOrganizationsState = Arc::new(parking_lot::RwLock::new(None));
        (Arc::new(Self::new(state.clone())), state)
    }

    fn create_organization(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let feature_set = body
            .get("FeatureSet")
            .and_then(|v| v.as_str())
            .unwrap_or(FEATURE_SET_ALL);
        if feature_set != FEATURE_SET_ALL {
            // fakecloud ships SCP enforcement which requires the ALL
            // feature set. CONSOLIDATED_BILLING disables SCPs in AWS,
            // and we don't simulate that distinction — reject up front
            // rather than silently lie about which feature set is on.
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "UnsupportedAPIEndpointException",
                "fakecloud only supports the ALL feature set for organizations",
            ));
        }

        let mut guard = self.state.write();
        if guard.is_some() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "AlreadyInOrganizationException",
                "The AWS account is already a member of an organization.",
            ));
        }
        let org = OrganizationState::bootstrap(&req.account_id);
        let resp_value = organization_payload(&org);
        *guard = Some(org);
        Ok(AwsResponse::ok_json(json!({ "Organization": resp_value })))
    }

    fn describe_organization(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let guard = self.state.read();
        let org = guard.as_ref().ok_or_else(organizations_not_in_use)?;
        // AWS scopes DescribeOrganization to members of the organization.
        // Non-members must not learn that an org exists at all — return
        // the same `AWSOrganizationsNotInUseException` the no-org path
        // returns so org metadata doesn't leak across account boundaries.
        if !org.accounts.contains_key(&req.account_id) {
            return Err(organizations_not_in_use());
        }
        Ok(AwsResponse::ok_json(
            json!({ "Organization": organization_payload(org) }),
        ))
    }

    fn delete_organization(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mut guard = self.state.write();
        let org = guard.as_ref().ok_or_else(organizations_not_in_use)?;
        // Non-members get the same "not in use" error as callers in a
        // process with no org at all — they should not be able to tell
        // the difference.
        if !org.accounts.contains_key(&req.account_id) {
            return Err(organizations_not_in_use());
        }
        if !org.is_management(&req.account_id) {
            return Err(AwsServiceError::aws_error(
                StatusCode::FORBIDDEN,
                "AccessDeniedException",
                "Only the management account can delete the organization.",
            ));
        }
        // Match AWS: delete fails if any member accounts besides the
        // management account remain. In Batch 1 only the management is
        // enrolled, so this check is a no-op; Batch 2 starts populating
        // real member accounts.
        let non_mgmt = org
            .accounts
            .keys()
            .filter(|id| id.as_str() != org.management_account_id)
            .count();
        if non_mgmt > 0 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "OrganizationNotEmptyException",
                "The organization still has member accounts. Remove them first.",
            ));
        }
        *guard = None;
        Ok(AwsResponse::ok_json(Value::Null))
    }

    fn list_roots(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let guard = self.state.read();
        let org = self.require_member(&guard, &req.account_id)?;
        let policy_types: Vec<Value> = org
            .list_policy_type_statuses()
            .into_iter()
            .filter(|(_, status)| status == "ENABLED")
            .map(|(t, status)| json!({"Type": t, "Status": status}))
            .collect();
        let root = json!({
            "Id": org.root_id,
            "Arn": org.root_arn,
            "Name": org.root_name,
            "PolicyTypes": policy_types,
        });
        Ok(AwsResponse::ok_json(json!({ "Roots": [root] })))
    }

    fn create_organizational_unit(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let parent_id = required_str(&body, "ParentId")?;
        let name = required_str(&body, "Name")?;
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().unwrap();
        let ou = org.create_ou(parent_id, name).map_err(org_error_to_aws)?;
        Ok(AwsResponse::ok_json(
            json!({ "OrganizationalUnit": ou_payload(&ou) }),
        ))
    }

    fn update_organizational_unit(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let ou_id = required_str(&body, "OrganizationalUnitId")?;
        let new_name = required_str(&body, "Name")?;
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().unwrap();
        let ou = org.rename_ou(ou_id, new_name).map_err(org_error_to_aws)?;
        Ok(AwsResponse::ok_json(
            json!({ "OrganizationalUnit": ou_payload(&ou) }),
        ))
    }

    fn delete_organizational_unit(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let ou_id = required_str(&body, "OrganizationalUnitId")?;
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().unwrap();
        org.delete_ou(ou_id).map_err(org_error_to_aws)?;
        Ok(AwsResponse::ok_json(Value::Null))
    }

    fn describe_organizational_unit(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let ou_id = required_str(&body, "OrganizationalUnitId")?;
        let guard = self.state.read();
        let org = self.require_member(&guard, &req.account_id)?;
        let ou = org.ous.get(ou_id).ok_or_else(|| {
            org_error_to_aws(OrgError::OrganizationalUnitNotFound(ou_id.to_string()))
        })?;
        Ok(AwsResponse::ok_json(
            json!({ "OrganizationalUnit": ou_payload(ou) }),
        ))
    }

    fn list_organizational_units_for_parent(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let parent_id = required_str(&body, "ParentId")?;
        let guard = self.state.read();
        let org = self.require_member(&guard, &req.account_id)?;
        if parent_id != org.root_id && !org.ous.contains_key(parent_id) {
            return Err(org_error_to_aws(OrgError::ParentNotFound(
                parent_id.to_string(),
            )));
        }
        let children: Vec<Value> = org
            .ous
            .values()
            .filter(|ou| ou.parent_id == parent_id)
            .map(ou_payload)
            .collect();
        Ok(AwsResponse::ok_json(
            json!({ "OrganizationalUnits": children }),
        ))
    }

    fn list_accounts(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let guard = self.state.read();
        let org = self.require_member(&guard, &req.account_id)?;
        let accounts: Vec<Value> = org.accounts.values().map(account_payload).collect();
        Ok(AwsResponse::ok_json(json!({ "Accounts": accounts })))
    }

    fn list_accounts_for_parent(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let parent_id = required_str(&body, "ParentId")?;
        let guard = self.state.read();
        let org = self.require_member(&guard, &req.account_id)?;
        if parent_id != org.root_id && !org.ous.contains_key(parent_id) {
            return Err(org_error_to_aws(OrgError::ParentNotFound(
                parent_id.to_string(),
            )));
        }
        let accounts: Vec<Value> = org
            .accounts
            .values()
            .filter(|a| a.parent_id == parent_id)
            .map(account_payload)
            .collect();
        Ok(AwsResponse::ok_json(json!({ "Accounts": accounts })))
    }

    fn describe_account(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let account_id = required_str(&body, "AccountId")?;
        let guard = self.state.read();
        let org = self.require_member(&guard, &req.account_id)?;
        let account = org
            .accounts
            .get(account_id)
            .ok_or_else(|| org_error_to_aws(OrgError::AccountNotFound(account_id.to_string())))?;
        Ok(AwsResponse::ok_json(
            json!({ "Account": account_payload(account) }),
        ))
    }

    fn move_account(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let account_id = required_str(&body, "AccountId")?;
        let source = required_str(&body, "SourceParentId")?;
        let dest = required_str(&body, "DestinationParentId")?;
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().unwrap();
        org.move_account(account_id, source, dest)
            .map_err(org_error_to_aws)?;
        Ok(AwsResponse::ok_json(Value::Null))
    }

    fn create_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = required_str(&body, "Name")?;
        let policy_type = required_str(&body, "Type")?;
        let content = required_str(&body, "Content")?;
        let description = body
            .get("Description")
            .and_then(|v| v.as_str())
            .unwrap_or("");
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().unwrap();
        let policy = org
            .create_policy(name, description, content, policy_type)
            .map_err(org_error_to_aws)?;
        Ok(AwsResponse::ok_json(
            json!({ "Policy": policy_with_content(&policy) }),
        ))
    }

    fn update_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let policy_id = required_str(&body, "PolicyId")?;
        let name = body.get("Name").and_then(|v| v.as_str());
        let description = body.get("Description").and_then(|v| v.as_str());
        let content = body.get("Content").and_then(|v| v.as_str());
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().unwrap();
        let policy = org
            .update_policy(policy_id, name, description, content)
            .map_err(org_error_to_aws)?;
        Ok(AwsResponse::ok_json(
            json!({ "Policy": policy_with_content(&policy) }),
        ))
    }

    fn delete_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let policy_id = required_str(&body, "PolicyId")?;
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().unwrap();
        org.delete_policy(policy_id).map_err(org_error_to_aws)?;
        Ok(AwsResponse::ok_json(Value::Null))
    }

    fn describe_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let policy_id = required_str(&body, "PolicyId")?;
        let guard = self.state.read();
        let org = self.require_member(&guard, &req.account_id)?;
        let policy = org
            .policies
            .get(policy_id)
            .ok_or_else(|| org_error_to_aws(OrgError::PolicyNotFound(policy_id.to_string())))?;
        Ok(AwsResponse::ok_json(
            json!({ "Policy": policy_with_content(policy) }),
        ))
    }

    fn list_policies(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        // Filter is a required parameter on the AWS API. Reject missing
        // filter so the SDK wire format matches and callers learn about
        // their typo rather than getting an implicit SCP default.
        let filter = required_str(&body, "Filter")?;
        if !is_known_policy_type(filter) {
            return Err(org_error_to_aws(OrgError::PolicyTypeNotSupported(
                filter.to_string(),
            )));
        }
        let guard = self.state.read();
        let org = self.require_member(&guard, &req.account_id)?;
        let mut policies: Vec<&Policy> = org
            .policies
            .values()
            .filter(|p| p.policy_type == filter)
            .collect();
        policies.sort_by(|a, b| a.name.cmp(&b.name));
        let summaries: Vec<Value> = policies.iter().map(|p| policy_summary(p)).collect();
        Ok(AwsResponse::ok_json(json!({ "Policies": summaries })))
    }

    fn attach_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let policy_id = required_str(&body, "PolicyId")?;
        let target_id = required_str(&body, "TargetId")?;
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().unwrap();
        org.attach_policy(policy_id, target_id)
            .map_err(org_error_to_aws)?;
        Ok(AwsResponse::ok_json(Value::Null))
    }

    fn detach_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let policy_id = required_str(&body, "PolicyId")?;
        let target_id = required_str(&body, "TargetId")?;
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().unwrap();
        org.detach_policy(policy_id, target_id)
            .map_err(org_error_to_aws)?;
        Ok(AwsResponse::ok_json(Value::Null))
    }

    fn list_policies_for_target(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let target_id = required_str(&body, "TargetId")?;
        let filter = required_str(&body, "Filter")?;
        if !is_known_policy_type(filter) {
            return Err(org_error_to_aws(OrgError::PolicyTypeNotSupported(
                filter.to_string(),
            )));
        }
        let guard = self.state.read();
        let org = self.require_member(&guard, &req.account_id)?;
        let mut policies = org
            .policies_for_target(target_id)
            .map_err(org_error_to_aws)?;
        policies.sort_by(|a, b| a.name.cmp(&b.name));
        let summaries: Vec<Value> = policies.iter().map(|p| policy_summary(p)).collect();
        Ok(AwsResponse::ok_json(json!({ "Policies": summaries })))
    }

    fn list_targets_for_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let policy_id = required_str(&body, "PolicyId")?;
        let guard = self.state.read();
        let org = self.require_member(&guard, &req.account_id)?;
        let targets = org
            .targets_for_policy(policy_id)
            .map_err(org_error_to_aws)?;
        let payload: Vec<Value> = targets
            .iter()
            .map(|(id, name, ttype)| {
                json!({
                    "TargetId": id,
                    "Name": name,
                    "Type": ttype,
                    "Arn": target_arn(org, id, ttype),
                })
            })
            .collect();
        Ok(AwsResponse::ok_json(json!({ "Targets": payload })))
    }

    /// Read-side helper: enforce that an org exists and the caller is a
    /// member. Returns the borrowed org on success.
    fn require_member<'a>(
        &self,
        guard: &'a parking_lot::RwLockReadGuard<'_, Option<OrganizationState>>,
        account_id: &str,
    ) -> Result<&'a OrganizationState, AwsServiceError> {
        let org = guard.as_ref().ok_or_else(organizations_not_in_use)?;
        if !org.accounts.contains_key(account_id) {
            return Err(organizations_not_in_use());
        }
        Ok(org)
    }

    /// Write-side helper for mutating ops: caller must be the
    /// management account of an existing organization. Returns the
    /// management-only error rather than an Option, so the caller can
    /// unwrap the guard safely right after.
    fn require_member_management(
        &self,
        guard: &parking_lot::RwLockWriteGuard<'_, Option<OrganizationState>>,
        account_id: &str,
    ) -> Result<(), AwsServiceError> {
        let org = guard.as_ref().ok_or_else(organizations_not_in_use)?;
        if !org.accounts.contains_key(account_id) {
            return Err(organizations_not_in_use());
        }
        if !org.is_management(account_id) {
            return Err(AwsServiceError::aws_error(
                StatusCode::FORBIDDEN,
                "AccessDeniedException",
                "This operation can be called only from the organization's management account.",
            ));
        }
        Ok(())
    }

    fn create_account(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let email = required_str(&body, "Email")?.to_string();
        let name = required_str(&body, "AccountName")?.to_string();

        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().expect("management gate proved Some");
        let status = org.begin_create_account(&email, &name, None);
        let request_id = status.id.clone();
        drop(guard);

        self.spawn_create_account_completion(request_id);

        Ok(AwsResponse::ok_json(json!({
            "CreateAccountStatus": create_account_status_payload(&status),
        })))
    }

    fn create_gov_cloud_account(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let email = required_str(&body, "Email")?.to_string();
        let name = required_str(&body, "AccountName")?.to_string();

        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().expect("management gate proved Some");
        // The GovCloud "paired" id is a 12-digit account id in the
        // GovCloud partition; we mint one alongside the commercial id
        // so callers see both, matching the real AWS response.
        let gov_id = org.next_account_id();
        let status = org.begin_create_account(&email, &name, Some(gov_id));
        let request_id = status.id.clone();
        drop(guard);

        self.spawn_create_account_completion(request_id);

        Ok(AwsResponse::ok_json(json!({
            "CreateAccountStatus": create_account_status_payload(&status),
        })))
    }

    /// Spawn a background tokio task that flips `request_id` from
    /// `IN_PROGRESS` to `SUCCEEDED` after a synthetic 1-2s delay,
    /// enrolling the reserved account id (and GovCloud paired id, if
    /// any) into `state.accounts`. Mirrors the async shape of real
    /// AWS `CreateAccount` so SDK callers can observe both phases.
    fn spawn_create_account_completion(&self, request_id: String) {
        let state = self.state.clone();
        let delay = {
            let mut rng = rand::thread_rng();
            let span = CREATE_ACCOUNT_MAX_DELAY.saturating_sub(CREATE_ACCOUNT_MIN_DELAY);
            let jitter_millis = if span.is_zero() {
                0
            } else {
                rng.gen_range(0..=span.as_millis() as u64)
            };
            CREATE_ACCOUNT_MIN_DELAY + Duration::from_millis(jitter_millis)
        };
        tokio::spawn(async move {
            tokio::time::sleep(delay).await;
            let mut guard = state.write();
            if let Some(org) = guard.as_mut() {
                org.complete_create_account(&request_id);
            }
        });
    }

    fn describe_create_account_status(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let request_id = required_str(&body, "CreateAccountRequestId")?.to_string();

        let guard = self.state.read();
        let org = self.require_member(&guard, &req.account_id)?;
        let status = org.describe_create_account(&request_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "CreateAccountStatusNotFoundException",
                format!("Create account status with id {request_id} was not found."),
            )
        })?;
        Ok(AwsResponse::ok_json(json!({
            "CreateAccountStatus": create_account_status_payload(&status),
        })))
    }

    fn list_create_account_status(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let states: Vec<String> = body
            .get("States")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str())
                    .map(|s| s.to_string())
                    .collect()
            })
            .unwrap_or_default();
        // AWS caps MaxResults at 20 for ListCreateAccountStatus and
        // defaults to 20 when unset. Match that so SDK pagination
        // tests don't have to special-case fakecloud.
        let max_results = body
            .get("MaxResults")
            .and_then(|v| v.as_u64())
            .map(|n| n.clamp(1, 20) as usize)
            .unwrap_or(20);
        let next_token = body
            .get("NextToken")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let guard = self.state.read();
        let org = self.require_member(&guard, &req.account_id)?;
        let filtered: Vec<Value> = org
            .create_account_requests
            .values()
            .filter(|s| states.is_empty() || states.iter().any(|st| st == &s.state))
            .map(create_account_status_payload)
            .collect();
        let (page, token) = paginate(&filtered, next_token.as_deref(), max_results);
        let mut body = json!({ "CreateAccountStatuses": page });
        if let Some(t) = token {
            body["NextToken"] = json!(t);
        }
        Ok(AwsResponse::ok_json(body))
    }

    fn close_account(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let target = required_str(&body, "AccountId")?.to_string();

        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().expect("management gate proved Some");
        org.close_account(&target).map_err(org_error_to_aws)?;
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn remove_account_from_organization(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let target = required_str(&body, "AccountId")?.to_string();

        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().expect("management gate proved Some");
        org.remove_account(&target).map_err(org_error_to_aws)?;
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn invite_account_to_organization(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let target_obj = body.get("Target").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidInputException",
                "Target is required",
            )
        })?;
        let kind = target_obj
            .get("Type")
            .and_then(|v| v.as_str())
            .unwrap_or("ACCOUNT");
        let id = target_obj
            .get("Id")
            .and_then(|v| v.as_str())
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidInputException",
                    "Target.Id is required",
                )
            })?
            .to_string();
        let notes = body
            .get("Notes")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let target_email = if kind == "EMAIL" {
            Some(id.clone())
        } else {
            None
        };

        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().expect("management gate proved Some");
        let handshake = org
            .invite_account(&req.account_id, &id, target_email, notes)
            .map_err(org_error_to_aws)?;
        Ok(AwsResponse::ok_json(
            json!({ "Handshake": handshake_payload(&handshake) }),
        ))
    }

    fn accept_handshake(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        self.transition_handshake(req, "ACCEPTED")
    }

    fn decline_handshake(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        self.transition_handshake(req, "DECLINED")
    }

    fn cancel_handshake(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        self.transition_handshake(req, "CANCELED")
    }

    fn transition_handshake(
        &self,
        req: &AwsRequest,
        new_state: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let id = required_str(&body, "HandshakeId")?.to_string();
        let mut guard = self.state.write();
        let org = guard.as_mut().ok_or_else(organizations_not_in_use)?;

        // AcceptHandshake / DeclineHandshake belong to the *target*
        // account; CancelHandshake belongs to the *source* (management)
        // account. Enforce party-correctness so test harnesses catch
        // misuse before AWS would.
        let handshake = org.handshakes.get(&id).ok_or_else(|| {
            org_error_to_aws(crate::state::OrgError::HandshakeNotFound(id.clone()))
        })?;
        let allowed = match new_state {
            "ACCEPTED" | "DECLINED" => req.account_id == handshake.target_account_id,
            "CANCELED" => req.account_id == handshake.source_account_id,
            _ => false,
        };
        if !allowed {
            return Err(org_error_to_aws(
                crate::state::OrgError::InvalidHandshakeParty(req.account_id.clone()),
            ));
        }
        let updated = org
            .resolve_handshake(&id, new_state)
            .map_err(org_error_to_aws)?;
        Ok(AwsResponse::ok_json(
            json!({ "Handshake": handshake_payload(&updated) }),
        ))
    }

    fn describe_handshake(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let id = required_str(&body, "HandshakeId")?.to_string();
        let guard = self.state.read();
        let org = guard.as_ref().ok_or_else(organizations_not_in_use)?;
        let handshake = org.handshakes.get(&id).ok_or_else(|| {
            org_error_to_aws(crate::state::OrgError::HandshakeNotFound(id.clone()))
        })?;
        Ok(AwsResponse::ok_json(
            json!({ "Handshake": handshake_payload(handshake) }),
        ))
    }

    fn list_handshakes_for_account(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let guard = self.state.read();
        let org = guard.as_ref().ok_or_else(organizations_not_in_use)?;
        let entries: Vec<Value> = org
            .list_handshakes(Some(&req.account_id))
            .iter()
            .map(handshake_payload)
            .collect();
        Ok(AwsResponse::ok_json(json!({ "Handshakes": entries })))
    }

    fn list_handshakes_for_organization(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_ref().expect("management gate proved Some");
        let entries: Vec<Value> = org
            .list_handshakes(None)
            .iter()
            .map(handshake_payload)
            .collect();
        Ok(AwsResponse::ok_json(json!({ "Handshakes": entries })))
    }

    fn enable_aws_service_access(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let principal = required_str(&body, "ServicePrincipal")?.to_string();
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().expect("management gate proved Some");
        org.enable_aws_service_access(&principal);
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn disable_aws_service_access(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let principal = required_str(&body, "ServicePrincipal")?.to_string();
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().expect("management gate proved Some");
        org.disable_aws_service_access(&principal)
            .map_err(org_error_to_aws)?;
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn list_aws_service_access_for_organization(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_ref().expect("management gate proved Some");
        let entries: Vec<Value> = org
            .list_trusted_services()
            .into_iter()
            .map(|svc| {
                json!({
                    "ServicePrincipal": svc,
                    "DateEnabled": Utc::now().timestamp() as f64,
                })
            })
            .collect();
        Ok(AwsResponse::ok_json(
            json!({ "EnabledServicePrincipals": entries }),
        ))
    }

    fn register_delegated_administrator(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let account_id = required_str(&body, "AccountId")?.to_string();
        let principal = required_str(&body, "ServicePrincipal")?.to_string();
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().expect("management gate proved Some");
        org.register_delegated_administrator(&account_id, &principal)
            .map_err(org_error_to_aws)?;
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn deregister_delegated_administrator(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let account_id = required_str(&body, "AccountId")?.to_string();
        let principal = required_str(&body, "ServicePrincipal")?.to_string();
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().expect("management gate proved Some");
        org.deregister_delegated_administrator(&account_id, &principal)
            .map_err(org_error_to_aws)?;
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn list_delegated_administrators(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let filter = body
            .get("ServicePrincipal")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_ref().expect("management gate proved Some");
        let entries: Vec<Value> = org
            .list_delegated_administrators(filter.as_deref())
            .into_iter()
            .filter_map(|admin| {
                let acct = org.accounts.get(&admin.account_id)?;
                Some(json!({
                    "Id": acct.id,
                    "Arn": acct.arn,
                    "Email": acct.email,
                    "Name": acct.name,
                    "Status": acct.status,
                    "JoinedMethod": acct.joined_method,
                    "JoinedTimestamp": acct.joined_timestamp.timestamp() as f64,
                    "DelegationEnabledDate": admin.registered_at.timestamp() as f64,
                }))
            })
            .collect();
        Ok(AwsResponse::ok_json(
            json!({ "DelegatedAdministrators": entries }),
        ))
    }

    fn list_delegated_services_for_account(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let account_id = required_str(&body, "AccountId")?.to_string();
        let guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_ref().expect("management gate proved Some");
        let entries: Vec<Value> = org
            .list_delegated_services_for_account(&account_id)
            .into_iter()
            .map(|svc| {
                json!({
                    "ServicePrincipal": svc,
                    "DelegationEnabledDate": Utc::now().timestamp() as f64,
                })
            })
            .collect();
        Ok(AwsResponse::ok_json(
            json!({ "DelegatedServices": entries }),
        ))
    }

    fn enable_all_features(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().expect("management gate proved Some");
        org.enable_all_features();
        // AWS returns a Handshake here; we synthesize a minimal accepted
        // shape so SDKs can deserialize the response.
        let handshake = json!({
            "Id": "h-enableallfeatures",
            "Arn": format!(
                "arn:aws:organizations::{}:handshake/{}/enable-all-features/h-enableallfeatures",
                org.management_account_id, org.org_id
            ),
            "Action": "ENABLE_ALL_FEATURES",
            "State": "ACCEPTED",
            "Parties": [],
            "Resources": [],
        });
        Ok(AwsResponse::ok_json(json!({ "Handshake": handshake })))
    }

    fn enable_policy_type(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let policy_type = required_str(&body, "PolicyType")?.to_string();
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().expect("management gate proved Some");
        org.enable_policy_type(&policy_type);
        let policy_types: Vec<Value> = org
            .list_policy_type_statuses()
            .into_iter()
            .filter(|(_, status)| status == "ENABLED")
            .map(|(t, status)| json!({"Type": t, "Status": status}))
            .collect();
        Ok(AwsResponse::ok_json(json!({
            "Root": {
                "Id": org.root_id,
                "Arn": org.root_arn,
                "Name": org.root_name,
                "PolicyTypes": policy_types,
            }
        })))
    }

    fn disable_policy_type(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let policy_type = required_str(&body, "PolicyType")?.to_string();
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().expect("management gate proved Some");
        org.disable_policy_type(&policy_type)
            .map_err(org_error_to_aws)?;
        let policy_types: Vec<Value> = org
            .list_policy_type_statuses()
            .into_iter()
            .filter(|(_, status)| status == "ENABLED")
            .map(|(t, status)| json!({"Type": t, "Status": status}))
            .collect();
        Ok(AwsResponse::ok_json(json!({
            "Root": {
                "Id": org.root_id,
                "Arn": org.root_arn,
                "Name": org.root_name,
                "PolicyTypes": policy_types,
            }
        })))
    }
    fn tag_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let resource_id = required_str(&body, "ResourceId")?.to_string();
        let tags = parse_tags(body.get("Tags"));
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().expect("management gate proved Some");
        org.set_resource_tags(&resource_id, &tags);
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn untag_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let resource_id = required_str(&body, "ResourceId")?.to_string();
        let tag_keys: Vec<String> = body
            .get("TagKeys")
            .and_then(|v| v.as_array())
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().expect("management gate proved Some");
        org.untag_resource(&resource_id, &tag_keys);
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn list_tags_for_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let resource_id = required_str(&body, "ResourceId")?.to_string();
        let guard = self.state.read();
        let org = guard.as_ref().ok_or_else(organizations_not_in_use)?;
        let tags: Vec<Value> = org
            .list_resource_tags(&resource_id)
            .into_iter()
            .map(|(k, v)| json!({"Key": k, "Value": v}))
            .collect();
        Ok(AwsResponse::ok_json(json!({ "Tags": tags })))
    }

    fn list_parents(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let child_id = required_str(&body, "ChildId")?.to_string();
        let guard = self.state.read();
        let org = guard.as_ref().ok_or_else(organizations_not_in_use)?;
        let parents = match org.parent_of(&child_id) {
            Some((id, kind)) => vec![json!({"Id": id, "Type": kind})],
            None => Vec::new(),
        };
        Ok(AwsResponse::ok_json(json!({ "Parents": parents })))
    }

    fn list_children(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let parent_id = required_str(&body, "ParentId")?.to_string();
        let child_type = required_str(&body, "ChildType")?.to_string();
        let guard = self.state.read();
        let org = guard.as_ref().ok_or_else(organizations_not_in_use)?;
        let children: Vec<Value> = org
            .list_children(&parent_id, &child_type)
            .into_iter()
            .map(|id| json!({"Id": id, "Type": child_type}))
            .collect();
        Ok(AwsResponse::ok_json(json!({ "Children": children })))
    }

    fn describe_effective_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let policy_type = required_str(&body, "PolicyType")?.to_string();
        let target_id = body
            .get("TargetId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| req.account_id.clone());
        let guard = self.state.read();
        let org = guard.as_ref().ok_or_else(organizations_not_in_use)?;
        // The effective policy is the union of every policy of `policy_type`
        // attached up the org hierarchy from `target_id` to root. We
        // present it as a single Statement[] union so callers can audit.
        let mut statements: Vec<Value> = Vec::new();
        for ancestor in ancestors_for(org, &target_id) {
            if let Some(policy_ids) = org.attachments.get(&ancestor) {
                for pid in policy_ids {
                    if let Some(policy) = org.policies.get(pid) {
                        if policy.policy_type == policy_type {
                            if let Ok(content) = serde_json::from_str::<Value>(&policy.content) {
                                if let Some(arr) =
                                    content.get("Statement").and_then(|v| v.as_array())
                                {
                                    statements.extend(arr.iter().cloned());
                                }
                            }
                        }
                    }
                }
            }
        }
        let merged = json!({"Version": "2012-10-17", "Statement": statements});
        let payload = json!({
            "EffectivePolicy": {
                "PolicyType": policy_type,
                "TargetId": target_id,
                "PolicyContent": merged.to_string(),
                "LastUpdatedTimestamp": Utc::now().timestamp() as f64,
            }
        });
        Ok(AwsResponse::ok_json(payload))
    }

    fn put_resource_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let content = required_str(&body, "Content")?.to_string();
        // Reject malformed JSON up front.
        serde_json::from_str::<Value>(&content).map_err(|_| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidInputException",
                "Content must be valid JSON",
            )
        })?;
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().expect("management gate proved Some");
        org.resource_policy = Some(content);
        let payload = json!({
            "ResourcePolicy": {
                "ResourcePolicySummary": {
                    "Id": "rp-fakecloud",
                    "Arn": format!(
                        "arn:aws:organizations::{}:resourcepolicy/{}/rp-fakecloud",
                        org.management_account_id, org.org_id
                    ),
                },
                "Content": org.resource_policy.clone(),
            }
        });
        Ok(AwsResponse::ok_json(payload))
    }

    fn delete_resource_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mut guard = self.state.write();
        self.require_member_management(&guard, &req.account_id)?;
        let org = guard.as_mut().expect("management gate proved Some");
        org.resource_policy = None;
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn describe_resource_policy(&self, _req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let guard = self.state.read();
        let org = guard.as_ref().ok_or_else(organizations_not_in_use)?;
        let content = org.resource_policy.clone().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourcePolicyNotFoundException",
                "No resource policy is attached to this organization.",
            )
        })?;
        Ok(AwsResponse::ok_json(json!({
            "ResourcePolicy": {
                "ResourcePolicySummary": {
                    "Id": "rp-fakecloud",
                    "Arn": format!(
                        "arn:aws:organizations::{}:resourcepolicy/{}/rp-fakecloud",
                        org.management_account_id, org.org_id
                    ),
                },
                "Content": content,
            }
        })))
    }
}

fn parse_tags(value: Option<&Value>) -> Vec<(String, String)> {
    let arr = match value.and_then(|v| v.as_array()) {
        Some(a) => a,
        None => return Vec::new(),
    };
    arr.iter()
        .filter_map(|v| {
            let k = v.get("Key")?.as_str()?.to_string();
            let value = v.get("Value")?.as_str()?.to_string();
            Some((k, value))
        })
        .collect()
}

/// Walk from `target_id` up to root (inclusive) via OU/account parents.
/// Used by `DescribeEffectivePolicy` to union policy statements across
/// every level. Keeps the input id at the front so direct attachments
/// take precedence in iteration order.
fn ancestors_for(org: &OrganizationState, target_id: &str) -> Vec<String> {
    let mut chain = vec![target_id.to_string()];
    let mut cursor = target_id.to_string();
    while let Some((parent, _)) = org.parent_of(&cursor) {
        if parent.is_empty() {
            break;
        }
        chain.push(parent.clone());
        if parent.starts_with("r-") {
            break;
        }
        cursor = parent;
    }
    chain
}

#[async_trait]
impl AwsService for OrganizationsService {
    fn service_name(&self) -> &str {
        "organizations"
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        match req.action.as_str() {
            "CreateOrganization" => self.create_organization(&req),
            "DescribeOrganization" => self.describe_organization(&req),
            "DeleteOrganization" => self.delete_organization(&req),
            "ListRoots" => self.list_roots(&req),
            "CreateOrganizationalUnit" => self.create_organizational_unit(&req),
            "UpdateOrganizationalUnit" => self.update_organizational_unit(&req),
            "DeleteOrganizationalUnit" => self.delete_organizational_unit(&req),
            "DescribeOrganizationalUnit" => self.describe_organizational_unit(&req),
            "ListOrganizationalUnitsForParent" => self.list_organizational_units_for_parent(&req),
            "ListAccounts" => self.list_accounts(&req),
            "ListAccountsForParent" => self.list_accounts_for_parent(&req),
            "DescribeAccount" => self.describe_account(&req),
            "MoveAccount" => self.move_account(&req),
            "CreatePolicy" => self.create_policy(&req),
            "UpdatePolicy" => self.update_policy(&req),
            "DeletePolicy" => self.delete_policy(&req),
            "DescribePolicy" => self.describe_policy(&req),
            "ListPolicies" => self.list_policies(&req),
            "AttachPolicy" => self.attach_policy(&req),
            "DetachPolicy" => self.detach_policy(&req),
            "ListPoliciesForTarget" => self.list_policies_for_target(&req),
            "ListTargetsForPolicy" => self.list_targets_for_policy(&req),
            "CreateAccount" => self.create_account(&req),
            "CreateGovCloudAccount" => self.create_gov_cloud_account(&req),
            "DescribeCreateAccountStatus" => self.describe_create_account_status(&req),
            "ListCreateAccountStatus" => self.list_create_account_status(&req),
            "CloseAccount" => self.close_account(&req),
            "RemoveAccountFromOrganization" => self.remove_account_from_organization(&req),
            "InviteAccountToOrganization" => self.invite_account_to_organization(&req),
            "AcceptHandshake" => self.accept_handshake(&req),
            "DeclineHandshake" => self.decline_handshake(&req),
            "CancelHandshake" => self.cancel_handshake(&req),
            "DescribeHandshake" => self.describe_handshake(&req),
            "ListHandshakesForAccount" => self.list_handshakes_for_account(&req),
            "ListHandshakesForOrganization" => self.list_handshakes_for_organization(&req),
            "EnableAWSServiceAccess" => self.enable_aws_service_access(&req),
            "DisableAWSServiceAccess" => self.disable_aws_service_access(&req),
            "ListAWSServiceAccessForOrganization" => {
                self.list_aws_service_access_for_organization(&req)
            }
            "RegisterDelegatedAdministrator" => self.register_delegated_administrator(&req),
            "DeregisterDelegatedAdministrator" => self.deregister_delegated_administrator(&req),
            "ListDelegatedAdministrators" => self.list_delegated_administrators(&req),
            "ListDelegatedServicesForAccount" => self.list_delegated_services_for_account(&req),
            "EnableAllFeatures" => self.enable_all_features(&req),
            "EnablePolicyType" => self.enable_policy_type(&req),
            "DisablePolicyType" => self.disable_policy_type(&req),
            "TagResource" => self.tag_resource(&req),
            "UntagResource" => self.untag_resource(&req),
            "ListTagsForResource" => self.list_tags_for_resource(&req),
            "ListParents" => self.list_parents(&req),
            "ListChildren" => self.list_children(&req),
            "DescribeEffectivePolicy" => self.describe_effective_policy(&req),
            "PutResourcePolicy" => self.put_resource_policy(&req),
            "DeleteResourcePolicy" => self.delete_resource_policy(&req),
            "DescribeResourcePolicy" => self.describe_resource_policy(&req),
            _ => Err(AwsServiceError::action_not_implemented(
                "organizations",
                &req.action,
            )),
        }
    }

    fn supported_actions(&self) -> &[&str] {
        ORGANIZATIONS_ACTIONS
    }
}

fn organizations_not_in_use() -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "AWSOrganizationsNotInUseException",
        "Your account is not a member of an organization.",
    )
}

fn policy_summary(policy: &Policy) -> Value {
    json!({
        "Id": policy.id,
        "Arn": policy.arn,
        "Name": policy.name,
        "Description": policy.description,
        "Type": policy.policy_type,
        "AwsManaged": policy.aws_managed,
    })
}

fn policy_with_content(policy: &Policy) -> Value {
    json!({
        "PolicySummary": policy_summary(policy),
        "Content": policy.content,
    })
}

fn target_arn(org: &OrganizationState, target_id: &str, target_type: &str) -> String {
    match target_type {
        "ROOT" => org.root_arn.clone(),
        "ORGANIZATIONAL_UNIT" => org
            .ous
            .get(target_id)
            .map(|ou| ou.arn.clone())
            .unwrap_or_default(),
        "ACCOUNT" => org
            .accounts
            .get(target_id)
            .map(|a| a.arn.clone())
            .unwrap_or_default(),
        _ => String::new(),
    }
}

fn ou_payload(ou: &OrganizationalUnit) -> Value {
    json!({
        "Id": ou.id,
        "Arn": ou.arn,
        "Name": ou.name,
    })
}

fn account_payload(account: &MemberAccount) -> Value {
    json!({
        "Id": account.id,
        "Arn": account.arn,
        "Email": account.email,
        "Name": account.name,
        "Status": account.status,
        "JoinedMethod": account.joined_method,
        "JoinedTimestamp": account.joined_timestamp.timestamp() as f64,
    })
}

fn required_str<'a>(body: &'a Value, key: &str) -> Result<&'a str, AwsServiceError> {
    body.get(key).and_then(|v| v.as_str()).ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidInputException",
            format!("Missing required parameter: {key}"),
        )
    })
}

fn is_known_policy_type(t: &str) -> bool {
    matches!(
        t,
        POLICY_TYPE_SCP
            | "TAG_POLICY"
            | "BACKUP_POLICY"
            | "AISERVICES_OPT_OUT_POLICY"
            | "RESOURCE_CONTROL_POLICY"
    )
}

fn org_error_to_aws(err: OrgError) -> AwsServiceError {
    match err {
        OrgError::ParentNotFound(id) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ParentNotFoundException",
            format!("The parent with id {id} was not found."),
        ),
        OrgError::DuplicateOrganizationalUnit(name) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "DuplicateOrganizationalUnitException",
            format!("An organizational unit named {name} already exists under this parent."),
        ),
        OrgError::OrganizationalUnitNotFound(id) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "OrganizationalUnitNotFoundException",
            format!("The organizational unit with id {id} was not found."),
        ),
        OrgError::OrganizationalUnitNotEmpty(id) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "OrganizationalUnitNotEmptyException",
            format!("The organizational unit {id} still contains accounts or child OUs."),
        ),
        OrgError::AccountNotFound(id) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "AccountNotFoundException",
            format!("The account with id {id} was not found."),
        ),
        OrgError::SourceParentNotFound(id) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "SourceParentNotFoundException",
            format!("The source parent {id} does not contain this account."),
        ),
        OrgError::DestinationParentNotFound(id) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "DestinationParentNotFoundException",
            format!("The destination parent {id} does not exist."),
        ),
        OrgError::PolicyNotFound(id) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "PolicyNotFoundException",
            format!("The policy with id {id} was not found."),
        ),
        OrgError::DuplicatePolicy(name) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "DuplicatePolicyException",
            format!("A policy named {name} already exists for this policy type."),
        ),
        OrgError::MalformedPolicyDocument => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "MalformedPolicyDocumentException",
            "The policy document is not valid JSON.",
        ),
        OrgError::PolicyTypeNotSupported(t) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "PolicyTypeNotSupportedException",
            format!("fakecloud only supports SERVICE_CONTROL_POLICY; got {t}."),
        ),
        OrgError::PolicyChangesNotAllowed(id) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "PolicyChangesNotAllowedException",
            format!("Policy {id} is AWS-managed and cannot be modified or deleted."),
        ),
        OrgError::PolicyInUse(id) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "PolicyInUseException",
            format!("Policy {id} is attached to one or more targets; detach before deleting."),
        ),
        OrgError::PolicyNotAttached(id) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "PolicyNotAttachedException",
            format!("Policy {id} is not attached to this target."),
        ),
        OrgError::TargetNotFound(id) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "TargetNotFoundException",
            format!("The target with id {id} was not found."),
        ),
        OrgError::AccountChangesNotAllowed(id) => AwsServiceError::aws_error(
            StatusCode::FORBIDDEN,
            "ConstraintViolationException",
            format!("Account {id} cannot be removed or closed (management account)."),
        ),
        OrgError::CreateAccountStatusNotFound(id) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "CreateAccountStatusNotFoundException",
            format!("Create account status with id {id} was not found."),
        ),
        OrgError::HandshakeNotFound(id) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "HandshakeNotFoundException",
            format!("The handshake with id {id} was not found."),
        ),
        OrgError::HandshakeAlreadyResolved(state) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidHandshakeTransitionException",
            format!("Handshake is already in terminal state {state}."),
        ),
        OrgError::InvalidHandshakeState(state) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidHandshakeTransitionException",
            format!("State {state} is not a valid terminal handshake state."),
        ),
        OrgError::InvalidHandshakeParty(account) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "AccessDeniedException",
            format!("Account {account} is not party to this handshake's transition."),
        ),
        OrgError::DuplicateHandshakeForAccount(account) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "DuplicateHandshakeException",
            format!("An OPEN handshake already exists for account {account}."),
        ),
        OrgError::AccountAlreadyMember(account) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "AccountAlreadyRegisteredException",
            format!("Account {account} is already a member of this organization."),
        ),
        OrgError::AWSServiceAccessNotEnabled(svc) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "AWSOrganizationsNotInUseException",
            format!("AWS service access for {svc} is not enabled."),
        ),
        OrgError::DelegatedAdministratorAlreadyRegistered(id) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "AccountAlreadyRegisteredException",
            format!("Account {id} is already registered as a delegated administrator."),
        ),
        OrgError::DelegatedAdministratorNotRegistered(id) => AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "AccountNotRegisteredException",
            format!("Account {id} is not registered as a delegated administrator."),
        ),
    }
}

fn handshake_payload(h: &crate::state::Handshake) -> Value {
    let parties = json!([
        {"Id": h.source_account_id, "Type": "ACCOUNT"},
        {"Id": h.target_account_id, "Type": h.target_kind},
    ]);
    let resources = json!([
        {"Type": "ORGANIZATION", "Value": h.organization_id},
        {"Type": "ACCOUNT", "Value": h.target_account_id},
    ]);
    let mut obj = json!({
        "Id": h.id,
        "Arn": h.arn,
        "Action": h.action,
        "State": h.state,
        "RequestedTimestamp": h.requested_timestamp.timestamp() as f64,
        "ExpirationTimestamp": h.expiration_timestamp.timestamp() as f64,
        "Parties": parties,
        "Resources": resources,
    });
    if let Some(notes) = &h.notes {
        obj["Notes"] = json!(notes);
    }
    obj
}

fn create_account_status_payload(status: &crate::state::CreateAccountStatus) -> Value {
    let mut obj = json!({
        "Id": status.id,
        "AccountName": status.account_name,
        "State": status.state,
        "RequestedTimestamp": status.requested_timestamp.timestamp() as f64,
    });
    if let Some(account_id) = &status.account_id {
        obj["AccountId"] = json!(account_id);
    }
    if let Some(ts) = status.completed_timestamp {
        obj["CompletedTimestamp"] = json!(ts.timestamp() as f64);
    }
    if let Some(reason) = &status.failure_reason {
        obj["FailureReason"] = json!(reason);
    }
    if let Some(gov_id) = &status.gov_cloud_account_id {
        obj["GovCloudAccountId"] = json!(gov_id);
    }
    obj
}

fn organization_payload(org: &OrganizationState) -> Value {
    json!({
        "Id": org.org_id,
        "Arn": org.org_arn,
        "FeatureSet": org.feature_set,
        "MasterAccountArn": org.management_account_arn,
        "MasterAccountId": org.management_account_id,
        "MasterAccountEmail": org.management_account_email,
        "AvailablePolicyTypes": [
            {"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}
        ],
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, Method};
    use std::collections::HashMap;

    fn req_with(account: &str, action: &str, body: Value) -> AwsRequest {
        AwsRequest {
            service: "organizations".to_string(),
            action: action.to_string(),
            region: "us-east-1".to_string(),
            account_id: account.to_string(),
            request_id: "test".to_string(),
            headers: HeaderMap::new(),
            query_params: HashMap::new(),
            body: Bytes::from(serde_json::to_vec(&body).unwrap()),
            body_stream: parking_lot::Mutex::new(None),
            path_segments: vec![],
            raw_path: String::new(),
            raw_query: String::new(),
            method: Method::POST,
            is_query_protocol: false,
            access_key_id: None,
            principal: None,
        }
    }

    fn body_json(resp: &AwsResponse) -> Value {
        serde_json::from_slice(resp.body.expect_bytes()).unwrap()
    }

    fn expect_err(r: Result<AwsResponse, AwsServiceError>) -> AwsServiceError {
        match r {
            Ok(_) => panic!("expected error"),
            Err(e) => e,
        }
    }

    #[tokio::test]
    async fn create_organization_succeeds_once() {
        let (svc, state) = OrganizationsService::shared();
        let resp = svc
            .handle(req_with("111111111111", "CreateOrganization", json!({})))
            .await
            .unwrap();
        assert_eq!(resp.status, StatusCode::OK);
        let v = body_json(&resp);
        assert_eq!(v["Organization"]["MasterAccountId"], "111111111111");
        assert!(state.read().is_some());
    }

    #[tokio::test]
    async fn create_organization_twice_errors() {
        let (svc, _state) = OrganizationsService::shared();
        svc.handle(req_with("111111111111", "CreateOrganization", json!({})))
            .await
            .unwrap();
        let err = expect_err(
            svc.handle(req_with("222222222222", "CreateOrganization", json!({})))
                .await,
        );
        assert_eq!(err.code(), "AlreadyInOrganizationException");
    }

    #[tokio::test]
    async fn describe_without_org_errors() {
        let (svc, _state) = OrganizationsService::shared();
        let err = expect_err(
            svc.handle(req_with("111111111111", "DescribeOrganization", json!({})))
                .await,
        );
        assert_eq!(err.code(), "AWSOrganizationsNotInUseException");
    }

    #[tokio::test]
    async fn describe_round_trips_create() {
        let (svc, _state) = OrganizationsService::shared();
        svc.handle(req_with("111111111111", "CreateOrganization", json!({})))
            .await
            .unwrap();
        let resp = svc
            .handle(req_with("111111111111", "DescribeOrganization", json!({})))
            .await
            .unwrap();
        let v = body_json(&resp);
        assert_eq!(v["Organization"]["MasterAccountId"], "111111111111");
        assert_eq!(v["Organization"]["FeatureSet"], "ALL");
    }

    #[tokio::test]
    async fn non_member_describe_returns_not_in_use() {
        let (svc, _state) = OrganizationsService::shared();
        svc.handle(req_with("111111111111", "CreateOrganization", json!({})))
            .await
            .unwrap();
        let err = expect_err(
            svc.handle(req_with("222222222222", "DescribeOrganization", json!({})))
                .await,
        );
        assert_eq!(err.code(), "AWSOrganizationsNotInUseException");
    }

    #[tokio::test]
    async fn non_member_delete_returns_not_in_use() {
        let (svc, _state) = OrganizationsService::shared();
        svc.handle(req_with("111111111111", "CreateOrganization", json!({})))
            .await
            .unwrap();
        let err = expect_err(
            svc.handle(req_with("222222222222", "DeleteOrganization", json!({})))
                .await,
        );
        assert_eq!(err.code(), "AWSOrganizationsNotInUseException");
    }

    #[tokio::test]
    async fn member_non_management_delete_returns_access_denied() {
        let (svc, state) = OrganizationsService::shared();
        svc.handle(req_with("111111111111", "CreateOrganization", json!({})))
            .await
            .unwrap();
        // Simulate Batch 2 membership by enrolling a second account
        // directly in state (auto-enrollment lands in Batch 2).
        {
            let mut guard = state.write();
            let org = guard.as_mut().unwrap();
            let account_id = "222222222222".to_string();
            let parent_id = org.root_id.clone();
            let org_id = org.org_id.clone();
            let arn = format!(
                "arn:aws:organizations::111111111111:account/{}/{}",
                org_id, &account_id
            );
            org.accounts.insert(
                account_id.clone(),
                crate::state::MemberAccount {
                    id: account_id.clone(),
                    arn,
                    email: "member@example.com".to_string(),
                    name: "member".to_string(),
                    status: "ACTIVE".to_string(),
                    joined_method: "INVITED".to_string(),
                    joined_timestamp: chrono::Utc::now(),
                    parent_id,
                },
            );
        }
        let err = expect_err(
            svc.handle(req_with("222222222222", "DeleteOrganization", json!({})))
                .await,
        );
        assert_eq!(err.code(), "AccessDeniedException");
    }

    #[tokio::test]
    async fn delete_clears_state() {
        let (svc, state) = OrganizationsService::shared();
        svc.handle(req_with("111111111111", "CreateOrganization", json!({})))
            .await
            .unwrap();
        svc.handle(req_with("111111111111", "DeleteOrganization", json!({})))
            .await
            .unwrap();
        assert!(state.read().is_none());
    }

    #[tokio::test]
    async fn create_with_consolidated_billing_rejected() {
        let (svc, _state) = OrganizationsService::shared();
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "CreateOrganization",
                json!({"FeatureSet": "CONSOLIDATED_BILLING"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "UnsupportedAPIEndpointException");
    }

    /// Helper: create org with ACCOUNT_A as management, return shared
    /// state + root id for subsequent assertions.
    async fn create_org_with_root(svc: &Arc<OrganizationsService>) -> String {
        svc.handle(req_with("111111111111", "CreateOrganization", json!({})))
            .await
            .unwrap();
        let roots = svc
            .handle(req_with("111111111111", "ListRoots", json!({})))
            .await
            .unwrap();
        let v = body_json(&roots);
        v["Roots"][0]["Id"].as_str().unwrap().to_string()
    }

    #[tokio::test]
    async fn list_roots_returns_single_root() {
        let (svc, _state) = OrganizationsService::shared();
        let root_id = create_org_with_root(&svc).await;
        assert!(root_id.starts_with("r-"));
    }

    #[tokio::test]
    async fn list_roots_non_member_hidden() {
        let (svc, _state) = OrganizationsService::shared();
        svc.handle(req_with("111111111111", "CreateOrganization", json!({})))
            .await
            .unwrap();
        let err = expect_err(
            svc.handle(req_with("999999999999", "ListRoots", json!({})))
                .await,
        );
        assert_eq!(err.code(), "AWSOrganizationsNotInUseException");
    }

    #[tokio::test]
    async fn create_ou_happy_path_and_describe() {
        let (svc, _state) = OrganizationsService::shared();
        let root_id = create_org_with_root(&svc).await;
        let created = svc
            .handle(req_with(
                "111111111111",
                "CreateOrganizationalUnit",
                json!({"ParentId": root_id, "Name": "eng"}),
            ))
            .await
            .unwrap();
        let ou = body_json(&created);
        let ou_id = ou["OrganizationalUnit"]["Id"].as_str().unwrap().to_string();
        assert!(ou_id.starts_with("ou-"));

        let described = svc
            .handle(req_with(
                "111111111111",
                "DescribeOrganizationalUnit",
                json!({"OrganizationalUnitId": ou_id}),
            ))
            .await
            .unwrap();
        let v = body_json(&described);
        assert_eq!(v["OrganizationalUnit"]["Name"], "eng");
    }

    #[tokio::test]
    async fn create_ou_missing_parent_id_rejected() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "CreateOrganizationalUnit",
                json!({"Name": "eng"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "InvalidInputException");
    }

    #[tokio::test]
    async fn create_ou_duplicate_under_same_parent() {
        let (svc, _state) = OrganizationsService::shared();
        let root_id = create_org_with_root(&svc).await;
        svc.handle(req_with(
            "111111111111",
            "CreateOrganizationalUnit",
            json!({"ParentId": root_id, "Name": "eng"}),
        ))
        .await
        .unwrap();
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "CreateOrganizationalUnit",
                json!({"ParentId": root_id, "Name": "eng"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "DuplicateOrganizationalUnitException");
    }

    #[tokio::test]
    async fn create_ou_unknown_parent_rejected() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "CreateOrganizationalUnit",
                json!({"ParentId": "ou-bogus", "Name": "eng"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "ParentNotFoundException");
    }

    #[tokio::test]
    async fn create_ou_non_management_rejected() {
        let (svc, state) = OrganizationsService::shared();
        let root_id = create_org_with_root(&svc).await;
        // Enroll a non-management member directly.
        {
            let mut guard = state.write();
            guard
                .as_mut()
                .unwrap()
                .enroll_account_if_missing("222222222222");
        }
        let err = expect_err(
            svc.handle(req_with(
                "222222222222",
                "CreateOrganizationalUnit",
                json!({"ParentId": root_id, "Name": "eng"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "AccessDeniedException");
    }

    #[tokio::test]
    async fn create_ou_without_org_not_in_use() {
        let (svc, _state) = OrganizationsService::shared();
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "CreateOrganizationalUnit",
                json!({"ParentId": "r-whatever", "Name": "eng"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "AWSOrganizationsNotInUseException");
    }

    #[tokio::test]
    async fn update_ou_renames_and_rejects_dup() {
        let (svc, _state) = OrganizationsService::shared();
        let root_id = create_org_with_root(&svc).await;
        let created = svc
            .handle(req_with(
                "111111111111",
                "CreateOrganizationalUnit",
                json!({"ParentId": root_id, "Name": "eng"}),
            ))
            .await
            .unwrap();
        let ou_id = body_json(&created)["OrganizationalUnit"]["Id"]
            .as_str()
            .unwrap()
            .to_string();
        svc.handle(req_with(
            "111111111111",
            "CreateOrganizationalUnit",
            json!({"ParentId": root_id, "Name": "ops"}),
        ))
        .await
        .unwrap();

        let renamed = svc
            .handle(req_with(
                "111111111111",
                "UpdateOrganizationalUnit",
                json!({"OrganizationalUnitId": ou_id, "Name": "platform"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            body_json(&renamed)["OrganizationalUnit"]["Name"],
            "platform"
        );

        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "UpdateOrganizationalUnit",
                json!({"OrganizationalUnitId": ou_id, "Name": "ops"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "DuplicateOrganizationalUnitException");
    }

    #[tokio::test]
    async fn update_ou_unknown_id_rejected() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "UpdateOrganizationalUnit",
                json!({"OrganizationalUnitId": "ou-unknown", "Name": "x"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "OrganizationalUnitNotFoundException");
    }

    #[tokio::test]
    async fn delete_ou_rejects_when_not_empty() {
        let (svc, state) = OrganizationsService::shared();
        let root_id = create_org_with_root(&svc).await;
        let created = svc
            .handle(req_with(
                "111111111111",
                "CreateOrganizationalUnit",
                json!({"ParentId": root_id, "Name": "eng"}),
            ))
            .await
            .unwrap();
        let ou_id = body_json(&created)["OrganizationalUnit"]["Id"]
            .as_str()
            .unwrap()
            .to_string();
        {
            let mut guard = state.write();
            let org = guard.as_mut().unwrap();
            org.enroll_account_if_missing("222222222222");
            let root = org.root_id.clone();
            org.move_account("222222222222", &root, &ou_id).unwrap();
        }
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "DeleteOrganizationalUnit",
                json!({"OrganizationalUnitId": ou_id}),
            ))
            .await,
        );
        assert_eq!(err.code(), "OrganizationalUnitNotEmptyException");
    }

    #[tokio::test]
    async fn delete_ou_unknown_rejected() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "DeleteOrganizationalUnit",
                json!({"OrganizationalUnitId": "ou-unknown"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "OrganizationalUnitNotFoundException");
    }

    #[tokio::test]
    async fn describe_ou_unknown_rejected() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "DescribeOrganizationalUnit",
                json!({"OrganizationalUnitId": "ou-unknown"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "OrganizationalUnitNotFoundException");
    }

    #[tokio::test]
    async fn list_ous_for_parent_filters_by_parent() {
        let (svc, _state) = OrganizationsService::shared();
        let root_id = create_org_with_root(&svc).await;
        let created = svc
            .handle(req_with(
                "111111111111",
                "CreateOrganizationalUnit",
                json!({"ParentId": root_id, "Name": "top"}),
            ))
            .await
            .unwrap();
        let top_id = body_json(&created)["OrganizationalUnit"]["Id"]
            .as_str()
            .unwrap()
            .to_string();
        svc.handle(req_with(
            "111111111111",
            "CreateOrganizationalUnit",
            json!({"ParentId": top_id, "Name": "child"}),
        ))
        .await
        .unwrap();

        let under_root = svc
            .handle(req_with(
                "111111111111",
                "ListOrganizationalUnitsForParent",
                json!({"ParentId": root_id}),
            ))
            .await
            .unwrap();
        let v = body_json(&under_root);
        assert_eq!(v["OrganizationalUnits"].as_array().unwrap().len(), 1);
        assert_eq!(v["OrganizationalUnits"][0]["Id"], top_id);

        let under_top = svc
            .handle(req_with(
                "111111111111",
                "ListOrganizationalUnitsForParent",
                json!({"ParentId": top_id}),
            ))
            .await
            .unwrap();
        let v = body_json(&under_top);
        assert_eq!(v["OrganizationalUnits"].as_array().unwrap().len(), 1);
        assert_eq!(v["OrganizationalUnits"][0]["Name"], "child");
    }

    #[tokio::test]
    async fn list_ous_for_parent_unknown_parent() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "ListOrganizationalUnitsForParent",
                json!({"ParentId": "ou-unknown"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "ParentNotFoundException");
    }

    #[tokio::test]
    async fn list_accounts_returns_all_members() {
        let (svc, state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        {
            let mut guard = state.write();
            guard
                .as_mut()
                .unwrap()
                .enroll_account_if_missing("222222222222");
        }
        let resp = svc
            .handle(req_with("111111111111", "ListAccounts", json!({})))
            .await
            .unwrap();
        let v = body_json(&resp);
        assert_eq!(v["Accounts"].as_array().unwrap().len(), 2);
    }

    #[tokio::test]
    async fn list_accounts_for_parent_scopes_to_parent() {
        let (svc, state) = OrganizationsService::shared();
        let root_id = create_org_with_root(&svc).await;
        let created = svc
            .handle(req_with(
                "111111111111",
                "CreateOrganizationalUnit",
                json!({"ParentId": root_id, "Name": "team"}),
            ))
            .await
            .unwrap();
        let ou_id = body_json(&created)["OrganizationalUnit"]["Id"]
            .as_str()
            .unwrap()
            .to_string();
        {
            let mut guard = state.write();
            let org = guard.as_mut().unwrap();
            org.enroll_account_if_missing("222222222222");
            org.move_account("222222222222", &org.root_id.clone(), &ou_id)
                .unwrap();
        }
        let in_ou = svc
            .handle(req_with(
                "111111111111",
                "ListAccountsForParent",
                json!({"ParentId": ou_id}),
            ))
            .await
            .unwrap();
        let v = body_json(&in_ou);
        assert_eq!(v["Accounts"].as_array().unwrap().len(), 1);
        assert_eq!(v["Accounts"][0]["Id"], "222222222222");
    }

    #[tokio::test]
    async fn list_accounts_for_parent_unknown_rejected() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "ListAccountsForParent",
                json!({"ParentId": "ou-unknown"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "ParentNotFoundException");
    }

    #[tokio::test]
    async fn describe_account_roundtrip_and_unknown() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let resp = svc
            .handle(req_with(
                "111111111111",
                "DescribeAccount",
                json!({"AccountId": "111111111111"}),
            ))
            .await
            .unwrap();
        assert_eq!(body_json(&resp)["Account"]["Id"], "111111111111");

        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "DescribeAccount",
                json!({"AccountId": "999999999999"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "AccountNotFoundException");
    }

    #[tokio::test]
    async fn move_account_happy_path() {
        let (svc, state) = OrganizationsService::shared();
        let root_id = create_org_with_root(&svc).await;
        let created = svc
            .handle(req_with(
                "111111111111",
                "CreateOrganizationalUnit",
                json!({"ParentId": root_id, "Name": "team"}),
            ))
            .await
            .unwrap();
        let ou_id = body_json(&created)["OrganizationalUnit"]["Id"]
            .as_str()
            .unwrap()
            .to_string();
        {
            let mut guard = state.write();
            guard
                .as_mut()
                .unwrap()
                .enroll_account_if_missing("222222222222");
        }
        svc.handle(req_with(
            "111111111111",
            "MoveAccount",
            json!({
                "AccountId": "222222222222",
                "SourceParentId": root_id,
                "DestinationParentId": ou_id,
            }),
        ))
        .await
        .unwrap();
        let guard = state.read();
        let org = guard.as_ref().unwrap();
        assert_eq!(org.accounts.get("222222222222").unwrap().parent_id, ou_id);
    }

    #[tokio::test]
    async fn move_account_unknown_account() {
        let (svc, _state) = OrganizationsService::shared();
        let root_id = create_org_with_root(&svc).await;
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "MoveAccount",
                json!({
                    "AccountId": "777777777777",
                    "SourceParentId": root_id,
                    "DestinationParentId": root_id,
                }),
            ))
            .await,
        );
        assert_eq!(err.code(), "AccountNotFoundException");
    }

    #[tokio::test]
    async fn move_account_wrong_source_parent() {
        let (svc, state) = OrganizationsService::shared();
        let root_id = create_org_with_root(&svc).await;
        let created = svc
            .handle(req_with(
                "111111111111",
                "CreateOrganizationalUnit",
                json!({"ParentId": root_id, "Name": "team"}),
            ))
            .await
            .unwrap();
        let ou_id = body_json(&created)["OrganizationalUnit"]["Id"]
            .as_str()
            .unwrap()
            .to_string();
        {
            let mut guard = state.write();
            guard
                .as_mut()
                .unwrap()
                .enroll_account_if_missing("222222222222");
        }
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "MoveAccount",
                json!({
                    "AccountId": "222222222222",
                    "SourceParentId": ou_id,
                    "DestinationParentId": root_id,
                }),
            ))
            .await,
        );
        assert_eq!(err.code(), "SourceParentNotFoundException");
    }

    #[tokio::test]
    async fn move_account_unknown_destination() {
        let (svc, _state) = OrganizationsService::shared();
        let root_id = create_org_with_root(&svc).await;
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "MoveAccount",
                json!({
                    "AccountId": "111111111111",
                    "SourceParentId": root_id,
                    "DestinationParentId": "ou-bogus",
                }),
            ))
            .await,
        );
        assert_eq!(err.code(), "DestinationParentNotFoundException");
    }

    #[tokio::test]
    async fn unknown_action_returns_not_implemented() {
        let (svc, _state) = OrganizationsService::shared();
        let err = expect_err(
            svc.handle(req_with("111111111111", "BogusAction", json!({})))
                .await,
        );
        // ActionNotImplemented carries NOT_IMPLEMENTED status.
        assert_eq!(err.status(), StatusCode::NOT_IMPLEMENTED);
    }

    const SCP_ALLOW_ALL: &str =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;

    async fn create_scp(svc: &Arc<OrganizationsService>, name: &str) -> String {
        let resp = svc
            .handle(req_with(
                "111111111111",
                "CreatePolicy",
                json!({
                    "Name": name,
                    "Description": "",
                    "Type": "SERVICE_CONTROL_POLICY",
                    "Content": SCP_ALLOW_ALL,
                }),
            ))
            .await
            .unwrap();
        body_json(&resp)["Policy"]["PolicySummary"]["Id"]
            .as_str()
            .unwrap()
            .to_string()
    }

    #[tokio::test]
    async fn create_policy_happy_path() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let id = create_scp(&svc, "Custom").await;
        assert!(id.starts_with("p-"));
    }

    #[tokio::test]
    async fn create_policy_rejects_unrecognized_type() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "CreatePolicy",
                json!({
                    "Name": "T",
                    "Description": "",
                    "Type": "NONSENSE_POLICY",
                    "Content": SCP_ALLOW_ALL,
                }),
            ))
            .await,
        );
        assert_eq!(err.code(), "PolicyTypeNotSupportedException");
    }

    #[tokio::test]
    async fn create_policy_accepts_tag_policy_type() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let resp = svc
            .handle(req_with(
                "111111111111",
                "CreatePolicy",
                json!({
                    "Name": "MyTags",
                    "Description": "",
                    "Type": "TAG_POLICY",
                    "Content": SCP_ALLOW_ALL,
                }),
            ))
            .await
            .unwrap();
        let v = body_json(&resp);
        assert_eq!(v["Policy"]["PolicySummary"]["Type"], "TAG_POLICY");
        assert!(v["Policy"]["PolicySummary"]["Arn"]
            .as_str()
            .unwrap()
            .contains("/tag_policy/"));
    }

    #[tokio::test]
    async fn create_policy_malformed_content_rejected() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "CreatePolicy",
                json!({
                    "Name": "X",
                    "Description": "",
                    "Type": "SERVICE_CONTROL_POLICY",
                    "Content": "not json",
                }),
            ))
            .await,
        );
        assert_eq!(err.code(), "MalformedPolicyDocumentException");
    }

    #[tokio::test]
    async fn create_policy_missing_required_fields() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "CreatePolicy",
                json!({"Name": "X", "Type": "SERVICE_CONTROL_POLICY"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "InvalidInputException");
    }

    #[tokio::test]
    async fn create_policy_non_management_rejected() {
        let (svc, state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        {
            let mut guard = state.write();
            guard
                .as_mut()
                .unwrap()
                .enroll_account_if_missing("222222222222");
        }
        let err = expect_err(
            svc.handle(req_with(
                "222222222222",
                "CreatePolicy",
                json!({
                    "Name": "X",
                    "Description": "",
                    "Type": "SERVICE_CONTROL_POLICY",
                    "Content": SCP_ALLOW_ALL,
                }),
            ))
            .await,
        );
        assert_eq!(err.code(), "AccessDeniedException");
    }

    #[tokio::test]
    async fn update_policy_roundtrip_and_blocks_aws_managed() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let id = create_scp(&svc, "Original").await;
        let renamed = svc
            .handle(req_with(
                "111111111111",
                "UpdatePolicy",
                json!({"PolicyId": id, "Name": "Renamed"}),
            ))
            .await
            .unwrap();
        assert_eq!(
            body_json(&renamed)["Policy"]["PolicySummary"]["Name"],
            "Renamed"
        );
        // FullAWSAccess is AWS-managed -> blocked.
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "UpdatePolicy",
                json!({"PolicyId": "p-FullAWSAccess", "Name": "Hacked"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "PolicyChangesNotAllowedException");
    }

    #[tokio::test]
    async fn delete_policy_blocked_when_attached_and_aws_managed() {
        let (svc, _state) = OrganizationsService::shared();
        let root_id = create_org_with_root(&svc).await;
        let id = create_scp(&svc, "InUse").await;
        svc.handle(req_with(
            "111111111111",
            "AttachPolicy",
            json!({"PolicyId": id, "TargetId": root_id}),
        ))
        .await
        .unwrap();
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "DeletePolicy",
                json!({"PolicyId": id}),
            ))
            .await,
        );
        assert_eq!(err.code(), "PolicyInUseException");
        // AWS-managed cannot be deleted either.
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "DeletePolicy",
                json!({"PolicyId": "p-FullAWSAccess"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "PolicyChangesNotAllowedException");
    }

    #[tokio::test]
    async fn describe_policy_unknown_and_known() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let id = create_scp(&svc, "X").await;
        let ok = svc
            .handle(req_with(
                "111111111111",
                "DescribePolicy",
                json!({"PolicyId": id}),
            ))
            .await
            .unwrap();
        assert_eq!(body_json(&ok)["Policy"]["PolicySummary"]["Id"], id);
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "DescribePolicy",
                json!({"PolicyId": "p-none"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "PolicyNotFoundException");
    }

    #[tokio::test]
    async fn list_policies_rejects_unrecognized_filter() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "ListPolicies",
                json!({"Filter": "NONSENSE_POLICY"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "PolicyTypeNotSupportedException");
    }

    #[tokio::test]
    async fn list_policies_includes_full_aws_access() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let resp = svc
            .handle(req_with(
                "111111111111",
                "ListPolicies",
                json!({"Filter": "SERVICE_CONTROL_POLICY"}),
            ))
            .await
            .unwrap();
        let v = body_json(&resp);
        assert!(v["Policies"]
            .as_array()
            .unwrap()
            .iter()
            .any(|p| p["Id"] == "p-FullAWSAccess"));
    }

    #[tokio::test]
    async fn attach_detach_lifecycle_and_errors() {
        let (svc, _state) = OrganizationsService::shared();
        let root_id = create_org_with_root(&svc).await;
        let id = create_scp(&svc, "X").await;

        // Attach then detach.
        svc.handle(req_with(
            "111111111111",
            "AttachPolicy",
            json!({"PolicyId": id, "TargetId": root_id}),
        ))
        .await
        .unwrap();
        // Re-attach is idempotent.
        svc.handle(req_with(
            "111111111111",
            "AttachPolicy",
            json!({"PolicyId": id, "TargetId": root_id}),
        ))
        .await
        .unwrap();

        // Unknown target.
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "AttachPolicy",
                json!({"PolicyId": id, "TargetId": "ou-bogus"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "TargetNotFoundException");

        // Unknown policy.
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "AttachPolicy",
                json!({"PolicyId": "p-none", "TargetId": root_id}),
            ))
            .await,
        );
        assert_eq!(err.code(), "PolicyNotFoundException");

        // Detach unattached policy.
        let id2 = create_scp(&svc, "Y").await;
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "DetachPolicy",
                json!({"PolicyId": id2, "TargetId": root_id}),
            ))
            .await,
        );
        assert_eq!(err.code(), "PolicyNotAttachedException");

        // Happy-path detach of the first policy.
        svc.handle(req_with(
            "111111111111",
            "DetachPolicy",
            json!({"PolicyId": id, "TargetId": root_id}),
        ))
        .await
        .unwrap();
    }

    #[tokio::test]
    async fn list_policies_for_target_and_targets_for_policy() {
        let (svc, _state) = OrganizationsService::shared();
        let root_id = create_org_with_root(&svc).await;
        let id = create_scp(&svc, "Custom").await;
        svc.handle(req_with(
            "111111111111",
            "AttachPolicy",
            json!({"PolicyId": id, "TargetId": root_id}),
        ))
        .await
        .unwrap();

        let list = svc
            .handle(req_with(
                "111111111111",
                "ListPoliciesForTarget",
                json!({"TargetId": root_id, "Filter": "SERVICE_CONTROL_POLICY"}),
            ))
            .await
            .unwrap();
        let v = body_json(&list);
        let names: Vec<_> = v["Policies"]
            .as_array()
            .unwrap()
            .iter()
            .map(|p| p["Name"].as_str().unwrap().to_string())
            .collect();
        assert!(names.contains(&"Custom".to_string()));
        assert!(names.contains(&"FullAWSAccess".to_string()));

        let targets = svc
            .handle(req_with(
                "111111111111",
                "ListTargetsForPolicy",
                json!({"PolicyId": id}),
            ))
            .await
            .unwrap();
        let v = body_json(&targets);
        assert_eq!(v["Targets"].as_array().unwrap().len(), 1);
        assert_eq!(v["Targets"][0]["TargetId"], root_id);
        assert_eq!(v["Targets"][0]["Type"], "ROOT");
    }

    #[tokio::test]
    async fn list_policies_for_target_rejects_bad_filter() {
        let (svc, _state) = OrganizationsService::shared();
        let root_id = create_org_with_root(&svc).await;
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "ListPoliciesForTarget",
                json!({"TargetId": root_id, "Filter": "NONSENSE_POLICY"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "PolicyTypeNotSupportedException");
    }

    #[tokio::test]
    async fn list_targets_for_unknown_policy() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "ListTargetsForPolicy",
                json!({"PolicyId": "p-none"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "PolicyNotFoundException");
    }

    // ── account lifecycle (CreateAccount, Describe/ListCreateAccountStatus,
    //    CloseAccount, RemoveAccountFromOrganization) ─────────────────────

    fn body_value(resp: AwsResponse) -> Value {
        serde_json::from_slice(resp.body.expect_bytes()).unwrap()
    }

    /// Poll `DescribeCreateAccountStatus` until the request reaches a
    /// terminal state, with a timeout. Mirrors how SDK callers observe
    /// the async `CreateAccount` lifecycle in fakecloud.
    async fn poll_until_terminal(svc: &Arc<OrganizationsService>, request_id: &str) -> Value {
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let resp = svc
                .handle(req_with(
                    "111111111111",
                    "DescribeCreateAccountStatus",
                    json!({"CreateAccountRequestId": request_id}),
                ))
                .await
                .unwrap();
            let body = body_value(resp);
            let state = body["CreateAccountStatus"]["State"]
                .as_str()
                .unwrap()
                .to_string();
            if state == "SUCCEEDED" || state == "FAILED" {
                return body;
            }
            if std::time::Instant::now() >= deadline {
                panic!("CreateAccount {request_id} did not terminate before deadline");
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    #[tokio::test]
    async fn create_account_starts_in_progress_then_describes_succeeded() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let resp = svc
            .handle(req_with(
                "111111111111",
                "CreateAccount",
                json!({"Email": "new@example.com", "AccountName": "New"}),
            ))
            .await
            .unwrap();
        let body = body_value(resp);
        let status = &body["CreateAccountStatus"];
        let request_id = status["Id"].as_str().unwrap().to_string();
        assert_eq!(status["State"].as_str().unwrap(), "IN_PROGRESS");
        assert_eq!(status["AccountName"].as_str().unwrap(), "New");
        let new_account_id = status["AccountId"].as_str().unwrap().to_string();
        assert_eq!(new_account_id.len(), 12);

        let body = poll_until_terminal(&svc, &request_id).await;
        assert_eq!(
            body["CreateAccountStatus"]["State"].as_str().unwrap(),
            "SUCCEEDED"
        );
        assert!(body["CreateAccountStatus"]["CompletedTimestamp"].is_number());
        assert_eq!(
            body["CreateAccountStatus"]["AccountId"].as_str().unwrap(),
            new_account_id
        );
    }

    #[tokio::test]
    async fn create_account_only_management_account_can_call() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        // Enroll a non-management account first and wait for it to succeed.
        let resp = svc
            .handle(req_with(
                "111111111111",
                "CreateAccount",
                json!({"Email": "non-mgmt@example.com", "AccountName": "NonMgmt"}),
            ))
            .await
            .unwrap();
        let request_id = body_value(resp)["CreateAccountStatus"]["Id"]
            .as_str()
            .unwrap()
            .to_string();
        let body = poll_until_terminal(&svc, &request_id).await;
        let new_id = body["CreateAccountStatus"]["AccountId"]
            .as_str()
            .unwrap()
            .to_string();
        let err = expect_err(
            svc.handle(req_with(
                &new_id,
                "CreateAccount",
                json!({"Email": "x@example.com", "AccountName": "X"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "AccessDeniedException");
    }

    #[tokio::test]
    async fn list_create_account_status_filters_by_state() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let resp = svc
            .handle(req_with(
                "111111111111",
                "CreateAccount",
                json!({"Email": "a@example.com", "AccountName": "A"}),
            ))
            .await
            .unwrap();
        let request_id = body_value(resp)["CreateAccountStatus"]["Id"]
            .as_str()
            .unwrap()
            .to_string();
        // Filter for IN_PROGRESS first — should include the new request.
        let resp = svc
            .handle(req_with(
                "111111111111",
                "ListCreateAccountStatus",
                json!({"States": ["IN_PROGRESS"]}),
            ))
            .await
            .unwrap();
        let listed = body_value(resp);
        let arr = listed["CreateAccountStatuses"].as_array().unwrap();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["Id"].as_str().unwrap(), request_id);

        // Wait for the spawned completion task to flip the status, then
        // re-filter for IN_PROGRESS — the new request should drop out.
        poll_until_terminal(&svc, &request_id).await;
        let resp = svc
            .handle(req_with(
                "111111111111",
                "ListCreateAccountStatus",
                json!({"States": ["IN_PROGRESS"]}),
            ))
            .await
            .unwrap();
        assert!(body_value(resp)["CreateAccountStatuses"]
            .as_array()
            .unwrap()
            .is_empty());
        // SUCCEEDED filter should now contain it.
        let resp = svc
            .handle(req_with(
                "111111111111",
                "ListCreateAccountStatus",
                json!({"States": ["SUCCEEDED"]}),
            ))
            .await
            .unwrap();
        let arr = body_value(resp)["CreateAccountStatuses"]
            .as_array()
            .unwrap()
            .clone();
        assert_eq!(arr.len(), 1);
        assert_eq!(arr[0]["Id"].as_str().unwrap(), request_id);
    }

    #[tokio::test]
    async fn list_create_account_status_paginates_with_max_results() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        // Fire three CreateAccount requests so we have something to page over.
        let mut request_ids = Vec::new();
        for i in 0..3 {
            let resp = svc
                .handle(req_with(
                    "111111111111",
                    "CreateAccount",
                    json!({"Email": format!("p{i}@example.com"), "AccountName": format!("P{i}")}),
                ))
                .await
                .unwrap();
            request_ids.push(
                body_value(resp)["CreateAccountStatus"]["Id"]
                    .as_str()
                    .unwrap()
                    .to_string(),
            );
        }
        // First page: MaxResults=2 -> 2 entries + NextToken.
        let resp = svc
            .handle(req_with(
                "111111111111",
                "ListCreateAccountStatus",
                json!({"MaxResults": 2}),
            ))
            .await
            .unwrap();
        let body = body_value(resp);
        assert_eq!(body["CreateAccountStatuses"].as_array().unwrap().len(), 2);
        let next = body["NextToken"].as_str().unwrap().to_string();

        // Second page: same MaxResults + the token returns the remaining one
        // and no further token.
        let resp = svc
            .handle(req_with(
                "111111111111",
                "ListCreateAccountStatus",
                json!({"MaxResults": 2, "NextToken": next}),
            ))
            .await
            .unwrap();
        let body = body_value(resp);
        assert_eq!(body["CreateAccountStatuses"].as_array().unwrap().len(), 1);
        assert!(body.get("NextToken").is_none());
    }

    #[tokio::test]
    async fn close_account_marks_suspended_and_management_is_protected() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let new_resp = svc
            .handle(req_with(
                "111111111111",
                "CreateAccount",
                json!({"Email": "a@example.com", "AccountName": "A"}),
            ))
            .await
            .unwrap();
        let request_id = body_value(new_resp)["CreateAccountStatus"]["Id"]
            .as_str()
            .unwrap()
            .to_string();
        let body = poll_until_terminal(&svc, &request_id).await;
        let new_id = body["CreateAccountStatus"]["AccountId"]
            .as_str()
            .unwrap()
            .to_string();
        svc.handle(req_with(
            "111111111111",
            "CloseAccount",
            json!({"AccountId": new_id}),
        ))
        .await
        .unwrap();
        // Status should be SUSPENDED via DescribeAccount.
        let resp = svc
            .handle(req_with(
                "111111111111",
                "DescribeAccount",
                json!({"AccountId": new_id}),
            ))
            .await
            .unwrap();
        assert_eq!(
            body_value(resp)["Account"]["Status"].as_str().unwrap(),
            "SUSPENDED"
        );

        // Management account cannot be closed.
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "CloseAccount",
                json!({"AccountId": "111111111111"}),
            ))
            .await,
        );
        assert_eq!(err.code(), "ConstraintViolationException");
    }

    #[tokio::test]
    async fn remove_account_from_organization_drops_member() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let new_resp = svc
            .handle(req_with(
                "111111111111",
                "CreateAccount",
                json!({"Email": "a@example.com", "AccountName": "A"}),
            ))
            .await
            .unwrap();
        let request_id = body_value(new_resp)["CreateAccountStatus"]["Id"]
            .as_str()
            .unwrap()
            .to_string();
        let body = poll_until_terminal(&svc, &request_id).await;
        let new_id = body["CreateAccountStatus"]["AccountId"]
            .as_str()
            .unwrap()
            .to_string();
        svc.handle(req_with(
            "111111111111",
            "RemoveAccountFromOrganization",
            json!({"AccountId": new_id}),
        ))
        .await
        .unwrap();
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "DescribeAccount",
                json!({"AccountId": new_id}),
            ))
            .await,
        );
        assert_eq!(err.code(), "AccountNotFoundException");
    }

    #[tokio::test]
    async fn create_gov_cloud_account_returns_paired_id() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let resp = svc
            .handle(req_with(
                "111111111111",
                "CreateGovCloudAccount",
                json!({"Email": "gov@example.com", "AccountName": "Gov"}),
            ))
            .await
            .unwrap();
        let body = body_value(resp);
        let status = &body["CreateAccountStatus"];
        assert!(status["AccountId"].is_string());
        assert!(status["GovCloudAccountId"].is_string());
        assert_ne!(
            status["AccountId"].as_str().unwrap(),
            status["GovCloudAccountId"].as_str().unwrap()
        );
    }
}
