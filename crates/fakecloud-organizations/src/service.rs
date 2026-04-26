use std::sync::Arc;

use async_trait::async_trait;
use http::StatusCode;
use serde_json::{json, Value};

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};

use crate::state::{
    MemberAccount, OrgError, OrganizationState, OrganizationalUnit, Policy,
    SharedOrganizationsState, FEATURE_SET_ALL, POLICY_TYPE_SCP,
};

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
        let root = json!({
            "Id": org.root_id,
            "Arn": org.root_arn,
            "Name": org.root_name,
            "PolicyTypes": [
                {"Type": "SERVICE_CONTROL_POLICY", "Status": "ENABLED"}
            ],
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
        if filter != POLICY_TYPE_SCP {
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
        if filter != POLICY_TYPE_SCP {
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
    }
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
    async fn create_policy_rejects_non_scp_type() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "CreatePolicy",
                json!({
                    "Name": "T",
                    "Description": "",
                    "Type": "TAG_POLICY",
                    "Content": SCP_ALLOW_ALL,
                }),
            ))
            .await,
        );
        assert_eq!(err.code(), "PolicyTypeNotSupportedException");
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
    async fn list_policies_rejects_unsupported_filter() {
        let (svc, _state) = OrganizationsService::shared();
        create_org_with_root(&svc).await;
        let err = expect_err(
            svc.handle(req_with(
                "111111111111",
                "ListPolicies",
                json!({"Filter": "TAG_POLICY"}),
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
                json!({"TargetId": root_id, "Filter": "TAG_POLICY"}),
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
}
