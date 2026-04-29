use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Shared, cross-account singleton. `None` until `CreateOrganization`
/// runs; at most one organization exists per fakecloud process. An AWS
/// org is not per-account state (it spans accounts), so this is NOT
/// wrapped in `MultiAccountState`.
pub type SharedOrganizationsState = Arc<RwLock<Option<OrganizationState>>>;

pub const FEATURE_SET_ALL: &str = "ALL";
pub const FEATURE_SET_CONSOLIDATED_BILLING: &str = "CONSOLIDATED_BILLING";

pub const POLICY_TYPE_SCP: &str = "SERVICE_CONTROL_POLICY";

/// Stable ID of the AWS-managed FullAWSAccess SCP. Matches AWS's
/// documented identifier so SDK callers can reference it by name.
pub const FULL_AWS_ACCESS_POLICY_ID: &str = "p-FullAWSAccess";
pub const FULL_AWS_ACCESS_POLICY_NAME: &str = "FullAWSAccess";
pub const FULL_AWS_ACCESS_POLICY_DESCRIPTION: &str = "Allows access to every operation";
pub const FULL_AWS_ACCESS_POLICY_CONTENT: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrganizationState {
    pub org_id: String,
    pub org_arn: String,
    pub management_account_id: String,
    pub management_account_arn: String,
    pub management_account_email: String,
    pub feature_set: String,
    pub root_id: String,
    pub root_arn: String,
    pub root_name: String,
    pub created_at: DateTime<Utc>,
    pub ous: BTreeMap<String, OrganizationalUnit>,
    pub accounts: BTreeMap<String, MemberAccount>,
    pub policies: BTreeMap<String, Policy>,
    /// target_id -> attached policy ids. Targets are root id, OU id, or account id.
    pub attachments: BTreeMap<String, HashSet<String>>,
}

impl OrganizationState {
    /// Bootstrap a new organization with `management_account_id` as the
    /// management account. Creates the root OU, seeds the AWS-managed
    /// `FullAWSAccess` SCP, and auto-attaches it to root (matching AWS's
    /// default behavior).
    pub fn bootstrap(management_account_id: &str) -> Self {
        let now = Utc::now();
        let org_id = format!("o-{}", random_id(10));
        let root_id = format!("r-{}", random_id(4));
        let org_arn = format!(
            "arn:aws:organizations::{}:organization/{}",
            management_account_id, org_id
        );
        let root_arn = format!(
            "arn:aws:organizations::{}:root/{}/{}",
            management_account_id, org_id, root_id
        );
        let mgmt_arn = format!(
            "arn:aws:organizations::{}:account/{}/{}",
            management_account_id, org_id, management_account_id
        );

        let mut policies = BTreeMap::new();
        policies.insert(
            FULL_AWS_ACCESS_POLICY_ID.to_string(),
            Policy {
                id: FULL_AWS_ACCESS_POLICY_ID.to_string(),
                arn: format!(
                    "arn:aws:organizations::aws:policy/service_control_policy/{}",
                    FULL_AWS_ACCESS_POLICY_ID
                ),
                name: FULL_AWS_ACCESS_POLICY_NAME.to_string(),
                description: FULL_AWS_ACCESS_POLICY_DESCRIPTION.to_string(),
                policy_type: POLICY_TYPE_SCP.to_string(),
                aws_managed: true,
                content: FULL_AWS_ACCESS_POLICY_CONTENT.to_string(),
            },
        );

        let mut attachments: BTreeMap<String, HashSet<String>> = BTreeMap::new();
        attachments
            .entry(root_id.clone())
            .or_default()
            .insert(FULL_AWS_ACCESS_POLICY_ID.to_string());

        let mut accounts = BTreeMap::new();
        accounts.insert(
            management_account_id.to_string(),
            MemberAccount {
                id: management_account_id.to_string(),
                arn: mgmt_arn.clone(),
                email: format!("{}@example.com", management_account_id),
                name: format!("Account {}", management_account_id),
                status: "ACTIVE".to_string(),
                joined_method: "INVITED".to_string(),
                joined_timestamp: now,
                parent_id: root_id.clone(),
            },
        );

        Self {
            org_id,
            org_arn,
            management_account_id: management_account_id.to_string(),
            management_account_arn: mgmt_arn,
            management_account_email: format!("{}@example.com", management_account_id),
            feature_set: FEATURE_SET_ALL.to_string(),
            root_id,
            root_arn,
            root_name: "Root".to_string(),
            created_at: now,
            ous: BTreeMap::new(),
            accounts,
            policies,
            attachments,
        }
    }

    /// Returns `true` iff `account_id` is the management account.
    pub fn is_management(&self, account_id: &str) -> bool {
        account_id == self.management_account_id
    }

    /// Enroll `account_id` into the root OU as a member of the
    /// organization if not already known. No-op when the account is
    /// already enrolled anywhere in the tree. Used as the
    /// auto-enrollment hook when a new IAM admin bootstraps via
    /// `/_fakecloud/iam/create-admin` while an organization exists.
    pub fn enroll_account_if_missing(&mut self, account_id: &str) {
        if self.accounts.contains_key(account_id) {
            return;
        }
        let arn = format!(
            "arn:aws:organizations::{}:account/{}/{}",
            self.management_account_id, self.org_id, account_id
        );
        self.accounts.insert(
            account_id.to_string(),
            MemberAccount {
                id: account_id.to_string(),
                arn,
                email: format!("{}@example.com", account_id),
                name: format!("Account {}", account_id),
                status: "ACTIVE".to_string(),
                joined_method: "INVITED".to_string(),
                joined_timestamp: Utc::now(),
                parent_id: self.root_id.clone(),
            },
        );
    }

    /// Create a new OU under `parent_id` (which must be the root or
    /// another existing OU). Returns the created OU on success.
    ///
    /// Errors:
    /// - `ParentNotFoundException` — `parent_id` does not exist in
    ///   this org (neither root nor a known OU).
    /// - `DuplicateOrganizationalUnitException` — another OU with the
    ///   same name already lives directly under `parent_id`.
    pub fn create_ou(
        &mut self,
        parent_id: &str,
        name: &str,
    ) -> Result<OrganizationalUnit, OrgError> {
        if parent_id != self.root_id && !self.ous.contains_key(parent_id) {
            return Err(OrgError::ParentNotFound(parent_id.to_string()));
        }
        let dup = self
            .ous
            .values()
            .any(|ou| ou.parent_id == parent_id && ou.name == name);
        if dup {
            return Err(OrgError::DuplicateOrganizationalUnit(name.to_string()));
        }
        let root_suffix = self.root_id.strip_prefix("r-").unwrap_or(&self.root_id);
        let id = format!("ou-{}-{}", root_suffix, random_id(8));
        let arn = format!(
            "arn:aws:organizations::{}:ou/{}/{}",
            self.management_account_id, self.org_id, id
        );
        let ou = OrganizationalUnit {
            id: id.clone(),
            arn,
            name: name.to_string(),
            parent_id: parent_id.to_string(),
        };
        self.ous.insert(id, ou.clone());
        Ok(ou)
    }

    /// Rename an existing OU.
    pub fn rename_ou(
        &mut self,
        ou_id: &str,
        new_name: &str,
    ) -> Result<OrganizationalUnit, OrgError> {
        let parent_id = self
            .ous
            .get(ou_id)
            .ok_or_else(|| OrgError::OrganizationalUnitNotFound(ou_id.to_string()))?
            .parent_id
            .clone();
        let dup = self
            .ous
            .values()
            .any(|ou| ou.id != ou_id && ou.parent_id == parent_id && ou.name == new_name);
        if dup {
            return Err(OrgError::DuplicateOrganizationalUnit(new_name.to_string()));
        }
        let ou = self.ous.get_mut(ou_id).unwrap();
        ou.name = new_name.to_string();
        Ok(ou.clone())
    }

    /// Delete an OU. Fails with `OrganizationalUnitNotEmptyException`
    /// if the OU contains any child OUs or member accounts.
    pub fn delete_ou(&mut self, ou_id: &str) -> Result<(), OrgError> {
        if !self.ous.contains_key(ou_id) {
            return Err(OrgError::OrganizationalUnitNotFound(ou_id.to_string()));
        }
        let has_child_ou = self.ous.values().any(|ou| ou.parent_id == ou_id);
        let has_account = self.accounts.values().any(|a| a.parent_id == ou_id);
        if has_child_ou || has_account {
            return Err(OrgError::OrganizationalUnitNotEmpty(ou_id.to_string()));
        }
        // Detach all policies from the deleted target so stale pointers
        // don't survive.
        self.attachments.remove(ou_id);
        self.ous.remove(ou_id);
        Ok(())
    }

    /// Move an account between OUs.
    ///
    /// Errors:
    /// - `AccountNotFoundException`
    /// - `SourceParentNotFoundException` when `source_parent` is not
    ///   the account's current parent
    /// - `DestinationParentNotFoundException` when `dest_parent` is
    ///   not root or a known OU
    pub fn move_account(
        &mut self,
        account_id: &str,
        source_parent: &str,
        dest_parent: &str,
    ) -> Result<(), OrgError> {
        let account = self
            .accounts
            .get_mut(account_id)
            .ok_or_else(|| OrgError::AccountNotFound(account_id.to_string()))?;
        if account.parent_id != source_parent {
            return Err(OrgError::SourceParentNotFound(source_parent.to_string()));
        }
        let dest_exists = dest_parent == self.root_id || self.ous.contains_key(dest_parent);
        if !dest_exists {
            return Err(OrgError::DestinationParentNotFound(dest_parent.to_string()));
        }
        account.parent_id = dest_parent.to_string();
        Ok(())
    }

    /// Create a customer-managed SCP. Returns the created policy on
    /// success.
    ///
    /// Errors:
    /// - `PolicyTypeNotSupportedException` — `policy_type` isn't SCP.
    /// - `MalformedPolicyDocumentException` — `content` doesn't parse
    ///   as JSON.
    /// - `DuplicatePolicyException` — another SCP with the same name.
    pub fn create_policy(
        &mut self,
        name: &str,
        description: &str,
        content: &str,
        policy_type: &str,
    ) -> Result<Policy, OrgError> {
        if policy_type != POLICY_TYPE_SCP {
            return Err(OrgError::PolicyTypeNotSupported(policy_type.to_string()));
        }
        if serde_json::from_str::<serde_json::Value>(content).is_err() {
            return Err(OrgError::MalformedPolicyDocument);
        }
        let dup = self
            .policies
            .values()
            .any(|p| p.policy_type == POLICY_TYPE_SCP && p.name == name);
        if dup {
            return Err(OrgError::DuplicatePolicy(name.to_string()));
        }
        let id = format!("p-{}", random_id(8));
        let arn = format!(
            "arn:aws:organizations::{}:policy/{}/service_control_policy/{}",
            self.management_account_id, self.org_id, id
        );
        let policy = Policy {
            id: id.clone(),
            arn,
            name: name.to_string(),
            description: description.to_string(),
            policy_type: POLICY_TYPE_SCP.to_string(),
            aws_managed: false,
            content: content.to_string(),
        };
        self.policies.insert(id, policy.clone());
        Ok(policy)
    }

    /// Update an existing customer-managed SCP. Any `Option::Some`
    /// field overrides the stored value; `None` leaves it untouched.
    /// AWS-managed policies (e.g. `FullAWSAccess`) are immutable.
    pub fn update_policy(
        &mut self,
        id: &str,
        name: Option<&str>,
        description: Option<&str>,
        content: Option<&str>,
    ) -> Result<Policy, OrgError> {
        let policy = self
            .policies
            .get(id)
            .ok_or_else(|| OrgError::PolicyNotFound(id.to_string()))?;
        if policy.aws_managed {
            return Err(OrgError::PolicyChangesNotAllowed(id.to_string()));
        }
        if let Some(new_name) = name {
            let dup = self
                .policies
                .values()
                .any(|p| p.id != id && p.policy_type == POLICY_TYPE_SCP && p.name == new_name);
            if dup {
                return Err(OrgError::DuplicatePolicy(new_name.to_string()));
            }
        }
        if let Some(c) = content {
            if serde_json::from_str::<serde_json::Value>(c).is_err() {
                return Err(OrgError::MalformedPolicyDocument);
            }
        }
        let policy = self.policies.get_mut(id).unwrap();
        if let Some(n) = name {
            policy.name = n.to_string();
        }
        if let Some(d) = description {
            policy.description = d.to_string();
        }
        if let Some(c) = content {
            policy.content = c.to_string();
        }
        Ok(policy.clone())
    }

    /// Delete a customer-managed SCP. Fails with `PolicyInUseException`
    /// if the policy is still attached to any target.
    pub fn delete_policy(&mut self, id: &str) -> Result<(), OrgError> {
        let policy = self
            .policies
            .get(id)
            .ok_or_else(|| OrgError::PolicyNotFound(id.to_string()))?;
        if policy.aws_managed {
            return Err(OrgError::PolicyChangesNotAllowed(id.to_string()));
        }
        let attached = self.attachments.values().any(|set| set.contains(id));
        if attached {
            return Err(OrgError::PolicyInUse(id.to_string()));
        }
        self.policies.remove(id);
        Ok(())
    }

    /// Verify `target_id` is one of root, an OU, or a member account.
    pub fn target_exists(&self, target_id: &str) -> bool {
        target_id == self.root_id
            || self.ous.contains_key(target_id)
            || self.accounts.contains_key(target_id)
    }

    /// Type tag for target listings (`ROOT`, `ORGANIZATIONAL_UNIT`,
    /// `ACCOUNT`). Returns `None` when the target is unknown.
    pub fn target_type(&self, target_id: &str) -> Option<&'static str> {
        if target_id == self.root_id {
            Some("ROOT")
        } else if self.ous.contains_key(target_id) {
            Some("ORGANIZATIONAL_UNIT")
        } else if self.accounts.contains_key(target_id) {
            Some("ACCOUNT")
        } else {
            None
        }
    }

    /// Attach a policy to a target. No-op if already attached (AWS
    /// treats re-attach as success; matches the documented idempotent
    /// behaviour).
    pub fn attach_policy(&mut self, policy_id: &str, target_id: &str) -> Result<(), OrgError> {
        if !self.policies.contains_key(policy_id) {
            return Err(OrgError::PolicyNotFound(policy_id.to_string()));
        }
        if !self.target_exists(target_id) {
            return Err(OrgError::TargetNotFound(target_id.to_string()));
        }
        self.attachments
            .entry(target_id.to_string())
            .or_default()
            .insert(policy_id.to_string());
        Ok(())
    }

    /// Detach a policy from a target.
    ///
    /// Errors:
    /// - `PolicyNotFoundException`
    /// - `TargetNotFoundException`
    /// - `PolicyNotAttachedException` — policy is known but not
    ///   attached to `target_id`.
    pub fn detach_policy(&mut self, policy_id: &str, target_id: &str) -> Result<(), OrgError> {
        if !self.policies.contains_key(policy_id) {
            return Err(OrgError::PolicyNotFound(policy_id.to_string()));
        }
        if !self.target_exists(target_id) {
            return Err(OrgError::TargetNotFound(target_id.to_string()));
        }
        let set = self
            .attachments
            .get_mut(target_id)
            .ok_or_else(|| OrgError::PolicyNotAttached(policy_id.to_string()))?;
        if !set.remove(policy_id) {
            return Err(OrgError::PolicyNotAttached(policy_id.to_string()));
        }
        if set.is_empty() {
            self.attachments.remove(target_id);
        }
        Ok(())
    }

    /// All SCPs attached directly to `target_id` (no inheritance).
    pub fn policies_for_target(&self, target_id: &str) -> Result<Vec<&Policy>, OrgError> {
        if !self.target_exists(target_id) {
            return Err(OrgError::TargetNotFound(target_id.to_string()));
        }
        let ids = match self.attachments.get(target_id) {
            Some(s) => s,
            None => return Ok(Vec::new()),
        };
        Ok(ids.iter().filter_map(|id| self.policies.get(id)).collect())
    }

    /// All targets that carry a direct attachment of `policy_id`. Each
    /// entry pairs the target id with its type tag so callers can
    /// render the full AWS response shape.
    pub fn targets_for_policy(
        &self,
        policy_id: &str,
    ) -> Result<Vec<(&str, &str, &'static str)>, OrgError> {
        if !self.policies.contains_key(policy_id) {
            return Err(OrgError::PolicyNotFound(policy_id.to_string()));
        }
        let mut out = Vec::new();
        for (target_id, set) in &self.attachments {
            if set.contains(policy_id) {
                let ttype = self
                    .target_type(target_id)
                    .expect("attachment target must still exist");
                let name = match ttype {
                    "ROOT" => self.root_name.as_str(),
                    "ORGANIZATIONAL_UNIT" => self
                        .ous
                        .get(target_id)
                        .map(|o| o.name.as_str())
                        .unwrap_or(""),
                    "ACCOUNT" => self
                        .accounts
                        .get(target_id)
                        .map(|a| a.name.as_str())
                        .unwrap_or(""),
                    _ => "",
                };
                out.push((target_id.as_str(), name, ttype));
            }
        }
        Ok(out)
    }
}

/// Typed errors used by organization state mutations so the service
/// layer can translate each into the correct AWS exception code.
#[derive(Debug)]
pub enum OrgError {
    ParentNotFound(String),
    DuplicateOrganizationalUnit(String),
    OrganizationalUnitNotFound(String),
    OrganizationalUnitNotEmpty(String),
    AccountNotFound(String),
    SourceParentNotFound(String),
    DestinationParentNotFound(String),
    PolicyNotFound(String),
    DuplicatePolicy(String),
    MalformedPolicyDocument,
    PolicyTypeNotSupported(String),
    PolicyChangesNotAllowed(String),
    PolicyInUse(String),
    PolicyNotAttached(String),
    TargetNotFound(String),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OrganizationalUnit {
    pub id: String,
    pub arn: String,
    pub name: String,
    pub parent_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct MemberAccount {
    pub id: String,
    pub arn: String,
    pub email: String,
    pub name: String,
    pub status: String,
    pub joined_method: String,
    pub joined_timestamp: DateTime<Utc>,
    pub parent_id: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Policy {
    pub id: String,
    pub arn: String,
    pub name: String,
    pub description: String,
    pub policy_type: String,
    pub aws_managed: bool,
    pub content: String,
}

/// Generate a lowercase alphanumeric ID fragment of `len` characters.
/// Used for org/root/OU/policy IDs. Pulled from a UUID v4 so the PRNG
/// is the one already pulled in by the rest of fakecloud.
pub fn random_id(len: usize) -> String {
    let mut out = String::with_capacity(len);
    while out.len() < len {
        let u = Uuid::new_v4().simple().to_string();
        for ch in u.chars() {
            if out.len() >= len {
                break;
            }
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bootstrap_has_root_and_full_aws_access() {
        let org = OrganizationState::bootstrap("111111111111");
        assert_eq!(org.management_account_id, "111111111111");
        assert!(org.org_id.starts_with("o-"));
        assert!(org.root_id.starts_with("r-"));
        assert_eq!(org.feature_set, FEATURE_SET_ALL);

        let full = org
            .policies
            .get(FULL_AWS_ACCESS_POLICY_ID)
            .expect("FullAWSAccess auto-seeded");
        assert!(full.aws_managed);
        assert_eq!(full.policy_type, POLICY_TYPE_SCP);

        let root_attachments = org.attachments.get(&org.root_id).expect("root attachments");
        assert!(root_attachments.contains(FULL_AWS_ACCESS_POLICY_ID));
    }

    #[test]
    fn bootstrap_enrolls_management_account_in_root() {
        let org = OrganizationState::bootstrap("222222222222");
        let mgmt = org.accounts.get("222222222222").unwrap();
        assert_eq!(mgmt.parent_id, org.root_id);
        assert_eq!(mgmt.status, "ACTIVE");
    }

    #[test]
    fn is_management_distinguishes_accounts() {
        let org = OrganizationState::bootstrap("111111111111");
        assert!(org.is_management("111111111111"));
        assert!(!org.is_management("222222222222"));
    }

    #[test]
    fn random_id_has_requested_length() {
        for len in [4, 8, 10, 16, 32] {
            let id = random_id(len);
            assert_eq!(id.len(), len);
        }
    }

    #[test]
    fn enroll_account_if_missing_adds_to_root() {
        let mut org = OrganizationState::bootstrap("111111111111");
        org.enroll_account_if_missing("222222222222");
        let member = org.accounts.get("222222222222").expect("enrolled");
        assert_eq!(member.parent_id, org.root_id);
    }

    #[test]
    fn enroll_account_if_missing_is_idempotent() {
        let mut org = OrganizationState::bootstrap("111111111111");
        org.enroll_account_if_missing("111111111111");
        assert_eq!(org.accounts.len(), 1);
    }

    #[test]
    fn create_ou_rejects_unknown_parent() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let err = org.create_ou("ou-nope", "team").unwrap_err();
        assert!(matches!(err, OrgError::ParentNotFound(_)));
    }

    #[test]
    fn create_ou_rejects_duplicate_name_under_same_parent() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let root = org.root_id.clone();
        org.create_ou(&root, "engineering").unwrap();
        let err = org.create_ou(&root, "engineering").unwrap_err();
        assert!(matches!(err, OrgError::DuplicateOrganizationalUnit(_)));
    }

    #[test]
    fn create_ou_allows_same_name_under_different_parents() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let root = org.root_id.clone();
        let parent = org.create_ou(&root, "top").unwrap();
        // Same leaf name under a different parent OU must succeed.
        org.create_ou(&parent.id, "engineering").unwrap();
        org.create_ou(&root, "engineering").unwrap();
    }

    #[test]
    fn delete_ou_rejects_non_empty_with_accounts() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let root = org.root_id.clone();
        let ou = org.create_ou(&root, "team").unwrap();
        org.enroll_account_if_missing("222222222222");
        org.move_account("222222222222", &root, &ou.id).unwrap();
        let err = org.delete_ou(&ou.id).unwrap_err();
        assert!(matches!(err, OrgError::OrganizationalUnitNotEmpty(_)));
    }

    #[test]
    fn delete_ou_rejects_non_empty_with_child_ou() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let root = org.root_id.clone();
        let parent = org.create_ou(&root, "parent").unwrap();
        org.create_ou(&parent.id, "child").unwrap();
        let err = org.delete_ou(&parent.id).unwrap_err();
        assert!(matches!(err, OrgError::OrganizationalUnitNotEmpty(_)));
    }

    #[test]
    fn delete_ou_clears_attachments() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let root = org.root_id.clone();
        let ou = org.create_ou(&root, "team").unwrap();
        org.attachments
            .entry(ou.id.clone())
            .or_default()
            .insert("p-custom".to_string());
        org.delete_ou(&ou.id).unwrap();
        assert!(!org.attachments.contains_key(&ou.id));
    }

    #[test]
    fn move_account_enforces_source_parent() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let root = org.root_id.clone();
        let ou = org.create_ou(&root, "team").unwrap();
        org.enroll_account_if_missing("222222222222");
        let err = org.move_account("222222222222", &ou.id, &root).unwrap_err();
        assert!(matches!(err, OrgError::SourceParentNotFound(_)));
    }

    #[test]
    fn move_account_rejects_unknown_destination() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let root = org.root_id.clone();
        let err = org
            .move_account("111111111111", &root, "ou-nope")
            .unwrap_err();
        assert!(matches!(err, OrgError::DestinationParentNotFound(_)));
    }

    #[test]
    fn rename_ou_rejects_duplicate() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let root = org.root_id.clone();
        let a = org.create_ou(&root, "a").unwrap();
        let b = org.create_ou(&root, "b").unwrap();
        let err = org.rename_ou(&b.id, "a").unwrap_err();
        assert!(matches!(err, OrgError::DuplicateOrganizationalUnit(_)));
        // Renaming in place is fine.
        org.rename_ou(&a.id, "a").unwrap();
    }

    const CONTENT_ALL: &str =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"*","Resource":"*"}]}"#;

    #[test]
    fn create_policy_assigns_id_and_arn() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let p = org
            .create_policy("AllowAll", "d", CONTENT_ALL, POLICY_TYPE_SCP)
            .unwrap();
        assert!(p.id.starts_with("p-"));
        assert!(p.arn.contains("service_control_policy"));
        assert_eq!(p.policy_type, POLICY_TYPE_SCP);
        assert!(!p.aws_managed);
    }

    #[test]
    fn create_policy_rejects_non_scp_type() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let err = org
            .create_policy("x", "d", CONTENT_ALL, "TAG_POLICY")
            .unwrap_err();
        assert!(matches!(err, OrgError::PolicyTypeNotSupported(_)));
    }

    #[test]
    fn create_policy_rejects_malformed_json() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let err = org
            .create_policy("x", "d", "not-json", POLICY_TYPE_SCP)
            .unwrap_err();
        assert!(matches!(err, OrgError::MalformedPolicyDocument));
    }

    #[test]
    fn create_policy_duplicate_name_rejected() {
        let mut org = OrganizationState::bootstrap("111111111111");
        org.create_policy("AllowAll", "d", CONTENT_ALL, POLICY_TYPE_SCP)
            .unwrap();
        let err = org
            .create_policy("AllowAll", "other", CONTENT_ALL, POLICY_TYPE_SCP)
            .unwrap_err();
        assert!(matches!(err, OrgError::DuplicatePolicy(_)));
    }

    #[test]
    fn update_policy_overrides_fields() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let p = org
            .create_policy("a", "old", CONTENT_ALL, POLICY_TYPE_SCP)
            .unwrap();
        let updated = org
            .update_policy(&p.id, Some("b"), Some("new"), None)
            .unwrap();
        assert_eq!(updated.name, "b");
        assert_eq!(updated.description, "new");
        assert_eq!(updated.content, CONTENT_ALL);
    }

    #[test]
    fn update_policy_rejects_aws_managed() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let err = org
            .update_policy(FULL_AWS_ACCESS_POLICY_ID, Some("x"), None, None)
            .unwrap_err();
        assert!(matches!(err, OrgError::PolicyChangesNotAllowed(_)));
    }

    #[test]
    fn update_policy_rejects_malformed_content() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let p = org
            .create_policy("a", "d", CONTENT_ALL, POLICY_TYPE_SCP)
            .unwrap();
        let err = org
            .update_policy(&p.id, None, None, Some("{bad"))
            .unwrap_err();
        assert!(matches!(err, OrgError::MalformedPolicyDocument));
    }

    #[test]
    fn update_policy_duplicate_name_rejected() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let a = org
            .create_policy("a", "d", CONTENT_ALL, POLICY_TYPE_SCP)
            .unwrap();
        let b = org
            .create_policy("b", "d", CONTENT_ALL, POLICY_TYPE_SCP)
            .unwrap();
        let err = org.update_policy(&b.id, Some("a"), None, None).unwrap_err();
        assert!(matches!(err, OrgError::DuplicatePolicy(_)));
        // Rename to its own name is fine (idempotent).
        org.update_policy(&a.id, Some("a"), None, None).unwrap();
    }

    #[test]
    fn delete_policy_rejects_in_use() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let root = org.root_id.clone();
        let p = org
            .create_policy("p", "d", CONTENT_ALL, POLICY_TYPE_SCP)
            .unwrap();
        org.attach_policy(&p.id, &root).unwrap();
        let err = org.delete_policy(&p.id).unwrap_err();
        assert!(matches!(err, OrgError::PolicyInUse(_)));
    }

    #[test]
    fn delete_policy_rejects_aws_managed() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let err = org.delete_policy(FULL_AWS_ACCESS_POLICY_ID).unwrap_err();
        assert!(matches!(err, OrgError::PolicyChangesNotAllowed(_)));
    }

    #[test]
    fn attach_detach_roundtrip() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let root = org.root_id.clone();
        let p = org
            .create_policy("p", "d", CONTENT_ALL, POLICY_TYPE_SCP)
            .unwrap();
        let ou = org.create_ou(&root, "team").unwrap();
        org.attach_policy(&p.id, &ou.id).unwrap();
        let targets = org.targets_for_policy(&p.id).unwrap();
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].0, ou.id);
        assert_eq!(targets[0].2, "ORGANIZATIONAL_UNIT");
        org.detach_policy(&p.id, &ou.id).unwrap();
        assert!(org.targets_for_policy(&p.id).unwrap().is_empty());
    }

    #[test]
    fn attach_rejects_unknown_target_and_policy() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let p = org
            .create_policy("p", "d", CONTENT_ALL, POLICY_TYPE_SCP)
            .unwrap();
        let err = org.attach_policy(&p.id, "ou-bogus").unwrap_err();
        assert!(matches!(err, OrgError::TargetNotFound(_)));
        let root = org.root_id.clone();
        let err = org.attach_policy("p-bogus", &root).unwrap_err();
        assert!(matches!(err, OrgError::PolicyNotFound(_)));
    }

    #[test]
    fn detach_unattached_policy_fails() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let root = org.root_id.clone();
        let p = org
            .create_policy("p", "d", CONTENT_ALL, POLICY_TYPE_SCP)
            .unwrap();
        let err = org.detach_policy(&p.id, &root).unwrap_err();
        assert!(matches!(err, OrgError::PolicyNotAttached(_)));
    }

    #[test]
    fn policies_for_target_returns_attached_only() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let root = org.root_id.clone();
        let p = org
            .create_policy("p", "d", CONTENT_ALL, POLICY_TYPE_SCP)
            .unwrap();
        org.attach_policy(&p.id, &root).unwrap();
        // Root starts with FullAWSAccess + new p attached.
        let list = org.policies_for_target(&root).unwrap();
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn policies_for_target_unknown_target() {
        let org = OrganizationState::bootstrap("111111111111");
        let err = org.policies_for_target("ou-bogus").unwrap_err();
        assert!(matches!(err, OrgError::TargetNotFound(_)));
    }

    #[test]
    fn targets_for_policy_identifies_target_types() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let root = org.root_id.clone();
        let ou = org.create_ou(&root, "team").unwrap();
        let p = org
            .create_policy("p", "d", CONTENT_ALL, POLICY_TYPE_SCP)
            .unwrap();
        org.enroll_account_if_missing("222222222222");
        org.attach_policy(&p.id, &root).unwrap();
        org.attach_policy(&p.id, &ou.id).unwrap();
        org.attach_policy(&p.id, "222222222222").unwrap();
        let mut types: Vec<_> = org
            .targets_for_policy(&p.id)
            .unwrap()
            .into_iter()
            .map(|(_, _, t)| t)
            .collect();
        types.sort();
        assert_eq!(types, vec!["ACCOUNT", "ORGANIZATIONAL_UNIT", "ROOT"]);
    }

    #[test]
    fn attach_is_idempotent() {
        let mut org = OrganizationState::bootstrap("111111111111");
        let root = org.root_id.clone();
        let p = org
            .create_policy("p", "d", CONTENT_ALL, POLICY_TYPE_SCP)
            .unwrap();
        org.attach_policy(&p.id, &root).unwrap();
        org.attach_policy(&p.id, &root).unwrap();
        let targets = org.targets_for_policy(&p.id).unwrap();
        assert_eq!(targets.len(), 1);
    }
}
