//! WAF v2 JSON 1.1 service.

use std::collections::HashMap;
use std::sync::Arc;

use async_trait::async_trait;
use base64::Engine;
use chrono::Utc;
use http::StatusCode;
use parking_lot::RwLock;
use serde_json::{json, Value};
use uuid::Uuid;

use fakecloud_core::pagination::paginate;
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};

use crate::state::{
    AccountState, ApiKey, IpSet, RegexPatternSet, RuleGroup, SharedWafv2State, Wafv2Accounts,
    WebAcl,
};

const SUPPORTED_ACTIONS: &[&str] = &[
    "AssociateWebACL",
    "CheckCapacity",
    "CreateAPIKey",
    "CreateIPSet",
    "CreateRegexPatternSet",
    "CreateRuleGroup",
    "CreateWebACL",
    "DeleteAPIKey",
    "DeleteFirewallManagerRuleGroups",
    "DeleteIPSet",
    "DeleteLoggingConfiguration",
    "DeletePermissionPolicy",
    "DeleteRegexPatternSet",
    "DeleteRuleGroup",
    "DeleteWebACL",
    "DescribeAllManagedProducts",
    "DescribeManagedProductsByVendor",
    "DescribeManagedRuleGroup",
    "DisassociateWebACL",
    "GenerateMobileSdkReleaseUrl",
    "GetDecryptedAPIKey",
    "GetIPSet",
    "GetLoggingConfiguration",
    "GetManagedRuleSet",
    "GetMobileSdkRelease",
    "GetPermissionPolicy",
    "GetRateBasedStatementManagedKeys",
    "GetRegexPatternSet",
    "GetRuleGroup",
    "GetSampledRequests",
    "GetTopPathStatisticsByTraffic",
    "GetWebACL",
    "GetWebACLForResource",
    "ListAPIKeys",
    "ListAvailableManagedRuleGroups",
    "ListAvailableManagedRuleGroupVersions",
    "ListIPSets",
    "ListLoggingConfigurations",
    "ListManagedRuleSets",
    "ListMobileSdkReleases",
    "ListRegexPatternSets",
    "ListResourcesForWebACL",
    "ListRuleGroups",
    "ListTagsForResource",
    "ListWebACLs",
    "PutLoggingConfiguration",
    "PutManagedRuleSetVersions",
    "PutPermissionPolicy",
    "TagResource",
    "UntagResource",
    "UpdateIPSet",
    "UpdateManagedRuleSetVersionExpiryDate",
    "UpdateRegexPatternSet",
    "UpdateRuleGroup",
    "UpdateWebACL",
];

pub struct Wafv2Service {
    state: SharedWafv2State,
}

impl Wafv2Service {
    pub fn new(state: SharedWafv2State) -> Self {
        Self { state }
    }

    pub fn shared_state(&self) -> SharedWafv2State {
        Arc::clone(&self.state)
    }
}

impl Default for Wafv2Service {
    fn default() -> Self {
        Self::new(Arc::new(RwLock::new(Wafv2Accounts::new())))
    }
}

#[async_trait]
impl AwsService for Wafv2Service {
    fn service_name(&self) -> &str {
        "wafv2"
    }

    fn supported_actions(&self) -> &[&str] {
        SUPPORTED_ACTIONS
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        match req.action.as_str() {
            "CreateWebACL" => self.create_web_acl(&req),
            "GetWebACL" => self.get_web_acl(&req),
            "ListWebACLs" => self.list_web_acls(&req),
            "UpdateWebACL" => self.update_web_acl(&req),
            "DeleteWebACL" => self.delete_web_acl(&req),
            "CreateRuleGroup" => self.create_rule_group(&req),
            "GetRuleGroup" => self.get_rule_group(&req),
            "ListRuleGroups" => self.list_rule_groups(&req),
            "UpdateRuleGroup" => self.update_rule_group(&req),
            "DeleteRuleGroup" => self.delete_rule_group(&req),
            "CreateIPSet" => self.create_ip_set(&req),
            "GetIPSet" => self.get_ip_set(&req),
            "ListIPSets" => self.list_ip_sets(&req),
            "UpdateIPSet" => self.update_ip_set(&req),
            "DeleteIPSet" => self.delete_ip_set(&req),
            "CreateRegexPatternSet" => self.create_regex_pattern_set(&req),
            "GetRegexPatternSet" => self.get_regex_pattern_set(&req),
            "ListRegexPatternSets" => self.list_regex_pattern_sets(&req),
            "UpdateRegexPatternSet" => self.update_regex_pattern_set(&req),
            "DeleteRegexPatternSet" => self.delete_regex_pattern_set(&req),
            "AssociateWebACL" => self.associate_web_acl(&req),
            "DisassociateWebACL" => self.disassociate_web_acl(&req),
            "GetWebACLForResource" => self.get_web_acl_for_resource(&req),
            "ListResourcesForWebACL" => self.list_resources_for_web_acl(&req),
            "PutLoggingConfiguration" => self.put_logging_configuration(&req),
            "GetLoggingConfiguration" => self.get_logging_configuration(&req),
            "DeleteLoggingConfiguration" => self.delete_logging_configuration(&req),
            "ListLoggingConfigurations" => self.list_logging_configurations(&req),
            "PutPermissionPolicy" => self.put_permission_policy(&req),
            "GetPermissionPolicy" => self.get_permission_policy(&req),
            "DeletePermissionPolicy" => self.delete_permission_policy(&req),
            "TagResource" => self.tag_resource(&req),
            "UntagResource" => self.untag_resource(&req),
            "ListTagsForResource" => self.list_tags_for_resource(&req),
            "CreateAPIKey" => self.create_api_key(&req),
            "DeleteAPIKey" => self.delete_api_key(&req),
            "GetDecryptedAPIKey" => self.get_decrypted_api_key(&req),
            "ListAPIKeys" => self.list_api_keys(&req),
            "DescribeAllManagedProducts" => self.describe_all_managed_products(&req),
            "DescribeManagedProductsByVendor" => self.describe_managed_products_by_vendor(&req),
            "DescribeManagedRuleGroup" => self.describe_managed_rule_group(&req),
            "GetManagedRuleSet" => self.get_managed_rule_set(&req),
            "ListAvailableManagedRuleGroups" => self.list_available_managed_rule_groups(&req),
            "ListAvailableManagedRuleGroupVersions" => {
                self.list_available_managed_rule_group_versions(&req)
            }
            "ListManagedRuleSets" => self.list_managed_rule_sets(&req),
            "PutManagedRuleSetVersions" => self.put_managed_rule_set_versions(&req),
            "UpdateManagedRuleSetVersionExpiryDate" => {
                self.update_managed_rule_set_version_expiry_date(&req)
            }
            "GenerateMobileSdkReleaseUrl" => self.generate_mobile_sdk_release_url(&req),
            "GetMobileSdkRelease" => self.get_mobile_sdk_release(&req),
            "ListMobileSdkReleases" => self.list_mobile_sdk_releases(&req),
            "CheckCapacity" => self.check_capacity(&req),
            "GetSampledRequests" => self.get_sampled_requests(&req),
            "GetTopPathStatisticsByTraffic" => self.get_top_path_statistics_by_traffic(&req),
            "GetRateBasedStatementManagedKeys" => self.get_rate_based_statement_managed_keys(&req),
            "DeleteFirewallManagerRuleGroups" => self.delete_firewall_manager_rule_groups(&req),
            other => Err(AwsServiceError::action_not_implemented("wafv2", other)),
        }
    }
}

// ─── WebACL ─────────────────────────────────────────────────────────

impl Wafv2Service {
    fn create_web_acl(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = require_str(&body, "Name")?;
        let scope = require_scope(&body)?;
        let default_action = body
            .get("DefaultAction")
            .cloned()
            .ok_or_else(|| invalid_param("DefaultAction is required"))?;
        let visibility_config = body
            .get("VisibilityConfig")
            .cloned()
            .ok_or_else(|| invalid_param("VisibilityConfig is required"))?;
        let rules = body
            .get("Rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let description = body
            .get("Description")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let custom_response_bodies = parse_custom_response_bodies(body.get("CustomResponseBodies"));
        let captcha_config = body.get("CaptchaConfig").cloned();
        let challenge_config = body.get("ChallengeConfig").cloned();
        let token_domains = parse_string_list(body.get("TokenDomains"));
        let association_config = body.get("AssociationConfig").cloned();
        let data_protection_config = body.get("DataProtectionConfig").cloned();
        let on_source_d_do_s_protection_config = body.get("OnSourceDDoSProtectionConfig").cloned();
        let application_config = body.get("ApplicationConfig").cloned();
        let tags = parse_tags(body.get("Tags"))?;

        let key = (scope.clone(), name.clone());
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        if account.web_acls.contains_key(&key) {
            return Err(already_exists(&format!("WebACL {name} already exists")));
        }
        let id = synth_uuid();
        let arn = synth_arn(&req.account_id, &req.region, &scope, "webacl", &name, &id);
        let lock_token = synth_uuid();
        let capacity = compute_capacity(&rules);
        let label_namespace = format!("awswaf:{}:webacl:{name}:", req.account_id);
        let summary = web_acl_summary_json(&id, &name, &arn, description.as_deref(), &lock_token);
        let acl = WebAcl {
            id,
            name,
            arn: arn.clone(),
            scope: scope.clone(),
            default_action,
            description,
            rules,
            visibility_config,
            capacity,
            lock_token,
            label_namespace,
            custom_response_bodies,
            captcha_config,
            challenge_config,
            token_domains,
            association_config,
            data_protection_config,
            on_source_d_do_s_protection_config,
            application_config,
            retrofitted_by_firewall_manager: false,
            pre_process_firewall_manager_rule_groups: Vec::new(),
            post_process_firewall_manager_rule_groups: Vec::new(),
            managed_by_firewall_manager: false,
            created_time: Utc::now(),
        };
        account.web_acls.insert(key, acl);
        if !tags.is_empty() {
            account.tags.insert(arn, tags);
        }
        Ok(AwsResponse::ok_json(json!({ "Summary": summary })))
    }

    fn get_web_acl(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn_in = body.get("ARN").and_then(Value::as_str).map(str::to_owned);
        let state = self.state.read();
        let account = state
            .accounts
            .get(&req.account_id)
            .ok_or_else(|| not_found("WebACL"))?;
        let acl = if let Some(arn) = arn_in.as_deref() {
            account
                .web_acls
                .values()
                .find(|a| a.arn == arn)
                .ok_or_else(|| not_found("WebACL"))?
        } else {
            let name = require_str(&body, "Name")?;
            let scope = require_scope(&body)?;
            account
                .web_acls
                .get(&(scope, name))
                .ok_or_else(|| not_found("WebACL"))?
        };
        let cleared = body
            .get("ARN")
            .is_none() // when fetched by name+scope path, AWS may return ApplicationIntegrationURL
            ;
        let mut response = json!({
            "WebACL": web_acl_detail_json(acl),
            "LockToken": acl.lock_token,
        });
        if cleared {
            response.as_object_mut().unwrap().insert(
                "ApplicationIntegrationURL".to_string(),
                Value::String(format!(
                    "https://{}.{}.amazonaws.com/captcha",
                    acl.id, req.region
                )),
            );
        }
        Ok(AwsResponse::ok_json(response))
    }

    fn list_web_acls(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let scope = require_scope(&body)?;
        let limit = body.get("Limit").and_then(Value::as_u64).unwrap_or(100) as usize;
        let next_marker = body
            .get("NextMarker")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let state = self.state.read();
        let mut all: Vec<WebAcl> = state
            .accounts
            .get(&req.account_id)
            .map(|a| {
                a.web_acls
                    .values()
                    .filter(|x| x.scope == scope)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        all.sort_by(|a, b| a.name.cmp(&b.name));
        let (page, next) = paginate(&all, next_marker.as_deref(), limit);
        let summaries: Vec<Value> = page
            .iter()
            .map(|a| {
                web_acl_summary_json(
                    &a.id,
                    &a.name,
                    &a.arn,
                    a.description.as_deref(),
                    &a.lock_token,
                )
            })
            .collect();
        let mut response = json!({ "WebACLs": summaries });
        if let Some(t) = next {
            response
                .as_object_mut()
                .unwrap()
                .insert("NextMarker".to_string(), Value::String(t));
        }
        Ok(AwsResponse::ok_json(response))
    }

    fn update_web_acl(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = require_str(&body, "Name")?;
        let scope = require_scope(&body)?;
        let id_in = require_str(&body, "Id")?;
        let lock_token_in = require_str(&body, "LockToken")?;
        let default_action = body
            .get("DefaultAction")
            .cloned()
            .ok_or_else(|| invalid_param("DefaultAction is required"))?;
        let visibility_config = body
            .get("VisibilityConfig")
            .cloned()
            .ok_or_else(|| invalid_param("VisibilityConfig is required"))?;
        let rules = body
            .get("Rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let description = body
            .get("Description")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        let acl = account
            .web_acls
            .get_mut(&(scope, name.clone()))
            .ok_or_else(|| not_found("WebACL"))?;
        if acl.id != id_in {
            return Err(invalid_param("Id does not match the named WebACL"));
        }
        if acl.lock_token != lock_token_in {
            return Err(stale_lock_token());
        }
        acl.default_action = default_action;
        acl.visibility_config = visibility_config;
        acl.capacity = compute_capacity(&rules);
        acl.rules = rules;
        acl.description = description;
        if let Some(b) = body.get("CustomResponseBodies") {
            acl.custom_response_bodies = parse_custom_response_bodies(Some(b));
        }
        if body.get("CaptchaConfig").is_some() {
            acl.captcha_config = body.get("CaptchaConfig").cloned();
        }
        if body.get("ChallengeConfig").is_some() {
            acl.challenge_config = body.get("ChallengeConfig").cloned();
        }
        if let Some(td) = body.get("TokenDomains") {
            acl.token_domains = parse_string_list(Some(td));
        }
        if body.get("AssociationConfig").is_some() {
            acl.association_config = body.get("AssociationConfig").cloned();
        }
        if body.get("DataProtectionConfig").is_some() {
            acl.data_protection_config = body.get("DataProtectionConfig").cloned();
        }
        acl.lock_token = synth_uuid();
        Ok(AwsResponse::ok_json(
            json!({ "NextLockToken": acl.lock_token }),
        ))
    }

    fn delete_web_acl(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = require_str(&body, "Name")?;
        let scope = require_scope(&body)?;
        let id_in = require_str(&body, "Id")?;
        let lock_token_in = require_str(&body, "LockToken")?;
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        let key = (scope, name);
        let acl = account
            .web_acls
            .get(&key)
            .ok_or_else(|| not_found("WebACL"))?;
        if acl.id != id_in {
            return Err(invalid_param("Id does not match the named WebACL"));
        }
        if acl.lock_token != lock_token_in {
            return Err(stale_lock_token());
        }
        let arn = acl.arn.clone();
        // Reject if any resource still associated (matches WAFAssociatedItemException).
        if account.associations.values().any(|v| *v == arn) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "WAFAssociatedItemException",
                "WebACL is still associated with resources",
            ));
        }
        account.web_acls.remove(&key);
        account.tags.remove(&arn);
        account.logging_configs.remove(&arn);
        Ok(AwsResponse::ok_json(json!({})))
    }
}

// ─── RuleGroup ─────────────────────────────────────────────────────

impl Wafv2Service {
    fn create_rule_group(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = require_str(&body, "Name")?;
        let scope = require_scope(&body)?;
        let capacity = body
            .get("Capacity")
            .and_then(Value::as_i64)
            .ok_or_else(|| invalid_param("Capacity is required"))?;
        let visibility_config = body
            .get("VisibilityConfig")
            .cloned()
            .ok_or_else(|| invalid_param("VisibilityConfig is required"))?;
        let rules = body
            .get("Rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let description = body
            .get("Description")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let custom_response_bodies = parse_custom_response_bodies(body.get("CustomResponseBodies"));
        let available_labels = body
            .get("AvailableLabels")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let consumed_labels = body
            .get("ConsumedLabels")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let tags = parse_tags(body.get("Tags"))?;

        let used = compute_capacity(&rules);
        if used > capacity {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "WAFLimitsExceededException",
                format!("Rules consume {used} WCU but capacity is {capacity}"),
            ));
        }

        let key = (scope.clone(), name.clone());
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        if account.rule_groups.contains_key(&key) {
            return Err(already_exists(&format!("RuleGroup {name} already exists")));
        }
        let id = synth_uuid();
        let arn = synth_arn(
            &req.account_id,
            &req.region,
            &scope,
            "rulegroup",
            &name,
            &id,
        );
        let lock_token = synth_uuid();
        let label_namespace = format!("awswaf:{}:rulegroup:{name}:", req.account_id);
        let summary =
            rule_group_summary_json(&id, &name, &arn, description.as_deref(), &lock_token);
        let rg = RuleGroup {
            id,
            name,
            arn: arn.clone(),
            scope: scope.clone(),
            capacity,
            description,
            rules,
            visibility_config,
            lock_token,
            label_namespace,
            custom_response_bodies,
            available_labels,
            consumed_labels,
            created_time: Utc::now(),
        };
        account.rule_groups.insert(key, rg);
        if !tags.is_empty() {
            account.tags.insert(arn, tags);
        }
        Ok(AwsResponse::ok_json(json!({ "Summary": summary })))
    }

    fn get_rule_group(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn_in = body.get("ARN").and_then(Value::as_str).map(str::to_owned);
        let state = self.state.read();
        let account = state
            .accounts
            .get(&req.account_id)
            .ok_or_else(|| not_found("RuleGroup"))?;
        let rg = if let Some(arn) = arn_in.as_deref() {
            account
                .rule_groups
                .values()
                .find(|r| r.arn == arn)
                .ok_or_else(|| not_found("RuleGroup"))?
        } else {
            let name = require_str(&body, "Name")?;
            let scope = require_scope(&body)?;
            account
                .rule_groups
                .get(&(scope, name))
                .ok_or_else(|| not_found("RuleGroup"))?
        };
        Ok(AwsResponse::ok_json(json!({
            "RuleGroup": rule_group_detail_json(rg),
            "LockToken": rg.lock_token,
        })))
    }

    fn list_rule_groups(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let scope = require_scope(&body)?;
        let limit = body.get("Limit").and_then(Value::as_u64).unwrap_or(100) as usize;
        let next_marker = body
            .get("NextMarker")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let state = self.state.read();
        let mut all: Vec<RuleGroup> = state
            .accounts
            .get(&req.account_id)
            .map(|a| {
                a.rule_groups
                    .values()
                    .filter(|x| x.scope == scope)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        all.sort_by(|a, b| a.name.cmp(&b.name));
        let (page, next) = paginate(&all, next_marker.as_deref(), limit);
        let summaries: Vec<Value> = page
            .iter()
            .map(|r| {
                rule_group_summary_json(
                    &r.id,
                    &r.name,
                    &r.arn,
                    r.description.as_deref(),
                    &r.lock_token,
                )
            })
            .collect();
        let mut response = json!({ "RuleGroups": summaries });
        if let Some(t) = next {
            response
                .as_object_mut()
                .unwrap()
                .insert("NextMarker".to_string(), Value::String(t));
        }
        Ok(AwsResponse::ok_json(response))
    }

    fn update_rule_group(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = require_str(&body, "Name")?;
        let scope = require_scope(&body)?;
        let id_in = require_str(&body, "Id")?;
        let lock_token_in = require_str(&body, "LockToken")?;
        let visibility_config = body
            .get("VisibilityConfig")
            .cloned()
            .ok_or_else(|| invalid_param("VisibilityConfig is required"))?;
        let rules = body
            .get("Rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let description = body
            .get("Description")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        let rg = account
            .rule_groups
            .get_mut(&(scope, name.clone()))
            .ok_or_else(|| not_found("RuleGroup"))?;
        if rg.id != id_in {
            return Err(invalid_param("Id does not match the named RuleGroup"));
        }
        if rg.lock_token != lock_token_in {
            return Err(stale_lock_token());
        }
        let used = compute_capacity(&rules);
        if used > rg.capacity {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "WAFLimitsExceededException",
                format!("Rules consume {used} WCU but capacity is {}", rg.capacity),
            ));
        }
        rg.visibility_config = visibility_config;
        rg.rules = rules;
        rg.description = description;
        if let Some(b) = body.get("CustomResponseBodies") {
            rg.custom_response_bodies = parse_custom_response_bodies(Some(b));
        }
        rg.lock_token = synth_uuid();
        Ok(AwsResponse::ok_json(
            json!({ "NextLockToken": rg.lock_token }),
        ))
    }

    fn delete_rule_group(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = require_str(&body, "Name")?;
        let scope = require_scope(&body)?;
        let id_in = require_str(&body, "Id")?;
        let lock_token_in = require_str(&body, "LockToken")?;
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        let key = (scope, name);
        let rg = account
            .rule_groups
            .get(&key)
            .ok_or_else(|| not_found("RuleGroup"))?;
        if rg.id != id_in {
            return Err(invalid_param("Id does not match the named RuleGroup"));
        }
        if rg.lock_token != lock_token_in {
            return Err(stale_lock_token());
        }
        let arn = rg.arn.clone();
        // Reject if any web ACL still references the rule group.
        let referenced = account.web_acls.values().any(|acl| {
            acl.rules.iter().any(|rule| {
                rule.get("Statement")
                    .and_then(|s| s.get("RuleGroupReferenceStatement"))
                    .and_then(|s| s.get("ARN"))
                    .and_then(Value::as_str)
                    == Some(arn.as_str())
            })
        });
        if referenced {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "WAFAssociatedItemException",
                "RuleGroup is referenced by one or more WebACLs",
            ));
        }
        account.rule_groups.remove(&key);
        account.tags.remove(&arn);
        account.permission_policies.remove(&arn);
        Ok(AwsResponse::ok_json(json!({})))
    }
}

// ─── IPSet ─────────────────────────────────────────────────────────

impl Wafv2Service {
    fn create_ip_set(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = require_str(&body, "Name")?;
        let scope = require_scope(&body)?;
        let ip_address_version = require_str(&body, "IPAddressVersion")?;
        let addresses = parse_string_list(body.get("Addresses"));
        let description = body
            .get("Description")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let tags = parse_tags(body.get("Tags"))?;
        let key = (scope.clone(), name.clone());
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        if account.ip_sets.contains_key(&key) {
            return Err(already_exists(&format!("IPSet {name} already exists")));
        }
        let id = synth_uuid();
        let arn = synth_arn(&req.account_id, &req.region, &scope, "ipset", &name, &id);
        let lock_token = synth_uuid();
        let summary = ip_set_summary_json(&id, &name, &arn, description.as_deref(), &lock_token);
        let set = IpSet {
            id,
            name,
            arn: arn.clone(),
            scope,
            description,
            ip_address_version,
            addresses,
            lock_token,
            created_time: Utc::now(),
        };
        account.ip_sets.insert(key, set);
        if !tags.is_empty() {
            account.tags.insert(arn, tags);
        }
        Ok(AwsResponse::ok_json(json!({ "Summary": summary })))
    }

    fn get_ip_set(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = require_str(&body, "Name")?;
        let scope = require_scope(&body)?;
        let _id = body.get("Id").and_then(Value::as_str);
        let state = self.state.read();
        let set = state
            .accounts
            .get(&req.account_id)
            .and_then(|a| a.ip_sets.get(&(scope, name)))
            .ok_or_else(|| not_found("IPSet"))?
            .clone();
        Ok(AwsResponse::ok_json(json!({
            "IPSet": ip_set_detail_json(&set),
            "LockToken": set.lock_token,
        })))
    }

    fn list_ip_sets(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let scope = require_scope(&body)?;
        let limit = body.get("Limit").and_then(Value::as_u64).unwrap_or(100) as usize;
        let next_marker = body
            .get("NextMarker")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let state = self.state.read();
        let mut all: Vec<IpSet> = state
            .accounts
            .get(&req.account_id)
            .map(|a| {
                a.ip_sets
                    .values()
                    .filter(|x| x.scope == scope)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        all.sort_by(|a, b| a.name.cmp(&b.name));
        let (page, next) = paginate(&all, next_marker.as_deref(), limit);
        let summaries: Vec<Value> = page
            .iter()
            .map(|s| {
                ip_set_summary_json(
                    &s.id,
                    &s.name,
                    &s.arn,
                    s.description.as_deref(),
                    &s.lock_token,
                )
            })
            .collect();
        let mut response = json!({ "IPSets": summaries });
        if let Some(t) = next {
            response
                .as_object_mut()
                .unwrap()
                .insert("NextMarker".to_string(), Value::String(t));
        }
        Ok(AwsResponse::ok_json(response))
    }

    fn update_ip_set(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = require_str(&body, "Name")?;
        let scope = require_scope(&body)?;
        let id_in = require_str(&body, "Id")?;
        let lock_token_in = require_str(&body, "LockToken")?;
        let addresses = parse_string_list(body.get("Addresses"));
        let description = body
            .get("Description")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        let set = account
            .ip_sets
            .get_mut(&(scope, name))
            .ok_or_else(|| not_found("IPSet"))?;
        if set.id != id_in {
            return Err(invalid_param("Id does not match the named IPSet"));
        }
        if set.lock_token != lock_token_in {
            return Err(stale_lock_token());
        }
        set.addresses = addresses;
        set.description = description;
        set.lock_token = synth_uuid();
        Ok(AwsResponse::ok_json(
            json!({ "NextLockToken": set.lock_token }),
        ))
    }

    fn delete_ip_set(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = require_str(&body, "Name")?;
        let scope = require_scope(&body)?;
        let id_in = require_str(&body, "Id")?;
        let lock_token_in = require_str(&body, "LockToken")?;
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        let key = (scope, name);
        let set = account
            .ip_sets
            .get(&key)
            .ok_or_else(|| not_found("IPSet"))?;
        if set.id != id_in {
            return Err(invalid_param("Id does not match the named IPSet"));
        }
        if set.lock_token != lock_token_in {
            return Err(stale_lock_token());
        }
        let arn = set.arn.clone();
        account.ip_sets.remove(&key);
        account.tags.remove(&arn);
        Ok(AwsResponse::ok_json(json!({})))
    }
}

// ─── RegexPatternSet ───────────────────────────────────────────────

impl Wafv2Service {
    fn create_regex_pattern_set(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = require_str(&body, "Name")?;
        let scope = require_scope(&body)?;
        let regular_expressions = body
            .get("RegularExpressionList")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let description = body
            .get("Description")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let tags = parse_tags(body.get("Tags"))?;
        let key = (scope.clone(), name.clone());
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        if account.regex_pattern_sets.contains_key(&key) {
            return Err(already_exists(&format!(
                "RegexPatternSet {name} already exists"
            )));
        }
        let id = synth_uuid();
        let arn = synth_arn(
            &req.account_id,
            &req.region,
            &scope,
            "regexpatternset",
            &name,
            &id,
        );
        let lock_token = synth_uuid();
        let summary = regex_set_summary_json(&id, &name, &arn, description.as_deref(), &lock_token);
        let set = RegexPatternSet {
            id,
            name,
            arn: arn.clone(),
            scope,
            description,
            regular_expressions,
            lock_token,
            created_time: Utc::now(),
        };
        account.regex_pattern_sets.insert(key, set);
        if !tags.is_empty() {
            account.tags.insert(arn, tags);
        }
        Ok(AwsResponse::ok_json(json!({ "Summary": summary })))
    }

    fn get_regex_pattern_set(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = require_str(&body, "Name")?;
        let scope = require_scope(&body)?;
        let state = self.state.read();
        let set = state
            .accounts
            .get(&req.account_id)
            .and_then(|a| a.regex_pattern_sets.get(&(scope, name)))
            .ok_or_else(|| not_found("RegexPatternSet"))?
            .clone();
        Ok(AwsResponse::ok_json(json!({
            "RegexPatternSet": regex_set_detail_json(&set),
            "LockToken": set.lock_token,
        })))
    }

    fn list_regex_pattern_sets(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let scope = require_scope(&body)?;
        let limit = body.get("Limit").and_then(Value::as_u64).unwrap_or(100) as usize;
        let next_marker = body
            .get("NextMarker")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let state = self.state.read();
        let mut all: Vec<RegexPatternSet> = state
            .accounts
            .get(&req.account_id)
            .map(|a| {
                a.regex_pattern_sets
                    .values()
                    .filter(|x| x.scope == scope)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        all.sort_by(|a, b| a.name.cmp(&b.name));
        let (page, next) = paginate(&all, next_marker.as_deref(), limit);
        let summaries: Vec<Value> = page
            .iter()
            .map(|s| {
                regex_set_summary_json(
                    &s.id,
                    &s.name,
                    &s.arn,
                    s.description.as_deref(),
                    &s.lock_token,
                )
            })
            .collect();
        let mut response = json!({ "RegexPatternSets": summaries });
        if let Some(t) = next {
            response
                .as_object_mut()
                .unwrap()
                .insert("NextMarker".to_string(), Value::String(t));
        }
        Ok(AwsResponse::ok_json(response))
    }

    fn update_regex_pattern_set(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = require_str(&body, "Name")?;
        let scope = require_scope(&body)?;
        let id_in = require_str(&body, "Id")?;
        let lock_token_in = require_str(&body, "LockToken")?;
        let regular_expressions = body
            .get("RegularExpressionList")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let description = body
            .get("Description")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        let set = account
            .regex_pattern_sets
            .get_mut(&(scope, name))
            .ok_or_else(|| not_found("RegexPatternSet"))?;
        if set.id != id_in {
            return Err(invalid_param("Id does not match the named RegexPatternSet"));
        }
        if set.lock_token != lock_token_in {
            return Err(stale_lock_token());
        }
        set.regular_expressions = regular_expressions;
        set.description = description;
        set.lock_token = synth_uuid();
        Ok(AwsResponse::ok_json(
            json!({ "NextLockToken": set.lock_token }),
        ))
    }

    fn delete_regex_pattern_set(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = require_str(&body, "Name")?;
        let scope = require_scope(&body)?;
        let id_in = require_str(&body, "Id")?;
        let lock_token_in = require_str(&body, "LockToken")?;
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        let key = (scope, name);
        let set = account
            .regex_pattern_sets
            .get(&key)
            .ok_or_else(|| not_found("RegexPatternSet"))?;
        if set.id != id_in {
            return Err(invalid_param("Id does not match the named RegexPatternSet"));
        }
        if set.lock_token != lock_token_in {
            return Err(stale_lock_token());
        }
        let arn = set.arn.clone();
        account.regex_pattern_sets.remove(&key);
        account.tags.remove(&arn);
        Ok(AwsResponse::ok_json(json!({})))
    }
}

// ─── Associations ───────────────────────────────────────────────────

impl Wafv2Service {
    fn associate_web_acl(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let acl_arn = require_str(&body, "WebACLArn")?;
        let resource_arn = require_str(&body, "ResourceArn")?;
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        if !account.web_acls.values().any(|a| a.arn == acl_arn) {
            return Err(not_found("WebACL"));
        }
        account.associations.insert(resource_arn, acl_arn);
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn disassociate_web_acl(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let resource_arn = require_str(&body, "ResourceArn")?;
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        account.associations.remove(&resource_arn);
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn get_web_acl_for_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let resource_arn = require_str(&body, "ResourceArn")?;
        let state = self.state.read();
        let account = state.accounts.get(&req.account_id);
        let acl_arn = account.and_then(|a| a.associations.get(&resource_arn).cloned());
        let mut response = json!({});
        if let Some(arn) = acl_arn {
            if let Some(acl) = account.and_then(|a| a.web_acls.values().find(|x| x.arn == arn)) {
                response
                    .as_object_mut()
                    .unwrap()
                    .insert("WebACL".to_string(), web_acl_detail_json(acl));
            }
        }
        Ok(AwsResponse::ok_json(response))
    }

    fn list_resources_for_web_acl(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let acl_arn = require_str(&body, "WebACLArn")?;
        let _resource_type = body
            .get("ResourceType")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let state = self.state.read();
        let resources: Vec<String> = state
            .accounts
            .get(&req.account_id)
            .map(|a| {
                a.associations
                    .iter()
                    .filter(|(_, v)| **v == acl_arn)
                    .map(|(k, _)| k.clone())
                    .collect()
            })
            .unwrap_or_default();
        Ok(AwsResponse::ok_json(json!({
            "ResourceArns": resources,
        })))
    }
}

// ─── Logging Config ────────────────────────────────────────────────

impl Wafv2Service {
    fn put_logging_configuration(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let cfg = body
            .get("LoggingConfiguration")
            .cloned()
            .ok_or_else(|| invalid_param("LoggingConfiguration is required"))?;
        let acl_arn = cfg
            .get("ResourceArn")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .ok_or_else(|| invalid_param("LoggingConfiguration.ResourceArn is required"))?;
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        if !account.web_acls.values().any(|a| a.arn == acl_arn) {
            return Err(not_found("WebACL"));
        }
        account.logging_configs.insert(acl_arn, cfg.clone());
        Ok(AwsResponse::ok_json(json!({
            "LoggingConfiguration": cfg,
        })))
    }

    fn get_logging_configuration(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let acl_arn = require_str(&body, "ResourceArn")?;
        let state = self.state.read();
        let cfg = state
            .accounts
            .get(&req.account_id)
            .and_then(|a| a.logging_configs.get(&acl_arn))
            .cloned()
            .ok_or_else(|| not_found("LoggingConfiguration"))?;
        Ok(AwsResponse::ok_json(json!({
            "LoggingConfiguration": cfg,
        })))
    }

    fn delete_logging_configuration(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let acl_arn = require_str(&body, "ResourceArn")?;
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        if account.logging_configs.remove(&acl_arn).is_none() {
            return Err(not_found("LoggingConfiguration"));
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn list_logging_configurations(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let scope = body
            .get("Scope")
            .and_then(Value::as_str)
            .unwrap_or("REGIONAL")
            .to_string();
        let state = self.state.read();
        let configs: Vec<Value> = state
            .accounts
            .get(&req.account_id)
            .map(|a| {
                a.logging_configs
                    .values()
                    .filter(|cfg| {
                        let arn = cfg.get("ResourceArn").and_then(Value::as_str).unwrap_or("");
                        a.web_acls
                            .values()
                            .any(|w| w.arn == arn && w.scope == scope)
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        Ok(AwsResponse::ok_json(json!({
            "LoggingConfigurations": configs,
        })))
    }
}

// ─── Permission Policy ─────────────────────────────────────────────

impl Wafv2Service {
    fn put_permission_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let resource_arn = require_str(&body, "ResourceArn")?;
        let policy = require_str(&body, "Policy")?;
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        if !account.rule_groups.values().any(|r| r.arn == resource_arn) {
            return Err(not_found("RuleGroup"));
        }
        account.permission_policies.insert(resource_arn, policy);
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn get_permission_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let resource_arn = require_str(&body, "ResourceArn")?;
        let state = self.state.read();
        let policy = state
            .accounts
            .get(&req.account_id)
            .and_then(|a| a.permission_policies.get(&resource_arn))
            .cloned()
            .ok_or_else(|| not_found("PermissionPolicy"))?;
        Ok(AwsResponse::ok_json(json!({ "Policy": policy })))
    }

    fn delete_permission_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let resource_arn = require_str(&body, "ResourceArn")?;
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        account.permission_policies.remove(&resource_arn);
        Ok(AwsResponse::ok_json(json!({})))
    }
}

// ─── Tags ───────────────────────────────────────────────────────────

impl Wafv2Service {
    fn tag_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = require_str(&body, "ResourceARN")?;
        let tags = parse_tags(body.get("Tags"))?;
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        if !resource_exists(account, &arn) {
            return Err(not_found("Resource"));
        }
        let entry = account.tags.entry(arn).or_default();
        for (k, v) in tags {
            entry.insert(k, v);
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn untag_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = require_str(&body, "ResourceARN")?;
        let keys = parse_string_list(body.get("TagKeys"));
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        if !resource_exists(account, &arn) {
            return Err(not_found("Resource"));
        }
        if let Some(t) = account.tags.get_mut(&arn) {
            for k in keys {
                t.remove(&k);
            }
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn list_tags_for_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let arn = require_str(&body, "ResourceARN")?;
        let state = self.state.read();
        let account = state.accounts.get(&req.account_id);
        let exists = account.is_some_and(|a| resource_exists(a, &arn));
        if !exists {
            return Err(not_found("Resource"));
        }
        let tags = account
            .and_then(|a| a.tags.get(&arn))
            .cloned()
            .unwrap_or_default();
        let tag_list: Vec<Value> = tags
            .into_iter()
            .map(|(k, v)| json!({ "Key": k, "Value": v }))
            .collect();
        Ok(AwsResponse::ok_json(json!({
            "TagInfoForResource": {
                "ResourceARN": arn,
                "TagList": tag_list,
            },
        })))
    }
}

// ─── API Keys ───────────────────────────────────────────────────────

impl Wafv2Service {
    fn create_api_key(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let scope = require_scope(&body)?;
        let token_domains = parse_string_list(body.get("TokenDomains"));
        if token_domains.is_empty() {
            return Err(invalid_param(
                "TokenDomains must contain at least one entry",
            ));
        }
        // API keys in real WAF are opaque encrypted blobs. fakecloud encodes
        // a deterministic JSON payload so callers can round-trip via
        // GetDecryptedAPIKey without storing extra state.
        let payload = json!({
            "tokenDomains": token_domains,
            "scope": scope,
            "version": 1,
            "id": Uuid::new_v4().to_string(),
        });
        let api_key = base64::engine::general_purpose::STANDARD
            .encode(serde_json::to_vec(&payload).unwrap_or_default());
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        account.api_keys.insert(
            api_key.clone(),
            ApiKey {
                api_key: api_key.clone(),
                scope,
                token_domains,
                version: 1,
                creation_timestamp: Utc::now(),
            },
        );
        Ok(AwsResponse::ok_json(json!({ "APIKey": api_key })))
    }

    fn delete_api_key(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let api_key = require_str(&body, "APIKey")?;
        let _scope = require_scope(&body)?;
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        if account.api_keys.remove(&api_key).is_none() {
            return Err(not_found("APIKey"));
        }
        Ok(AwsResponse::ok_json(json!({})))
    }

    fn get_decrypted_api_key(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let api_key = require_str(&body, "APIKey")?;
        let _scope = require_scope(&body)?;
        let state = self.state.read();
        let key = state
            .accounts
            .get(&req.account_id)
            .and_then(|a| a.api_keys.get(&api_key))
            .cloned()
            .ok_or_else(|| not_found("APIKey"))?;
        Ok(AwsResponse::ok_json(json!({
            "TokenDomains": key.token_domains,
            "CreationTimestamp": key.creation_timestamp.timestamp() as f64,
        })))
    }

    fn list_api_keys(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let scope = require_scope(&body)?;
        let limit = body.get("Limit").and_then(Value::as_u64).unwrap_or(100) as usize;
        let next_marker = body
            .get("NextMarker")
            .and_then(Value::as_str)
            .map(str::to_owned);
        let state = self.state.read();
        let mut all: Vec<ApiKey> = state
            .accounts
            .get(&req.account_id)
            .map(|a| {
                a.api_keys
                    .values()
                    .filter(|k| k.scope == scope)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        all.sort_by(|a, b| a.api_key.cmp(&b.api_key));
        let (page, next) = paginate(&all, next_marker.as_deref(), limit);
        let summaries: Vec<Value> = page
            .iter()
            .map(|k| {
                json!({
                    "TokenDomains": k.token_domains,
                    "APIKey": k.api_key,
                    "CreationTimestamp": k.creation_timestamp.timestamp() as f64,
                    "Version": k.version,
                })
            })
            .collect();
        let mut response = json!({
            "APIKeySummaries": summaries,
            "ApplicationIntegrationURL": format!("https://wafv2-token.{}.amazonaws.com/", req.region),
        });
        if let Some(t) = next {
            response
                .as_object_mut()
                .unwrap()
                .insert("NextMarker".to_string(), Value::String(t));
        }
        Ok(AwsResponse::ok_json(response))
    }
}

// ─── Managed rule sets / products ──────────────────────────────────

impl Wafv2Service {
    fn describe_all_managed_products(
        &self,
        _req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        Ok(AwsResponse::ok_json(json!({
            "ManagedProducts": managed_products(),
        })))
    }

    fn describe_managed_products_by_vendor(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let vendor = require_str(&body, "VendorName")?;
        let _scope = require_scope(&body)?;
        let products: Vec<Value> = managed_products()
            .into_iter()
            .filter(|p| p.get("VendorName").and_then(Value::as_str) == Some(vendor.as_str()))
            .collect();
        Ok(AwsResponse::ok_json(json!({
            "ManagedProducts": products,
        })))
    }

    fn describe_managed_rule_group(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let vendor = require_str(&body, "VendorName")?;
        let name = require_str(&body, "Name")?;
        let _scope = require_scope(&body)?;
        let version = body
            .get("VersionName")
            .and_then(Value::as_str)
            .unwrap_or("Version_1.0")
            .to_string();
        Ok(AwsResponse::ok_json(json!({
            "VersionName": version,
            "SnsTopicArn": format!("arn:aws:sns:us-east-1::{vendor}-{name}-notifications"),
            "Capacity": 50,
            "Rules": managed_rule_summaries(&vendor, &name),
            "LabelNamespace": format!("awswaf:managed:{vendor}:{name}:"),
            "AvailableLabels": [],
            "ConsumedLabels": [],
        })))
    }

    fn get_managed_rule_set(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let name = require_str(&body, "Name")?;
        let id = body
            .get("Id")
            .and_then(Value::as_str)
            .map(str::to_owned)
            .unwrap_or_else(|| format!("mrs-{name}"));
        let _scope = require_scope(&body)?;
        Ok(AwsResponse::ok_json(json!({
            "ManagedRuleSet": {
                "Name": name,
                "Id": id,
                "ARN": format!("arn:aws:wafv2:{}:{}:managedruleset/{name}/{id}", req.region, req.account_id),
                "Description": format!("Managed rule set {name}"),
                "PublishedVersions": {
                    "Version_1.0": {
                        "AssociatedRuleGroupArn": format!("arn:aws:wafv2:{}:aws:managedrulegroup/{name}", req.region),
                        "Capacity": 50,
                        "ForecastedLifetime": 90,
                        "PublishTimestamp": Utc::now().timestamp() as f64,
                        "LastUpdateTimestamp": Utc::now().timestamp() as f64,
                        "ExpiryTimestamp": (Utc::now() + chrono::Duration::days(365)).timestamp() as f64,
                    }
                },
                "RecommendedVersion": "Version_1.0",
                "LabelNamespace": format!("awswaf:managed::{name}:"),
            },
            "LockToken": synth_uuid(),
        })))
    }

    fn list_available_managed_rule_groups(
        &self,
        _req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        Ok(AwsResponse::ok_json(json!({
            "ManagedRuleGroups": [
                {
                    "VendorName": "AWS",
                    "Name": "AWSManagedRulesCommonRuleSet",
                    "VersioningSupported": true,
                    "Description": "OWASP Top 10 baseline rules",
                },
                {
                    "VendorName": "AWS",
                    "Name": "AWSManagedRulesKnownBadInputsRuleSet",
                    "VersioningSupported": true,
                    "Description": "Block request patterns associated with known exploits",
                },
                {
                    "VendorName": "AWS",
                    "Name": "AWSManagedRulesSQLiRuleSet",
                    "VersioningSupported": true,
                    "Description": "SQL injection patterns",
                },
            ],
        })))
    }

    fn list_available_managed_rule_group_versions(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let _vendor = require_str(&body, "VendorName")?;
        let _name = require_str(&body, "Name")?;
        Ok(AwsResponse::ok_json(json!({
            "Versions": [
                {"Name": "Version_1.0", "LastUpdateTimestamp": Utc::now().timestamp() as f64},
                {"Name": "Version_2.0", "LastUpdateTimestamp": Utc::now().timestamp() as f64},
            ],
            "CurrentDefaultVersion": "Version_2.0",
        })))
    }

    fn list_managed_rule_sets(&self, _req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        // fakecloud does not expose vendor-side managed rule set publishing,
        // so this always returns an empty list (matches accounts without
        // FirewallManager publishing rights).
        Ok(AwsResponse::ok_json(json!({ "ManagedRuleSets": [] })))
    }

    fn put_managed_rule_set_versions(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let _name = require_str(&body, "Name")?;
        let _id = require_str(&body, "Id")?;
        let _lock_token = require_str(&body, "LockToken")?;
        let _scope = require_scope(&body)?;
        Ok(AwsResponse::ok_json(json!({
            "NextLockToken": synth_uuid(),
        })))
    }

    fn update_managed_rule_set_version_expiry_date(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let _name = require_str(&body, "Name")?;
        let _id = require_str(&body, "Id")?;
        let _lock_token = require_str(&body, "LockToken")?;
        let _scope = require_scope(&body)?;
        let version_to_expire = require_str(&body, "VersionToExpire")?;
        let expiry_timestamp = body
            .get("ExpiryTimestamp")
            .and_then(Value::as_f64)
            .unwrap_or_else(|| Utc::now().timestamp() as f64);
        Ok(AwsResponse::ok_json(json!({
            "ExpiringVersion": version_to_expire,
            "ExpiryTimestamp": expiry_timestamp,
            "NextLockToken": synth_uuid(),
        })))
    }
}

// ─── Mobile SDK ─────────────────────────────────────────────────────

impl Wafv2Service {
    fn generate_mobile_sdk_release_url(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let platform = require_str(&body, "Platform")?;
        let release = require_str(&body, "ReleaseVersion")?;
        Ok(AwsResponse::ok_json(json!({
            "Url": format!("https://wafv2-mobile-sdk.{}.amazonaws.com/{}/{}.zip", req.region, platform, release),
        })))
    }

    fn get_mobile_sdk_release(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let platform = require_str(&body, "Platform")?;
        let release = require_str(&body, "ReleaseVersion")?;
        Ok(AwsResponse::ok_json(json!({
            "MobileSdkRelease": {
                "ReleaseVersion": release,
                "Timestamp": Utc::now().timestamp() as f64,
                "ReleaseNotes": format!("fakecloud {platform} SDK release {release}"),
                "Tags": [],
            },
        })))
    }

    fn list_mobile_sdk_releases(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let _platform = require_str(&body, "Platform")?;
        Ok(AwsResponse::ok_json(json!({
            "ReleaseSummaries": [
                {"ReleaseVersion": "1.0.0", "Timestamp": Utc::now().timestamp() as f64},
                {"ReleaseVersion": "1.1.0", "Timestamp": Utc::now().timestamp() as f64},
            ],
        })))
    }
}

// ─── Misc query / capacity ─────────────────────────────────────────

impl Wafv2Service {
    fn check_capacity(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let _scope = require_scope(&body)?;
        let rules = body
            .get("Rules")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        Ok(AwsResponse::ok_json(json!({
            "Capacity": compute_capacity(&rules),
        })))
    }

    fn get_sampled_requests(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let _web_acl_arn = require_str(&body, "WebAclArn")?;
        let _rule_metric_name = require_str(&body, "RuleMetricName")?;
        let _scope = require_scope(&body)?;
        let max_items = body.get("MaxItems").and_then(Value::as_u64).unwrap_or(100);
        Ok(AwsResponse::ok_json(json!({
            "SampledRequests": [],
            "PopulationSize": 0_u64,
            "TimeWindow": body.get("TimeWindow").cloned().unwrap_or(json!({})),
            "MaxItemsExamined": max_items,
        })))
    }

    fn get_top_path_statistics_by_traffic(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        // Smithy member is `WebAclArn` (lowercase l), unlike most other ops
        // which use `WebACLArn`. Match the model exactly.
        let _web_acl_arn = require_str(&body, "WebAclArn")?;
        let _scope = require_scope(&body)?;
        Ok(AwsResponse::ok_json(json!({
            "PathStatistics": [],
            "TopCategories": [],
            "TotalRequestCount": 0_u64,
        })))
    }

    fn get_rate_based_statement_managed_keys(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let _scope = require_scope(&body)?;
        let _web_acl_name = require_str(&body, "WebACLName")?;
        let _web_acl_id = require_str(&body, "WebACLId")?;
        let _rule_name = require_str(&body, "RuleName")?;
        Ok(AwsResponse::ok_json(json!({
            "ManagedKeysIPV4": {"IPAddressVersion": "IPV4", "Addresses": []},
            "ManagedKeysIPV6": {"IPAddressVersion": "IPV6", "Addresses": []},
        })))
    }

    fn delete_firewall_manager_rule_groups(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = req.json_body();
        let acl_arn = require_str(&body, "WebACLArn")?;
        let _lock_token = require_str(&body, "WebACLLockToken")?;
        let mut state = self.state.write();
        let account = account_mut(&mut state, &req.account_id);
        let acl = account
            .web_acls
            .values_mut()
            .find(|a| a.arn == acl_arn)
            .ok_or_else(|| not_found("WebACL"))?;
        acl.pre_process_firewall_manager_rule_groups.clear();
        acl.post_process_firewall_manager_rule_groups.clear();
        acl.lock_token = synth_uuid();
        Ok(AwsResponse::ok_json(json!({
            "NextWebACLLockToken": acl.lock_token,
        })))
    }
}

// ─── Helpers ────────────────────────────────────────────────────────

fn account_mut<'a>(state: &'a mut Wafv2Accounts, account_id: &str) -> &'a mut AccountState {
    state.accounts.entry(account_id.to_string()).or_default()
}

fn require_str(body: &Value, field: &str) -> Result<String, AwsServiceError> {
    body.get(field)
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or_else(|| invalid_param(format!("{field} is required")))
}

fn require_scope(body: &Value) -> Result<String, AwsServiceError> {
    let scope = require_str(body, "Scope")?;
    if scope != "REGIONAL" && scope != "CLOUDFRONT" {
        return Err(invalid_param(format!("Invalid Scope: {scope}")));
    }
    Ok(scope)
}

fn invalid_param(msg: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(StatusCode::BAD_REQUEST, "WAFInvalidParameterException", msg)
}

fn not_found(resource: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "WAFNonexistentItemException",
        format!("{resource} not found"),
    )
}

fn already_exists(msg: &str) -> AwsServiceError {
    AwsServiceError::aws_error(StatusCode::BAD_REQUEST, "WAFDuplicateItemException", msg)
}

fn stale_lock_token() -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "WAFOptimisticLockException",
        "LockToken does not match the current value; refresh and retry",
    )
}

fn synth_uuid() -> String {
    Uuid::new_v4().to_string()
}

fn synth_arn(
    account_id: &str,
    region: &str,
    scope: &str,
    kind: &str,
    name: &str,
    id: &str,
) -> String {
    let region = if region.is_empty() {
        "us-east-1"
    } else {
        region
    };
    // Real AWS WAF v2 CLOUDFRONT-scope ARNs always use `us-east-1` as the
    // region segment plus a `global/...` resource path. REGIONAL ARNs use
    // the caller's region with the region as the resource-path prefix.
    let (region_in_arn, scope_seg) = if scope == "CLOUDFRONT" {
        ("us-east-1", "global")
    } else {
        (region, region)
    };
    format!("arn:aws:wafv2:{region_in_arn}:{account_id}:{scope_seg}/{kind}/{name}/{id}")
}

fn parse_string_list(value: Option<&Value>) -> Vec<String> {
    value
        .and_then(Value::as_array)
        .map(|v| {
            v.iter()
                .filter_map(|s| s.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

fn parse_tags(value: Option<&Value>) -> Result<HashMap<String, String>, AwsServiceError> {
    let mut out = HashMap::new();
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

fn parse_custom_response_bodies(value: Option<&Value>) -> HashMap<String, Value> {
    value
        .and_then(Value::as_object)
        .map(|m| m.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
        .unwrap_or_default()
}

fn resource_exists(account: &AccountState, arn: &str) -> bool {
    account.web_acls.values().any(|w| w.arn == arn)
        || account.rule_groups.values().any(|r| r.arn == arn)
        || account.ip_sets.values().any(|s| s.arn == arn)
        || account.regex_pattern_sets.values().any(|s| s.arn == arn)
}

/// WCU cost is 1 per leaf statement in real WAF. fakecloud uses the
/// recursive count of statement leaves as a stand-in — close enough for
/// CheckCapacity round-tripping and for the WAFLimitsExceeded path.
fn compute_capacity(rules: &[Value]) -> i64 {
    rules
        .iter()
        .map(|r| r.get("Statement").map(count_statement_leaves).unwrap_or(1) as i64)
        .sum()
}

fn count_statement_leaves(stmt: &Value) -> u32 {
    let Some(obj) = stmt.as_object() else {
        return 1;
    };
    let mut total = 0u32;
    for (k, v) in obj {
        match k.as_str() {
            "AndStatement" | "OrStatement" => {
                if let Some(arr) = v.get("Statements").and_then(Value::as_array) {
                    for s in arr {
                        total += count_statement_leaves(s);
                    }
                }
            }
            "NotStatement" => {
                if let Some(s) = v.get("Statement") {
                    total += count_statement_leaves(s);
                }
            }
            _ => {
                total += 1;
            }
        }
    }
    total.max(1)
}

fn managed_products() -> Vec<Value> {
    vec![
        json!({
            "VendorName": "AWS",
            "ManagedRuleSetName": "AWSManagedRulesCommonRuleSet",
            "ProductId": "prod-aws-common",
            "ProductLink": "https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html",
            "ProductTitle": "Core rule set",
            "ProductDescription": "OWASP Top 10 baseline rules",
            "SnsTopicArn": "arn:aws:sns:us-east-1::aws-managed-common-notifications",
            "IsVersioningSupported": true,
            "IsAdvancedManagedRuleSet": false,
        }),
        json!({
            "VendorName": "AWS",
            "ManagedRuleSetName": "AWSManagedRulesSQLiRuleSet",
            "ProductId": "prod-aws-sqli",
            "ProductLink": "https://docs.aws.amazon.com/waf/latest/developerguide/aws-managed-rule-groups-list.html",
            "ProductTitle": "SQL injection rule set",
            "ProductDescription": "Rules that block SQL injection patterns",
            "SnsTopicArn": "arn:aws:sns:us-east-1::aws-managed-sqli-notifications",
            "IsVersioningSupported": true,
            "IsAdvancedManagedRuleSet": false,
        }),
    ]
}

fn managed_rule_summaries(_vendor: &str, _name: &str) -> Vec<Value> {
    vec![json!({
        "Name": "RuleA",
        "Action": {"Block": {}},
    })]
}

// ─── JSON shaping ──────────────────────────────────────────────────

fn web_acl_summary_json(
    id: &str,
    name: &str,
    arn: &str,
    description: Option<&str>,
    lock_token: &str,
) -> Value {
    let mut obj = json!({
        "Id": id,
        "Name": name,
        "ARN": arn,
        "LockToken": lock_token,
    });
    if let Some(d) = description {
        obj.as_object_mut()
            .unwrap()
            .insert("Description".to_string(), Value::String(d.to_string()));
    }
    obj
}

fn web_acl_detail_json(acl: &WebAcl) -> Value {
    let mut obj = json!({
        "Id": acl.id,
        "Name": acl.name,
        "ARN": acl.arn,
        "DefaultAction": acl.default_action,
        "Rules": acl.rules,
        "VisibilityConfig": acl.visibility_config,
        "Capacity": acl.capacity,
        "ManagedByFirewallManager": acl.managed_by_firewall_manager,
        "RetrofittedByFirewallManager": acl.retrofitted_by_firewall_manager,
        "LabelNamespace": acl.label_namespace,
        "TokenDomains": acl.token_domains,
        "PreProcessFirewallManagerRuleGroups": acl.pre_process_firewall_manager_rule_groups,
        "PostProcessFirewallManagerRuleGroups": acl.post_process_firewall_manager_rule_groups,
    });
    if let Some(d) = &acl.description {
        obj.as_object_mut()
            .unwrap()
            .insert("Description".to_string(), Value::String(d.clone()));
    }
    if !acl.custom_response_bodies.is_empty() {
        obj.as_object_mut().unwrap().insert(
            "CustomResponseBodies".to_string(),
            json!(acl.custom_response_bodies),
        );
    }
    if let Some(c) = &acl.captcha_config {
        obj.as_object_mut()
            .unwrap()
            .insert("CaptchaConfig".to_string(), c.clone());
    }
    if let Some(c) = &acl.challenge_config {
        obj.as_object_mut()
            .unwrap()
            .insert("ChallengeConfig".to_string(), c.clone());
    }
    if let Some(c) = &acl.association_config {
        obj.as_object_mut()
            .unwrap()
            .insert("AssociationConfig".to_string(), c.clone());
    }
    if let Some(c) = &acl.data_protection_config {
        obj.as_object_mut()
            .unwrap()
            .insert("DataProtectionConfig".to_string(), c.clone());
    }
    if let Some(c) = &acl.on_source_d_do_s_protection_config {
        obj.as_object_mut()
            .unwrap()
            .insert("OnSourceDDoSProtectionConfig".to_string(), c.clone());
    }
    if let Some(c) = &acl.application_config {
        obj.as_object_mut()
            .unwrap()
            .insert("ApplicationConfig".to_string(), c.clone());
    }
    obj
}

fn rule_group_summary_json(
    id: &str,
    name: &str,
    arn: &str,
    description: Option<&str>,
    lock_token: &str,
) -> Value {
    let mut obj = json!({
        "Id": id,
        "Name": name,
        "ARN": arn,
        "LockToken": lock_token,
    });
    if let Some(d) = description {
        obj.as_object_mut()
            .unwrap()
            .insert("Description".to_string(), Value::String(d.to_string()));
    }
    obj
}

fn rule_group_detail_json(rg: &RuleGroup) -> Value {
    let mut obj = json!({
        "Id": rg.id,
        "Name": rg.name,
        "ARN": rg.arn,
        "Capacity": rg.capacity,
        "Rules": rg.rules,
        "VisibilityConfig": rg.visibility_config,
        "LabelNamespace": rg.label_namespace,
        "AvailableLabels": rg.available_labels,
        "ConsumedLabels": rg.consumed_labels,
    });
    if let Some(d) = &rg.description {
        obj.as_object_mut()
            .unwrap()
            .insert("Description".to_string(), Value::String(d.clone()));
    }
    if !rg.custom_response_bodies.is_empty() {
        obj.as_object_mut().unwrap().insert(
            "CustomResponseBodies".to_string(),
            json!(rg.custom_response_bodies),
        );
    }
    obj
}

fn ip_set_summary_json(
    id: &str,
    name: &str,
    arn: &str,
    description: Option<&str>,
    lock_token: &str,
) -> Value {
    let mut obj = json!({
        "Id": id,
        "Name": name,
        "ARN": arn,
        "LockToken": lock_token,
    });
    if let Some(d) = description {
        obj.as_object_mut()
            .unwrap()
            .insert("Description".to_string(), Value::String(d.to_string()));
    }
    obj
}

fn ip_set_detail_json(set: &IpSet) -> Value {
    let mut obj = json!({
        "Id": set.id,
        "Name": set.name,
        "ARN": set.arn,
        "IPAddressVersion": set.ip_address_version,
        "Addresses": set.addresses,
    });
    if let Some(d) = &set.description {
        obj.as_object_mut()
            .unwrap()
            .insert("Description".to_string(), Value::String(d.clone()));
    }
    obj
}

fn regex_set_summary_json(
    id: &str,
    name: &str,
    arn: &str,
    description: Option<&str>,
    lock_token: &str,
) -> Value {
    let mut obj = json!({
        "Id": id,
        "Name": name,
        "ARN": arn,
        "LockToken": lock_token,
    });
    if let Some(d) = description {
        obj.as_object_mut()
            .unwrap()
            .insert("Description".to_string(), Value::String(d.to_string()));
    }
    obj
}

fn regex_set_detail_json(set: &RegexPatternSet) -> Value {
    let mut obj = json!({
        "Id": set.id,
        "Name": set.name,
        "ARN": set.arn,
        "RegularExpressionList": set.regular_expressions,
    });
    if let Some(d) = &set.description {
        obj.as_object_mut()
            .unwrap()
            .insert("Description".to_string(), Value::String(d.clone()));
    }
    obj
}
