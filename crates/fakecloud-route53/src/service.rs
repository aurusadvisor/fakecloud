//! Route 53 REST-XML service implementation.

use std::collections::BTreeMap;
use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use http::{HeaderMap, StatusCode};
use parking_lot::RwLock;
use uuid::Uuid;

use fakecloud_aws::arn::Arn;
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError, ResponseBody};

use crate::model::{
    AssociateVpcRequest, ChangeCidrCollectionRequest, ChangeResourceRecordSetsRequest,
    ChangeTagsForResourceRequest, CreateCidrCollectionRequest, CreateHealthCheckRequest,
    CreateHostedZoneRequest, CreateKeySigningKeyRequest, CreateQueryLoggingConfigRequest,
    CreateReusableDelegationSetRequest, CreateTrafficPolicyInstanceRequest,
    CreateTrafficPolicyRequest, CreateTrafficPolicyVersionRequest, HealthCheckConfig,
    ListTagsForResourcesRequest, ResourceRecordSet, UpdateHealthCheckRequest,
    UpdateHostedZoneCommentRequest, UpdateHostedZoneFeaturesRequest,
    UpdateTrafficPolicyCommentRequest, UpdateTrafficPolicyInstanceRequest, VpcAuthorizationRequest,
    VPC,
};
use crate::router::{route, Route};
use crate::state::{
    AccountState, Route53Accounts, SharedRoute53State, StoredChange, StoredCidrCollection,
    StoredHealthCheck, StoredHostedZone, StoredKeySigningKey, StoredQueryLoggingConfig,
    StoredReusableDelegationSet, StoredTrafficPolicy, StoredTrafficPolicyInstance,
};
use crate::xml_io;

pub(crate) const DEFAULT_ACCOUNT: &str = "000000000000";
pub(crate) const NS: &str = crate::NAMESPACE;
const XML_DECL: &str = r#"<?xml version="1.0" encoding="UTF-8"?>"#;

const SUPPORTED_ACTIONS: &[&str] = &[
    "CreateHostedZone",
    "GetHostedZone",
    "DeleteHostedZone",
    "ListHostedZones",
    "ListHostedZonesByName",
    "GetHostedZoneCount",
    "UpdateHostedZoneComment",
    "UpdateHostedZoneFeatures",
    "GetHostedZoneLimit",
    "ChangeResourceRecordSets",
    "ListResourceRecordSets",
    "GetChange",
    "TestDNSAnswer",
    "CreateHealthCheck",
    "GetHealthCheck",
    "UpdateHealthCheck",
    "DeleteHealthCheck",
    "ListHealthChecks",
    "GetHealthCheckCount",
    "GetHealthCheckStatus",
    "GetHealthCheckLastFailureReason",
    "GetCheckerIpRanges",
    "CreateTrafficPolicy",
    "CreateTrafficPolicyVersion",
    "GetTrafficPolicy",
    "UpdateTrafficPolicyComment",
    "DeleteTrafficPolicy",
    "ListTrafficPolicies",
    "ListTrafficPolicyVersions",
    "CreateTrafficPolicyInstance",
    "GetTrafficPolicyInstance",
    "UpdateTrafficPolicyInstance",
    "DeleteTrafficPolicyInstance",
    "ListTrafficPolicyInstances",
    "ListTrafficPolicyInstancesByHostedZone",
    "ListTrafficPolicyInstancesByPolicy",
    "GetTrafficPolicyInstanceCount",
    "GetDNSSEC",
    "EnableHostedZoneDNSSEC",
    "DisableHostedZoneDNSSEC",
    "CreateKeySigningKey",
    "DeleteKeySigningKey",
    "ActivateKeySigningKey",
    "DeactivateKeySigningKey",
    "CreateQueryLoggingConfig",
    "GetQueryLoggingConfig",
    "DeleteQueryLoggingConfig",
    "ListQueryLoggingConfigs",
    "CreateCidrCollection",
    "ChangeCidrCollection",
    "DeleteCidrCollection",
    "ListCidrCollections",
    "ListCidrLocations",
    "ListCidrBlocks",
    "AssociateVPCWithHostedZone",
    "DisassociateVPCFromHostedZone",
    "CreateVPCAssociationAuthorization",
    "DeleteVPCAssociationAuthorization",
    "ListVPCAssociationAuthorizations",
    "ListHostedZonesByVPC",
    "CreateReusableDelegationSet",
    "GetReusableDelegationSet",
    "DeleteReusableDelegationSet",
    "ListReusableDelegationSets",
    "GetReusableDelegationSetLimit",
    "ListGeoLocations",
    "GetGeoLocation",
    "GetAccountLimit",
    "ChangeTagsForResource",
    "ListTagsForResource",
    "ListTagsForResources",
];

pub struct Route53Service {
    pub(crate) state: SharedRoute53State,
}

impl Route53Service {
    pub fn new(state: SharedRoute53State) -> Self {
        Self { state }
    }

    pub fn shared_state(&self) -> SharedRoute53State {
        Arc::clone(&self.state)
    }
}

impl Default for Route53Service {
    fn default() -> Self {
        Self::new(Arc::new(RwLock::new(Route53Accounts::new())))
    }
}

#[async_trait]
impl AwsService for Route53Service {
    fn service_name(&self) -> &str {
        "route53"
    }

    fn supported_actions(&self) -> &[&str] {
        SUPPORTED_ACTIONS
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let resolved = match route(&req.method, &req.raw_path, &req.raw_query) {
            Some(r) => r,
            None => {
                return Err(aws_error(
                    StatusCode::NOT_FOUND,
                    "InvalidArgument",
                    format!("Unknown Route 53 route: {} {}", req.method, req.raw_path),
                ));
            }
        };

        match resolved.action {
            "CreateHostedZone" => self.create_hosted_zone(&req),
            "GetHostedZone" => self.get_hosted_zone(&resolved),
            "DeleteHostedZone" => self.delete_hosted_zone(&resolved),
            "ListHostedZones" => self.list_hosted_zones(&req),
            "ListHostedZonesByName" => self.list_hosted_zones_by_name(&req),
            "GetHostedZoneCount" => self.get_hosted_zone_count(),
            "UpdateHostedZoneComment" => self.update_hosted_zone_comment(&req, &resolved),
            "UpdateHostedZoneFeatures" => self.update_hosted_zone_features(&req, &resolved),
            "GetHostedZoneLimit" => self.get_hosted_zone_limit(&resolved),
            "ChangeResourceRecordSets" => self.change_resource_record_sets(&req, &resolved),
            "ListResourceRecordSets" => self.list_resource_record_sets(&req, &resolved),
            "GetChange" => self.get_change(&resolved),
            "TestDNSAnswer" => self.test_dns_answer(&req),
            "CreateHealthCheck" => self.create_health_check(&req),
            "GetHealthCheck" => self.get_health_check(&resolved),
            "UpdateHealthCheck" => self.update_health_check(&req, &resolved),
            "DeleteHealthCheck" => self.delete_health_check(&resolved),
            "ListHealthChecks" => self.list_health_checks(&req),
            "GetHealthCheckCount" => self.get_health_check_count(),
            "GetHealthCheckStatus" => self.get_health_check_status(&resolved),
            "GetHealthCheckLastFailureReason" => {
                self.get_health_check_last_failure_reason(&resolved)
            }
            "GetCheckerIpRanges" => self.get_checker_ip_ranges(),
            "CreateTrafficPolicy" => self.create_traffic_policy(&req),
            "CreateTrafficPolicyVersion" => self.create_traffic_policy_version(&req, &resolved),
            "GetTrafficPolicy" => self.get_traffic_policy(&resolved),
            "UpdateTrafficPolicyComment" => self.update_traffic_policy_comment(&req, &resolved),
            "DeleteTrafficPolicy" => self.delete_traffic_policy(&resolved),
            "ListTrafficPolicies" => self.list_traffic_policies(&req),
            "ListTrafficPolicyVersions" => self.list_traffic_policy_versions(&req, &resolved),
            "CreateTrafficPolicyInstance" => self.create_traffic_policy_instance(&req),
            "GetTrafficPolicyInstance" => self.get_traffic_policy_instance(&resolved),
            "UpdateTrafficPolicyInstance" => self.update_traffic_policy_instance(&req, &resolved),
            "DeleteTrafficPolicyInstance" => self.delete_traffic_policy_instance(&resolved),
            "ListTrafficPolicyInstances" => self.list_traffic_policy_instances(&req),
            "ListTrafficPolicyInstancesByHostedZone" => {
                self.list_traffic_policy_instances_by_hosted_zone(&req)
            }
            "ListTrafficPolicyInstancesByPolicy" => {
                self.list_traffic_policy_instances_by_policy(&req)
            }
            "GetTrafficPolicyInstanceCount" => self.get_traffic_policy_instance_count(),
            "GetDNSSEC" => self.get_dnssec(&resolved),
            "EnableHostedZoneDNSSEC" => self.enable_hosted_zone_dnssec(&resolved),
            "DisableHostedZoneDNSSEC" => self.disable_hosted_zone_dnssec(&resolved),
            "CreateKeySigningKey" => self.create_key_signing_key(&req),
            "DeleteKeySigningKey" => self.delete_key_signing_key(&resolved),
            "ActivateKeySigningKey" => self.activate_key_signing_key(&resolved),
            "DeactivateKeySigningKey" => self.deactivate_key_signing_key(&resolved),
            "CreateQueryLoggingConfig" => self.create_query_logging_config(&req),
            "GetQueryLoggingConfig" => self.get_query_logging_config(&resolved),
            "DeleteQueryLoggingConfig" => self.delete_query_logging_config(&resolved),
            "ListQueryLoggingConfigs" => self.list_query_logging_configs(&req),
            "CreateCidrCollection" => self.create_cidr_collection(&req),
            "ChangeCidrCollection" => self.change_cidr_collection(&req, &resolved),
            "DeleteCidrCollection" => self.delete_cidr_collection(&resolved),
            "ListCidrCollections" => self.list_cidr_collections(&req),
            "ListCidrLocations" => self.list_cidr_locations(&req, &resolved),
            "ListCidrBlocks" => self.list_cidr_blocks(&req, &resolved),
            "AssociateVPCWithHostedZone" => self.associate_vpc_with_hosted_zone(&req, &resolved),
            "DisassociateVPCFromHostedZone" => {
                self.disassociate_vpc_from_hosted_zone(&req, &resolved)
            }
            "CreateVPCAssociationAuthorization" => {
                self.create_vpc_association_authorization(&req, &resolved)
            }
            "DeleteVPCAssociationAuthorization" => {
                self.delete_vpc_association_authorization(&req, &resolved)
            }
            "ListVPCAssociationAuthorizations" => {
                self.list_vpc_association_authorizations(&req, &resolved)
            }
            "ListHostedZonesByVPC" => self.list_hosted_zones_by_vpc(&req),
            "CreateReusableDelegationSet" => self.create_reusable_delegation_set(&req),
            "GetReusableDelegationSet" => self.get_reusable_delegation_set(&resolved),
            "DeleteReusableDelegationSet" => self.delete_reusable_delegation_set(&resolved),
            "ListReusableDelegationSets" => self.list_reusable_delegation_sets(&req),
            "GetReusableDelegationSetLimit" => self.get_reusable_delegation_set_limit(&resolved),
            "ListGeoLocations" => self.list_geo_locations(&req),
            "GetGeoLocation" => self.get_geo_location(&req),
            "GetAccountLimit" => self.get_account_limit(&resolved),
            "ChangeTagsForResource" => self.change_tags_for_resource(&req, &resolved),
            "ListTagsForResource" => self.list_tags_for_resource(&resolved),
            "ListTagsForResources" => self.list_tags_for_resources(&req, &resolved),
            other => Err(aws_error(
                StatusCode::NOT_IMPLEMENTED,
                "InvalidAction",
                format!("Route 53 action {other} is not implemented yet"),
            )),
        }
    }
}

// ─── Hosted Zone handlers ────────────────────────────────────────────

impl Route53Service {
    fn create_hosted_zone(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let cfg: CreateHostedZoneRequest = xml_io::from_xml_root(&req.body)
            .map_err(|e| invalid_argument(format!("invalid CreateHostedZoneRequest XML: {e}")))?;
        if cfg.name.is_empty() {
            return Err(invalid_argument("Name is required"));
        }
        if cfg.caller_reference.is_empty() {
            return Err(invalid_argument("CallerReference is required"));
        }
        let mut name = cfg.name.clone();
        if !name.ends_with('.') {
            name.push('.');
        }
        let private_zone = cfg
            .hosted_zone_config
            .as_ref()
            .and_then(|c| c.private_zone)
            .unwrap_or(false);
        if private_zone && cfg.vpc.is_none() {
            return Err(invalid_argument("Private hosted zone must include a VPC"));
        }
        let comment = cfg
            .hosted_zone_config
            .as_ref()
            .and_then(|c| c.comment.clone());

        let mut state = self.state.write();
        let account = state
            .accounts
            .entry(DEFAULT_ACCOUNT.to_string())
            .or_default();
        if account
            .hosted_zones
            .values()
            .any(|z| z.caller_reference == cfg.caller_reference)
        {
            return Err(aws_error(
                StatusCode::CONFLICT,
                "HostedZoneAlreadyExists",
                format!(
                    "A hosted zone with the same caller reference already exists: {}",
                    cfg.caller_reference
                ),
            ));
        }
        let id = generate_zone_id();
        let now = Utc::now();
        let name_servers = synth_name_servers(&id);
        let vpcs = cfg.vpc.into_iter().collect();
        let default_records = if private_zone {
            Vec::new()
        } else {
            default_zone_records(&name, &name_servers)
        };
        let zone = StoredHostedZone {
            id: id.clone(),
            name: name.clone(),
            caller_reference: cfg.caller_reference,
            comment,
            private_zone,
            features: None,
            vpcs,
            delegation_set_id: cfg.delegation_set_id,
            name_servers: name_servers.clone(),
            created_time: now,
            resource_record_sets: default_records,
        };
        account.hosted_zones.insert(id.clone(), zone.clone());

        let change_id = generate_change_id();
        let change = StoredChange {
            id: change_id.clone(),
            status: "INSYNC".to_string(),
            submitted_at: now,
            comment: Some(format!("CreateHostedZone {}", id)),
        };
        account.changes.insert(change_id.clone(), change.clone());
        drop(state);

        let mut body = String::with_capacity(1024);
        body.push_str(XML_DECL);
        body.push_str(&format!("<CreateHostedZoneResponse xmlns=\"{NS}\">"));
        push_hosted_zone(&mut body, &zone);
        push_change_info(&mut body, &change);
        body.push_str("<DelegationSet>");
        if let Some(id) = &zone.delegation_set_id {
            body.push_str(&format!("<Id>{}</Id>", esc(id)));
        }
        body.push_str("<NameServers>");
        for ns in &zone.name_servers {
            body.push_str(&format!("<NameServer>{}</NameServer>", esc(ns)));
        }
        body.push_str("</NameServers>");
        body.push_str("</DelegationSet>");
        if !zone.vpcs.is_empty() {
            push_vpc_block(&mut body, "VPC", &zone.vpcs[0]);
        }
        body.push_str("</CreateHostedZoneResponse>");

        let mut headers = HeaderMap::new();
        if let Ok(loc) = http::HeaderValue::from_str(&format!("/2013-04-01/hostedzone/{}", zone.id))
        {
            headers.insert(http::header::LOCATION, loc);
        }
        Ok(xml_response(StatusCode::CREATED, body, headers))
    }

    fn get_hosted_zone(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let id = strip_zone_prefix(&id);
        let state = self.state.read();
        let account = state.accounts.get(DEFAULT_ACCOUNT);
        let zone = account
            .and_then(|a| a.hosted_zones.get(&id).cloned())
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        drop(state);
        let mut body = String::with_capacity(1024);
        body.push_str(XML_DECL);
        body.push_str(&format!("<GetHostedZoneResponse xmlns=\"{NS}\">"));
        push_hosted_zone(&mut body, &zone);
        body.push_str("<DelegationSet>");
        if let Some(id) = &zone.delegation_set_id {
            body.push_str(&format!("<Id>{}</Id>", esc(id)));
        }
        body.push_str("<NameServers>");
        for ns in &zone.name_servers {
            body.push_str(&format!("<NameServer>{}</NameServer>", esc(ns)));
        }
        body.push_str("</NameServers>");
        body.push_str("</DelegationSet>");
        if !zone.vpcs.is_empty() {
            body.push_str("<VPCs>");
            for v in &zone.vpcs {
                push_vpc_block(&mut body, "VPC", v);
            }
            body.push_str("</VPCs>");
        }
        body.push_str("</GetHostedZoneResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn delete_hosted_zone(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let id = strip_zone_prefix(&id);
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        let zone = account
            .hosted_zones
            .get(&id)
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        if zone
            .resource_record_sets
            .iter()
            .any(|r| !is_default_record(r, &zone.name))
        {
            return Err(aws_error(
                StatusCode::BAD_REQUEST,
                "HostedZoneNotEmpty",
                format!("HostedZone {} has user-managed resource record sets", id),
            ));
        }
        account.hosted_zones.remove(&id);
        let change_id = generate_change_id();
        let change = StoredChange {
            id: change_id.clone(),
            status: "INSYNC".to_string(),
            submitted_at: Utc::now(),
            comment: Some(format!("DeleteHostedZone {}", id)),
        };
        account.changes.insert(change_id.clone(), change.clone());
        drop(state);

        let mut body = String::with_capacity(256);
        body.push_str(XML_DECL);
        body.push_str(&format!("<DeleteHostedZoneResponse xmlns=\"{NS}\">"));
        push_change_info(&mut body, &change);
        body.push_str("</DeleteHostedZoneResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_hosted_zones(&self, _req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let state = self.state.read();
        let mut zones: Vec<StoredHostedZone> = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .map(|a| a.hosted_zones.values().cloned().collect())
            .unwrap_or_default();
        drop(state);
        zones.sort_by(|a, b| a.id.cmp(&b.id));
        let mut body = String::with_capacity(1024);
        body.push_str(XML_DECL);
        body.push_str(&format!("<ListHostedZonesResponse xmlns=\"{NS}\">"));
        body.push_str("<HostedZones>");
        for z in &zones {
            push_hosted_zone(&mut body, z);
        }
        body.push_str("</HostedZones>");
        body.push_str("<MaxItems>100</MaxItems>");
        body.push_str("<IsTruncated>false</IsTruncated>");
        body.push_str("</ListHostedZonesResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_hosted_zones_by_name(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let dns_name = req.query_params.get("dnsname").cloned();
        let state = self.state.read();
        let mut zones: Vec<StoredHostedZone> = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .map(|a| a.hosted_zones.values().cloned().collect())
            .unwrap_or_default();
        drop(state);
        zones.sort_by(|a, b| a.name.cmp(&b.name));
        if let Some(name) = &dns_name {
            let normalized = if name.ends_with('.') {
                name.clone()
            } else {
                format!("{name}.")
            };
            zones.retain(|z| z.name >= normalized);
        }
        let mut body = String::with_capacity(1024);
        body.push_str(XML_DECL);
        body.push_str(&format!("<ListHostedZonesByNameResponse xmlns=\"{NS}\">"));
        body.push_str("<HostedZones>");
        for z in &zones {
            push_hosted_zone(&mut body, z);
        }
        body.push_str("</HostedZones>");
        if let Some(name) = &dns_name {
            body.push_str(&format!("<DNSName>{}</DNSName>", esc(name)));
        }
        body.push_str("<MaxItems>100</MaxItems>");
        body.push_str("<IsTruncated>false</IsTruncated>");
        body.push_str("</ListHostedZonesByNameResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn get_hosted_zone_count(&self) -> Result<AwsResponse, AwsServiceError> {
        let state = self.state.read();
        let count = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .map(|a| a.hosted_zones.len())
            .unwrap_or(0);
        drop(state);
        let mut body = String::with_capacity(128);
        body.push_str(XML_DECL);
        body.push_str(&format!("<GetHostedZoneCountResponse xmlns=\"{NS}\">"));
        body.push_str(&format!("<HostedZoneCount>{}</HostedZoneCount>", count));
        body.push_str("</GetHostedZoneCountResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn update_hosted_zone_comment(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let id = strip_zone_prefix(&id);
        let cfg: UpdateHostedZoneCommentRequest =
            xml_io::from_xml_root(&req.body).map_err(|e| {
                invalid_argument(format!("invalid UpdateHostedZoneCommentRequest XML: {e}"))
            })?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        let zone = account
            .hosted_zones
            .get_mut(&id)
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        zone.comment = cfg.comment;
        let snap = zone.clone();
        drop(state);
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<UpdateHostedZoneCommentResponse xmlns=\"{NS}\">"));
        push_hosted_zone(&mut body, &snap);
        body.push_str("</UpdateHostedZoneCommentResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn update_hosted_zone_features(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let id = strip_zone_prefix(&id);
        let cfg: UpdateHostedZoneFeaturesRequest =
            xml_io::from_xml_root(&req.body).map_err(|e| {
                invalid_argument(format!("invalid UpdateHostedZoneFeaturesRequest XML: {e}"))
            })?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        let zone = account
            .hosted_zones
            .get_mut(&id)
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        zone.features = Some(crate::model::HostedZoneFeatures {
            enable_accelerated_recovery: cfg.enable_accelerated_recovery,
        });
        let snap = zone.clone();
        drop(state);
        let mut body = String::with_capacity(256);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<UpdateHostedZoneFeaturesResponse xmlns=\"{NS}\">"
        ));
        push_hosted_zone(&mut body, &snap);
        body.push_str("</UpdateHostedZoneFeaturesResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn get_hosted_zone_limit(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let id = strip_zone_prefix(&id);
        let lim_type = route
            .second_id
            .clone()
            .ok_or_else(|| invalid_argument("limit Type is required"))?;
        let state = self.state.read();
        let zone = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.hosted_zones.get(&id).cloned())
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        drop(state);
        let (value, count) = match lim_type.as_str() {
            "MAX_RRSETS_BY_ZONE" => (10000_u64, zone.resource_record_sets.len() as u64),
            "MAX_VPCS_ASSOCIATED_BY_ZONE" => (300_u64, zone.vpcs.len() as u64),
            other => {
                return Err(invalid_argument(format!(
                    "Unknown hosted zone limit type: {other}"
                )));
            }
        };
        let mut body = String::with_capacity(256);
        body.push_str(XML_DECL);
        body.push_str(&format!("<GetHostedZoneLimitResponse xmlns=\"{NS}\">"));
        body.push_str(&format!(
            "<Limit><Type>{}</Type><Value>{}</Value></Limit>",
            esc(&lim_type),
            value
        ));
        body.push_str(&format!("<Count>{}</Count>", count));
        body.push_str("</GetHostedZoneLimitResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

// ─── Resource Record Set handlers ────────────────────────────────────

impl Route53Service {
    fn change_resource_record_sets(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let id = strip_zone_prefix(&id);
        let cfg: ChangeResourceRecordSetsRequest =
            xml_io::from_xml_root(&req.body).map_err(|e| {
                invalid_argument(format!("invalid ChangeResourceRecordSetsRequest XML: {e}"))
            })?;
        if cfg.change_batch.changes.change.is_empty() {
            return Err(invalid_argument("ChangeBatch.Changes is empty"));
        }
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        let zone = account
            .hosted_zones
            .get_mut(&id)
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        // AWS applies a ChangeBatch atomically: either every change succeeds
        // or none do. Stage the mutations against a clone first; only swap
        // the live record set in once every action validates.
        let mut working = zone.resource_record_sets.clone();
        for ch in &cfg.change_batch.changes.change {
            let action = ch.action.to_uppercase();
            let rec = normalize_rrset(&ch.resource_record_set);
            match action.as_str() {
                "CREATE" => {
                    if working.iter().any(|r| rrset_matches(r, &rec)) {
                        return Err(invalid_change_batch(format!(
                            "Tried to create resource record set [name='{}', type='{}'] but it already exists",
                            rec.name, rec.record_type
                        )));
                    }
                    working.push(rec);
                }
                "UPSERT" => {
                    let pos = working.iter().position(|r| rrset_matches(r, &rec));
                    if let Some(p) = pos {
                        working[p] = rec;
                    } else {
                        working.push(rec);
                    }
                }
                "DELETE" => {
                    let pos = working.iter().position(|r| rrset_matches(r, &rec));
                    let p = pos.ok_or_else(|| {
                        invalid_change_batch(format!(
                            "Tried to delete resource record set [name='{}', type='{}'] but it was not found",
                            rec.name, rec.record_type
                        ))
                    })?;
                    if is_default_record(&working[p], &zone.name) {
                        return Err(invalid_change_batch(
                            "Cannot delete default SOA or NS record",
                        ));
                    }
                    working.remove(p);
                }
                other => {
                    return Err(invalid_change_batch(format!(
                        "Unknown change action: {other}"
                    )));
                }
            }
        }
        zone.resource_record_sets = working;
        let change_id = generate_change_id();
        let change = StoredChange {
            id: change_id.clone(),
            status: "INSYNC".to_string(),
            submitted_at: Utc::now(),
            comment: cfg.change_batch.comment,
        };
        account.changes.insert(change_id.clone(), change.clone());
        drop(state);
        let mut body = String::with_capacity(256);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<ChangeResourceRecordSetsResponse xmlns=\"{NS}\">"
        ));
        push_change_info(&mut body, &change);
        body.push_str("</ChangeResourceRecordSetsResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_resource_record_sets(
        &self,
        _req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let id = strip_zone_prefix(&id);
        let state = self.state.read();
        let zone = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.hosted_zones.get(&id).cloned())
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        drop(state);
        let mut body = String::with_capacity(1024);
        body.push_str(XML_DECL);
        body.push_str(&format!("<ListResourceRecordSetsResponse xmlns=\"{NS}\">"));
        body.push_str("<ResourceRecordSets>");
        for r in &zone.resource_record_sets {
            push_rrset(&mut body, r);
        }
        body.push_str("</ResourceRecordSets>");
        body.push_str("<IsTruncated>false</IsTruncated>");
        body.push_str("<MaxItems>100</MaxItems>");
        body.push_str("</ListResourceRecordSetsResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

// ─── Change tracking + DNS test ──────────────────────────────────────

impl Route53Service {
    fn get_change(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let state = self.state.read();
        let account = state.accounts.get(DEFAULT_ACCOUNT);
        let change = account
            .and_then(|a| a.changes.get(&id).cloned())
            .ok_or_else(|| {
                aws_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchChange",
                    format!("Change {} not found", id),
                )
            })?;
        drop(state);
        let mut body = String::with_capacity(256);
        body.push_str(XML_DECL);
        body.push_str(&format!("<GetChangeResponse xmlns=\"{NS}\">"));
        push_change_info(&mut body, &change);
        body.push_str("</GetChangeResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn test_dns_answer(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let zone_id = req
            .query_params
            .get("hostedzoneid")
            .cloned()
            .ok_or_else(|| invalid_argument("hostedzoneid query parameter is required"))?;
        let record_name = req
            .query_params
            .get("recordname")
            .cloned()
            .ok_or_else(|| invalid_argument("recordname query parameter is required"))?;
        let record_type = req
            .query_params
            .get("recordtype")
            .cloned()
            .ok_or_else(|| invalid_argument("recordtype query parameter is required"))?;
        let resolver_ip = req
            .query_params
            .get("resolverip")
            .cloned()
            .unwrap_or_else(|| "8.8.8.8".to_string());
        let edns0_subnet = req.query_params.get("edns0clientsubnetip").cloned();
        let zone_id = strip_zone_prefix(&zone_id);
        let state = self.state.read();
        let zone = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.hosted_zones.get(&zone_id).cloned())
            .ok_or_else(|| no_such_hosted_zone(&zone_id))?;
        drop(state);
        let normalized_name = if record_name.ends_with('.') {
            record_name.clone()
        } else {
            format!("{record_name}.")
        };
        let answers: Vec<String> = zone
            .resource_record_sets
            .iter()
            .find(|r| r.name == normalized_name && r.record_type == record_type)
            .map(|r| {
                r.resource_records
                    .as_ref()
                    .map(|rr| rr.resource_record.iter().map(|x| x.value.clone()).collect())
                    .unwrap_or_default()
            })
            .unwrap_or_default();
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<TestDNSAnswerResponse xmlns=\"{NS}\">"));
        body.push_str(&format!("<Nameserver>{}</Nameserver>", esc(&resolver_ip)));
        body.push_str(&format!("<RecordName>{}</RecordName>", esc(&record_name)));
        body.push_str(&format!("<RecordType>{}</RecordType>", esc(&record_type)));
        body.push_str("<RecordData>");
        for v in &answers {
            body.push_str(&format!("<RecordDataEntry>{}</RecordDataEntry>", esc(v)));
        }
        body.push_str("</RecordData>");
        body.push_str("<ResponseCode>NOERROR</ResponseCode>");
        body.push_str(&format!(
            "<Protocol>{}</Protocol>",
            if edns0_subnet.is_some() {
                "EDNS0"
            } else {
                "UDP"
            }
        ));
        body.push_str("</TestDNSAnswerResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

// ─── Health Check handlers ───────────────────────────────────────────

impl Route53Service {
    fn create_health_check(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let cfg: CreateHealthCheckRequest = xml_io::from_xml_root(&req.body)
            .map_err(|e| invalid_argument(format!("invalid CreateHealthCheckRequest XML: {e}")))?;
        if cfg.caller_reference.is_empty() {
            return Err(invalid_argument("CallerReference is required"));
        }
        if cfg.health_check_config.health_check_type.is_empty() {
            return Err(invalid_argument("HealthCheckConfig.Type is required"));
        }
        let mut state = self.state.write();
        let account = state
            .accounts
            .entry(DEFAULT_ACCOUNT.to_string())
            .or_default();
        if let Some(existing) = account
            .health_checks
            .values()
            .find(|h| h.caller_reference == cfg.caller_reference)
        {
            return Err(aws_error(
                StatusCode::CONFLICT,
                "HealthCheckAlreadyExists",
                format!(
                    "A health check with the same CallerReference already exists: {} (id={})",
                    cfg.caller_reference, existing.id
                ),
            ));
        }
        let id = generate_health_check_id();
        let stored = StoredHealthCheck {
            id: id.clone(),
            caller_reference: cfg.caller_reference,
            version: 1,
            config: cfg.health_check_config,
            created_time: Utc::now(),
        };
        account.health_checks.insert(id.clone(), stored.clone());
        drop(state);
        let mut body = String::with_capacity(1024);
        body.push_str(XML_DECL);
        body.push_str(&format!("<CreateHealthCheckResponse xmlns=\"{NS}\">"));
        push_health_check(&mut body, &stored);
        body.push_str("</CreateHealthCheckResponse>");
        let mut headers = HeaderMap::new();
        if let Ok(loc) =
            http::HeaderValue::from_str(&format!("/2013-04-01/healthcheck/{}", stored.id))
        {
            headers.insert(http::header::LOCATION, loc);
        }
        Ok(xml_response(StatusCode::CREATED, body, headers))
    }

    fn get_health_check(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let state = self.state.read();
        let hc = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.health_checks.get(&id).cloned())
            .ok_or_else(|| no_such_health_check(&id))?;
        drop(state);
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<GetHealthCheckResponse xmlns=\"{NS}\">"));
        push_health_check(&mut body, &hc);
        body.push_str("</GetHealthCheckResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn update_health_check(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let cfg: UpdateHealthCheckRequest = xml_io::from_xml_root(&req.body)
            .map_err(|e| invalid_argument(format!("invalid UpdateHealthCheckRequest XML: {e}")))?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_health_check(&id))?;
        let hc = account
            .health_checks
            .get_mut(&id)
            .ok_or_else(|| no_such_health_check(&id))?;
        if let Some(client_version) = cfg.health_check_version {
            if client_version != hc.version {
                return Err(aws_error(
                    StatusCode::CONFLICT,
                    "HealthCheckVersionMismatch",
                    format!(
                        "Provided HealthCheckVersion ({}) does not match the current version ({})",
                        client_version, hc.version
                    ),
                ));
            }
        }
        if let Some(v) = cfg.ip_address {
            hc.config.ip_address = Some(v);
        }
        if let Some(v) = cfg.port {
            hc.config.port = Some(v);
        }
        if let Some(v) = cfg.resource_path {
            hc.config.resource_path = Some(v);
        }
        if let Some(v) = cfg.fully_qualified_domain_name {
            hc.config.fully_qualified_domain_name = Some(v);
        }
        if let Some(v) = cfg.search_string {
            hc.config.search_string = Some(v);
        }
        if let Some(v) = cfg.failure_threshold {
            hc.config.failure_threshold = Some(v);
        }
        if let Some(v) = cfg.inverted {
            hc.config.inverted = Some(v);
        }
        if let Some(v) = cfg.disabled {
            hc.config.disabled = Some(v);
        }
        if let Some(v) = cfg.health_threshold {
            hc.config.health_threshold = Some(v);
        }
        if let Some(v) = cfg.child_health_checks {
            hc.config.child_health_checks = Some(v);
        }
        if let Some(v) = cfg.enable_sni {
            hc.config.enable_sni = Some(v);
        }
        if let Some(v) = cfg.regions {
            hc.config.regions = Some(v);
        }
        if let Some(v) = cfg.alarm_identifier {
            hc.config.alarm_identifier = Some(v);
        }
        if let Some(v) = cfg.insufficient_data_health_status {
            hc.config.insufficient_data_health_status = Some(v);
        }
        if let Some(reset) = cfg.reset_elements {
            for name in reset.resettable_element_name {
                match name.as_str() {
                    "ChildHealthChecks" => hc.config.child_health_checks = None,
                    "FullyQualifiedDomainName" => hc.config.fully_qualified_domain_name = None,
                    "Regions" => hc.config.regions = None,
                    "ResourcePath" => hc.config.resource_path = None,
                    _ => {}
                }
            }
        }
        hc.version += 1;
        let snap = hc.clone();
        drop(state);
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<UpdateHealthCheckResponse xmlns=\"{NS}\">"));
        push_health_check(&mut body, &snap);
        body.push_str("</UpdateHealthCheckResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn delete_health_check(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_health_check(&id))?;
        if !account.health_checks.contains_key(&id) {
            return Err(no_such_health_check(&id));
        }
        // Real Route 53 returns HealthCheckInUse if any record set still
        // references the health check. Mirror that across all hosted zones.
        for zone in account.hosted_zones.values() {
            for rrset in &zone.resource_record_sets {
                if rrset.health_check_id.as_deref() == Some(id.as_str()) {
                    return Err(aws_error(
                        StatusCode::BAD_REQUEST,
                        "HealthCheckInUse",
                        format!(
                            "Health check {} is in use by record set {} ({}) in zone {}",
                            id, rrset.name, rrset.record_type, zone.id
                        ),
                    ));
                }
            }
        }
        account.health_checks.remove(&id);
        drop(state);
        let mut body = String::with_capacity(128);
        body.push_str(XML_DECL);
        body.push_str(&format!("<DeleteHealthCheckResponse xmlns=\"{NS}\"/>"));
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_health_checks(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let marker = req.query_params.get("marker").cloned();
        let max_items: usize = req
            .query_params
            .get("maxitems")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);
        let state = self.state.read();
        let mut hcs: Vec<StoredHealthCheck> = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .map(|a| a.health_checks.values().cloned().collect())
            .unwrap_or_default();
        drop(state);
        hcs.sort_by(|a, b| a.id.cmp(&b.id));
        let start = match &marker {
            Some(m) => hcs
                .iter()
                .position(|h| h.id.as_str() >= m.as_str())
                .unwrap_or(hcs.len()),
            None => 0,
        };
        let slice: Vec<StoredHealthCheck> =
            hcs.iter().skip(start).take(max_items).cloned().collect();
        let next_marker = if start + slice.len() < hcs.len() {
            Some(hcs[start + slice.len()].id.clone())
        } else {
            None
        };
        let mut body = String::with_capacity(1024);
        body.push_str(XML_DECL);
        body.push_str(&format!("<ListHealthChecksResponse xmlns=\"{NS}\">"));
        body.push_str("<HealthChecks>");
        for hc in &slice {
            push_health_check(&mut body, hc);
        }
        body.push_str("</HealthChecks>");
        if let Some(m) = &marker {
            body.push_str(&format!("<Marker>{}</Marker>", esc(m)));
        } else {
            body.push_str("<Marker></Marker>");
        }
        body.push_str(&format!("<MaxItems>{}</MaxItems>", max_items));
        body.push_str(&format!(
            "<IsTruncated>{}</IsTruncated>",
            next_marker.is_some()
        ));
        if let Some(nm) = &next_marker {
            body.push_str(&format!("<NextMarker>{}</NextMarker>", esc(nm)));
        }
        body.push_str("</ListHealthChecksResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn get_health_check_count(&self) -> Result<AwsResponse, AwsServiceError> {
        let state = self.state.read();
        let count = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .map(|a| a.health_checks.len())
            .unwrap_or(0);
        drop(state);
        let mut body = String::with_capacity(128);
        body.push_str(XML_DECL);
        body.push_str(&format!("<GetHealthCheckCountResponse xmlns=\"{NS}\">"));
        body.push_str(&format!("<HealthCheckCount>{}</HealthCheckCount>", count));
        body.push_str("</GetHealthCheckCountResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn get_health_check_status(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let state = self.state.read();
        let hc = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.health_checks.get(&id).cloned())
            .ok_or_else(|| no_such_health_check(&id))?;
        drop(state);
        let now = rfc3339(&Utc::now());
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<GetHealthCheckStatusResponse xmlns=\"{NS}\">"));
        body.push_str("<HealthCheckObservations>");
        for region in checker_regions() {
            body.push_str("<HealthCheckObservation>");
            body.push_str(&format!("<Region>{}</Region>", esc(region)));
            body.push_str(&format!(
                "<IPAddress>{}</IPAddress>",
                esc(&checker_ip_for_region(region))
            ));
            body.push_str("<StatusReport>");
            body.push_str("<Status>Success: HTTP Status Code 200, OK.</Status>");
            body.push_str(&format!("<CheckedTime>{}</CheckedTime>", now));
            body.push_str("</StatusReport>");
            body.push_str("</HealthCheckObservation>");
        }
        body.push_str("</HealthCheckObservations>");
        body.push_str("</GetHealthCheckStatusResponse>");
        let _ = hc;
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn get_health_check_last_failure_reason(
        &self,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let state = self.state.read();
        let _hc = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.health_checks.get(&id).cloned())
            .ok_or_else(|| no_such_health_check(&id))?;
        drop(state);
        // Real Route 53 returns an empty observations list when the
        // checker has not seen a failure yet. fakecloud has no live
        // checker, so the list is always empty.
        let mut body = String::with_capacity(256);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<GetHealthCheckLastFailureReasonResponse xmlns=\"{NS}\">"
        ));
        body.push_str("<HealthCheckObservations></HealthCheckObservations>");
        body.push_str("</GetHealthCheckLastFailureReasonResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn get_checker_ip_ranges(&self) -> Result<AwsResponse, AwsServiceError> {
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<GetCheckerIpRangesResponse xmlns=\"{NS}\">"));
        body.push_str("<CheckerIpRanges>");
        for cidr in CHECKER_IP_RANGES {
            body.push_str(&format!("<member>{}</member>", esc(cidr)));
        }
        body.push_str("</CheckerIpRanges>");
        body.push_str("</GetCheckerIpRangesResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

// ─── Traffic Policy handlers ─────────────────────────────────────────

impl Route53Service {
    fn create_traffic_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let cfg: CreateTrafficPolicyRequest = xml_io::from_xml_root(&req.body).map_err(|e| {
            invalid_argument(format!("invalid CreateTrafficPolicyRequest XML: {e}"))
        })?;
        if cfg.name.is_empty() {
            return Err(invalid_argument("Name is required"));
        }
        if cfg.document.is_empty() {
            return Err(invalid_argument("Document is required"));
        }
        let policy_type = infer_policy_type(&cfg.document);
        let mut state = self.state.write();
        let account = state
            .accounts
            .entry(DEFAULT_ACCOUNT.to_string())
            .or_default();
        // Match real Route 53: name uniqueness applies across all versions
        // of every existing policy. Checking only version == 1 would let a
        // duplicate name slip through whenever the v1 row had been deleted
        // but later versions remained.
        if account
            .traffic_policies
            .values()
            .any(|p| p.name == cfg.name)
        {
            return Err(aws_error(
                StatusCode::CONFLICT,
                "TrafficPolicyAlreadyExists",
                format!("A traffic policy named '{}' already exists", cfg.name),
            ));
        }
        let id = generate_traffic_policy_id();
        let stored = StoredTrafficPolicy {
            id: id.clone(),
            version: 1,
            name: cfg.name,
            policy_type,
            document: cfg.document,
            comment: cfg.comment,
            created_time: Utc::now(),
        };
        account
            .traffic_policies
            .insert((id.clone(), 1), stored.clone());
        drop(state);
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<CreateTrafficPolicyResponse xmlns=\"{NS}\">"));
        push_traffic_policy(&mut body, &stored);
        body.push_str("</CreateTrafficPolicyResponse>");
        let mut headers = HeaderMap::new();
        if let Ok(loc) = http::HeaderValue::from_str(&format!(
            "/2013-04-01/trafficpolicy/{}/{}",
            stored.id, stored.version
        )) {
            headers.insert(http::header::LOCATION, loc);
        }
        Ok(xml_response(StatusCode::CREATED, body, headers))
    }

    fn create_traffic_policy_version(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let cfg: CreateTrafficPolicyVersionRequest =
            xml_io::from_xml_root(&req.body).map_err(|e| {
                invalid_argument(format!(
                    "invalid CreateTrafficPolicyVersionRequest XML: {e}"
                ))
            })?;
        if cfg.document.is_empty() {
            return Err(invalid_argument("Document is required"));
        }
        let policy_type = infer_policy_type(&cfg.document);
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_traffic_policy(&id))?;
        let existing_versions: Vec<i64> = account
            .traffic_policies
            .keys()
            .filter(|(pid, _)| pid == &id)
            .map(|(_, v)| *v)
            .collect();
        if existing_versions.is_empty() {
            return Err(no_such_traffic_policy(&id));
        }
        let next_version = existing_versions.iter().max().copied().unwrap_or(0) + 1;
        // Borrow name from the latest existing version so the new one stays consistent.
        let (name, original_comment) = {
            let latest_v = existing_versions.iter().max().copied().unwrap();
            let p = account
                .traffic_policies
                .get(&(id.clone(), latest_v))
                .unwrap();
            (p.name.clone(), p.comment.clone())
        };
        let stored = StoredTrafficPolicy {
            id: id.clone(),
            version: next_version,
            name,
            policy_type,
            document: cfg.document,
            comment: cfg.comment.or(original_comment),
            created_time: Utc::now(),
        };
        account
            .traffic_policies
            .insert((id.clone(), next_version), stored.clone());
        drop(state);
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<CreateTrafficPolicyVersionResponse xmlns=\"{NS}\">"
        ));
        push_traffic_policy(&mut body, &stored);
        body.push_str("</CreateTrafficPolicyVersionResponse>");
        let mut headers = HeaderMap::new();
        if let Ok(loc) = http::HeaderValue::from_str(&format!(
            "/2013-04-01/trafficpolicy/{}/{}",
            stored.id, stored.version
        )) {
            headers.insert(http::header::LOCATION, loc);
        }
        Ok(xml_response(StatusCode::CREATED, body, headers))
    }

    fn get_traffic_policy(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let version = require_version(route)?;
        let state = self.state.read();
        let p = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.traffic_policies.get(&(id.clone(), version)).cloned())
            .ok_or_else(|| no_such_traffic_policy(&id))?;
        drop(state);
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<GetTrafficPolicyResponse xmlns=\"{NS}\">"));
        push_traffic_policy(&mut body, &p);
        body.push_str("</GetTrafficPolicyResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn update_traffic_policy_comment(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let version = require_version(route)?;
        let cfg: UpdateTrafficPolicyCommentRequest =
            xml_io::from_xml_root(&req.body).map_err(|e| {
                invalid_argument(format!(
                    "invalid UpdateTrafficPolicyCommentRequest XML: {e}"
                ))
            })?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_traffic_policy(&id))?;
        let p = account
            .traffic_policies
            .get_mut(&(id.clone(), version))
            .ok_or_else(|| no_such_traffic_policy(&id))?;
        p.comment = Some(cfg.comment);
        let snap = p.clone();
        drop(state);
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<UpdateTrafficPolicyCommentResponse xmlns=\"{NS}\">"
        ));
        push_traffic_policy(&mut body, &snap);
        body.push_str("</UpdateTrafficPolicyCommentResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn delete_traffic_policy(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let version = require_version(route)?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_traffic_policy(&id))?;
        if !account
            .traffic_policies
            .contains_key(&(id.clone(), version))
        {
            return Err(no_such_traffic_policy(&id));
        }
        // TrafficPolicyInUse if any instance still references this (id, version).
        if account
            .traffic_policy_instances
            .values()
            .any(|i| i.traffic_policy_id == id && i.traffic_policy_version == version)
        {
            return Err(aws_error(
                StatusCode::BAD_REQUEST,
                "TrafficPolicyInUse",
                format!("Traffic policy {}/{} is in use by an instance", id, version),
            ));
        }
        account.traffic_policies.remove(&(id, version));
        drop(state);
        let mut body = String::with_capacity(128);
        body.push_str(XML_DECL);
        body.push_str(&format!("<DeleteTrafficPolicyResponse xmlns=\"{NS}\"/>"));
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_traffic_policies(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let marker = req.query_params.get("trafficpolicyid").cloned();
        let max_items: usize = req
            .query_params
            .get("maxitems")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);
        let state = self.state.read();
        // Group by policy id; emit only the latest version of each.
        let mut latest: BTreeMap<String, StoredTrafficPolicy> = BTreeMap::new();
        let mut counts: BTreeMap<String, i64> = BTreeMap::new();
        if let Some(account) = state.accounts.get(DEFAULT_ACCOUNT) {
            for p in account.traffic_policies.values() {
                let entry = latest.entry(p.id.clone()).or_insert_with(|| p.clone());
                if p.version > entry.version {
                    *entry = p.clone();
                }
                *counts.entry(p.id.clone()).or_insert(0) += 1;
            }
        }
        drop(state);
        let mut summaries: Vec<StoredTrafficPolicy> = latest.into_values().collect();
        summaries.sort_by(|a, b| a.id.cmp(&b.id));
        let start = match &marker {
            Some(m) => summaries
                .iter()
                .position(|p| p.id.as_str() >= m.as_str())
                .unwrap_or(summaries.len()),
            None => 0,
        };
        let slice: Vec<&StoredTrafficPolicy> =
            summaries.iter().skip(start).take(max_items).collect();
        let next_marker = if start + slice.len() < summaries.len() {
            Some(summaries[start + slice.len()].id.clone())
        } else {
            None
        };
        let mut body = String::with_capacity(1024);
        body.push_str(XML_DECL);
        body.push_str(&format!("<ListTrafficPoliciesResponse xmlns=\"{NS}\">"));
        body.push_str("<TrafficPolicySummaries>");
        for p in &slice {
            push_traffic_policy_summary(&mut body, p, counts.get(&p.id).copied().unwrap_or(1));
        }
        body.push_str("</TrafficPolicySummaries>");
        body.push_str(&format!(
            "<IsTruncated>{}</IsTruncated>",
            next_marker.is_some()
        ));
        body.push_str(&format!("<MaxItems>{}</MaxItems>", max_items));
        if let Some(nm) = &next_marker {
            body.push_str(&format!(
                "<TrafficPolicyIdMarker>{}</TrafficPolicyIdMarker>",
                esc(nm)
            ));
        }
        body.push_str("</ListTrafficPoliciesResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_traffic_policy_versions(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let marker: Option<i64> = req
            .query_params
            .get("trafficpolicyversion")
            .and_then(|s| s.parse().ok());
        let max_items: usize = req
            .query_params
            .get("maxitems")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);
        let state = self.state.read();
        let mut versions: Vec<StoredTrafficPolicy> = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .map(|a| {
                a.traffic_policies
                    .values()
                    .filter(|p| p.id == id)
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        drop(state);
        if versions.is_empty() {
            return Err(no_such_traffic_policy(&id));
        }
        versions.sort_by_key(|p| p.version);
        let start = match marker {
            Some(m) => versions
                .iter()
                .position(|p| p.version >= m)
                .unwrap_or(versions.len()),
            None => 0,
        };
        let slice: Vec<&StoredTrafficPolicy> =
            versions.iter().skip(start).take(max_items).collect();
        let next_marker = if start + slice.len() < versions.len() {
            Some(versions[start + slice.len()].version)
        } else {
            None
        };
        let mut body = String::with_capacity(1024);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<ListTrafficPolicyVersionsResponse xmlns=\"{NS}\">"
        ));
        body.push_str("<TrafficPolicies>");
        for p in &slice {
            push_traffic_policy(&mut body, p);
        }
        body.push_str("</TrafficPolicies>");
        body.push_str(&format!(
            "<IsTruncated>{}</IsTruncated>",
            next_marker.is_some()
        ));
        body.push_str(&format!("<MaxItems>{}</MaxItems>", max_items));
        if let Some(nm) = next_marker {
            body.push_str(&format!(
                "<TrafficPolicyVersionMarker>{}</TrafficPolicyVersionMarker>",
                nm
            ));
        } else {
            body.push_str("<TrafficPolicyVersionMarker></TrafficPolicyVersionMarker>");
        }
        body.push_str("</ListTrafficPolicyVersionsResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

// ─── Traffic Policy Instance handlers ────────────────────────────────

impl Route53Service {
    fn create_traffic_policy_instance(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let cfg: CreateTrafficPolicyInstanceRequest =
            xml_io::from_xml_root(&req.body).map_err(|e| {
                invalid_argument(format!(
                    "invalid CreateTrafficPolicyInstanceRequest XML: {e}"
                ))
            })?;
        if cfg.hosted_zone_id.is_empty() || cfg.name.is_empty() || cfg.traffic_policy_id.is_empty()
        {
            return Err(invalid_argument(
                "HostedZoneId, Name, and TrafficPolicyId are required",
            ));
        }
        let zone_id = strip_zone_prefix(&cfg.hosted_zone_id);
        let mut state = self.state.write();
        let account = state
            .accounts
            .entry(DEFAULT_ACCOUNT.to_string())
            .or_default();
        if !account.hosted_zones.contains_key(&zone_id) {
            return Err(no_such_hosted_zone(&zone_id));
        }
        let policy = account
            .traffic_policies
            .get(&(cfg.traffic_policy_id.clone(), cfg.traffic_policy_version))
            .cloned()
            .ok_or_else(|| no_such_traffic_policy(&cfg.traffic_policy_id))?;
        let mut name = cfg.name.clone();
        if !name.ends_with('.') {
            name.push('.');
        }
        // Real Route 53 rejects a duplicate (HostedZoneId, Name, Type) instance
        // with TrafficPolicyInstanceAlreadyExists. Mirror that.
        if account.traffic_policy_instances.values().any(|i| {
            i.hosted_zone_id == zone_id
                && i.name == name
                && i.traffic_policy_type == policy.policy_type
        }) {
            return Err(aws_error(
                StatusCode::CONFLICT,
                "TrafficPolicyInstanceAlreadyExists",
                format!(
                    "A traffic policy instance for {} ({}) already exists in zone {}",
                    name, policy.policy_type, zone_id
                ),
            ));
        }
        let id = generate_traffic_policy_instance_id();
        let stored = StoredTrafficPolicyInstance {
            id: id.clone(),
            hosted_zone_id: zone_id,
            name,
            ttl: cfg.ttl,
            state: "Applied".to_string(),
            message: String::new(),
            traffic_policy_id: cfg.traffic_policy_id,
            traffic_policy_version: cfg.traffic_policy_version,
            traffic_policy_type: policy.policy_type,
            created_time: Utc::now(),
        };
        account
            .traffic_policy_instances
            .insert(id.clone(), stored.clone());
        drop(state);
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<CreateTrafficPolicyInstanceResponse xmlns=\"{NS}\">"
        ));
        push_traffic_policy_instance(&mut body, &stored);
        body.push_str("</CreateTrafficPolicyInstanceResponse>");
        let mut headers = HeaderMap::new();
        if let Ok(loc) =
            http::HeaderValue::from_str(&format!("/2013-04-01/trafficpolicyinstance/{}", stored.id))
        {
            headers.insert(http::header::LOCATION, loc);
        }
        Ok(xml_response(StatusCode::CREATED, body, headers))
    }

    fn get_traffic_policy_instance(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let state = self.state.read();
        let i = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.traffic_policy_instances.get(&id).cloned())
            .ok_or_else(|| no_such_traffic_policy_instance(&id))?;
        drop(state);
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<GetTrafficPolicyInstanceResponse xmlns=\"{NS}\">"
        ));
        push_traffic_policy_instance(&mut body, &i);
        body.push_str("</GetTrafficPolicyInstanceResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn update_traffic_policy_instance(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let cfg: UpdateTrafficPolicyInstanceRequest =
            xml_io::from_xml_root(&req.body).map_err(|e| {
                invalid_argument(format!(
                    "invalid UpdateTrafficPolicyInstanceRequest XML: {e}"
                ))
            })?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_traffic_policy_instance(&id))?;
        let policy = account
            .traffic_policies
            .get(&(cfg.traffic_policy_id.clone(), cfg.traffic_policy_version))
            .cloned()
            .ok_or_else(|| no_such_traffic_policy(&cfg.traffic_policy_id))?;
        let i = account
            .traffic_policy_instances
            .get_mut(&id)
            .ok_or_else(|| no_such_traffic_policy_instance(&id))?;
        i.ttl = cfg.ttl;
        i.traffic_policy_id = cfg.traffic_policy_id;
        i.traffic_policy_version = cfg.traffic_policy_version;
        i.traffic_policy_type = policy.policy_type;
        i.state = "Applied".to_string();
        let snap = i.clone();
        drop(state);
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<UpdateTrafficPolicyInstanceResponse xmlns=\"{NS}\">"
        ));
        push_traffic_policy_instance(&mut body, &snap);
        body.push_str("</UpdateTrafficPolicyInstanceResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn delete_traffic_policy_instance(
        &self,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_traffic_policy_instance(&id))?;
        if account.traffic_policy_instances.remove(&id).is_none() {
            return Err(no_such_traffic_policy_instance(&id));
        }
        drop(state);
        let mut body = String::with_capacity(128);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<DeleteTrafficPolicyInstanceResponse xmlns=\"{NS}\"/>"
        ));
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_traffic_policy_instances(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let max_items: usize = req
            .query_params
            .get("maxitems")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);
        let state = self.state.read();
        let mut instances: Vec<StoredTrafficPolicyInstance> = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .map(|a| a.traffic_policy_instances.values().cloned().collect())
            .unwrap_or_default();
        drop(state);
        instances.sort_by(|a, b| a.id.cmp(&b.id));
        let slice: Vec<&StoredTrafficPolicyInstance> = instances.iter().take(max_items).collect();
        let next_marker = if slice.len() < instances.len() {
            Some(instances[slice.len()].id.clone())
        } else {
            None
        };
        let mut body = String::with_capacity(1024);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<ListTrafficPolicyInstancesResponse xmlns=\"{NS}\">"
        ));
        body.push_str("<TrafficPolicyInstances>");
        for i in &slice {
            push_traffic_policy_instance(&mut body, i);
        }
        body.push_str("</TrafficPolicyInstances>");
        body.push_str(&format!(
            "<IsTruncated>{}</IsTruncated>",
            next_marker.is_some()
        ));
        body.push_str(&format!("<MaxItems>{}</MaxItems>", max_items));
        if let Some(nm) = &next_marker {
            body.push_str(&format!(
                "<TrafficPolicyInstanceNameMarker>{}</TrafficPolicyInstanceNameMarker>",
                esc(nm)
            ));
        }
        body.push_str("</ListTrafficPolicyInstancesResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_traffic_policy_instances_by_hosted_zone(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let zone_id = req
            .query_params
            .get("id")
            .cloned()
            .ok_or_else(|| invalid_argument("id query parameter is required"))?;
        let zone_id = strip_zone_prefix(&zone_id);
        let max_items: usize = req
            .query_params
            .get("maxitems")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);
        let state = self.state.read();
        let account = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_hosted_zone(&zone_id))?;
        if !account.hosted_zones.contains_key(&zone_id) {
            return Err(no_such_hosted_zone(&zone_id));
        }
        let mut instances: Vec<StoredTrafficPolicyInstance> = account
            .traffic_policy_instances
            .values()
            .filter(|i| i.hosted_zone_id == zone_id)
            .cloned()
            .collect();
        drop(state);
        instances.sort_by(|a, b| a.id.cmp(&b.id));
        let slice: Vec<&StoredTrafficPolicyInstance> = instances.iter().take(max_items).collect();
        let truncated = slice.len() < instances.len();
        let mut body = String::with_capacity(1024);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<ListTrafficPolicyInstancesByHostedZoneResponse xmlns=\"{NS}\">"
        ));
        body.push_str("<TrafficPolicyInstances>");
        for i in &slice {
            push_traffic_policy_instance(&mut body, i);
        }
        body.push_str("</TrafficPolicyInstances>");
        body.push_str(&format!("<IsTruncated>{}</IsTruncated>", truncated));
        body.push_str(&format!("<MaxItems>{}</MaxItems>", max_items));
        if truncated {
            body.push_str(&format!(
                "<TrafficPolicyInstanceNameMarker>{}</TrafficPolicyInstanceNameMarker>",
                esc(&instances[slice.len()].id)
            ));
        }
        body.push_str("</ListTrafficPolicyInstancesByHostedZoneResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_traffic_policy_instances_by_policy(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let policy_id = req
            .query_params
            .get("id")
            .cloned()
            .ok_or_else(|| invalid_argument("id query parameter is required"))?;
        let version: Option<i64> = req.query_params.get("version").and_then(|s| s.parse().ok());
        let max_items: usize = req
            .query_params
            .get("maxitems")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);
        let state = self.state.read();
        let mut instances: Vec<StoredTrafficPolicyInstance> = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .map(|a| {
                a.traffic_policy_instances
                    .values()
                    .filter(|i| {
                        i.traffic_policy_id == policy_id
                            && version
                                .map(|v| i.traffic_policy_version == v)
                                .unwrap_or(true)
                    })
                    .cloned()
                    .collect()
            })
            .unwrap_or_default();
        drop(state);
        instances.sort_by(|a, b| a.id.cmp(&b.id));
        let slice: Vec<&StoredTrafficPolicyInstance> = instances.iter().take(max_items).collect();
        let truncated = slice.len() < instances.len();
        let mut body = String::with_capacity(1024);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<ListTrafficPolicyInstancesByPolicyResponse xmlns=\"{NS}\">"
        ));
        body.push_str("<TrafficPolicyInstances>");
        for i in &slice {
            push_traffic_policy_instance(&mut body, i);
        }
        body.push_str("</TrafficPolicyInstances>");
        body.push_str(&format!("<IsTruncated>{}</IsTruncated>", truncated));
        body.push_str(&format!("<MaxItems>{}</MaxItems>", max_items));
        if truncated {
            body.push_str(&format!(
                "<TrafficPolicyInstanceNameMarker>{}</TrafficPolicyInstanceNameMarker>",
                esc(&instances[slice.len()].id)
            ));
        }
        body.push_str("</ListTrafficPolicyInstancesByPolicyResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn get_traffic_policy_instance_count(&self) -> Result<AwsResponse, AwsServiceError> {
        let state = self.state.read();
        let count = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .map(|a| a.traffic_policy_instances.len())
            .unwrap_or(0);
        drop(state);
        let mut body = String::with_capacity(128);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<GetTrafficPolicyInstanceCountResponse xmlns=\"{NS}\">"
        ));
        body.push_str(&format!(
            "<TrafficPolicyInstanceCount>{}</TrafficPolicyInstanceCount>",
            count
        ));
        body.push_str("</GetTrafficPolicyInstanceCountResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

// ─── DNSSEC + KSK handlers ───────────────────────────────────────────

impl Route53Service {
    fn get_dnssec(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let zone_id = strip_zone_prefix(&require_id(route)?);
        let state = self.state.read();
        let account = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_hosted_zone(&zone_id))?;
        if !account.hosted_zones.contains_key(&zone_id) {
            return Err(no_such_hosted_zone(&zone_id));
        }
        let status = account
            .dnssec_status
            .get(&zone_id)
            .cloned()
            .unwrap_or_else(|| "NOT_SIGNING".to_string());
        let ksks: Vec<StoredKeySigningKey> = account
            .key_signing_keys
            .values()
            .filter(|k| k.hosted_zone_id == zone_id)
            .cloned()
            .collect();
        drop(state);
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<GetDNSSECResponse xmlns=\"{NS}\">"));
        body.push_str("<Status>");
        body.push_str(&format!(
            "<ServeSignature>{}</ServeSignature>",
            esc(&status)
        ));
        body.push_str("</Status>");
        body.push_str("<KeySigningKeys>");
        for k in &ksks {
            // KeySigningKeys list members lack `xmlName`, so the AWS SDK
            // expects the default `<member>` element name.
            body.push_str("<member>");
            push_key_signing_key_inner(&mut body, k);
            body.push_str("</member>");
        }
        body.push_str("</KeySigningKeys>");
        body.push_str("</GetDNSSECResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn enable_hosted_zone_dnssec(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let zone_id = strip_zone_prefix(&require_id(route)?);
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_hosted_zone(&zone_id))?;
        if !account.hosted_zones.contains_key(&zone_id) {
            return Err(no_such_hosted_zone(&zone_id));
        }
        account
            .dnssec_status
            .insert(zone_id.clone(), "SIGNING".to_string());
        let change = StoredChange {
            id: generate_change_id(),
            status: "INSYNC".to_string(),
            submitted_at: Utc::now(),
            comment: Some(format!("EnableHostedZoneDNSSEC {}", zone_id)),
        };
        account.changes.insert(change.id.clone(), change.clone());
        drop(state);
        let mut body = String::with_capacity(256);
        body.push_str(XML_DECL);
        body.push_str(&format!("<EnableHostedZoneDNSSECResponse xmlns=\"{NS}\">"));
        push_change_info(&mut body, &change);
        body.push_str("</EnableHostedZoneDNSSECResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn disable_hosted_zone_dnssec(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let zone_id = strip_zone_prefix(&require_id(route)?);
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_hosted_zone(&zone_id))?;
        if !account.hosted_zones.contains_key(&zone_id) {
            return Err(no_such_hosted_zone(&zone_id));
        }
        account
            .dnssec_status
            .insert(zone_id.clone(), "NOT_SIGNING".to_string());
        let change = StoredChange {
            id: generate_change_id(),
            status: "INSYNC".to_string(),
            submitted_at: Utc::now(),
            comment: Some(format!("DisableHostedZoneDNSSEC {}", zone_id)),
        };
        account.changes.insert(change.id.clone(), change.clone());
        drop(state);
        let mut body = String::with_capacity(256);
        body.push_str(XML_DECL);
        body.push_str(&format!("<DisableHostedZoneDNSSECResponse xmlns=\"{NS}\">"));
        push_change_info(&mut body, &change);
        body.push_str("</DisableHostedZoneDNSSECResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn create_key_signing_key(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let cfg: CreateKeySigningKeyRequest = xml_io::from_xml_root(&req.body).map_err(|e| {
            invalid_argument(format!("invalid CreateKeySigningKeyRequest XML: {e}"))
        })?;
        if cfg.caller_reference.is_empty()
            || cfg.hosted_zone_id.is_empty()
            || cfg.key_management_service_arn.is_empty()
            || cfg.name.is_empty()
            || cfg.status.is_empty()
        {
            return Err(invalid_argument(
                "CallerReference, HostedZoneId, KeyManagementServiceArn, Name, Status all required",
            ));
        }
        let zone_id = strip_zone_prefix(&cfg.hosted_zone_id);
        let mut state = self.state.write();
        let account = state
            .accounts
            .entry(DEFAULT_ACCOUNT.to_string())
            .or_default();
        if !account.hosted_zones.contains_key(&zone_id) {
            return Err(no_such_hosted_zone(&zone_id));
        }
        // Real Route 53 enforces unique KSK Name per zone and unique KMS ARN per zone.
        if account
            .key_signing_keys
            .contains_key(&(zone_id.clone(), cfg.name.clone()))
        {
            return Err(aws_error(
                StatusCode::CONFLICT,
                "KeySigningKeyAlreadyExists",
                format!(
                    "A key-signing key named '{}' already exists in zone {}",
                    cfg.name, zone_id
                ),
            ));
        }
        let now = Utc::now();
        let ksk = StoredKeySigningKey {
            hosted_zone_id: zone_id.clone(),
            name: cfg.name.clone(),
            kms_arn: cfg.key_management_service_arn,
            status: cfg.status,
            caller_reference: cfg.caller_reference,
            created_date: now,
            last_modified_date: now,
            key_tag: deterministic_key_tag(&zone_id, &cfg.name),
        };
        account
            .key_signing_keys
            .insert((zone_id.clone(), cfg.name.clone()), ksk.clone());
        let change = StoredChange {
            id: generate_change_id(),
            status: "INSYNC".to_string(),
            submitted_at: now,
            comment: Some(format!("CreateKeySigningKey {}/{}", zone_id, cfg.name)),
        };
        account.changes.insert(change.id.clone(), change.clone());
        drop(state);
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<CreateKeySigningKeyResponse xmlns=\"{NS}\">"));
        push_change_info(&mut body, &change);
        body.push_str("<KeySigningKey>");
        push_key_signing_key_inner(&mut body, &ksk);
        body.push_str("</KeySigningKey>");
        body.push_str("</CreateKeySigningKeyResponse>");
        let mut headers = HeaderMap::new();
        if let Ok(loc) = http::HeaderValue::from_str(&format!(
            "/2013-04-01/keysigningkey/{}/{}",
            zone_id, ksk.name
        )) {
            headers.insert(http::header::LOCATION, loc);
        }
        Ok(xml_response(StatusCode::CREATED, body, headers))
    }

    fn delete_key_signing_key(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let (zone_id, name) = require_zone_and_name(route)?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_key_signing_key(&zone_id, &name))?;
        let ksk = account
            .key_signing_keys
            .get(&(zone_id.clone(), name.clone()))
            .ok_or_else(|| no_such_key_signing_key(&zone_id, &name))?;
        // Real Route 53 requires Status == INACTIVE before delete.
        if ksk.status.eq_ignore_ascii_case("ACTIVE") {
            return Err(aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidKeySigningKeyStatus",
                format!(
                    "KeySigningKey {}/{} must be deactivated before deletion",
                    zone_id, name
                ),
            ));
        }
        account
            .key_signing_keys
            .remove(&(zone_id.clone(), name.clone()));
        let change = StoredChange {
            id: generate_change_id(),
            status: "INSYNC".to_string(),
            submitted_at: Utc::now(),
            comment: Some(format!("DeleteKeySigningKey {}/{}", zone_id, name)),
        };
        account.changes.insert(change.id.clone(), change.clone());
        drop(state);
        let mut body = String::with_capacity(256);
        body.push_str(XML_DECL);
        body.push_str(&format!("<DeleteKeySigningKeyResponse xmlns=\"{NS}\">"));
        push_change_info(&mut body, &change);
        body.push_str("</DeleteKeySigningKeyResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn activate_key_signing_key(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        self.set_ksk_status(route, "ACTIVE", "ActivateKeySigningKey")
    }

    fn deactivate_key_signing_key(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        self.set_ksk_status(route, "INACTIVE", "DeactivateKeySigningKey")
    }

    fn set_ksk_status(
        &self,
        route: &Route,
        status: &str,
        op: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let (zone_id, name) = require_zone_and_name(route)?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_key_signing_key(&zone_id, &name))?;
        let ksk = account
            .key_signing_keys
            .get_mut(&(zone_id.clone(), name.clone()))
            .ok_or_else(|| no_such_key_signing_key(&zone_id, &name))?;
        ksk.status = status.to_string();
        ksk.last_modified_date = Utc::now();
        let change = StoredChange {
            id: generate_change_id(),
            status: "INSYNC".to_string(),
            submitted_at: Utc::now(),
            comment: Some(format!("{} {}/{}", op, zone_id, name)),
        };
        account.changes.insert(change.id.clone(), change.clone());
        drop(state);
        let mut body = String::with_capacity(256);
        body.push_str(XML_DECL);
        body.push_str(&format!("<{op}Response xmlns=\"{NS}\">"));
        push_change_info(&mut body, &change);
        body.push_str(&format!("</{op}Response>"));
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

// ─── Query Logging handlers ──────────────────────────────────────────

impl Route53Service {
    fn create_query_logging_config(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let cfg: CreateQueryLoggingConfigRequest =
            xml_io::from_xml_root(&req.body).map_err(|e| {
                invalid_argument(format!("invalid CreateQueryLoggingConfigRequest XML: {e}"))
            })?;
        if cfg.hosted_zone_id.is_empty() || cfg.cloud_watch_logs_log_group_arn.is_empty() {
            return Err(invalid_argument(
                "HostedZoneId and CloudWatchLogsLogGroupArn are required",
            ));
        }
        let zone_id = strip_zone_prefix(&cfg.hosted_zone_id);
        let mut state = self.state.write();
        let account = state
            .accounts
            .entry(DEFAULT_ACCOUNT.to_string())
            .or_default();
        if let Some(zone) = account.hosted_zones.get(&zone_id) {
            if zone.private_zone {
                return Err(invalid_argument(
                    "Query logging is only supported for public hosted zones",
                ));
            }
        } else {
            return Err(no_such_hosted_zone(&zone_id));
        }
        // One config per zone.
        if account
            .query_logging_configs
            .values()
            .any(|c| c.hosted_zone_id == zone_id)
        {
            return Err(aws_error(
                StatusCode::CONFLICT,
                "QueryLoggingConfigAlreadyExists",
                format!("A query logging config already exists for zone {}", zone_id),
            ));
        }
        let id = Uuid::new_v4().to_string();
        let stored = StoredQueryLoggingConfig {
            id: id.clone(),
            hosted_zone_id: zone_id,
            cloud_watch_logs_log_group_arn: cfg.cloud_watch_logs_log_group_arn,
        };
        account
            .query_logging_configs
            .insert(id.clone(), stored.clone());
        drop(state);
        let mut body = String::with_capacity(256);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<CreateQueryLoggingConfigResponse xmlns=\"{NS}\">"
        ));
        push_query_logging_config(&mut body, &stored);
        body.push_str("</CreateQueryLoggingConfigResponse>");
        let mut headers = HeaderMap::new();
        if let Ok(loc) =
            http::HeaderValue::from_str(&format!("/2013-04-01/queryloggingconfig/{}", stored.id))
        {
            headers.insert(http::header::LOCATION, loc);
        }
        Ok(xml_response(StatusCode::CREATED, body, headers))
    }

    fn get_query_logging_config(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let state = self.state.read();
        let cfg = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.query_logging_configs.get(&id).cloned())
            .ok_or_else(|| no_such_query_logging_config(&id))?;
        drop(state);
        let mut body = String::with_capacity(256);
        body.push_str(XML_DECL);
        body.push_str(&format!("<GetQueryLoggingConfigResponse xmlns=\"{NS}\">"));
        push_query_logging_config(&mut body, &cfg);
        body.push_str("</GetQueryLoggingConfigResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn delete_query_logging_config(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_query_logging_config(&id))?;
        if account.query_logging_configs.remove(&id).is_none() {
            return Err(no_such_query_logging_config(&id));
        }
        drop(state);
        let mut body = String::with_capacity(128);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<DeleteQueryLoggingConfigResponse xmlns=\"{NS}\"/>"
        ));
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_query_logging_configs(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let zone_filter = req.query_params.get("hostedzoneid").cloned();
        let max_items: usize = req
            .query_params
            .get("maxresults")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);
        let state = self.state.read();
        let mut configs: Vec<StoredQueryLoggingConfig> = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .map(|a| a.query_logging_configs.values().cloned().collect())
            .unwrap_or_default();
        drop(state);
        if let Some(zid) = zone_filter {
            let z = strip_zone_prefix(&zid);
            configs.retain(|c| c.hosted_zone_id == z);
        }
        configs.sort_by(|a, b| a.id.cmp(&b.id));
        let slice: Vec<&StoredQueryLoggingConfig> = configs.iter().take(max_items).collect();
        let next = if slice.len() < configs.len() {
            Some(configs[slice.len()].id.clone())
        } else {
            None
        };
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<ListQueryLoggingConfigsResponse xmlns=\"{NS}\">"));
        body.push_str("<QueryLoggingConfigs>");
        for c in &slice {
            push_query_logging_config(&mut body, c);
        }
        body.push_str("</QueryLoggingConfigs>");
        if let Some(n) = &next {
            body.push_str(&format!("<NextToken>{}</NextToken>", esc(n)));
        }
        body.push_str("</ListQueryLoggingConfigsResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

// ─── CIDR Collection handlers ────────────────────────────────────────

impl Route53Service {
    fn create_cidr_collection(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let cfg: CreateCidrCollectionRequest = xml_io::from_xml_root(&req.body).map_err(|e| {
            invalid_argument(format!("invalid CreateCidrCollectionRequest XML: {e}"))
        })?;
        if cfg.name.is_empty() || cfg.caller_reference.is_empty() {
            return Err(invalid_argument("Name and CallerReference are required"));
        }
        let mut state = self.state.write();
        let account = state
            .accounts
            .entry(DEFAULT_ACCOUNT.to_string())
            .or_default();
        if account
            .cidr_collections
            .values()
            .any(|c| c.name == cfg.name)
        {
            return Err(aws_error(
                StatusCode::CONFLICT,
                "CidrCollectionAlreadyExistsException",
                format!("A CIDR collection named '{}' already exists", cfg.name),
            ));
        }
        let id = Uuid::new_v4().to_string();
        let arn =
            Arn::global("route53", DEFAULT_ACCOUNT, &format!("cidrcollection/{id}")).to_string();
        let stored = StoredCidrCollection {
            id: id.clone(),
            name: cfg.name,
            arn: arn.clone(),
            version: 1,
            caller_reference: cfg.caller_reference,
            locations: BTreeMap::new(),
        };
        account.cidr_collections.insert(id.clone(), stored.clone());
        drop(state);
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<CreateCidrCollectionResponse xmlns=\"{NS}\">"));
        push_cidr_collection_full(&mut body, &stored);
        body.push_str("<Location>");
        body.push_str(&format!("<Arn>{}</Arn>", esc(&arn)));
        body.push_str("</Location>");
        body.push_str("</CreateCidrCollectionResponse>");
        let mut headers = HeaderMap::new();
        if let Ok(loc) =
            http::HeaderValue::from_str(&format!("/2013-04-01/cidrcollection/{}", stored.id))
        {
            headers.insert(http::header::LOCATION, loc);
        }
        Ok(xml_response(StatusCode::CREATED, body, headers))
    }

    fn change_cidr_collection(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let cfg: ChangeCidrCollectionRequest = xml_io::from_xml_root(&req.body).map_err(|e| {
            invalid_argument(format!("invalid ChangeCidrCollectionRequest XML: {e}"))
        })?;
        if cfg.changes.change.is_empty() {
            return Err(invalid_argument("Changes must contain at least one entry"));
        }
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_cidr_collection(&id))?;
        let coll = account
            .cidr_collections
            .get_mut(&id)
            .ok_or_else(|| no_such_cidr_collection(&id))?;
        if let Some(client_v) = cfg.collection_version {
            if client_v != coll.version {
                return Err(aws_error(
                    StatusCode::CONFLICT,
                    "CidrCollectionVersionMismatchException",
                    format!(
                        "CollectionVersion ({}) does not match the current ({})",
                        client_v, coll.version
                    ),
                ));
            }
        }
        // Stage changes against a clone so a later invalid change rolls
        // everything back atomically.
        let mut working = coll.locations.clone();
        for ch in &cfg.changes.change {
            match ch.action.to_uppercase().as_str() {
                "PUT" => {
                    let entry = working.entry(ch.location_name.clone()).or_default();
                    for cidr in &ch.cidr_list.cidr {
                        if !entry.contains(cidr) {
                            entry.push(cidr.clone());
                        }
                    }
                    entry.sort();
                }
                "DELETE_IF_EXISTS" => {
                    if let Some(entry) = working.get_mut(&ch.location_name) {
                        entry.retain(|c| !ch.cidr_list.cidr.contains(c));
                        if entry.is_empty() {
                            working.remove(&ch.location_name);
                        }
                    }
                }
                other => {
                    return Err(invalid_argument(format!(
                        "Unknown CIDR change action: {other}"
                    )));
                }
            }
        }
        coll.locations = working;
        coll.version += 1;
        drop(state);
        let mut body = String::with_capacity(128);
        body.push_str(XML_DECL);
        body.push_str(&format!("<ChangeCidrCollectionResponse xmlns=\"{NS}\">"));
        body.push_str(&format!("<Id>{}</Id>", esc(&id)));
        body.push_str("</ChangeCidrCollectionResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn delete_cidr_collection(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_cidr_collection(&id))?;
        let coll = account
            .cidr_collections
            .get(&id)
            .ok_or_else(|| no_such_cidr_collection(&id))?;
        if !coll.locations.is_empty() {
            return Err(aws_error(
                StatusCode::BAD_REQUEST,
                "CidrCollectionInUseException",
                format!(
                    "CIDR collection {} still contains {} location(s)",
                    id,
                    coll.locations.len()
                ),
            ));
        }
        account.cidr_collections.remove(&id);
        drop(state);
        let mut body = String::with_capacity(128);
        body.push_str(XML_DECL);
        body.push_str(&format!("<DeleteCidrCollectionResponse xmlns=\"{NS}\"/>"));
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_cidr_collections(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let max_items: usize = req
            .query_params
            .get("maxresults")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);
        let state = self.state.read();
        let mut colls: Vec<StoredCidrCollection> = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .map(|a| a.cidr_collections.values().cloned().collect())
            .unwrap_or_default();
        drop(state);
        colls.sort_by(|a, b| a.id.cmp(&b.id));
        let slice: Vec<&StoredCidrCollection> = colls.iter().take(max_items).collect();
        let next = if slice.len() < colls.len() {
            Some(colls[slice.len()].id.clone())
        } else {
            None
        };
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<ListCidrCollectionsResponse xmlns=\"{NS}\">"));
        body.push_str("<CidrCollections>");
        for c in &slice {
            // CollectionSummaries.member has no xmlName trait, so AWS
            // SDKs deserialize members from the default `<member>` element.
            body.push_str("<member>");
            body.push_str(&format!("<Arn>{}</Arn>", esc(&c.arn)));
            body.push_str(&format!("<Id>{}</Id>", esc(&c.id)));
            body.push_str(&format!("<Name>{}</Name>", esc(&c.name)));
            body.push_str(&format!("<Version>{}</Version>", c.version));
            body.push_str("</member>");
        }
        body.push_str("</CidrCollections>");
        if let Some(n) = &next {
            body.push_str(&format!("<NextToken>{}</NextToken>", esc(n)));
        }
        body.push_str("</ListCidrCollectionsResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_cidr_locations(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let max_items: usize = req
            .query_params
            .get("maxresults")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);
        let state = self.state.read();
        let coll = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.cidr_collections.get(&id).cloned())
            .ok_or_else(|| no_such_cidr_collection(&id))?;
        drop(state);
        let mut names: Vec<String> = coll.locations.keys().cloned().collect();
        names.sort();
        let slice: Vec<&String> = names.iter().take(max_items).collect();
        let next = if slice.len() < names.len() {
            Some(names[slice.len()].clone())
        } else {
            None
        };
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<ListCidrLocationsResponse xmlns=\"{NS}\">"));
        body.push_str("<CidrLocations>");
        for n in &slice {
            body.push_str("<member>");
            body.push_str(&format!("<LocationName>{}</LocationName>", esc(n)));
            body.push_str("</member>");
        }
        body.push_str("</CidrLocations>");
        if let Some(n) = &next {
            body.push_str(&format!("<NextToken>{}</NextToken>", esc(n)));
        }
        body.push_str("</ListCidrLocationsResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_cidr_blocks(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let location_name = req.query_params.get("location").cloned();
        let max_items: usize = req
            .query_params
            .get("maxresults")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);
        let state = self.state.read();
        let coll = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.cidr_collections.get(&id).cloned())
            .ok_or_else(|| no_such_cidr_collection(&id))?;
        drop(state);
        let blocks: Vec<(String, String)> = coll
            .locations
            .iter()
            .filter(|(n, _)| location_name.as_ref().is_none_or(|name| name == *n))
            .flat_map(|(n, blocks)| blocks.iter().map(move |b| (n.clone(), b.clone())))
            .collect();
        let slice: Vec<&(String, String)> = blocks.iter().take(max_items).collect();
        let next = if slice.len() < blocks.len() {
            Some(blocks[slice.len()].1.clone())
        } else {
            None
        };
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<ListCidrBlocksResponse xmlns=\"{NS}\">"));
        body.push_str("<CidrBlocks>");
        for (loc, cidr) in &slice {
            body.push_str("<member>");
            body.push_str(&format!("<CidrBlock>{}</CidrBlock>", esc(cidr)));
            body.push_str(&format!("<LocationName>{}</LocationName>", esc(loc)));
            body.push_str("</member>");
        }
        body.push_str("</CidrBlocks>");
        if let Some(n) = &next {
            body.push_str(&format!("<NextToken>{}</NextToken>", esc(n)));
        }
        body.push_str("</ListCidrBlocksResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

// ─── Helpers ─────────────────────────────────────────────────────────

fn _account_helper(_state: &mut Route53Accounts) -> &mut AccountState {
    unreachable!()
}

fn require_id(route: &Route) -> Result<String, AwsServiceError> {
    route
        .id
        .clone()
        .ok_or_else(|| invalid_argument("missing id in URI"))
}

fn strip_zone_prefix(id: &str) -> String {
    if let Some(rest) = id.strip_prefix("/hostedzone/") {
        rest.to_string()
    } else if let Some(rest) = id.strip_prefix("hostedzone/") {
        rest.to_string()
    } else {
        id.to_string()
    }
}

fn synth_name_servers(_id: &str) -> Vec<String> {
    vec![
        "ns-2048.awsdns-64.com".to_string(),
        "ns-2049.awsdns-65.net".to_string(),
        "ns-2050.awsdns-66.org".to_string(),
        "ns-2051.awsdns-67.co.uk".to_string(),
    ]
}

fn default_zone_records(name: &str, name_servers: &[String]) -> Vec<ResourceRecordSet> {
    let mut soa_value = String::new();
    soa_value.push_str(&name_servers[0]);
    soa_value.push_str(" awsdns-hostmaster.amazon.com. 1 7200 900 1209600 86400");
    let soa = ResourceRecordSet {
        name: name.to_string(),
        record_type: "SOA".to_string(),
        ttl: Some(900),
        resource_records: Some(crate::model::ResourceRecords {
            resource_record: vec![crate::model::ResourceRecord { value: soa_value }],
        }),
        ..Default::default()
    };
    let ns = ResourceRecordSet {
        name: name.to_string(),
        record_type: "NS".to_string(),
        ttl: Some(172800),
        resource_records: Some(crate::model::ResourceRecords {
            resource_record: name_servers
                .iter()
                .map(|n| crate::model::ResourceRecord { value: n.clone() })
                .collect(),
        }),
        ..Default::default()
    };
    vec![soa, ns]
}

fn normalize_rrset(r: &ResourceRecordSet) -> ResourceRecordSet {
    let mut out = r.clone();
    if !out.name.ends_with('.') {
        out.name.push('.');
    }
    out
}

fn rrset_matches(a: &ResourceRecordSet, b: &ResourceRecordSet) -> bool {
    a.name == b.name && a.record_type == b.record_type && a.set_identifier == b.set_identifier
}

fn is_default_record(r: &ResourceRecordSet, zone_name: &str) -> bool {
    r.name == zone_name && (r.record_type == "SOA" || r.record_type == "NS")
}

fn push_hosted_zone(out: &mut String, z: &StoredHostedZone) {
    out.push_str("<HostedZone>");
    out.push_str(&format!("<Id>/hostedzone/{}</Id>", esc(&z.id)));
    out.push_str(&format!("<Name>{}</Name>", esc(&z.name)));
    out.push_str(&format!(
        "<CallerReference>{}</CallerReference>",
        esc(&z.caller_reference)
    ));
    out.push_str("<Config>");
    if let Some(c) = &z.comment {
        out.push_str(&format!("<Comment>{}</Comment>", esc(c)));
    }
    out.push_str(&format!("<PrivateZone>{}</PrivateZone>", z.private_zone));
    out.push_str("</Config>");
    out.push_str(&format!(
        "<ResourceRecordSetCount>{}</ResourceRecordSetCount>",
        z.resource_record_sets.len()
    ));
    out.push_str("</HostedZone>");
}

fn push_change_info(out: &mut String, c: &StoredChange) {
    out.push_str("<ChangeInfo>");
    out.push_str(&format!("<Id>/change/{}</Id>", esc(&c.id)));
    out.push_str(&format!("<Status>{}</Status>", esc(&c.status)));
    out.push_str(&format!(
        "<SubmittedAt>{}</SubmittedAt>",
        rfc3339(&c.submitted_at)
    ));
    if let Some(cm) = &c.comment {
        out.push_str(&format!("<Comment>{}</Comment>", esc(cm)));
    }
    out.push_str("</ChangeInfo>");
}

fn push_vpc_block(out: &mut String, root: &str, v: &crate::model::VPC) {
    out.push_str(&format!("<{root}>"));
    if let Some(id) = &v.vpc_id {
        out.push_str(&format!("<VPCId>{}</VPCId>", esc(id)));
    }
    if let Some(r) = &v.vpc_region {
        out.push_str(&format!("<VPCRegion>{}</VPCRegion>", esc(r)));
    }
    out.push_str(&format!("</{root}>"));
}

fn push_rrset(out: &mut String, r: &ResourceRecordSet) {
    out.push_str("<ResourceRecordSet>");
    out.push_str(&format!("<Name>{}</Name>", esc(&r.name)));
    out.push_str(&format!("<Type>{}</Type>", esc(&r.record_type)));
    if let Some(s) = &r.set_identifier {
        out.push_str(&format!("<SetIdentifier>{}</SetIdentifier>", esc(s)));
    }
    if let Some(w) = r.weight {
        out.push_str(&format!("<Weight>{}</Weight>", w));
    }
    if let Some(reg) = &r.region {
        out.push_str(&format!("<Region>{}</Region>", esc(reg)));
    }
    if let Some(g) = &r.geo_location {
        out.push_str("<GeoLocation>");
        if let Some(v) = &g.continent_code {
            out.push_str(&format!("<ContinentCode>{}</ContinentCode>", esc(v)));
        }
        if let Some(v) = &g.country_code {
            out.push_str(&format!("<CountryCode>{}</CountryCode>", esc(v)));
        }
        if let Some(v) = &g.subdivision_code {
            out.push_str(&format!("<SubdivisionCode>{}</SubdivisionCode>", esc(v)));
        }
        out.push_str("</GeoLocation>");
    }
    if let Some(f) = &r.failover {
        out.push_str(&format!("<Failover>{}</Failover>", esc(f)));
    }
    if let Some(m) = r.multi_value_answer {
        out.push_str(&format!("<MultiValueAnswer>{}</MultiValueAnswer>", m));
    }
    if let Some(t) = r.ttl {
        out.push_str(&format!("<TTL>{}</TTL>", t));
    }
    if let Some(rr) = &r.resource_records {
        out.push_str("<ResourceRecords>");
        for v in &rr.resource_record {
            out.push_str("<ResourceRecord>");
            out.push_str(&format!("<Value>{}</Value>", esc(&v.value)));
            out.push_str("</ResourceRecord>");
        }
        out.push_str("</ResourceRecords>");
    }
    if let Some(at) = &r.alias_target {
        out.push_str("<AliasTarget>");
        out.push_str(&format!(
            "<HostedZoneId>{}</HostedZoneId>",
            esc(&at.hosted_zone_id)
        ));
        out.push_str(&format!("<DNSName>{}</DNSName>", esc(&at.dns_name)));
        out.push_str(&format!(
            "<EvaluateTargetHealth>{}</EvaluateTargetHealth>",
            at.evaluate_target_health
        ));
        out.push_str("</AliasTarget>");
    }
    if let Some(h) = &r.health_check_id {
        out.push_str(&format!("<HealthCheckId>{}</HealthCheckId>", esc(h)));
    }
    if let Some(t) = &r.traffic_policy_instance_id {
        out.push_str(&format!(
            "<TrafficPolicyInstanceId>{}</TrafficPolicyInstanceId>",
            esc(t)
        ));
    }
    if let Some(c) = &r.cidr_routing_config {
        out.push_str("<CidrRoutingConfig>");
        out.push_str(&format!(
            "<CollectionId>{}</CollectionId>",
            esc(&c.collection_id)
        ));
        out.push_str(&format!(
            "<LocationName>{}</LocationName>",
            esc(&c.location_name)
        ));
        out.push_str("</CidrRoutingConfig>");
    }
    if let Some(g) = &r.geo_proximity_location {
        out.push_str("<GeoProximityLocation>");
        if let Some(v) = &g.aws_region {
            out.push_str(&format!("<AWSRegion>{}</AWSRegion>", esc(v)));
        }
        if let Some(v) = &g.local_zone_group {
            out.push_str(&format!("<LocalZoneGroup>{}</LocalZoneGroup>", esc(v)));
        }
        if let Some(c) = &g.coordinates {
            out.push_str("<Coordinates>");
            out.push_str(&format!("<Latitude>{}</Latitude>", esc(&c.latitude)));
            out.push_str(&format!("<Longitude>{}</Longitude>", esc(&c.longitude)));
            out.push_str("</Coordinates>");
        }
        if let Some(b) = g.bias {
            out.push_str(&format!("<Bias>{}</Bias>", b));
        }
        out.push_str("</GeoProximityLocation>");
    }
    out.push_str("</ResourceRecordSet>");
}

fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

fn generate_zone_id() -> String {
    let raw = Uuid::new_v4().simple().to_string().to_uppercase();
    format!("Z{}", &raw[..14])
}

fn generate_change_id() -> String {
    let raw = Uuid::new_v4().simple().to_string().to_uppercase();
    format!("C{}", &raw[..14])
}

fn generate_health_check_id() -> String {
    Uuid::new_v4().to_string()
}

fn push_health_check(out: &mut String, hc: &StoredHealthCheck) {
    out.push_str("<HealthCheck>");
    out.push_str(&format!("<Id>{}</Id>", esc(&hc.id)));
    out.push_str(&format!(
        "<CallerReference>{}</CallerReference>",
        esc(&hc.caller_reference)
    ));
    push_health_check_config(out, &hc.config);
    out.push_str(&format!(
        "<HealthCheckVersion>{}</HealthCheckVersion>",
        hc.version
    ));
    out.push_str("</HealthCheck>");
}

fn push_health_check_config(out: &mut String, c: &HealthCheckConfig) {
    out.push_str("<HealthCheckConfig>");
    if let Some(v) = &c.ip_address {
        out.push_str(&format!("<IPAddress>{}</IPAddress>", esc(v)));
    }
    if let Some(v) = c.port {
        out.push_str(&format!("<Port>{}</Port>", v));
    }
    out.push_str(&format!("<Type>{}</Type>", esc(&c.health_check_type)));
    if let Some(v) = &c.resource_path {
        out.push_str(&format!("<ResourcePath>{}</ResourcePath>", esc(v)));
    }
    if let Some(v) = &c.fully_qualified_domain_name {
        out.push_str(&format!(
            "<FullyQualifiedDomainName>{}</FullyQualifiedDomainName>",
            esc(v)
        ));
    }
    if let Some(v) = &c.search_string {
        out.push_str(&format!("<SearchString>{}</SearchString>", esc(v)));
    }
    if let Some(v) = c.request_interval {
        out.push_str(&format!("<RequestInterval>{}</RequestInterval>", v));
    }
    if let Some(v) = c.failure_threshold {
        out.push_str(&format!("<FailureThreshold>{}</FailureThreshold>", v));
    }
    if let Some(v) = c.measure_latency {
        out.push_str(&format!("<MeasureLatency>{}</MeasureLatency>", v));
    }
    if let Some(v) = c.inverted {
        out.push_str(&format!("<Inverted>{}</Inverted>", v));
    }
    if let Some(v) = c.disabled {
        out.push_str(&format!("<Disabled>{}</Disabled>", v));
    }
    if let Some(v) = c.health_threshold {
        out.push_str(&format!("<HealthThreshold>{}</HealthThreshold>", v));
    }
    if let Some(child) = &c.child_health_checks {
        out.push_str("<ChildHealthChecks>");
        for id in &child.child_health_check {
            out.push_str(&format!("<ChildHealthCheck>{}</ChildHealthCheck>", esc(id)));
        }
        out.push_str("</ChildHealthChecks>");
    }
    if let Some(v) = c.enable_sni {
        out.push_str(&format!("<EnableSNI>{}</EnableSNI>", v));
    }
    if let Some(regs) = &c.regions {
        out.push_str("<Regions>");
        for r in &regs.region {
            out.push_str(&format!("<Region>{}</Region>", esc(r)));
        }
        out.push_str("</Regions>");
    }
    if let Some(a) = &c.alarm_identifier {
        out.push_str("<AlarmIdentifier>");
        out.push_str(&format!("<Region>{}</Region>", esc(&a.region)));
        out.push_str(&format!("<Name>{}</Name>", esc(&a.name)));
        out.push_str("</AlarmIdentifier>");
    }
    if let Some(v) = &c.insufficient_data_health_status {
        out.push_str(&format!(
            "<InsufficientDataHealthStatus>{}</InsufficientDataHealthStatus>",
            esc(v)
        ));
    }
    if let Some(v) = &c.routing_control_arn {
        out.push_str(&format!(
            "<RoutingControlArn>{}</RoutingControlArn>",
            esc(v)
        ));
    }
    out.push_str("</HealthCheckConfig>");
}

fn no_such_health_check(id: &str) -> AwsServiceError {
    aws_error(
        StatusCode::NOT_FOUND,
        "NoSuchHealthCheck",
        format!("No health check found with ID: {id}"),
    )
}

// Public Route 53 health checker IP ranges (subset of the published list).
// fakecloud is offline so the exact set doesn't matter; SDKs only check
// the structure of the response.
const CHECKER_IP_RANGES: &[&str] = &[
    "15.177.0.0/18",
    "15.177.64.0/18",
    "15.177.128.0/18",
    "15.177.192.0/18",
    "54.183.255.128/26",
    "54.228.16.0/26",
    "54.232.40.64/26",
    "54.241.32.64/26",
    "54.243.31.192/26",
    "54.244.52.192/26",
    "54.245.168.0/26",
    "54.248.220.0/26",
    "54.250.253.192/26",
    "54.251.31.128/26",
    "54.252.79.128/26",
    "54.252.254.192/26",
    "54.255.254.192/26",
    "107.23.255.0/26",
    "176.34.159.192/26",
    "177.71.207.128/26",
];

fn checker_regions() -> &'static [&'static str] {
    &[
        "us-east-1",
        "us-west-1",
        "us-west-2",
        "eu-west-1",
        "ap-southeast-1",
        "ap-southeast-2",
        "ap-northeast-1",
        "sa-east-1",
    ]
}

fn checker_ip_for_region(region: &str) -> String {
    // Route 53 reports a per-region checker IP. The exact value isn't
    // observable to clients in any way that matters for fakecloud, so use
    // a deterministic offset into the documented ranges.
    let idx = region.bytes().fold(0usize, |a, b| a + b as usize) % CHECKER_IP_RANGES.len();
    CHECKER_IP_RANGES[idx]
        .split('/')
        .next()
        .unwrap_or("0.0.0.0")
        .to_string()
}

fn rfc3339(t: &chrono::DateTime<chrono::Utc>) -> String {
    t.to_rfc3339_opts(chrono::SecondsFormat::Millis, true)
}

fn invalid_argument(msg: impl Into<String>) -> AwsServiceError {
    aws_error(StatusCode::BAD_REQUEST, "InvalidInput", msg)
}

fn invalid_change_batch(msg: impl Into<String>) -> AwsServiceError {
    aws_error(StatusCode::BAD_REQUEST, "InvalidChangeBatch", msg)
}

fn no_such_hosted_zone(id: &str) -> AwsServiceError {
    aws_error(
        StatusCode::NOT_FOUND,
        "NoSuchHostedZone",
        format!("No hosted zone found with ID: {id}"),
    )
}

fn aws_error(
    status: StatusCode,
    code: impl Into<String>,
    msg: impl Into<String>,
) -> AwsServiceError {
    AwsServiceError::aws_error(status, code.into(), msg)
}

fn xml_response(status: StatusCode, body: String, headers: HeaderMap) -> AwsResponse {
    AwsResponse {
        status,
        content_type: "text/xml".to_string(),
        body: ResponseBody::Bytes(Bytes::from(body)),
        headers,
    }
}

// ─── Traffic Policy helpers ──────────────────────────────────────────

fn require_version(route: &Route) -> Result<i64, AwsServiceError> {
    route
        .second_id
        .as_ref()
        .ok_or_else(|| invalid_argument("missing version in URI"))
        .and_then(|v| {
            v.parse::<i64>()
                .map_err(|_| invalid_argument(format!("invalid version: {v}")))
        })
}

fn generate_traffic_policy_id() -> String {
    Uuid::new_v4().to_string()
}

fn generate_traffic_policy_instance_id() -> String {
    Uuid::new_v4().to_string()
}

/// Inspect a traffic policy document JSON for `RecordType` to seed the
/// `TrafficPolicy.Type` field. Defaults to `A` if the document is empty
/// or doesn't declare one.
fn infer_policy_type(doc: &str) -> String {
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(doc) {
        if let Some(rt) = v.get("RecordType").and_then(|x| x.as_str()) {
            return rt.to_string();
        }
    }
    "A".to_string()
}

fn no_such_traffic_policy(id: &str) -> AwsServiceError {
    aws_error(
        StatusCode::NOT_FOUND,
        "NoSuchTrafficPolicy",
        format!("No traffic policy found with ID: {id}"),
    )
}

fn no_such_traffic_policy_instance(id: &str) -> AwsServiceError {
    aws_error(
        StatusCode::NOT_FOUND,
        "NoSuchTrafficPolicyInstance",
        format!("No traffic policy instance found with ID: {id}"),
    )
}

fn push_traffic_policy(out: &mut String, p: &StoredTrafficPolicy) {
    out.push_str("<TrafficPolicy>");
    out.push_str(&format!("<Id>{}</Id>", esc(&p.id)));
    out.push_str(&format!("<Version>{}</Version>", p.version));
    out.push_str(&format!("<Name>{}</Name>", esc(&p.name)));
    out.push_str(&format!("<Type>{}</Type>", esc(&p.policy_type)));
    out.push_str(&format!("<Document>{}</Document>", esc(&p.document)));
    if let Some(c) = &p.comment {
        out.push_str(&format!("<Comment>{}</Comment>", esc(c)));
    }
    out.push_str("</TrafficPolicy>");
}

fn push_traffic_policy_summary(
    out: &mut String,
    p: &StoredTrafficPolicy,
    traffic_policy_count: i64,
) {
    out.push_str("<TrafficPolicySummary>");
    out.push_str(&format!("<Id>{}</Id>", esc(&p.id)));
    out.push_str(&format!("<Name>{}</Name>", esc(&p.name)));
    out.push_str(&format!("<Type>{}</Type>", esc(&p.policy_type)));
    out.push_str(&format!("<LatestVersion>{}</LatestVersion>", p.version));
    out.push_str(&format!(
        "<TrafficPolicyCount>{}</TrafficPolicyCount>",
        traffic_policy_count
    ));
    out.push_str("</TrafficPolicySummary>");
}

fn push_traffic_policy_instance(out: &mut String, i: &StoredTrafficPolicyInstance) {
    out.push_str("<TrafficPolicyInstance>");
    out.push_str(&format!("<Id>{}</Id>", esc(&i.id)));
    out.push_str(&format!(
        "<HostedZoneId>{}</HostedZoneId>",
        esc(&i.hosted_zone_id)
    ));
    out.push_str(&format!("<Name>{}</Name>", esc(&i.name)));
    out.push_str(&format!("<TTL>{}</TTL>", i.ttl));
    out.push_str(&format!("<State>{}</State>", esc(&i.state)));
    out.push_str(&format!("<Message>{}</Message>", esc(&i.message)));
    out.push_str(&format!(
        "<TrafficPolicyId>{}</TrafficPolicyId>",
        esc(&i.traffic_policy_id)
    ));
    out.push_str(&format!(
        "<TrafficPolicyVersion>{}</TrafficPolicyVersion>",
        i.traffic_policy_version
    ));
    out.push_str(&format!(
        "<TrafficPolicyType>{}</TrafficPolicyType>",
        esc(&i.traffic_policy_type)
    ));
    out.push_str("</TrafficPolicyInstance>");
}

// ─── DNSSEC + Query Logging + CIDR helpers ───────────────────────────

fn require_zone_and_name(route: &Route) -> Result<(String, String), AwsServiceError> {
    let zone = require_id(route)?;
    let name = route
        .second_id
        .clone()
        .ok_or_else(|| invalid_argument("missing name in URI"))?;
    Ok((strip_zone_prefix(&zone), name))
}

/// Pick a deterministic 16-bit key tag from the (zone, name) pair so
/// repeated test runs see a stable value without ever creating real
/// crypto material.
fn deterministic_key_tag(zone_id: &str, name: &str) -> i32 {
    let mut acc: u32 = 0;
    for b in zone_id.bytes().chain(name.bytes()) {
        acc = acc.wrapping_mul(31).wrapping_add(b as u32);
    }
    (acc & 0xFFFF) as i32
}

fn no_such_key_signing_key(zone_id: &str, name: &str) -> AwsServiceError {
    aws_error(
        StatusCode::NOT_FOUND,
        "NoSuchKeySigningKey",
        format!("No key-signing key {}/{} found", zone_id, name),
    )
}

fn no_such_query_logging_config(id: &str) -> AwsServiceError {
    aws_error(
        StatusCode::NOT_FOUND,
        "NoSuchQueryLoggingConfig",
        format!("No query logging config found with ID: {id}"),
    )
}

fn no_such_cidr_collection(id: &str) -> AwsServiceError {
    aws_error(
        StatusCode::NOT_FOUND,
        "NoSuchCidrCollectionException",
        format!("No CIDR collection found with ID: {id}"),
    )
}

fn push_key_signing_key_inner(out: &mut String, k: &StoredKeySigningKey) {
    out.push_str(&format!("<Name>{}</Name>", esc(&k.name)));
    out.push_str(&format!("<KmsArn>{}</KmsArn>", esc(&k.kms_arn)));
    out.push_str("<Flag>257</Flag>");
    out.push_str(
        "<SigningAlgorithmMnemonic>ECDSAP256SHA256</SigningAlgorithmMnemonic>\
         <SigningAlgorithmType>13</SigningAlgorithmType>\
         <DigestAlgorithmMnemonic>SHA-256</DigestAlgorithmMnemonic>\
         <DigestAlgorithmType>2</DigestAlgorithmType>",
    );
    out.push_str(&format!("<KeyTag>{}</KeyTag>", k.key_tag));
    out.push_str(&format!("<Status>{}</Status>", esc(&k.status)));
    out.push_str(&format!(
        "<CreatedDate>{}</CreatedDate>",
        rfc3339(&k.created_date)
    ));
    out.push_str(&format!(
        "<LastModifiedDate>{}</LastModifiedDate>",
        rfc3339(&k.last_modified_date)
    ));
}

fn push_query_logging_config(out: &mut String, c: &StoredQueryLoggingConfig) {
    out.push_str("<QueryLoggingConfig>");
    out.push_str(&format!("<Id>{}</Id>", esc(&c.id)));
    out.push_str(&format!(
        "<HostedZoneId>{}</HostedZoneId>",
        esc(&c.hosted_zone_id)
    ));
    out.push_str(&format!(
        "<CloudWatchLogsLogGroupArn>{}</CloudWatchLogsLogGroupArn>",
        esc(&c.cloud_watch_logs_log_group_arn)
    ));
    out.push_str("</QueryLoggingConfig>");
}

fn push_cidr_collection_full(out: &mut String, c: &StoredCidrCollection) {
    out.push_str("<Collection>");
    out.push_str(&format!("<Arn>{}</Arn>", esc(&c.arn)));
    out.push_str(&format!("<Id>{}</Id>", esc(&c.id)));
    out.push_str(&format!("<Name>{}</Name>", esc(&c.name)));
    out.push_str(&format!("<Version>{}</Version>", c.version));
    out.push_str("</Collection>");
}

// ─── VPC Association handlers ────────────────────────────────────────

impl Route53Service {
    fn associate_vpc_with_hosted_zone(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = strip_zone_prefix(&require_id(route)?);
        let cfg: AssociateVpcRequest = xml_io::from_xml_root(&req.body)
            .map_err(|e| invalid_argument(format!("invalid AssociateVPCRequest XML: {e}")))?;
        let vpc = cfg.vpc;
        require_vpc(&vpc)?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        let zone = account
            .hosted_zones
            .get_mut(&id)
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        if !zone.private_zone {
            return Err(aws_error(
                StatusCode::BAD_REQUEST,
                "PublicZoneVPCAssociation",
                format!("HostedZone {id} is a public zone; cannot associate a VPC"),
            ));
        }
        if zone.vpcs.iter().any(|v| same_vpc(v, &vpc)) {
            return Err(aws_error(
                StatusCode::CONFLICT,
                "ConflictingDomainExists",
                format!(
                    "VPC {} is already associated with hosted zone {id}",
                    vpc.vpc_id.clone().unwrap_or_default()
                ),
            ));
        }
        // For cross-account associations Route 53 requires a prior
        // CreateVPCAssociationAuthorization. For same-account associations
        // (the only kind fakecloud has — single DEFAULT_ACCOUNT) the
        // authorization is implicit, so we don't gate on it. Once we model
        // multi-account ownership of zones we can wire the authorization
        // check in.
        zone.vpcs.push(vpc);
        let now = Utc::now();
        let change_id = generate_change_id();
        let change = StoredChange {
            id: change_id.clone(),
            status: "INSYNC".to_string(),
            submitted_at: now,
            comment: cfg.comment,
        };
        account.changes.insert(change_id.clone(), change.clone());
        drop(state);
        let mut body = String::with_capacity(256);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<AssociateVPCWithHostedZoneResponse xmlns=\"{NS}\">"
        ));
        push_change_info(&mut body, &change);
        body.push_str("</AssociateVPCWithHostedZoneResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn disassociate_vpc_from_hosted_zone(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = strip_zone_prefix(&require_id(route)?);
        let cfg: AssociateVpcRequest = xml_io::from_xml_root(&req.body)
            .map_err(|e| invalid_argument(format!("invalid DisassociateVPCRequest XML: {e}")))?;
        let vpc = cfg.vpc;
        require_vpc(&vpc)?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        let zone = account
            .hosted_zones
            .get_mut(&id)
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        let Some(pos) = zone.vpcs.iter().position(|v| same_vpc(v, &vpc)) else {
            return Err(aws_error(
                StatusCode::NOT_FOUND,
                "VPCAssociationNotFound",
                format!(
                    "VPC {} is not associated with hosted zone {id}",
                    vpc.vpc_id.clone().unwrap_or_default()
                ),
            ));
        };
        if zone.vpcs.len() == 1 {
            return Err(aws_error(
                StatusCode::BAD_REQUEST,
                "LastVPCAssociation",
                format!("Cannot remove the last VPC association from private hosted zone {id}"),
            ));
        }
        zone.vpcs.remove(pos);
        let now = Utc::now();
        let change_id = generate_change_id();
        let change = StoredChange {
            id: change_id.clone(),
            status: "INSYNC".to_string(),
            submitted_at: now,
            comment: cfg.comment,
        };
        account.changes.insert(change_id.clone(), change.clone());
        drop(state);
        let mut body = String::with_capacity(256);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<DisassociateVPCFromHostedZoneResponse xmlns=\"{NS}\">"
        ));
        push_change_info(&mut body, &change);
        body.push_str("</DisassociateVPCFromHostedZoneResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn create_vpc_association_authorization(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = strip_zone_prefix(&require_id(route)?);
        let cfg: VpcAuthorizationRequest = xml_io::from_xml_root(&req.body).map_err(|e| {
            invalid_argument(format!(
                "invalid CreateVPCAssociationAuthorizationRequest XML: {e}"
            ))
        })?;
        let vpc = cfg.vpc;
        require_vpc(&vpc)?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        let zone = account
            .hosted_zones
            .get(&id)
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        if !zone.private_zone {
            return Err(aws_error(
                StatusCode::BAD_REQUEST,
                "PublicZoneVPCAssociation",
                format!("HostedZone {id} is a public zone; cannot authorize a VPC association"),
            ));
        }
        let entry = account.vpc_authorizations.entry(id.clone()).or_default();
        if !entry.iter().any(|v| same_vpc(v, &vpc)) {
            entry.push(vpc.clone());
        }
        drop(state);
        let mut body = String::with_capacity(256);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<CreateVPCAssociationAuthorizationResponse xmlns=\"{NS}\">"
        ));
        body.push_str(&format!("<HostedZoneId>{}</HostedZoneId>", esc(&id)));
        push_vpc_block(&mut body, "VPC", &vpc);
        body.push_str("</CreateVPCAssociationAuthorizationResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn delete_vpc_association_authorization(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = strip_zone_prefix(&require_id(route)?);
        let cfg: VpcAuthorizationRequest = xml_io::from_xml_root(&req.body).map_err(|e| {
            invalid_argument(format!(
                "invalid DeleteVPCAssociationAuthorizationRequest XML: {e}"
            ))
        })?;
        let vpc = cfg.vpc;
        require_vpc(&vpc)?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        if !account.hosted_zones.contains_key(&id) {
            return Err(no_such_hosted_zone(&id));
        }
        let entry = account.vpc_authorizations.entry(id.clone()).or_default();
        let before = entry.len();
        entry.retain(|v| !same_vpc(v, &vpc));
        if entry.len() == before {
            return Err(aws_error(
                StatusCode::NOT_FOUND,
                "VPCAssociationAuthorizationNotFound",
                format!(
                    "VPC {} is not authorized for hosted zone {id}",
                    vpc.vpc_id.clone().unwrap_or_default()
                ),
            ));
        }
        if entry.is_empty() {
            account.vpc_authorizations.remove(&id);
        }
        drop(state);
        let mut body = String::with_capacity(128);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<DeleteVPCAssociationAuthorizationResponse xmlns=\"{NS}\"/>"
        ));
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_vpc_association_authorizations(
        &self,
        _req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = strip_zone_prefix(&require_id(route)?);
        let state = self.state.read();
        let account = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_hosted_zone(&id))?;
        if !account.hosted_zones.contains_key(&id) {
            return Err(no_such_hosted_zone(&id));
        }
        let vpcs: Vec<VPC> = account
            .vpc_authorizations
            .get(&id)
            .cloned()
            .unwrap_or_default();
        drop(state);
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<ListVPCAssociationAuthorizationsResponse xmlns=\"{NS}\">"
        ));
        body.push_str(&format!("<HostedZoneId>{}</HostedZoneId>", esc(&id)));
        body.push_str("<VPCs>");
        for v in &vpcs {
            push_vpc_block(&mut body, "VPC", v);
        }
        body.push_str("</VPCs>");
        body.push_str("</ListVPCAssociationAuthorizationsResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_hosted_zones_by_vpc(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let vpc_id = req
            .query_params
            .get("vpcid")
            .cloned()
            .ok_or_else(|| invalid_argument("vpcid query parameter is required"))?;
        let vpc_region = req
            .query_params
            .get("vpcregion")
            .cloned()
            .ok_or_else(|| invalid_argument("vpcregion query parameter is required"))?;
        let state = self.state.read();
        let mut summaries: Vec<(String, String)> = Vec::new();
        if let Some(account) = state.accounts.get(DEFAULT_ACCOUNT) {
            for z in account.hosted_zones.values() {
                if z.vpcs.iter().any(|v| {
                    v.vpc_id.as_deref() == Some(vpc_id.as_str())
                        && v.vpc_region.as_deref() == Some(vpc_region.as_str())
                }) {
                    summaries.push((z.id.clone(), z.name.clone()));
                }
            }
        }
        drop(state);
        summaries.sort_by(|a, b| a.0.cmp(&b.0));
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<ListHostedZonesByVPCResponse xmlns=\"{NS}\">"));
        body.push_str("<HostedZoneSummaries>");
        for (id, name) in &summaries {
            body.push_str("<HostedZoneSummary>");
            body.push_str(&format!(
                "<HostedZoneId>/hostedzone/{}</HostedZoneId>",
                esc(id)
            ));
            body.push_str(&format!("<Name>{}</Name>", esc(name)));
            body.push_str("<Owner>");
            body.push_str(&format!("<OwningAccount>{DEFAULT_ACCOUNT}</OwningAccount>",));
            body.push_str("</Owner>");
            body.push_str("</HostedZoneSummary>");
        }
        body.push_str("</HostedZoneSummaries>");
        body.push_str("<MaxItems>100</MaxItems>");
        body.push_str("</ListHostedZonesByVPCResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

// ─── Reusable Delegation Set handlers ────────────────────────────────

impl Route53Service {
    fn create_reusable_delegation_set(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let cfg: CreateReusableDelegationSetRequest =
            xml_io::from_xml_root(&req.body).map_err(|e| {
                invalid_argument(format!(
                    "invalid CreateReusableDelegationSetRequest XML: {e}"
                ))
            })?;
        if cfg.caller_reference.is_empty() {
            return Err(invalid_argument("CallerReference is required"));
        }
        let mut state = self.state.write();
        let account = state
            .accounts
            .entry(DEFAULT_ACCOUNT.to_string())
            .or_default();
        if account
            .reusable_delegation_sets
            .values()
            .any(|d| d.caller_reference == cfg.caller_reference)
        {
            return Err(aws_error(
                StatusCode::CONFLICT,
                "DelegationSetAlreadyCreated",
                format!(
                    "A delegation set with caller reference {} already exists",
                    cfg.caller_reference
                ),
            ));
        }
        let id = generate_delegation_set_id();
        // When the caller supplies an existing hosted zone, reuse that
        // zone's authoritative name servers — that's the documented Route
        // 53 behavior for "promote a zone's delegation set to a reusable
        // one." Without that lookup, an unknown HostedZoneId silently
        // succeeds, which is what Cubic flagged.
        let name_servers = if let Some(hosted_zone_id) = cfg.hosted_zone_id.as_deref() {
            let hosted_zone_id = strip_zone_prefix(hosted_zone_id);
            account
                .hosted_zones
                .get(&hosted_zone_id)
                .ok_or_else(|| no_such_hosted_zone(&hosted_zone_id))?
                .name_servers
                .clone()
        } else {
            synth_name_servers(&id)
        };
        let ds = StoredReusableDelegationSet {
            id: id.clone(),
            caller_reference: cfg.caller_reference,
            name_servers,
        };
        account
            .reusable_delegation_sets
            .insert(id.clone(), ds.clone());
        drop(state);

        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<CreateReusableDelegationSetResponse xmlns=\"{NS}\">"
        ));
        push_delegation_set(&mut body, &ds);
        body.push_str("</CreateReusableDelegationSetResponse>");

        let mut headers = HeaderMap::new();
        if let Ok(loc) = http::HeaderValue::from_str(&format!("/2013-04-01/delegationset/{id}")) {
            headers.insert(http::header::LOCATION, loc);
        }
        Ok(xml_response(StatusCode::CREATED, body, headers))
    }

    fn get_reusable_delegation_set(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let state = self.state.read();
        let ds = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.reusable_delegation_sets.get(&id).cloned())
            .ok_or_else(|| no_such_delegation_set(&id))?;
        drop(state);
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<GetReusableDelegationSetResponse xmlns=\"{NS}\">"
        ));
        push_delegation_set(&mut body, &ds);
        body.push_str("</GetReusableDelegationSetResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn delete_reusable_delegation_set(
        &self,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_delegation_set(&id))?;
        if !account.reusable_delegation_sets.contains_key(&id) {
            return Err(no_such_delegation_set(&id));
        }
        if account
            .hosted_zones
            .values()
            .any(|z| z.delegation_set_id.as_deref() == Some(id.as_str()))
        {
            return Err(aws_error(
                StatusCode::BAD_REQUEST,
                "DelegationSetInUse",
                format!("Delegation set {id} is in use by one or more hosted zones"),
            ));
        }
        account.reusable_delegation_sets.remove(&id);
        drop(state);
        let mut body = String::with_capacity(128);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<DeleteReusableDelegationSetResponse xmlns=\"{NS}\"/>"
        ));
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_reusable_delegation_sets(
        &self,
        _req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let state = self.state.read();
        let mut sets: Vec<StoredReusableDelegationSet> = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .map(|a| a.reusable_delegation_sets.values().cloned().collect())
            .unwrap_or_default();
        drop(state);
        sets.sort_by(|a, b| a.id.cmp(&b.id));
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<ListReusableDelegationSetsResponse xmlns=\"{NS}\">"
        ));
        body.push_str("<DelegationSets>");
        for d in &sets {
            push_delegation_set(&mut body, d);
        }
        body.push_str("</DelegationSets>");
        body.push_str("<Marker></Marker>");
        body.push_str("<IsTruncated>false</IsTruncated>");
        body.push_str("<MaxItems>100</MaxItems>");
        body.push_str("</ListReusableDelegationSetsResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn get_reusable_delegation_set_limit(
        &self,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = require_id(route)?;
        let lim_type = route
            .second_id
            .clone()
            .ok_or_else(|| invalid_argument("limit Type is required"))?;
        let state = self.state.read();
        let account = state.accounts.get(DEFAULT_ACCOUNT);
        if !account
            .map(|a| a.reusable_delegation_sets.contains_key(&id))
            .unwrap_or(false)
        {
            return Err(no_such_delegation_set(&id));
        }
        let count = account
            .map(|a| {
                a.hosted_zones
                    .values()
                    .filter(|z| z.delegation_set_id.as_deref() == Some(id.as_str()))
                    .count() as u64
            })
            .unwrap_or(0);
        drop(state);
        if lim_type != "MAX_ZONES_BY_REUSABLE_DELEGATION_SET" {
            return Err(invalid_argument(format!(
                "Unknown reusable delegation set limit type: {lim_type}"
            )));
        }
        let mut body = String::with_capacity(256);
        body.push_str(XML_DECL);
        body.push_str(&format!(
            "<GetReusableDelegationSetLimitResponse xmlns=\"{NS}\">"
        ));
        body.push_str(&format!(
            "<Limit><Type>{}</Type><Value>500</Value></Limit>",
            esc(&lim_type)
        ));
        body.push_str(&format!("<Count>{count}</Count>"));
        body.push_str("</GetReusableDelegationSetLimitResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

// ─── Geo Locations + Account Limits ─────────────────────────────────

impl Route53Service {
    fn list_geo_locations(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let start_continent = req.query_params.get("startcontinentcode").cloned();
        let start_country = req.query_params.get("startcountrycode").cloned();
        let start_subdivision = req.query_params.get("startsubdivisioncode").cloned();
        let max_items: usize = req
            .query_params
            .get("maxitems")
            .and_then(|s| s.parse().ok())
            .unwrap_or(100);
        let mut filtered: Vec<GeoLocationEntry> = geo_locations()
            .iter()
            .filter(|g| {
                if let Some(c) = &start_continent {
                    if g.continent_code < c.as_str() {
                        return false;
                    }
                }
                if let Some(c) = &start_country {
                    if g.country_code < c.as_str() {
                        return false;
                    }
                }
                if let Some(c) = &start_subdivision {
                    if g.subdivision_code < c.as_str() {
                        return false;
                    }
                }
                true
            })
            .cloned()
            .collect();
        // Compute the next-page marker from the *filtered* list, not from
        // the unfiltered catalogue. With non-empty start parameters the
        // unfiltered offset would point at the wrong row entirely.
        let next = if filtered.len() > max_items {
            filtered.get(max_items).cloned()
        } else {
            None
        };
        let truncated = next.is_some();
        if truncated {
            filtered.truncate(max_items);
        }
        let mut body = String::with_capacity(2048);
        body.push_str(XML_DECL);
        body.push_str(&format!("<ListGeoLocationsResponse xmlns=\"{NS}\">"));
        body.push_str("<GeoLocationDetailsList>");
        for g in &filtered {
            push_geo_location_details(&mut body, g);
        }
        body.push_str("</GeoLocationDetailsList>");
        body.push_str(&format!("<IsTruncated>{truncated}</IsTruncated>"));
        if let Some(n) = &next {
            if !n.continent_code.is_empty() {
                body.push_str(&format!(
                    "<NextContinentCode>{}</NextContinentCode>",
                    esc(n.continent_code)
                ));
            }
            if !n.country_code.is_empty() {
                body.push_str(&format!(
                    "<NextCountryCode>{}</NextCountryCode>",
                    esc(n.country_code)
                ));
            }
            if !n.subdivision_code.is_empty() {
                body.push_str(&format!(
                    "<NextSubdivisionCode>{}</NextSubdivisionCode>",
                    esc(n.subdivision_code)
                ));
            }
        }
        body.push_str(&format!("<MaxItems>{max_items}</MaxItems>"));
        body.push_str("</ListGeoLocationsResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn get_geo_location(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let continent = req.query_params.get("continentcode").cloned();
        let country = req.query_params.get("countrycode").cloned();
        let subdivision = req.query_params.get("subdivisioncode").cloned();
        if continent.is_none() && country.is_none() {
            return Err(invalid_argument(
                "Either continentcode or countrycode must be supplied",
            ));
        }
        let entry = geo_locations().iter().find(|g| {
            let c = continent.as_deref().unwrap_or("");
            let co = country.as_deref().unwrap_or("");
            let sd = subdivision.as_deref().unwrap_or("");
            g.continent_code == c && g.country_code == co && g.subdivision_code == sd
        });
        let g = match entry {
            Some(g) => g,
            None => {
                return Err(aws_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchGeoLocation",
                    "The geo location requested is not supported".to_string(),
                ));
            }
        };
        let mut body = String::with_capacity(256);
        body.push_str(XML_DECL);
        body.push_str(&format!("<GetGeoLocationResponse xmlns=\"{NS}\">"));
        push_geo_location_details(&mut body, g);
        body.push_str("</GetGeoLocationResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn get_account_limit(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let lim_type = require_id(route)?;
        let state = self.state.read();
        let account = state.accounts.get(DEFAULT_ACCOUNT);
        let (value, count) = match lim_type.as_str() {
            "MAX_HEALTH_CHECKS_BY_OWNER" => (
                200_u64,
                account.map(|a| a.health_checks.len() as u64).unwrap_or(0),
            ),
            "MAX_HOSTED_ZONES_BY_OWNER" => (
                500_u64,
                account.map(|a| a.hosted_zones.len() as u64).unwrap_or(0),
            ),
            "MAX_REUSABLE_DELEGATION_SETS_BY_OWNER" => (
                100_u64,
                account
                    .map(|a| a.reusable_delegation_sets.len() as u64)
                    .unwrap_or(0),
            ),
            "MAX_TRAFFIC_POLICIES_BY_OWNER" => {
                let mut policies = std::collections::HashSet::new();
                if let Some(a) = account {
                    for (id, _) in a.traffic_policies.keys().map(|k| (k.0.clone(), 0)) {
                        policies.insert(id);
                    }
                }
                (50_u64, policies.len() as u64)
            }
            "MAX_TRAFFIC_POLICY_INSTANCES_BY_OWNER" => (
                5_u64,
                account
                    .map(|a| a.traffic_policy_instances.len() as u64)
                    .unwrap_or(0),
            ),
            other => {
                return Err(invalid_argument(format!(
                    "Unknown account limit type: {other}"
                )));
            }
        };
        drop(state);
        let mut body = String::with_capacity(256);
        body.push_str(XML_DECL);
        body.push_str(&format!("<GetAccountLimitResponse xmlns=\"{NS}\">"));
        body.push_str(&format!(
            "<Limit><Type>{}</Type><Value>{}</Value></Limit>",
            esc(&lim_type),
            value
        ));
        body.push_str(&format!("<Count>{count}</Count>"));
        body.push_str("</GetAccountLimitResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

// ─── Tag handlers ────────────────────────────────────────────────────

impl Route53Service {
    fn change_tags_for_resource(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let (res_type, res_id) = require_tag_target(route)?;
        let cfg: ChangeTagsForResourceRequest = xml_io::from_xml_root(&req.body).map_err(|e| {
            invalid_argument(format!("invalid ChangeTagsForResourceRequest XML: {e}"))
        })?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .entry(DEFAULT_ACCOUNT.to_string())
            .or_default();
        if !tag_target_exists(account, &res_type, &res_id) {
            return Err(no_such_tag_target(&res_type, &res_id));
        }
        let bag = account
            .tags
            .entry((res_type.clone(), res_id.clone()))
            .or_default();
        if let Some(adds) = &cfg.add_tags {
            for tag in &adds.tag {
                let key = match &tag.key {
                    Some(k) if !k.is_empty() => k.clone(),
                    _ => return Err(invalid_argument("Tag.Key is required")),
                };
                bag.insert(key, tag.value.clone().unwrap_or_default());
            }
        }
        if let Some(removes) = &cfg.remove_tag_keys {
            for key in &removes.key {
                bag.remove(key);
            }
        }
        if bag.is_empty() {
            account.tags.remove(&(res_type.clone(), res_id.clone()));
        }
        drop(state);
        let mut body = String::with_capacity(128);
        body.push_str(XML_DECL);
        body.push_str(&format!("<ChangeTagsForResourceResponse xmlns=\"{NS}\"/>"));
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_tags_for_resource(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let (res_type, res_id) = require_tag_target(route)?;
        let state = self.state.read();
        let account = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .ok_or_else(|| no_such_tag_target(&res_type, &res_id))?;
        if !tag_target_exists(account, &res_type, &res_id) {
            return Err(no_such_tag_target(&res_type, &res_id));
        }
        let bag = account
            .tags
            .get(&(res_type.clone(), res_id.clone()))
            .cloned()
            .unwrap_or_default();
        drop(state);
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<ListTagsForResourceResponse xmlns=\"{NS}\">"));
        push_resource_tag_set(&mut body, &res_type, &res_id, &bag);
        body.push_str("</ListTagsForResourceResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    fn list_tags_for_resources(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let res_type = require_id(route)?;
        if res_type != "healthcheck" && res_type != "hostedzone" {
            return Err(invalid_argument(format!(
                "Unknown tag resource type: {res_type}"
            )));
        }
        let cfg: ListTagsForResourcesRequest = xml_io::from_xml_root(&req.body).map_err(|e| {
            invalid_argument(format!("invalid ListTagsForResourcesRequest XML: {e}"))
        })?;
        if cfg.resource_ids.resource_id.is_empty() {
            return Err(invalid_argument("ResourceIds must contain at least one ID"));
        }
        let state = self.state.read();
        let account = state.accounts.get(DEFAULT_ACCOUNT);
        let mut sets: Vec<(String, BTreeMap<String, String>)> = Vec::new();
        for id in &cfg.resource_ids.resource_id {
            if let Some(a) = account {
                if !tag_target_exists(a, &res_type, id) {
                    return Err(no_such_tag_target(&res_type, id));
                }
                let bag = a
                    .tags
                    .get(&(res_type.clone(), id.clone()))
                    .cloned()
                    .unwrap_or_default();
                sets.push((id.clone(), bag));
            } else {
                return Err(no_such_tag_target(&res_type, id));
            }
        }
        drop(state);
        let mut body = String::with_capacity(1024);
        body.push_str(XML_DECL);
        body.push_str(&format!("<ListTagsForResourcesResponse xmlns=\"{NS}\">"));
        body.push_str("<ResourceTagSets>");
        for (id, bag) in &sets {
            push_resource_tag_set(&mut body, &res_type, id, bag);
        }
        body.push_str("</ResourceTagSets>");
        body.push_str("</ListTagsForResourcesResponse>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

// ─── Batch 5 helpers ─────────────────────────────────────────────────

fn require_vpc(v: &VPC) -> Result<(), AwsServiceError> {
    if v.vpc_id.as_deref().unwrap_or("").is_empty() {
        return Err(invalid_argument("VPC.VPCId is required"));
    }
    if v.vpc_region.as_deref().unwrap_or("").is_empty() {
        return Err(invalid_argument("VPC.VPCRegion is required"));
    }
    Ok(())
}

fn same_vpc(a: &VPC, b: &VPC) -> bool {
    a.vpc_id == b.vpc_id && a.vpc_region == b.vpc_region
}

fn push_delegation_set(out: &mut String, d: &StoredReusableDelegationSet) {
    out.push_str("<DelegationSet>");
    out.push_str(&format!("<Id>{}</Id>", esc(&d.id)));
    out.push_str(&format!(
        "<CallerReference>{}</CallerReference>",
        esc(&d.caller_reference)
    ));
    out.push_str("<NameServers>");
    for ns in &d.name_servers {
        out.push_str(&format!("<NameServer>{}</NameServer>", esc(ns)));
    }
    out.push_str("</NameServers>");
    out.push_str("</DelegationSet>");
}

fn generate_delegation_set_id() -> String {
    let raw = Uuid::new_v4().simple().to_string().to_uppercase();
    format!("N{}", &raw[..14])
}

fn no_such_delegation_set(id: &str) -> AwsServiceError {
    aws_error(
        StatusCode::NOT_FOUND,
        "NoSuchDelegationSet",
        format!("No reusable delegation set found with ID: {id}"),
    )
}

fn require_tag_target(route: &Route) -> Result<(String, String), AwsServiceError> {
    let res_type = require_id(route)?;
    let res_id = route
        .second_id
        .clone()
        .ok_or_else(|| invalid_argument("ResourceId is required"))?;
    if res_type != "healthcheck" && res_type != "hostedzone" {
        return Err(invalid_argument(format!(
            "Unknown tag resource type: {res_type}"
        )));
    }
    Ok((res_type, res_id))
}

fn tag_target_exists(account: &AccountState, res_type: &str, res_id: &str) -> bool {
    match res_type {
        "healthcheck" => account.health_checks.contains_key(res_id),
        "hostedzone" => account.hosted_zones.contains_key(res_id),
        _ => false,
    }
}

fn no_such_tag_target(res_type: &str, res_id: &str) -> AwsServiceError {
    let code = match res_type {
        "healthcheck" => "NoSuchHealthCheck",
        "hostedzone" => "NoSuchHostedZone",
        _ => "NoSuchResource",
    };
    aws_error(
        StatusCode::NOT_FOUND,
        code,
        format!("No {res_type} found with ID: {res_id}"),
    )
}

fn push_resource_tag_set(
    out: &mut String,
    res_type: &str,
    res_id: &str,
    bag: &BTreeMap<String, String>,
) {
    out.push_str("<ResourceTagSet>");
    out.push_str(&format!("<ResourceType>{}</ResourceType>", esc(res_type)));
    out.push_str(&format!("<ResourceId>{}</ResourceId>", esc(res_id)));
    out.push_str("<Tags>");
    let mut pairs: Vec<(&String, &String)> = bag.iter().collect();
    pairs.sort_by(|a, b| a.0.cmp(b.0));
    for (k, v) in pairs {
        out.push_str("<Tag>");
        out.push_str(&format!("<Key>{}</Key>", esc(k)));
        out.push_str(&format!("<Value>{}</Value>", esc(v)));
        out.push_str("</Tag>");
    }
    out.push_str("</Tags>");
    out.push_str("</ResourceTagSet>");
}

#[derive(Debug, Clone)]
struct GeoLocationEntry {
    continent_code: &'static str,
    continent_name: &'static str,
    country_code: &'static str,
    country_name: &'static str,
    subdivision_code: &'static str,
    subdivision_name: &'static str,
}

fn push_geo_location_details(out: &mut String, g: &GeoLocationEntry) {
    out.push_str("<GeoLocationDetails>");
    if !g.continent_code.is_empty() {
        out.push_str(&format!(
            "<ContinentCode>{}</ContinentCode>",
            esc(g.continent_code)
        ));
    }
    if !g.continent_name.is_empty() {
        out.push_str(&format!(
            "<ContinentName>{}</ContinentName>",
            esc(g.continent_name)
        ));
    }
    if !g.country_code.is_empty() {
        out.push_str(&format!(
            "<CountryCode>{}</CountryCode>",
            esc(g.country_code)
        ));
    }
    if !g.country_name.is_empty() {
        out.push_str(&format!(
            "<CountryName>{}</CountryName>",
            esc(g.country_name)
        ));
    }
    if !g.subdivision_code.is_empty() {
        out.push_str(&format!(
            "<SubdivisionCode>{}</SubdivisionCode>",
            esc(g.subdivision_code)
        ));
    }
    if !g.subdivision_name.is_empty() {
        out.push_str(&format!(
            "<SubdivisionName>{}</SubdivisionName>",
            esc(g.subdivision_name)
        ));
    }
    out.push_str("</GeoLocationDetails>");
}

/// A representative slice of the geographic locations Route 53 supports
/// for geolocation routing. fakecloud does not track every ISO-3166-1
/// country (Route 53 supports 200+) — this list is enough to exercise
/// continent / country / subdivision pagination with deterministic
/// values across CI runs. `*` is the AWS-documented fallback "default
/// resource" continent code.
fn geo_locations() -> &'static [GeoLocationEntry] {
    &[
        GeoLocationEntry {
            continent_code: "AF",
            continent_name: "Africa",
            country_code: "",
            country_name: "",
            subdivision_code: "",
            subdivision_name: "",
        },
        GeoLocationEntry {
            continent_code: "AN",
            continent_name: "Antarctica",
            country_code: "",
            country_name: "",
            subdivision_code: "",
            subdivision_name: "",
        },
        GeoLocationEntry {
            continent_code: "AS",
            continent_name: "Asia",
            country_code: "",
            country_name: "",
            subdivision_code: "",
            subdivision_name: "",
        },
        GeoLocationEntry {
            continent_code: "EU",
            continent_name: "Europe",
            country_code: "",
            country_name: "",
            subdivision_code: "",
            subdivision_name: "",
        },
        GeoLocationEntry {
            continent_code: "NA",
            continent_name: "North America",
            country_code: "",
            country_name: "",
            subdivision_code: "",
            subdivision_name: "",
        },
        GeoLocationEntry {
            continent_code: "OC",
            continent_name: "Oceania",
            country_code: "",
            country_name: "",
            subdivision_code: "",
            subdivision_name: "",
        },
        GeoLocationEntry {
            continent_code: "SA",
            continent_name: "South America",
            country_code: "",
            country_name: "",
            subdivision_code: "",
            subdivision_name: "",
        },
        GeoLocationEntry {
            continent_code: "",
            continent_name: "",
            country_code: "*",
            country_name: "Default",
            subdivision_code: "",
            subdivision_name: "",
        },
        GeoLocationEntry {
            continent_code: "",
            continent_name: "",
            country_code: "BR",
            country_name: "Brazil",
            subdivision_code: "",
            subdivision_name: "",
        },
        GeoLocationEntry {
            continent_code: "",
            continent_name: "",
            country_code: "CA",
            country_name: "Canada",
            subdivision_code: "",
            subdivision_name: "",
        },
        GeoLocationEntry {
            continent_code: "",
            continent_name: "",
            country_code: "DE",
            country_name: "Germany",
            subdivision_code: "",
            subdivision_name: "",
        },
        GeoLocationEntry {
            continent_code: "",
            continent_name: "",
            country_code: "FR",
            country_name: "France",
            subdivision_code: "",
            subdivision_name: "",
        },
        GeoLocationEntry {
            continent_code: "",
            continent_name: "",
            country_code: "GB",
            country_name: "United Kingdom",
            subdivision_code: "",
            subdivision_name: "",
        },
        GeoLocationEntry {
            continent_code: "",
            continent_name: "",
            country_code: "JP",
            country_name: "Japan",
            subdivision_code: "",
            subdivision_name: "",
        },
        GeoLocationEntry {
            continent_code: "",
            continent_name: "",
            country_code: "US",
            country_name: "United States",
            subdivision_code: "",
            subdivision_name: "",
        },
        GeoLocationEntry {
            continent_code: "",
            continent_name: "",
            country_code: "US",
            country_name: "United States",
            subdivision_code: "CA",
            subdivision_name: "California",
        },
        GeoLocationEntry {
            continent_code: "",
            continent_name: "",
            country_code: "US",
            country_name: "United States",
            subdivision_code: "NY",
            subdivision_name: "New York",
        },
        GeoLocationEntry {
            continent_code: "",
            continent_name: "",
            country_code: "US",
            country_name: "United States",
            subdivision_code: "TX",
            subdivision_name: "Texas",
        },
        GeoLocationEntry {
            continent_code: "",
            continent_name: "",
            country_code: "US",
            country_name: "United States",
            subdivision_code: "WA",
            subdivision_name: "Washington",
        },
    ]
}
