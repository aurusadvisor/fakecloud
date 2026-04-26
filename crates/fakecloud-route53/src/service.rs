//! Route 53 REST-XML service implementation.

use std::sync::Arc;

use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use http::{HeaderMap, StatusCode};
use parking_lot::RwLock;
use uuid::Uuid;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError, ResponseBody};

use crate::model::{
    ChangeResourceRecordSetsRequest, CreateHostedZoneRequest, ResourceRecordSet,
    UpdateHostedZoneCommentRequest, UpdateHostedZoneFeaturesRequest,
};
use crate::router::{route, Route};
use crate::state::{
    AccountState, Route53Accounts, SharedRoute53State, StoredChange, StoredHostedZone,
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
