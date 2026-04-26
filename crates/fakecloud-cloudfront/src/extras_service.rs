//! Handlers for CloudFront Batch 6a: VPC Origins, Anycast IP Lists,
//! Trust Stores, Resource Policies.

use chrono::Utc;
use http::{HeaderMap, StatusCode};

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::extras::{
    CaCertificatesBundleSource, CreateAnycastIpListRequest, CreateTrustStoreRequest,
    CreateVpcOriginRequest, ResourcePolicyRequest, StoredAnycastIpList, StoredResourcePolicy,
    StoredTrustStore, StoredVpcOrigin, UpdateAnycastIpListRequest, VpcOriginEndpointConfig,
};
use crate::policies::{
    not_found, precondition_failed, require_if_match, rfc3339, route_id, xml_with_etag,
};
use crate::router::Route;
use crate::service::{
    aws_error, esc, generate_id_with_prefix, invalid_argument, xml_response, CloudFrontService,
    DEFAULT_ACCOUNT,
};
use crate::xml_io;

const NS: &str = crate::NAMESPACE;
const XML_DECL: &str = r#"<?xml version="1.0" encoding="UTF-8"?>"#;

// ─── VPC Origin ───────────────────────────────────────────────────────

impl CloudFrontService {
    pub(crate) fn create_vpc_origin(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let parsed: CreateVpcOriginRequest = xml_io::from_xml_root(&req.body)
            .map_err(|e| invalid_argument(format!("invalid CreateVpcOriginRequest XML: {e}")))?;
        let cfg = parsed.vpc_origin_endpoint_config;
        if cfg.name.is_empty() {
            return Err(invalid_argument("Name is required"));
        }
        if cfg.arn.is_empty() {
            return Err(invalid_argument("Arn is required"));
        }
        let mut state = self.state.write();
        let account = state
            .accounts
            .entry(DEFAULT_ACCOUNT.to_string())
            .or_default();
        if account
            .vpc_origins
            .values()
            .any(|v| v.config.name == cfg.name)
        {
            return Err(aws_error(
                StatusCode::CONFLICT,
                "EntityAlreadyExists",
                format!("VpcOrigin {} already exists", cfg.name),
            ));
        }
        let id = generate_id_with_prefix("VO");
        let etag = generate_id_with_prefix("E");
        let now = Utc::now();
        let arn = format!("arn:aws:cloudfront::{}:vpc-origin/{}", DEFAULT_ACCOUNT, id);
        let stored = StoredVpcOrigin {
            id: id.clone(),
            arn,
            status: "Deployed".to_string(),
            etag: etag.clone(),
            created_time: now,
            last_modified_time: now,
            config: cfg,
        };
        account.vpc_origins.insert(id.clone(), stored.clone());
        drop(state);
        let body = render_vpc_origin(&stored);
        Ok(xml_with_etag(StatusCode::CREATED, body, &etag, Some(&id)))
    }

    pub(crate) fn get_vpc_origin(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let id = route_id(route, "VpcOrigin")?;
        let state = self.state.read();
        let v = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.vpc_origins.get(&id).cloned())
            .ok_or_else(|| not_found("VpcOrigin", &id))?;
        drop(state);
        let body = render_vpc_origin(&v);
        Ok(xml_with_etag(StatusCode::OK, body, &v.etag, None))
    }

    pub(crate) fn update_vpc_origin(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = route_id(route, "VpcOrigin")?;
        let if_match = require_if_match(req)?;
        let cfg: VpcOriginEndpointConfig = xml_io::from_xml_root(&req.body)
            .map_err(|e| invalid_argument(format!("invalid VpcOriginEndpointConfig XML: {e}")))?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| not_found("VpcOrigin", &id))?;
        let v = account
            .vpc_origins
            .get_mut(&id)
            .ok_or_else(|| not_found("VpcOrigin", &id))?;
        if v.etag != if_match {
            return Err(precondition_failed());
        }
        if cfg.name.is_empty() {
            return Err(invalid_argument("Name is required"));
        }
        if cfg.arn.is_empty() {
            return Err(invalid_argument("Arn is required"));
        }
        v.config = cfg;
        v.etag = generate_id_with_prefix("E");
        v.last_modified_time = Utc::now();
        let snap = v.clone();
        drop(state);
        let body = render_vpc_origin(&snap);
        Ok(xml_with_etag(StatusCode::OK, body, &snap.etag, None))
    }

    pub(crate) fn delete_vpc_origin(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = route_id(route, "VpcOrigin")?;
        let if_match = require_if_match(req)?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| not_found("VpcOrigin", &id))?;
        let v = account
            .vpc_origins
            .get(&id)
            .ok_or_else(|| not_found("VpcOrigin", &id))?;
        if v.etag != if_match {
            return Err(precondition_failed());
        }
        let arn = v.arn.clone();
        let snap = v.clone();
        account.vpc_origins.remove(&id);
        account.tags.remove(&arn);
        drop(state);
        let body = render_vpc_origin(&snap);
        Ok(xml_with_etag(StatusCode::OK, body, &snap.etag, None))
    }

    pub(crate) fn list_vpc_origins(
        &self,
        _req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let state = self.state.read();
        let mut items: Vec<StoredVpcOrigin> = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .map(|a| a.vpc_origins.values().cloned().collect())
            .unwrap_or_default();
        drop(state);
        items.sort_by(|a, b| a.id.cmp(&b.id));

        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<VpcOriginList xmlns=\"{NS}\">"));
        body.push_str("<Marker></Marker>");
        body.push_str("<MaxItems>100</MaxItems>");
        body.push_str(&format!("<IsTruncated>{}</IsTruncated>", false));
        body.push_str(&format!("<Quantity>{}</Quantity>", items.len()));
        body.push_str("<Items>");
        for v in &items {
            body.push_str("<VpcOriginSummary>");
            body.push_str(&format!("<Id>{}</Id>", esc(&v.id)));
            body.push_str(&format!("<Name>{}</Name>", esc(&v.config.name)));
            body.push_str(&format!("<Status>{}</Status>", esc(&v.status)));
            body.push_str(&format!(
                "<CreatedTime>{}</CreatedTime>",
                rfc3339(&v.created_time)
            ));
            body.push_str(&format!(
                "<LastModifiedTime>{}</LastModifiedTime>",
                rfc3339(&v.last_modified_time)
            ));
            body.push_str(&format!("<Arn>{}</Arn>", esc(&v.arn)));
            body.push_str(&format!(
                "<OriginEndpointArn>{}</OriginEndpointArn>",
                esc(&v.config.arn)
            ));
            body.push_str("</VpcOriginSummary>");
        }
        body.push_str("</Items>");
        body.push_str("</VpcOriginList>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

// ─── Anycast IP List ──────────────────────────────────────────────────

impl CloudFrontService {
    pub(crate) fn create_anycast_ip_list(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let cfg: CreateAnycastIpListRequest = xml_io::from_xml_root(&req.body).map_err(|e| {
            invalid_argument(format!("invalid CreateAnycastIpListRequest XML: {e}"))
        })?;
        if cfg.name.is_empty() {
            return Err(invalid_argument("Name is required"));
        }
        if cfg.ip_count != 3 && cfg.ip_count != 21 {
            return Err(invalid_argument("IpCount must be 3 or 21"));
        }
        let mut state = self.state.write();
        let account = state
            .accounts
            .entry(DEFAULT_ACCOUNT.to_string())
            .or_default();
        if account
            .anycast_ip_lists
            .values()
            .any(|a| a.name == cfg.name)
        {
            return Err(aws_error(
                StatusCode::CONFLICT,
                "EntityAlreadyExists",
                format!("AnycastIpList {} already exists", cfg.name),
            ));
        }
        let id = generate_id_with_prefix("AIL");
        let arn = format!(
            "arn:aws:cloudfront::{}:anycast-ip-list/{}",
            DEFAULT_ACCOUNT, id
        );
        // Synthesize deterministic ipv4 addresses for the list.
        let anycast_ips: Vec<String> = (0..cfg.ip_count)
            .map(|i| format!("198.51.100.{}", (i + 1) as u8))
            .collect();
        let etag = generate_id_with_prefix("E");
        let stored = StoredAnycastIpList {
            id: id.clone(),
            name: cfg.name,
            status: "Deployed".to_string(),
            arn,
            ip_count: cfg.ip_count,
            ip_address_type: cfg.ip_address_type,
            anycast_ips,
            last_modified_time: Utc::now(),
            etag: etag.clone(),
        };
        account.anycast_ip_lists.insert(id.clone(), stored.clone());
        drop(state);
        let body = render_anycast_ip_list(&stored);
        Ok(xml_with_etag(StatusCode::CREATED, body, &etag, Some(&id)))
    }

    pub(crate) fn get_anycast_ip_list(
        &self,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = route_id(route, "AnycastIpList")?;
        let state = self.state.read();
        let a = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.anycast_ip_lists.get(&id).cloned())
            .ok_or_else(|| not_found("AnycastIpList", &id))?;
        drop(state);
        let body = render_anycast_ip_list(&a);
        Ok(xml_with_etag(StatusCode::OK, body, &a.etag, None))
    }

    pub(crate) fn update_anycast_ip_list(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = route_id(route, "AnycastIpList")?;
        let if_match = require_if_match(req)?;
        let cfg: UpdateAnycastIpListRequest = xml_io::from_xml_root(&req.body).map_err(|e| {
            invalid_argument(format!("invalid UpdateAnycastIpListRequest XML: {e}"))
        })?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| not_found("AnycastIpList", &id))?;
        let a = account
            .anycast_ip_lists
            .get_mut(&id)
            .ok_or_else(|| not_found("AnycastIpList", &id))?;
        if a.etag != if_match {
            return Err(precondition_failed());
        }
        if let Some(t) = cfg.ip_address_type {
            a.ip_address_type = Some(t);
        }
        a.last_modified_time = Utc::now();
        a.etag = generate_id_with_prefix("E");
        let snap = a.clone();
        drop(state);
        let body = render_anycast_ip_list(&snap);
        Ok(xml_with_etag(StatusCode::OK, body, &snap.etag, None))
    }

    pub(crate) fn delete_anycast_ip_list(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = route_id(route, "AnycastIpList")?;
        let if_match = require_if_match(req)?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| not_found("AnycastIpList", &id))?;
        let a = account
            .anycast_ip_lists
            .get(&id)
            .ok_or_else(|| not_found("AnycastIpList", &id))?;
        if a.etag != if_match {
            return Err(precondition_failed());
        }
        let arn = a.arn.clone();
        account.anycast_ip_lists.remove(&id);
        account.tags.remove(&arn);
        drop(state);
        Ok(crate::policies::empty(StatusCode::NO_CONTENT))
    }

    pub(crate) fn list_anycast_ip_lists(
        &self,
        _req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let state = self.state.read();
        let mut items: Vec<StoredAnycastIpList> = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .map(|a| a.anycast_ip_lists.values().cloned().collect())
            .unwrap_or_default();
        drop(state);
        items.sort_by(|a, b| a.id.cmp(&b.id));

        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<AnycastIpListCollection xmlns=\"{NS}\">"));
        body.push_str("<Marker></Marker>");
        body.push_str("<MaxItems>100</MaxItems>");
        body.push_str(&format!("<IsTruncated>{}</IsTruncated>", false));
        body.push_str(&format!("<Quantity>{}</Quantity>", items.len()));
        body.push_str("<Items>");
        for a in &items {
            body.push_str("<AnycastIpListSummary>");
            push_anycast_summary(&mut body, a);
            body.push_str("</AnycastIpListSummary>");
        }
        body.push_str("</Items>");
        body.push_str("</AnycastIpListCollection>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

// ─── Trust Store ──────────────────────────────────────────────────────

impl CloudFrontService {
    pub(crate) fn create_trust_store(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let cfg: CreateTrustStoreRequest = xml_io::from_xml_root(&req.body)
            .map_err(|e| invalid_argument(format!("invalid CreateTrustStoreRequest XML: {e}")))?;
        if cfg.name.is_empty() {
            return Err(invalid_argument("Name is required"));
        }
        if cfg
            .ca_certificates_bundle_source
            .ca_certificates_bundle_s3_location
            .is_none()
        {
            return Err(invalid_argument(
                "CaCertificatesBundleSource must specify a non-empty member",
            ));
        }
        let mut state = self.state.write();
        let account = state
            .accounts
            .entry(DEFAULT_ACCOUNT.to_string())
            .or_default();
        if account.trust_stores.values().any(|t| t.name == cfg.name) {
            return Err(aws_error(
                StatusCode::CONFLICT,
                "EntityAlreadyExists",
                format!("TrustStore {} already exists", cfg.name),
            ));
        }
        let id = generate_id_with_prefix("TS");
        let arn = format!("arn:aws:cloudfront::{}:trust-store/{}", DEFAULT_ACCOUNT, id);
        let etag = generate_id_with_prefix("E");
        let stored = StoredTrustStore {
            id: id.clone(),
            arn,
            name: cfg.name,
            etag: etag.clone(),
            last_modified_time: Utc::now(),
            ca_certificates_bundle_source: cfg.ca_certificates_bundle_source,
        };
        account.trust_stores.insert(id.clone(), stored.clone());
        drop(state);
        let body = render_trust_store(&stored);
        Ok(xml_with_etag(StatusCode::CREATED, body, &etag, Some(&id)))
    }

    pub(crate) fn get_trust_store(&self, route: &Route) -> Result<AwsResponse, AwsServiceError> {
        let id = route_id(route, "TrustStore")?;
        let state = self.state.read();
        let t = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.trust_stores.get(&id).cloned())
            .ok_or_else(|| not_found("TrustStore", &id))?;
        drop(state);
        let body = render_trust_store(&t);
        Ok(xml_with_etag(StatusCode::OK, body, &t.etag, None))
    }

    pub(crate) fn update_trust_store(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = route_id(route, "TrustStore")?;
        let if_match = require_if_match(req)?;
        let bundle: CaCertificatesBundleSource = xml_io::from_xml_root(&req.body).map_err(|e| {
            invalid_argument(format!("invalid CaCertificatesBundleSource XML: {e}"))
        })?;
        if bundle.ca_certificates_bundle_s3_location.is_none() {
            return Err(invalid_argument(
                "CaCertificatesBundleSource must specify a non-empty member",
            ));
        }
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| not_found("TrustStore", &id))?;
        let t = account
            .trust_stores
            .get_mut(&id)
            .ok_or_else(|| not_found("TrustStore", &id))?;
        if t.etag != if_match {
            return Err(precondition_failed());
        }
        t.ca_certificates_bundle_source = bundle;
        t.last_modified_time = Utc::now();
        t.etag = generate_id_with_prefix("E");
        let snap = t.clone();
        drop(state);
        let body = render_trust_store(&snap);
        Ok(xml_with_etag(StatusCode::OK, body, &snap.etag, None))
    }

    pub(crate) fn delete_trust_store(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let id = route_id(route, "TrustStore")?;
        let if_match = require_if_match(req)?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| not_found("TrustStore", &id))?;
        let t = account
            .trust_stores
            .get(&id)
            .ok_or_else(|| not_found("TrustStore", &id))?;
        if t.etag != if_match {
            return Err(precondition_failed());
        }
        let arn = t.arn.clone();
        account.trust_stores.remove(&id);
        account.tags.remove(&arn);
        drop(state);
        Ok(crate::policies::empty(StatusCode::NO_CONTENT))
    }

    pub(crate) fn list_trust_stores(
        &self,
        _req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let state = self.state.read();
        let mut items: Vec<StoredTrustStore> = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .map(|a| a.trust_stores.values().cloned().collect())
            .unwrap_or_default();
        drop(state);
        items.sort_by(|a, b| a.id.cmp(&b.id));

        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<ListTrustStoresResult xmlns=\"{NS}\">"));
        body.push_str("<TrustStoreList>");
        for t in &items {
            body.push_str("<TrustStoreSummary>");
            body.push_str(&format!("<Id>{}</Id>", esc(&t.id)));
            body.push_str(&format!("<Arn>{}</Arn>", esc(&t.arn)));
            body.push_str(&format!("<Name>{}</Name>", esc(&t.name)));
            body.push_str(&format!(
                "<LastModifiedTime>{}</LastModifiedTime>",
                rfc3339(&t.last_modified_time)
            ));
            body.push_str("</TrustStoreSummary>");
        }
        body.push_str("</TrustStoreList>");
        body.push_str("</ListTrustStoresResult>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

// ─── Resource Policy ──────────────────────────────────────────────────

impl CloudFrontService {
    pub(crate) fn put_resource_policy(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let parsed: ResourcePolicyRequest = xml_io::from_xml_root(&req.body)
            .map_err(|e| invalid_argument(format!("invalid PutResourcePolicyRequest XML: {e}")))?;
        if parsed.resource_arn.is_empty() {
            return Err(invalid_argument("ResourceArn is required"));
        }
        let policy = parsed
            .policy_document
            .ok_or_else(|| invalid_argument("PolicyDocument is required"))?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .entry(DEFAULT_ACCOUNT.to_string())
            .or_default();
        account.resource_policies.insert(
            parsed.resource_arn.clone(),
            StoredResourcePolicy {
                resource_arn: parsed.resource_arn,
                policy_document: policy,
            },
        );
        drop(state);
        let mut body = String::with_capacity(128);
        body.push_str(XML_DECL);
        body.push_str(&format!("<PutResourcePolicyResult xmlns=\"{NS}\"/>"));
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    pub(crate) fn get_resource_policy(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let parsed: ResourcePolicyRequest = xml_io::from_xml_root(&req.body)
            .map_err(|e| invalid_argument(format!("invalid GetResourcePolicyRequest XML: {e}")))?;
        if parsed.resource_arn.is_empty() {
            return Err(invalid_argument("ResourceArn is required"));
        }
        let state = self.state.read();
        let p = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.resource_policies.get(&parsed.resource_arn).cloned())
            .ok_or_else(|| not_found("ResourcePolicy", &parsed.resource_arn))?;
        drop(state);
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<GetResourcePolicyResult xmlns=\"{NS}\">"));
        body.push_str(&format!(
            "<ResourceArn>{}</ResourceArn>",
            esc(&p.resource_arn)
        ));
        body.push_str(&format!(
            "<PolicyDocument>{}</PolicyDocument>",
            esc(&p.policy_document)
        ));
        body.push_str("</GetResourcePolicyResult>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    pub(crate) fn delete_resource_policy(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let parsed: ResourcePolicyRequest = xml_io::from_xml_root(&req.body).map_err(|e| {
            invalid_argument(format!("invalid DeleteResourcePolicyRequest XML: {e}"))
        })?;
        if parsed.resource_arn.is_empty() {
            return Err(invalid_argument("ResourceArn is required"));
        }
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| not_found("ResourcePolicy", &parsed.resource_arn))?;
        if account
            .resource_policies
            .remove(&parsed.resource_arn)
            .is_none()
        {
            return Err(not_found("ResourcePolicy", &parsed.resource_arn));
        }
        drop(state);
        Ok(crate::policies::empty(StatusCode::NO_CONTENT))
    }
}

// ─── XML render helpers ───────────────────────────────────────────────

fn render_vpc_origin(v: &StoredVpcOrigin) -> String {
    let mut out = String::with_capacity(512);
    out.push_str(XML_DECL);
    out.push_str(&format!("<VpcOrigin xmlns=\"{NS}\">"));
    out.push_str(&format!("<Id>{}</Id>", esc(&v.id)));
    out.push_str(&format!("<Arn>{}</Arn>", esc(&v.arn)));
    out.push_str(&format!("<Status>{}</Status>", esc(&v.status)));
    out.push_str(&format!(
        "<CreatedTime>{}</CreatedTime>",
        rfc3339(&v.created_time)
    ));
    out.push_str(&format!(
        "<LastModifiedTime>{}</LastModifiedTime>",
        rfc3339(&v.last_modified_time)
    ));
    out.push_str(&render_vpc_origin_endpoint_config(&v.config));
    out.push_str("</VpcOrigin>");
    out
}

fn render_vpc_origin_endpoint_config(c: &VpcOriginEndpointConfig) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("<VpcOriginEndpointConfig>");
    out.push_str(&format!("<Name>{}</Name>", esc(&c.name)));
    out.push_str(&format!("<Arn>{}</Arn>", esc(&c.arn)));
    out.push_str(&format!("<HTTPPort>{}</HTTPPort>", c.http_port));
    out.push_str(&format!("<HTTPSPort>{}</HTTPSPort>", c.https_port));
    out.push_str(&format!(
        "<OriginProtocolPolicy>{}</OriginProtocolPolicy>",
        esc(&c.origin_protocol_policy)
    ));
    if let Some(ssl) = &c.origin_ssl_protocols {
        out.push_str("<OriginSslProtocols>");
        out.push_str(&format!("<Quantity>{}</Quantity>", ssl.quantity));
        out.push_str("<Items>");
        for p in &ssl.items.ssl_protocol {
            out.push_str(&format!("<SslProtocol>{}</SslProtocol>", esc(p)));
        }
        out.push_str("</Items>");
        out.push_str("</OriginSslProtocols>");
    }
    out.push_str("</VpcOriginEndpointConfig>");
    out
}

fn render_anycast_ip_list(a: &StoredAnycastIpList) -> String {
    let mut out = String::with_capacity(512);
    out.push_str(XML_DECL);
    out.push_str(&format!("<AnycastIpList xmlns=\"{NS}\">"));
    out.push_str(&format!("<Id>{}</Id>", esc(&a.id)));
    out.push_str(&format!("<Name>{}</Name>", esc(&a.name)));
    out.push_str(&format!("<Status>{}</Status>", esc(&a.status)));
    out.push_str(&format!("<Arn>{}</Arn>", esc(&a.arn)));
    if let Some(t) = &a.ip_address_type {
        out.push_str(&format!("<IpAddressType>{}</IpAddressType>", esc(t)));
    }
    out.push_str("<AnycastIps>");
    for ip in &a.anycast_ips {
        out.push_str(&format!("<AnycastIp>{}</AnycastIp>", esc(ip)));
    }
    out.push_str("</AnycastIps>");
    out.push_str(&format!("<IpCount>{}</IpCount>", a.ip_count));
    out.push_str(&format!(
        "<LastModifiedTime>{}</LastModifiedTime>",
        rfc3339(&a.last_modified_time)
    ));
    out.push_str("</AnycastIpList>");
    out
}

fn push_anycast_summary(out: &mut String, a: &StoredAnycastIpList) {
    out.push_str(&format!("<Id>{}</Id>", esc(&a.id)));
    out.push_str(&format!("<Name>{}</Name>", esc(&a.name)));
    out.push_str(&format!("<Status>{}</Status>", esc(&a.status)));
    out.push_str(&format!("<Arn>{}</Arn>", esc(&a.arn)));
    if let Some(t) = &a.ip_address_type {
        out.push_str(&format!("<IpAddressType>{}</IpAddressType>", esc(t)));
    }
    out.push_str(&format!("<IpCount>{}</IpCount>", a.ip_count));
    out.push_str(&format!(
        "<LastModifiedTime>{}</LastModifiedTime>",
        rfc3339(&a.last_modified_time)
    ));
}

fn render_trust_store(t: &StoredTrustStore) -> String {
    let mut out = String::with_capacity(512);
    out.push_str(XML_DECL);
    out.push_str(&format!("<TrustStore xmlns=\"{NS}\">"));
    out.push_str(&format!("<Id>{}</Id>", esc(&t.id)));
    out.push_str(&format!("<Arn>{}</Arn>", esc(&t.arn)));
    out.push_str(&format!("<Name>{}</Name>", esc(&t.name)));
    out.push_str(&format!(
        "<LastModifiedTime>{}</LastModifiedTime>",
        rfc3339(&t.last_modified_time)
    ));
    out.push_str(&render_bundle_source(&t.ca_certificates_bundle_source));
    out.push_str("</TrustStore>");
    out
}

fn render_bundle_source(s: &CaCertificatesBundleSource) -> String {
    let mut out = String::with_capacity(256);
    out.push_str("<CaCertificatesBundleSource>");
    if let Some(s3) = &s.ca_certificates_bundle_s3_location {
        out.push_str("<CaCertificatesBundleS3Location>");
        out.push_str(&format!("<Bucket>{}</Bucket>", esc(&s3.bucket)));
        out.push_str(&format!("<Key>{}</Key>", esc(&s3.key)));
        out.push_str(&format!("<Region>{}</Region>", esc(&s3.region)));
        if let Some(v) = &s3.version {
            out.push_str(&format!("<Version>{}</Version>", esc(v)));
        }
        out.push_str("</CaCertificatesBundleS3Location>");
    }
    out.push_str("</CaCertificatesBundleSource>");
    out
}
