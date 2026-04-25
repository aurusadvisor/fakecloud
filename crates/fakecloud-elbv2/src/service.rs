//! Elastic Load Balancing v2 (ALB/NLB/GWLB) service implementation.
//!
//! Wire protocol: AWS Query (form-encoded request, XML response). Endpoint
//! prefix `elasticloadbalancing`, SigV4 service `elasticloadbalancing`.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use http::StatusCode;

use fakecloud_core::query::{
    optional_query_param, query_metadata_only_xml, query_response_xml, required_query_param,
};
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};

use crate::state::{AvailabilityZone, LoadBalancer, LoadBalancerAddress, SharedElbv2State, Tag};
use crate::ELBV2_NAMESPACE;

const NS: &str = ELBV2_NAMESPACE;

const ELBV2_SUPPORTED_ACTIONS: &[&str] = &[
    "CreateLoadBalancer",
    "DescribeLoadBalancers",
    "DeleteLoadBalancer",
    "SetSubnets",
    "SetSecurityGroups",
    "SetIpAddressType",
    "ModifyIpPools",
    "AddTags",
    "RemoveTags",
    "DescribeTags",
    "DescribeAccountLimits",
    "DescribeSSLPolicies",
    "CreateTargetGroup",
    "DescribeTargetGroups",
    "ModifyTargetGroup",
    "DeleteTargetGroup",
    "RegisterTargets",
    "DeregisterTargets",
    "DescribeTargetHealth",
    "ModifyTargetGroupAttributes",
    "DescribeTargetGroupAttributes",
];

pub struct Elbv2Service {
    state: SharedElbv2State,
    pub region: String,
}

impl Elbv2Service {
    pub fn new(state: SharedElbv2State) -> Self {
        Self {
            state,
            region: "us-east-1".to_string(),
        }
    }

    pub fn shared_state(&self) -> SharedElbv2State {
        Arc::clone(&self.state)
    }
}

#[async_trait]
impl AwsService for Elbv2Service {
    fn service_name(&self) -> &str {
        "elasticloadbalancing"
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        match req.action.as_str() {
            "CreateLoadBalancer" => self.create_load_balancer(&req),
            "DescribeLoadBalancers" => self.describe_load_balancers(&req),
            "DeleteLoadBalancer" => self.delete_load_balancer(&req),
            "SetSubnets" => self.set_subnets(&req),
            "SetSecurityGroups" => self.set_security_groups(&req),
            "SetIpAddressType" => self.set_ip_address_type(&req),
            "ModifyIpPools" => self.modify_ip_pools(&req),
            "AddTags" => self.add_tags(&req),
            "RemoveTags" => self.remove_tags(&req),
            "DescribeTags" => self.describe_tags(&req),
            "DescribeAccountLimits" => self.describe_account_limits(&req),
            "DescribeSSLPolicies" => self.describe_ssl_policies(&req),
            "CreateTargetGroup" => self.create_target_group(&req),
            "DescribeTargetGroups" => self.describe_target_groups(&req),
            "ModifyTargetGroup" => self.modify_target_group(&req),
            "DeleteTargetGroup" => self.delete_target_group(&req),
            "RegisterTargets" => self.register_targets(&req),
            "DeregisterTargets" => self.deregister_targets(&req),
            "DescribeTargetHealth" => self.describe_target_health(&req),
            "ModifyTargetGroupAttributes" => self.modify_target_group_attributes(&req),
            "DescribeTargetGroupAttributes" => self.describe_target_group_attributes(&req),
            _ => Err(AwsServiceError::action_not_implemented(
                "elasticloadbalancing",
                &req.action,
            )),
        }
    }

    fn supported_actions(&self) -> &[&str] {
        ELBV2_SUPPORTED_ACTIONS
    }

    fn iam_enforceable(&self) -> bool {
        false
    }
}

// ───────────────────────── helpers ─────────────────────────

fn xml_resp(action: &str, inner: String, request_id: &str) -> AwsResponse {
    let xml = query_response_xml(action, NS, &inner, request_id);
    AwsResponse::xml(StatusCode::OK, xml)
}

fn xml_metadata_only(action: &str, request_id: &str) -> AwsResponse {
    let xml = query_metadata_only_xml(action, NS, request_id);
    AwsResponse::xml(StatusCode::OK, xml)
}

fn xml_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '&' => out.push_str("&amp;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            _ => out.push(c),
        }
    }
    out
}

fn parse_member_list(req: &AwsRequest, prefix: &str) -> Vec<String> {
    let mut out = Vec::new();
    for n in 1..=100 {
        let key = format!("{prefix}.member.{n}");
        if let Some(v) = req.query_params.get(&key) {
            out.push(v.clone());
        } else {
            break;
        }
    }
    out
}

struct SubnetMapping {
    subnet_id: Option<String>,
    allocation_id: Option<String>,
    #[allow(dead_code)]
    private_ipv4_address: Option<String>,
    #[allow(dead_code)]
    ipv6_address: Option<String>,
    #[allow(dead_code)]
    source_nat_ipv6_prefix: Option<String>,
}

fn parse_subnet_mappings(req: &AwsRequest) -> Vec<SubnetMapping> {
    let mut out = Vec::new();
    for n in 1..=20 {
        let prefix = format!("SubnetMappings.member.{n}");
        let subnet_id = req.query_params.get(&format!("{prefix}.SubnetId")).cloned();
        let allocation_id = req
            .query_params
            .get(&format!("{prefix}.AllocationId"))
            .cloned();
        let private_ipv4 = req
            .query_params
            .get(&format!("{prefix}.PrivateIPv4Address"))
            .cloned();
        let ipv6 = req
            .query_params
            .get(&format!("{prefix}.IPv6Address"))
            .cloned();
        let source_nat_ipv6_prefix = req
            .query_params
            .get(&format!("{prefix}.SourceNatIpv6Prefix"))
            .cloned();
        if subnet_id.is_none()
            && allocation_id.is_none()
            && private_ipv4.is_none()
            && ipv6.is_none()
        {
            break;
        }
        out.push(SubnetMapping {
            subnet_id,
            allocation_id,
            private_ipv4_address: private_ipv4,
            ipv6_address: ipv6,
            source_nat_ipv6_prefix,
        });
    }
    out
}

fn parse_tags(req: &AwsRequest) -> Vec<Tag> {
    let mut out = Vec::new();
    for n in 1..=50 {
        let key = req
            .query_params
            .get(&format!("Tags.member.{n}.Key"))
            .cloned();
        if let Some(k) = key {
            let v = req
                .query_params
                .get(&format!("Tags.member.{n}.Value"))
                .cloned()
                .unwrap_or_default();
            out.push(Tag { key: k, value: v });
        } else {
            break;
        }
    }
    out
}

fn validate_ip_address_type(ipt: &str) -> Result<(), AwsServiceError> {
    if !matches!(ipt, "ipv4" | "dualstack" | "dualstack-without-public-ipv4") {
        return Err(invalid_param(format!(
            "IpAddressType must be one of ipv4|dualstack|dualstack-without-public-ipv4, got '{ipt}'"
        )));
    }
    Ok(())
}

fn validate_lb_name(name: &str) -> Result<(), AwsServiceError> {
    if name.is_empty() || name.len() > 32 {
        return Err(invalid_param(
            "LoadBalancer name must be between 1 and 32 characters",
        ));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(invalid_param(
            "LoadBalancer name must contain only ASCII letters, digits, and hyphens",
        ));
    }
    if name.starts_with('-') || name.ends_with('-') || name.starts_with("internal-") {
        return Err(invalid_param(
            "LoadBalancer name cannot start or end with hyphen, and cannot start with 'internal-'",
        ));
    }
    Ok(())
}

fn invalid_param(msg: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(StatusCode::BAD_REQUEST, "ValidationError", msg.into())
}

fn lb_not_found(arn: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "LoadBalancerNotFound",
        format!("Load balancer '{arn}' not found"),
    )
}

fn build_lb_arn(region: &str, account_id: &str, lb_type: &str, name: &str, suffix: &str) -> String {
    let prefix = match lb_type {
        "network" => "net",
        "gateway" => "gwy",
        _ => "app",
    };
    format!(
        "arn:aws:elasticloadbalancing:{region}:{account_id}:loadbalancer/{prefix}/{name}/{suffix}"
    )
}

fn build_dns_name(name: &str, _lb_type: &str, scheme: &str, region: &str, suffix: &str) -> String {
    let scheme_part = if scheme == "internal" {
        "internal-"
    } else {
        ""
    };
    format!("{scheme_part}{name}-{suffix}.{region}.elb.amazonaws.com")
}

fn render_lb_xml(lb: &LoadBalancer) -> String {
    let azs_xml = lb
        .availability_zones
        .iter()
        .map(render_az_xml)
        .collect::<String>();
    let sg_xml = lb
        .security_groups
        .iter()
        .map(|s| format!("<member>{}</member>", xml_escape(s)))
        .collect::<String>();
    let state_reason = lb
        .state_reason
        .as_deref()
        .map(|r| format!("<Reason>{}</Reason>", xml_escape(r)))
        .unwrap_or_default();
    let coip = lb
        .customer_owned_ipv4_pool
        .as_deref()
        .map(|s| {
            format!(
                "<CustomerOwnedIpv4Pool>{}</CustomerOwnedIpv4Pool>",
                xml_escape(s)
            )
        })
        .unwrap_or_default();
    let enforce = lb
        .enforce_security_group_inbound_rules_on_private_link_traffic
        .as_deref()
        .map(|s| {
            format!(
                "<EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic>{}</EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic>",
                xml_escape(s)
            )
        })
        .unwrap_or_default();
    let nat6 = lb
        .enable_prefix_for_ipv6_source_nat
        .as_deref()
        .map(|s| {
            format!(
                "<EnablePrefixForIpv6SourceNat>{}</EnablePrefixForIpv6SourceNat>",
                xml_escape(s)
            )
        })
        .unwrap_or_default();
    let ipam = lb
        .ipv4_ipam_pool_id
        .as_deref()
        .map(|s| {
            format!(
                "<IpamPools><Ipv4IpamPoolId>{}</Ipv4IpamPoolId></IpamPools>",
                xml_escape(s)
            )
        })
        .unwrap_or_default();
    let min_cap = lb
        .minimum_capacity_units
        .map(|v| {
            format!(
                "<MinimumLoadBalancerCapacity><CapacityUnits>{v}</CapacityUnits></MinimumLoadBalancerCapacity>"
            )
        })
        .unwrap_or_default();
    format!(
        "<LoadBalancerArn>{arn}</LoadBalancerArn>\
         <DNSName>{dns}</DNSName>\
         <CanonicalHostedZoneId>{zone}</CanonicalHostedZoneId>\
         <CreatedTime>{created}</CreatedTime>\
         <LoadBalancerName>{name}</LoadBalancerName>\
         <Scheme>{scheme}</Scheme>\
         <VpcId>{vpc}</VpcId>\
         <State><Code>{code}</Code>{state_reason}</State>\
         <Type>{ty}</Type>\
         <AvailabilityZones>{azs}</AvailabilityZones>\
         <SecurityGroups>{sgs}</SecurityGroups>\
         <IpAddressType>{ipt}</IpAddressType>{coip}{enforce}{nat6}{ipam}{min_cap}",
        arn = xml_escape(&lb.arn),
        dns = xml_escape(&lb.dns_name),
        zone = xml_escape(&lb.canonical_hosted_zone_id),
        created = lb
            .created_time
            .to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
        name = xml_escape(&lb.name),
        scheme = xml_escape(&lb.scheme),
        vpc = xml_escape(&lb.vpc_id),
        code = xml_escape(&lb.state_code),
        ty = xml_escape(&lb.lb_type),
        azs = azs_xml,
        sgs = sg_xml,
        ipt = xml_escape(&lb.ip_address_type),
    )
}

fn render_az_xml(az: &AvailabilityZone) -> String {
    let addresses = az
        .load_balancer_addresses
        .iter()
        .map(render_address_xml)
        .collect::<String>();
    let prefixes = az
        .source_nat_ipv6_prefixes
        .iter()
        .map(|p| format!("<member>{}</member>", xml_escape(p)))
        .collect::<String>();
    let outpost = az
        .outpost_id
        .as_deref()
        .map(|o| format!("<OutpostId>{}</OutpostId>", xml_escape(o)))
        .unwrap_or_default();
    format!(
        "<member><ZoneName>{zone}</ZoneName><SubnetId>{subnet}</SubnetId>{outpost}<LoadBalancerAddresses>{addrs}</LoadBalancerAddresses><SourceNatIpv6Prefixes>{prefixes}</SourceNatIpv6Prefixes></member>",
        zone = xml_escape(&az.zone_name),
        subnet = xml_escape(&az.subnet_id),
        addrs = addresses,
    )
}

fn render_address_xml(addr: &LoadBalancerAddress) -> String {
    let mut s = String::from("<member>");
    if let Some(ip) = &addr.ip_address {
        s.push_str(&format!("<IpAddress>{}</IpAddress>", xml_escape(ip)));
    }
    if let Some(a) = &addr.allocation_id {
        s.push_str(&format!("<AllocationId>{}</AllocationId>", xml_escape(a)));
    }
    if let Some(p) = &addr.private_ipv4_address {
        s.push_str(&format!(
            "<PrivateIPv4Address>{}</PrivateIPv4Address>",
            xml_escape(p)
        ));
    }
    if let Some(p) = &addr.ipv6_address {
        s.push_str(&format!("<IPv6Address>{}</IPv6Address>", xml_escape(p)));
    }
    if let Some(p) = &addr.ipv4_prefix {
        s.push_str(&format!("<IPv4Prefix>{}</IPv4Prefix>", xml_escape(p)));
    }
    if let Some(p) = &addr.ipv6_prefix {
        s.push_str(&format!("<IPv6Prefix>{}</IPv6Prefix>", xml_escape(p)));
    }
    s.push_str("</member>");
    s
}

fn az_for_subnet(region: &str, subnet_id: &str) -> String {
    let suffix = match subnet_id
        .chars()
        .fold(0u32, |a, c| a.wrapping_add(c as u32))
        % 6
    {
        0 => 'a',
        1 => 'b',
        2 => 'c',
        3 => 'd',
        4 => 'e',
        _ => 'f',
    };
    format!("{region}{suffix}")
}

fn alphanumeric_id(len: usize) -> String {
    let raw = uuid::Uuid::new_v4().simple().to_string();
    raw.chars().take(len).collect()
}

// ───────────────────────── operations ─────────────────────────

impl Elbv2Service {
    fn create_load_balancer(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let name = required_query_param(req, "Name")?;
        validate_lb_name(&name)?;
        let lb_type = optional_query_param(req, "Type").unwrap_or_else(|| "application".into());
        if !matches!(lb_type.as_str(), "application" | "network" | "gateway") {
            return Err(invalid_param(format!(
                "Type must be one of application|network|gateway, got '{lb_type}'"
            )));
        }
        let scheme =
            optional_query_param(req, "Scheme").unwrap_or_else(|| "internet-facing".to_string());
        if !matches!(scheme.as_str(), "internet-facing" | "internal") {
            return Err(invalid_param(format!(
                "Scheme must be 'internet-facing' or 'internal', got '{scheme}'"
            )));
        }
        let ip_address_type =
            optional_query_param(req, "IpAddressType").unwrap_or_else(|| "ipv4".to_string());
        validate_ip_address_type(&ip_address_type)?;

        let subnets_explicit = parse_member_list(req, "Subnets");
        let subnet_mappings = parse_subnet_mappings(req);
        let subnets: Vec<(String, Option<String>)> = if !subnets_explicit.is_empty() {
            subnets_explicit
                .into_iter()
                .map(|s| (s, None::<String>))
                .collect()
        } else {
            subnet_mappings
                .iter()
                .filter_map(|m| m.subnet_id.clone().map(|s| (s, m.allocation_id.clone())))
                .collect()
        };

        let security_groups = parse_member_list(req, "SecurityGroups");
        let mut tags = parse_tags(req);

        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);

        if let Some(existing) = st.load_balancers.values().find(|lb| lb.name == name) {
            let lb_xml = render_lb_xml(existing);
            return Ok(xml_resp(
                "CreateLoadBalancer",
                format!("<LoadBalancers><member>{lb_xml}</member></LoadBalancers>"),
                &req.request_id,
            ));
        }

        let suffix = alphanumeric_id(16);
        let arn = build_lb_arn(&req.region, &req.account_id, &lb_type, &name, &suffix);
        let dns_name = build_dns_name(&name, &lb_type, &scheme, &req.region, &suffix);
        let canonical_hosted_zone_id = "Z2P70J7EXAMPLE".to_string();
        let availability_zones: Vec<AvailabilityZone> = subnets
            .iter()
            .map(|(subnet_id, allocation_id)| AvailabilityZone {
                zone_name: az_for_subnet(&req.region, subnet_id),
                subnet_id: subnet_id.clone(),
                outpost_id: None,
                load_balancer_addresses: allocation_id
                    .as_ref()
                    .map(|a| {
                        vec![LoadBalancerAddress {
                            ip_address: None,
                            allocation_id: Some(a.clone()),
                            private_ipv4_address: None,
                            ipv6_address: None,
                            ipv4_prefix: None,
                            ipv6_prefix: None,
                        }]
                    })
                    .unwrap_or_default(),
                source_nat_ipv6_prefixes: Vec::new(),
            })
            .collect();

        tags.dedup_by(|a, b| a.key == b.key);

        let vpc_id = optional_query_param(req, "VpcId")
            .unwrap_or_else(|| format!("vpc-{}", alphanumeric_id(8)));

        let lb = LoadBalancer {
            arn: arn.clone(),
            name,
            dns_name,
            canonical_hosted_zone_id,
            created_time: Utc::now(),
            scheme,
            vpc_id,
            state_code: "active".to_string(),
            state_reason: None,
            lb_type,
            availability_zones,
            security_groups,
            ip_address_type,
            customer_owned_ipv4_pool: optional_query_param(req, "CustomerOwnedIpv4Pool"),
            enforce_security_group_inbound_rules_on_private_link_traffic: optional_query_param(
                req,
                "EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic",
            ),
            enable_prefix_for_ipv6_source_nat: optional_query_param(
                req,
                "EnablePrefixForIpv6SourceNat",
            ),
            ipv4_ipam_pool_id: optional_query_param(req, "IpamPools.Ipv4IpamPoolId"),
            tags,
            attributes: HashMap::new(),
            minimum_capacity_units: optional_query_param(
                req,
                "MinimumLoadBalancerCapacity.CapacityUnits",
            )
            .and_then(|s| s.parse().ok()),
        };
        let lb_xml = render_lb_xml(&lb);
        st.load_balancers.insert(arn, lb);

        Ok(xml_resp(
            "CreateLoadBalancer",
            format!("<LoadBalancers><member>{lb_xml}</member></LoadBalancers>"),
            &req.request_id,
        ))
    }

    fn describe_load_balancers(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arns: HashSet<String> = parse_member_list(req, "LoadBalancerArns")
            .into_iter()
            .collect();
        let names: HashSet<String> = parse_member_list(req, "Names").into_iter().collect();
        let accounts = self.state.read();
        let empty = crate::state::Elbv2State::new(&req.account_id);
        let st = accounts.get(&req.account_id).unwrap_or(&empty);
        let mut lbs: Vec<&LoadBalancer> = st.load_balancers.values().collect();
        if !arns.is_empty() {
            let kept: Vec<&LoadBalancer> = lbs
                .iter()
                .filter(|lb| arns.contains(&lb.arn))
                .copied()
                .collect();
            if kept.len() != arns.len() {
                let missing = arns
                    .iter()
                    .find(|a| !kept.iter().any(|lb| lb.arn == **a))
                    .cloned()
                    .unwrap_or_default();
                return Err(lb_not_found(&missing));
            }
            lbs = kept;
        }
        if !names.is_empty() {
            let kept: Vec<&LoadBalancer> = lbs
                .iter()
                .filter(|lb| names.contains(&lb.name))
                .copied()
                .collect();
            if kept.len() != names.len() {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "LoadBalancerNotFound",
                    "One or more named load balancers not found",
                ));
            }
            lbs = kept;
        }
        lbs.sort_by_key(|a| a.created_time);
        let inner = format!(
            "<LoadBalancers>{}</LoadBalancers>",
            lbs.iter()
                .map(|lb| format!("<member>{}</member>", render_lb_xml(lb)))
                .collect::<String>()
        );
        Ok(xml_resp("DescribeLoadBalancers", inner, &req.request_id))
    }

    fn delete_load_balancer(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "LoadBalancerArn")?;
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        st.load_balancers.remove(&arn);
        let listener_arns: Vec<String> = st
            .listeners
            .iter()
            .filter(|(_, l)| l.load_balancer_arn == arn)
            .map(|(k, _)| k.clone())
            .collect();
        for la in &listener_arns {
            st.listeners.remove(la);
            st.rules.retain(|_, r| r.listener_arn != *la);
        }
        for tg in st.target_groups.values_mut() {
            tg.load_balancer_arns.retain(|a| a != &arn);
        }
        Ok(xml_metadata_only("DeleteLoadBalancer", &req.request_id))
    }

    fn set_subnets(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "LoadBalancerArn")?;
        let subnets_explicit = parse_member_list(req, "Subnets");
        let mappings = parse_subnet_mappings(req);
        let new_ip_address_type = optional_query_param(req, "IpAddressType");
        if let Some(ref ipt) = new_ip_address_type {
            validate_ip_address_type(ipt)?;
        }
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let lb = st
            .load_balancers
            .get_mut(&arn)
            .ok_or_else(|| lb_not_found(&arn))?;
        let pairs: Vec<(String, Option<String>)> = if !subnets_explicit.is_empty() {
            subnets_explicit.into_iter().map(|s| (s, None)).collect()
        } else {
            mappings
                .iter()
                .filter_map(|m| m.subnet_id.clone().map(|s| (s, m.allocation_id.clone())))
                .collect()
        };
        lb.availability_zones = pairs
            .iter()
            .map(|(subnet_id, allocation_id)| AvailabilityZone {
                zone_name: az_for_subnet(&req.region, subnet_id),
                subnet_id: subnet_id.clone(),
                outpost_id: None,
                load_balancer_addresses: allocation_id
                    .as_ref()
                    .map(|a| {
                        vec![LoadBalancerAddress {
                            ip_address: None,
                            allocation_id: Some(a.clone()),
                            private_ipv4_address: None,
                            ipv6_address: None,
                            ipv4_prefix: None,
                            ipv6_prefix: None,
                        }]
                    })
                    .unwrap_or_default(),
                source_nat_ipv6_prefixes: Vec::new(),
            })
            .collect();
        if let Some(ipt) = new_ip_address_type {
            lb.ip_address_type = ipt;
        }
        let azs_xml = lb
            .availability_zones
            .iter()
            .map(render_az_xml)
            .collect::<String>();
        let ip_type = xml_escape(&lb.ip_address_type);
        Ok(xml_resp(
            "SetSubnets",
            format!(
                "<AvailabilityZones>{azs_xml}</AvailabilityZones><IpAddressType>{ip_type}</IpAddressType>"
            ),
            &req.request_id,
        ))
    }

    fn set_security_groups(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "LoadBalancerArn")?;
        let sgs = parse_member_list(req, "SecurityGroups");
        let enforce =
            optional_query_param(req, "EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic");
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let lb = st
            .load_balancers
            .get_mut(&arn)
            .ok_or_else(|| lb_not_found(&arn))?;
        lb.security_groups = sgs.clone();
        if enforce.is_some() {
            lb.enforce_security_group_inbound_rules_on_private_link_traffic = enforce.clone();
        }
        let sg_xml = sgs
            .iter()
            .map(|s| format!("<member>{}</member>", xml_escape(s)))
            .collect::<String>();
        let enforce_xml = lb
            .enforce_security_group_inbound_rules_on_private_link_traffic
            .as_deref()
            .map(|e| {
                format!(
                    "<EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic>{}</EnforceSecurityGroupInboundRulesOnPrivateLinkTraffic>",
                    xml_escape(e)
                )
            })
            .unwrap_or_default();
        Ok(xml_resp(
            "SetSecurityGroups",
            format!("<SecurityGroupIds>{sg_xml}</SecurityGroupIds>{enforce_xml}"),
            &req.request_id,
        ))
    }

    fn set_ip_address_type(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "LoadBalancerArn")?;
        let ipt = required_query_param(req, "IpAddressType")?;
        validate_ip_address_type(&ipt)?;
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let lb = st
            .load_balancers
            .get_mut(&arn)
            .ok_or_else(|| lb_not_found(&arn))?;
        lb.ip_address_type = ipt.clone();
        Ok(xml_resp(
            "SetIpAddressType",
            format!("<IpAddressType>{}</IpAddressType>", xml_escape(&ipt)),
            &req.request_id,
        ))
    }

    fn modify_ip_pools(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "LoadBalancerArn")?;
        let pool = optional_query_param(req, "IpamPools.Ipv4IpamPoolId");
        let remove = optional_query_param(req, "RemoveIpamPools.member.1");
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let lb = st
            .load_balancers
            .get_mut(&arn)
            .ok_or_else(|| lb_not_found(&arn))?;
        if remove.is_some() {
            lb.ipv4_ipam_pool_id = None;
        }
        if let Some(p) = pool {
            lb.ipv4_ipam_pool_id = Some(p);
        }
        let ipam_xml = lb
            .ipv4_ipam_pool_id
            .as_deref()
            .map(|p| {
                format!(
                    "<IpamPools><Ipv4IpamPoolId>{}</Ipv4IpamPoolId></IpamPools>",
                    xml_escape(p)
                )
            })
            .unwrap_or_default();
        Ok(xml_resp("ModifyIpPools", ipam_xml, &req.request_id))
    }

    fn add_tags(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arns = parse_member_list(req, "ResourceArns");
        if arns.is_empty() {
            return Err(invalid_param("ResourceArns is required"));
        }
        let new_tags = parse_tags(req);
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        for arn in &arns {
            apply_tags(st, arn, &new_tags)?;
        }
        Ok(xml_metadata_only("AddTags", &req.request_id))
    }

    fn remove_tags(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arns = parse_member_list(req, "ResourceArns");
        if arns.is_empty() {
            return Err(invalid_param("ResourceArns is required"));
        }
        let keys = parse_member_list(req, "TagKeys");
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        for arn in &arns {
            remove_tag_keys(st, arn, &keys)?;
        }
        Ok(xml_metadata_only("RemoveTags", &req.request_id))
    }

    fn describe_tags(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arns = parse_member_list(req, "ResourceArns");
        if arns.is_empty() {
            return Err(invalid_param("ResourceArns is required"));
        }
        let accounts = self.state.read();
        let empty = crate::state::Elbv2State::new(&req.account_id);
        let st = accounts.get(&req.account_id).unwrap_or(&empty);
        let mut blocks = String::new();
        for arn in &arns {
            let tags = lookup_tags(st, arn);
            let tags_xml = tags
                .iter()
                .map(|t| {
                    format!(
                        "<member><Key>{}</Key><Value>{}</Value></member>",
                        xml_escape(&t.key),
                        xml_escape(&t.value)
                    )
                })
                .collect::<String>();
            blocks.push_str(&format!(
                "<member><ResourceArn>{}</ResourceArn><Tags>{tags_xml}</Tags></member>",
                xml_escape(arn)
            ));
        }
        Ok(xml_resp(
            "DescribeTags",
            format!("<TagDescriptions>{blocks}</TagDescriptions>"),
            &req.request_id,
        ))
    }

    fn describe_account_limits(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let limits = [
            ("application-load-balancers", "50"),
            ("network-load-balancers", "50"),
            ("gateway-load-balancers", "100"),
            ("target-groups", "3000"),
            ("targets-per-application-load-balancer", "1000"),
            ("targets-per-network-load-balancer", "500"),
            (
                "targets-per-availability-zone-per-network-load-balancer",
                "500",
            ),
            ("targets-per-target-group", "1000"),
            ("listeners-per-application-load-balancer", "50"),
            ("listeners-per-network-load-balancer", "50"),
            ("listeners-per-gateway-load-balancer", "50"),
            ("rules-per-application-load-balancer", "100"),
            ("certificates-per-application-load-balancer", "25"),
            ("certificates-per-network-load-balancer", "25"),
            ("trust-stores", "100"),
            ("trust-store-ca-certificate-bundle-size", "1000"),
            ("revocation-entries-per-trust-store", "65535"),
            ("network-load-balancer-capacity-reservations", "1500"),
        ];
        let xml = limits
            .iter()
            .map(|(n, m)| format!("<member><Name>{n}</Name><Max>{m}</Max></member>"))
            .collect::<String>();
        Ok(xml_resp(
            "DescribeAccountLimits",
            format!("<Limits>{xml}</Limits>"),
            &req.request_id,
        ))
    }

    fn describe_ssl_policies(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let policies: &[(&str, &[&str], &[&str])] = &[
            (
                "ELBSecurityPolicy-TLS13-1-2-2021-06",
                &["TLSv1.2", "TLSv1.3"],
                &[
                    "TLS_AES_128_GCM_SHA256",
                    "TLS_AES_256_GCM_SHA384",
                    "TLS_CHACHA20_POLY1305_SHA256",
                ],
            ),
            (
                "ELBSecurityPolicy-TLS13-1-2-Res-2021-06",
                &["TLSv1.2", "TLSv1.3"],
                &["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384"],
            ),
            (
                "ELBSecurityPolicy-2016-08",
                &["TLSv1", "TLSv1.1", "TLSv1.2"],
                &["ECDHE-RSA-AES128-SHA256", "ECDHE-RSA-AES256-SHA384"],
            ),
            (
                "ELBSecurityPolicy-FS-1-2-Res-2020-10",
                &["TLSv1.2"],
                &["ECDHE-RSA-AES128-GCM-SHA256", "ECDHE-RSA-AES256-GCM-SHA384"],
            ),
            (
                "ELBSecurityPolicy-2015-05",
                &["TLSv1", "TLSv1.1", "TLSv1.2"],
                &["ECDHE-RSA-AES128-SHA", "AES128-SHA"],
            ),
        ];
        let names: HashSet<String> = parse_member_list(req, "Names").into_iter().collect();
        let xml = policies
            .iter()
            .filter(|(name, _, _)| names.is_empty() || names.contains(*name))
            .map(|(name, protocols, ciphers)| {
                let proto_xml = protocols
                    .iter()
                    .map(|p| format!("<member>{p}</member>"))
                    .collect::<String>();
                let cipher_xml = ciphers
                    .iter()
                    .enumerate()
                    .map(|(i, c)| {
                        format!("<member><Name>{c}</Name><Priority>{i}</Priority></member>")
                    })
                    .collect::<String>();
                format!(
                    "<member><Name>{name}</Name><SslProtocols>{proto_xml}</SslProtocols><Ciphers>{cipher_xml}</Ciphers></member>"
                )
            })
            .collect::<String>();
        Ok(xml_resp(
            "DescribeSSLPolicies",
            format!("<SslPolicies>{xml}</SslPolicies>"),
            &req.request_id,
        ))
    }

    // ───────────── Target Group ops ─────────────

    fn create_target_group(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let name = required_query_param(req, "Name")?;
        validate_tg_name(&name)?;
        let target_type =
            optional_query_param(req, "TargetType").unwrap_or_else(|| "instance".into());
        if !matches!(target_type.as_str(), "instance" | "ip" | "lambda" | "alb") {
            return Err(invalid_param(format!(
                "TargetType must be one of instance|ip|lambda|alb, got '{target_type}'"
            )));
        }
        let protocol = optional_query_param(req, "Protocol");
        let port = optional_query_param(req, "Port").and_then(|s| s.parse().ok());
        let vpc_id = optional_query_param(req, "VpcId");
        let ip_address_type =
            optional_query_param(req, "IpAddressType").unwrap_or_else(|| "ipv4".into());
        let protocol_version = optional_query_param(req, "ProtocolVersion");
        let health_check_protocol =
            optional_query_param(req, "HealthCheckProtocol").or_else(|| protocol.clone());
        let health_check_port =
            optional_query_param(req, "HealthCheckPort").or_else(|| Some("traffic-port".into()));
        let health_check_path = optional_query_param(req, "HealthCheckPath");
        let health_check_enabled = optional_query_param(req, "HealthCheckEnabled")
            .map(|s| s != "false")
            .unwrap_or(true);
        let health_check_interval_seconds = optional_query_param(req, "HealthCheckIntervalSeconds")
            .and_then(|s| s.parse().ok())
            .unwrap_or(30);
        let health_check_timeout_seconds = optional_query_param(req, "HealthCheckTimeoutSeconds")
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);
        let healthy_threshold_count = optional_query_param(req, "HealthyThresholdCount")
            .and_then(|s| s.parse().ok())
            .unwrap_or(5);
        let unhealthy_threshold_count = optional_query_param(req, "UnhealthyThresholdCount")
            .and_then(|s| s.parse().ok())
            .unwrap_or(2);
        let matcher_http_code = optional_query_param(req, "Matcher.HttpCode");
        let matcher_grpc_code = optional_query_param(req, "Matcher.GrpcCode");
        let mut tags = parse_tags(req);
        tags.dedup_by(|a, b| a.key == b.key);

        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);

        if let Some(existing) = st.target_groups.values().find(|tg| tg.name == name) {
            let inner = format!(
                "<TargetGroups><member>{}</member></TargetGroups>",
                render_target_group_xml(existing)
            );
            return Ok(xml_resp("CreateTargetGroup", inner, &req.request_id));
        }

        let suffix = alphanumeric_id(16);
        let arn = format!(
            "arn:aws:elasticloadbalancing:{}:{}:targetgroup/{}/{}",
            req.region, req.account_id, name, suffix
        );
        let tg = crate::state::TargetGroup {
            arn: arn.clone(),
            name,
            protocol,
            port,
            vpc_id,
            target_type,
            ip_address_type,
            protocol_version,
            health_check_protocol,
            health_check_port,
            health_check_enabled,
            health_check_path,
            health_check_interval_seconds,
            health_check_timeout_seconds,
            healthy_threshold_count,
            unhealthy_threshold_count,
            matcher_http_code,
            matcher_grpc_code,
            load_balancer_arns: Vec::new(),
            targets: Vec::new(),
            tags,
            attributes: default_target_group_attributes(),
            created_time: Utc::now(),
        };
        let tg_xml = render_target_group_xml(&tg);
        st.target_groups.insert(arn, tg);
        Ok(xml_resp(
            "CreateTargetGroup",
            format!("<TargetGroups><member>{tg_xml}</member></TargetGroups>"),
            &req.request_id,
        ))
    }

    fn describe_target_groups(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arns: HashSet<String> = parse_member_list(req, "TargetGroupArns")
            .into_iter()
            .collect();
        let names: HashSet<String> = parse_member_list(req, "Names").into_iter().collect();
        let lb_arn = optional_query_param(req, "LoadBalancerArn");
        let accounts = self.state.read();
        let empty = crate::state::Elbv2State::new(&req.account_id);
        let st = accounts.get(&req.account_id).unwrap_or(&empty);
        let mut tgs: Vec<&crate::state::TargetGroup> = st.target_groups.values().collect();
        if !arns.is_empty() {
            let kept: Vec<&crate::state::TargetGroup> = tgs
                .iter()
                .filter(|t| arns.contains(&t.arn))
                .copied()
                .collect();
            if kept.len() != arns.len() {
                let missing = arns
                    .iter()
                    .find(|a| !kept.iter().any(|t| t.arn == **a))
                    .cloned()
                    .unwrap_or_default();
                return Err(target_group_not_found(&missing));
            }
            tgs = kept;
        }
        if !names.is_empty() {
            let kept: Vec<&crate::state::TargetGroup> = tgs
                .iter()
                .filter(|t| names.contains(&t.name))
                .copied()
                .collect();
            if kept.len() != names.len() {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "TargetGroupNotFound",
                    "One or more named target groups not found",
                ));
            }
            tgs = kept;
        }
        if let Some(lb) = lb_arn.as_deref() {
            tgs.retain(|t| t.load_balancer_arns.iter().any(|a| a == lb));
        }
        tgs.sort_by_key(|a| a.created_time);
        let inner = format!(
            "<TargetGroups>{}</TargetGroups>",
            tgs.iter()
                .map(|tg| format!("<member>{}</member>", render_target_group_xml(tg)))
                .collect::<String>()
        );
        Ok(xml_resp("DescribeTargetGroups", inner, &req.request_id))
    }

    fn modify_target_group(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "TargetGroupArn")?;
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let tg = st
            .target_groups
            .get_mut(&arn)
            .ok_or_else(|| target_group_not_found(&arn))?;
        if let Some(p) = optional_query_param(req, "HealthCheckProtocol") {
            tg.health_check_protocol = Some(p);
        }
        if let Some(p) = optional_query_param(req, "HealthCheckPort") {
            tg.health_check_port = Some(p);
        }
        if let Some(p) = optional_query_param(req, "HealthCheckPath") {
            tg.health_check_path = Some(p);
        }
        if let Some(e) = optional_query_param(req, "HealthCheckEnabled") {
            tg.health_check_enabled = e != "false";
        }
        if let Some(s) =
            optional_query_param(req, "HealthCheckIntervalSeconds").and_then(|s| s.parse().ok())
        {
            tg.health_check_interval_seconds = s;
        }
        if let Some(s) =
            optional_query_param(req, "HealthCheckTimeoutSeconds").and_then(|s| s.parse().ok())
        {
            tg.health_check_timeout_seconds = s;
        }
        if let Some(s) =
            optional_query_param(req, "HealthyThresholdCount").and_then(|s| s.parse().ok())
        {
            tg.healthy_threshold_count = s;
        }
        if let Some(s) =
            optional_query_param(req, "UnhealthyThresholdCount").and_then(|s| s.parse().ok())
        {
            tg.unhealthy_threshold_count = s;
        }
        if let Some(c) = optional_query_param(req, "Matcher.HttpCode") {
            tg.matcher_http_code = Some(c);
        }
        if let Some(c) = optional_query_param(req, "Matcher.GrpcCode") {
            tg.matcher_grpc_code = Some(c);
        }
        let xml = render_target_group_xml(tg);
        Ok(xml_resp(
            "ModifyTargetGroup",
            format!("<TargetGroups><member>{xml}</member></TargetGroups>"),
            &req.request_id,
        ))
    }

    fn delete_target_group(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "TargetGroupArn")?;
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        // Reject if the TG is still referenced by listeners/rules.
        let referenced = st.listeners.values().any(|l| {
            l.default_actions
                .iter()
                .any(|a| a.target_group_arn.as_deref() == Some(arn.as_str()))
                || l.default_actions.iter().any(|a| {
                    a.forward
                        .as_ref()
                        .map(|f| f.target_groups.iter().any(|t| t.target_group_arn == arn))
                        .unwrap_or(false)
                })
        }) || st.rules.values().any(|r| {
            r.actions
                .iter()
                .any(|a| a.target_group_arn.as_deref() == Some(arn.as_str()))
        });
        if referenced {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceInUse",
                "Target group is currently in use by a listener or a rule",
            ));
        }
        st.target_groups.remove(&arn);
        Ok(xml_metadata_only("DeleteTargetGroup", &req.request_id))
    }

    fn register_targets(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "TargetGroupArn")?;
        let targets = parse_target_descriptions(req);
        if targets.is_empty() {
            return Err(invalid_param("Targets is required"));
        }
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let tg = st
            .target_groups
            .get_mut(&arn)
            .ok_or_else(|| target_group_not_found(&arn))?;
        for t in targets {
            // Replace existing entry with same id+port, otherwise append.
            tg.targets.retain(|x| !(x.id == t.id && x.port == t.port));
            tg.targets.push(t);
        }
        Ok(xml_metadata_only("RegisterTargets", &req.request_id))
    }

    fn deregister_targets(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "TargetGroupArn")?;
        let targets = parse_target_descriptions(req);
        if targets.is_empty() {
            return Err(invalid_param("Targets is required"));
        }
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let tg = st
            .target_groups
            .get_mut(&arn)
            .ok_or_else(|| target_group_not_found(&arn))?;
        for t in targets {
            tg.targets
                .retain(|x| !(x.id == t.id && (t.port.is_none() || x.port == t.port)));
        }
        Ok(xml_metadata_only("DeregisterTargets", &req.request_id))
    }

    fn describe_target_health(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "TargetGroupArn")?;
        let filter = parse_target_descriptions(req);
        let accounts = self.state.read();
        let empty = crate::state::Elbv2State::new(&req.account_id);
        let st = accounts.get(&req.account_id).unwrap_or(&empty);
        let tg = st
            .target_groups
            .get(&arn)
            .ok_or_else(|| target_group_not_found(&arn))?;
        let entries: Vec<&crate::state::TargetDescription> = if filter.is_empty() {
            tg.targets.iter().collect()
        } else {
            tg.targets
                .iter()
                .filter(|t| {
                    filter
                        .iter()
                        .any(|f| f.id == t.id && (f.port.is_none() || f.port == t.port))
                })
                .collect()
        };
        let xml = entries
            .iter()
            .map(|t| {
                let port_xml = t
                    .port
                    .map(|p| format!("<Port>{p}</Port>"))
                    .unwrap_or_default();
                let az_xml = t
                    .availability_zone
                    .as_deref()
                    .map(|a| format!("<AvailabilityZone>{}</AvailabilityZone>", xml_escape(a)))
                    .unwrap_or_default();
                let reason = t
                    .health
                    .reason
                    .as_deref()
                    .map(|r| format!("<Reason>{}</Reason>", xml_escape(r)))
                    .unwrap_or_default();
                let desc = t
                    .health
                    .description
                    .as_deref()
                    .map(|d| format!("<Description>{}</Description>", xml_escape(d)))
                    .unwrap_or_default();
                format!(
                    "<member><Target><Id>{}</Id>{port_xml}{az_xml}</Target><TargetHealth><State>{}</State>{reason}{desc}</TargetHealth></member>",
                    xml_escape(&t.id),
                    xml_escape(&t.health.state),
                )
            })
            .collect::<String>();
        Ok(xml_resp(
            "DescribeTargetHealth",
            format!("<TargetHealthDescriptions>{xml}</TargetHealthDescriptions>"),
            &req.request_id,
        ))
    }

    fn modify_target_group_attributes(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "TargetGroupArn")?;
        let new_attrs = parse_attributes(req);
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let tg = st
            .target_groups
            .get_mut(&arn)
            .ok_or_else(|| target_group_not_found(&arn))?;
        for (k, v) in &new_attrs {
            tg.attributes.insert(k.clone(), v.clone());
        }
        Ok(xml_resp(
            "ModifyTargetGroupAttributes",
            render_attributes_xml(&tg.attributes),
            &req.request_id,
        ))
    }

    fn describe_target_group_attributes(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "TargetGroupArn")?;
        let accounts = self.state.read();
        let empty = crate::state::Elbv2State::new(&req.account_id);
        let st = accounts.get(&req.account_id).unwrap_or(&empty);
        let tg = st
            .target_groups
            .get(&arn)
            .ok_or_else(|| target_group_not_found(&arn))?;
        Ok(xml_resp(
            "DescribeTargetGroupAttributes",
            render_attributes_xml(&tg.attributes),
            &req.request_id,
        ))
    }
}

fn validate_tg_name(name: &str) -> Result<(), AwsServiceError> {
    if name.is_empty() || name.len() > 32 {
        return Err(invalid_param(
            "TargetGroup name must be between 1 and 32 characters",
        ));
    }
    if !name.chars().all(|c| c.is_ascii_alphanumeric() || c == '-') {
        return Err(invalid_param(
            "TargetGroup name must contain only ASCII letters, digits, and hyphens",
        ));
    }
    if name.starts_with('-') || name.ends_with('-') {
        return Err(invalid_param(
            "TargetGroup name cannot start or end with a hyphen",
        ));
    }
    Ok(())
}

fn target_group_not_found(arn: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "TargetGroupNotFound",
        format!("Target group '{arn}' not found"),
    )
}

fn render_target_group_xml(tg: &crate::state::TargetGroup) -> String {
    let lb_xml = tg
        .load_balancer_arns
        .iter()
        .map(|a| format!("<member>{}</member>", xml_escape(a)))
        .collect::<String>();
    let port = tg
        .port
        .map(|p| format!("<Port>{p}</Port>"))
        .unwrap_or_default();
    let proto = tg
        .protocol
        .as_deref()
        .map(|p| format!("<Protocol>{}</Protocol>", xml_escape(p)))
        .unwrap_or_default();
    let vpc = tg
        .vpc_id
        .as_deref()
        .map(|v| format!("<VpcId>{}</VpcId>", xml_escape(v)))
        .unwrap_or_default();
    let proto_ver = tg
        .protocol_version
        .as_deref()
        .map(|p| format!("<ProtocolVersion>{}</ProtocolVersion>", xml_escape(p)))
        .unwrap_or_default();
    let hc_proto = tg
        .health_check_protocol
        .as_deref()
        .map(|p| {
            format!(
                "<HealthCheckProtocol>{}</HealthCheckProtocol>",
                xml_escape(p)
            )
        })
        .unwrap_or_default();
    let hc_port = tg
        .health_check_port
        .as_deref()
        .map(|p| format!("<HealthCheckPort>{}</HealthCheckPort>", xml_escape(p)))
        .unwrap_or_default();
    let hc_path = tg
        .health_check_path
        .as_deref()
        .map(|p| format!("<HealthCheckPath>{}</HealthCheckPath>", xml_escape(p)))
        .unwrap_or_default();
    let matcher = tg
        .matcher_http_code
        .as_deref()
        .map(|m| format!("<Matcher><HttpCode>{}</HttpCode></Matcher>", xml_escape(m)))
        .unwrap_or_default();
    format!(
        "<TargetGroupArn>{arn}</TargetGroupArn>\
         <TargetGroupName>{name}</TargetGroupName>\
         {proto}{port}{vpc}{proto_ver}\
         <TargetType>{tt}</TargetType>\
         <IpAddressType>{ipt}</IpAddressType>\
         <HealthCheckEnabled>{hce}</HealthCheckEnabled>\
         {hc_proto}{hc_port}{hc_path}\
         <HealthCheckIntervalSeconds>{hci}</HealthCheckIntervalSeconds>\
         <HealthCheckTimeoutSeconds>{hct}</HealthCheckTimeoutSeconds>\
         <HealthyThresholdCount>{ht}</HealthyThresholdCount>\
         <UnhealthyThresholdCount>{uht}</UnhealthyThresholdCount>\
         {matcher}\
         <LoadBalancerArns>{lb_xml}</LoadBalancerArns>",
        arn = xml_escape(&tg.arn),
        name = xml_escape(&tg.name),
        tt = xml_escape(&tg.target_type),
        ipt = xml_escape(&tg.ip_address_type),
        hce = tg.health_check_enabled,
        hci = tg.health_check_interval_seconds,
        hct = tg.health_check_timeout_seconds,
        ht = tg.healthy_threshold_count,
        uht = tg.unhealthy_threshold_count,
    )
}

fn parse_target_descriptions(req: &AwsRequest) -> Vec<crate::state::TargetDescription> {
    let mut out = Vec::new();
    for n in 1..=100 {
        let id = req
            .query_params
            .get(&format!("Targets.member.{n}.Id"))
            .cloned();
        if let Some(id) = id {
            let port = req
                .query_params
                .get(&format!("Targets.member.{n}.Port"))
                .and_then(|s| s.parse().ok());
            let az = req
                .query_params
                .get(&format!("Targets.member.{n}.AvailabilityZone"))
                .cloned();
            out.push(crate::state::TargetDescription {
                id,
                port,
                availability_zone: az,
                health: crate::state::TargetHealth::default(),
            });
        } else {
            break;
        }
    }
    out
}

fn parse_attributes(req: &AwsRequest) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for n in 1..=50 {
        let key = req
            .query_params
            .get(&format!("Attributes.member.{n}.Key"))
            .cloned();
        if let Some(k) = key {
            let v = req
                .query_params
                .get(&format!("Attributes.member.{n}.Value"))
                .cloned()
                .unwrap_or_default();
            out.push((k, v));
        } else {
            break;
        }
    }
    out
}

fn render_attributes_xml(attrs: &HashMap<String, String>) -> String {
    let entries = attrs
        .iter()
        .map(|(k, v)| {
            format!(
                "<member><Key>{}</Key><Value>{}</Value></member>",
                xml_escape(k),
                xml_escape(v)
            )
        })
        .collect::<String>();
    format!("<Attributes>{entries}</Attributes>")
}

fn default_target_group_attributes() -> HashMap<String, String> {
    let mut m = HashMap::new();
    m.insert(
        "deregistration_delay.timeout_seconds".to_string(),
        "300".to_string(),
    );
    m.insert("stickiness.enabled".to_string(), "false".to_string());
    m.insert("stickiness.type".to_string(), "lb_cookie".to_string());
    m.insert(
        "stickiness.lb_cookie.duration_seconds".to_string(),
        "86400".to_string(),
    );
    m.insert(
        "load_balancing.algorithm.type".to_string(),
        "round_robin".to_string(),
    );
    m.insert("slow_start.duration_seconds".to_string(), "0".to_string());
    m
}

fn apply_tags(
    st: &mut crate::state::Elbv2State,
    arn: &str,
    new_tags: &[Tag],
) -> Result<(), AwsServiceError> {
    let target = resolve_taggable(st, arn)?;
    for nt in new_tags {
        target.retain(|t| t.key != nt.key);
        target.push(nt.clone());
    }
    Ok(())
}

fn remove_tag_keys(
    st: &mut crate::state::Elbv2State,
    arn: &str,
    keys: &[String],
) -> Result<(), AwsServiceError> {
    let target = resolve_taggable(st, arn)?;
    target.retain(|t| !keys.contains(&t.key));
    Ok(())
}

fn lookup_tags<'a>(st: &'a crate::state::Elbv2State, arn: &str) -> &'a [Tag] {
    if let Some(lb) = st.load_balancers.get(arn) {
        return &lb.tags;
    }
    if let Some(tg) = st.target_groups.get(arn) {
        return &tg.tags;
    }
    if let Some(l) = st.listeners.get(arn) {
        return &l.tags;
    }
    if let Some(r) = st.rules.get(arn) {
        return &r.tags;
    }
    if let Some(ts) = st.trust_stores.get(arn) {
        return &ts.tags;
    }
    &[]
}

fn resolve_taggable<'a>(
    st: &'a mut crate::state::Elbv2State,
    arn: &str,
) -> Result<&'a mut Vec<Tag>, AwsServiceError> {
    if st.load_balancers.contains_key(arn) {
        return Ok(&mut st.load_balancers.get_mut(arn).unwrap().tags);
    }
    if st.target_groups.contains_key(arn) {
        return Ok(&mut st.target_groups.get_mut(arn).unwrap().tags);
    }
    if st.listeners.contains_key(arn) {
        return Ok(&mut st.listeners.get_mut(arn).unwrap().tags);
    }
    if st.rules.contains_key(arn) {
        return Ok(&mut st.rules.get_mut(arn).unwrap().tags);
    }
    if st.trust_stores.contains_key(arn) {
        return Ok(&mut st.trust_stores.get_mut(arn).unwrap().tags);
    }
    Err(AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ResourceNotFound",
        format!("Resource '{arn}' not found"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::HeaderMap;
    use parking_lot::RwLock;

    fn req(action: &str, params: &[(&str, &str)]) -> AwsRequest {
        let mut q = HashMap::new();
        for (k, v) in params {
            q.insert((*k).to_string(), (*v).to_string());
        }
        AwsRequest {
            service: "elasticloadbalancing".to_string(),
            action: action.to_string(),
            region: "us-east-1".to_string(),
            account_id: "123456789012".to_string(),
            request_id: "rid".to_string(),
            headers: HeaderMap::new(),
            query_params: q,
            body: Bytes::new(),
            path_segments: vec![],
            raw_path: "/".to_string(),
            raw_query: String::new(),
            method: http::Method::POST,
            is_query_protocol: true,
            access_key_id: None,
            principal: None,
        }
    }

    fn svc() -> Elbv2Service {
        Elbv2Service::new(Arc::new(RwLock::new(crate::state::Elbv2Accounts::new())))
    }

    fn body_string(resp: &AwsResponse) -> String {
        match &resp.body {
            fakecloud_core::service::ResponseBody::Bytes(b) => {
                String::from_utf8_lossy(b).to_string()
            }
            _ => panic!("not bytes"),
        }
    }

    #[tokio::test]
    async fn create_then_describe_lb() {
        let svc = svc();
        let resp = svc
            .handle(req(
                "CreateLoadBalancer",
                &[
                    ("Name", "myapp"),
                    ("Subnets.member.1", "subnet-1"),
                    ("Subnets.member.2", "subnet-2"),
                ],
            ))
            .await
            .unwrap();
        let body = body_string(&resp);
        assert!(body.contains("<LoadBalancerName>myapp</LoadBalancerName>"));
        assert!(body.contains("<Type>application</Type>"));

        let resp = svc.handle(req("DescribeLoadBalancers", &[])).await.unwrap();
        let body = body_string(&resp);
        assert!(body.contains("<LoadBalancerName>myapp</LoadBalancerName>"));
    }

    #[tokio::test]
    async fn create_validates_name() {
        let svc = svc();
        let err = svc
            .handle(req("CreateLoadBalancer", &[("Name", "internal-bad")]))
            .await
            .err()
            .expect("expected error");
        assert_eq!(err.code(), "ValidationError");
    }

    #[tokio::test]
    async fn delete_lb_is_idempotent() {
        let svc = svc();
        svc.handle(req("CreateLoadBalancer", &[("Name", "foo")]))
            .await
            .unwrap();
        let arn = {
            let st = svc.state.read();
            st.get("123456789012")
                .unwrap()
                .load_balancers
                .keys()
                .next()
                .cloned()
                .unwrap()
        };
        svc.handle(req("DeleteLoadBalancer", &[("LoadBalancerArn", &arn)]))
            .await
            .unwrap();
        svc.handle(req("DeleteLoadBalancer", &[("LoadBalancerArn", &arn)]))
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn add_remove_describe_tags_round_trip() {
        let svc = svc();
        svc.handle(req("CreateLoadBalancer", &[("Name", "tagged")]))
            .await
            .unwrap();
        let arn = svc
            .state
            .read()
            .get("123456789012")
            .unwrap()
            .load_balancers
            .keys()
            .next()
            .cloned()
            .unwrap();
        svc.handle(req(
            "AddTags",
            &[
                ("ResourceArns.member.1", &arn),
                ("Tags.member.1.Key", "env"),
                ("Tags.member.1.Value", "prod"),
            ],
        ))
        .await
        .unwrap();
        let resp = svc
            .handle(req("DescribeTags", &[("ResourceArns.member.1", &arn)]))
            .await
            .unwrap();
        assert!(body_string(&resp).contains("<Key>env</Key>"));
        svc.handle(req(
            "RemoveTags",
            &[("ResourceArns.member.1", &arn), ("TagKeys.member.1", "env")],
        ))
        .await
        .unwrap();
        let resp = svc
            .handle(req("DescribeTags", &[("ResourceArns.member.1", &arn)]))
            .await
            .unwrap();
        assert!(!body_string(&resp).contains("<Key>env</Key>"));
    }

    #[tokio::test]
    async fn describe_account_limits_returns_known_keys() {
        let svc = svc();
        let resp = svc.handle(req("DescribeAccountLimits", &[])).await.unwrap();
        let body = body_string(&resp);
        assert!(body.contains("application-load-balancers"));
        assert!(body.contains("trust-stores"));
    }

    #[tokio::test]
    async fn describe_ssl_policies_includes_tls13() {
        let svc = svc();
        let resp = svc.handle(req("DescribeSSLPolicies", &[])).await.unwrap();
        assert!(body_string(&resp).contains("ELBSecurityPolicy-TLS13-1-2-2021-06"));
    }

    #[tokio::test]
    async fn unimplemented_action_errors() {
        let svc = svc();
        let err = svc
            .handle(req("CreateListener", &[]))
            .await
            .err()
            .expect("expected error");
        assert!(matches!(err, AwsServiceError::ActionNotImplemented { .. }));
    }
}
