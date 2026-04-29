//! Elastic Load Balancing v2 (ALB/NLB/GWLB) service implementation.
//!
//! Wire protocol: AWS Query (form-encoded request, XML response). Endpoint
//! prefix `elasticloadbalancing`, SigV4 service `elasticloadbalancing`.

use std::collections::{BTreeMap, HashSet};
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
    "CreateListener",
    "DescribeListeners",
    "ModifyListener",
    "DeleteListener",
    "DescribeListenerAttributes",
    "ModifyListenerAttributes",
    "AddListenerCertificates",
    "RemoveListenerCertificates",
    "DescribeListenerCertificates",
    "CreateRule",
    "DescribeRules",
    "ModifyRule",
    "DeleteRule",
    "SetRulePriorities",
    "ModifyLoadBalancerAttributes",
    "DescribeLoadBalancerAttributes",
    "ModifyCapacityReservation",
    "DescribeCapacityReservation",
    "CreateTrustStore",
    "DescribeTrustStores",
    "ModifyTrustStore",
    "DeleteTrustStore",
    "AddTrustStoreRevocations",
    "RemoveTrustStoreRevocations",
    "DescribeTrustStoreRevocations",
    "DescribeTrustStoreAssociations",
    "DeleteSharedTrustStoreAssociation",
    "GetTrustStoreCaCertificatesBundle",
    "GetTrustStoreRevocationContent",
    "GetResourcePolicy",
];

pub struct Elbv2Service {
    state: SharedElbv2State,
    pub region: String,
}

impl Elbv2Service {
    pub fn new(state: SharedElbv2State) -> Self {
        crate::prober::spawn_prober(Arc::clone(&state));
        crate::dataplane::spawn_dataplane(Arc::clone(&state));
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
            "CreateListener" => self.create_listener(&req),
            "DescribeListeners" => self.describe_listeners(&req),
            "ModifyListener" => self.modify_listener(&req),
            "DeleteListener" => self.delete_listener(&req),
            "DescribeListenerAttributes" => self.describe_listener_attributes(&req),
            "ModifyListenerAttributes" => self.modify_listener_attributes(&req),
            "AddListenerCertificates" => self.add_listener_certificates(&req),
            "RemoveListenerCertificates" => self.remove_listener_certificates(&req),
            "DescribeListenerCertificates" => self.describe_listener_certificates(&req),
            "CreateRule" => self.create_rule(&req),
            "DescribeRules" => self.describe_rules(&req),
            "ModifyRule" => self.modify_rule(&req),
            "DeleteRule" => self.delete_rule(&req),
            "SetRulePriorities" => self.set_rule_priorities(&req),
            "ModifyLoadBalancerAttributes" => self.modify_load_balancer_attributes(&req),
            "DescribeLoadBalancerAttributes" => self.describe_load_balancer_attributes(&req),
            "ModifyCapacityReservation" => self.modify_capacity_reservation(&req),
            "DescribeCapacityReservation" => self.describe_capacity_reservation(&req),
            "CreateTrustStore" => self.create_trust_store(&req),
            "DescribeTrustStores" => self.describe_trust_stores(&req),
            "ModifyTrustStore" => self.modify_trust_store(&req),
            "DeleteTrustStore" => self.delete_trust_store(&req),
            "AddTrustStoreRevocations" => self.add_trust_store_revocations(&req),
            "RemoveTrustStoreRevocations" => self.remove_trust_store_revocations(&req),
            "DescribeTrustStoreRevocations" => self.describe_trust_store_revocations(&req),
            "DescribeTrustStoreAssociations" => self.describe_trust_store_associations(&req),
            "DeleteSharedTrustStoreAssociation" => self.delete_shared_trust_store_association(&req),
            "GetTrustStoreCaCertificatesBundle" => {
                self.get_trust_store_ca_certificates_bundle(&req)
            }
            "GetTrustStoreRevocationContent" => self.get_trust_store_revocation_content(&req),
            "GetResourcePolicy" => self.get_resource_policy(&req),
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
        if subnet_id.is_none() && allocation_id.is_none() {
            break;
        }
        out.push(SubnetMapping {
            subnet_id,
            allocation_id,
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
            attributes: BTreeMap::new(),
            minimum_capacity_units: optional_query_param(
                req,
                "MinimumLoadBalancerCapacity.CapacityUnits",
            )
            .and_then(|s| s.parse().ok()),
            bound_port: None,
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
        // Reject if the TG is still referenced by listeners/rules — including
        // ForwardConfig.TargetGroups blocks on either default actions or rule actions.
        let action_refs_tg = |a: &crate::state::Action| {
            a.target_group_arn.as_deref() == Some(arn.as_str())
                || a.forward
                    .as_ref()
                    .is_some_and(|f| f.target_groups.iter().any(|t| t.target_group_arn == arn))
        };
        let referenced = st
            .listeners
            .values()
            .any(|l| l.default_actions.iter().any(action_refs_tg))
            || st
                .rules
                .values()
                .any(|r| r.actions.iter().any(action_refs_tg));
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

    // ───────────── Listener ops ─────────────

    fn create_listener(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let lb_arn = required_query_param(req, "LoadBalancerArn")?;
        let protocol = optional_query_param(req, "Protocol");
        let port = optional_query_param(req, "Port").and_then(|s| s.parse().ok());
        let ssl_policy = optional_query_param(req, "SslPolicy");
        let alpn_policy = parse_member_list(req, "AlpnPolicy");
        let certificates = parse_certificates(req);
        let actions = parse_actions(req, "DefaultActions");
        if actions.is_empty() {
            return Err(invalid_param("DefaultActions is required"));
        }
        let mut tags = parse_tags(req);
        tags.dedup_by(|a, b| a.key == b.key);

        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        if !st.load_balancers.contains_key(&lb_arn) {
            return Err(lb_not_found(&lb_arn));
        }
        // Validate referenced target groups exist (forward action targets).
        for action in &actions {
            if let Some(tg_arn) = &action.target_group_arn {
                if !st.target_groups.contains_key(tg_arn) {
                    return Err(target_group_not_found(tg_arn));
                }
            }
            if let Some(forward) = &action.forward {
                for tgt in &forward.target_groups {
                    if !st.target_groups.contains_key(&tgt.target_group_arn) {
                        return Err(target_group_not_found(&tgt.target_group_arn));
                    }
                }
            }
        }
        let suffix = alphanumeric_id(16);
        let arn = format!("{lb_arn}/{suffix}").replace(":loadbalancer/", ":listener/");
        // Mark referenced target groups as attached to this LB.
        let referenced_tgs: HashSet<String> = actions
            .iter()
            .filter_map(|a| a.target_group_arn.clone())
            .chain(actions.iter().flat_map(|a| {
                a.forward
                    .as_ref()
                    .map(|f| {
                        f.target_groups
                            .iter()
                            .map(|t| t.target_group_arn.clone())
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default()
            }))
            .collect();
        for tg_arn in &referenced_tgs {
            if let Some(tg) = st.target_groups.get_mut(tg_arn) {
                if !tg.load_balancer_arns.contains(&lb_arn) {
                    tg.load_balancer_arns.push(lb_arn.clone());
                }
            }
        }
        let listener = crate::state::Listener {
            arn: arn.clone(),
            load_balancer_arn: lb_arn,
            port,
            protocol,
            certificates,
            ssl_policy,
            default_actions: actions,
            alpn_policy,
            mutual_authentication: parse_mutual_authentication(req),
            tags,
            attributes: BTreeMap::new(),
        };
        let listener_xml = render_listener_xml(&listener);
        st.listeners.insert(arn, listener);
        Ok(xml_resp(
            "CreateListener",
            format!("<Listeners><member>{listener_xml}</member></Listeners>"),
            &req.request_id,
        ))
    }

    fn describe_listeners(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let lb_arn = optional_query_param(req, "LoadBalancerArn");
        let listener_arns: HashSet<String> =
            parse_member_list(req, "ListenerArns").into_iter().collect();
        let accounts = self.state.read();
        let empty = crate::state::Elbv2State::new(&req.account_id);
        let st = accounts.get(&req.account_id).unwrap_or(&empty);
        let mut listeners: Vec<&crate::state::Listener> = st
            .listeners
            .values()
            .filter(|l| {
                lb_arn.as_deref().is_none_or(|a| l.load_balancer_arn == a)
                    && (listener_arns.is_empty() || listener_arns.contains(&l.arn))
            })
            .collect();
        listeners.sort_by_key(|l| l.port.unwrap_or(0));
        let inner = format!(
            "<Listeners>{}</Listeners>",
            listeners
                .iter()
                .map(|l| format!("<member>{}</member>", render_listener_xml(l)))
                .collect::<String>()
        );
        Ok(xml_resp("DescribeListeners", inner, &req.request_id))
    }

    fn modify_listener(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "ListenerArn")?;
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let listener = st
            .listeners
            .get_mut(&arn)
            .ok_or_else(|| listener_not_found(&arn))?;
        if let Some(p) = optional_query_param(req, "Port").and_then(|s| s.parse().ok()) {
            listener.port = Some(p);
        }
        if let Some(p) = optional_query_param(req, "Protocol") {
            listener.protocol = Some(p);
        }
        if let Some(p) = optional_query_param(req, "SslPolicy") {
            listener.ssl_policy = Some(p);
        }
        let new_certs = parse_certificates(req);
        if !new_certs.is_empty() {
            listener.certificates = new_certs;
        }
        let new_actions = parse_actions(req, "DefaultActions");
        if !new_actions.is_empty() {
            listener.default_actions = new_actions;
        }
        let alpn = parse_member_list(req, "AlpnPolicy");
        if !alpn.is_empty() {
            listener.alpn_policy = alpn;
        }
        let xml = render_listener_xml(listener);
        Ok(xml_resp(
            "ModifyListener",
            format!("<Listeners><member>{xml}</member></Listeners>"),
            &req.request_id,
        ))
    }

    fn delete_listener(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "ListenerArn")?;
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        st.listeners.remove(&arn);
        st.rules.retain(|_, r| r.listener_arn != arn);
        Ok(xml_metadata_only("DeleteListener", &req.request_id))
    }

    fn describe_listener_attributes(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "ListenerArn")?;
        let accounts = self.state.read();
        let empty = crate::state::Elbv2State::new(&req.account_id);
        let st = accounts.get(&req.account_id).unwrap_or(&empty);
        let listener = st
            .listeners
            .get(&arn)
            .ok_or_else(|| listener_not_found(&arn))?;
        Ok(xml_resp(
            "DescribeListenerAttributes",
            render_attributes_xml(&listener.attributes),
            &req.request_id,
        ))
    }

    fn modify_listener_attributes(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "ListenerArn")?;
        let new_attrs = parse_attributes(req);
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let listener = st
            .listeners
            .get_mut(&arn)
            .ok_or_else(|| listener_not_found(&arn))?;
        for (k, v) in &new_attrs {
            listener.attributes.insert(k.clone(), v.clone());
        }
        Ok(xml_resp(
            "ModifyListenerAttributes",
            render_attributes_xml(&listener.attributes),
            &req.request_id,
        ))
    }

    fn add_listener_certificates(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "ListenerArn")?;
        let new_certs = parse_certificates(req);
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let listener = st
            .listeners
            .get_mut(&arn)
            .ok_or_else(|| listener_not_found(&arn))?;
        for c in &new_certs {
            listener
                .certificates
                .retain(|x| x.certificate_arn != c.certificate_arn);
            listener.certificates.push(c.clone());
        }
        let cert_xml = listener
            .certificates
            .iter()
            .map(render_certificate_xml)
            .collect::<String>();
        Ok(xml_resp(
            "AddListenerCertificates",
            format!("<Certificates>{cert_xml}</Certificates>"),
            &req.request_id,
        ))
    }

    fn remove_listener_certificates(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "ListenerArn")?;
        let to_remove = parse_certificates(req);
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let listener = st
            .listeners
            .get_mut(&arn)
            .ok_or_else(|| listener_not_found(&arn))?;
        let remove_arns: HashSet<String> = to_remove
            .iter()
            .map(|c| c.certificate_arn.clone())
            .collect();
        listener
            .certificates
            .retain(|c| !remove_arns.contains(&c.certificate_arn));
        Ok(xml_metadata_only(
            "RemoveListenerCertificates",
            &req.request_id,
        ))
    }

    fn describe_listener_certificates(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "ListenerArn")?;
        let accounts = self.state.read();
        let empty = crate::state::Elbv2State::new(&req.account_id);
        let st = accounts.get(&req.account_id).unwrap_or(&empty);
        let listener = st
            .listeners
            .get(&arn)
            .ok_or_else(|| listener_not_found(&arn))?;
        let cert_xml = listener
            .certificates
            .iter()
            .map(render_certificate_xml)
            .collect::<String>();
        Ok(xml_resp(
            "DescribeListenerCertificates",
            format!("<Certificates>{cert_xml}</Certificates>"),
            &req.request_id,
        ))
    }

    // ───────────── Rule ops ─────────────

    fn create_rule(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let listener_arn = required_query_param(req, "ListenerArn")?;
        let priority = required_query_param(req, "Priority")?;
        match priority.parse::<i32>() {
            Ok(n) if n > 0 => {}
            _ => {
                return Err(invalid_param(format!(
                    "Priority must be a positive integer, got '{priority}'"
                )));
            }
        }
        let conditions = parse_conditions(req);
        if conditions.is_empty() {
            return Err(invalid_param("Conditions is required"));
        }
        let actions = parse_actions(req, "Actions");
        if actions.is_empty() {
            return Err(invalid_param("Actions is required"));
        }
        let mut tags = parse_tags(req);
        tags.dedup_by(|a, b| a.key == b.key);

        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        if !st.listeners.contains_key(&listener_arn) {
            return Err(listener_not_found(&listener_arn));
        }
        // Reject any forward action that references a target group not in this account.
        for action in &actions {
            if let Some(arn) = action.target_group_arn.as_deref() {
                if !st.target_groups.contains_key(arn) {
                    return Err(target_group_not_found(arn));
                }
            }
            if let Some(forward) = action.forward.as_ref() {
                for t in &forward.target_groups {
                    if !st.target_groups.contains_key(&t.target_group_arn) {
                        return Err(target_group_not_found(&t.target_group_arn));
                    }
                }
            }
        }
        if st
            .rules
            .values()
            .any(|r| r.listener_arn == listener_arn && r.priority == priority && !r.is_default)
        {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "PriorityInUse",
                format!("Priority '{priority}' already in use on listener '{listener_arn}'"),
            ));
        }
        let suffix = alphanumeric_id(16);
        let arn = format!("{listener_arn}/{suffix}").replace(":listener/", ":listener-rule/");
        let rule = crate::state::Rule {
            arn: arn.clone(),
            listener_arn,
            priority,
            conditions,
            actions,
            is_default: false,
            tags,
        };
        let rule_xml = render_rule_xml(&rule);
        st.rules.insert(arn, rule);
        Ok(xml_resp(
            "CreateRule",
            format!("<Rules><member>{rule_xml}</member></Rules>"),
            &req.request_id,
        ))
    }

    fn describe_rules(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let listener_arn = optional_query_param(req, "ListenerArn");
        let rule_arns: HashSet<String> = parse_member_list(req, "RuleArns").into_iter().collect();
        let accounts = self.state.read();
        let empty = crate::state::Elbv2State::new(&req.account_id);
        let st = accounts.get(&req.account_id).unwrap_or(&empty);
        let mut rules: Vec<&crate::state::Rule> = st
            .rules
            .values()
            .filter(|r| {
                listener_arn.as_deref().is_none_or(|a| r.listener_arn == a)
                    && (rule_arns.is_empty() || rule_arns.contains(&r.arn))
            })
            .collect();
        rules.sort_by(|a, b| {
            let ap = a.priority.parse::<i32>().unwrap_or(i32::MAX);
            let bp = b.priority.parse::<i32>().unwrap_or(i32::MAX);
            ap.cmp(&bp)
        });
        let inner = format!(
            "<Rules>{}</Rules>",
            rules
                .iter()
                .map(|r| format!("<member>{}</member>", render_rule_xml(r)))
                .collect::<String>()
        );
        Ok(xml_resp("DescribeRules", inner, &req.request_id))
    }

    fn modify_rule(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "RuleArn")?;
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let new_conditions = parse_conditions(req);
        let new_actions = parse_actions(req, "Actions");
        let rule = st.rules.get_mut(&arn).ok_or_else(|| rule_not_found(&arn))?;
        if !new_conditions.is_empty() {
            rule.conditions = new_conditions;
        }
        if !new_actions.is_empty() {
            rule.actions = new_actions;
        }
        let xml = render_rule_xml(rule);
        Ok(xml_resp(
            "ModifyRule",
            format!("<Rules><member>{xml}</member></Rules>"),
            &req.request_id,
        ))
    }

    fn delete_rule(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "RuleArn")?;
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        st.rules.remove(&arn);
        Ok(xml_metadata_only("DeleteRule", &req.request_id))
    }

    fn set_rule_priorities(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mut updates: Vec<(String, String)> = Vec::new();
        for n in 1..=100 {
            let arn = req
                .query_params
                .get(&format!("RulePriorities.member.{n}.RuleArn"))
                .cloned();
            if let Some(arn) = arn {
                let priority = req
                    .query_params
                    .get(&format!("RulePriorities.member.{n}.Priority"))
                    .cloned()
                    .unwrap_or_default();
                updates.push((arn, priority));
            } else {
                break;
            }
        }
        if updates.is_empty() {
            return Err(invalid_param("RulePriorities is required"));
        }
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let mut updated = Vec::new();
        for (arn, priority) in updates {
            let rule = st.rules.get_mut(&arn).ok_or_else(|| rule_not_found(&arn))?;
            rule.priority = priority;
            updated.push(rule.arn.clone());
        }
        let arns: Vec<String> = updated;
        let rules_xml = arns
            .iter()
            .filter_map(|a| st.rules.get(a))
            .map(|r| format!("<member>{}</member>", render_rule_xml(r)))
            .collect::<String>();
        Ok(xml_resp(
            "SetRulePriorities",
            format!("<Rules>{rules_xml}</Rules>"),
            &req.request_id,
        ))
    }

    // ───────────── LB attributes + Capacity ─────────────

    fn modify_load_balancer_attributes(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "LoadBalancerArn")?;
        let new_attrs = parse_attributes(req);
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let lb = st
            .load_balancers
            .get_mut(&arn)
            .ok_or_else(|| lb_not_found(&arn))?;
        for (k, v) in &new_attrs {
            lb.attributes.insert(k.clone(), v.clone());
        }
        let merged = merge_lb_attributes(&lb.lb_type, &lb.attributes);
        Ok(xml_resp(
            "ModifyLoadBalancerAttributes",
            render_attributes_xml(&merged),
            &req.request_id,
        ))
    }

    fn describe_load_balancer_attributes(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "LoadBalancerArn")?;
        let accounts = self.state.read();
        let empty = crate::state::Elbv2State::new(&req.account_id);
        let st = accounts.get(&req.account_id).unwrap_or(&empty);
        let lb = st
            .load_balancers
            .get(&arn)
            .ok_or_else(|| lb_not_found(&arn))?;
        let merged = merge_lb_attributes(&lb.lb_type, &lb.attributes);
        Ok(xml_resp(
            "DescribeLoadBalancerAttributes",
            render_attributes_xml(&merged),
            &req.request_id,
        ))
    }

    fn modify_capacity_reservation(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "LoadBalancerArn")?;
        let units = optional_query_param(req, "MinimumLoadBalancerCapacity.CapacityUnits")
            .and_then(|s| s.parse().ok());
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let lb = st
            .load_balancers
            .get_mut(&arn)
            .ok_or_else(|| lb_not_found(&arn))?;
        lb.minimum_capacity_units = units;
        Ok(xml_resp(
            "ModifyCapacityReservation",
            capacity_reservation_xml(lb),
            &req.request_id,
        ))
    }

    fn describe_capacity_reservation(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "LoadBalancerArn")?;
        let accounts = self.state.read();
        let empty = crate::state::Elbv2State::new(&req.account_id);
        let st = accounts.get(&req.account_id).unwrap_or(&empty);
        let lb = st
            .load_balancers
            .get(&arn)
            .ok_or_else(|| lb_not_found(&arn))?;
        Ok(xml_resp(
            "DescribeCapacityReservation",
            capacity_reservation_xml(lb),
            &req.request_id,
        ))
    }

    // ───────────── Trust stores ─────────────

    fn create_trust_store(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let name = required_query_param(req, "Name")?;
        let bucket = required_query_param(req, "CaCertificatesBundleS3Bucket")?;
        let key = required_query_param(req, "CaCertificatesBundleS3Key")?;
        let _version = optional_query_param(req, "CaCertificatesBundleS3ObjectVersion");
        let tags = parse_tags(req);
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        if st.trust_stores.values().any(|t| t.name == name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "DuplicateTrustStoreName",
                format!("Trust store '{name}' already exists"),
            ));
        }
        let suffix = alphanumeric_id(16);
        let arn = format!(
            "arn:aws:elasticloadbalancing:{}:{}:truststore/{}/{}",
            req.region, req.account_id, name, suffix
        );
        let ts = crate::state::TrustStore {
            arn: arn.clone(),
            name,
            status: "ACTIVE".to_string(),
            number_of_ca_certificates: 1,
            total_revoked_entries: 0,
            created_time: Utc::now(),
            ca_certificates_bundle: Some(format!("s3://{bucket}/{key}").into_bytes()),
            revocations: BTreeMap::new(),
            next_revocation_id: 1,
            tags,
        };
        let xml = render_trust_store_xml(&ts);
        st.trust_stores.insert(arn, ts);
        Ok(xml_resp(
            "CreateTrustStore",
            format!("<TrustStores><member>{xml}</member></TrustStores>"),
            &req.request_id,
        ))
    }

    fn describe_trust_stores(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arns: HashSet<String> = parse_member_list(req, "TrustStoreArns")
            .into_iter()
            .collect();
        let names: HashSet<String> = parse_member_list(req, "Names").into_iter().collect();
        let accounts = self.state.read();
        let empty = crate::state::Elbv2State::new(&req.account_id);
        let st = accounts.get(&req.account_id).unwrap_or(&empty);
        let mut stores: Vec<&crate::state::TrustStore> = st
            .trust_stores
            .values()
            .filter(|t| {
                (arns.is_empty() || arns.contains(&t.arn))
                    && (names.is_empty() || names.contains(&t.name))
            })
            .collect();
        stores.sort_by_key(|s| s.created_time);
        let inner = format!(
            "<TrustStores>{}</TrustStores>",
            stores
                .iter()
                .map(|t| format!("<member>{}</member>", render_trust_store_xml(t)))
                .collect::<String>()
        );
        Ok(xml_resp("DescribeTrustStores", inner, &req.request_id))
    }

    fn modify_trust_store(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "TrustStoreArn")?;
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let ts = st
            .trust_stores
            .get_mut(&arn)
            .ok_or_else(|| trust_store_not_found(&arn))?;
        if let Some(b) = optional_query_param(req, "CaCertificatesBundleS3Bucket") {
            let key = required_query_param(req, "CaCertificatesBundleS3Key")?;
            ts.ca_certificates_bundle = Some(format!("s3://{b}/{key}").into_bytes());
        }
        let xml = render_trust_store_xml(ts);
        Ok(xml_resp(
            "ModifyTrustStore",
            format!("<TrustStores><member>{xml}</member></TrustStores>"),
            &req.request_id,
        ))
    }

    fn delete_trust_store(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "TrustStoreArn")?;
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let in_use = st.listeners.values().any(|l| {
            l.mutual_authentication
                .as_ref()
                .and_then(|m| m.trust_store_arn.as_deref())
                == Some(arn.as_str())
        });
        if in_use {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "TrustStoreInUse",
                "Trust store is in use by one or more listeners",
            ));
        }
        st.trust_stores.remove(&arn);
        Ok(xml_metadata_only("DeleteTrustStore", &req.request_id))
    }

    fn add_trust_store_revocations(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "TrustStoreArn")?;
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let ts = st
            .trust_stores
            .get_mut(&arn)
            .ok_or_else(|| trust_store_not_found(&arn))?;
        let mut added = Vec::new();
        for n in 1..=10 {
            let bucket = req
                .query_params
                .get(&format!("RevocationContents.member.{n}.S3Bucket"))
                .cloned();
            if let Some(bucket) = bucket {
                let key = req
                    .query_params
                    .get(&format!("RevocationContents.member.{n}.S3Key"))
                    .cloned()
                    .unwrap_or_default();
                let id = ts.next_revocation_id;
                ts.next_revocation_id += 1;
                let rev = crate::state::TrustStoreRevocation {
                    revocation_id: id,
                    revocation_type: "CRL".to_string(),
                    number_of_revoked_entries: 0,
                    content: format!("s3://{bucket}/{key}").into_bytes(),
                };
                ts.revocations.insert(id, rev);
                added.push(id);
            } else {
                break;
            }
        }
        ts.total_revoked_entries += added.len() as i64;
        let revs_xml = added
            .iter()
            .map(|id| {
                format!(
                    "<member><TrustStoreArn>{}</TrustStoreArn><RevocationId>{id}</RevocationId><RevocationType>CRL</RevocationType><NumberOfRevokedEntries>0</NumberOfRevokedEntries></member>",
                    xml_escape(&arn)
                )
            })
            .collect::<String>();
        Ok(xml_resp(
            "AddTrustStoreRevocations",
            format!("<TrustStoreRevocations>{revs_xml}</TrustStoreRevocations>"),
            &req.request_id,
        ))
    }

    fn remove_trust_store_revocations(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "TrustStoreArn")?;
        let ids: Vec<i64> = parse_member_list(req, "RevocationIds")
            .into_iter()
            .filter_map(|s| s.parse().ok())
            .collect();
        let mut accounts = self.state.write();
        let st = accounts.get_or_create(&req.account_id);
        let ts = st
            .trust_stores
            .get_mut(&arn)
            .ok_or_else(|| trust_store_not_found(&arn))?;
        for id in &ids {
            ts.revocations.remove(id);
        }
        Ok(xml_metadata_only(
            "RemoveTrustStoreRevocations",
            &req.request_id,
        ))
    }

    fn describe_trust_store_revocations(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "TrustStoreArn")?;
        let accounts = self.state.read();
        let empty = crate::state::Elbv2State::new(&req.account_id);
        let st = accounts.get(&req.account_id).unwrap_or(&empty);
        let ts = st
            .trust_stores
            .get(&arn)
            .ok_or_else(|| trust_store_not_found(&arn))?;
        let revs_xml = ts
            .revocations
            .values()
            .map(|r| {
                format!(
                    "<member><TrustStoreArn>{}</TrustStoreArn><RevocationId>{}</RevocationId><RevocationType>{}</RevocationType><NumberOfRevokedEntries>{}</NumberOfRevokedEntries></member>",
                    xml_escape(&arn),
                    r.revocation_id,
                    xml_escape(&r.revocation_type),
                    r.number_of_revoked_entries
                )
            })
            .collect::<String>();
        Ok(xml_resp(
            "DescribeTrustStoreRevocations",
            format!("<TrustStoreRevocations>{revs_xml}</TrustStoreRevocations>"),
            &req.request_id,
        ))
    }

    fn describe_trust_store_associations(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "TrustStoreArn")?;
        let accounts = self.state.read();
        let empty = crate::state::Elbv2State::new(&req.account_id);
        let st = accounts.get(&req.account_id).unwrap_or(&empty);
        let assocs: Vec<&str> = st
            .listeners
            .values()
            .filter(|l| {
                l.mutual_authentication
                    .as_ref()
                    .and_then(|m| m.trust_store_arn.as_deref())
                    == Some(arn.as_str())
            })
            .map(|l| l.arn.as_str())
            .collect();
        let xml = assocs
            .iter()
            .map(|a| {
                format!(
                    "<member><ResourceArn>{}</ResourceArn></member>",
                    xml_escape(a)
                )
            })
            .collect::<String>();
        Ok(xml_resp(
            "DescribeTrustStoreAssociations",
            format!("<TrustStoreAssociations>{xml}</TrustStoreAssociations>"),
            &req.request_id,
        ))
    }

    fn delete_shared_trust_store_association(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let _arn = required_query_param(req, "TrustStoreArn")?;
        let _resource = required_query_param(req, "ResourceArn")?;
        Ok(xml_metadata_only(
            "DeleteSharedTrustStoreAssociation",
            &req.request_id,
        ))
    }

    fn get_trust_store_ca_certificates_bundle(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "TrustStoreArn")?;
        let accounts = self.state.read();
        let empty = crate::state::Elbv2State::new(&req.account_id);
        let st = accounts.get(&req.account_id).unwrap_or(&empty);
        let ts = st
            .trust_stores
            .get(&arn)
            .ok_or_else(|| trust_store_not_found(&arn))?;
        let location = ts
            .ca_certificates_bundle
            .as_deref()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .unwrap_or_default();
        Ok(xml_resp(
            "GetTrustStoreCaCertificatesBundle",
            format!("<Location>{}</Location>", xml_escape(&location)),
            &req.request_id,
        ))
    }

    fn get_trust_store_revocation_content(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "TrustStoreArn")?;
        let id: i64 = required_query_param(req, "RevocationId")?
            .parse()
            .map_err(|_| invalid_param("RevocationId must be an integer"))?;
        let accounts = self.state.read();
        let empty = crate::state::Elbv2State::new(&req.account_id);
        let st = accounts.get(&req.account_id).unwrap_or(&empty);
        let ts = st
            .trust_stores
            .get(&arn)
            .ok_or_else(|| trust_store_not_found(&arn))?;
        let rev = ts.revocations.get(&id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "RevocationIdNotFound",
                format!("Revocation '{id}' not found"),
            )
        })?;
        let location = String::from_utf8_lossy(&rev.content).to_string();
        Ok(xml_resp(
            "GetTrustStoreRevocationContent",
            format!("<Location>{}</Location>", xml_escape(&location)),
            &req.request_id,
        ))
    }

    fn get_resource_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let arn = required_query_param(req, "ResourceArn")?;
        let accounts = self.state.read();
        let empty = crate::state::Elbv2State::new(&req.account_id);
        let st = accounts.get(&req.account_id).unwrap_or(&empty);
        let policy = st
            .resource_policies
            .get(&arn)
            .cloned()
            .unwrap_or_else(|| "{}".to_string());
        Ok(xml_resp(
            "GetResourcePolicy",
            format!("<Policy>{}</Policy>", xml_escape(&policy)),
            &req.request_id,
        ))
    }
}

fn trust_store_not_found(arn: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "TrustStoreNotFound",
        format!("Trust store '{arn}' not found"),
    )
}

fn default_lb_attributes(lb_type: &str) -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
    m.insert("idle_timeout.timeout_seconds".to_string(), "60".to_string());
    m.insert(
        "deletion_protection.enabled".to_string(),
        "false".to_string(),
    );
    m.insert(
        "load_balancing.cross_zone.enabled".to_string(),
        "true".to_string(),
    );
    m.insert("access_logs.s3.enabled".to_string(), "false".to_string());
    m.insert("access_logs.s3.bucket".to_string(), String::new());
    m.insert("access_logs.s3.prefix".to_string(), String::new());
    if lb_type == "application" {
        m.insert("routing.http2.enabled".to_string(), "true".to_string());
        m.insert(
            "routing.http.drop_invalid_header_fields.enabled".to_string(),
            "false".to_string(),
        );
        m.insert(
            "routing.http.preserve_host_header.enabled".to_string(),
            "false".to_string(),
        );
    }
    m
}

fn merge_lb_attributes(
    lb_type: &str,
    stored: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut m = default_lb_attributes(lb_type);
    for (k, v) in stored {
        m.insert(k.clone(), v.clone());
    }
    m
}

fn capacity_reservation_xml(lb: &crate::state::LoadBalancer) -> String {
    let units = lb
        .minimum_capacity_units
        .map(|v| {
            format!(
                "<MinimumLoadBalancerCapacity><CapacityUnits>{v}</CapacityUnits></MinimumLoadBalancerCapacity>"
            )
        })
        .unwrap_or_default();
    format!("<LastModifiedTime>{}</LastModifiedTime>{units}<DecreaseRequestsRemaining>0</DecreaseRequestsRemaining>", lb.created_time.to_rfc3339_opts(chrono::SecondsFormat::Millis, true))
}

fn render_trust_store_xml(ts: &crate::state::TrustStore) -> String {
    format!(
        "<TrustStoreArn>{arn}</TrustStoreArn>\
         <Name>{name}</Name>\
         <Status>{status}</Status>\
         <NumberOfCaCertificates>{num}</NumberOfCaCertificates>\
         <TotalRevokedEntries>{rev}</TotalRevokedEntries>",
        arn = xml_escape(&ts.arn),
        name = xml_escape(&ts.name),
        status = xml_escape(&ts.status),
        num = ts.number_of_ca_certificates,
        rev = ts.total_revoked_entries,
    )
}

fn listener_not_found(arn: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ListenerNotFound",
        format!("Listener '{arn}' not found"),
    )
}

fn rule_not_found(arn: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "RuleNotFound",
        format!("Rule '{arn}' not found"),
    )
}

fn parse_certificates(req: &AwsRequest) -> Vec<crate::state::Certificate> {
    let mut out = Vec::new();
    for n in 1..=25 {
        let arn = req
            .query_params
            .get(&format!("Certificates.member.{n}.CertificateArn"))
            .cloned();
        if let Some(arn) = arn {
            let is_default = req
                .query_params
                .get(&format!("Certificates.member.{n}.IsDefault"))
                .map(|s| s == "true")
                .unwrap_or(false);
            out.push(crate::state::Certificate {
                certificate_arn: arn,
                is_default,
            });
        } else {
            break;
        }
    }
    out
}

fn parse_actions(req: &AwsRequest, prefix: &str) -> Vec<crate::state::Action> {
    let mut out = Vec::new();
    for n in 1..=10 {
        let p = format!("{prefix}.member.{n}");
        let action_type = req.query_params.get(&format!("{p}.Type")).cloned();
        if let Some(t) = action_type {
            let target_group_arn = req
                .query_params
                .get(&format!("{p}.TargetGroupArn"))
                .cloned();
            let order = req
                .query_params
                .get(&format!("{p}.Order"))
                .and_then(|s| s.parse().ok());
            let redirect = parse_redirect(req, &p);
            let fixed_response = parse_fixed_response(req, &p);
            let forward = parse_forward(req, &p);
            out.push(crate::state::Action {
                action_type: t,
                target_group_arn,
                order,
                redirect,
                fixed_response,
                forward,
                authenticate_cognito: None,
                authenticate_oidc: None,
            });
        } else {
            break;
        }
    }
    out
}

fn parse_redirect(req: &AwsRequest, prefix: &str) -> Option<crate::state::RedirectConfig> {
    let status = req
        .query_params
        .get(&format!("{prefix}.RedirectConfig.StatusCode"))
        .cloned()?;
    Some(crate::state::RedirectConfig {
        protocol: req
            .query_params
            .get(&format!("{prefix}.RedirectConfig.Protocol"))
            .cloned(),
        port: req
            .query_params
            .get(&format!("{prefix}.RedirectConfig.Port"))
            .cloned(),
        host: req
            .query_params
            .get(&format!("{prefix}.RedirectConfig.Host"))
            .cloned(),
        path: req
            .query_params
            .get(&format!("{prefix}.RedirectConfig.Path"))
            .cloned(),
        query: req
            .query_params
            .get(&format!("{prefix}.RedirectConfig.Query"))
            .cloned(),
        status_code: status,
    })
}

fn parse_fixed_response(
    req: &AwsRequest,
    prefix: &str,
) -> Option<crate::state::FixedResponseConfig> {
    let status = req
        .query_params
        .get(&format!("{prefix}.FixedResponseConfig.StatusCode"))
        .cloned()?;
    Some(crate::state::FixedResponseConfig {
        message_body: req
            .query_params
            .get(&format!("{prefix}.FixedResponseConfig.MessageBody"))
            .cloned(),
        status_code: status,
        content_type: req
            .query_params
            .get(&format!("{prefix}.FixedResponseConfig.ContentType"))
            .cloned(),
    })
}

fn parse_forward(req: &AwsRequest, prefix: &str) -> Option<crate::state::ForwardConfig> {
    let mut target_groups = Vec::new();
    for n in 1..=5 {
        let key = format!("{prefix}.ForwardConfig.TargetGroups.member.{n}.TargetGroupArn");
        if let Some(arn) = req.query_params.get(&key) {
            let weight = req
                .query_params
                .get(&format!(
                    "{prefix}.ForwardConfig.TargetGroups.member.{n}.Weight"
                ))
                .and_then(|s| s.parse().ok());
            target_groups.push(crate::state::TargetGroupTuple {
                target_group_arn: arn.clone(),
                weight,
            });
        } else {
            break;
        }
    }
    if target_groups.is_empty() {
        return None;
    }
    Some(crate::state::ForwardConfig {
        target_groups,
        stickiness: None,
    })
}

fn parse_mutual_authentication(req: &AwsRequest) -> Option<crate::state::MutualAuthentication> {
    let mode = req.query_params.get("MutualAuthentication.Mode").cloned()?;
    Some(crate::state::MutualAuthentication {
        mode: Some(mode),
        trust_store_arn: req
            .query_params
            .get("MutualAuthentication.TrustStoreArn")
            .cloned(),
        ignore_client_certificate_expiry: req
            .query_params
            .get("MutualAuthentication.IgnoreClientCertificateExpiry")
            .map(|s| s == "true"),
        trust_store_association_status: None,
        advertise_trust_store_ca_names: req
            .query_params
            .get("MutualAuthentication.AdvertiseTrustStoreCaNames")
            .cloned(),
    })
}

fn parse_conditions(req: &AwsRequest) -> Vec<crate::state::RuleCondition> {
    let mut out = Vec::new();
    for n in 1..=10 {
        let p = format!("Conditions.member.{n}");
        let field = req.query_params.get(&format!("{p}.Field")).cloned();
        if let Some(field) = field {
            out.push(crate::state::RuleCondition {
                field,
                values: parse_member_list(req, &format!("{p}.Values")),
                host_header_values: parse_member_list(req, &format!("{p}.HostHeaderConfig.Values")),
                path_pattern_values: parse_member_list(
                    req,
                    &format!("{p}.PathPatternConfig.Values"),
                ),
                http_header_name: req
                    .query_params
                    .get(&format!("{p}.HttpHeaderConfig.HttpHeaderName"))
                    .cloned(),
                http_header_values: parse_member_list(req, &format!("{p}.HttpHeaderConfig.Values")),
                query_string_values: Vec::new(),
                http_request_method_values: parse_member_list(
                    req,
                    &format!("{p}.HttpRequestMethodConfig.Values"),
                ),
                source_ip_values: parse_member_list(req, &format!("{p}.SourceIpConfig.Values")),
            });
        } else {
            break;
        }
    }
    out
}

fn render_listener_xml(l: &crate::state::Listener) -> String {
    let port = l
        .port
        .map(|p| format!("<Port>{p}</Port>"))
        .unwrap_or_default();
    let proto = l
        .protocol
        .as_deref()
        .map(|p| format!("<Protocol>{}</Protocol>", xml_escape(p)))
        .unwrap_or_default();
    let ssl = l
        .ssl_policy
        .as_deref()
        .map(|p| format!("<SslPolicy>{}</SslPolicy>", xml_escape(p)))
        .unwrap_or_default();
    let cert_xml = l
        .certificates
        .iter()
        .map(render_certificate_xml)
        .collect::<String>();
    let actions_xml = l
        .default_actions
        .iter()
        .map(render_action_xml)
        .collect::<String>();
    let alpn_xml = l
        .alpn_policy
        .iter()
        .map(|p| format!("<member>{}</member>", xml_escape(p)))
        .collect::<String>();
    let ma_xml = l
        .mutual_authentication
        .as_ref()
        .map(render_mutual_auth_xml)
        .unwrap_or_default();
    format!(
        "<ListenerArn>{arn}</ListenerArn>\
         <LoadBalancerArn>{lb}</LoadBalancerArn>\
         {port}{proto}\
         <Certificates>{cert_xml}</Certificates>\
         {ssl}\
         <DefaultActions>{actions_xml}</DefaultActions>\
         <AlpnPolicy>{alpn_xml}</AlpnPolicy>\
         {ma_xml}",
        arn = xml_escape(&l.arn),
        lb = xml_escape(&l.load_balancer_arn),
    )
}

fn render_certificate_xml(c: &crate::state::Certificate) -> String {
    format!(
        "<member><CertificateArn>{}</CertificateArn><IsDefault>{}</IsDefault></member>",
        xml_escape(&c.certificate_arn),
        c.is_default
    )
}

fn render_action_xml(a: &crate::state::Action) -> String {
    let order = a
        .order
        .map(|o| format!("<Order>{o}</Order>"))
        .unwrap_or_default();
    let tg = a
        .target_group_arn
        .as_deref()
        .map(|t| format!("<TargetGroupArn>{}</TargetGroupArn>", xml_escape(t)))
        .unwrap_or_default();
    let redirect = a
        .redirect
        .as_ref()
        .map(|r| {
            let mut s = String::from("<RedirectConfig>");
            if let Some(p) = &r.protocol {
                s.push_str(&format!("<Protocol>{}</Protocol>", xml_escape(p)));
            }
            if let Some(p) = &r.port {
                s.push_str(&format!("<Port>{}</Port>", xml_escape(p)));
            }
            if let Some(p) = &r.host {
                s.push_str(&format!("<Host>{}</Host>", xml_escape(p)));
            }
            if let Some(p) = &r.path {
                s.push_str(&format!("<Path>{}</Path>", xml_escape(p)));
            }
            if let Some(p) = &r.query {
                s.push_str(&format!("<Query>{}</Query>", xml_escape(p)));
            }
            s.push_str(&format!(
                "<StatusCode>{}</StatusCode>",
                xml_escape(&r.status_code)
            ));
            s.push_str("</RedirectConfig>");
            s
        })
        .unwrap_or_default();
    let fixed = a
        .fixed_response
        .as_ref()
        .map(|f| {
            let mb = f
                .message_body
                .as_deref()
                .map(|m| format!("<MessageBody>{}</MessageBody>", xml_escape(m)))
                .unwrap_or_default();
            let ct = f
                .content_type
                .as_deref()
                .map(|c| format!("<ContentType>{}</ContentType>", xml_escape(c)))
                .unwrap_or_default();
            format!(
                "<FixedResponseConfig>{mb}<StatusCode>{}</StatusCode>{ct}</FixedResponseConfig>",
                xml_escape(&f.status_code)
            )
        })
        .unwrap_or_default();
    let forward = a
        .forward
        .as_ref()
        .map(|f| {
            let groups = f
                .target_groups
                .iter()
                .map(|g| {
                    let weight = g
                        .weight
                        .map(|w| format!("<Weight>{w}</Weight>"))
                        .unwrap_or_default();
                    format!(
                        "<member><TargetGroupArn>{}</TargetGroupArn>{weight}</member>",
                        xml_escape(&g.target_group_arn)
                    )
                })
                .collect::<String>();
            format!("<ForwardConfig><TargetGroups>{groups}</TargetGroups></ForwardConfig>")
        })
        .unwrap_or_default();
    format!(
        "<member><Type>{ty}</Type>{tg}{order}{redirect}{fixed}{forward}</member>",
        ty = xml_escape(&a.action_type),
    )
}

fn render_mutual_auth_xml(ma: &crate::state::MutualAuthentication) -> String {
    let mode = ma
        .mode
        .as_deref()
        .map(|m| format!("<Mode>{}</Mode>", xml_escape(m)))
        .unwrap_or_default();
    let ts = ma
        .trust_store_arn
        .as_deref()
        .map(|t| format!("<TrustStoreArn>{}</TrustStoreArn>", xml_escape(t)))
        .unwrap_or_default();
    let ig = ma
        .ignore_client_certificate_expiry
        .map(|b| format!("<IgnoreClientCertificateExpiry>{b}</IgnoreClientCertificateExpiry>"))
        .unwrap_or_default();
    let adv = ma
        .advertise_trust_store_ca_names
        .as_deref()
        .map(|a| {
            format!(
                "<AdvertiseTrustStoreCaNames>{}</AdvertiseTrustStoreCaNames>",
                xml_escape(a)
            )
        })
        .unwrap_or_default();
    format!("<MutualAuthentication>{mode}{ts}{ig}{adv}</MutualAuthentication>")
}

fn render_rule_xml(r: &crate::state::Rule) -> String {
    let conditions_xml = r
        .conditions
        .iter()
        .map(|c| {
            let values = c
                .values
                .iter()
                .map(|v| format!("<member>{}</member>", xml_escape(v)))
                .collect::<String>();
            format!(
                "<member><Field>{}</Field><Values>{values}</Values></member>",
                xml_escape(&c.field)
            )
        })
        .collect::<String>();
    let actions_xml = r.actions.iter().map(render_action_xml).collect::<String>();
    format!(
        "<RuleArn>{arn}</RuleArn>\
         <Priority>{priority}</Priority>\
         <Conditions>{conditions_xml}</Conditions>\
         <Actions>{actions_xml}</Actions>\
         <IsDefault>{is_default}</IsDefault>",
        arn = xml_escape(&r.arn),
        priority = xml_escape(&r.priority),
        is_default = r.is_default,
    )
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
    let matcher = match (
        tg.matcher_http_code.as_deref(),
        tg.matcher_grpc_code.as_deref(),
    ) {
        (Some(http), Some(grpc)) => format!(
            "<Matcher><HttpCode>{}</HttpCode><GrpcCode>{}</GrpcCode></Matcher>",
            xml_escape(http),
            xml_escape(grpc)
        ),
        (Some(http), None) => {
            format!(
                "<Matcher><HttpCode>{}</HttpCode></Matcher>",
                xml_escape(http)
            )
        }
        (None, Some(grpc)) => {
            format!(
                "<Matcher><GrpcCode>{}</GrpcCode></Matcher>",
                xml_escape(grpc)
            )
        }
        (None, None) => String::new(),
    };
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
                health: if crate::prober::probes_enabled() {
                    crate::state::TargetHealth::initial()
                } else {
                    crate::state::TargetHealth::default()
                },
                consecutive_success: 0,
                consecutive_failure: 0,
                last_probe_at: None,
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

fn render_attributes_xml(attrs: &BTreeMap<String, String>) -> String {
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

fn default_target_group_attributes() -> BTreeMap<String, String> {
    let mut m = BTreeMap::new();
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
    use std::collections::HashMap;

    fn req(action: &str, params: &[(&str, &str)]) -> AwsRequest {
        let mut q = std::collections::HashMap::new();
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
            body_stream: parking_lot::Mutex::new(None),
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
        // Use a name that is not in the AWS Smithy model so this test
        // remains stable as new ops are implemented.
        let err = svc
            .handle(req("ThisActionDoesNotExist", &[]))
            .await
            .err()
            .expect("expected error");
        assert!(matches!(err, AwsServiceError::ActionNotImplemented { .. }));
    }
}
