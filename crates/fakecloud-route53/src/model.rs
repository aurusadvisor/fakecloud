//! Data types for Route 53 hosted zones and resource record sets.

use serde::{Deserialize, Serialize};

fn skip_if_none<T>(x: &Option<T>) -> bool {
    x.is_none()
}

// ─── CreateHostedZone ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CreateHostedZoneRequest {
    pub name: String,
    pub caller_reference: String,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub hosted_zone_config: Option<HostedZoneConfig>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub vpc: Option<VPC>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub delegation_set_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct HostedZoneConfig {
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub comment: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub private_zone: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct VPC {
    #[serde(default, skip_serializing_if = "skip_if_none", rename = "VPCId")]
    pub vpc_id: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none", rename = "VPCRegion")]
    pub vpc_region: Option<String>,
}

// ─── UpdateHostedZoneComment ─────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateHostedZoneCommentRequest {
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub comment: Option<String>,
}

// ─── UpdateHostedZoneFeatures ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateHostedZoneFeaturesRequest {
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub enable_accelerated_recovery: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct HostedZoneFeatures {
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub enable_accelerated_recovery: Option<bool>,
}

// ─── ChangeResourceRecordSets ────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ChangeResourceRecordSetsRequest {
    pub change_batch: ChangeBatch,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ChangeBatch {
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub comment: Option<String>,
    pub changes: ChangeList,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ChangeList {
    #[serde(default, rename = "Change")]
    pub change: Vec<Change>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct Change {
    pub action: String,
    pub resource_record_set: ResourceRecordSet,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ResourceRecordSet {
    pub name: String,
    #[serde(rename = "Type")]
    pub record_type: String,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub set_identifier: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub weight: Option<i64>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub region: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub geo_location: Option<GeoLocation>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub failover: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub multi_value_answer: Option<bool>,
    #[serde(default, skip_serializing_if = "skip_if_none", rename = "TTL")]
    pub ttl: Option<i64>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub resource_records: Option<ResourceRecords>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub alias_target: Option<AliasTarget>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub health_check_id: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub traffic_policy_instance_id: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub cidr_routing_config: Option<CidrRoutingConfig>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub geo_proximity_location: Option<GeoProximityLocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ResourceRecords {
    #[serde(default, rename = "ResourceRecord")]
    pub resource_record: Vec<ResourceRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ResourceRecord {
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct AliasTarget {
    pub hosted_zone_id: String,
    #[serde(rename = "DNSName")]
    pub dns_name: String,
    pub evaluate_target_health: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct GeoLocation {
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub continent_code: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub country_code: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub subdivision_code: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct CidrRoutingConfig {
    pub collection_id: String,
    pub location_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct GeoProximityLocation {
    #[serde(default, skip_serializing_if = "skip_if_none", rename = "AWSRegion")]
    pub aws_region: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub local_zone_group: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub coordinates: Option<Coordinates>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub bias: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct Coordinates {
    pub latitude: String,
    pub longitude: String,
}
