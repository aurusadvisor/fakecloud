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

// ─── Health Checks ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CreateHealthCheckRequest {
    pub caller_reference: String,
    pub health_check_config: HealthCheckConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct HealthCheckConfig {
    #[serde(default, skip_serializing_if = "skip_if_none", rename = "IPAddress")]
    pub ip_address: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub port: Option<i32>,
    #[serde(rename = "Type")]
    pub health_check_type: String,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub resource_path: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub fully_qualified_domain_name: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub search_string: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub request_interval: Option<i32>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub failure_threshold: Option<i32>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub measure_latency: Option<bool>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub inverted: Option<bool>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub disabled: Option<bool>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub health_threshold: Option<i32>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub child_health_checks: Option<ChildHealthChecks>,
    #[serde(default, skip_serializing_if = "skip_if_none", rename = "EnableSNI")]
    pub enable_sni: Option<bool>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub regions: Option<HealthCheckRegions>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub alarm_identifier: Option<AlarmIdentifier>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub insufficient_data_health_status: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub routing_control_arn: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct ChildHealthChecks {
    #[serde(default, rename = "ChildHealthCheck")]
    pub child_health_check: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct HealthCheckRegions {
    #[serde(default, rename = "Region")]
    pub region: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "PascalCase")]
pub struct AlarmIdentifier {
    pub region: String,
    pub name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateHealthCheckRequest {
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub health_check_version: Option<i64>,
    #[serde(default, skip_serializing_if = "skip_if_none", rename = "IPAddress")]
    pub ip_address: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub port: Option<i32>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub resource_path: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub fully_qualified_domain_name: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub search_string: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub failure_threshold: Option<i32>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub inverted: Option<bool>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub disabled: Option<bool>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub health_threshold: Option<i32>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub child_health_checks: Option<ChildHealthChecks>,
    #[serde(default, skip_serializing_if = "skip_if_none", rename = "EnableSNI")]
    pub enable_sni: Option<bool>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub regions: Option<HealthCheckRegions>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub alarm_identifier: Option<AlarmIdentifier>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub insufficient_data_health_status: Option<String>,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub reset_elements: Option<ResetElements>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ResetElements {
    #[serde(default, rename = "ResettableElementName")]
    pub resettable_element_name: Vec<String>,
}

// ─── Traffic Policies ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CreateTrafficPolicyRequest {
    pub name: String,
    pub document: String,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CreateTrafficPolicyVersionRequest {
    pub document: String,
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub comment: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateTrafficPolicyCommentRequest {
    pub comment: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CreateTrafficPolicyInstanceRequest {
    pub hosted_zone_id: String,
    pub name: String,
    #[serde(rename = "TTL")]
    pub ttl: i64,
    pub traffic_policy_id: String,
    pub traffic_policy_version: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct UpdateTrafficPolicyInstanceRequest {
    #[serde(rename = "TTL")]
    pub ttl: i64,
    pub traffic_policy_id: String,
    pub traffic_policy_version: i64,
}

// ─── DNSSEC + KSK ────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CreateKeySigningKeyRequest {
    pub caller_reference: String,
    pub hosted_zone_id: String,
    pub key_management_service_arn: String,
    pub name: String,
    pub status: String,
}

// ─── Query Logging ───────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CreateQueryLoggingConfigRequest {
    pub hosted_zone_id: String,
    #[serde(rename = "CloudWatchLogsLogGroupArn")]
    pub cloud_watch_logs_log_group_arn: String,
}

// ─── CIDR Collections ────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CreateCidrCollectionRequest {
    pub name: String,
    pub caller_reference: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct ChangeCidrCollectionRequest {
    #[serde(default, skip_serializing_if = "skip_if_none")]
    pub collection_version: Option<i64>,
    pub changes: CidrCollectionChanges,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CidrCollectionChanges {
    // The Smithy `CidrCollectionChanges` list has no `xmlName` trait on
    // its member, so the on-wire element name is the restXml default:
    // `<member>`, not `<CidrCollectionChange>`. The Rust SDK does send
    // `<member>` — verified against `cidr_collection_lifecycle` E2E.
    #[serde(default, rename = "member")]
    pub change: Vec<CidrCollectionChange>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CidrCollectionChange {
    pub location_name: String,
    pub action: String,
    pub cidr_list: CidrList,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "PascalCase")]
pub struct CidrList {
    #[serde(default, rename = "Cidr")]
    pub cidr: Vec<String>,
}
