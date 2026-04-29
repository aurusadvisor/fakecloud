// CloudFront DistributionTenant data types — multi-tenant distribution
// service that lets callers carve a base distribution into per-tenant
// configurations (custom domains, certs, parameter overrides). Wire
// protocol mirrors the parent Distribution: REST-XML with ETag-based
// concurrency control.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredDistributionTenant {
    pub id: String,
    pub arn: String,
    pub name: String,
    pub distribution_id: String,
    pub domains: Vec<String>,
    pub connection_group_id: Option<String>,
    pub web_acl_arn: Option<String>,
    pub enabled: bool,
    pub status: String,
    pub etag: String,
    pub created_time: DateTime<Utc>,
    pub last_modified_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredTenantInvalidation {
    pub id: String,
    pub tenant_id: String,
    pub status: String,
    pub create_time: DateTime<Utc>,
    pub paths: Vec<String>,
    pub caller_reference: String,
}
