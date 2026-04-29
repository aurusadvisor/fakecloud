// CloudFront ConnectionFunction data types. Connection Functions are
// edge functions that run on the connection-handling path (different
// from regular CloudFront Functions which run on viewer requests).
// Same lifecycle as Functions: create -> publish -> attached to
// distributions.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredConnectionFunction {
    pub id: String,
    pub name: String,
    pub arn: String,
    pub stage: String,
    pub status: String,
    pub runtime: String,
    pub comment: String,
    pub code: Vec<u8>,
    pub etag: String,
    pub created_time: DateTime<Utc>,
    pub last_modified_time: DateTime<Utc>,
}
