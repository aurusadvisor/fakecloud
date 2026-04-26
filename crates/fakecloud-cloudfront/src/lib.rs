//! AWS CloudFront emulation for FakeCloud.
//!
//! Wire protocol: REST-XML. Requests are routed by HTTP method + URI
//! beneath the `/2020-05-31/` API version prefix. SigV4 service name is
//! `cloudfront`; the service is global so callers always sign for
//! `us-east-1`.

pub mod model;
pub mod router;
pub mod service;
pub mod state;
pub mod xml_io;

pub use service::CloudFrontService;
pub use state::{CloudFrontAccounts, SharedCloudFrontState};

pub const API_VERSION: &str = "2020-05-31";
pub const API_PREFIX: &str = "/2020-05-31";
pub const NAMESPACE: &str = "http://cloudfront.amazonaws.com/doc/2020-05-31/";
