//! Shared helpers for AWS Query protocol services (SQS, SNS, ElastiCache, RDS, SES v1, IAM).

use std::collections::HashMap;

use http::StatusCode;

use crate::service::{AwsRequest, AwsServiceError};

/// Wrap an action result in the standard AWS Query protocol XML envelope.
///
/// Produces the canonical response shape:
/// ```xml
/// <?xml version="1.0" encoding="UTF-8"?>
/// <{Action}Response xmlns="{namespace}">
///   <{Action}Result>{inner}</{Action}Result>
///   <ResponseMetadata><RequestId>{request_id}</RequestId></ResponseMetadata>
/// </{Action}Response>
/// ```
pub fn query_response_xml(action: &str, namespace: &str, inner: &str, request_id: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <{action}Response xmlns=\"{namespace}\">\
         <{action}Result>{inner}</{action}Result>\
         <ResponseMetadata><RequestId>{request_id}</RequestId></ResponseMetadata>\
         </{action}Response>"
    )
}

/// Produce a Query protocol XML response with only metadata (no result body).
pub fn query_metadata_only_xml(action: &str, namespace: &str, request_id: &str) -> String {
    format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
         <{action}Response xmlns=\"{namespace}\">\
         <ResponseMetadata><RequestId>{request_id}</RequestId></ResponseMetadata>\
         </{action}Response>"
    )
}

/// Extract an optional parameter from a query parameter map.
///
/// Returns `None` if the parameter is missing or empty.
pub fn optional_param(params: &HashMap<String, String>, name: &str) -> Option<String> {
    params.get(name).cloned().filter(|value| !value.is_empty())
}

/// Extract a required parameter from a query parameter map.
///
/// Returns `MissingParameter` error if the parameter is missing or empty.
pub fn required_param(
    params: &HashMap<String, String>,
    name: &str,
) -> Result<String, AwsServiceError> {
    optional_param(params, name).ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "MissingParameter",
            format!("The request must contain the parameter {name}."),
        )
    })
}

/// Extract an optional query parameter from an `AwsRequest`.
pub fn optional_query_param(req: &AwsRequest, name: &str) -> Option<String> {
    optional_param(&req.query_params, name)
}

/// Extract a required query parameter from an `AwsRequest`.
pub fn required_query_param(req: &AwsRequest, name: &str) -> Result<String, AwsServiceError> {
    required_param(&req.query_params, name)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::HeaderMap;
    use std::collections::HashMap;

    fn make_req(params: &[(&str, &str)]) -> AwsRequest {
        let mut query_params = HashMap::new();
        for (k, v) in params {
            query_params.insert((*k).to_string(), (*v).to_string());
        }
        AwsRequest {
            service: "x".to_string(),
            action: "A".to_string(),
            region: "us-east-1".to_string(),
            account_id: "123".to_string(),
            request_id: "r".to_string(),
            headers: HeaderMap::new(),
            query_params,
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

    #[test]
    fn query_response_xml_format() {
        let xml = query_response_xml("Foo", "http://example.com/", "<Bar/>", "req-1");
        assert!(xml.contains("<FooResponse"));
        assert!(xml.contains("<FooResult><Bar/></FooResult>"));
        assert!(xml.contains("<RequestId>req-1</RequestId>"));
    }

    #[test]
    fn query_metadata_only_xml_omits_result() {
        let xml = query_metadata_only_xml("Foo", "http://example.com/", "req-1");
        assert!(xml.contains("<FooResponse"));
        assert!(!xml.contains("<FooResult"));
        assert!(xml.contains("<RequestId>req-1</RequestId>"));
    }

    #[test]
    fn optional_query_param_returns_value() {
        let req = make_req(&[("key", "value")]);
        assert_eq!(optional_query_param(&req, "key").as_deref(), Some("value"));
    }

    #[test]
    fn optional_query_param_missing_returns_none() {
        let req = make_req(&[]);
        assert!(optional_query_param(&req, "key").is_none());
    }

    #[test]
    fn optional_query_param_empty_returns_none() {
        let req = make_req(&[("key", "")]);
        assert!(optional_query_param(&req, "key").is_none());
    }

    #[test]
    fn required_query_param_returns_value() {
        let req = make_req(&[("k", "v")]);
        assert_eq!(required_query_param(&req, "k").unwrap(), "v");
    }

    #[test]
    fn required_query_param_missing_errors() {
        let req = make_req(&[]);
        assert!(required_query_param(&req, "k").is_err());
    }
}
