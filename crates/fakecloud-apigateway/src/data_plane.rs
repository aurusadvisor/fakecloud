//! Execute API (data plane) handler for API Gateway v1.
//!
//! Incoming unsigned HTTP requests that didn't match a control-plane
//! REST route land here. The first path segment is treated as the
//! stage name; the rest is matched against the resource tree of any
//! REST API that has the stage deployed. The matching method's
//! integration is then invoked.
//!
//! Resource matching uses AWS's path-parameter syntax: `{var}` matches
//! a single segment, `{var+}` greedily matches the rest of the path.
//! Method matching is exact (`POST`, `GET`, …) — `ANY` is not a v1
//! concept (that's API Gateway v2). Methods configured for `OPTIONS`
//! handle CORS preflights.

use http::{Method, StatusCode};
use serde_json::json;
use std::collections::HashMap;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::lambda_proxy;
use crate::service::ApiGatewayService;
use crate::state::Integration;

/// Resolved data-plane match: which API hosts this request, the
/// integration to invoke, the path-parameter bindings, the resource
/// path the integration was registered against, and any stage
/// variables.
struct DataPlaneMatch {
    api_id: String,
    integration: Integration,
    path_params: HashMap<String, String>,
    resource_path: String,
    stage_vars: HashMap<String, String>,
}

pub async fn handle(
    service: &ApiGatewayService,
    req: &AwsRequest,
) -> Result<AwsResponse, AwsServiceError> {
    if req.path_segments.is_empty() {
        return Err(not_found(format!(
            "No matching API for path {}",
            req.raw_path
        )));
    }
    let stage_name = req.path_segments[0].clone();
    let remaining: Vec<String> = req.path_segments[1..].to_vec();

    // Find the API/stage pair that owns this request.
    let DataPlaneMatch {
        api_id,
        integration,
        path_params,
        resource_path,
        stage_vars,
    } = {
        let accounts = service.state_handle().read();
        let state = match accounts.get(&req.account_id) {
            Some(s) => s,
            None => {
                return Err(not_found(format!(
                    "No matching API for path {}",
                    req.raw_path
                )))
            }
        };
        let mut found: Option<DataPlaneMatch> = None;
        for (api_id, api_stages) in &state.stages {
            let Some(_stage) = api_stages.get(&stage_name) else {
                continue;
            };
            let resources = match state.resources.get(api_id) {
                Some(r) => r,
                None => continue,
            };
            for resource in resources.values() {
                if let Some(params) = match_resource_path(&resource.path, &remaining) {
                    let key = format!(
                        "{api_id}/{}/{}",
                        resource.id,
                        req.method.as_str().to_uppercase()
                    );
                    if let Some(integration) = state.integrations.get(&key).cloned() {
                        let stage_vars = api_stages
                            .get(&stage_name)
                            .map(|s| s.variables.clone())
                            .unwrap_or_default();
                        found = Some(DataPlaneMatch {
                            api_id: api_id.clone(),
                            integration,
                            path_params: params,
                            resource_path: resource.path.clone(),
                            stage_vars,
                        });
                        break;
                    }
                }
            }
            if found.is_some() {
                break;
            }
        }
        match found {
            Some(x) => x,
            None => {
                return Err(not_found(format!(
                    "No matching API for path {}",
                    req.raw_path
                )))
            }
        }
    };

    // Record for introspection.
    service.record_request(&req.account_id, &api_id, &stage_name, req, StatusCode::OK);

    match integration.integration_type.as_str() {
        "AWS_PROXY" => {
            let function_arn = match integration.uri.as_deref() {
                Some(uri) => extract_lambda_arn(uri).ok_or_else(|| {
                    bad_gateway("AWS_PROXY integration uri must reference a Lambda function ARN")
                })?,
                None => {
                    return Err(bad_gateway("AWS_PROXY integration missing uri"));
                }
            };
            let event = lambda_proxy::construct_event(
                req,
                &api_id,
                &stage_name,
                &resource_path,
                path_params,
                stage_vars,
            );
            let delivery = service
                .delivery()
                .ok_or_else(|| bad_gateway("Lambda delivery not configured"))?;
            lambda_proxy::invoke_lambda(delivery, &function_arn, event).await
        }
        "HTTP_PROXY" | "HTTP" => http_proxy(req, &integration).await,
        "MOCK" => Ok(AwsResponse::ok_json(json!({}))),
        other => Err(bad_gateway(format!(
            "Integration type '{other}' not supported in fakecloud's data plane",
        ))),
    }
}

fn not_found(msg: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(StatusCode::NOT_FOUND, "NotFoundException", msg.into())
}

fn bad_gateway(msg: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(StatusCode::BAD_GATEWAY, "BadGatewayException", msg.into())
}

/// Match `template` (e.g. `/items/{id}/parts`) against `path_segments`
/// (e.g. `["items", "42", "parts"]`). Returns the path-parameter map on
/// match, or `None` if the path doesn't fit the template.
fn match_resource_path(
    template: &str,
    path_segments: &[String],
) -> Option<HashMap<String, String>> {
    // Root resource: only an empty (or missing) remaining path matches.
    if template == "/" {
        return if path_segments.is_empty() {
            Some(HashMap::new())
        } else {
            None
        };
    }
    let template_segments: Vec<&str> = template.split('/').filter(|s| !s.is_empty()).collect();
    let mut params = HashMap::new();
    let mut t = 0;
    let mut p = 0;
    while t < template_segments.len() {
        let seg = template_segments[t];
        if seg.starts_with('{') && seg.ends_with('}') {
            let inner = seg.trim_start_matches('{').trim_end_matches('}');
            if let Some(name) = inner.strip_suffix('+') {
                // Greedy match — consume the remainder.
                if p >= path_segments.len() {
                    return None;
                }
                params.insert(name.to_string(), path_segments[p..].join("/"));
                return Some(params);
            }
            if p >= path_segments.len() {
                return None;
            }
            params.insert(inner.to_string(), path_segments[p].clone());
            p += 1;
        } else {
            if p >= path_segments.len() || path_segments[p] != seg {
                return None;
            }
            p += 1;
        }
        t += 1;
    }
    if p == path_segments.len() {
        Some(params)
    } else {
        None
    }
}

/// Pull the function ARN out of an AWS_PROXY integration URI of the
/// shape `arn:aws:apigateway:<region>:lambda:path/<api-version>/functions/<arn>/invocations`.
fn extract_lambda_arn(uri: &str) -> Option<String> {
    if !uri.contains(":lambda:path/") {
        return None;
    }
    let prefix = uri.split("/functions/").nth(1)?;
    let arn = prefix.trim_end_matches("/invocations");
    Some(arn.to_string())
}

async fn http_proxy(
    req: &AwsRequest,
    integration: &Integration,
) -> Result<AwsResponse, AwsServiceError> {
    let url = integration
        .uri
        .as_ref()
        .ok_or_else(|| bad_gateway("HTTP integration missing uri"))?;
    let method = match req.method {
        Method::GET => reqwest::Method::GET,
        Method::POST => reqwest::Method::POST,
        Method::PUT => reqwest::Method::PUT,
        Method::DELETE => reqwest::Method::DELETE,
        Method::PATCH => reqwest::Method::PATCH,
        Method::HEAD => reqwest::Method::HEAD,
        Method::OPTIONS => reqwest::Method::OPTIONS,
        _ => reqwest::Method::GET,
    };
    let client = reqwest::Client::new();
    let mut builder = client.request(method, url);
    for (k, v) in req.headers.iter() {
        if let Ok(s) = v.to_str() {
            builder = builder.header(k.as_str(), s);
        }
    }
    if !req.body.is_empty() {
        builder = builder.body(req.body.clone().to_vec());
    }
    let resp = builder
        .send()
        .await
        .map_err(|e| bad_gateway(format!("backend HTTP failure: {e}")))?;
    let status = StatusCode::from_u16(resp.status().as_u16()).unwrap_or(StatusCode::BAD_GATEWAY);
    let mut headers = http::HeaderMap::new();
    for (k, v) in resp.headers().iter() {
        if let (Ok(name), Ok(val)) = (
            http::HeaderName::from_bytes(k.as_str().as_bytes()),
            http::HeaderValue::from_bytes(v.as_bytes()),
        ) {
            headers.insert(name, val);
        }
    }
    let content_type = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let body = resp
        .bytes()
        .await
        .map_err(|e| bad_gateway(format!("backend body read failure: {e}")))?;
    Ok(AwsResponse {
        status,
        content_type,
        headers,
        body: bytes::Bytes::from(body.to_vec()).into(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn match_root_only_for_empty_path() {
        assert!(match_resource_path("/", &[]).is_some());
        assert!(match_resource_path("/", &["x".to_string()]).is_none());
    }

    #[test]
    fn match_exact_segments() {
        let r = match_resource_path("/items", &["items".to_string()]).unwrap();
        assert!(r.is_empty());
        assert!(match_resource_path("/items", &["items".to_string(), "x".to_string()]).is_none());
        assert!(match_resource_path("/items", &["other".to_string()]).is_none());
    }

    #[test]
    fn match_param_segment() {
        let r =
            match_resource_path("/items/{id}", &["items".to_string(), "42".to_string()]).unwrap();
        assert_eq!(r.get("id"), Some(&"42".to_string()));
    }

    #[test]
    fn match_greedy_segment() {
        let r = match_resource_path(
            "/proxy/{path+}",
            &[
                "proxy".to_string(),
                "a".to_string(),
                "b".to_string(),
                "c".to_string(),
            ],
        )
        .unwrap();
        assert_eq!(r.get("path"), Some(&"a/b/c".to_string()));
    }

    #[test]
    fn extract_lambda_arn_from_uri() {
        let uri = "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/arn:aws:lambda:us-east-1:000000000000:function:my-fn/invocations";
        assert_eq!(
            extract_lambda_arn(uri),
            Some("arn:aws:lambda:us-east-1:000000000000:function:my-fn".to_string())
        );
    }
}
