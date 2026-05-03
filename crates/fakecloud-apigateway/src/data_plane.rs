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
//! Method matching tries the exact verb first (`POST`, `GET`, …); if no
//! method-specific integration is configured, falls back to `ANY`
//! (registered via `x-amazon-apigateway-any-method`), matching real
//! REST API behavior. Methods configured for `OPTIONS` handle CORS
//! preflights.

use http::{Method, StatusCode};
use serde_json::json;
use std::collections::BTreeMap;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::lambda_proxy;
use crate::service::ApiGatewayService;
use crate::state::{AuthEffect, Authorizer, CachedAuthorizerResult, Integration};

/// Default `authorizerResultTtlInSeconds` per AWS docs.
const DEFAULT_AUTHORIZER_TTL_SECS: i64 = 300;

/// Resolved data-plane match: which API hosts this request, the
/// integration to invoke, the path-parameter bindings, the resource
/// path the integration was registered against, the stage variables,
/// and the method-level auth config (type + optional authorizer).
struct DataPlaneMatch {
    api_id: String,
    integration: Integration,
    path_params: BTreeMap<String, String>,
    resource_path: String,
    stage_vars: BTreeMap<String, String>,
    authorization_type: String,
    authorizer: Option<Authorizer>,
}

/// Outcome of authorizer evaluation. `claims`/`context` are merged into
/// `requestContext.authorizer` of the proxy event when present.
struct AuthorizerOutcome {
    principal_id: String,
    context: serde_json::Value,
    claims: Option<serde_json::Value>,
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
        authorization_type,
        authorizer,
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
                    let exact_key = format!(
                        "{api_id}/{}/{}",
                        resource.id,
                        req.method.as_str().to_uppercase()
                    );
                    let any_key = format!("{api_id}/{}/ANY", resource.id);
                    let (integration_opt, method_lookup_key) = match (
                        state.integrations.get(&exact_key),
                        state.integrations.get(&any_key),
                    ) {
                        (Some(i), _) => (Some(i.clone()), exact_key.clone()),
                        (None, Some(i)) => (Some(i.clone()), any_key.clone()),
                        (None, None) => (None, exact_key.clone()),
                    };
                    if let Some(integration) = integration_opt {
                        // Look up the matching method record so we can
                        // pick up its authorizer config. Fall back to
                        // ANY when no method-specific record exists, so
                        // catch-all routes still get authorized.
                        let method_record = state
                            .methods
                            .get(&method_lookup_key)
                            .or_else(|| state.methods.get(&any_key))
                            .cloned();
                        let authorization_type = method_record
                            .as_ref()
                            .map(|m| m.authorization_type.clone())
                            .unwrap_or_else(|| "NONE".to_string());
                        let authorizer = method_record
                            .as_ref()
                            .and_then(|m| m.authorizer_id.clone())
                            .and_then(|aid| {
                                state
                                    .authorizers
                                    .get(api_id)
                                    .and_then(|m| m.get(&aid))
                                    .cloned()
                            });
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
                            authorization_type,
                            authorizer,
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

    // Run the authorizer (when configured) before touching the
    // integration. AWS rejects with 401/403 here without ever invoking
    // the backend; mirror that semantics so caching and observability
    // in tests reflect a real auth failure rather than a bad upstream.
    let auth_outcome = match enforce_authorizer(
        service,
        req,
        &api_id,
        &stage_name,
        &resource_path,
        &authorization_type,
        authorizer.as_ref(),
    )
    .await
    {
        Ok(out) => out,
        Err(err) => {
            service.record_request(&req.account_id, &api_id, &stage_name, req, err.status());
            return Err(err);
        }
    };

    let result: Result<AwsResponse, AwsServiceError> = match integration.integration_type.as_str() {
        "AWS_PROXY" => {
            let function_arn = match integration.uri.as_deref() {
                Some(uri) => extract_lambda_arn(uri).ok_or_else(|| {
                    bad_gateway("AWS_PROXY integration uri must reference a Lambda function ARN")
                })?,
                None => {
                    return Err(bad_gateway("AWS_PROXY integration missing uri"));
                }
            };
            let mut event = lambda_proxy::construct_event(
                req,
                &api_id,
                &stage_name,
                &resource_path,
                path_params,
                stage_vars,
            );
            if let Some(out) = &auth_outcome {
                inject_authorizer_into_event(&mut event, out);
            }
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
    };

    // Record after the integration runs so introspection sees the real
    // outcome (e.g. 502 from a failed Lambda invoke or HTTP backend).
    let recorded_status = match &result {
        Ok(r) => r.status,
        Err(e) => e.status(),
    };
    service.record_request(&req.account_id, &api_id, &stage_name, req, recorded_status);

    result
}

fn not_found(msg: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(StatusCode::NOT_FOUND, "NotFoundException", msg.into())
}

fn bad_gateway(msg: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(StatusCode::BAD_GATEWAY, "BadGatewayException", msg.into())
}

fn unauthorized(msg: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::UNAUTHORIZED,
        "UnauthorizedException",
        msg.into(),
    )
}

fn forbidden(msg: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(StatusCode::FORBIDDEN, "AccessDeniedException", msg.into())
}

/// Resolve the header name an authorizer's `identitySource` points at.
/// AWS uses `method.request.header.<Name>` (e.g.
/// `method.request.header.Authorization`). Bare names also work for
/// callers that store just `Authorization`. Defaults to `Authorization`
/// when nothing was configured.
fn header_name_from_identity_source(source: Option<&str>) -> String {
    let raw = source.unwrap_or("Authorization").trim();
    // `identitySource` may contain comma-separated entries; use the
    // first one (matches AWS's behaviour for primary-key caching).
    let first = raw.split(',').next().unwrap_or(raw).trim();
    if let Some(stripped) = first.strip_prefix("method.request.header.") {
        stripped.to_string()
    } else if first.is_empty() {
        "Authorization".to_string()
    } else {
        first.to_string()
    }
}

fn extract_header_value(req: &AwsRequest, header_name: &str) -> Option<String> {
    req.headers
        .get(header_name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

/// Strip an optional `Bearer ` prefix from a TOKEN-authorizer header
/// value before forwarding the raw token to the Lambda. AWS leaves the
/// prefix in place, but Lambdas commonly receive it stripped too;
/// preserve verbatim to match real behaviour.
fn raw_token(value: &str) -> &str {
    value
}

async fn enforce_authorizer(
    service: &ApiGatewayService,
    req: &AwsRequest,
    api_id: &str,
    stage: &str,
    resource_path: &str,
    authorization_type: &str,
    authorizer: Option<&Authorizer>,
) -> Result<Option<AuthorizerOutcome>, AwsServiceError> {
    match authorization_type {
        // Methods that haven't opted into authorization pass through.
        // `AWS_IAM` is treated as "no method-level authorizer" here —
        // SigV4 enforcement is handled upstream by the request signer.
        "" | "NONE" | "AWS_IAM" => Ok(None),
        "CUSTOM" | "TOKEN" | "REQUEST" => {
            let authorizer = authorizer.ok_or_else(|| {
                forbidden("Method requires a custom authorizer but none is configured")
            })?;
            run_lambda_authorizer(service, req, api_id, stage, resource_path, authorizer).await
        }
        "COGNITO_USER_POOLS" => {
            let authorizer = authorizer.ok_or_else(|| {
                forbidden("Method requires Cognito authorization but no authorizer is attached")
            })?;
            run_cognito_authorizer(service, req, authorizer).await
        }
        other => Err(forbidden(format!(
            "Unsupported authorizationType '{other}'"
        ))),
    }
}

/// Invoke a TOKEN/REQUEST authorizer Lambda and translate its policy
/// into an Allow/Deny outcome. Caches successful evaluations by
/// `<authorizerId>|<token>` for `authorizerResultTtlInSeconds`.
async fn run_lambda_authorizer(
    service: &ApiGatewayService,
    req: &AwsRequest,
    api_id: &str,
    stage: &str,
    resource_path: &str,
    authorizer: &Authorizer,
) -> Result<Option<AuthorizerOutcome>, AwsServiceError> {
    // For TOKEN authorizers AWS treats the value of the configured
    // identity-source header as the cache key. For REQUEST authorizers
    // the cache key concatenates all configured sources; we keep the
    // simpler one-header model here because that's what real-world
    // configurations use 95% of the time.
    let header_name = header_name_from_identity_source(authorizer.identity_source.as_deref());
    let token_value = extract_header_value(req, &header_name).ok_or_else(|| {
        unauthorized(format!(
            "Missing required identity source header '{header_name}'"
        ))
    })?;
    if token_value.trim().is_empty() {
        return Err(unauthorized(format!(
            "Empty identity source header '{header_name}'"
        )));
    }

    let cache_key = format!("{}|{}", authorizer.id, token_value);
    if let Some(cached) = lookup_cached_auth(service, &req.account_id, &cache_key) {
        return interpret_cached(cached);
    }

    let auth_uri = authorizer
        .authorizer_uri
        .as_deref()
        .ok_or_else(|| bad_gateway("Authorizer is missing authorizerUri; cannot invoke Lambda"))?;
    let function_arn = extract_lambda_arn(auth_uri)
        .ok_or_else(|| bad_gateway("authorizerUri must reference a Lambda function ARN"))?;
    let method_arn = build_method_arn(req, api_id, stage, resource_path);

    let event = match authorizer.authorizer_type.as_str() {
        "TOKEN" => {
            json!({
                "type": "TOKEN",
                "methodArn": method_arn,
                "authorizationToken": raw_token(&token_value),
            })
        }
        // Default to REQUEST shape for any non-TOKEN Lambda authorizer.
        _ => {
            let mut headers = serde_json::Map::new();
            for (k, v) in req.headers.iter() {
                if let Ok(s) = v.to_str() {
                    headers.insert(
                        k.as_str().to_string(),
                        serde_json::Value::String(s.to_string()),
                    );
                }
            }
            let mut query = serde_json::Map::new();
            for (k, v) in &req.query_params {
                query.insert(k.clone(), serde_json::Value::String(v.clone()));
            }
            json!({
                "type": "REQUEST",
                "methodArn": method_arn,
                "resource": resource_path,
                "path": req.raw_path,
                "httpMethod": req.method.as_str(),
                "headers": headers,
                "queryStringParameters": query,
                "requestContext": {
                    "apiId": api_id,
                    "stage": stage,
                    "path": req.raw_path,
                    "httpMethod": req.method.as_str(),
                },
            })
        }
    };

    let delivery = service
        .delivery()
        .ok_or_else(|| bad_gateway("Lambda delivery not configured"))?;
    let response_bytes = delivery
        .invoke_lambda(&function_arn, &event.to_string())
        .await
        .ok_or_else(|| bad_gateway("Lambda delivery not configured"))?
        .map_err(|e| forbidden(format!("Authorizer Lambda failed: {e}")))?;
    let response: serde_json::Value = serde_json::from_slice(&response_bytes)
        .map_err(|e| forbidden(format!("Authorizer returned invalid JSON: {e}")))?;

    let principal_id = response
        .get("principalId")
        .and_then(|v| v.as_str())
        .unwrap_or("user")
        .to_string();
    let context = response
        .get("context")
        .cloned()
        .unwrap_or_else(|| serde_json::Value::Object(serde_json::Map::new()));
    let effect = parse_policy_effect(&response, &method_arn);

    let ttl = authorizer
        .authorizer_result_ttl_in_seconds
        .map(|v| v as i64)
        .unwrap_or(DEFAULT_AUTHORIZER_TTL_SECS);
    cache_auth_result(
        service,
        &req.account_id,
        cache_key,
        CachedAuthorizerResult {
            principal_id: principal_id.clone(),
            effect,
            context: context.clone(),
            claims: None,
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(ttl),
        },
    );

    match effect {
        AuthEffect::Allow => Ok(Some(AuthorizerOutcome {
            principal_id,
            context,
            claims: None,
        })),
        AuthEffect::Deny => Err(forbidden("User is not authorized to access this resource")),
    }
}

/// Walk `policyDocument.Statement` and resolve to a single Allow/Deny
/// effect. Multiple matching Allow statements collapse to Allow; any
/// Deny short-circuits to Deny (mirroring the IAM policy combinator).
fn parse_policy_effect(response: &serde_json::Value, method_arn: &str) -> AuthEffect {
    let Some(stmts) = response
        .get("policyDocument")
        .and_then(|p| p.get("Statement"))
        .and_then(|s| s.as_array())
    else {
        return AuthEffect::Deny;
    };
    let mut allow = false;
    for stmt in stmts {
        let effect = stmt.get("Effect").and_then(|v| v.as_str()).unwrap_or("");
        // Resource matching: explicit ARN match, wildcard `*`, or
        // missing Resource (treat as `*`).
        let matches = match stmt.get("Resource") {
            Some(serde_json::Value::String(s)) => arn_matches(s, method_arn),
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str())
                .any(|s| arn_matches(s, method_arn)),
            _ => true,
        };
        if !matches {
            continue;
        }
        match effect {
            "Deny" => return AuthEffect::Deny,
            "Allow" => allow = true,
            _ => {}
        }
    }
    if allow {
        AuthEffect::Allow
    } else {
        AuthEffect::Deny
    }
}

/// Glob-match a policy resource expression (`arn:...:*` etc) against a
/// concrete method ARN. `*` matches any sequence inside a single
/// segment; `?` matches a single character.
fn arn_matches(pattern: &str, target: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    let mut p_chars = pattern.chars().peekable();
    let mut t_chars = target.chars().peekable();
    loop {
        match (p_chars.peek().copied(), t_chars.peek().copied()) {
            (None, None) => return true,
            (None, Some(_)) => return false,
            (Some('*'), _) => {
                p_chars.next();
                if p_chars.peek().is_none() {
                    return true;
                }
                while t_chars.peek().is_some() {
                    if arn_matches(
                        &p_chars.clone().collect::<String>(),
                        &t_chars.clone().collect::<String>(),
                    ) {
                        return true;
                    }
                    t_chars.next();
                }
                return false;
            }
            (Some('?'), Some(_)) => {
                p_chars.next();
                t_chars.next();
            }
            (Some(a), Some(b)) if a == b => {
                p_chars.next();
                t_chars.next();
            }
            _ => return false,
        }
    }
}

fn build_method_arn(req: &AwsRequest, api_id: &str, stage: &str, resource_path: &str) -> String {
    let trimmed = resource_path.trim_start_matches('/');
    format!(
        "arn:aws:execute-api:{}:{}:{}/{}/{}/{}",
        req.region,
        req.account_id,
        api_id,
        stage,
        req.method.as_str().to_uppercase(),
        trimmed,
    )
}

async fn run_cognito_authorizer(
    service: &ApiGatewayService,
    req: &AwsRequest,
    authorizer: &Authorizer,
) -> Result<Option<AuthorizerOutcome>, AwsServiceError> {
    let header_name = header_name_from_identity_source(authorizer.identity_source.as_deref());
    let token_value = extract_header_value(req, &header_name)
        .ok_or_else(|| unauthorized(format!("Missing required JWT in header '{header_name}'")))?;
    let token = token_value
        .strip_prefix("Bearer ")
        .or_else(|| token_value.strip_prefix("bearer "))
        .unwrap_or(&token_value)
        .trim();
    if token.is_empty() {
        return Err(unauthorized("Empty Authorization header"));
    }

    let cache_key = format!("{}|{}", authorizer.id, token);
    if let Some(cached) = lookup_cached_auth(service, &req.account_id, &cache_key) {
        return interpret_cached(cached);
    }

    let pool_arn = authorizer
        .provider_arns
        .first()
        .ok_or_else(|| forbidden("Cognito authorizer has no providerARNs configured"))?;
    let delivery = service
        .delivery()
        .ok_or_else(|| unauthorized("Cognito JWT verifier not configured"))?;
    let claims = delivery
        .verify_cognito_jwt(&req.account_id, pool_arn, token)
        .map_err(|e| unauthorized(format!("Invalid JWT: {e}")))?;

    let principal_id = claims
        .get("sub")
        .and_then(|v| v.as_str())
        .unwrap_or("user")
        .to_string();
    let ttl = authorizer
        .authorizer_result_ttl_in_seconds
        .map(|v| v as i64)
        .unwrap_or(DEFAULT_AUTHORIZER_TTL_SECS);
    cache_auth_result(
        service,
        &req.account_id,
        cache_key,
        CachedAuthorizerResult {
            principal_id: principal_id.clone(),
            effect: AuthEffect::Allow,
            context: serde_json::Value::Object(serde_json::Map::new()),
            claims: Some(claims.clone()),
            expires_at: chrono::Utc::now() + chrono::Duration::seconds(ttl),
        },
    );

    Ok(Some(AuthorizerOutcome {
        principal_id,
        context: serde_json::Value::Object(serde_json::Map::new()),
        claims: Some(claims),
    }))
}

fn lookup_cached_auth(
    service: &ApiGatewayService,
    account_id: &str,
    key: &str,
) -> Option<CachedAuthorizerResult> {
    let now = chrono::Utc::now();
    let mut accounts = service.state_handle().write();
    let state = accounts.get_or_create(account_id);
    if let Some(cached) = state.authorizer_cache.get(key) {
        if cached.expires_at > now {
            return Some(cached.clone());
        }
    }
    state.authorizer_cache.remove(key);
    None
}

fn cache_auth_result(
    service: &ApiGatewayService,
    account_id: &str,
    key: String,
    entry: CachedAuthorizerResult,
) {
    let mut accounts = service.state_handle().write();
    let state = accounts.get_or_create(account_id);
    state.authorizer_cache.insert(key, entry);
}

fn interpret_cached(
    cached: CachedAuthorizerResult,
) -> Result<Option<AuthorizerOutcome>, AwsServiceError> {
    match cached.effect {
        AuthEffect::Allow => Ok(Some(AuthorizerOutcome {
            principal_id: cached.principal_id,
            context: cached.context,
            claims: cached.claims,
        })),
        AuthEffect::Deny => Err(forbidden("User is not authorized to access this resource")),
    }
}

fn inject_authorizer_into_event(event: &mut serde_json::Value, outcome: &AuthorizerOutcome) {
    let Some(req_ctx) = event
        .get_mut("requestContext")
        .and_then(|v| v.as_object_mut())
    else {
        return;
    };
    let mut auth_obj = serde_json::Map::new();
    auth_obj.insert(
        "principalId".to_string(),
        serde_json::Value::String(outcome.principal_id.clone()),
    );
    if let serde_json::Value::Object(ctx) = &outcome.context {
        for (k, v) in ctx {
            auth_obj.insert(k.clone(), v.clone());
        }
    }
    if let Some(claims) = &outcome.claims {
        auth_obj.insert("claims".to_string(), claims.clone());
    }
    req_ctx.insert(
        "authorizer".to_string(),
        serde_json::Value::Object(auth_obj),
    );
}

/// Match `template` (e.g. `/items/{id}/parts`) against `path_segments`
/// (e.g. `["items", "42", "parts"]`). Returns the path-parameter map on
/// match, or `None` if the path doesn't fit the template.
fn match_resource_path(
    template: &str,
    path_segments: &[String],
) -> Option<BTreeMap<String, String>> {
    // Root resource: only an empty (or missing) remaining path matches.
    if template == "/" {
        return if path_segments.is_empty() {
            Some(BTreeMap::new())
        } else {
            None
        };
    }
    let template_segments: Vec<&str> = template.split('/').filter(|s| !s.is_empty()).collect();
    let mut params = BTreeMap::new();
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
            // `append` preserves multi-value headers like multiple
            // `Set-Cookie` lines that the backend may emit.
            headers.append(name, val);
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
    use crate::state::{
        ApiGatewayState, Authorizer as StateAuthorizer, Integration as StateIntegration,
        Method as StateMethod, Resource as StateResource, RestApi, SharedApiGatewayState,
        Stage as StateStage,
    };
    use bytes::Bytes;
    use chrono::Utc;
    use fakecloud_core::delivery::{CognitoJwtVerifier, DeliveryBus, LambdaDelivery};
    use fakecloud_core::multi_account::MultiAccountState;
    use http::HeaderMap;
    use std::collections::HashMap;
    use std::pin::Pin;
    use std::sync::Arc;

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

    // ── data-plane authorizer enforcement tests ──

    const TEST_ACCOUNT: &str = "000000000000";
    const TEST_REGION: &str = "us-east-1";
    const TEST_API_ID: &str = "abc123";
    const RES_ID: &str = "items0001";
    const AUTH_ID: &str = "auth000001";
    const FN_ARN: &str = "arn:aws:lambda:us-east-1:000000000000:function:authorizer";
    const BACKEND_ARN: &str = "arn:aws:lambda:us-east-1:000000000000:function:backend";
    const COGNITO_ARN: &str = "arn:aws:cognito-idp:us-east-1:000000000000:userpool/us-east-1_pool1";

    /// Lambda stub that returns a fixed JSON response for authorizer
    /// invocations and a generic 200 proxy response for the backend.
    /// `expectations` records how many times each function was invoked.
    struct StubLambda {
        responses: parking_lot::Mutex<HashMap<String, Vec<u8>>>,
        invocations: parking_lot::Mutex<Vec<(String, String)>>,
    }

    impl StubLambda {
        fn new() -> Self {
            Self {
                responses: parking_lot::Mutex::new(HashMap::new()),
                invocations: parking_lot::Mutex::new(Vec::new()),
            }
        }

        fn set(&self, arn: &str, body: serde_json::Value) {
            self.responses
                .lock()
                .insert(arn.to_string(), body.to_string().into_bytes());
        }

        fn invocation_count(&self, arn: &str) -> usize {
            self.invocations
                .lock()
                .iter()
                .filter(|(a, _)| a == arn)
                .count()
        }

        fn last_payload(&self, arn: &str) -> Option<String> {
            self.invocations
                .lock()
                .iter()
                .rev()
                .find(|(a, _)| a == arn)
                .map(|(_, p)| p.clone())
        }
    }

    impl LambdaDelivery for StubLambda {
        fn invoke_lambda(
            &self,
            function_arn: &str,
            payload: &str,
        ) -> Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send>> {
            self.invocations
                .lock()
                .push((function_arn.to_string(), payload.to_string()));
            let resp = self
                .responses
                .lock()
                .get(function_arn)
                .cloned()
                .unwrap_or_else(|| {
                    serde_json::json!({"statusCode": 200, "body": "ok"})
                        .to_string()
                        .into_bytes()
                });
            Box::pin(async move { Ok(resp) })
        }
    }

    /// JWT verifier stub that returns a fixed claims object for valid
    /// tokens and a fixed error for invalid ones. Tests register the
    /// outcome explicitly so we don't need real RSA in unit tests.
    struct StubJwtVerifier {
        valid_token: String,
        claims: serde_json::Value,
    }

    impl CognitoJwtVerifier for StubJwtVerifier {
        fn verify_token(
            &self,
            _account_id: &str,
            _user_pool_arn: &str,
            token: &str,
        ) -> Result<serde_json::Value, String> {
            if token == self.valid_token {
                Ok(self.claims.clone())
            } else {
                Err("invalid signature".to_string())
            }
        }
    }

    fn build_state(
        authorization_type: &str,
        authorizer: Option<StateAuthorizer>,
    ) -> SharedApiGatewayState {
        let mut state = ApiGatewayState::new(TEST_ACCOUNT, TEST_REGION);
        state.apis.insert(
            TEST_API_ID.to_string(),
            RestApi {
                id: TEST_API_ID.to_string(),
                name: "test".to_string(),
                description: None,
                version: None,
                created_date: Utc::now(),
                api_key_source: "HEADER".to_string(),
                endpoint_configuration: serde_json::json!({}),
                policy: None,
                binary_media_types: vec![],
                minimum_compression_size: None,
                disable_execute_api_endpoint: false,
                root_resource_id: "root".to_string(),
                tags: BTreeMap::new(),
                import_source: None,
            },
        );
        let mut resources = BTreeMap::new();
        resources.insert(
            RES_ID.to_string(),
            StateResource {
                id: RES_ID.to_string(),
                parent_id: Some("root".to_string()),
                path_part: Some("items".to_string()),
                path: "/items".to_string(),
            },
        );
        state.resources.insert(TEST_API_ID.to_string(), resources);
        let key = format!("{TEST_API_ID}/{RES_ID}/GET");
        state.methods.insert(
            key.clone(),
            StateMethod {
                rest_api_id: TEST_API_ID.to_string(),
                resource_id: RES_ID.to_string(),
                http_method: "GET".to_string(),
                authorization_type: authorization_type.to_string(),
                authorizer_id: authorizer.as_ref().map(|a| a.id.clone()),
                api_key_required: false,
                operation_name: None,
                request_parameters: BTreeMap::new(),
                request_models: BTreeMap::new(),
                request_validator_id: None,
                authorization_scopes: vec![],
            },
        );
        state.integrations.insert(
            key,
            StateIntegration {
                rest_api_id: TEST_API_ID.to_string(),
                resource_id: RES_ID.to_string(),
                http_method: "GET".to_string(),
                integration_type: "AWS_PROXY".to_string(),
                integration_http_method: Some("POST".to_string()),
                uri: Some(format!(
                    "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/{BACKEND_ARN}/invocations"
                )),
                credentials: None,
                request_parameters: BTreeMap::new(),
                request_templates: BTreeMap::new(),
                passthrough_behavior: "WHEN_NO_MATCH".to_string(),
                timeout_in_millis: None,
                cache_namespace: None,
                cache_key_parameters: vec![],
                content_handling: None,
                connection_type: None,
                connection_id: None,
                tls_config: None,
            },
        );
        if let Some(auth) = authorizer {
            state
                .authorizers
                .entry(TEST_API_ID.to_string())
                .or_default()
                .insert(auth.id.clone(), auth);
        }
        let mut stages = BTreeMap::new();
        stages.insert(
            "prod".to_string(),
            StateStage {
                stage_name: "prod".to_string(),
                deployment_id: "dep1".to_string(),
                description: None,
                cache_cluster_enabled: false,
                cache_cluster_size: None,
                variables: BTreeMap::new(),
                method_settings: BTreeMap::new(),
                created_date: Utc::now(),
                last_updated_date: Utc::now(),
                tracing_enabled: false,
                web_acl_arn: None,
                canary_settings: None,
                access_log_settings: None,
                tags: BTreeMap::new(),
            },
        );
        state.stages.insert(TEST_API_ID.to_string(), stages);

        let mut mas: MultiAccountState<ApiGatewayState> =
            MultiAccountState::new(TEST_ACCOUNT, TEST_REGION, "http://localhost:4566");
        *mas.get_or_create(TEST_ACCOUNT) = state;
        Arc::new(parking_lot::RwLock::new(mas))
    }

    fn make_request(headers: HeaderMap) -> AwsRequest {
        AwsRequest {
            service: "apigateway".to_string(),
            action: String::new(),
            method: Method::GET,
            raw_path: "/prod/items".to_string(),
            raw_query: String::new(),
            path_segments: vec!["prod".to_string(), "items".to_string()],
            query_params: HashMap::new(),
            headers,
            body: Bytes::new(),
            body_stream: parking_lot::Mutex::new(None),
            account_id: TEST_ACCOUNT.to_string(),
            region: TEST_REGION.to_string(),
            request_id: "rid".to_string(),
            is_query_protocol: false,
            access_key_id: None,
            principal: None,
        }
    }

    fn token_authorizer() -> StateAuthorizer {
        StateAuthorizer {
            id: AUTH_ID.to_string(),
            name: "tok".to_string(),
            authorizer_type: "TOKEN".to_string(),
            provider_arns: vec![],
            auth_type: None,
            authorizer_uri: Some(format!(
                "arn:aws:apigateway:us-east-1:lambda:path/2015-03-31/functions/{FN_ARN}/invocations"
            )),
            authorizer_credentials: None,
            identity_source: Some("method.request.header.Authorization".to_string()),
            identity_validation_expression: None,
            authorizer_result_ttl_in_seconds: Some(300),
        }
    }

    fn request_authorizer() -> StateAuthorizer {
        let mut a = token_authorizer();
        a.authorizer_type = "REQUEST".to_string();
        a.identity_source = Some("method.request.header.X-Custom".to_string());
        a
    }

    fn cognito_authorizer() -> StateAuthorizer {
        StateAuthorizer {
            id: AUTH_ID.to_string(),
            name: "cog".to_string(),
            authorizer_type: "COGNITO_USER_POOLS".to_string(),
            provider_arns: vec![COGNITO_ARN.to_string()],
            auth_type: None,
            authorizer_uri: None,
            authorizer_credentials: None,
            identity_source: Some("method.request.header.Authorization".to_string()),
            identity_validation_expression: None,
            authorizer_result_ttl_in_seconds: Some(300),
        }
    }

    fn build_service(
        state: SharedApiGatewayState,
        lambda: Arc<StubLambda>,
        verifier: Option<Arc<dyn CognitoJwtVerifier>>,
    ) -> ApiGatewayService {
        let mut bus = DeliveryBus::new().with_lambda(lambda);
        if let Some(v) = verifier {
            bus = bus.with_cognito_jwt_verifier(v);
        }
        ApiGatewayService::new(state).with_delivery(Arc::new(bus))
    }

    #[tokio::test]
    async fn request_passes_when_authorization_type_none() {
        let state = build_state("NONE", None);
        let lambda = Arc::new(StubLambda::new());
        lambda.set(
            BACKEND_ARN,
            serde_json::json!({"statusCode": 200, "body": "ok"}),
        );
        let service = build_service(state, lambda.clone(), None);
        let resp = handle(&service, &make_request(HeaderMap::new()))
            .await
            .expect("request must succeed");
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(lambda.invocation_count(BACKEND_ARN), 1);
    }

    #[tokio::test]
    async fn request_blocked_by_token_authorizer_returning_deny() {
        let state = build_state("CUSTOM", Some(token_authorizer()));
        let lambda = Arc::new(StubLambda::new());
        lambda.set(
            FN_ARN,
            serde_json::json!({
                "principalId": "user-1",
                "policyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Deny", "Action": "execute-api:Invoke", "Resource": "*"}]
                }
            }),
        );
        let service = build_service(state, lambda.clone(), None);
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "tok-deny".parse().unwrap());
        let result = handle(&service, &make_request(headers)).await;
        let err = match result {
            Ok(_) => panic!("Deny must surface as error"),
            Err(e) => e,
        };
        assert_eq!(err.status(), StatusCode::FORBIDDEN);
        assert_eq!(lambda.invocation_count(FN_ARN), 1);
        assert_eq!(lambda.invocation_count(BACKEND_ARN), 0);
    }

    #[tokio::test]
    async fn request_allowed_by_token_authorizer_returning_allow() {
        let state = build_state("CUSTOM", Some(token_authorizer()));
        let lambda = Arc::new(StubLambda::new());
        lambda.set(
            FN_ARN,
            serde_json::json!({
                "principalId": "user-1",
                "policyDocument": {
                    "Version": "2012-10-17",
                    "Statement": [{"Effect": "Allow", "Action": "execute-api:Invoke", "Resource": "*"}]
                },
                "context": {"role": "admin"}
            }),
        );
        lambda.set(
            BACKEND_ARN,
            serde_json::json!({"statusCode": 200, "body": "ok"}),
        );
        let service = build_service(state, lambda.clone(), None);
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "tok-allow".parse().unwrap());
        let resp = handle(&service, &make_request(headers))
            .await
            .expect("Allow must let request through");
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(lambda.invocation_count(BACKEND_ARN), 1);
        // Backend received the authorizer context in requestContext.
        let payload: serde_json::Value =
            serde_json::from_str(&lambda.last_payload(BACKEND_ARN).unwrap()).unwrap();
        assert_eq!(payload["requestContext"]["authorizer"]["role"], "admin");
        assert_eq!(
            payload["requestContext"]["authorizer"]["principalId"],
            "user-1"
        );
    }

    #[tokio::test]
    async fn request_blocked_by_token_authorizer_when_token_missing() {
        let state = build_state("CUSTOM", Some(token_authorizer()));
        let lambda = Arc::new(StubLambda::new());
        let service = build_service(state, lambda.clone(), None);
        let result = handle(&service, &make_request(HeaderMap::new())).await;
        let err = match result {
            Ok(_) => panic!("missing identity source must 401"),
            Err(e) => e,
        };
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(lambda.invocation_count(FN_ARN), 0);
        assert_eq!(lambda.invocation_count(BACKEND_ARN), 0);
    }

    #[tokio::test]
    async fn cognito_authorizer_rejects_invalid_jwt_signature() {
        let state = build_state("COGNITO_USER_POOLS", Some(cognito_authorizer()));
        let lambda = Arc::new(StubLambda::new());
        let verifier: Arc<dyn CognitoJwtVerifier> = Arc::new(StubJwtVerifier {
            valid_token: "valid-jwt".to_string(),
            claims: serde_json::json!({"sub": "u-1"}),
        });
        let service = build_service(state, lambda.clone(), Some(verifier));
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer tampered".parse().unwrap());
        let result = handle(&service, &make_request(headers)).await;
        let err = match result {
            Ok(_) => panic!("tampered JWT must 401"),
            Err(e) => e,
        };
        assert_eq!(err.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(lambda.invocation_count(BACKEND_ARN), 0);
    }

    #[tokio::test]
    async fn cognito_authorizer_accepts_valid_jwt_from_pool() {
        let state = build_state("COGNITO_USER_POOLS", Some(cognito_authorizer()));
        let lambda = Arc::new(StubLambda::new());
        lambda.set(
            BACKEND_ARN,
            serde_json::json!({"statusCode": 200, "body": "ok"}),
        );
        let claims = serde_json::json!({"sub": "u-1", "email": "a@b.c"});
        let verifier: Arc<dyn CognitoJwtVerifier> = Arc::new(StubJwtVerifier {
            valid_token: "valid-jwt".to_string(),
            claims: claims.clone(),
        });
        let service = build_service(state, lambda.clone(), Some(verifier));
        let mut headers = HeaderMap::new();
        headers.insert("authorization", "Bearer valid-jwt".parse().unwrap());
        let resp = handle(&service, &make_request(headers))
            .await
            .expect("valid JWT lets request through");
        assert_eq!(resp.status, StatusCode::OK);
        let payload: serde_json::Value =
            serde_json::from_str(&lambda.last_payload(BACKEND_ARN).unwrap()).unwrap();
        assert_eq!(payload["requestContext"]["authorizer"]["claims"], claims);
    }

    #[tokio::test]
    async fn request_authorizer_evaluates_full_request_event() {
        let state = build_state("CUSTOM", Some(request_authorizer()));
        let lambda = Arc::new(StubLambda::new());
        lambda.set(
            FN_ARN,
            serde_json::json!({
                "principalId": "u",
                "policyDocument": {
                    "Statement": [{"Effect": "Allow", "Resource": "*"}]
                }
            }),
        );
        lambda.set(
            BACKEND_ARN,
            serde_json::json!({"statusCode": 200, "body": "ok"}),
        );
        let service = build_service(state, lambda.clone(), None);
        let mut headers = HeaderMap::new();
        headers.insert("x-custom", "secret".parse().unwrap());
        let resp = handle(&service, &make_request(headers))
            .await
            .expect("REQUEST authorizer Allow must succeed");
        assert_eq!(resp.status, StatusCode::OK);
        let payload: serde_json::Value =
            serde_json::from_str(&lambda.last_payload(FN_ARN).unwrap()).unwrap();
        assert_eq!(payload["type"], "REQUEST");
        assert_eq!(payload["headers"]["x-custom"], "secret");
        assert_eq!(payload["httpMethod"], "GET");
        assert!(payload["methodArn"].as_str().unwrap().contains("/items"));
    }
}
