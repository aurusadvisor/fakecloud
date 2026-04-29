// Handlers for CloudFront ConnectionFunction ops (8 ops). Mirrors the
// regular CloudFront Functions lifecycle: create -> describe/get ->
// update -> publish -> attach. Code blob is base64-encoded on the
// wire, returned raw for GetConnectionFunction.

use base64::Engine;
use chrono::Utc;
use http::header::ETAG;
use http::{HeaderMap, StatusCode};

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError, ResponseBody};

use crate::cfunctions::StoredConnectionFunction;
use crate::policies::{
    not_found, precondition_failed, require_if_match, rfc3339, route_id, xml_with_etag,
};
use crate::router::Route;
use crate::service::{
    aws_error, esc, generate_id_with_prefix, invalid_argument, xml_response, CloudFrontService,
    DEFAULT_ACCOUNT,
};
use crate::xml_io;

const NS: &str = crate::NAMESPACE;
const XML_DECL: &str = r#"<?xml version="1.0" encoding="UTF-8"?>"#;

#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct CreateConnectionFunctionRequest {
    pub name: String,
    pub connection_function_config: ConnectionFunctionConfigInput,
    pub connection_function_code: String,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct UpdateConnectionFunctionRequest {
    pub connection_function_config: ConnectionFunctionConfigInput,
    pub connection_function_code: String,
}

#[derive(Debug, Default, serde::Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ConnectionFunctionConfigInput {
    pub comment: String,
    pub runtime: String,
}

impl CloudFrontService {
    pub(crate) fn create_connection_function(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let parsed: CreateConnectionFunctionRequest =
            xml_io::from_xml_root(&req.body).map_err(|e| {
                invalid_argument(format!("invalid CreateConnectionFunctionRequest XML: {e}"))
            })?;
        if parsed.name.is_empty() {
            return Err(invalid_argument("Name is required"));
        }
        let mut state = self.state.write();
        let account = state
            .accounts
            .entry(DEFAULT_ACCOUNT.to_string())
            .or_default();
        if account.connection_functions.contains_key(&parsed.name) {
            return Err(aws_error(
                StatusCode::CONFLICT,
                "EntityAlreadyExists",
                format!("ConnectionFunction {} already exists", parsed.name),
            ));
        }
        let now = Utc::now();
        let etag = generate_id_with_prefix("E");
        let id = generate_id_with_prefix("CF");
        let arn = format!(
            "arn:aws:cloudfront::{}:connection-function/{}",
            DEFAULT_ACCOUNT, parsed.name
        );
        let code = base64::engine::general_purpose::STANDARD
            .decode(parsed.connection_function_code.trim())
            .unwrap_or_else(|_| parsed.connection_function_code.into_bytes());
        let stored = StoredConnectionFunction {
            id,
            name: parsed.name.clone(),
            arn,
            stage: "DEVELOPMENT".to_string(),
            status: "UNPUBLISHED".to_string(),
            runtime: parsed.connection_function_config.runtime,
            comment: parsed.connection_function_config.comment,
            code,
            etag: etag.clone(),
            created_time: now,
            last_modified_time: now,
        };
        account
            .connection_functions
            .insert(parsed.name.clone(), stored.clone());
        drop(state);
        let body = render_connection_function_summary(&stored, true);
        Ok(xml_with_etag(StatusCode::CREATED, body, &etag, None))
    }

    pub(crate) fn describe_connection_function(
        &self,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = route_id(route, "ConnectionFunction")?;
        let state = self.state.read();
        let f = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.connection_functions.get(&name).cloned())
            .ok_or_else(|| not_found("ConnectionFunction", &name))?;
        drop(state);
        let body = render_connection_function_summary(&f, true);
        Ok(xml_with_etag(StatusCode::OK, body, &f.etag, None))
    }

    pub(crate) fn get_connection_function(
        &self,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = route_id(route, "ConnectionFunction")?;
        let state = self.state.read();
        let f = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.connection_functions.get(&name).cloned())
            .ok_or_else(|| not_found("ConnectionFunction", &name))?;
        drop(state);
        let mut headers = HeaderMap::new();
        if let Ok(v) = http::HeaderValue::from_str(&f.etag) {
            headers.insert(ETAG, v);
        }
        Ok(AwsResponse {
            status: StatusCode::OK,
            headers,
            content_type: "application/octet-stream".to_string(),
            body: ResponseBody::Bytes(bytes::Bytes::from(f.code.clone())),
        })
    }

    pub(crate) fn update_connection_function(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = route_id(route, "ConnectionFunction")?;
        let if_match = require_if_match(req)?;
        let parsed: UpdateConnectionFunctionRequest =
            xml_io::from_xml_root(&req.body).map_err(|e| {
                invalid_argument(format!("invalid UpdateConnectionFunctionRequest XML: {e}"))
            })?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| not_found("ConnectionFunction", &name))?;
        let f = account
            .connection_functions
            .get_mut(&name)
            .ok_or_else(|| not_found("ConnectionFunction", &name))?;
        if f.etag != if_match {
            return Err(precondition_failed());
        }
        f.runtime = parsed.connection_function_config.runtime;
        f.comment = parsed.connection_function_config.comment;
        f.code = base64::engine::general_purpose::STANDARD
            .decode(parsed.connection_function_code.trim())
            .unwrap_or_else(|_| parsed.connection_function_code.into_bytes());
        f.etag = generate_id_with_prefix("E");
        f.last_modified_time = Utc::now();
        f.status = "UNPUBLISHED".to_string();
        f.stage = "DEVELOPMENT".to_string();
        let snap = f.clone();
        drop(state);
        let body = render_connection_function_summary(&snap, true);
        Ok(xml_with_etag(StatusCode::OK, body, &snap.etag, None))
    }

    pub(crate) fn delete_connection_function(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = route_id(route, "ConnectionFunction")?;
        let if_match = require_if_match(req)?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| not_found("ConnectionFunction", &name))?;
        let f = account
            .connection_functions
            .get(&name)
            .ok_or_else(|| not_found("ConnectionFunction", &name))?;
        if f.etag != if_match {
            return Err(precondition_failed());
        }
        account.connection_functions.remove(&name);
        drop(state);
        Ok(crate::policies::empty(StatusCode::NO_CONTENT))
    }

    pub(crate) fn list_connection_functions(
        &self,
        _req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let state = self.state.read();
        let mut items: Vec<StoredConnectionFunction> = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .map(|a| a.connection_functions.values().cloned().collect())
            .unwrap_or_default();
        drop(state);
        items.sort_by(|a, b| a.name.cmp(&b.name));
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<ListConnectionFunctionsResult xmlns=\"{NS}\">"));
        body.push_str("<NextMarker></NextMarker>");
        body.push_str("<ConnectionFunctions>");
        for f in &items {
            body.push_str(&render_connection_function_summary_inner(f));
        }
        body.push_str("</ConnectionFunctions>");
        body.push_str("</ListConnectionFunctionsResult>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }

    pub(crate) fn publish_connection_function(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = route_id(route, "ConnectionFunction")?;
        let if_match = require_if_match(req)?;
        let mut state = self.state.write();
        let account = state
            .accounts
            .get_mut(DEFAULT_ACCOUNT)
            .ok_or_else(|| not_found("ConnectionFunction", &name))?;
        let f = account
            .connection_functions
            .get_mut(&name)
            .ok_or_else(|| not_found("ConnectionFunction", &name))?;
        if f.etag != if_match {
            return Err(precondition_failed());
        }
        f.status = "DEPLOYED".to_string();
        f.stage = "LIVE".to_string();
        f.last_modified_time = Utc::now();
        let snap = f.clone();
        drop(state);
        let body = render_connection_function_summary(&snap, true);
        Ok(xml_with_etag(StatusCode::OK, body, &snap.etag, None))
    }

    pub(crate) fn test_connection_function(
        &self,
        req: &AwsRequest,
        route: &Route,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = route_id(route, "ConnectionFunction")?;
        let if_match = require_if_match(req)?;
        let state = self.state.read();
        let f = state
            .accounts
            .get(DEFAULT_ACCOUNT)
            .and_then(|a| a.connection_functions.get(&name).cloned())
            .ok_or_else(|| not_found("ConnectionFunction", &name))?;
        drop(state);
        if f.etag != if_match {
            return Err(precondition_failed());
        }
        let mut body = String::with_capacity(512);
        body.push_str(XML_DECL);
        body.push_str(&format!("<ConnectionFunctionTestResult xmlns=\"{NS}\">"));
        body.push_str(&render_connection_function_summary_inner(&f));
        body.push_str("<ComputeUtilization>0</ComputeUtilization>");
        body.push_str("<ConnectionFunctionExecutionLogs></ConnectionFunctionExecutionLogs>");
        body.push_str("<ConnectionFunctionErrorMessage></ConnectionFunctionErrorMessage>");
        body.push_str("<ConnectionFunctionOutput>{}</ConnectionFunctionOutput>");
        body.push_str("</ConnectionFunctionTestResult>");
        Ok(xml_response(StatusCode::OK, body, HeaderMap::new()))
    }
}

fn render_connection_function_summary(f: &StoredConnectionFunction, with_decl: bool) -> String {
    let mut out = String::with_capacity(512);
    if with_decl {
        out.push_str(XML_DECL);
    }
    out.push_str(&format!("<ConnectionFunctionSummary xmlns=\"{NS}\">"));
    push_summary_body(&mut out, f);
    out.push_str("</ConnectionFunctionSummary>");
    out
}

fn render_connection_function_summary_inner(f: &StoredConnectionFunction) -> String {
    let mut out = String::with_capacity(512);
    out.push_str("<ConnectionFunctionSummary>");
    push_summary_body(&mut out, f);
    out.push_str("</ConnectionFunctionSummary>");
    out
}

fn push_summary_body(out: &mut String, f: &StoredConnectionFunction) {
    out.push_str(&format!("<Name>{}</Name>", esc(&f.name)));
    out.push_str(&format!("<Id>{}</Id>", esc(&f.id)));
    out.push_str(&format!("<Status>{}</Status>", esc(&f.status)));
    out.push_str(&format!(
        "<ConnectionFunctionArn>{}</ConnectionFunctionArn>",
        esc(&f.arn)
    ));
    out.push_str(&format!("<Stage>{}</Stage>", esc(&f.stage)));
    out.push_str(&format!(
        "<CreatedTime>{}</CreatedTime>",
        rfc3339(&f.created_time)
    ));
    out.push_str(&format!(
        "<LastModifiedTime>{}</LastModifiedTime>",
        rfc3339(&f.last_modified_time)
    ));
    out.push_str("<ConnectionFunctionConfig>");
    out.push_str(&format!("<Comment>{}</Comment>", esc(&f.comment)));
    out.push_str(&format!("<Runtime>{}</Runtime>", esc(&f.runtime)));
    out.push_str("</ConnectionFunctionConfig>");
}
