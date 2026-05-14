//! Shared input validation for Bedrock runtime operations
//! (InvokeModel, InvokeModelWithResponseStream, InvokeModelWithBidirectionalStream,
//! Converse, ConverseStream, CountTokens, StartAsyncInvoke, GetAsyncInvoke,
//! ListAsyncInvokes).
//!
//! These checks mirror the `@length`, `@range`, `@pattern` and enum constraints
//! declared in the upstream Smithy model so that out-of-band requests surface
//! the same `ValidationException` real AWS would return, instead of slipping
//! through to the canned handlers.

use fakecloud_core::service::{AwsRequest, AwsServiceError};
use http::StatusCode;

/// `@length: min=1 max=2048` on `InvokeModelIdentifier` / `ConversationalModelId`
/// (used by InvokeModel, InvokeModelWithResponseStream,
/// InvokeModelWithBidirectionalStream, Converse, ConverseStream).
pub(crate) fn validate_invoke_model_id(model_id: &str) -> Result<(), AwsServiceError> {
    validate_length("modelId", model_id, 1, 2048)?;
    validate_model_id_pattern(model_id)
}

/// `@length: min=1 max=256` on `FoundationModelVersionIdentifier`
/// (CountTokens) and `AsyncInvokeIdentifier` (StartAsyncInvoke modelId).
pub(crate) fn validate_short_model_id(model_id: &str) -> Result<(), AwsServiceError> {
    validate_length("modelId", model_id, 1, 256)?;
    validate_model_id_pattern(model_id)
}

/// Reject obviously-bogus modelId values. The upstream Smithy regex is a
/// 600-character alternation — rather than mirror it byte-for-byte we
/// enforce the cheap structural checks that distinguish a real model
/// identifier from a stray URI template (`{modelId}`), an empty
/// percent-encoded path segment, or whitespace.
fn validate_model_id_pattern(model_id: &str) -> Result<(), AwsServiceError> {
    if model_id.contains('{') || model_id.contains('}') {
        return Err(validation(format!(
            "Value '{model_id}' at 'modelId' failed to satisfy constraint: Member must match a valid model identifier pattern"
        )));
    }
    if model_id.chars().any(|c| c.is_whitespace()) {
        return Err(validation(format!(
            "Value '{model_id}' at 'modelId' failed to satisfy constraint: whitespace is not allowed"
        )));
    }
    Ok(())
}

/// Validate a string length against `min..=max`. Pass `min=0` to skip the
/// lower bound. Empty values trip the min check when `min >= 1`.
pub(crate) fn validate_length(
    field: &str,
    value: &str,
    min: usize,
    max: usize,
) -> Result<(), AwsServiceError> {
    let len = value.chars().count();
    if len < min {
        return Err(validation(format!(
            "'{value}' at '{field}' failed to satisfy constraint: Member must have length greater than or equal to {min}"
        )));
    }
    if len > max {
        return Err(validation(format!(
            "Value at '{field}' failed to satisfy constraint: Member must have length less than or equal to {max}"
        )));
    }
    Ok(())
}

/// `@range: min=1 max=1000` on `MaxResults` (ListAsyncInvokes).
pub(crate) fn validate_range_i64(
    field: &str,
    value: i64,
    min: i64,
    max: i64,
) -> Result<(), AwsServiceError> {
    if value < min {
        return Err(validation(format!(
            "Value '{value}' at '{field}' failed to satisfy constraint: Member must have value greater than or equal to {min}"
        )));
    }
    if value > max {
        return Err(validation(format!(
            "Value '{value}' at '{field}' failed to satisfy constraint: Member must have value less than or equal to {max}"
        )));
    }
    Ok(())
}

/// Validate an enum value against the allowed set.
pub(crate) fn validate_enum(
    field: &str,
    value: &str,
    allowed: &[&str],
) -> Result<(), AwsServiceError> {
    if allowed.contains(&value) {
        return Ok(());
    }
    Err(validation(format!(
        "Value '{value}' at '{field}' failed to satisfy constraint: Member must satisfy enum value set: [{}]",
        allowed.join(", ")
    )))
}

/// Allowed values for `@httpHeader X-Amzn-Bedrock-PerformanceConfig-Latency`.
const PERFORMANCE_CONFIG_LATENCY: &[&str] = &["standard", "optimized"];

/// Allowed values for `@httpHeader X-Amzn-Bedrock-Service-Tier`.
const SERVICE_TIER: &[&str] = &["priority", "default", "flex", "reserved"];

/// Allowed values for `@httpHeader X-Amzn-Bedrock-Trace`.
const TRACE: &[&str] = &["ENABLED", "DISABLED", "ENABLED_FULL"];

/// Validate shared invoke/converse headers (performanceConfigLatency,
/// serviceTier, trace) and the body-size cap on Body (max 25_000_000 bytes).
/// Returns the validation error on first violation.
pub(crate) fn validate_runtime_headers(req: &AwsRequest) -> Result<(), AwsServiceError> {
    if let Some(v) = req
        .headers
        .get("x-amzn-bedrock-performanceconfig-latency")
        .and_then(|h| h.to_str().ok())
    {
        validate_enum("performanceConfigLatency", v, PERFORMANCE_CONFIG_LATENCY)?;
    }
    if let Some(v) = req
        .headers
        .get("x-amzn-bedrock-service-tier")
        .and_then(|h| h.to_str().ok())
    {
        validate_enum("serviceTier", v, SERVICE_TIER)?;
    }
    if let Some(v) = req
        .headers
        .get("x-amzn-bedrock-trace")
        .and_then(|h| h.to_str().ok())
    {
        validate_enum("trace", v, TRACE)?;
    }
    // GuardrailIdentifier: @length max=2048 (no min). Header form.
    if let Some(v) = req
        .headers
        .get("x-amzn-bedrock-guardrailidentifier")
        .and_then(|h| h.to_str().ok())
    {
        validate_length("guardrailIdentifier", v, 0, 2048)?;
    }
    Ok(())
}

/// Validate the body-size cap on InvokeModel-style payloads (`@length max=25_000_000`).
pub(crate) fn validate_invoke_body_size(body: &[u8]) -> Result<(), AwsServiceError> {
    if body.len() > 25_000_000 {
        return Err(validation(
            "Value at 'body' failed to satisfy constraint: Member must have length less than or equal to 25000000",
        ));
    }
    Ok(())
}

/// Build a `ValidationException` with 400 status — the response shape declared
/// by every runtime operation we care about here.
pub(crate) fn validation<S: Into<String>>(message: S) -> AwsServiceError {
    AwsServiceError::aws_error(StatusCode::BAD_REQUEST, "ValidationException", message)
}
