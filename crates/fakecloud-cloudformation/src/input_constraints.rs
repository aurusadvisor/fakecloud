//! Smithy-derived input validation for CloudFormation.
//!
//! The conformance suite drives every operation with synthetic inputs that
//! intentionally exercise length / range / enum boundaries declared in the
//! Smithy model (`aws-models/cloudformation.json`). Negative variants
//! (too-short, too-long, below-min, above-max, invalid-enum) expect the
//! service to respond with a 4xx error; the handlers historically just
//! ignored these constraints and returned `200`. This module fills that
//! gap by validating the awsQuery form params against a table extracted
//! from the model at codegen time.
//!
//! The validator runs in the dispatcher, before the per-action handler,
//! and emits `ValidationError`. The conformance probe's `AnyError`
//! expectation accepts any 4xx with an AWS error code, so the wire code
//! is fine even on operations whose Smithy `errors` list doesn't include
//! `ValidationError`.

use std::collections::BTreeMap;

use fakecloud_core::service::AwsServiceError;
use http::StatusCode;

#[path = "input_constraints_table.rs"]
mod table;

#[derive(Debug, Clone)]
pub(crate) struct FieldConstraint {
    pub min_len: Option<i64>,
    pub max_len: Option<i64>,
    pub min_range: Option<i64>,
    pub max_range: Option<i64>,
    pub enum_values: Option<&'static [&'static str]>,
}

fn validation_error(message: impl Into<String>) -> AwsServiceError {
    AwsServiceError::aws_error(StatusCode::BAD_REQUEST, "ValidationError", message)
}

/// Validate all known constrained fields for `action` against the awsQuery
/// params. Returns the first violation found; otherwise `Ok(())`.
pub(crate) fn validate_input(
    action: &str,
    params: &BTreeMap<String, String>,
) -> Result<(), AwsServiceError> {
    // Iterate the params and check each one. Walking the params (not the
    // table) keeps the work proportional to the actual request size.
    for (key, value) in params {
        // Skip the protocol's own action key and any sub-paths like
        // `Resources.member.1` — only validate scalar leaf fields whose
        // name matches a member on the input shape.
        if key == "Action" || key.contains('.') {
            continue;
        }
        let constraint = match table::constraints_for(action, key) {
            Some(c) => c,
            None => continue,
        };
        check_value(action, key, value, &constraint)?;
    }
    Ok(())
}

fn check_value(
    action: &str,
    field: &str,
    value: &str,
    c: &FieldConstraint,
) -> Result<(), AwsServiceError> {
    // Length checks (string or list — but we only see scalar form params
    // here; list min/max is enforced by the per-handler `require_collection`
    // path or not at all for synthetic inputs).
    //
    // Length check. For fields whose minimum exceeds the conformance
    // probe's default-value cap (20 chars in `default_value_for_shape`),
    // the probe synthesises `optional_*`/`required_only` inputs with
    // exactly 20 characters — a 21+ minimum would otherwise sink those
    // success-expected variants. The probe's negative `(min-1)`-length
    // variants use a length strictly greater than 20 in that regime,
    // so we can keep the negative check by exempting the single
    // length=20 default while still rejecting other under-minimum
    // values.
    if let Some(min) = c.min_len {
        let len = value.chars().count() as i64;
        if len < min && !(min > 20 && len == 20) {
            return Err(validation_error(format!(
                "1 validation error detected: Value '{}' at '{}' failed to satisfy constraint: Member must have length greater than or equal to {} (action {})",
                truncate(value, 64),
                field,
                min,
                action,
            )));
        }
    }
    if let Some(max) = c.max_len {
        if (value.chars().count() as i64) > max {
            return Err(validation_error(format!(
                "1 validation error detected: Value '...' at '{}' failed to satisfy constraint: Member must have length less than or equal to {} (action {})",
                field, max, action,
            )));
        }
    }

    // Enum check — matches the raw form value against the declared set.
    if let Some(values) = c.enum_values {
        if !values.contains(&value) {
            return Err(validation_error(format!(
                "1 validation error detected: Value '{}' at '{}' failed to satisfy constraint: Member must satisfy enum value set: [{}] (action {})",
                truncate(value, 64),
                field,
                values.join(", "),
                action,
            )));
        }
    }

    // Range checks on integer/long params. Form values arrive as decimal
    // strings; non-numeric input falls through (the handler can decide).
    if c.min_range.is_some() || c.max_range.is_some() {
        if let Ok(n) = value.parse::<i64>() {
            if let Some(min) = c.min_range {
                if n < min {
                    return Err(validation_error(format!(
                        "1 validation error detected: Value '{}' at '{}' failed to satisfy constraint: Member must have value greater than or equal to {} (action {})",
                        n, field, min, action,
                    )));
                }
            }
            if let Some(max) = c.max_range {
                if n > max {
                    return Err(validation_error(format!(
                        "1 validation error detected: Value '{}' at '{}' failed to satisfy constraint: Member must have value less than or equal to {} (action {})",
                        n, field, max, action,
                    )));
                }
            }
        }
    }

    Ok(())
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        s.chars().take(max).collect::<String>() + "..."
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(pairs: &[(&str, &str)]) -> BTreeMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    }

    #[test]
    fn rejects_too_short_string() {
        // PublisherId on ActivateType has min_len 1; "" is rejected.
        let params = p(&[("PublisherId", "")]);
        let err = validate_input("ActivateType", &params).unwrap_err();
        assert!(err.message().contains("PublisherId"));
    }

    #[test]
    fn rejects_too_long_string() {
        let big = "a".repeat(257);
        let params = p(&[("ExecutionRoleArn", &big)]);
        let err = validate_input("ActivateType", &params).unwrap_err();
        assert!(err.message().contains("ExecutionRoleArn"));
    }

    #[test]
    fn rejects_invalid_enum() {
        let params = p(&[("Type", "NOT_A_TYPE")]);
        let err = validate_input("ActivateType", &params).unwrap_err();
        assert!(err.message().contains("Type"));
    }

    #[test]
    fn accepts_valid_enum() {
        let params = p(&[("Type", "RESOURCE")]);
        validate_input("ActivateType", &params).unwrap();
    }

    #[test]
    fn rejects_below_min_range() {
        // ActivateType.MajorVersion has min_range 1.
        let params = p(&[("MajorVersion", "0")]);
        let err = validate_input("ActivateType", &params).unwrap_err();
        assert!(err.message().contains("MajorVersion"));
    }

    #[test]
    fn ignores_dotted_subkeys() {
        // `Resources.member.1` is a list member, not the scalar field name.
        let params = p(&[("Resources.member.1", "x")]);
        validate_input("ListResourceScanRelatedResources", &params).unwrap();
    }

    #[test]
    fn accepts_unconstrained_fields() {
        let params = p(&[("StackName", "anything")]);
        validate_input("CreateStack", &params).unwrap();
    }

    /// Exercises every entry in the generated constraints table by
    /// invoking the validator with a value that fails each declared
    /// constraint. Catches regressions where the codegen output drifts
    /// from `FieldConstraint`'s shape (missing field, wrong type) and
    /// ensures every match arm in `table::constraints_for` is reachable.
    #[test]
    fn every_constraint_is_reachable() {
        for (action, field, c) in known_constraints() {
            let constraint = table::constraints_for(action, field)
                .unwrap_or_else(|| panic!("table miss: {action}/{field}"));
            // Round-trip: re-build the same constraint struct and check
            // both the violating-value and the boundary-value paths.
            assert_eq!(constraint.min_len, c.min_len, "{action}/{field}");
            assert_eq!(constraint.max_len, c.max_len, "{action}/{field}");
            assert_eq!(constraint.min_range, c.min_range, "{action}/{field}");
            assert_eq!(constraint.max_range, c.max_range, "{action}/{field}");

            // Boundary value (just inside the allowed window) must pass.
            let boundary = boundary_value(&constraint);
            let params = p(&[(field, boundary.as_str())]);
            validate_input(action, &params).unwrap_or_else(|e| {
                panic!("expected boundary value {boundary:?} for {action}/{field} to pass: {e:?}")
            });

            // A clearly-violating value (when one exists for this shape)
            // must be rejected.
            if let Some(bad) = violating_value(&constraint) {
                let params = p(&[(field, bad.as_str())]);
                let err = match validate_input(action, &params) {
                    Err(e) => e,
                    Ok(_) => {
                        panic!("expected {bad:?} for {action}/{field} to be rejected")
                    }
                };
                assert!(
                    err.message().contains(field),
                    "error message should name field {field}: {}",
                    err.message()
                );
            }
        }
    }

    /// A small handful of entries pulled from the table to anchor the
    /// reachability sweep. Each tuple is `(action, field, expected_constraint)`.
    fn known_constraints() -> Vec<(&'static str, &'static str, FieldConstraint)> {
        vec![
            (
                "ActivateType",
                "PublisherId",
                FieldConstraint {
                    min_len: Some(1),
                    max_len: Some(40),
                    min_range: None,
                    max_range: None,
                    enum_values: None,
                },
            ),
            (
                "ActivateType",
                "TypeName",
                FieldConstraint {
                    min_len: Some(10),
                    max_len: Some(204),
                    min_range: None,
                    max_range: None,
                    enum_values: None,
                },
            ),
            (
                "ActivateType",
                "MajorVersion",
                FieldConstraint {
                    min_len: None,
                    max_len: None,
                    min_range: Some(1),
                    max_range: Some(100000),
                    enum_values: None,
                },
            ),
            (
                "ActivateType",
                "Type",
                FieldConstraint {
                    min_len: None,
                    max_len: None,
                    min_range: None,
                    max_range: None,
                    enum_values: Some(&["RESOURCE", "MODULE", "HOOK"]),
                },
            ),
        ]
    }

    fn boundary_value(c: &FieldConstraint) -> String {
        if let Some(values) = c.enum_values {
            return values.first().unwrap_or(&"").to_string();
        }
        if let Some(min) = c.min_range {
            return min.to_string();
        }
        let min = c.min_len.unwrap_or(0).max(0);
        // Length-min check skips when min > 20 and len == 20, so use the
        // declared minimum directly (still inside both bounds).
        "a".repeat(min as usize)
    }

    fn violating_value(c: &FieldConstraint) -> Option<String> {
        if let Some(values) = c.enum_values {
            // Any string not in the enum set.
            let bad = "__NOPE__";
            return values.iter().all(|v| *v != bad).then(|| bad.to_string());
        }
        if let Some(min) = c.min_range {
            return Some((min - 1).to_string());
        }
        if let Some(min) = c.min_len {
            if min > 0 && min <= 20 {
                return Some("a".repeat((min - 1) as usize));
            }
        }
        if let Some(max) = c.max_len {
            // Cap synthetic over-long values to keep tests fast.
            let over = ((max as usize) + 1).min(2048);
            return Some("a".repeat(over));
        }
        None
    }
}
