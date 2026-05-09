//! Minimal JSON Schema Draft 4 validator for API Gateway model validation.
//!
//! Supports the subset of JSON Schema that API Gateway commonly uses:
//! `type`, `required`, `properties`, `items`, `enum`, `minLength`, `maxLength`,
//! `minimum`, `maximum`, `pattern`, `additionalProperties`, and `format`.

use regex::Regex;
use serde_json::Value;
use std::collections::BTreeSet;

#[derive(Debug, Clone, PartialEq)]
pub struct ValidationError {
    pub path: String,
    pub message: String,
}

impl std::fmt::Display for ValidationError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.path, self.message)
    }
}

impl std::error::Error for ValidationError {}

/// Validate `value` against a JSON Schema (Draft 4 subset).
/// Returns `Ok(())` when valid, or the first validation error encountered.
pub fn validate(schema: &Value, value: &Value) -> Result<(), ValidationError> {
    validate_at(schema, value, "")
}

fn validate_at(schema: &Value, value: &Value, path: &str) -> Result<(), ValidationError> {
    if let Some(o) = schema.as_object() {
        if let Some(ref_val) = o.get("$ref").and_then(|v| v.as_str()) {
            // We don't support remote $ref resolution. Inline refs only.
            return Err(ValidationError {
                path: path.to_string(),
                message: format!("Remote $ref resolution not supported: {ref_val}"),
            });
        }

        if let Some(types) = o.get("type") {
            if !type_matches(types, value) {
                return Err(ValidationError {
                    path: path.to_string(),
                    message: format!(
                        "Expected type {}, got {}",
                        json_type_str(types),
                        value_type_str(value)
                    ),
                });
            }
        }

        if let Some(enum_vals) = o.get("enum").and_then(|v| v.as_array()) {
            if !enum_vals.contains(value) {
                return Err(ValidationError {
                    path: path.to_string(),
                    message: format!(
                        "Value not in enum: {:?}",
                        enum_vals.iter().map(|v| v.to_string()).collect::<Vec<_>>()
                    ),
                });
            }
        }

        match value {
            Value::String(s) => {
                if let Some(min) = o.get("minLength").and_then(|v| v.as_u64()) {
                    if s.chars().count() < min as usize {
                        return Err(ValidationError {
                            path: path.to_string(),
                            message: format!("String length {} < minLength {}", s.len(), min),
                        });
                    }
                }
                if let Some(max) = o.get("maxLength").and_then(|v| v.as_u64()) {
                    if s.chars().count() > max as usize {
                        return Err(ValidationError {
                            path: path.to_string(),
                            message: format!("String length {} > maxLength {}", s.len(), max),
                        });
                    }
                }
                if let Some(pattern) = o.get("pattern").and_then(|v| v.as_str()) {
                    let re = Regex::new(pattern).map_err(|e| ValidationError {
                        path: path.to_string(),
                        message: format!("Invalid pattern: {e}"),
                    })?;
                    if !re.is_match(s) {
                        return Err(ValidationError {
                            path: path.to_string(),
                            message: format!("String does not match pattern: {pattern}"),
                        });
                    }
                }
                if let Some(fmt) = o.get("format").and_then(|v| v.as_str()) {
                    if !check_format(fmt, s) {
                        return Err(ValidationError {
                            path: path.to_string(),
                            message: format!("String does not match format: {fmt}"),
                        });
                    }
                }
            }
            Value::Number(n) => {
                if let Some(min) = o.get("minimum").and_then(|v| v.as_f64()) {
                    if n.as_f64().unwrap_or(f64::NAN) < min {
                        return Err(ValidationError {
                            path: path.to_string(),
                            message: format!("Number {} < minimum {}", n, min),
                        });
                    }
                }
                if let Some(max) = o.get("maximum").and_then(|v| v.as_f64()) {
                    if n.as_f64().unwrap_or(f64::NAN) > max {
                        return Err(ValidationError {
                            path: path.to_string(),
                            message: format!("Number {} > maximum {}", n, max),
                        });
                    }
                }
            }
            Value::Array(arr) => {
                if let Some(items_schema) = o.get("items") {
                    for (i, item) in arr.iter().enumerate() {
                        let item_path = format!("{}[{}]", path, i);
                        validate_at(items_schema, item, &item_path)?;
                    }
                }
                if let Some(min_items) = o.get("minItems").and_then(|v| v.as_u64()) {
                    if arr.len() < min_items as usize {
                        return Err(ValidationError {
                            path: path.to_string(),
                            message: format!("Array length {} < minItems {}", arr.len(), min_items),
                        });
                    }
                }
                if let Some(max_items) = o.get("maxItems").and_then(|v| v.as_u64()) {
                    if arr.len() > max_items as usize {
                        return Err(ValidationError {
                            path: path.to_string(),
                            message: format!("Array length {} > maxItems {}", arr.len(), max_items),
                        });
                    }
                }
            }
            Value::Object(obj) => {
                if let Some(required) = o.get("required").and_then(|v| v.as_array()) {
                    let keys: BTreeSet<&str> = obj.keys().map(|s| s.as_str()).collect();
                    for req in required {
                        if let Some(r) = req.as_str() {
                            if !keys.contains(r) {
                                return Err(ValidationError {
                                    path: path.to_string(),
                                    message: format!("Missing required property: {r}"),
                                });
                            }
                        }
                    }
                }
                if let Some(props) = o.get("properties").and_then(|v| v.as_object()) {
                    for (key, prop_schema) in props {
                        if let Some(prop_value) = obj.get(key) {
                            let prop_path = if path.is_empty() {
                                key.clone()
                            } else {
                                format!("{}.{}", path, key)
                            };
                            validate_at(prop_schema, prop_value, &prop_path)?;
                        }
                    }
                }
                if let Some(additional) = o.get("additionalProperties") {
                    if additional == &Value::Bool(false) {
                        let known: BTreeSet<&str> = o
                            .get("properties")
                            .and_then(|v| v.as_object())
                            .map(|p| p.keys().map(|s| s.as_str()).collect())
                            .unwrap_or_default();
                        for key in obj.keys() {
                            if !known.contains(key.as_str()) {
                                return Err(ValidationError {
                                    path: path.to_string(),
                                    message: format!("Additional property not allowed: {key}"),
                                });
                            }
                        }
                    }
                }
            }
            _ => {}
        }
    }
    Ok(())
}

fn type_matches(types: &Value, value: &Value) -> bool {
    let expected = match types {
        Value::String(s) => vec![s.as_str()],
        Value::Array(arr) => arr.iter().filter_map(|v| v.as_str()).collect(),
        _ => return true,
    };
    if expected.is_empty() {
        return true;
    }
    let actual = value_type_str(value);
    expected.contains(&actual.as_str())
        || (expected.contains(&"number") && actual == "integer")
        || (expected.contains(&"integer") && actual == "number" && is_integer(value))
}

fn is_integer(value: &Value) -> bool {
    value
        .as_f64()
        .map(|f| f.fract() == 0.0 && !f.is_nan() && !f.is_infinite())
        .unwrap_or(false)
}

fn value_type_str(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(_) => "boolean".to_string(),
        Value::Number(n) => {
            if n.is_i64() || n.is_u64() || (n.as_f64().map(|f| f.fract() == 0.0).unwrap_or(false)) {
                "integer".to_string()
            } else {
                "number".to_string()
            }
        }
        Value::String(_) => "string".to_string(),
        Value::Array(_) => "array".to_string(),
        Value::Object(_) => "object".to_string(),
    }
}

fn json_type_str(types: &Value) -> String {
    match types {
        Value::String(s) => s.clone(),
        Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect::<Vec<_>>()
            .join(" | "),
        _ => "any".to_string(),
    }
}

fn check_format(fmt: &str, s: &str) -> bool {
    match fmt {
        "email" => {
            // Basic email check
            s.contains('@') && s.contains('.')
        }
        "uri" | "uri-reference" => {
            // Basic URI check
            s.contains("://") || s.starts_with('/') || s.starts_with("#")
        }
        "date-time" => {
            // ISO 8601 basic check
            Regex::new(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}")
                .map(|re| re.is_match(s))
                .unwrap_or(true)
        }
        "date" => Regex::new(r"^\d{4}-\d{2}-\d{2}$")
            .map(|re| re.is_match(s))
            .unwrap_or(true),
        "uuid" => Regex::new(
            r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        )
        .map(|re| re.is_match(s))
        .unwrap_or(true),
        "ipv4" => Regex::new(r"^(\d{1,3}\.){3}\d{1,3}$")
            .map(|re| re.is_match(s))
            .unwrap_or(true),
        "ipv6" => s.contains(':'),
        _ => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn valid_string() {
        let schema = json!({"type": "string"});
        assert!(validate(&schema, &json!("hello")).is_ok());
    }

    #[test]
    fn invalid_string_type() {
        let schema = json!({"type": "string"});
        let err = validate(&schema, &json!(42)).unwrap_err();
        assert!(err.message.contains("Expected type string"));
    }

    #[test]
    fn required_property_missing() {
        let schema = json!({
            "type": "object",
            "required": ["name"],
            "properties": {
                "name": {"type": "string"}
            }
        });
        let err = validate(&schema, &json!({})).unwrap_err();
        assert!(err.message.contains("Missing required property: name"));
    }

    #[test]
    fn nested_property_validation() {
        let schema = json!({
            "type": "object",
            "properties": {
                "user": {
                    "type": "object",
                    "properties": {
                        "age": {"type": "integer", "minimum": 0}
                    }
                }
            }
        });
        assert!(validate(&schema, &json!({"user": {"age": 25}})).is_ok());
        let err = validate(&schema, &json!({"user": {"age": -1}})).unwrap_err();
        assert!(err.message.contains("minimum"));
    }

    #[test]
    fn array_items_validation() {
        let schema = json!({
            "type": "array",
            "items": {"type": "integer"}
        });
        assert!(validate(&schema, &json!([1, 2, 3])).is_ok());
        let err = validate(&schema, &json!([1, "two", 3])).unwrap_err();
        assert!(err.message.contains("Expected type integer"));
    }

    #[test]
    fn enum_validation() {
        let schema = json!({"enum": ["red", "green", "blue"]});
        assert!(validate(&schema, &json!("red")).is_ok());
        let err = validate(&schema, &json!("yellow")).unwrap_err();
        assert!(err.message.contains("enum"));
    }

    #[test]
    fn pattern_validation() {
        let schema = json!({"type": "string", "pattern": "^[a-z]+$"});
        assert!(validate(&schema, &json!("hello")).is_ok());
        let err = validate(&schema, &json!("Hello123")).unwrap_err();
        assert!(err.message.contains("pattern"));
    }

    #[test]
    fn additional_properties_false() {
        let schema = json!({
            "type": "object",
            "properties": {
                "name": {"type": "string"}
            },
            "additionalProperties": false
        });
        assert!(validate(&schema, &json!({"name": "test"})).is_ok());
        let err = validate(&schema, &json!({"name": "test", "extra": 1})).unwrap_err();
        assert!(err.message.contains("Additional property not allowed"));
    }
}
