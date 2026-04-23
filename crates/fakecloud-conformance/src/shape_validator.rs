//! Response shape validation against Smithy models.
//!
//! Validates that HTTP response bodies from fakecloud match the expected output
//! shape structure defined in the Smithy model.

use serde_json::Value;

use crate::probe::Protocol;
use crate::smithy::{effective_shape_type, ServiceModel, ShapeType};

const MAX_DEPTH: usize = 10;

/// A violation found when validating a response body against the expected shape.
#[derive(Debug, Clone)]
pub enum ShapeViolation {
    /// A required field defined in the model is missing from the response.
    MissingField { path: String, field: String },
    /// A field is present but has the wrong JSON type.
    WrongType {
        path: String,
        expected: String,
        got: String,
    },
    /// A field is present in the response but not defined in the model.
    UnexpectedField { path: String, field: String },
    /// The response body could not be parsed.
    ParseError { message: String },
}

impl std::fmt::Display for ShapeViolation {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ShapeViolation::MissingField { path, field } => {
                write!(f, "missing required field '{}' at {}", field, path)
            }
            ShapeViolation::WrongType {
                path,
                expected,
                got,
            } => {
                write!(
                    f,
                    "wrong type at {}: expected {}, got {}",
                    path, expected, got
                )
            }
            ShapeViolation::UnexpectedField { path, field } => {
                write!(f, "unexpected field '{}' at {}", field, path)
            }
            ShapeViolation::ParseError { message } => {
                write!(f, "parse error: {}", message)
            }
        }
    }
}

/// Validate a response body against the expected output shape from the Smithy model.
///
/// Returns a list of violations. An empty list means the response conforms to the model.
pub fn validate_response(
    model: &ServiceModel,
    output_shape_id: &str,
    response_body: &str,
    protocol: Protocol,
) -> Vec<ShapeViolation> {
    if response_body.is_empty() {
        // An empty body is valid if the output shape is Unit or has no required members.
        if let Some(ShapeType::Structure { members }) = effective_shape_type(model, output_shape_id)
        {
            let required: Vec<_> = members.iter().filter(|m| m.required).collect();
            if !required.is_empty() {
                return required
                    .iter()
                    .map(|m| ShapeViolation::MissingField {
                        path: "$".to_string(),
                        field: m.name.clone(),
                    })
                    .collect();
            }
        }
        return Vec::new();
    }

    match protocol {
        Protocol::Json { .. } | Protocol::Rest => {
            validate_json_response(model, output_shape_id, response_body)
        }
        Protocol::Query => validate_query_response(model, output_shape_id, response_body),
    }
}

/// Validate a JSON protocol response body.
fn validate_json_response(
    model: &ServiceModel,
    output_shape_id: &str,
    response_body: &str,
) -> Vec<ShapeViolation> {
    let value: Value = match serde_json::from_str(response_body) {
        Ok(v) => v,
        Err(e) => {
            return vec![ShapeViolation::ParseError {
                message: format!("invalid JSON: {}", e),
            }];
        }
    };

    let mut violations = Vec::new();
    validate_shape(model, output_shape_id, &value, "$", 0, &mut violations);
    violations
}

/// Validate a Query protocol (XML) response body.
///
/// Query protocol responses wrap their result in a `<ActionNameResponse><ActionNameResult>` element.
/// We extract field names from the XML and check required fields are present.
fn validate_query_response(
    model: &ServiceModel,
    output_shape_id: &str,
    response_body: &str,
) -> Vec<ShapeViolation> {
    let shape_type = match effective_shape_type(model, output_shape_id) {
        Some(st) => st,
        None => return Vec::new(),
    };

    let members = match &shape_type {
        ShapeType::Structure { members } => members,
        _ => return Vec::new(),
    };

    // Extract XML element names present in the response body using simple text scanning.
    // This avoids pulling in an XML parser dependency for what is essentially a field-presence check.
    let xml_fields = extract_xml_field_names(response_body);

    let mut violations = Vec::new();

    for member in members {
        if member.required && !xml_fields.contains(&member.name.as_str()) {
            violations.push(ShapeViolation::MissingField {
                path: "$".to_string(),
                field: member.name.clone(),
            });
        }
    }

    violations
}

/// Extract top-level-ish XML element names from a response body.
/// This is a best-effort extraction — it finds all `<ElementName>` opening tags.
fn extract_xml_field_names(xml: &str) -> Vec<&str> {
    let mut names = Vec::new();
    let mut rest = xml;
    while let Some(start) = rest.find('<') {
        rest = &rest[start + 1..];
        // Skip closing tags, processing instructions, comments
        if rest.starts_with('/') || rest.starts_with('?') || rest.starts_with('!') {
            continue;
        }
        // Find end of tag name
        if let Some(end) = rest.find(['>', ' ', '/']) {
            let tag_name = &rest[..end];
            if !tag_name.is_empty() {
                names.push(tag_name);
            }
        }
    }
    names
}

/// Recursively validate a JSON value against a shape definition.
fn validate_shape(
    model: &ServiceModel,
    shape_id: &str,
    value: &Value,
    path: &str,
    depth: usize,
    violations: &mut Vec<ShapeViolation>,
) {
    if depth >= MAX_DEPTH {
        return;
    }

    let shape_type = match effective_shape_type(model, shape_id) {
        Some(st) => st,
        None => return, // Unknown shape; skip validation
    };

    match &shape_type {
        ShapeType::Structure { members } => {
            validate_structure(model, members, value, path, depth, violations);
        }
        ShapeType::List { member_target } => {
            validate_list(model, member_target, value, path, depth, violations);
        }
        ShapeType::Map { value_target, .. } => {
            validate_map(model, value_target, value, path, depth, violations);
        }
        ShapeType::Union { members } => {
            // A union should be an object with exactly one key matching a member name.
            if let Value::Object(obj) = value {
                if obj.len() != 1 {
                    violations.push(ShapeViolation::WrongType {
                        path: path.to_string(),
                        expected: "union (object with exactly 1 member)".to_string(),
                        got: format!("object with {} members", obj.len()),
                    });
                }
                for (key, val) in obj {
                    let member = members.iter().find(|m| {
                        let member_key = m.traits.json_name.as_deref().unwrap_or(&m.name);
                        member_key == key.as_str()
                    });
                    if let Some(member) = member {
                        let child_path = format!("{}.{}", path, key);
                        validate_shape(
                            model,
                            &member.target,
                            val,
                            &child_path,
                            depth + 1,
                            violations,
                        );
                    } else {
                        violations.push(ShapeViolation::UnexpectedField {
                            path: path.to_string(),
                            field: key.clone(),
                        });
                    }
                }
            } else {
                violations.push(ShapeViolation::WrongType {
                    path: path.to_string(),
                    expected: "object (union)".to_string(),
                    got: json_type_name(value).to_string(),
                });
            }
        }
        ShapeType::String { .. } | ShapeType::Enum { .. } => {
            if !value.is_string() {
                violations.push(ShapeViolation::WrongType {
                    path: path.to_string(),
                    expected: "string".to_string(),
                    got: json_type_name(value).to_string(),
                });
            }
        }
        ShapeType::Integer | ShapeType::Long | ShapeType::IntEnum { .. } => {
            if !(value.is_i64() || value.is_u64()) {
                violations.push(ShapeViolation::WrongType {
                    path: path.to_string(),
                    expected: "integer".to_string(),
                    got: json_type_name(value).to_string(),
                });
            }
        }
        ShapeType::Float | ShapeType::Double => {
            if !value.is_number() {
                violations.push(ShapeViolation::WrongType {
                    path: path.to_string(),
                    expected: "number".to_string(),
                    got: json_type_name(value).to_string(),
                });
            }
        }
        ShapeType::Boolean => {
            if !value.is_boolean() {
                violations.push(ShapeViolation::WrongType {
                    path: path.to_string(),
                    expected: "boolean".to_string(),
                    got: json_type_name(value).to_string(),
                });
            }
        }
        ShapeType::Blob => {
            // Blobs are base64-encoded strings in JSON
            if !value.is_string() {
                violations.push(ShapeViolation::WrongType {
                    path: path.to_string(),
                    expected: "string (base64 blob)".to_string(),
                    got: json_type_name(value).to_string(),
                });
            }
        }
        ShapeType::Timestamp => {
            // Timestamps can be strings or numbers depending on format
            if !value.is_string() && !value.is_number() {
                violations.push(ShapeViolation::WrongType {
                    path: path.to_string(),
                    expected: "string or number (timestamp)".to_string(),
                    got: json_type_name(value).to_string(),
                });
            }
        }
        // Service, Operation, Resource shapes are not value types
        ShapeType::Service | ShapeType::Operation | ShapeType::Resource => {}
    }
}

/// Validate a JSON value against a structure shape.
fn validate_structure(
    model: &ServiceModel,
    members: &[crate::smithy::Member],
    value: &Value,
    path: &str,
    depth: usize,
    violations: &mut Vec<ShapeViolation>,
) {
    let obj = match value.as_object() {
        Some(o) => o,
        None => {
            violations.push(ShapeViolation::WrongType {
                path: path.to_string(),
                expected: "object".to_string(),
                got: json_type_name(value).to_string(),
            });
            return;
        }
    };

    // Per-member key: `@jsonName` trait on the member (or its target shape)
    // wins; otherwise the member's own name. AWS restJson1 services commonly
    // override with camelCase (e.g. `Items` -> `items`).
    let member_key = |m: &crate::smithy::Member| -> String {
        if let Some(name) = &m.traits.json_name {
            return name.clone();
        }
        if let Some(shape) = model.shapes.get(&m.target) {
            if let Some(name) = &shape.traits.json_name {
                return name.clone();
            }
        }
        m.name.clone()
    };

    // Check required fields are present
    for member in members {
        let key = member_key(member);
        if member.required && !obj.contains_key(&key) {
            violations.push(ShapeViolation::MissingField {
                path: path.to_string(),
                field: key,
            });
        }
    }

    // Validate present fields
    for (key, val) in obj {
        if let Some(member) = members.iter().find(|m| member_key(m) == *key) {
            let child_path = format!("{}.{}", path, key);
            validate_shape(
                model,
                &member.target,
                val,
                &child_path,
                depth + 1,
                violations,
            );
        } else {
            violations.push(ShapeViolation::UnexpectedField {
                path: path.to_string(),
                field: key.clone(),
            });
        }
    }
}

/// Validate a JSON value against a list shape.
fn validate_list(
    model: &ServiceModel,
    member_target: &str,
    value: &Value,
    path: &str,
    depth: usize,
    violations: &mut Vec<ShapeViolation>,
) {
    let arr = match value.as_array() {
        Some(a) => a,
        None => {
            violations.push(ShapeViolation::WrongType {
                path: path.to_string(),
                expected: "array".to_string(),
                got: json_type_name(value).to_string(),
            });
            return;
        }
    };

    for (i, item) in arr.iter().enumerate() {
        let child_path = format!("{}[{}]", path, i);
        validate_shape(
            model,
            member_target,
            item,
            &child_path,
            depth + 1,
            violations,
        );
    }
}

/// Validate a JSON value against a map shape.
fn validate_map(
    model: &ServiceModel,
    value_target: &str,
    value: &Value,
    path: &str,
    depth: usize,
    violations: &mut Vec<ShapeViolation>,
) {
    let obj = match value.as_object() {
        Some(o) => o,
        None => {
            violations.push(ShapeViolation::WrongType {
                path: path.to_string(),
                expected: "object (map)".to_string(),
                got: json_type_name(value).to_string(),
            });
            return;
        }
    };

    for (key, val) in obj {
        let child_path = format!("{}[{:?}]", path, key);
        validate_shape(model, value_target, val, &child_path, depth + 1, violations);
    }
}

/// Return a human-readable name for a JSON value type.
fn json_type_name(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "boolean",
        Value::Number(_) => "number",
        Value::String(_) => "string",
        Value::Array(_) => "array",
        Value::Object(_) => "object",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smithy::{Member, Shape, ShapeTraits};
    use std::collections::HashMap;

    /// Build a minimal ServiceModel for testing.
    fn test_model() -> ServiceModel {
        let mut shapes = HashMap::new();

        // A simple output structure: { "QueueUrl": string (required), "Tags": map }
        shapes.insert(
            "test#CreateQueueOutput".to_string(),
            Shape {
                shape_id: "test#CreateQueueOutput".to_string(),
                shape_type: ShapeType::Structure {
                    members: vec![
                        Member {
                            name: "QueueUrl".to_string(),
                            target: "smithy.api#String".to_string(),
                            required: true,
                            traits: ShapeTraits::default(),
                        },
                        Member {
                            name: "Tags".to_string(),
                            target: "test#TagMap".to_string(),
                            required: false,
                            traits: ShapeTraits::default(),
                        },
                    ],
                },
                traits: ShapeTraits::default(),
            },
        );

        // TagMap: map<String, String>
        shapes.insert(
            "test#TagMap".to_string(),
            Shape {
                shape_id: "test#TagMap".to_string(),
                shape_type: ShapeType::Map {
                    key_target: "smithy.api#String".to_string(),
                    value_target: "smithy.api#String".to_string(),
                },
                traits: ShapeTraits::default(),
            },
        );

        // A structure with a list member
        shapes.insert(
            "test#ListOutput".to_string(),
            Shape {
                shape_id: "test#ListOutput".to_string(),
                shape_type: ShapeType::Structure {
                    members: vec![Member {
                        name: "Items".to_string(),
                        target: "test#ItemList".to_string(),
                        required: true,
                        traits: ShapeTraits::default(),
                    }],
                },
                traits: ShapeTraits::default(),
            },
        );

        shapes.insert(
            "test#ItemList".to_string(),
            Shape {
                shape_id: "test#ItemList".to_string(),
                shape_type: ShapeType::List {
                    member_target: "test#Item".to_string(),
                },
                traits: ShapeTraits::default(),
            },
        );

        shapes.insert(
            "test#Item".to_string(),
            Shape {
                shape_id: "test#Item".to_string(),
                shape_type: ShapeType::Structure {
                    members: vec![
                        Member {
                            name: "Id".to_string(),
                            target: "smithy.api#Integer".to_string(),
                            required: true,
                            traits: ShapeTraits::default(),
                        },
                        Member {
                            name: "Name".to_string(),
                            target: "smithy.api#String".to_string(),
                            required: true,
                            traits: ShapeTraits::default(),
                        },
                    ],
                },
                traits: ShapeTraits::default(),
            },
        );

        ServiceModel {
            service_name: "test".to_string(),
            operations: Vec::new(),
            shapes,
        }
    }

    #[test]
    fn valid_json_response() {
        let model = test_model();
        let body = r#"{"QueueUrl": "http://localhost:4566/queue/test"}"#;
        let violations = validate_response(
            &model,
            "test#CreateQueueOutput",
            body,
            Protocol::Json {
                target_prefix: "Test",
            },
        );
        assert!(
            violations.is_empty(),
            "expected no violations: {:?}",
            violations
        );
    }

    #[test]
    fn missing_required_field() {
        let model = test_model();
        let body = r#"{"Tags": {}}"#;
        let violations = validate_response(
            &model,
            "test#CreateQueueOutput",
            body,
            Protocol::Json {
                target_prefix: "Test",
            },
        );
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            &violations[0],
            ShapeViolation::MissingField { field, .. } if field == "QueueUrl"
        ));
    }

    #[test]
    fn wrong_type_field() {
        let model = test_model();
        let body = r#"{"QueueUrl": 123}"#;
        let violations = validate_response(
            &model,
            "test#CreateQueueOutput",
            body,
            Protocol::Json {
                target_prefix: "Test",
            },
        );
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            &violations[0],
            ShapeViolation::WrongType { expected, got, .. } if expected == "string" && got == "number"
        ));
    }

    #[test]
    fn unexpected_field() {
        let model = test_model();
        let body = r#"{"QueueUrl": "http://localhost/q", "Bogus": true}"#;
        let violations = validate_response(
            &model,
            "test#CreateQueueOutput",
            body,
            Protocol::Json {
                target_prefix: "Test",
            },
        );
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            &violations[0],
            ShapeViolation::UnexpectedField { field, .. } if field == "Bogus"
        ));
    }

    #[test]
    fn nested_list_validation() {
        let model = test_model();
        let body = r#"{"Items": [{"Id": 1, "Name": "a"}, {"Id": "bad", "Name": "b"}]}"#;
        let violations = validate_response(
            &model,
            "test#ListOutput",
            body,
            Protocol::Json {
                target_prefix: "Test",
            },
        );
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            &violations[0],
            ShapeViolation::WrongType { path, expected, got } if path == "$.Items[1].Id" && expected == "integer" && got == "string"
        ));
    }

    #[test]
    fn map_validation() {
        let model = test_model();
        let body = r#"{"QueueUrl": "http://localhost/q", "Tags": {"env": "dev", "bad": 42}}"#;
        let violations = validate_response(
            &model,
            "test#CreateQueueOutput",
            body,
            Protocol::Json {
                target_prefix: "Test",
            },
        );
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            &violations[0],
            ShapeViolation::WrongType { expected, got, .. } if expected == "string" && got == "number"
        ));
    }

    #[test]
    fn invalid_json_body() {
        let model = test_model();
        let body = "not json at all";
        let violations = validate_response(
            &model,
            "test#CreateQueueOutput",
            body,
            Protocol::Json {
                target_prefix: "Test",
            },
        );
        assert_eq!(violations.len(), 1);
        assert!(matches!(&violations[0], ShapeViolation::ParseError { .. }));
    }

    #[test]
    fn empty_body_with_required_fields() {
        let model = test_model();
        let violations = validate_response(
            &model,
            "test#CreateQueueOutput",
            "",
            Protocol::Json {
                target_prefix: "Test",
            },
        );
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            &violations[0],
            ShapeViolation::MissingField { field, .. } if field == "QueueUrl"
        ));
    }

    #[test]
    fn query_protocol_checks_required_fields() {
        let model = test_model();
        let xml = r#"<CreateQueueResponse><CreateQueueResult><QueueUrl>http://localhost/q</QueueUrl></CreateQueueResult></CreateQueueResponse>"#;
        let violations = validate_response(&model, "test#CreateQueueOutput", xml, Protocol::Query);
        assert!(
            violations.is_empty(),
            "expected no violations: {:?}",
            violations
        );
    }

    #[test]
    fn query_protocol_missing_required_field() {
        let model = test_model();
        let xml = r#"<CreateQueueResponse><CreateQueueResult><Tags></Tags></CreateQueueResult></CreateQueueResponse>"#;
        let violations = validate_response(&model, "test#CreateQueueOutput", xml, Protocol::Query);
        assert_eq!(violations.len(), 1);
        assert!(matches!(
            &violations[0],
            ShapeViolation::MissingField { field, .. } if field == "QueueUrl"
        ));
    }

    #[test]
    fn rest_protocol_validates_as_json() {
        let model = test_model();
        let body = r#"{"QueueUrl": "http://localhost/q"}"#;
        let violations = validate_response(&model, "test#CreateQueueOutput", body, Protocol::Rest);
        assert!(
            violations.is_empty(),
            "expected no violations: {:?}",
            violations
        );
    }

    #[test]
    fn unknown_shape_is_lenient() {
        let model = test_model();
        let body = r#"{"anything": "goes"}"#;
        let violations = validate_response(
            &model,
            "test#DoesNotExist",
            body,
            Protocol::Json {
                target_prefix: "Test",
            },
        );
        assert!(violations.is_empty());
    }
}
