//! Strategy 2: Enum exhaustion.
//!
//! For each enum field in the input, generate a variant for every enum value.
//! When multiple enum fields exist, use cartesian product up to a cap.

use serde_json::Value;
use std::collections::HashMap;

use super::{build_required_input, Expectation, Strategy, TestVariant};
use crate::smithy::{ServiceModel, ShapeType};

/// Maximum number of variants from cartesian product of multiple enum fields.
const MAX_CARTESIAN_VARIANTS: usize = 50;

pub fn generate(
    model: &ServiceModel,
    input_shape_id: &str,
    overrides: &HashMap<String, Value>,
) -> Vec<TestVariant> {
    let members = super::get_members(model, input_shape_id);

    // Collect enum fields and their values
    let mut enum_fields: Vec<(String, Vec<String>)> = Vec::new();

    for member in members {
        let values = get_enum_values(model, &member.target);
        if !values.is_empty() {
            enum_fields.push((member.name.clone(), values));
        }
    }

    if enum_fields.is_empty() {
        return Vec::new();
    }

    // If single enum field, generate one variant per value
    if enum_fields.len() == 1 {
        let (field_name, values) = &enum_fields[0];
        return values
            .iter()
            .map(|val| {
                let mut input = build_required_input(model, input_shape_id, overrides);
                if let Value::Object(ref mut obj) = input {
                    obj.insert(field_name.clone(), Value::String(val.clone()));
                }
                TestVariant {
                    name: format!("enum_{}__{}", field_name, val),
                    strategy: Strategy::EnumExhaust,
                    input,
                    expectation: Expectation::Success,
                    expected_output: None,
                    followup: None,
                }
            })
            .collect();
    }

    // Multiple enum fields: cartesian product with cap
    let mut variants = Vec::new();
    let total_combos: usize = enum_fields.iter().map(|(_, v)| v.len()).product();

    if total_combos <= MAX_CARTESIAN_VARIANTS {
        // Full cartesian product
        let combos = cartesian_product(&enum_fields);
        for combo in combos {
            let mut input = build_required_input(model, input_shape_id, overrides);
            let mut name_parts = Vec::new();
            if let Value::Object(ref mut obj) = input {
                for (field, val) in &combo {
                    obj.insert(field.clone(), Value::String(val.clone()));
                    name_parts.push(format!("{}={}", field, val));
                }
            }
            variants.push(TestVariant {
                name: format!("enum_combo_{}", name_parts.join("_")),
                strategy: Strategy::EnumExhaust,
                input,
                expectation: Expectation::Success,
                expected_output: None,
                followup: None,
            });
        }
    } else {
        // Too many combos — test each enum value individually (one-at-a-time)
        for (field_name, values) in &enum_fields {
            for val in values {
                let mut input = build_required_input(model, input_shape_id, overrides);
                if let Value::Object(ref mut obj) = input {
                    obj.insert(field_name.clone(), Value::String(val.clone()));
                }
                variants.push(TestVariant {
                    name: format!("enum_{}__{}", field_name, val),
                    strategy: Strategy::EnumExhaust,
                    input,
                    expectation: Expectation::Success,
                    expected_output: None,
                    followup: None,
                });
            }
        }
    }

    variants
}

fn get_enum_values(model: &ServiceModel, shape_id: &str) -> Vec<String> {
    let shape = match model.shapes.get(shape_id) {
        Some(s) => s,
        None => return Vec::new(),
    };

    match &shape.shape_type {
        ShapeType::String {
            enum_values: Some(values),
        } => values.iter().map(|v| v.value.clone()).collect(),
        ShapeType::Enum { values } => values.iter().map(|v| v.value.clone()).collect(),
        _ => Vec::new(),
    }
}

fn cartesian_product(fields: &[(String, Vec<String>)]) -> Vec<Vec<(String, String)>> {
    if fields.is_empty() {
        return vec![vec![]];
    }

    let (ref name, ref values) = fields[0];
    let rest = cartesian_product(&fields[1..]);

    let mut result = Vec::new();
    for val in values {
        for combo in &rest {
            let mut new_combo = vec![(name.clone(), val.clone())];
            new_combo.extend(combo.clone());
            result.push(new_combo);
        }
    }
    result
}
