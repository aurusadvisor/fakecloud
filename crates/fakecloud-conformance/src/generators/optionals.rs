//! Strategy 3: Optionals permutation.
//!
//! Generates:
//! - A "required-only" variant (only required fields)
//! - An "all-fields" variant (every field populated)
//! - One variant per optional field (required + that one optional field)

use serde_json::Value;
use std::collections::HashMap;

use super::{
    build_full_input, build_required_input, default_value_for_shape, Expectation, Strategy,
    TestVariant,
};
use crate::smithy::ServiceModel;

pub fn generate(
    model: &ServiceModel,
    input_shape_id: &str,
    overrides: &HashMap<String, Value>,
) -> Vec<TestVariant> {
    let mut variants = Vec::new();

    let members = super::get_members(model, input_shape_id);
    let optional_count = members.iter().filter(|m| !m.required).count();

    // Required-only variant
    let required_input = build_required_input(model, input_shape_id, overrides);
    variants.push(TestVariant {
        name: "required_only".to_string(),
        strategy: Strategy::Optionals,
        input: required_input,
        expectation: Expectation::Success,
        expected_output: None,
    });

    // All-fields variant (only when there are 2+ optional fields, otherwise it
    // duplicates required_only or the single optional_* variant)
    if optional_count >= 2 {
        let full_input = build_full_input(model, input_shape_id, overrides);
        variants.push(TestVariant {
            name: "all_fields".to_string(),
            strategy: Strategy::Optionals,
            input: full_input,
            expectation: Expectation::Success,
            expected_output: None,
        });
    }

    // One variant per optional field
    for member in members {
        if member.required {
            continue;
        }

        let mut input = build_required_input(model, input_shape_id, overrides);
        let val = if let Some(override_val) = overrides.get(&member.name) {
            override_val.clone()
        } else {
            default_value_for_shape(model, &member.target, 0)
        };

        if let Value::Object(ref mut obj) = input {
            obj.insert(member.name.clone(), val);
        }

        variants.push(TestVariant {
            name: format!("optional_{}", member.name),
            strategy: Strategy::Optionals,
            input,
            expectation: Expectation::Success,
            expected_output: None,
        });
    }

    variants
}
