//! Strategy 1: Constraint-aware boundary value generation.
//!
//! For each constrained field in the input, generate variants that exercise
//! min, max, and mid-range values.

use serde_json::Value;
use std::collections::HashMap;

use super::{build_required_input, Expectation, Strategy, TestVariant};
use crate::smithy::{self, ServiceModel, ShapeType};

pub fn generate(
    model: &ServiceModel,
    input_shape_id: &str,
    overrides: &HashMap<String, Value>,
) -> Vec<TestVariant> {
    let mut variants = Vec::new();

    let members = super::get_members(model, input_shape_id);

    for member in members {
        let target_shape = model
            .shapes
            .get(&member.target)
            .or_else(|| smithy::prelude_shape_type(&member.target).map(|_| &*PLACEHOLDER_SHAPE));

        let shape = match target_shape {
            Some(s) => s,
            None => continue,
        };

        // Merge constraints from the target shape's traits and the member's own traits.
        // Member-level constraints take precedence when present.
        let merged = merge_traits(&shape.traits, &member.traits);

        let has_length = merged.length_min.is_some() || merged.length_max.is_some();
        let has_range = merged.range_min.is_some() || merged.range_max.is_some();

        if !has_length && !has_range {
            continue;
        }

        // String length boundaries
        if has_length {
            if let ShapeType::String { .. } = &shape.shape_type {
                if let Some(min) = merged.length_min {
                    let min = min as usize;
                    let val = "a".repeat(min);
                    let mut input = build_required_input(model, input_shape_id, overrides);
                    if let Value::Object(ref mut obj) = input {
                        obj.insert(member.name.clone(), Value::String(val));
                    }
                    variants.push(TestVariant {
                        name: format!("boundary_len_min_{}_{}", member.name, min),
                        strategy: Strategy::Boundary,
                        input,
                        expectation: Expectation::Success,
                        expected_output: None,
                        followup: None,
                    });
                }
                if let Some(max) = merged.length_max {
                    let max = max as usize;
                    if max <= 10000 {
                        // Don't generate enormous strings
                        let val = "a".repeat(max);
                        let mut input = build_required_input(model, input_shape_id, overrides);
                        if let Value::Object(ref mut obj) = input {
                            obj.insert(member.name.clone(), Value::String(val));
                        }
                        variants.push(TestVariant {
                            name: format!("boundary_len_max_{}_{}", member.name, max),
                            strategy: Strategy::Boundary,
                            input,
                            expectation: Expectation::Success,
                            expected_output: None,
                            followup: None,
                        });
                    }
                }
                if let (Some(min), Some(max)) = (merged.length_min, merged.length_max) {
                    let mid = ((min + max) / 2) as usize;
                    if mid > 0 && mid < 10000 {
                        let val = "a".repeat(mid);
                        let mut input = build_required_input(model, input_shape_id, overrides);
                        if let Value::Object(ref mut obj) = input {
                            obj.insert(member.name.clone(), Value::String(val));
                        }
                        variants.push(TestVariant {
                            name: format!("boundary_len_mid_{}_{}", member.name, mid),
                            strategy: Strategy::Boundary,
                            input,
                            expectation: Expectation::Success,
                            expected_output: None,
                            followup: None,
                        });
                    }
                }
            }

            // List/Map length boundaries
            if let ShapeType::List { member_target } = &shape.shape_type {
                if let Some(min) = merged.length_min {
                    let min = min as usize;
                    if min > 0 && min <= 100 {
                        let items: Vec<Value> = (0..min)
                            .map(|_| super::default_value_for_shape(model, member_target, 0))
                            .collect();
                        let mut input = build_required_input(model, input_shape_id, overrides);
                        if let Value::Object(ref mut obj) = input {
                            obj.insert(member.name.clone(), Value::Array(items));
                        }
                        variants.push(TestVariant {
                            name: format!("boundary_list_min_{}_{}", member.name, min),
                            strategy: Strategy::Boundary,
                            input,
                            expectation: Expectation::Success,
                            expected_output: None,
                            followup: None,
                        });
                    }
                }
            }
        }

        // Numeric range boundaries
        if has_range {
            match &shape.shape_type {
                ShapeType::Integer | ShapeType::Long => {
                    if let Some(min) = merged.range_min {
                        let val = min as i64;
                        let mut input = build_required_input(model, input_shape_id, overrides);
                        if let Value::Object(ref mut obj) = input {
                            obj.insert(member.name.clone(), Value::Number(val.into()));
                        }
                        variants.push(TestVariant {
                            name: format!("boundary_range_min_{}_{}", member.name, val),
                            strategy: Strategy::Boundary,
                            input,
                            expectation: Expectation::Success,
                            expected_output: None,
                            followup: None,
                        });
                    }
                    if let Some(max) = merged.range_max {
                        let val = max as i64;
                        let mut input = build_required_input(model, input_shape_id, overrides);
                        if let Value::Object(ref mut obj) = input {
                            obj.insert(member.name.clone(), Value::Number(val.into()));
                        }
                        variants.push(TestVariant {
                            name: format!("boundary_range_max_{}_{}", member.name, val),
                            strategy: Strategy::Boundary,
                            input,
                            expectation: Expectation::Success,
                            expected_output: None,
                            followup: None,
                        });
                    }
                    if let (Some(min), Some(max)) = (merged.range_min, merged.range_max) {
                        let mid = ((min + max) / 2.0) as i64;
                        let mut input = build_required_input(model, input_shape_id, overrides);
                        if let Value::Object(ref mut obj) = input {
                            obj.insert(member.name.clone(), Value::Number(mid.into()));
                        }
                        variants.push(TestVariant {
                            name: format!("boundary_range_mid_{}_{}", member.name, mid),
                            strategy: Strategy::Boundary,
                            input,
                            expectation: Expectation::Success,
                            expected_output: None,
                            followup: None,
                        });
                    }
                }
                _ => {}
            }
        }
    }

    variants
}

/// Merge target shape traits with member-level traits. Member traits take precedence.
fn merge_traits(
    shape_traits: &crate::smithy::ShapeTraits,
    member_traits: &crate::smithy::ShapeTraits,
) -> crate::smithy::ShapeTraits {
    crate::smithy::ShapeTraits {
        length_min: member_traits.length_min.or(shape_traits.length_min),
        length_max: member_traits.length_max.or(shape_traits.length_max),
        range_min: member_traits.range_min.or(shape_traits.range_min),
        range_max: member_traits.range_max.or(shape_traits.range_max),
        pattern: member_traits
            .pattern
            .clone()
            .or(shape_traits.pattern.clone()),
        ..shape_traits.clone()
    }
}

// Placeholder for prelude shapes that have no traits
use crate::smithy::Shape;
use std::sync::LazyLock;

static PLACEHOLDER_SHAPE: LazyLock<Shape> = LazyLock::new(|| Shape {
    shape_id: String::new(),
    shape_type: ShapeType::String { enum_values: None },
    traits: crate::smithy::ShapeTraits::default(),
});
