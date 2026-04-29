//! Strategy 5: Real-world examples from model.
//!
//! Some Smithy models include `smithy.api#examples` traits on operations
//! with actual request/response pairs. We use these as golden test cases.

use super::{Expectation, Strategy, TestVariant};
use crate::smithy::ShapeTraits;

pub fn generate(traits: &ShapeTraits) -> Vec<TestVariant> {
    traits
        .examples
        .iter()
        .enumerate()
        .map(|(i, example)| TestVariant {
            name: format!(
                "example_{}_{}",
                i,
                example
                    .title
                    .replace(' ', "_")
                    .replace(|c: char| !c.is_alphanumeric() && c != '_', "")
            ),
            strategy: Strategy::Examples,
            input: example.input.clone(),
            expectation: Expectation::Success,
            expected_output: None,
        })
        .collect()
}
