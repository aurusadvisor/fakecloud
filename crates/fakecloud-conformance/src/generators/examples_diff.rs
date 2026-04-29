//! Strategy 7: documented `@examples` output diff.
//!
//! AWS commits canonical request/response pairs to its Smithy models via
//! the `smithy.api#examples` trait. The existing `examples` strategy sends
//! the documented input. This strategy reuses the same input but additionally
//! carries the documented `output` so the probe layer can deep-diff the
//! live response against AWS's own answer.
//!
//! The diff is structural, not value-equality: every leaf path that exists
//! in the documented output must also exist (with matching JSON type) in
//! the live response. Placeholder string values like `"examplebucket"` are
//! intentionally not compared. This catches "field is optional in Smithy
//! but AWS always emits it" bugs (#816 — `BucketRegion` on `ListBuckets`).

use super::{Expectation, Strategy, TestVariant};
use crate::smithy::ShapeTraits;
use serde_json::Value;

pub fn generate(traits: &ShapeTraits) -> Vec<TestVariant> {
    traits
        .examples
        .iter()
        .enumerate()
        .filter(|(_, ex)| !is_empty_output(&ex.output))
        .map(|(i, example)| TestVariant {
            name: format!(
                "examples_diff_{}_{}",
                i,
                example
                    .title
                    .replace(' ', "_")
                    .replace(|c: char| !c.is_alphanumeric() && c != '_', "")
            ),
            strategy: Strategy::ExamplesDiff,
            input: example.input.clone(),
            expectation: Expectation::Success,
            expected_output: Some(example.output.clone()),
            followup: None,
        })
        .collect()
}

/// `@examples` entries with no documented output (or with `output: {}`)
/// give the diff nothing to assert against. Skip them so we don't pad the
/// variant count with empty checks.
fn is_empty_output(output: &Value) -> bool {
    match output {
        Value::Null => true,
        Value::Object(map) => map.is_empty(),
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::smithy::OperationExample;
    use serde_json::json;

    fn traits_with_examples(examples: Vec<OperationExample>) -> ShapeTraits {
        ShapeTraits {
            examples,
            ..ShapeTraits::default()
        }
    }

    #[test]
    fn skips_empty_output_examples() {
        let traits = traits_with_examples(vec![OperationExample {
            title: "no documented output".to_string(),
            input: json!({"Bucket": "x"}),
            output: json!({}),
        }]);
        assert!(generate(&traits).is_empty());
    }

    #[test]
    fn carries_documented_output() {
        let traits = traits_with_examples(vec![OperationExample {
            title: "List my buckets".to_string(),
            input: json!({}),
            output: json!({
                "Buckets": [{"Name": "examplebucket", "BucketRegion": "us-east-1"}],
                "Owner": {"ID": "123"}
            }),
        }]);
        let variants = generate(&traits);
        assert_eq!(variants.len(), 1);
        assert_eq!(variants[0].strategy, Strategy::ExamplesDiff);
        let expected = variants[0].expected_output.as_ref().unwrap();
        assert_eq!(expected["Buckets"][0]["BucketRegion"], "us-east-1");
    }
}
