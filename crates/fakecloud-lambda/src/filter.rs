//! Lambda event source mapping filter criteria.
//!
//! Implements the EventBridge-style JSON pattern subset documented for
//! Lambda ESM `FilterCriteria`. A record is delivered when *any*
//! supplied pattern matches; a record is dropped when *every* pattern
//! fails to match.
//!
//! Operators implemented (matches AWS's documented surface):
//! - exact-string / number / boolean / null match
//! - `{"exists": bool}` — field presence
//! - `{"prefix": "..."}` / `{"suffix": "..."}` / `{"equals-ignore-case": "..."}`
//! - `{"anything-but": value | [values]}`
//! - `{"numeric": [op, n, op, n, ...]}` with `=`, `<`, `<=`, `>`, `>=`
//! - SQS body decode: when the pattern contains a top-level `body`
//!   key whose value is an object, the SQS message body is parsed as
//!   JSON before pattern matching, mirroring AWS behavior.

use serde_json::Value;

/// Compiled filter set. `patterns` parses the raw `Filters: [{Pattern: "..."}]`
/// strings into JSON objects once at create time.
#[derive(Debug, Clone, Default)]
pub struct FilterSet {
    patterns: Vec<Value>,
}

impl FilterSet {
    /// Build from the raw filter pattern strings stored on
    /// [`crate::state::EventSourceMapping::filter_patterns`]. Patterns
    /// that fail to parse are logged and dropped; pre-validation at
    /// [`Self::validate`] (called from `CreateEventSourceMapping`)
    /// keeps the live data clean.
    pub fn from_strings<I, S>(raw: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let patterns = raw
            .into_iter()
            .filter_map(|s| match serde_json::from_str::<Value>(s.as_ref()) {
                Ok(v) => Some(v),
                Err(err) => {
                    tracing::warn!(
                        pattern = s.as_ref(),
                        error = %err,
                        "lambda ESM filter pattern is invalid JSON; ignoring this pattern (other patterns still apply)"
                    );
                    None
                }
            })
            .collect();
        Self { patterns }
    }

    /// Validate raw filter patterns the same way real AWS rejects bad
    /// `FilterCriteria` at `CreateEventSourceMapping`. Returns the
    /// first invalid pattern's parse error so the service can surface
    /// it as `InvalidParameterValueException`.
    pub fn validate<I, S>(raw: I) -> Result<(), String>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        for s in raw {
            serde_json::from_str::<Value>(s.as_ref())
                .map_err(|err| format!("FilterCriteria pattern is invalid JSON: {err}"))?;
        }
        Ok(())
    }

    /// Returns `true` when the record matches at least one pattern, or
    /// when the filter set is empty (no filtering = pass-through).
    pub fn matches(&self, record: &Value) -> bool {
        if self.patterns.is_empty() {
            return true;
        }
        self.patterns.iter().any(|p| match_value(p, record))
    }

    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }
}

fn match_value(pattern: &Value, value: &Value) -> bool {
    // The top-level entry has the value present, so wrap as Some.
    eval_field(pattern, Some(value))
}

/// Evaluate `pattern` against an optional `value`. `None` means the
/// parent object did not contain the key the pattern targets — this
/// matters for the `exists` operator, which is defined in terms of
/// field *presence*, not value-is-null.
fn eval_field(pattern: &Value, value: Option<&Value>) -> bool {
    if let Value::Object(po) = pattern {
        if is_operator_object(po) {
            return apply_operator(po, value);
        }
    }
    match pattern {
        Value::Object(po) => match value {
            Some(Value::Object(vo)) => po.iter().all(|(k, sub_pattern)| {
                if k == "body" {
                    if let Some(Value::String(s)) = vo.get("body") {
                        if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                            return eval_field(sub_pattern, Some(&parsed));
                        }
                    }
                }
                eval_field(sub_pattern, vo.get(k))
            }),
            _ => false,
        },
        Value::Array(arr) => arr.iter().any(|p| eval_field(p, value)),
        scalar => match (scalar, value) {
            (Value::Null, Some(Value::Null)) => true,
            (Value::Bool(a), Some(Value::Bool(b))) => a == b,
            (Value::Number(a), Some(Value::Number(b))) => a == b,
            (Value::String(a), Some(Value::String(b))) => a == b,
            _ => false,
        },
    }
}

const OPERATOR_KEYS: &[&str] = &[
    "exists",
    "prefix",
    "suffix",
    "equals-ignore-case",
    "anything-but",
    "numeric",
];

fn is_operator_object(o: &serde_json::Map<String, Value>) -> bool {
    o.keys().any(|k| OPERATOR_KEYS.contains(&k.as_str()))
}

fn apply_operator(o: &serde_json::Map<String, Value>, value: Option<&Value>) -> bool {
    o.iter().all(|(op, arg)| match op.as_str() {
        // `exists` is the only operator defined in terms of *field
        // presence*. AWS treats `null` as present, so a literal
        // `{"foo": null}` matches `{"foo": [{"exists": true}]}`.
        "exists" => matches!(
            (arg, value),
            (Value::Bool(true), Some(_)) | (Value::Bool(false), None)
        ),
        op_name => match value {
            Some(v) => apply_value_operator(op_name, arg, v),
            None => false,
        },
    })
}

fn apply_value_operator(op: &str, arg: &Value, value: &Value) -> bool {
    match op {
        "prefix" => match (arg.as_str(), value.as_str()) {
            (Some(p), Some(s)) => s.starts_with(p),
            _ => false,
        },
        "suffix" => match (arg.as_str(), value.as_str()) {
            (Some(p), Some(s)) => s.ends_with(p),
            _ => false,
        },
        "equals-ignore-case" => match (arg.as_str(), value.as_str()) {
            (Some(p), Some(s)) => p.eq_ignore_ascii_case(s),
            _ => false,
        },
        "anything-but" => match arg {
            Value::Array(arr) => !arr.iter().any(|v| v == value),
            other => other != value,
        },
        "numeric" => apply_numeric(arg, value),
        _ => false,
    }
}

fn apply_numeric(arg: &Value, value: &Value) -> bool {
    let Some(n) = value.as_f64() else {
        return false;
    };
    let Some(arr) = arg.as_array() else {
        return false;
    };
    // AWS rejects malformed numeric arrays at create time; defensively
    // treat odd-length arrays here as a no-match instead of letting
    // a leftover element silently pass.
    if arr.len() % 2 != 0 || arr.is_empty() {
        return false;
    }
    for chunk in arr.chunks(2) {
        let Some(target) = chunk[1].as_f64() else {
            return false;
        };
        let ok = match chunk[0].as_str() {
            Some("=") => n == target,
            Some("<") => n < target,
            Some("<=") => n <= target,
            Some(">") => n > target,
            Some(">=") => n >= target,
            _ => false,
        };
        if !ok {
            return false;
        }
    }
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fs(patterns: &[&str]) -> FilterSet {
        FilterSet::from_strings(patterns.iter().map(|s| s.to_string()))
    }

    #[test]
    fn empty_pattern_passes_through() {
        let f = FilterSet::default();
        assert!(f.matches(&json!({"any": "thing"})));
    }

    #[test]
    fn exact_string_match() {
        let f = fs(&[r#"{"foo": "bar"}"#]);
        assert!(f.matches(&json!({"foo": "bar"})));
        assert!(!f.matches(&json!({"foo": "baz"})));
    }

    #[test]
    fn array_of_scalars_is_or() {
        let f = fs(&[r#"{"foo": ["a", "b"]}"#]);
        assert!(f.matches(&json!({"foo": "a"})));
        assert!(f.matches(&json!({"foo": "b"})));
        assert!(!f.matches(&json!({"foo": "c"})));
    }

    #[test]
    fn exists_operator_treats_null_as_present() {
        let exists_true = fs(&[r#"{"foo": [{"exists": true}]}"#]);
        // AWS treats `{"foo": null}` as foo-is-present.
        assert!(exists_true.matches(&json!({"foo": null})));
        let exists_false = fs(&[r#"{"foo": [{"exists": false}]}"#]);
        // ...and conversely a missing key is exists:false even though
        // the value lookup returns the same Null sentinel under the
        // hood.
        assert!(exists_false.matches(&json!({})));
        assert!(!exists_false.matches(&json!({"foo": null})));
    }

    #[test]
    fn numeric_odd_length_is_no_match() {
        let f = fs(&[r#"{"n": [{"numeric": [">", 0, "<"]}]}"#]);
        assert!(!f.matches(&json!({"n": 5})));
    }

    #[test]
    fn validate_rejects_invalid_json() {
        assert!(FilterSet::validate(["{not json"].iter()).is_err());
        assert!(FilterSet::validate([r#"{"ok": true}"#].iter()).is_ok());
    }

    #[test]
    fn exists_operator() {
        let exists_true = fs(&[r#"{"foo": [{"exists": true}]}"#]);
        assert!(exists_true.matches(&json!({"foo": "x"})));
        assert!(!exists_true.matches(&json!({"bar": "x"})));

        let exists_false = fs(&[r#"{"foo": [{"exists": false}]}"#]);
        assert!(!exists_false.matches(&json!({"foo": "x"})));
        assert!(exists_false.matches(&json!({"bar": "x"})));
    }

    #[test]
    fn sqs_body_decode() {
        let f = fs(&[r#"{"body": {"action": "process"}}"#]);
        let record = json!({
            "body": "{\"action\": \"process\", \"id\": 42}",
        });
        assert!(f.matches(&record));
        let other = json!({
            "body": "{\"action\": \"skip\"}",
        });
        assert!(!f.matches(&other));
    }

    #[test]
    fn nested_object_match() {
        let f = fs(&[r#"{"order": {"status": "paid"}}"#]);
        assert!(f.matches(&json!({"order": {"status": "paid", "id": 1}})));
        assert!(!f.matches(&json!({"order": {"status": "pending"}})));
    }

    #[test]
    fn multiple_patterns_or() {
        let f = fs(&[r#"{"a": "x"}"#, r#"{"b": "y"}"#]);
        assert!(f.matches(&json!({"a": "x"})));
        assert!(f.matches(&json!({"b": "y"})));
        assert!(!f.matches(&json!({"c": "z"})));
    }
}
