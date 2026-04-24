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
    /// [`crate::state::EventSourceMapping::filter_patterns`].
    pub fn from_strings<I, S>(raw: I) -> Self
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        let patterns = raw
            .into_iter()
            .filter_map(|s| serde_json::from_str::<Value>(s.as_ref()).ok())
            .collect();
        Self { patterns }
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
    // An object pattern is either:
    //  - an operator (`{"exists": ...}`, `{"prefix": "..."}`, ...)
    //    applied to the current value, or
    //  - a nested object pattern, applied field-by-field when the
    //    value is itself an object.
    if let Value::Object(po) = pattern {
        if is_operator_object(po) {
            return apply_operator(po, value);
        }
    }
    match (pattern, value) {
        (Value::Object(po), Value::Object(vo)) => po.iter().all(|(k, sub_pattern)| {
            // Treat the "body" field of an SQS-shaped record specially:
            // patterns under "body" are matched against the JSON-parsed
            // body string, mirroring how Lambda decodes SQS bodies for
            // FilterCriteria evaluation.
            if k == "body" {
                if let Some(Value::String(s)) = vo.get("body") {
                    if let Ok(parsed) = serde_json::from_str::<Value>(s) {
                        return match_value(sub_pattern, &parsed);
                    }
                }
            }
            match vo.get(k) {
                Some(v) => match_value(sub_pattern, v),
                None => match_pattern_against_missing(sub_pattern),
            }
        }),
        (Value::Array(arr), v) => arr.iter().any(|p| match_value(p, v)),
        (Value::Null, Value::Null) => true,
        (Value::Bool(a), Value::Bool(b)) => a == b,
        (Value::Number(a), Value::Number(b)) => a == b,
        (Value::String(a), Value::String(b)) => a == b,
        _ => false,
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

fn apply_operator(o: &serde_json::Map<String, Value>, value: &Value) -> bool {
    o.iter().all(|(op, arg)| match op.as_str() {
        "exists" => match arg {
            Value::Bool(true) => !value.is_null(),
            Value::Bool(false) => value.is_null(),
            _ => false,
        },
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
    })
}

fn apply_numeric(arg: &Value, value: &Value) -> bool {
    let Some(n) = value.as_f64() else {
        return false;
    };
    let Some(arr) = arg.as_array() else {
        return false;
    };
    let mut iter = arr.iter();
    while let (Some(op), Some(num)) = (iter.next(), iter.next()) {
        let Some(target) = num.as_f64() else {
            return false;
        };
        let ok = match op.as_str() {
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

fn match_pattern_against_missing(pattern: &Value) -> bool {
    match pattern {
        Value::Object(o) => matches!(o.get("exists"), Some(Value::Bool(false))),
        Value::Array(arr) => arr.iter().any(match_pattern_against_missing),
        _ => false,
    }
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
