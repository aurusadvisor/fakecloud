//! Shared tag CRUD helpers for JSON-protocol services.
//!
//! Most AWS JSON-protocol services represent tags as an array of objects
//! with key/value fields (e.g. `[{"Key": "env", "Value": "prod"}]`) and
//! store them internally as `HashMap<String, String>`. This module provides
//! helpers to parse, apply, remove, and serialise those tags so that
//! individual service crates don't have to duplicate the logic.

use std::collections::{BTreeMap, HashMap};

use serde_json::{json, Value};

/// Common interface across tag-storage maps so the helpers in this module
/// work uniformly for `HashMap` and `BTreeMap`. State migrating to
/// `BTreeMap` for deterministic pagination order keeps using the same
/// helpers without copying values into a temporary `HashMap`.
pub trait MutableTagMap {
    fn insert(&mut self, key: String, value: String);
    fn remove(&mut self, key: &str);
}

impl MutableTagMap for HashMap<String, String> {
    fn insert(&mut self, key: String, value: String) {
        HashMap::insert(self, key, value);
    }
    fn remove(&mut self, key: &str) {
        HashMap::remove(self, key);
    }
}

impl MutableTagMap for BTreeMap<String, String> {
    fn insert(&mut self, key: String, value: String) {
        BTreeMap::insert(self, key, value);
    }
    fn remove(&mut self, key: &str) {
        BTreeMap::remove(self, key);
    }
}

pub trait ReadableTagMap {
    fn iter_tags(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_>;
}

impl ReadableTagMap for HashMap<String, String> {
    fn iter_tags(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_> {
        Box::new(self.iter())
    }
}

impl ReadableTagMap for BTreeMap<String, String> {
    fn iter_tags(&self) -> Box<dyn Iterator<Item = (&String, &String)> + '_> {
        Box::new(self.iter())
    }
}

/// Parse a JSON tags array and insert each tag into `existing_tags`.
///
/// `tags_field` is the name of the JSON field inside `body` that holds
/// the tags array (e.g. `"Tags"`).  Each element is expected to have
/// `key_field` and `value_field` string properties (typically `"Key"` /
/// `"Value"`, but KMS uses `"TagKey"` / `"TagValue"`).
///
/// Tags with missing or non-string key/value pairs are silently skipped.
///
/// Returns `Err(field_name)` if the field is present but not an array.
pub fn apply_tags<M: MutableTagMap>(
    existing_tags: &mut M,
    body: &Value,
    tags_field: &str,
    key_field: &str,
    value_field: &str,
) -> Result<(), String> {
    let obj = body.as_object();
    let field = obj.and_then(|o| o.get(tags_field));
    let Some(field) = field else {
        return Ok(());
    };
    let tags = field.as_array().ok_or_else(|| tags_field.to_string())?;
    for tag in tags {
        if let (Some(k), Some(v)) = (tag[key_field].as_str(), tag[value_field].as_str()) {
            existing_tags.insert(k.to_string(), v.to_string());
        }
    }
    Ok(())
}

/// Parse a JSON tag-keys array and remove matching keys from `existing_tags`.
///
/// `keys_field` is the name of the JSON field inside `body` that holds
/// the keys array (e.g. `"TagKeys"`).  Each element is expected to be a
/// plain string.
///
/// Returns `Err(field_name)` if the field is present but not an array.
pub fn remove_tags<M: MutableTagMap>(
    existing_tags: &mut M,
    body: &Value,
    keys_field: &str,
) -> Result<(), String> {
    let obj = body.as_object();
    let field = obj.and_then(|o| o.get(keys_field));
    let Some(field) = field else {
        return Ok(());
    };
    let keys = field.as_array().ok_or_else(|| keys_field.to_string())?;
    for key in keys {
        if let Some(k) = key.as_str() {
            existing_tags.remove(k);
        }
    }
    Ok(())
}

/// Convert a tag map into a sorted JSON array of `{key_field: k, value_field: v}` objects.
///
/// The output is sorted by key so that responses are deterministic.
pub fn tags_to_json<M: ReadableTagMap + ?Sized>(
    tags: &M,
    key_field: &str,
    value_field: &str,
) -> Vec<Value> {
    let mut sorted: Vec<(&String, &String)> = tags.iter_tags().collect();
    sorted.sort_by_key(|(k, _)| (*k).clone());
    sorted
        .into_iter()
        .map(|(k, v)| json!({ key_field: k, value_field: v }))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn apply_tags_inserts_and_overwrites() {
        let mut tags = HashMap::new();
        tags.insert("existing".to_string(), "old".to_string());

        let body = json!({
            "Tags": [
                {"Key": "existing", "Value": "new"},
                {"Key": "added", "Value": "val"},
            ]
        });

        apply_tags(&mut tags, &body, "Tags", "Key", "Value").unwrap();

        assert_eq!(tags.get("existing").unwrap(), "new");
        assert_eq!(tags.get("added").unwrap(), "val");
    }

    #[test]
    fn apply_tags_skips_invalid_entries() {
        let mut tags = HashMap::new();
        let body = json!({
            "Tags": [
                {"Key": "good", "Value": "val"},
                {"Key": 123, "Value": "bad_key"},
                {"NoKey": "x", "Value": "missing_key"},
            ]
        });

        apply_tags(&mut tags, &body, "Tags", "Key", "Value").unwrap();

        assert_eq!(tags.len(), 1);
        assert_eq!(tags.get("good").unwrap(), "val");
    }

    #[test]
    fn apply_tags_noop_when_field_missing() {
        let mut tags = HashMap::new();
        let body = json!({});
        apply_tags(&mut tags, &body, "Tags", "Key", "Value").unwrap();
        assert!(tags.is_empty());
    }

    #[test]
    fn apply_tags_errors_on_non_array() {
        let mut tags = HashMap::new();
        let body = json!({ "Tags": "not_an_array" });
        assert!(apply_tags(&mut tags, &body, "Tags", "Key", "Value").is_err());
    }

    #[test]
    fn apply_tags_errors_on_explicit_null() {
        let mut tags = HashMap::new();
        let body = json!({ "Tags": null });
        assert!(apply_tags(&mut tags, &body, "Tags", "Key", "Value").is_err());
    }

    #[test]
    fn remove_tags_removes_matching_keys() {
        let mut tags = HashMap::new();
        tags.insert("a".to_string(), "1".to_string());
        tags.insert("b".to_string(), "2".to_string());
        tags.insert("c".to_string(), "3".to_string());

        let body = json!({ "TagKeys": ["a", "c", "nonexistent"] });
        remove_tags(&mut tags, &body, "TagKeys").unwrap();

        assert_eq!(tags.len(), 1);
        assert!(tags.contains_key("b"));
    }

    #[test]
    fn remove_tags_noop_when_field_missing() {
        let mut tags = HashMap::new();
        tags.insert("a".to_string(), "1".to_string());
        let body = json!({});
        remove_tags(&mut tags, &body, "TagKeys").unwrap();
        assert_eq!(tags.len(), 1);
    }

    #[test]
    fn remove_tags_errors_on_non_array() {
        let mut tags = HashMap::new();
        let body = json!({ "TagKeys": 42 });
        assert!(remove_tags(&mut tags, &body, "TagKeys").is_err());
    }

    #[test]
    fn remove_tags_errors_on_explicit_null() {
        let mut tags = HashMap::new();
        let body = json!({ "TagKeys": null });
        assert!(remove_tags(&mut tags, &body, "TagKeys").is_err());
    }

    #[test]
    fn tags_to_json_produces_sorted_array() {
        let mut tags = HashMap::new();
        tags.insert("z_key".to_string(), "z_val".to_string());
        tags.insert("a_key".to_string(), "a_val".to_string());

        let result = tags_to_json(&tags, "Key", "Value");

        assert_eq!(result.len(), 2);
        assert_eq!(result[0]["Key"], "a_key");
        assert_eq!(result[0]["Value"], "a_val");
        assert_eq!(result[1]["Key"], "z_key");
        assert_eq!(result[1]["Value"], "z_val");
    }

    #[test]
    fn tags_to_json_with_custom_field_names() {
        let mut tags = HashMap::new();
        tags.insert("mykey".to_string(), "myval".to_string());

        let result = tags_to_json(&tags, "TagKey", "TagValue");

        assert_eq!(result[0]["TagKey"], "mykey");
        assert_eq!(result[0]["TagValue"], "myval");
    }

    #[test]
    fn tags_to_json_empty_map() {
        let tags = HashMap::new();
        let result = tags_to_json(&tags, "Key", "Value");
        assert!(result.is_empty());
    }
}
