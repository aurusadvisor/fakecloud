//! Auto-extracted helper functions from mod.rs as part of carryover
//! service.rs split. PartiQL/condition/update-expression evaluators,
//! attribute-value plumbing, table description builders, etc.

#![allow(clippy::too_many_arguments)]

use std::collections::{BTreeMap, HashMap};

use base64::Engine;
use http::StatusCode;
use serde_json::{json, Value};

use fakecloud_core::service::{AwsResponse, AwsServiceError};

use super::DynamoDbService;

use crate::state::*;

/// Actions that mutate DynamoDB state and therefore require a snapshot
/// write after success. Kept in sync with the dispatch table above.
pub(crate) fn is_mutating_action(action: &str) -> bool {
    matches!(
        action,
        "CreateTable"
            | "DeleteTable"
            | "UpdateTable"
            | "PutItem"
            | "DeleteItem"
            | "UpdateItem"
            | "BatchWriteItem"
            | "TagResource"
            | "UntagResource"
            | "TransactWriteItems"
            | "ExecuteStatement"
            | "BatchExecuteStatement"
            | "ExecuteTransaction"
            | "UpdateTimeToLive"
            | "PutResourcePolicy"
            | "DeleteResourcePolicy"
            | "CreateBackup"
            | "DeleteBackup"
            | "RestoreTableFromBackup"
            | "RestoreTableToPointInTime"
            | "UpdateContinuousBackups"
            | "CreateGlobalTable"
            | "UpdateGlobalTable"
            | "UpdateGlobalTableSettings"
            | "UpdateTableReplicaAutoScaling"
            | "EnableKinesisStreamingDestination"
            | "DisableKinesisStreamingDestination"
            | "UpdateKinesisStreamingDestination"
            | "UpdateContributorInsights"
            | "ExportTableToPointInTime"
            | "ImportTable"
    )
}

// ── Helper functions ────────────────────────────────────────────────────

pub(crate) fn require_str<'a>(body: &'a Value, field: &str) -> Result<&'a str, AwsServiceError> {
    body[field].as_str().ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            format!("{field} is required"),
        )
    })
}

pub(crate) fn require_object(
    body: &Value,
    field: &str,
) -> Result<HashMap<String, AttributeValue>, AwsServiceError> {
    let obj = body[field].as_object().ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            format!("{field} is required"),
        )
    })?;
    Ok(obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
}

pub(crate) fn get_table<'a>(
    tables: &'a BTreeMap<String, DynamoTable>,
    name: &str,
) -> Result<&'a DynamoTable, AwsServiceError> {
    tables.get(name).ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ResourceNotFoundException",
            format!("Requested resource not found: Table: {name} not found"),
        )
    })
}

pub(crate) fn get_table_mut<'a>(
    tables: &'a mut BTreeMap<String, DynamoTable>,
    name: &str,
) -> Result<&'a mut DynamoTable, AwsServiceError> {
    tables.get_mut(name).ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ResourceNotFoundException",
            format!("Requested resource not found: Table: {name} not found"),
        )
    })
}

pub(crate) fn find_table_by_arn<'a>(
    tables: &'a BTreeMap<String, DynamoTable>,
    arn: &str,
) -> Result<&'a DynamoTable, AwsServiceError> {
    tables.values().find(|t| t.arn == arn).ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ResourceNotFoundException",
            format!("Requested resource not found: {arn}"),
        )
    })
}

pub(crate) fn find_table_by_arn_mut<'a>(
    tables: &'a mut BTreeMap<String, DynamoTable>,
    arn: &str,
) -> Result<&'a mut DynamoTable, AwsServiceError> {
    tables.values_mut().find(|t| t.arn == arn).ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ResourceNotFoundException",
            format!("Requested resource not found: {arn}"),
        )
    })
}

pub(crate) fn parse_key_schema(val: &Value) -> Result<Vec<KeySchemaElement>, AwsServiceError> {
    let arr = val.as_array().ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "KeySchema is required",
        )
    })?;
    Ok(arr
        .iter()
        .map(|elem| KeySchemaElement {
            attribute_name: elem["AttributeName"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            key_type: elem["KeyType"].as_str().unwrap_or("HASH").to_string(),
        })
        .collect())
}

pub(crate) fn parse_attribute_definitions(
    val: &Value,
) -> Result<Vec<AttributeDefinition>, AwsServiceError> {
    let arr = val.as_array().ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "AttributeDefinitions is required",
        )
    })?;
    Ok(arr
        .iter()
        .map(|elem| AttributeDefinition {
            attribute_name: elem["AttributeName"]
                .as_str()
                .unwrap_or_default()
                .to_string(),
            attribute_type: elem["AttributeType"].as_str().unwrap_or("S").to_string(),
        })
        .collect())
}

pub(crate) fn parse_provisioned_throughput(
    val: &Value,
) -> Result<ProvisionedThroughput, AwsServiceError> {
    Ok(ProvisionedThroughput {
        read_capacity_units: val["ReadCapacityUnits"].as_i64().unwrap_or(5),
        write_capacity_units: val["WriteCapacityUnits"].as_i64().unwrap_or(5),
    })
}

pub(crate) fn parse_gsi(val: &Value, billing_mode: &str) -> Vec<GlobalSecondaryIndex> {
    let Some(arr) = val.as_array() else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|g| {
            Some(GlobalSecondaryIndex {
                index_name: g["IndexName"].as_str()?.to_string(),
                key_schema: parse_key_schema(&g["KeySchema"]).ok()?,
                projection: parse_projection(&g["Projection"]),
                provisioned_throughput: Some(parse_gsi_throughput(
                    &g["ProvisionedThroughput"],
                    billing_mode,
                )),
                on_demand_throughput: parse_on_demand_throughput(&g["OnDemandThroughput"]),
            })
        })
        .collect()
}

/// Parse an `OnDemandThroughput` block. Absent fields default to `-1`,
/// which is AWS's sentinel for "no cap" — and the value real AWS echoes
/// back on DescribeTable when the caller omitted either axis.
pub(super) fn parse_on_demand_throughput(val: &Value) -> Option<crate::state::OnDemandThroughput> {
    if !val.is_object() {
        return None;
    }
    Some(crate::state::OnDemandThroughput {
        max_read_request_units: val["MaxReadRequestUnits"].as_i64().unwrap_or(-1),
        max_write_request_units: val["MaxWriteRequestUnits"].as_i64().unwrap_or(-1),
    })
}

/// Resolve the provisioned-throughput slot for a GSI on a CreateTable or
/// UpdateTable Create action. Real DynamoDB returns `{0, 0}` for GSIs on
/// PAY_PER_REQUEST tables regardless of whether the caller sent a
/// `ProvisionedThroughput` block, and the Terraform provider's `flatten`
/// code keys `name`/`read_capacity`/`write_capacity` off the presence of
/// that field — returning `None` would desynchronise state.
pub(crate) fn parse_gsi_throughput(val: &Value, billing_mode: &str) -> ProvisionedThroughput {
    if billing_mode == "PAY_PER_REQUEST" {
        return ProvisionedThroughput {
            read_capacity_units: 0,
            write_capacity_units: 0,
        };
    }
    ProvisionedThroughput {
        read_capacity_units: val["ReadCapacityUnits"].as_i64().unwrap_or(5),
        write_capacity_units: val["WriteCapacityUnits"].as_i64().unwrap_or(5),
    }
}

pub(crate) fn parse_lsi(val: &Value) -> Vec<LocalSecondaryIndex> {
    let Some(arr) = val.as_array() else {
        return Vec::new();
    };
    arr.iter()
        .filter_map(|l| {
            Some(LocalSecondaryIndex {
                index_name: l["IndexName"].as_str()?.to_string(),
                key_schema: parse_key_schema(&l["KeySchema"]).ok()?,
                projection: parse_projection(&l["Projection"]),
            })
        })
        .collect()
}

pub(super) fn parse_projection(val: &Value) -> Projection {
    Projection {
        projection_type: val["ProjectionType"].as_str().unwrap_or("ALL").to_string(),
        non_key_attributes: val["NonKeyAttributes"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect()
            })
            .unwrap_or_default(),
    }
}

pub(crate) fn parse_tags(val: &Value) -> BTreeMap<String, String> {
    let mut tags = BTreeMap::new();
    if let Some(arr) = val.as_array() {
        for tag in arr {
            if let (Some(k), Some(v)) = (tag["Key"].as_str(), tag["Value"].as_str()) {
                tags.insert(k.to_string(), v.to_string());
            }
        }
    }
    tags
}

pub(crate) fn parse_expression_attribute_names(body: &Value) -> HashMap<String, String> {
    let mut names = HashMap::new();
    if let Some(obj) = body["ExpressionAttributeNames"].as_object() {
        for (k, v) in obj {
            if let Some(s) = v.as_str() {
                names.insert(k.clone(), s.to_string());
            }
        }
    }
    names
}

pub(crate) fn parse_expression_attribute_values(body: &Value) -> HashMap<String, Value> {
    let mut values = HashMap::new();
    if let Some(obj) = body["ExpressionAttributeValues"].as_object() {
        for (k, v) in obj {
            values.insert(k.clone(), v.clone());
        }
    }
    values
}

pub(crate) fn resolve_attr_name(name: &str, expr_attr_names: &HashMap<String, String>) -> String {
    if name.starts_with('#') {
        expr_attr_names
            .get(name)
            .cloned()
            .unwrap_or_else(|| name.to_string())
    } else {
        name.to_string()
    }
}

/// Resolve a (possibly dotted, possibly `#name`-containing) document path to
/// the leaf `AttributeValue` inside `item`. Single-segment paths (`foo`,
/// `#foo`) resolve to a top-level attribute. Dotted paths (`profile.email`,
/// `#p.#e`, `items[0].sku`) walk into `M`/`L` containers. Returns `None` if
/// any segment is missing or the intermediate value isn't a map/list.
pub(crate) fn resolve_path(
    path: &str,
    item: &HashMap<String, AttributeValue>,
    expr_attr_names: &HashMap<String, String>,
) -> Option<Value> {
    // Fast path: a single-segment expression (no `.` and no `[` in the raw
    // input) refers to a top-level attribute by its literal name, even if the
    // resolved alias contains a `.`. Without this, `#sw` -> `Safety.Warning`
    // would be misread as the nested path `Safety` -> `Warning`.
    if !path.contains('.') && !path.contains('[') {
        return item.get(&resolve_attr_name(path, expr_attr_names)).cloned();
    }
    let resolved = resolve_projection_path(path, expr_attr_names);
    resolve_nested_path(item, &resolved)
}

pub(crate) fn extract_key(
    table: &DynamoTable,
    item: &HashMap<String, AttributeValue>,
) -> HashMap<String, AttributeValue> {
    let mut key = HashMap::new();
    let hash_key = table.hash_key_name();
    if let Some(v) = item.get(hash_key) {
        key.insert(hash_key.to_string(), v.clone());
    }
    if let Some(range_key) = table.range_key_name() {
        if let Some(v) = item.get(range_key) {
            key.insert(range_key.to_string(), v.clone());
        }
    }
    key
}

/// Parse a JSON object into a key map (used for ExclusiveStartKey).
pub(crate) fn parse_key_map(value: &Value) -> Option<HashMap<String, AttributeValue>> {
    let obj = value.as_object()?;
    if obj.is_empty() {
        return None;
    }
    Some(obj.iter().map(|(k, v)| (k.clone(), v.clone())).collect())
}

/// Check whether an item's key attributes match the given key map.
pub(crate) fn item_matches_key(
    item: &HashMap<String, AttributeValue>,
    key: &HashMap<String, AttributeValue>,
    hash_key_name: &str,
    range_key_name: Option<&str>,
) -> bool {
    let hash_match = match (item.get(hash_key_name), key.get(hash_key_name)) {
        (Some(a), Some(b)) => a == b,
        _ => false,
    };
    if !hash_match {
        return false;
    }
    match range_key_name {
        Some(rk) => match (item.get(rk), key.get(rk)) {
            (Some(a), Some(b)) => a == b,
            (None, None) => true,
            _ => false,
        },
        None => true,
    }
}

/// Extract the primary key from an item given explicit key attribute names.
pub(crate) fn extract_key_for_schema(
    item: &HashMap<String, AttributeValue>,
    hash_key_name: &str,
    range_key_name: Option<&str>,
) -> HashMap<String, AttributeValue> {
    let mut key = HashMap::new();
    if let Some(v) = item.get(hash_key_name) {
        key.insert(hash_key_name.to_string(), v.clone());
    }
    if let Some(rk) = range_key_name {
        if let Some(v) = item.get(rk) {
            key.insert(rk.to_string(), v.clone());
        }
    }
    key
}

pub(crate) fn validate_key_in_item(
    table: &DynamoTable,
    item: &HashMap<String, AttributeValue>,
) -> Result<(), AwsServiceError> {
    let hash_key = table.hash_key_name();
    if !item.contains_key(hash_key) {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            format!("Missing the key {hash_key} in the item"),
        ));
    }
    if let Some(range_key) = table.range_key_name() {
        if !item.contains_key(range_key) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                format!("Missing the key {range_key} in the item"),
            ));
        }
    }
    Ok(())
}

pub(crate) fn validate_key_attributes_in_key(
    table: &DynamoTable,
    key: &HashMap<String, AttributeValue>,
) -> Result<(), AwsServiceError> {
    let hash_key = table.hash_key_name();
    if !key.contains_key(hash_key) {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            format!("Missing the key {hash_key} in the item"),
        ));
    }
    Ok(())
}

pub(crate) fn project_item(
    item: &HashMap<String, AttributeValue>,
    body: &Value,
) -> HashMap<String, AttributeValue> {
    let projection = body["ProjectionExpression"].as_str();
    match projection {
        Some(proj) if !proj.is_empty() => {
            let expr_attr_names = parse_expression_attribute_names(body);
            let mut result = HashMap::new();
            for raw in proj.split(',') {
                let raw = raw.trim();
                // Single-segment: treat as literal top-level attribute even if
                // the alias resolves to a name containing `.` (e.g. `#sw` ->
                // `Safety.Warning`).
                if !raw.contains('.') && !raw.contains('[') {
                    let key = resolve_attr_name(raw, &expr_attr_names);
                    if let Some(v) = item.get(&key) {
                        result.insert(key, v.clone());
                    }
                } else {
                    let resolved = resolve_projection_path(raw, &expr_attr_names);
                    if let Some(v) = resolve_nested_path(item, &resolved) {
                        insert_nested_value(&mut result, &resolved, v);
                    }
                }
            }
            result
        }
        _ => item.clone(),
    }
}

/// Resolve expression attribute names within each segment of a projection path.
/// For example, "people[0].#n" with {"#n": "name"} => "people[0].name".
pub(crate) fn resolve_projection_path(
    path: &str,
    expr_attr_names: &HashMap<String, String>,
) -> String {
    // Split on dots, resolve each part, rejoin
    let mut result = String::new();
    for (i, segment) in path.split('.').enumerate() {
        if i > 0 {
            result.push('.');
        }
        // A segment might be like "#n" or "people[0]" or "#attr[0]"
        if let Some(bracket_pos) = segment.find('[') {
            let key_part = &segment[..bracket_pos];
            let index_part = &segment[bracket_pos..];
            result.push_str(&resolve_attr_name(key_part, expr_attr_names));
            result.push_str(index_part);
        } else {
            result.push_str(&resolve_attr_name(segment, expr_attr_names));
        }
    }
    result
}

/// Resolve a potentially nested path like "a.b.c" or "a[0].b" from an item.
pub(crate) fn resolve_nested_path(
    item: &HashMap<String, AttributeValue>,
    path: &str,
) -> Option<Value> {
    let segments = parse_path_segments(path);
    if segments.is_empty() {
        return None;
    }

    let first = &segments[0];
    let top_key = match first {
        PathSegment::Key(k) => k.as_str(),
        _ => return None,
    };

    let mut current = item.get(top_key)?.clone();

    for segment in &segments[1..] {
        match segment {
            PathSegment::Key(k) => {
                // Navigate into a Map: {"M": {"key": ...}}
                current = current.get("M")?.get(k)?.clone();
            }
            PathSegment::Index(idx) => {
                // Navigate into a List: {"L": [...]}
                current = current.get("L")?.get(*idx)?.clone();
            }
        }
    }

    Some(current)
}

#[derive(Debug)]
pub(crate) enum PathSegment {
    Key(String),
    Index(usize),
}

/// Parse a path like "a.b[0].c" into segments: [Key("a"), Key("b"), Index(0), Key("c")]
pub(crate) fn parse_path_segments(path: &str) -> Vec<PathSegment> {
    let mut segments = Vec::new();
    let mut current = String::new();

    let chars: Vec<char> = path.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        match chars[i] {
            '.' => {
                if !current.is_empty() {
                    segments.push(PathSegment::Key(current.clone()));
                    current.clear();
                }
            }
            '[' => {
                if !current.is_empty() {
                    segments.push(PathSegment::Key(current.clone()));
                    current.clear();
                }
                i += 1;
                let mut num = String::new();
                while i < chars.len() && chars[i] != ']' {
                    num.push(chars[i]);
                    i += 1;
                }
                if let Ok(idx) = num.parse::<usize>() {
                    segments.push(PathSegment::Index(idx));
                }
                // skip ']'
            }
            c => {
                current.push(c);
            }
        }
        i += 1;
    }
    if !current.is_empty() {
        segments.push(PathSegment::Key(current));
    }
    segments
}

/// Insert a value at a nested path in the result HashMap.
/// For a path like "a.b", we set result["a"] = {"M": {"b": value}}.
pub(crate) fn insert_nested_value(
    result: &mut HashMap<String, AttributeValue>,
    path: &str,
    value: Value,
) {
    // Simple case: no nesting
    if !path.contains('.') && !path.contains('[') {
        result.insert(path.to_string(), value);
        return;
    }

    let segments = parse_path_segments(path);
    if segments.is_empty() {
        return;
    }

    let top_key = match &segments[0] {
        PathSegment::Key(k) => k.clone(),
        _ => return,
    };

    if segments.len() == 1 {
        result.insert(top_key, value);
        return;
    }

    // For nested paths, wrap the value back into the nested structure
    let wrapped = wrap_value_in_path(&segments[1..], value);
    // Merge into existing value if present
    let existing = result.remove(&top_key);
    let merged = match existing {
        Some(existing) => merge_attribute_values(existing, wrapped),
        None => wrapped,
    };
    result.insert(top_key, merged);
}

/// Wrap a value in the nested path structure.
pub(crate) fn wrap_value_in_path(segments: &[PathSegment], value: Value) -> Value {
    if segments.is_empty() {
        return value;
    }
    let inner = wrap_value_in_path(&segments[1..], value);
    match &segments[0] {
        PathSegment::Key(k) => {
            json!({"M": {k.clone(): inner}})
        }
        PathSegment::Index(idx) => {
            let mut arr = vec![Value::Null; idx + 1];
            arr[*idx] = inner;
            json!({"L": arr})
        }
    }
}

/// Merge two attribute values (for overlapping projections).
pub(crate) fn merge_attribute_values(a: Value, b: Value) -> Value {
    if let (Some(a_map), Some(b_map)) = (
        a.get("M").and_then(|v| v.as_object()),
        b.get("M").and_then(|v| v.as_object()),
    ) {
        let mut merged = a_map.clone();
        for (k, v) in b_map {
            if let Some(existing) = merged.get(k) {
                merged.insert(
                    k.clone(),
                    merge_attribute_values(existing.clone(), v.clone()),
                );
            } else {
                merged.insert(k.clone(), v.clone());
            }
        }
        json!({"M": merged})
    } else {
        b
    }
}

pub(crate) fn evaluate_condition(
    condition: &str,
    existing: Option<&HashMap<String, AttributeValue>>,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> Result<(), AwsServiceError> {
    // ConditionExpression and FilterExpression share the same DynamoDB grammar,
    // so we delegate to evaluate_filter_expression. An empty map models "item
    // doesn't exist" correctly: attribute_exists → false, attribute_not_exists
    // → true, comparisons against missing attributes → None vs Some(val).
    let empty = HashMap::new();
    let item = existing.unwrap_or(&empty);
    if evaluate_filter_expression(condition, item, expr_attr_names, expr_attr_values) {
        Ok(())
    } else {
        Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ConditionalCheckFailedException",
            "The conditional request failed",
        ))
    }
}

pub(crate) fn extract_function_arg<'a>(expr: &'a str, func_name: &str) -> Option<&'a str> {
    // aws-sdk-go v2's expression builder emits function calls with a space
    // between the name and the opening paren (`attribute_exists (#0)`),
    // while hand-written expressions usually don't — accept both.
    let with_paren = format!("{func_name}(");
    let with_space = format!("{func_name} (");
    let rest = expr
        .strip_prefix(&with_paren)
        .or_else(|| expr.strip_prefix(&with_space))?;
    let inner = rest.strip_suffix(')')?;
    Some(inner.trim())
}

pub(crate) fn evaluate_key_condition(
    expr: &str,
    item: &HashMap<String, AttributeValue>,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> bool {
    let trimmed = expr.trim();

    let parts = split_on_and(trimmed);
    if parts.len() > 1 {
        return parts.iter().all(|part| {
            evaluate_key_condition(part.trim(), item, expr_attr_names, expr_attr_values)
        });
    }

    let stripped = strip_outer_parens(trimmed);
    if stripped != trimmed {
        return evaluate_key_condition(stripped, item, expr_attr_names, expr_attr_values);
    }

    evaluate_single_key_condition(trimmed, item, expr_attr_names, expr_attr_values)
}

/// Split a DynamoDB condition expression on a top-level keyword (``AND`` /
/// ``OR``), case-insensitive, with ASCII-whitespace word boundaries so
/// ``:s\tAND\t:o`` and ``:s\nAND\n:o`` split the same as ``:s AND :o``.
///
/// Parenthesised groups are skipped so only unparenthesised occurrences of the
/// keyword act as separators. When splitting on ``AND``, each top-level
/// ``BETWEEN`` keyword consumes the next top-level ``AND`` as its own inner
/// separator (``x BETWEEN :lo AND :hi``) rather than letting it split the
/// expression.
pub(crate) fn split_on_top_level_keyword<'a>(expr: &'a str, keyword: &str) -> Vec<&'a str> {
    let bytes = expr.as_bytes();
    let len = bytes.len();
    let kw = keyword.as_bytes();
    let is_and = keyword.eq_ignore_ascii_case("AND");

    let mut parts: Vec<&str> = Vec::new();
    let mut start = 0usize;
    let mut depth: i32 = 0;
    let mut between_skip: u32 = 0;
    let mut i = 0usize;

    while i < len {
        let ch = bytes[i];
        if ch == b'(' {
            depth += 1;
            i += 1;
            continue;
        }
        if ch == b')' {
            if depth > 0 {
                depth -= 1;
            }
            i += 1;
            continue;
        }
        if depth == 0 {
            if is_and {
                if let Some(end) = match_keyword(bytes, i, b"BETWEEN") {
                    between_skip = between_skip.saturating_add(1);
                    i = end;
                    continue;
                }
            }
            if let Some(end) = match_keyword(bytes, i, kw) {
                if is_and && between_skip > 0 {
                    between_skip -= 1;
                    i = end;
                    continue;
                }
                parts.push(&expr[start..i]);
                start = end;
                i = end;
                continue;
            }
        }
        i += 1;
    }
    parts.push(&expr[start..]);
    parts
}

/// Case-insensitive keyword match. For alphanumeric keywords (``AND``,
/// ``OR``, ``BETWEEN``) the match also requires ASCII-whitespace word
/// boundaries so substrings of identifiers are not mistaken for keywords.
/// Punctuation keywords (``,``) match literally.
pub(crate) fn match_keyword(bytes: &[u8], i: usize, keyword: &[u8]) -> Option<usize> {
    let end = i + keyword.len();
    if end > bytes.len() {
        return None;
    }
    for k in 0..keyword.len() {
        if !bytes[i + k].eq_ignore_ascii_case(&keyword[k]) {
            return None;
        }
    }
    let needs_word_boundary = keyword.iter().all(|b| b.is_ascii_alphanumeric());
    if needs_word_boundary {
        let left_ok = i == 0 || bytes[i - 1].is_ascii_whitespace();
        if !left_ok {
            return None;
        }
        let right_ok = end == bytes.len() || bytes[end].is_ascii_whitespace();
        if !right_ok {
            return None;
        }
    }
    Some(end)
}

pub(crate) fn split_on_and(expr: &str) -> Vec<&str> {
    split_on_top_level_keyword(expr, "AND")
}

pub(crate) fn split_on_or(expr: &str) -> Vec<&str> {
    split_on_top_level_keyword(expr, "OR")
}

pub(crate) fn evaluate_single_key_condition(
    part: &str,
    item: &HashMap<String, AttributeValue>,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> bool {
    let part = part.trim();

    if let Some(rest) = part
        .strip_prefix("begins_with(")
        .or_else(|| part.strip_prefix("begins_with ("))
    {
        return key_cond_begins_with(rest, item, expr_attr_names, expr_attr_values);
    }

    if let Some(between_pos) = part.to_ascii_uppercase().find("BETWEEN") {
        return key_cond_between(part, between_pos, item, expr_attr_names, expr_attr_values);
    }

    key_cond_simple_comparison(part, item, expr_attr_names, expr_attr_values)
}

/// `begins_with(attr, :val)` — KeyCondition variant: supports only
/// S-typed attributes (mirrors AWS's behavior of returning false for
/// type mismatches). The filter-expression evaluator has its own
/// `eval_begins_with` because it operates on filter-grammar inputs.
pub(crate) fn key_cond_begins_with(
    rest: &str,
    item: &HashMap<String, AttributeValue>,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> bool {
    let Some(inner) = rest.strip_suffix(')') else {
        return false;
    };
    let mut split = inner.splitn(2, ',');
    let (Some(attr_ref), Some(val_ref)) = (split.next(), split.next()) else {
        return false;
    };
    let attr_name = resolve_attr_name(attr_ref.trim(), expr_attr_names);
    let expected = expr_attr_values.get(val_ref.trim());
    let actual = item.get(&attr_name);
    match (actual, expected) {
        (Some(a), Some(e)) => {
            let a_str = a.get("S").and_then(|v| v.as_str());
            let e_str = e.get("S").and_then(|v| v.as_str());
            matches!((a_str, e_str), (Some(a), Some(e)) if a.starts_with(e))
        }
        _ => false,
    }
}

/// `attr BETWEEN :lo AND :hi` — inclusive range comparison via the
/// shared `compare_attribute_values` ordering.
pub(crate) fn key_cond_between(
    part: &str,
    between_pos: usize,
    item: &HashMap<String, AttributeValue>,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> bool {
    let attr_part = part[..between_pos].trim();
    let attr_name = resolve_attr_name(attr_part, expr_attr_names);
    let range_part = &part[between_pos + 7..];
    let Some(and_pos) = range_part.to_ascii_uppercase().find(" AND ") else {
        return false;
    };
    let lo_ref = range_part[..and_pos].trim();
    let hi_ref = range_part[and_pos + 5..].trim();
    let lo = expr_attr_values.get(lo_ref);
    let hi = expr_attr_values.get(hi_ref);
    let actual = item.get(&attr_name);
    match (actual, lo, hi) {
        (Some(a), Some(l), Some(h)) => {
            compare_attribute_values(Some(a), Some(l)) != std::cmp::Ordering::Less
                && compare_attribute_values(Some(a), Some(h)) != std::cmp::Ordering::Greater
        }
        _ => false,
    }
}

/// `attr <op> :val` — six operators (`=`, `<>`, `<`, `>`, `<=`, `>=`).
/// Multi-character operators come first in the search list so that `<=`
/// is not mistakenly matched as `<`.
pub(crate) fn key_cond_simple_comparison(
    part: &str,
    item: &HashMap<String, AttributeValue>,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> bool {
    for op in &["<=", ">=", "<>", "=", "<", ">"] {
        let Some(pos) = part.find(op) else {
            continue;
        };
        let left = part[..pos].trim();
        let right = part[pos + op.len()..].trim();
        let actual_owned = resolve_path(left, item, expr_attr_names);
        let actual = actual_owned.as_ref();
        let expected = expr_attr_values.get(right);

        return match *op {
            "=" => actual == expected,
            "<>" => actual != expected,
            "<" => compare_attribute_values(actual, expected) == std::cmp::Ordering::Less,
            ">" => compare_attribute_values(actual, expected) == std::cmp::Ordering::Greater,
            "<=" => {
                let cmp = compare_attribute_values(actual, expected);
                cmp == std::cmp::Ordering::Less || cmp == std::cmp::Ordering::Equal
            }
            ">=" => {
                let cmp = compare_attribute_values(actual, expected);
                cmp == std::cmp::Ordering::Greater || cmp == std::cmp::Ordering::Equal
            }
            _ => false,
        };
    }
    false
}

/// Returns the "size" of a DynamoDB attribute value per AWS docs:
/// - S → character count
/// - B → decoded byte count
/// - SS/NS/BS → element count
/// - L → element count
/// - M → element count
///
/// `size()` is not valid on N, BOOL, or NULL per AWS; returns None for those so
/// the enclosing comparison evaluates to false (matching AWS's behavior of
/// silently filtering type-mismatched rows in FilterExpression context).
pub(crate) fn attribute_size(val: &Value) -> Option<usize> {
    if let Some(s) = val.get("S").and_then(|v| v.as_str()) {
        return Some(s.len());
    }
    if let Some(b) = val.get("B").and_then(|v| v.as_str()) {
        // B is base64-encoded — return decoded byte count
        let decoded_len = base64::engine::general_purpose::STANDARD
            .decode(b)
            .map(|v| v.len())
            .unwrap_or(b.len());
        return Some(decoded_len);
    }
    if let Some(arr) = val.get("SS").and_then(|v| v.as_array()) {
        return Some(arr.len());
    }
    if let Some(arr) = val.get("NS").and_then(|v| v.as_array()) {
        return Some(arr.len());
    }
    if let Some(arr) = val.get("BS").and_then(|v| v.as_array()) {
        return Some(arr.len());
    }
    if let Some(arr) = val.get("L").and_then(|v| v.as_array()) {
        return Some(arr.len());
    }
    if let Some(obj) = val.get("M").and_then(|v| v.as_object()) {
        return Some(obj.len());
    }
    None
}

/// Evaluate a `size(path) op :val` comparison expression.
pub(crate) fn evaluate_size_comparison(
    part: &str,
    item: &HashMap<String, AttributeValue>,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> Option<bool> {
    // Find the closing paren of size(...)
    let open = part.find('(')?;
    let close = part[open..].find(')')? + open;
    let path = part[open + 1..close].trim();
    let remainder = part[close + 1..].trim();

    // Parse operator and value ref
    let (op, val_ref) = if let Some(rest) = remainder.strip_prefix("<=") {
        ("<=", rest.trim())
    } else if let Some(rest) = remainder.strip_prefix(">=") {
        (">=", rest.trim())
    } else if let Some(rest) = remainder.strip_prefix("<>") {
        ("<>", rest.trim())
    } else if let Some(rest) = remainder.strip_prefix('<') {
        ("<", rest.trim())
    } else if let Some(rest) = remainder.strip_prefix('>') {
        (">", rest.trim())
    } else if let Some(rest) = remainder.strip_prefix('=') {
        ("=", rest.trim())
    } else {
        return None;
    };

    let actual_owned = resolve_path(path, item, expr_attr_names)?;
    let size = attribute_size(&actual_owned)? as f64;

    let expected = extract_number(&expr_attr_values.get(val_ref).cloned())?;

    Some(match op {
        "=" => (size - expected).abs() < f64::EPSILON,
        "<>" => (size - expected).abs() >= f64::EPSILON,
        "<" => size < expected,
        ">" => size > expected,
        "<=" => size <= expected,
        ">=" => size >= expected,
        _ => false,
    })
}

pub(crate) fn compare_attribute_values(a: Option<&Value>, b: Option<&Value>) -> std::cmp::Ordering {
    match (a, b) {
        (None, None) => std::cmp::Ordering::Equal,
        (None, Some(_)) => std::cmp::Ordering::Less,
        (Some(_), None) => std::cmp::Ordering::Greater,
        (Some(a), Some(b)) => {
            let a_type = attribute_type_and_value(a);
            let b_type = attribute_type_and_value(b);
            match (a_type, b_type) {
                (Some(("S", a_val)), Some(("S", b_val))) => {
                    let a_str = a_val.as_str().unwrap_or("");
                    let b_str = b_val.as_str().unwrap_or("");
                    a_str.cmp(b_str)
                }
                (Some(("N", a_val)), Some(("N", b_val))) => {
                    let a_num: f64 = a_val.as_str().and_then(|s| s.parse().ok()).unwrap_or(0.0);
                    let b_num: f64 = b_val.as_str().and_then(|s| s.parse().ok()).unwrap_or(0.0);
                    a_num
                        .partial_cmp(&b_num)
                        .unwrap_or(std::cmp::Ordering::Equal)
                }
                (Some(("B", a_val)), Some(("B", b_val))) => {
                    let a_str = a_val.as_str().unwrap_or("");
                    let b_str = b_val.as_str().unwrap_or("");
                    a_str.cmp(b_str)
                }
                _ => std::cmp::Ordering::Equal,
            }
        }
    }
}

pub(crate) fn evaluate_filter_expression(
    expr: &str,
    item: &HashMap<String, AttributeValue>,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> bool {
    let trimmed = expr.trim();

    // Split on OR first (lower precedence), respecting parentheses
    let or_parts = split_on_or(trimmed);
    if or_parts.len() > 1 {
        return or_parts.iter().any(|part| {
            evaluate_filter_expression(part.trim(), item, expr_attr_names, expr_attr_values)
        });
    }

    // Then split on AND (higher precedence), respecting parentheses
    let and_parts = split_on_and(trimmed);
    if and_parts.len() > 1 {
        return and_parts.iter().all(|part| {
            evaluate_filter_expression(part.trim(), item, expr_attr_names, expr_attr_values)
        });
    }

    // Strip outer parentheses if present
    let stripped = strip_outer_parens(trimmed);
    if stripped != trimmed {
        return evaluate_filter_expression(stripped, item, expr_attr_names, expr_attr_values);
    }

    // Handle NOT prefix (case-insensitive)
    if trimmed.len() > 4 && trimmed[..4].eq_ignore_ascii_case("NOT ") {
        return !evaluate_filter_expression(&trimmed[4..], item, expr_attr_names, expr_attr_values);
    }

    evaluate_single_filter_condition(trimmed, item, expr_attr_names, expr_attr_values)
}

/// Strip matching outer parentheses from an expression.
pub(crate) fn strip_outer_parens(expr: &str) -> &str {
    let trimmed = expr.trim();
    if !trimmed.starts_with('(') || !trimmed.ends_with(')') {
        return trimmed;
    }
    // Verify the outer parens actually match each other
    let inner = &trimmed[1..trimmed.len() - 1];
    let mut depth = 0;
    for ch in inner.bytes() {
        match ch {
            b'(' => depth += 1,
            b')' => {
                if depth == 0 {
                    return trimmed; // closing paren matches something inside, not the outer one
                }
                depth -= 1;
            }
            _ => {}
        }
    }
    if depth == 0 {
        inner
    } else {
        trimmed
    }
}

pub(crate) fn evaluate_single_filter_condition(
    part: &str,
    item: &HashMap<String, AttributeValue>,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> bool {
    if let Some(inner) = extract_function_arg(part, "attribute_exists") {
        return resolve_path(inner, item, expr_attr_names).is_some();
    }

    if let Some(inner) = extract_function_arg(part, "attribute_not_exists") {
        return resolve_path(inner, item, expr_attr_names).is_none();
    }

    if let Some(rest) = part
        .strip_prefix("begins_with(")
        .or_else(|| part.strip_prefix("begins_with ("))
    {
        return eval_begins_with(rest, item, expr_attr_names, expr_attr_values);
    }

    if let Some(rest) = part
        .strip_prefix("contains(")
        .or_else(|| part.strip_prefix("contains ("))
    {
        return eval_contains(rest, item, expr_attr_names, expr_attr_values);
    }

    if part.starts_with("size(") || part.starts_with("size (") {
        if let Some(result) =
            evaluate_size_comparison(part, item, expr_attr_names, expr_attr_values)
        {
            return result;
        }
    }

    if let Some(rest) = part
        .strip_prefix("attribute_type(")
        .or_else(|| part.strip_prefix("attribute_type ("))
    {
        return eval_attribute_type(rest, item, expr_attr_names, expr_attr_values);
    }

    if let Some((attr_ref, value_refs)) = parse_in_expression(part) {
        let attr_name = resolve_attr_name(attr_ref, expr_attr_names);
        let actual = item.get(&attr_name);
        return evaluate_in_match(actual, &value_refs, expr_attr_values);
    }

    evaluate_single_key_condition(part, item, expr_attr_names, expr_attr_values)
}

/// `begins_with(path, :val)` — only S (string) operands. Returns false on
/// any parse failure or type mismatch (this is the same shape DynamoDB
/// returns: a malformed predicate is silently false rather than an error).
pub(crate) fn eval_begins_with(
    rest: &str,
    item: &HashMap<String, AttributeValue>,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> bool {
    let Some(inner) = rest.strip_suffix(')') else {
        return false;
    };
    let mut split = inner.splitn(2, ',');
    let (Some(attr_ref), Some(val_ref)) = (split.next(), split.next()) else {
        return false;
    };
    let actual = resolve_path(attr_ref.trim(), item, expr_attr_names);
    let expected = expr_attr_values.get(val_ref.trim());
    match (actual.as_ref(), expected) {
        (Some(a), Some(e)) => {
            let a_str = a.get("S").and_then(|v| v.as_str());
            let e_str = e.get("S").and_then(|v| v.as_str());
            matches!((a_str, e_str), (Some(a), Some(e)) if a.starts_with(e))
        }
        _ => false,
    }
}

/// `contains(path, :val)` — substring check on S, set membership on
/// SS/NS/BS, and element membership on L. Other type pairings return
/// false.
pub(crate) fn eval_contains(
    rest: &str,
    item: &HashMap<String, AttributeValue>,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> bool {
    let Some(inner) = rest.strip_suffix(')') else {
        return false;
    };
    let mut split = inner.splitn(2, ',');
    let (Some(attr_ref), Some(val_ref)) = (split.next(), split.next()) else {
        return false;
    };
    let actual = resolve_path(attr_ref.trim(), item, expr_attr_names);
    let expected = expr_attr_values.get(val_ref.trim());
    let (Some(a), Some(e)) = (actual.as_ref(), expected) else {
        return false;
    };

    if let (Some(a_s), Some(e_s)) = (
        a.get("S").and_then(|v| v.as_str()),
        e.get("S").and_then(|v| v.as_str()),
    ) {
        return a_s.contains(e_s);
    }
    if let Some(set) = a.get("SS").and_then(|v| v.as_array()) {
        if let Some(val) = e.get("S") {
            return set.contains(val);
        }
    }
    if let Some(set) = a.get("NS").and_then(|v| v.as_array()) {
        if let Some(val) = e.get("N") {
            return set.contains(val);
        }
    }
    if let Some(set) = a.get("BS").and_then(|v| v.as_array()) {
        if let Some(val) = e.get("B") {
            return set.contains(val);
        }
    }
    if let Some(list) = a.get("L").and_then(|v| v.as_array()) {
        return list.contains(e);
    }
    false
}

/// `attribute_type(path, :type)` — checks whether the attribute at `path`
/// is stored under the wire type identified by `:type` (one of the
/// DynamoDB type letters S/N/B/BOOL/NULL/SS/NS/BS/L/M).
pub(crate) fn eval_attribute_type(
    rest: &str,
    item: &HashMap<String, AttributeValue>,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> bool {
    let Some(inner) = rest.strip_suffix(')') else {
        return false;
    };
    let mut split = inner.splitn(2, ',');
    let (Some(attr_ref), Some(val_ref)) = (split.next(), split.next()) else {
        return false;
    };
    let actual = resolve_path(attr_ref.trim(), item, expr_attr_names);
    let expected_type = expr_attr_values
        .get(val_ref.trim())
        .and_then(|v| v.get("S"))
        .and_then(|v| v.as_str());
    let (Some(val), Some(t)) = (actual.as_ref(), expected_type) else {
        return false;
    };
    match t {
        "S" => val.get("S").is_some(),
        "N" => val.get("N").is_some(),
        "B" => val.get("B").is_some(),
        "BOOL" => val.get("BOOL").is_some(),
        "NULL" => val.get("NULL").is_some(),
        "SS" => val.get("SS").is_some(),
        "NS" => val.get("NS").is_some(),
        "BS" => val.get("BS").is_some(),
        "L" => val.get("L").is_some(),
        "M" => val.get("M").is_some(),
        _ => false,
    }
}

/// Parse an `attr IN (:v1, :v2, ...)` expression. Mirrors the DynamoDB
/// ConditionExpression / FilterExpression grammar where IN takes a single
/// operand on the left and 1–100 comma-separated value refs inside parens
/// on the right. Case-insensitive; tolerates missing spaces after commas
/// (aws-sdk-go's `expression` builder emits ", " but hand-built expressions
/// often use `strings.Join(..., ",")`). Returns None for non-IN inputs so
/// callers can fall through to their other grammar branches.
pub(crate) fn parse_in_expression(expr: &str) -> Option<(&str, Vec<&str>)> {
    let upper = expr.to_ascii_uppercase();
    let in_pos = upper.find(" IN ")?;
    let attr_ref = expr[..in_pos].trim();
    if attr_ref.is_empty() {
        return None;
    }
    let rest = expr[in_pos + 4..].trim_start();
    let inner = rest.strip_prefix('(')?.strip_suffix(')')?;
    let values: Vec<&str> = inner
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect();
    if values.is_empty() {
        return None;
    }
    Some((attr_ref, values))
}

/// Return true iff `actual` equals any of the `value_refs` resolved through
/// `expr_attr_values`. A missing attribute never matches (mirrors AWS, which
/// evaluates `IN` against undefined attributes as false).
pub(crate) fn evaluate_in_match(
    actual: Option<&AttributeValue>,
    value_refs: &[&str],
    expr_attr_values: &HashMap<String, Value>,
) -> bool {
    value_refs.iter().any(|v_ref| {
        let expected = expr_attr_values.get(*v_ref);
        matches!((actual, expected), (Some(a), Some(e)) if a == e)
    })
}

/// One of the four DynamoDB ``UpdateExpression`` action keywords.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum UpdateAction {
    Set,
    Remove,
    Add,
    Delete,
}

impl UpdateAction {
    /// All four keywords as written on the wire — these double as the search
    /// terms for ``parse_update_clauses``.
    const KEYWORDS: &'static [(&'static str, UpdateAction)] = &[
        ("SET", UpdateAction::Set),
        ("REMOVE", UpdateAction::Remove),
        ("ADD", UpdateAction::Add),
        ("DELETE", UpdateAction::Delete),
    ];

    fn keyword(self) -> &'static str {
        match self {
            UpdateAction::Set => "SET",
            UpdateAction::Remove => "REMOVE",
            UpdateAction::Add => "ADD",
            UpdateAction::Delete => "DELETE",
        }
    }
}

pub(crate) fn apply_update_expression(
    item: &mut HashMap<String, AttributeValue>,
    expr: &str,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> Result<(), AwsServiceError> {
    let clauses = parse_update_clauses(expr);
    if clauses.is_empty() && !expr.trim().is_empty() {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "Invalid UpdateExpression: Syntax error; token: \"<expression>\"",
        ));
    }
    for (action, assignments) in &clauses {
        match action {
            UpdateAction::Set => {
                for assignment in assignments {
                    apply_set_assignment(item, assignment, expr_attr_names, expr_attr_values)?;
                }
            }
            UpdateAction::Remove => {
                for attr_ref in assignments {
                    let attr = resolve_attr_name(attr_ref.trim(), expr_attr_names);
                    item.remove(&attr);
                }
            }
            UpdateAction::Add => {
                for assignment in assignments {
                    apply_add_assignment(item, assignment, expr_attr_names, expr_attr_values)?;
                }
            }
            UpdateAction::Delete => {
                for assignment in assignments {
                    apply_delete_assignment(item, assignment, expr_attr_names, expr_attr_values)?;
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn parse_update_clauses(expr: &str) -> Vec<(UpdateAction, Vec<String>)> {
    let mut clauses: Vec<(UpdateAction, Vec<String>)> = Vec::new();
    let upper = expr.to_ascii_uppercase();
    let mut positions: Vec<(usize, UpdateAction)> = Vec::new();

    for &(kw, action) in UpdateAction::KEYWORDS {
        let mut search_from = 0;
        while let Some(pos) = upper[search_from..].find(kw) {
            let abs_pos = search_from + pos;
            let before_ok = abs_pos == 0 || !expr.as_bytes()[abs_pos - 1].is_ascii_alphanumeric();
            let after_pos = abs_pos + kw.len();
            let after_ok =
                after_pos >= expr.len() || !expr.as_bytes()[after_pos].is_ascii_alphanumeric();
            if before_ok && after_ok {
                positions.push((abs_pos, action));
            }
            search_from = abs_pos + kw.len();
        }
    }

    positions.sort_by_key(|(pos, _)| *pos);

    for (i, &(pos, action)) in positions.iter().enumerate() {
        let start = pos + action.keyword().len();
        let end = if i + 1 < positions.len() {
            positions[i + 1].0
        } else {
            expr.len()
        };
        let content = expr[start..end].trim();
        // Use a paren-aware split so that function-call arguments such as
        // `list_append(#a, :b)` are kept as a single assignment rather than
        // being torn apart at the inner comma.
        let assignments: Vec<String> = split_on_top_level_keyword(content, ",")
            .into_iter()
            .map(|s| s.trim().to_string())
            .collect();
        clauses.push((action, assignments));
    }

    clauses
}

pub(crate) fn apply_set_assignment(
    item: &mut HashMap<String, AttributeValue>,
    assignment: &str,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> Result<(), AwsServiceError> {
    let Some((left, right)) = assignment.split_once('=') else {
        return Ok(());
    };

    let left_trimmed = left.trim();
    let right = right.trim();

    // One RHS evaluator used for every LHS shape so `SET a.b = a.b + :d`,
    // `SET a.b = list_append(a.b, :list)`, and `SET a.b = if_not_exists(a.b, :v)`
    // all work against nested paths, not just top-level attributes. The evaluator
    // returns Ok(None) when the RHS is a no-op (if_not_exists where the target
    // already has a value, or an unresolvable plain reference).
    let new_value = evaluate_set_rhs(right, item, expr_attr_names, expr_attr_values)?;

    if is_dotted_path(left_trimmed) {
        // A None value is a no-op (if_not_exists skip, or unresolvable plain
        // ref) — matches top-level SET's silent-skip behavior for the same
        // shapes. Structural errors (missing parent map, non-map intermediate)
        // surface from assign_nested_path itself.
        let Some(v) = new_value else {
            return Ok(());
        };
        return assign_nested_path(item, left_trimmed, expr_attr_names, v);
    }

    // Split off a trailing `[N]` list-index suffix so we can resolve the
    // attribute name ref on its own. Without this, `resolve_attr_name` sees
    // "#items[0]" as a whole and misses the `#items` → `items` mapping.
    let (attr_ref, list_index) = match parse_list_index_suffix(left_trimmed) {
        Some((name, idx)) => (name, Some(idx)),
        None => (left_trimmed, None),
    };
    let attr = resolve_attr_name(attr_ref, expr_attr_names);

    let Some(v) = new_value else {
        return Ok(());
    };
    match list_index {
        Some(idx) => assign_list_index(item, &attr, idx, v),
        None => {
            item.insert(attr, v);
            Ok(())
        }
    }
}

/// Evaluate the RHS of a `SET` assignment without writing it anywhere.
/// Returns `Ok(Some(value))` with the computed value, `Ok(None)` for
/// no-op cases (if_not_exists where the target already has a value, or
/// an unresolvable plain reference in dotted-path context), or
/// `Err(ValidationException)` for type-mismatched arithmetic.
pub(crate) fn evaluate_set_rhs(
    right: &str,
    item: &HashMap<String, AttributeValue>,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> Result<Option<Value>, AwsServiceError> {
    if let Some(rest) = right
        .strip_prefix("if_not_exists(")
        .or_else(|| right.strip_prefix("if_not_exists ("))
    {
        return Ok(evaluate_if_not_exists_rhs(
            rest,
            item,
            expr_attr_names,
            expr_attr_values,
        ));
    }

    if let Some(rest) = right
        .strip_prefix("list_append(")
        .or_else(|| right.strip_prefix("list_append ("))
    {
        return Ok(evaluate_list_append_rhs(
            rest,
            item,
            expr_attr_names,
            expr_attr_values,
        ));
    }

    if let Some((arith_left, arith_right, is_add)) = parse_arithmetic(right) {
        return evaluate_arithmetic_rhs(
            arith_left,
            arith_right,
            is_add,
            item,
            expr_attr_names,
            expr_attr_values,
        );
    }

    Ok(resolve_ref_or_path(
        right,
        item,
        expr_attr_names,
        expr_attr_values,
    ))
}

/// `if_not_exists(path, :val)` — evaluates to nothing when `path` already
/// resolves to a value, and to the default ref otherwise. `path` may be a
/// top-level attribute, a placeholder, or a dotted path inside an M-typed
/// attribute.
pub(crate) fn evaluate_if_not_exists_rhs(
    rest: &str,
    item: &HashMap<String, AttributeValue>,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> Option<Value> {
    let inner = rest.strip_suffix(')')?;
    let mut split = inner.splitn(2, ',');
    let (check, default) = (split.next()?, split.next()?);
    if resolve_ref_or_path(check.trim(), item, expr_attr_names, expr_attr_values).is_some() {
        return None;
    }
    resolve_ref_or_path(default.trim(), item, expr_attr_names, expr_attr_values)
}

/// `list_append(a, b)` — concatenate the L arrays of two list operands.
/// Either operand may be missing or non-list, in which case it contributes
/// nothing. Both operands may be value refs (`:list`) or document paths
/// (top-level or dotted).
pub(crate) fn evaluate_list_append_rhs(
    rest: &str,
    item: &HashMap<String, AttributeValue>,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> Option<Value> {
    let inner = rest.strip_suffix(')')?;
    let mut split = inner.splitn(2, ',');
    let (a_ref, b_ref) = (split.next()?, split.next()?);
    let a_val = resolve_ref_or_path(a_ref.trim(), item, expr_attr_names, expr_attr_values);
    let b_val = resolve_ref_or_path(b_ref.trim(), item, expr_attr_names, expr_attr_values);

    let mut merged = Vec::new();
    for v in [&a_val, &b_val].iter().copied().flatten() {
        if let Value::Object(obj) = v {
            if let Some(Value::Array(arr)) = obj.get("L") {
                merged.extend(arr.clone());
            }
        }
    }
    Some(json!({ "L": merged }))
}

/// `<arith_left> +/- <arith_right>` — both operands must resolve to N values
/// (or the LHS may be missing, in which case it's treated as 0). Anything
/// else is rejected with the same `ValidationException` AWS returns.
pub(crate) fn evaluate_arithmetic_rhs(
    arith_left: &str,
    arith_right: &str,
    is_add: bool,
    item: &HashMap<String, AttributeValue>,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> Result<Option<Value>, AwsServiceError> {
    let left_val = resolve_ref_or_path(arith_left.trim(), item, expr_attr_names, expr_attr_values);
    let right_val =
        resolve_ref_or_path(arith_right.trim(), item, expr_attr_names, expr_attr_values);

    let left_num = match extract_number(&left_val) {
        Some(n) => n,
        None if left_val.is_some() => {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "An operand in the update expression has an incorrect data type",
            ));
        }
        None => 0.0,
    };
    let right_num = extract_number(&right_val).ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "An operand in the update expression has an incorrect data type",
        )
    })?;

    let result = if is_add {
        left_num + right_num
    } else {
        left_num - right_num
    };

    let num_str = if result == result.trunc() {
        format!("{}", result as i64)
    } else {
        format!("{result}")
    };

    Ok(Some(json!({ "N": num_str })))
}

/// Parse a trailing `[N]` list-index suffix off the LHS of a SET assignment.
/// Returns the bare attribute reference and the index, or None when the LHS
/// is a plain attribute (or a path shape we don't yet support).
pub(crate) fn parse_list_index_suffix(path: &str) -> Option<(&str, usize)> {
    let path = path.trim();
    if !path.ends_with(']') {
        return None;
    }
    let open = path.rfind('[')?;
    // Require no further `.` / `[` / `]` inside the bracketed portion and no
    // further path segments after — we only handle the single-index case
    // `name[N]`, not nested shapes like `a.b[0].c`.
    let idx_str = &path[open + 1..path.len() - 1];
    let idx: usize = idx_str.parse().ok()?;
    let name = &path[..open];
    if name.is_empty() || name.contains('[') || name.contains(']') || name.contains('.') {
        return None;
    }
    Some((name, idx))
}

/// Assign a value to a specific index of a `L`-typed attribute. If `idx` is
/// within the current list, replaces that slot; if it's at the end, appends.
/// AWS rejects writes beyond `len`, so we return a `ValidationException` for
/// out-of-range indices and non-list attributes.
pub(crate) fn assign_list_index(
    item: &mut HashMap<String, AttributeValue>,
    attr: &str,
    idx: usize,
    value: Value,
) -> Result<(), AwsServiceError> {
    let Some(existing) = item.get_mut(attr) else {
        return Err(invalid_document_path());
    };
    let Some(list) = existing.get_mut("L").and_then(|l| l.as_array_mut()) else {
        return Err(invalid_document_path());
    };
    if idx < list.len() {
        list[idx] = value;
    } else if idx == list.len() {
        list.push(value);
    } else {
        return Err(invalid_document_path());
    }
    Ok(())
}

pub(crate) fn invalid_document_path() -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ValidationException",
        "The document path provided in the update expression is invalid for update",
    )
}

/// Resolve a SET-RHS operand that may be either a value placeholder
/// (``:foo``) or a document path (top-level attribute, ``#name``, or a
/// dotted path like ``profile.email`` / ``#web.#count``).
pub(crate) fn resolve_ref_or_path(
    reference: &str,
    item: &HashMap<String, AttributeValue>,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> Option<Value> {
    let reference = reference.trim();
    if reference.starts_with(':') {
        return expr_attr_values.get(reference).cloned();
    }
    resolve_path(reference, item, expr_attr_names)
}

/// True if `path` targets a nested key inside an M-typed attribute. Bracketed
/// list indices (`a[0]`, `a.b[0]`) are not supported by the nested-SET writer.
pub(crate) fn is_dotted_path(path: &str) -> bool {
    path.contains('.') && !path.contains('[')
}

/// Write `value` at a dotted path inside an M-typed attribute.
///
/// Resolves each `#name` segment through `expr_attr_names`. The top-level
/// attribute and every intermediate segment must already exist as a Map —
/// DynamoDB rejects writes through missing parents with ValidationException.
pub(crate) fn assign_nested_path(
    item: &mut HashMap<String, AttributeValue>,
    path: &str,
    expr_attr_names: &HashMap<String, String>,
    value: Value,
) -> Result<(), AwsServiceError> {
    let mut segments: Vec<String> = path
        .split('.')
        .map(|seg| resolve_attr_name(seg.trim(), expr_attr_names))
        .collect();
    if segments.len() < 2 {
        return Err(invalid_document_path());
    }

    let leaf = segments.pop().expect("len >= 2");
    let top = segments.remove(0);

    let top_attr = item.get_mut(&top).ok_or_else(invalid_document_path)?;
    let mut current = top_attr
        .get_mut("M")
        .and_then(|m| m.as_object_mut())
        .ok_or_else(invalid_document_path)?;

    for seg in &segments {
        current = current
            .get_mut(seg)
            .and_then(|v| v.get_mut("M"))
            .and_then(|m| m.as_object_mut())
            .ok_or_else(invalid_document_path)?;
    }

    current.insert(leaf, value);
    Ok(())
}

pub(crate) fn extract_number(val: &Option<Value>) -> Option<f64> {
    val.as_ref()
        .and_then(|v| v.get("N"))
        .and_then(|n| n.as_str())
        .and_then(|s| s.parse().ok())
}

pub(crate) fn parse_arithmetic(expr: &str) -> Option<(&str, &str, bool)> {
    let mut depth = 0;
    for (i, c) in expr.char_indices() {
        match c {
            '(' => depth += 1,
            ')' => depth -= 1,
            '+' if depth == 0 && i > 0 => {
                return Some((&expr[..i], &expr[i + 1..], true));
            }
            '-' if depth == 0 && i > 0 => {
                return Some((&expr[..i], &expr[i + 1..], false));
            }
            _ => {}
        }
    }
    None
}

pub(crate) fn apply_add_assignment(
    item: &mut HashMap<String, AttributeValue>,
    assignment: &str,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> Result<(), AwsServiceError> {
    let parts: Vec<&str> = assignment.splitn(2, ' ').collect();
    if parts.len() != 2 {
        return Ok(());
    }

    let attr = resolve_attr_name(parts[0].trim(), expr_attr_names);
    let val_ref = parts[1].trim();
    let add_val = expr_attr_values.get(val_ref);

    if let Some(add_val) = add_val {
        if let Some(existing) = item.get(&attr) {
            if let (Some(existing_num), Some(add_num)) = (
                extract_number(&Some(existing.clone())),
                extract_number(&Some(add_val.clone())),
            ) {
                let result = existing_num + add_num;
                let num_str = if result == result.trunc() {
                    format!("{}", result as i64)
                } else {
                    format!("{result}")
                };
                item.insert(attr, json!({"N": num_str}));
            } else if let Some(existing_set) = existing.get("SS").and_then(|v| v.as_array()) {
                if let Some(add_set) = add_val.get("SS").and_then(|v| v.as_array()) {
                    let mut merged: Vec<Value> = existing_set.clone();
                    for v in add_set {
                        if !merged.contains(v) {
                            merged.push(v.clone());
                        }
                    }
                    item.insert(attr, json!({"SS": merged}));
                }
            } else if let Some(existing_set) = existing.get("NS").and_then(|v| v.as_array()) {
                if let Some(add_set) = add_val.get("NS").and_then(|v| v.as_array()) {
                    let mut merged: Vec<Value> = existing_set.clone();
                    for v in add_set {
                        if !merged.contains(v) {
                            merged.push(v.clone());
                        }
                    }
                    item.insert(attr, json!({"NS": merged}));
                }
            } else if let Some(existing_set) = existing.get("BS").and_then(|v| v.as_array()) {
                if let Some(add_set) = add_val.get("BS").and_then(|v| v.as_array()) {
                    let mut merged: Vec<Value> = existing_set.clone();
                    for v in add_set {
                        if !merged.contains(v) {
                            merged.push(v.clone());
                        }
                    }
                    item.insert(attr, json!({"BS": merged}));
                }
            }
        } else {
            item.insert(attr, add_val.clone());
        }
    }

    Ok(())
}

pub(crate) fn apply_delete_assignment(
    item: &mut HashMap<String, AttributeValue>,
    assignment: &str,
    expr_attr_names: &HashMap<String, String>,
    expr_attr_values: &HashMap<String, Value>,
) -> Result<(), AwsServiceError> {
    let parts: Vec<&str> = assignment.splitn(2, ' ').collect();
    if parts.len() != 2 {
        return Ok(());
    }

    let attr = resolve_attr_name(parts[0].trim(), expr_attr_names);
    let val_ref = parts[1].trim();
    let del_val = expr_attr_values.get(val_ref);

    if let (Some(existing), Some(del_val)) = (item.get(&attr).cloned(), del_val) {
        if let (Some(existing_set), Some(del_set)) = (
            existing.get("SS").and_then(|v| v.as_array()),
            del_val.get("SS").and_then(|v| v.as_array()),
        ) {
            let filtered: Vec<Value> = existing_set
                .iter()
                .filter(|v| !del_set.contains(v))
                .cloned()
                .collect();
            if filtered.is_empty() {
                item.remove(&attr);
            } else {
                item.insert(attr, json!({"SS": filtered}));
            }
        } else if let (Some(existing_set), Some(del_set)) = (
            existing.get("NS").and_then(|v| v.as_array()),
            del_val.get("NS").and_then(|v| v.as_array()),
        ) {
            let filtered: Vec<Value> = existing_set
                .iter()
                .filter(|v| !del_set.contains(v))
                .cloned()
                .collect();
            if filtered.is_empty() {
                item.remove(&attr);
            } else {
                item.insert(attr, json!({"NS": filtered}));
            }
        } else if let (Some(existing_set), Some(del_set)) = (
            existing.get("BS").and_then(|v| v.as_array()),
            del_val.get("BS").and_then(|v| v.as_array()),
        ) {
            let filtered: Vec<Value> = existing_set
                .iter()
                .filter(|v| !del_set.contains(v))
                .cloned()
                .collect();
            if filtered.is_empty() {
                item.remove(&attr);
            } else {
                item.insert(attr, json!({"BS": filtered}));
            }
        }
    }

    Ok(())
}

pub(crate) struct TableDescriptionInput<'a> {
    pub arn: &'a str,
    pub table_id: &'a str,
    pub key_schema: &'a [KeySchemaElement],
    pub attribute_definitions: &'a [AttributeDefinition],
    pub provisioned_throughput: &'a ProvisionedThroughput,
    pub gsi: &'a [GlobalSecondaryIndex],
    pub lsi: &'a [LocalSecondaryIndex],
    pub billing_mode: &'a str,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub item_count: i64,
    pub size_bytes: i64,
    pub status: &'a str,
    pub deletion_protection_enabled: bool,
    pub on_demand_throughput: Option<&'a crate::state::OnDemandThroughput>,
}

pub(crate) fn build_table_description_json(input: &TableDescriptionInput<'_>) -> Value {
    let TableDescriptionInput {
        arn,
        table_id,
        key_schema,
        attribute_definitions,
        provisioned_throughput,
        gsi,
        lsi,
        billing_mode,
        created_at,
        item_count,
        size_bytes,
        status,
        deletion_protection_enabled,
        on_demand_throughput,
    } = *input;
    let table_name = arn.rsplit('/').next().unwrap_or("");
    let creation_timestamp =
        created_at.timestamp() as f64 + created_at.timestamp_subsec_millis() as f64 / 1000.0;

    let ks: Vec<Value> = key_schema
        .iter()
        .map(|k| json!({"AttributeName": k.attribute_name, "KeyType": k.key_type}))
        .collect();

    let ad: Vec<Value> = attribute_definitions
        .iter()
        .map(|a| json!({"AttributeName": a.attribute_name, "AttributeType": a.attribute_type}))
        .collect();

    let mut desc = json!({
        "TableName": table_name,
        "TableArn": arn,
        "TableId": table_id,
        "TableStatus": status,
        "KeySchema": ks,
        "AttributeDefinitions": ad,
        "CreationDateTime": creation_timestamp,
        "ItemCount": item_count,
        "TableSizeBytes": size_bytes,
        "BillingModeSummary": { "BillingMode": billing_mode },
        "DeletionProtectionEnabled": deletion_protection_enabled,
    });

    if billing_mode != "PAY_PER_REQUEST" {
        desc["ProvisionedThroughput"] = json!({
            "ReadCapacityUnits": provisioned_throughput.read_capacity_units,
            "WriteCapacityUnits": provisioned_throughput.write_capacity_units,
            "NumberOfDecreasesToday": 0,
        });
    } else {
        desc["ProvisionedThroughput"] = json!({
            "ReadCapacityUnits": 0,
            "WriteCapacityUnits": 0,
            "NumberOfDecreasesToday": 0,
        });
    }

    if let Some(odt) = on_demand_throughput {
        desc["OnDemandThroughput"] = json!({
            "MaxReadRequestUnits": odt.max_read_request_units,
            "MaxWriteRequestUnits": odt.max_write_request_units,
        });
    }

    // Terraform's AWS provider now waits on WarmThroughput after CreateTable.
    // Real AWS returns an ACTIVE warm throughput object for active tables,
    // including PAY_PER_REQUEST tables. Returning null keeps the provider in a
    // perpetual "still creating" loop.
    if status == "ACTIVE" {
        desc["WarmThroughput"] = json!({
            "ReadUnitsPerSecond": 0,
            "WriteUnitsPerSecond": 0,
            "Status": "ACTIVE",
        });
    }

    if !gsi.is_empty() {
        let gsi_json: Vec<Value> = gsi
            .iter()
            .map(|g| {
                let gks: Vec<Value> = g
                    .key_schema
                    .iter()
                    .map(|k| json!({"AttributeName": k.attribute_name, "KeyType": k.key_type}))
                    .collect();
                let mut idx = json!({
                    "IndexName": g.index_name,
                    "KeySchema": gks,
                    "Projection": { "ProjectionType": g.projection.projection_type },
                    "IndexStatus": "ACTIVE",
                    "IndexArn": format!("{arn}/index/{}", g.index_name),
                    "ItemCount": 0,
                    "IndexSizeBytes": 0,
                });
                if !g.projection.non_key_attributes.is_empty() {
                    idx["Projection"]["NonKeyAttributes"] = json!(g.projection.non_key_attributes);
                }
                if let Some(ref pt) = g.provisioned_throughput {
                    idx["ProvisionedThroughput"] = json!({
                        "ReadCapacityUnits": pt.read_capacity_units,
                        "WriteCapacityUnits": pt.write_capacity_units,
                        "NumberOfDecreasesToday": 0,
                    });
                }
                if let Some(ref odt) = g.on_demand_throughput {
                    idx["OnDemandThroughput"] = json!({
                        "MaxReadRequestUnits": odt.max_read_request_units,
                        "MaxWriteRequestUnits": odt.max_write_request_units,
                    });
                }
                idx
            })
            .collect();
        desc["GlobalSecondaryIndexes"] = json!(gsi_json);
    }

    if !lsi.is_empty() {
        let lsi_json: Vec<Value> = lsi
            .iter()
            .map(|l| {
                let lks: Vec<Value> = l
                    .key_schema
                    .iter()
                    .map(|k| json!({"AttributeName": k.attribute_name, "KeyType": k.key_type}))
                    .collect();
                let mut idx = json!({
                    "IndexName": l.index_name,
                    "KeySchema": lks,
                    "Projection": { "ProjectionType": l.projection.projection_type },
                    "IndexArn": format!("{arn}/index/{}", l.index_name),
                    "ItemCount": 0,
                    "IndexSizeBytes": 0,
                });
                if !l.projection.non_key_attributes.is_empty() {
                    idx["Projection"]["NonKeyAttributes"] = json!(l.projection.non_key_attributes);
                }
                idx
            })
            .collect();
        desc["LocalSecondaryIndexes"] = json!(lsi_json);
    }

    desc
}

pub(crate) fn build_table_description(table: &DynamoTable) -> Value {
    let mut desc = build_table_description_json(&TableDescriptionInput {
        arn: &table.arn,
        table_id: &table.table_id,
        key_schema: &table.key_schema,
        attribute_definitions: &table.attribute_definitions,
        provisioned_throughput: &table.provisioned_throughput,
        gsi: &table.gsi,
        lsi: &table.lsi,
        billing_mode: &table.billing_mode,
        created_at: table.created_at,
        item_count: table.item_count,
        size_bytes: table.size_bytes,
        status: &table.status,
        deletion_protection_enabled: table.deletion_protection_enabled,
        on_demand_throughput: table.on_demand_throughput.as_ref(),
    });

    // `LatestStreamArn` / `LatestStreamLabel` persist after a stream has
    // been created, even if streams are currently disabled — real AWS
    // keeps them for ~24h post-disable so DescribeTable callers can still
    // observe the last active stream. fakecloud keeps them for the
    // table's lifetime, which is sufficient for any single test run.
    if let Some(ref stream_arn) = table.stream_arn {
        desc["LatestStreamArn"] = json!(stream_arn);
        desc["LatestStreamLabel"] = json!(stream_arn.rsplit('/').next().unwrap_or(""));
    }
    // The `StreamSpecification` block is only present while streams are
    // actively enabled. When absent, the Terraform provider Read falls
    // through to the prior `stream_view_type` from its own state rather
    // than clearing it, which matches the diff behaviour the upstream
    // acceptance tests assert on.
    if table.stream_enabled {
        if let Some(ref view_type) = table.stream_view_type {
            desc["StreamSpecification"] = json!({
                "StreamEnabled": true,
                "StreamViewType": view_type,
            });
        }
    }

    // SSEDescription is only returned when the customer explicitly enabled
    // a KMS-backed SSE. Real AWS tables using the default AWS-owned key omit
    // this field entirely, and the Terraform provider's Read asserts
    // `server_side_encryption.#` == 0 in that case.
    if let Some(ref sse_type) = table.sse_type {
        let mut sse_desc = json!({
            "Status": "ENABLED",
            "SSEType": sse_type,
        });
        if let Some(ref key_arn) = table.sse_kms_key_arn {
            sse_desc["KMSMasterKeyArn"] = json!(key_arn);
        }
        desc["SSEDescription"] = sse_desc;
    }

    desc
}

pub(crate) fn execute_partiql_statement(
    state: &SharedDynamoDbState,
    statement: &str,
    parameters: &[Value],
) -> Result<AwsResponse, AwsServiceError> {
    let trimmed = statement.trim();
    let upper = trimmed.to_ascii_uppercase();

    if upper.starts_with("SELECT") {
        execute_partiql_select(state, trimmed, parameters)
    } else if upper.starts_with("INSERT") {
        execute_partiql_insert(state, trimmed, parameters)
    } else if upper.starts_with("UPDATE") {
        execute_partiql_update(state, trimmed, parameters)
    } else if upper.starts_with("DELETE") {
        execute_partiql_delete(state, trimmed, parameters)
    } else {
        Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            format!("Unsupported PartiQL statement: {trimmed}"),
        ))
    }
}

/// Parse a simple `SELECT * FROM tablename WHERE pk = 'value'` or with parameters.
pub(crate) fn execute_partiql_select(
    state: &SharedDynamoDbState,
    statement: &str,
    parameters: &[Value],
) -> Result<AwsResponse, AwsServiceError> {
    // Pattern: SELECT * FROM "tablename" [WHERE col = 'val' | WHERE col = ?]
    let upper = statement.to_ascii_uppercase();
    let from_pos = upper.find("FROM").ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "Invalid SELECT statement: missing FROM",
        )
    })?;

    let after_from = statement[from_pos + 4..].trim();
    let (table_name, rest) = parse_partiql_table_name(after_from);

    let __mas = state.read();
    let state = __mas.default_ref();
    let table = get_table(&state.tables, &table_name)?;

    let rest_upper = rest.trim().to_ascii_uppercase();
    if rest_upper.starts_with("WHERE") {
        let where_clause = rest.trim()[5..].trim();
        let matched = evaluate_partiql_where(table, where_clause, parameters)?;
        let items: Vec<Value> = matched.iter().map(|item| json!(item)).collect();
        DynamoDbService::ok_json(json!({ "Items": items }))
    } else {
        // No WHERE, return all items
        let items: Vec<Value> = table.items.iter().map(|item| json!(item)).collect();
        DynamoDbService::ok_json(json!({ "Items": items }))
    }
}

pub(crate) fn execute_partiql_insert(
    state: &SharedDynamoDbState,
    statement: &str,
    parameters: &[Value],
) -> Result<AwsResponse, AwsServiceError> {
    // Pattern: INSERT INTO "tablename" VALUE {'pk': 'val', 'attr': 'val'}
    // or with parameters: INSERT INTO "tablename" VALUE {'pk': ?, 'attr': ?}
    let upper = statement.to_ascii_uppercase();
    let into_pos = upper.find("INTO").ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "Invalid INSERT statement: missing INTO",
        )
    })?;

    let after_into = statement[into_pos + 4..].trim();
    let (table_name, rest) = parse_partiql_table_name(after_into);

    let rest_upper = rest.trim().to_ascii_uppercase();
    let value_pos = rest_upper.find("VALUE").ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "Invalid INSERT statement: missing VALUE",
        )
    })?;

    let value_str = rest.trim()[value_pos + 5..].trim();
    let item = parse_partiql_value_object(value_str, parameters)?;

    let mut __mas = state.write();
    let state = __mas.default_mut();
    let table = get_table_mut(&mut state.tables, &table_name)?;
    let key = extract_key(table, &item);
    if table.find_item_index(&key).is_some() {
        // DynamoDB PartiQL INSERT fails if item exists
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "DuplicateItemException",
            "Duplicate primary key exists in table",
        ));
    } else {
        table.items.push(item);
    }
    table.recalculate_stats();

    DynamoDbService::ok_json(json!({}))
}

pub(crate) fn execute_partiql_update(
    state: &SharedDynamoDbState,
    statement: &str,
    parameters: &[Value],
) -> Result<AwsResponse, AwsServiceError> {
    // Pattern: UPDATE "tablename" SET attr='val' WHERE pk='val'
    // or: UPDATE "tablename" SET attr=? WHERE pk=?
    let after_update = statement[6..].trim(); // skip "UPDATE"
    let (table_name, rest) = parse_partiql_table_name(after_update);

    let rest_upper = rest.trim().to_ascii_uppercase();
    let set_pos = rest_upper.find("SET").ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "Invalid UPDATE statement: missing SET",
        )
    })?;

    let after_set = rest.trim()[set_pos + 3..].trim();

    // Split on WHERE
    let where_pos = after_set.to_ascii_uppercase().find("WHERE");
    let (set_clause, where_clause) = if let Some(wp) = where_pos {
        (&after_set[..wp], after_set[wp + 5..].trim())
    } else {
        (after_set, "")
    };

    let mut __mas = state.write();
    let state = __mas.default_mut();
    let table = get_table_mut(&mut state.tables, &table_name)?;

    let matched_indices = if !where_clause.is_empty() {
        find_partiql_where_indices(table, where_clause, parameters)?
    } else {
        (0..table.items.len()).collect()
    };

    // Parse SET assignments: attr=value, attr2=value2
    let param_offset = count_params_in_str(where_clause);
    let assignments: Vec<&str> = set_clause.split(',').collect();
    for idx in &matched_indices {
        let mut local_offset = param_offset;
        for assignment in &assignments {
            let assignment = assignment.trim();
            if let Some((attr, val_str)) = assignment.split_once('=') {
                let attr = attr.trim().trim_matches('"');
                let val_str = val_str.trim();
                let value = parse_partiql_literal(val_str, parameters, &mut local_offset);
                if let Some(v) = value {
                    table.items[*idx].insert(attr.to_string(), v);
                }
            }
        }
    }
    table.recalculate_stats();

    DynamoDbService::ok_json(json!({}))
}

pub(crate) fn execute_partiql_delete(
    state: &SharedDynamoDbState,
    statement: &str,
    parameters: &[Value],
) -> Result<AwsResponse, AwsServiceError> {
    // Pattern: DELETE FROM "tablename" WHERE pk='val'
    let upper = statement.to_ascii_uppercase();
    let from_pos = upper.find("FROM").ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "Invalid DELETE statement: missing FROM",
        )
    })?;

    let after_from = statement[from_pos + 4..].trim();
    let (table_name, rest) = parse_partiql_table_name(after_from);

    let rest_upper = rest.trim().to_ascii_uppercase();
    if !rest_upper.starts_with("WHERE") {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "DELETE requires a WHERE clause",
        ));
    }
    let where_clause = rest.trim()[5..].trim();

    let mut __mas = state.write();
    let state = __mas.default_mut();
    let table = get_table_mut(&mut state.tables, &table_name)?;

    let mut indices = find_partiql_where_indices(table, where_clause, parameters)?;
    // Remove from highest index first to avoid invalidating lower indices
    indices.sort_unstable();
    indices.reverse();
    for idx in indices {
        table.items.remove(idx);
    }
    table.recalculate_stats();

    DynamoDbService::ok_json(json!({}))
}

/// Parse a table name that may be quoted with double quotes.
/// Returns (table_name, rest_of_string).
pub(crate) fn parse_partiql_table_name(s: &str) -> (String, &str) {
    let s = s.trim();
    if let Some(stripped) = s.strip_prefix('"') {
        // Quoted name
        if let Some(end) = stripped.find('"') {
            let name = &stripped[..end];
            let rest = &stripped[end + 1..];
            (name.to_string(), rest)
        } else {
            let end = s.find(' ').unwrap_or(s.len());
            (s[..end].trim_matches('"').to_string(), &s[end..])
        }
    } else {
        let end = s.find(|c: char| c.is_whitespace()).unwrap_or(s.len());
        (s[..end].to_string(), &s[end..])
    }
}

/// Evaluate a simple WHERE clause: `col = 'value'` or `col = ?`
/// Returns matching items.
pub(crate) fn evaluate_partiql_where<'a>(
    table: &'a DynamoTable,
    where_clause: &str,
    parameters: &[Value],
) -> Result<Vec<&'a HashMap<String, AttributeValue>>, AwsServiceError> {
    let indices = find_partiql_where_indices(table, where_clause, parameters)?;
    Ok(indices.iter().map(|i| &table.items[*i]).collect())
}

pub(crate) fn find_partiql_where_indices(
    table: &DynamoTable,
    where_clause: &str,
    parameters: &[Value],
) -> Result<Vec<usize>, AwsServiceError> {
    let conditions = split_partiql_and_clauses(where_clause);
    let parsed_conditions = parse_partiql_equality_conditions(&conditions, parameters);

    let mut indices = Vec::new();
    for (i, item) in table.items.iter().enumerate() {
        let all_match = parsed_conditions
            .iter()
            .all(|(attr, expected)| item.get(attr) == Some(expected));
        if all_match {
            indices.push(i);
        }
    }

    Ok(indices)
}

/// Split a PartiQL WHERE clause on case-insensitive ` AND ` boundaries.
pub(crate) fn split_partiql_and_clauses(where_clause: &str) -> Vec<&str> {
    let upper = where_clause.to_uppercase();
    if !upper.contains(" AND ") {
        return vec![where_clause.trim()];
    }
    let mut parts = Vec::new();
    let mut last = 0;
    for (i, _) in upper.match_indices(" AND ") {
        parts.push(where_clause[last..i].trim());
        last = i + 5;
    }
    parts.push(where_clause[last..].trim());
    parts
}

/// Parse each `col = literal` (or `col = ?`) condition into an
/// `(attribute_name, expected_AttributeValue)` pair. Conditions that
/// don't parse as equality, or whose RHS literal can't be resolved, are
/// silently dropped — that mirrors the prior inline behavior.
pub(crate) fn parse_partiql_equality_conditions(
    conditions: &[&str],
    parameters: &[Value],
) -> Vec<(String, Value)> {
    let mut param_idx = 0usize;
    let mut parsed = Vec::new();
    for cond in conditions {
        let cond = cond.trim();
        if let Some((left, right)) = cond.split_once('=') {
            let attr = left.trim().trim_matches('"').to_string();
            let val_str = right.trim();
            if let Some(value) = parse_partiql_literal(val_str, parameters, &mut param_idx) {
                parsed.push((attr, value));
            }
        }
    }
    parsed
}

/// Parse a PartiQL literal value. Supports:
/// - 'string' -> {"S": "string"}
/// - 123 -> {"N": "123"}
/// - ? -> parameter from list
pub(crate) fn parse_partiql_literal(
    s: &str,
    parameters: &[Value],
    param_idx: &mut usize,
) -> Option<Value> {
    let s = s.trim();
    if s == "?" {
        let idx = *param_idx;
        *param_idx += 1;
        parameters.get(idx).cloned()
    } else if s.starts_with('\'') && s.ends_with('\'') && s.len() >= 2 {
        let inner = &s[1..s.len() - 1];
        Some(json!({"S": inner}))
    } else if let Ok(n) = s.parse::<f64>() {
        let num_str = if n == n.trunc() {
            format!("{}", n as i64)
        } else {
            format!("{n}")
        };
        Some(json!({"N": num_str}))
    } else {
        None
    }
}

/// Parse a PartiQL VALUE object like `{'pk': 'val1', 'attr': 'val2'}` or with ? params.
pub(crate) fn parse_partiql_value_object(
    s: &str,
    parameters: &[Value],
) -> Result<HashMap<String, AttributeValue>, AwsServiceError> {
    let s = s.trim();
    let inner = s
        .strip_prefix('{')
        .and_then(|s| s.strip_suffix('}'))
        .ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "Invalid VALUE: expected object literal",
            )
        })?;

    let mut item = HashMap::new();
    let mut param_idx = 0usize;

    // Simple comma-separated key:value parsing
    for pair in split_partiql_pairs(inner) {
        let pair = pair.trim();
        if pair.is_empty() {
            continue;
        }
        if let Some((key_part, val_part)) = pair.split_once(':') {
            let key = key_part
                .trim()
                .trim_matches('\'')
                .trim_matches('"')
                .to_string();
            if let Some(val) = parse_partiql_literal(val_part.trim(), parameters, &mut param_idx) {
                item.insert(key, val);
            }
        }
    }

    Ok(item)
}

/// Split PartiQL object pairs on commas, respecting nested braces and quotes.
pub(crate) fn split_partiql_pairs(s: &str) -> Vec<&str> {
    let mut parts = Vec::new();
    let mut start = 0;
    let mut depth = 0;
    let mut in_quote = false;

    for (i, c) in s.char_indices() {
        match c {
            '\'' if !in_quote => in_quote = true,
            '\'' if in_quote => in_quote = false,
            '{' if !in_quote => depth += 1,
            '}' if !in_quote => depth -= 1,
            ',' if !in_quote && depth == 0 => {
                parts.push(&s[start..i]);
                start = i + 1;
            }
            _ => {}
        }
    }
    parts.push(&s[start..]);
    parts
}

/// Count ? parameters in a string.
pub(crate) fn count_params_in_str(s: &str) -> usize {
    s.chars().filter(|c| *c == '?').count()
}
