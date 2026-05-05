use base64::Engine;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Internal sentinel emitted whenever a CFN value resolves to
/// `AWS::NoValue`. After resolution finishes, [`strip_no_value`] walks
/// the result and removes any object entry / array slot whose value is
/// this marker, matching CloudFormation's "drop the property" semantics
/// (e.g. inside an `Fn::If` branch). Picked so it cannot collide with
/// any real CFN property.
const NO_VALUE_SENTINEL_KEY: &str = "__fakecloud_aws_no_value__";

/// A parsed CloudFormation template.
#[derive(Debug, Clone)]
pub struct ParsedTemplate {
    pub description: Option<String>,
    pub resources: Vec<ResourceDefinition>,
    pub outputs: Vec<TemplateOutput>,
}

/// Resolved Outputs entry from the template's top-level `Outputs` block.
/// `value` is the post-resolution string; `export_name` is set when the
/// output declares `Export.Name`.
#[derive(Debug, Clone)]
pub struct TemplateOutput {
    pub logical_id: String,
    pub value: String,
    pub description: Option<String>,
    pub export_name: Option<String>,
}

/// A single resource from the template.
#[derive(Debug, Clone)]
pub struct ResourceDefinition {
    pub logical_id: String,
    pub resource_type: String,
    pub properties: Value,
}

/// Known pseudo-references that should be passed through as-is.
const PSEUDO_REFS: &[&str] = &[
    "AWS::AccountId",
    "AWS::NotificationARNs",
    "AWS::NoValue",
    "AWS::Partition",
    "AWS::Region",
    "AWS::StackId",
    "AWS::StackName",
    "AWS::URLSuffix",
];

/// Parse a CloudFormation template from a string (JSON or YAML).
pub fn parse_template(
    template_body: &str,
    parameters: &BTreeMap<String, String>,
) -> Result<ParsedTemplate, String> {
    parse_template_with_physical_ids(template_body, parameters, &BTreeMap::new())
}

/// Parse a CloudFormation template, resolving Refs using known physical resource IDs.
pub fn parse_template_with_physical_ids(
    template_body: &str,
    parameters: &BTreeMap<String, String>,
    resource_physical_ids: &BTreeMap<String, String>,
) -> Result<ParsedTemplate, String> {
    parse_template_with_resolution(
        template_body,
        parameters,
        resource_physical_ids,
        &BTreeMap::new(),
    )
}

/// Parse a CloudFormation template, resolving `Ref` via `resource_physical_ids`
/// and `Fn::GetAtt` via `resource_attributes` (keyed by logical id, then
/// attribute name).
pub fn parse_template_with_resolution(
    template_body: &str,
    parameters: &BTreeMap<String, String>,
    resource_physical_ids: &BTreeMap<String, String>,
    resource_attributes: &BTreeMap<String, BTreeMap<String, String>>,
) -> Result<ParsedTemplate, String> {
    let value: Value = if template_body.trim_start().starts_with('{') {
        serde_json::from_str(template_body).map_err(|e| format!("Invalid JSON template: {e}"))?
    } else {
        serde_yaml::from_str(template_body).map_err(|e| format!("Invalid YAML template: {e}"))?
    };

    let description = value
        .get("Description")
        .and_then(|v| v.as_str())
        .map(|s| s.to_string());

    let conditions = evaluate_conditions(&value, parameters)?;
    let mappings = parse_mappings(&value);

    let resources_obj = value
        .get("Resources")
        .and_then(|v| v.as_object())
        .ok_or("Template must contain a Resources section")?;

    let mut resources = Vec::new();
    for (logical_id, resource) in resources_obj {
        // Skip resources whose Condition evaluates to false. Real CFN
        // simply omits these resources from the stack.
        if let Some(cond_name) = resource.get("Condition").and_then(|v| v.as_str()) {
            if !conditions.get(cond_name).copied().unwrap_or(false) {
                continue;
            }
        }
        let resource_type = resource
            .get("Type")
            .and_then(|v| v.as_str())
            .ok_or(format!("Resource {logical_id} must have a Type property"))?
            .to_string();

        let properties = resource
            .get("Properties")
            .cloned()
            .unwrap_or(Value::Object(serde_json::Map::new()));

        // Pre-resolve Fn::FindInMap before the main intrinsics pass so the
        // existing resolver doesn't need to thread mappings through.
        let properties = apply_mappings(&properties, parameters, &mappings)?;

        // Resolve Ref and parameter substitutions in properties
        let resolved = resolve_refs_full(
            &properties,
            parameters,
            resources_obj,
            resource_physical_ids,
            resource_attributes,
            &BTreeMap::new(),
            &conditions,
        );
        let resolved = strip_no_value(resolved);

        resources.push(ResourceDefinition {
            logical_id: logical_id.clone(),
            resource_type,
            properties: resolved,
        });
    }

    let outputs = parse_outputs(
        &value,
        parameters,
        resources_obj,
        resource_physical_ids,
        resource_attributes,
        &BTreeMap::new(),
    )?;

    Ok(ParsedTemplate {
        description,
        resources,
        outputs,
    })
}

/// Walk every `Fn::ImportValue` site in the parsed template (Resources +
/// Outputs) and collect the static export names it references. Names that
/// can only be resolved at runtime (e.g. `{ "Fn::Sub": "${Env}-arn" }`)
/// resolve against `parameters` first; if they still aren't strings,
/// they're skipped — the runtime resolver will surface the gap then.
pub fn collect_import_value_names(
    template: &Value,
    parameters: &BTreeMap<String, String>,
) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    collect_imports_walk(template, parameters, &mut out);
    out.sort();
    out.dedup();
    out
}

fn collect_imports_walk(
    value: &Value,
    parameters: &BTreeMap<String, String>,
    out: &mut Vec<String>,
) {
    match value {
        Value::Object(map) => {
            if let Some(arg) = map.get("Fn::ImportValue") {
                if let Some(name) = static_import_name(arg, parameters) {
                    out.push(name);
                } else {
                    // Recurse into the arg in case it contains nested ImportValues.
                    collect_imports_walk(arg, parameters, out);
                }
            }
            for (k, v) in map {
                if k == "Fn::ImportValue" {
                    continue;
                }
                collect_imports_walk(v, parameters, out);
            }
        }
        Value::Array(arr) => {
            for v in arr {
                collect_imports_walk(v, parameters, out);
            }
        }
        _ => {}
    }
}

fn static_import_name(value: &Value, parameters: &BTreeMap<String, String>) -> Option<String> {
    match value {
        Value::String(s) => Some(s.clone()),
        Value::Object(m) => {
            if let Some(name) = m.get("Ref").and_then(|v| v.as_str()) {
                return parameters.get(name).cloned();
            }
            if let Some(s) = m.get("Fn::Sub").and_then(|v| v.as_str()) {
                let mut result = s.to_string();
                for (k, v) in parameters {
                    result = result.replace(&format!("${{{k}}}"), v);
                }
                if !result.contains("${") {
                    return Some(result);
                }
            }
            None
        }
        _ => None,
    }
}

/// Parse the template's `Outputs` block into resolved entries. Each
/// `Value` is fully resolved (Ref / GetAtt / Sub / Join / Fn::ImportValue)
/// to a string. Imports use `imports` for cross-stack lookups.
pub fn parse_outputs(
    template: &Value,
    parameters: &BTreeMap<String, String>,
    resources: &serde_json::Map<String, Value>,
    resource_physical_ids: &BTreeMap<String, String>,
    resource_attributes: &BTreeMap<String, BTreeMap<String, String>>,
    imports: &BTreeMap<String, String>,
) -> Result<Vec<TemplateOutput>, String> {
    let outputs_obj = match template.get("Outputs").and_then(|v| v.as_object()) {
        Some(o) => o,
        None => return Ok(Vec::new()),
    };

    let conditions = evaluate_conditions(template, parameters)?;
    let mut out = Vec::new();
    for (logical_id, body) in outputs_obj {
        // Skip outputs gated on a Condition that resolves false. CFN
        // simply omits these from the resolved Outputs set.
        if let Some(cond_name) = body.get("Condition").and_then(|v| v.as_str()) {
            if !conditions.get(cond_name).copied().unwrap_or(false) {
                continue;
            }
        }
        let raw_value = match body.get("Value") {
            Some(v) => v,
            None => continue,
        };
        let resolved = resolve_refs_full(
            raw_value,
            parameters,
            resources,
            resource_physical_ids,
            resource_attributes,
            imports,
            &conditions,
        );
        let resolved = strip_no_value(resolved);
        let value = match resolved {
            Value::String(s) => s,
            other => other.to_string(),
        };
        let description = body
            .get("Description")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let export_name = body.get("Export").and_then(|e| e.get("Name")).map(|n| {
            let resolved = resolve_refs_full(
                n,
                parameters,
                resources,
                resource_physical_ids,
                resource_attributes,
                imports,
                &conditions,
            );
            match resolved {
                Value::String(s) => s,
                other => other.to_string(),
            }
        });
        out.push(TemplateOutput {
            logical_id: logical_id.clone(),
            value,
            description,
            export_name,
        });
    }
    Ok(out)
}

/// Walk the top-level `Conditions` block and evaluate each entry to a
/// boolean. Conditions can reference each other; we evaluate
/// recursively with memoization plus an `in_progress` set to surface a
/// clear error on cycles (`A` -> `B` -> `A`).
fn evaluate_conditions(
    template: &Value,
    parameters: &BTreeMap<String, String>,
) -> Result<BTreeMap<String, bool>, String> {
    let mut memo: BTreeMap<String, bool> = BTreeMap::new();
    let Some(conds) = template.get("Conditions").and_then(|v| v.as_object()) else {
        return Ok(memo);
    };
    let mut in_progress: BTreeSet<String> = BTreeSet::new();
    let names: Vec<String> = conds.keys().cloned().collect();
    for name in names {
        evaluate_condition_named(&name, conds, parameters, &mut memo, &mut in_progress)?;
    }
    Ok(memo)
}

/// Resolve a single named condition, recursively walking its expression
/// tree. Memoizes into `memo`, tracks in-flight names in `in_progress`
/// to detect cycles. `Condition: <name>` references trigger recursion.
fn evaluate_condition_named(
    name: &str,
    conds: &serde_json::Map<String, Value>,
    parameters: &BTreeMap<String, String>,
    memo: &mut BTreeMap<String, bool>,
    in_progress: &mut BTreeSet<String>,
) -> Result<bool, String> {
    if let Some(b) = memo.get(name) {
        return Ok(*b);
    }
    if !in_progress.insert(name.to_string()) {
        return Err(format!(
            "Circular reference in Conditions: '{name}' transitively references itself"
        ));
    }
    let expr = conds.get(name).ok_or_else(|| {
        format!("Condition '{name}' is referenced but not defined in Conditions block")
    })?;
    let result = eval_condition_expr(expr, conds, parameters, memo, in_progress)?;
    in_progress.remove(name);
    memo.insert(name.to_string(), result);
    Ok(result)
}

type Mappings = BTreeMap<String, BTreeMap<String, BTreeMap<String, Value>>>;

/// Parse the top-level `Mappings` block into a 2-level lookup table.
/// `Fn::FindInMap: [MapName, TopKey, SecondKey]` returns the leaf
/// value at that path.
fn parse_mappings(template: &Value) -> Mappings {
    let mut out: Mappings = BTreeMap::new();
    let Some(maps) = template.get("Mappings").and_then(|v| v.as_object()) else {
        return out;
    };
    for (map_name, top) in maps {
        let Some(top_obj) = top.as_object() else {
            continue;
        };
        let mut top_out = BTreeMap::new();
        for (top_key, second) in top_obj {
            let Some(second_obj) = second.as_object() else {
                continue;
            };
            let mut second_out: BTreeMap<String, Value> = BTreeMap::new();
            for (k, v) in second_obj {
                second_out.insert(k.clone(), v.clone());
            }
            top_out.insert(top_key.clone(), second_out);
        }
        out.insert(map_name.clone(), top_out);
    }
    out
}

/// Evaluate a single condition expression node. Operators short-circuit
/// where it matters (`Fn::And` stops on first false, `Fn::Or` stops on
/// first true). Named-condition references recurse via
/// `evaluate_condition_named` so cycles are caught at the named layer.
fn eval_condition_expr(
    expr: &Value,
    conds: &serde_json::Map<String, Value>,
    parameters: &BTreeMap<String, String>,
    memo: &mut BTreeMap<String, bool>,
    in_progress: &mut BTreeSet<String>,
) -> Result<bool, String> {
    if let Some(b) = expr.as_bool() {
        return Ok(b);
    }
    let map = expr
        .as_object()
        .ok_or_else(|| format!("Invalid condition expression: {expr}"))?;
    if let Some(args) = map.get("Fn::Equals").and_then(|v| v.as_array()) {
        if args.len() != 2 {
            return Err("Fn::Equals requires exactly 2 arguments".to_string());
        }
        let a = stringify_value(&args[0], parameters);
        let b = stringify_value(&args[1], parameters);
        return Ok(a == b);
    }
    if let Some(args) = map.get("Fn::And").and_then(|v| v.as_array()) {
        if !(1..=10).contains(&args.len()) {
            return Err("Fn::And requires between 1 and 10 conditions".to_string());
        }
        for a in args {
            if !eval_condition_expr(a, conds, parameters, memo, in_progress)? {
                return Ok(false);
            }
        }
        return Ok(true);
    }
    if let Some(args) = map.get("Fn::Or").and_then(|v| v.as_array()) {
        if !(1..=10).contains(&args.len()) {
            return Err("Fn::Or requires between 1 and 10 conditions".to_string());
        }
        for a in args {
            if eval_condition_expr(a, conds, parameters, memo, in_progress)? {
                return Ok(true);
            }
        }
        return Ok(false);
    }
    if let Some(arr) = map.get("Fn::Not").and_then(|v| v.as_array()) {
        if arr.len() != 1 {
            return Err("Fn::Not requires exactly 1 argument".to_string());
        }
        return Ok(!eval_condition_expr(
            &arr[0],
            conds,
            parameters,
            memo,
            in_progress,
        )?);
    }
    if let Some(name) = map.get("Condition").and_then(|v| v.as_str()) {
        return evaluate_condition_named(name, conds, parameters, memo, in_progress);
    }
    Err(format!("Unknown condition operator in expression: {expr}"))
}

/// Render a CFN intrinsic value (Ref to a parameter, plain string, etc.)
/// as a string for Fn::Equals comparison.
fn stringify_value(value: &Value, parameters: &BTreeMap<String, String>) -> String {
    match value {
        Value::String(s) => s.clone(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::Object(m) => {
            if let Some(name) = m.get("Ref").and_then(|v| v.as_str()) {
                if let Some(p) = parameters.get(name) {
                    return p.clone();
                }
                return name.to_string();
            }
            value.to_string()
        }
        _ => value.to_string(),
    }
}

/// Walk `value`, replacing every `Fn::FindInMap` map ref with its
/// resolved leaf value. Args resolve `Ref` / nested `Fn::FindInMap`
/// against `parameters` + `mappings` first. Unresolvable lookups return
/// the optional `DefaultValue` from the 4-arg form, otherwise surface a
/// `ValidationError`-shaped string matching CloudFormation's error.
fn apply_mappings(
    value: &Value,
    parameters: &BTreeMap<String, String>,
    mappings: &Mappings,
) -> Result<Value, String> {
    match value {
        Value::Object(map) => {
            if let Some(arr) = map.get("Fn::FindInMap").and_then(|v| v.as_array()) {
                return resolve_find_in_map(arr, parameters, mappings);
            }
            let mut new_map = serde_json::Map::new();
            for (k, v) in map {
                new_map.insert(k.clone(), apply_mappings(v, parameters, mappings)?);
            }
            Ok(Value::Object(new_map))
        }
        Value::Array(arr) => {
            let mut out = Vec::with_capacity(arr.len());
            for v in arr {
                out.push(apply_mappings(v, parameters, mappings)?);
            }
            Ok(Value::Array(out))
        }
        other => Ok(other.clone()),
    }
}

/// Resolve a single `Fn::FindInMap` array. Supports the 3-arg form
/// `[MapName, TopKey, SecondKey]` and the 4-arg form
/// `[MapName, TopKey, SecondKey, { DefaultValue: <value> }]`. Args may
/// themselves be intrinsics (e.g. `{ "Ref": "AWS::Region" }` or a
/// nested `Fn::FindInMap`); those resolve before lookup.
fn resolve_find_in_map(
    arr: &[Value],
    parameters: &BTreeMap<String, String>,
    mappings: &Mappings,
) -> Result<Value, String> {
    if arr.len() != 3 && arr.len() != 4 {
        return Err(format!(
            "Fn::FindInMap requires 3 or 4 arguments, got {}",
            arr.len()
        ));
    }
    let default_value: Option<Value> = if arr.len() == 4 {
        let opts = arr[3].as_object().ok_or_else(|| {
            "Fn::FindInMap fourth argument must be an object with a DefaultValue key".to_string()
        })?;
        let dv = opts.get("DefaultValue").ok_or_else(|| {
            "Fn::FindInMap fourth argument must contain a DefaultValue key".to_string()
        })?;
        Some(apply_mappings(dv, parameters, mappings)?)
    } else {
        None
    };

    let map_name = stringify_findinmap_arg(&arr[0], parameters, mappings)?;
    let top_key = stringify_findinmap_arg(&arr[1], parameters, mappings)?;
    let second_key = stringify_findinmap_arg(&arr[2], parameters, mappings)?;

    if let Some(top) = mappings.get(&map_name) {
        if let Some(second) = top.get(&top_key) {
            if let Some(leaf) = second.get(&second_key) {
                return Ok(leaf.clone());
            }
        }
    }

    if let Some(dv) = default_value {
        return Ok(dv);
    }

    Err(format!(
        "Template error: Unable to get mapping for {map_name}::{top_key}::{second_key}"
    ))
}

fn stringify_findinmap_arg(
    value: &Value,
    parameters: &BTreeMap<String, String>,
    mappings: &Mappings,
) -> Result<String, String> {
    match value {
        Value::String(s) => Ok(s.clone()),
        Value::Object(m) => {
            if let Some(name) = m.get("Ref").and_then(|v| v.as_str()) {
                if let Some(p) = parameters.get(name) {
                    return Ok(p.clone());
                }
                // Pseudo refs that have a canonical default value
                // resolve so FindInMap keyed off `AWS::Region` etc.
                // works without the caller priming `parameters`.
                if let Some(Value::String(s)) = pseudo_value(name, parameters) {
                    return Ok(s);
                }
                return Ok(name.to_string());
            }
            // Nested Fn::FindInMap as a key — resolve it and stringify
            // the leaf, so e.g. `Fn::FindInMap: [Outer, !FindInMap [...], K]`
            // works.
            if let Some(arr) = m.get("Fn::FindInMap").and_then(|v| v.as_array()) {
                let resolved = resolve_find_in_map(arr, parameters, mappings)?;
                return Ok(match resolved {
                    Value::String(s) => s,
                    other => other.to_string(),
                });
            }
            Ok(value.to_string())
        }
        _ => Ok(value.to_string()),
    }
}

/// Re-resolve a single resource definition's properties with updated physical IDs.
pub fn resolve_resource_properties(
    resource: &ResourceDefinition,
    template_body: &str,
    parameters: &BTreeMap<String, String>,
    resource_physical_ids: &BTreeMap<String, String>,
) -> Result<ResourceDefinition, String> {
    resolve_resource_properties_with_attrs(
        resource,
        template_body,
        parameters,
        resource_physical_ids,
        &BTreeMap::new(),
    )
}

/// Re-resolve a single resource definition's properties with updated physical
/// IDs and attribute values for `Fn::GetAtt`.
pub fn resolve_resource_properties_with_attrs(
    resource: &ResourceDefinition,
    template_body: &str,
    parameters: &BTreeMap<String, String>,
    resource_physical_ids: &BTreeMap<String, String>,
    resource_attributes: &BTreeMap<String, BTreeMap<String, String>>,
) -> Result<ResourceDefinition, String> {
    let value: Value = if template_body.trim_start().starts_with('{') {
        serde_json::from_str(template_body).map_err(|e| format!("Invalid JSON template: {e}"))?
    } else {
        serde_yaml::from_str(template_body).map_err(|e| format!("Invalid YAML template: {e}"))?
    };

    let resources_obj = value
        .get("Resources")
        .and_then(|v| v.as_object())
        .ok_or("Template must contain a Resources section")?;

    let raw_props = resources_obj
        .get(&resource.logical_id)
        .and_then(|r| r.get("Properties"))
        .cloned()
        .unwrap_or(Value::Object(serde_json::Map::new()));

    // Re-evaluate Conditions / Mappings on every resolve so Fn::If picks
    // the right branch and AWS::NoValue still strips at incremental
    // provisioning time. Without this, the sentinel would leak into the
    // provisioned property map.
    let conditions = evaluate_conditions(&value, parameters)?;
    let mappings = parse_mappings(&value);
    let raw_props = apply_mappings(&raw_props, parameters, &mappings)?;

    let resolved = resolve_refs_full(
        &raw_props,
        parameters,
        resources_obj,
        resource_physical_ids,
        resource_attributes,
        &BTreeMap::new(),
        &conditions,
    );
    let resolved = strip_no_value(resolved);

    Ok(ResourceDefinition {
        logical_id: resource.logical_id.clone(),
        resource_type: resource.resource_type.clone(),
        properties: resolved,
    })
}

/// Substitute a pseudo-parameter with the value provided through the
/// stack `parameters` map (keyed by the same `AWS::*` name). When the
/// caller hasn't supplied a value, fall back to the canonical default
/// for that parameter (commercial partition / us-east-1 / empty list).
fn pseudo_value(name: &str, parameters: &BTreeMap<String, String>) -> Option<Value> {
    if let Some(v) = parameters.get(name) {
        return Some(Value::String(v.clone()));
    }
    match name {
        "AWS::Partition" => Some(Value::String("aws".to_string())),
        "AWS::URLSuffix" => Some(Value::String("amazonaws.com".to_string())),
        "AWS::Region" => Some(Value::String("us-east-1".to_string())),
        // NotificationARNs is an array; default to empty.
        "AWS::NotificationARNs" => Some(Value::Array(Vec::new())),
        // NoValue is a sentinel: emit a private marker object so the
        // post-resolution `strip_no_value` walk can drop the parent
        // property entirely. CloudFormation removes the key from the
        // resolved object rather than leaving a JSON null behind.
        "AWS::NoValue" => Some(no_value_sentinel()),
        _ => None,
    }
}

/// Build a fresh `AWS::NoValue` sentinel object. See
/// [`NO_VALUE_SENTINEL_KEY`].
fn no_value_sentinel() -> Value {
    let mut m = serde_json::Map::new();
    m.insert(NO_VALUE_SENTINEL_KEY.to_string(), Value::Bool(true));
    Value::Object(m)
}

/// Return true when `value` is the `AWS::NoValue` sentinel emitted by
/// `pseudo_value` (or by an `Fn::If` branch that resolved to it).
fn is_no_value(value: &Value) -> bool {
    value
        .as_object()
        .map(|m| m.len() == 1 && m.contains_key(NO_VALUE_SENTINEL_KEY))
        .unwrap_or(false)
}

/// Recursively walk `value` and drop any object entry / array slot
/// whose resolved content is the `AWS::NoValue` sentinel. A top-level
/// `AWS::NoValue` collapses to `Value::Null` so the caller can detect
/// the empty case (CFN's behavior is to omit the property entirely).
fn strip_no_value(value: Value) -> Value {
    match value {
        Value::Object(map) => {
            if is_no_value(&Value::Object(map.clone())) {
                return Value::Null;
            }
            let mut out = serde_json::Map::with_capacity(map.len());
            for (k, v) in map {
                if is_no_value(&v) {
                    continue;
                }
                out.insert(k, strip_no_value(v));
            }
            Value::Object(out)
        }
        Value::Array(arr) => Value::Array(
            arr.into_iter()
                .filter(|v| !is_no_value(v))
                .map(strip_no_value)
                .collect(),
        ),
        other => other,
    }
}

/// Resolve `Ref`, `Fn::GetAtt`, `Fn::Join`, and `Fn::Sub` in property
/// values. Cross-stack `Fn::ImportValue` is not consulted; use
/// `resolve_refs_with_imports` for that. Test-only after the
/// resource-properties path moved to `resolve_refs_full`.
#[cfg(test)]
fn resolve_refs(
    value: &Value,
    parameters: &BTreeMap<String, String>,
    _resources: &serde_json::Map<String, Value>,
    resource_physical_ids: &BTreeMap<String, String>,
    resource_attributes: &BTreeMap<String, BTreeMap<String, String>>,
) -> Value {
    resolve_refs_full(
        value,
        parameters,
        _resources,
        resource_physical_ids,
        resource_attributes,
        &BTreeMap::new(),
        &BTreeMap::new(),
    )
}

/// Resolve `Ref`, `Fn::GetAtt`, `Fn::Join`, `Fn::Sub`, and
/// `Fn::ImportValue` in property values.
fn resolve_refs_full(
    value: &Value,
    parameters: &BTreeMap<String, String>,
    _resources: &serde_json::Map<String, Value>,
    resource_physical_ids: &BTreeMap<String, String>,
    resource_attributes: &BTreeMap<String, BTreeMap<String, String>>,
    imports: &BTreeMap<String, String>,
    conditions: &BTreeMap<String, bool>,
) -> Value {
    // Fn::If always rewrites to either branch BEFORE descent so we don't
    // try to resolve the unused branch (it may legitimately reference an
    // unconditional resource).
    if let Some(map) = value.as_object() {
        if let Some(arr) = map.get("Fn::If").and_then(|v| v.as_array()) {
            if arr.len() == 3 {
                let cond_name = arr[0].as_str().unwrap_or("");
                let picked = if conditions.get(cond_name).copied().unwrap_or(false) {
                    &arr[1]
                } else {
                    &arr[2]
                };
                return resolve_refs_full(
                    picked,
                    parameters,
                    _resources,
                    resource_physical_ids,
                    resource_attributes,
                    imports,
                    conditions,
                );
            }
        }
    }
    match value {
        Value::Object(map) => {
            if let Some(ref_val) = map.get("Ref") {
                if let Some(ref_name) = ref_val.as_str() {
                    // 1. Check explicit parameters first
                    if let Some(param_val) = parameters.get(ref_name) {
                        return Value::String(param_val.clone());
                    }
                    // 2. Check already-provisioned resource physical IDs
                    if let Some(physical_id) = resource_physical_ids.get(ref_name) {
                        return Value::String(physical_id.clone());
                    }
                    // 3. Substitute pseudo-references with their stack-context
                    //    value (or a sane default for shape-only parity).
                    if PSEUDO_REFS.contains(&ref_name) {
                        if let Some(v) = pseudo_value(ref_name, parameters) {
                            return v;
                        }
                        return Value::String(ref_name.to_string());
                    }
                    // 4. If it's a known logical resource in the template but not yet
                    //    provisioned, return the logical ID (will be resolved later
                    //    during incremental provisioning)
                    if _resources.contains_key(ref_name) {
                        return Value::String(ref_name.to_string());
                    }
                    // 5. Unknown ref — return as-is (could be a default parameter)
                    return Value::String(ref_name.to_string());
                }
            }
            // Fn::ImportValue: look up an exported value from another stack.
            // Resolves to the empty string when the export name isn't known
            // (callers that need strict failure can pre-validate).
            if let Some(import_val) = map.get("Fn::ImportValue") {
                let resolved = resolve_refs_full(
                    import_val,
                    parameters,
                    _resources,
                    resource_physical_ids,
                    resource_attributes,
                    imports,
                    conditions,
                );
                let key = match &resolved {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                if let Some(v) = imports.get(&key) {
                    return Value::String(v.clone());
                }
                return Value::String(String::new());
            }
            if let Some(getatt_val) = map.get("Fn::GetAtt") {
                if let Some((logical_id, attr_name)) = parse_getatt(getatt_val) {
                    if let Some(attrs) = resource_attributes.get(&logical_id) {
                        if let Some(attr_value) = attrs.get(&attr_name) {
                            return Value::String(attr_value.clone());
                        }
                    }
                    // Resource not yet provisioned, or attribute unknown.
                    // Surface a placeholder so the consumer can still string-format
                    // it; multi-pass provisioning will retry once attributes land.
                    return Value::String(format!("{logical_id}.{attr_name}"));
                }
            }
            if let Some(join_val) = map.get("Fn::Join") {
                if let Some(arr) = join_val.as_array() {
                    if arr.len() == 2 {
                        let delimiter = arr[0].as_str().unwrap_or("");
                        if let Some(parts) = arr[1].as_array() {
                            let resolved_parts: Vec<String> = parts
                                .iter()
                                .map(|p| {
                                    let resolved = resolve_refs_full(
                                        p,
                                        parameters,
                                        _resources,
                                        resource_physical_ids,
                                        resource_attributes,
                                        imports,
                                        conditions,
                                    );
                                    match resolved {
                                        Value::String(s) => s,
                                        other => other.to_string(),
                                    }
                                })
                                .collect();
                            return Value::String(resolved_parts.join(delimiter));
                        }
                    }
                }
            }
            // Fn::Base64: base64-encode a string (or recursively-resolved
            // value).
            if let Some(b64_val) = map.get("Fn::Base64") {
                let resolved = resolve_refs_full(
                    b64_val,
                    parameters,
                    _resources,
                    resource_physical_ids,
                    resource_attributes,
                    imports,
                    conditions,
                );
                let s = match &resolved {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                };
                return Value::String(
                    base64::engine::general_purpose::STANDARD.encode(s.as_bytes()),
                );
            }
            // Fn::Length: number of elements in an array.
            if let Some(len_val) = map.get("Fn::Length") {
                let resolved = resolve_refs_full(
                    len_val,
                    parameters,
                    _resources,
                    resource_physical_ids,
                    resource_attributes,
                    imports,
                    conditions,
                );
                if let Some(arr) = resolved.as_array() {
                    return Value::Number(serde_json::Number::from(arr.len()));
                }
                return Value::Number(serde_json::Number::from(0));
            }
            // Fn::ToJsonString: serialize a value as a JSON string.
            if let Some(to_json) = map.get("Fn::ToJsonString") {
                let resolved = resolve_refs_full(
                    to_json,
                    parameters,
                    _resources,
                    resource_physical_ids,
                    resource_attributes,
                    imports,
                    conditions,
                );
                let s = serde_json::to_string(&resolved).unwrap_or_default();
                return Value::String(s);
            }
            // Fn::Split: split a string by a delimiter into an array of
            // strings. Args: ["delim", "source"] (source can be a Ref/etc).
            if let Some(split_val) = map.get("Fn::Split") {
                if let Some(arr) = split_val.as_array() {
                    if arr.len() == 2 {
                        let delim = arr[0].as_str().unwrap_or("");
                        let src_resolved = resolve_refs_full(
                            &arr[1],
                            parameters,
                            _resources,
                            resource_physical_ids,
                            resource_attributes,
                            imports,
                            conditions,
                        );
                        let src = match src_resolved {
                            Value::String(s) => s,
                            other => other.to_string(),
                        };
                        let parts: Vec<Value> = src
                            .split(delim)
                            .map(|p| Value::String(p.to_string()))
                            .collect();
                        return Value::Array(parts);
                    }
                }
            }
            // Fn::Select: pick element at index from an array. Args:
            // [index, list]. The list may itself be an Fn::Split / Ref.
            if let Some(sel_val) = map.get("Fn::Select") {
                if let Some(arr) = sel_val.as_array() {
                    if arr.len() == 2 {
                        let idx_val = resolve_refs_full(
                            &arr[0],
                            parameters,
                            _resources,
                            resource_physical_ids,
                            resource_attributes,
                            imports,
                            conditions,
                        );
                        let list_val = resolve_refs_full(
                            &arr[1],
                            parameters,
                            _resources,
                            resource_physical_ids,
                            resource_attributes,
                            imports,
                            conditions,
                        );
                        let idx: usize = match &idx_val {
                            Value::Number(n) => n.as_u64().unwrap_or(0) as usize,
                            Value::String(s) => s.parse().unwrap_or(0),
                            _ => 0,
                        };
                        if let Some(list) = list_val.as_array() {
                            if let Some(elt) = list.get(idx) {
                                return elt.clone();
                            }
                        }
                        return Value::Null;
                    }
                }
            }
            // Fn::Cidr: split a CIDR block into N subnets each of a given
            // bit count. Args: [ip_block, count, cidr_bits]. We compute
            // contiguous sub-blocks within an IPv4 range; IPv6 falls
            // through as a string for simplicity.
            if let Some(cidr_val) = map.get("Fn::Cidr") {
                if let Some(arr) = cidr_val.as_array() {
                    if arr.len() == 3 {
                        let block_val = resolve_refs_full(
                            &arr[0],
                            parameters,
                            _resources,
                            resource_physical_ids,
                            resource_attributes,
                            imports,
                            conditions,
                        );
                        let count_val = resolve_refs_full(
                            &arr[1],
                            parameters,
                            _resources,
                            resource_physical_ids,
                            resource_attributes,
                            imports,
                            conditions,
                        );
                        let bits_val = resolve_refs_full(
                            &arr[2],
                            parameters,
                            _resources,
                            resource_physical_ids,
                            resource_attributes,
                            imports,
                            conditions,
                        );
                        let block_str = match &block_val {
                            Value::String(s) => s.clone(),
                            other => other.to_string(),
                        };
                        let count: u32 = match &count_val {
                            Value::Number(n) => n.as_u64().unwrap_or(0) as u32,
                            Value::String(s) => s.parse().unwrap_or(0),
                            _ => 0,
                        };
                        let cidr_bits: u32 = match &bits_val {
                            Value::Number(n) => n.as_u64().unwrap_or(0) as u32,
                            Value::String(s) => s.parse().unwrap_or(0),
                            _ => 0,
                        };
                        if let Some(sub_cidrs) = compute_cidr_subnets(&block_str, count, cidr_bits)
                        {
                            return Value::Array(
                                sub_cidrs.into_iter().map(Value::String).collect(),
                            );
                        }
                    }
                }
            }
            if let Some(sub_val) = map.get("Fn::Sub") {
                if let Some(s) = sub_val.as_str() {
                    let mut result = s.to_string();
                    for (k, v) in parameters {
                        result = result.replace(&format!("${{{k}}}"), v);
                    }
                    // Also substitute resource physical IDs in Fn::Sub
                    for (k, v) in resource_physical_ids {
                        result = result.replace(&format!("${{{k}}}"), v);
                    }
                    // GetAtt-style substitutions: ${LogicalId.AttrName}
                    for (logical, attrs) in resource_attributes {
                        for (attr, value) in attrs {
                            result = result.replace(&format!("${{{logical}.{attr}}}"), value);
                        }
                    }
                    return Value::String(result);
                }
            }
            // Recurse into object
            let mut new_map = serde_json::Map::new();
            for (k, v) in map {
                new_map.insert(
                    k.clone(),
                    resolve_refs_full(
                        v,
                        parameters,
                        _resources,
                        resource_physical_ids,
                        resource_attributes,
                        imports,
                        conditions,
                    ),
                );
            }
            Value::Object(new_map)
        }
        Value::Array(arr) => Value::Array(
            arr.iter()
                .map(|v| {
                    resolve_refs_full(
                        v,
                        parameters,
                        _resources,
                        resource_physical_ids,
                        resource_attributes,
                        imports,
                        conditions,
                    )
                })
                .collect(),
        ),
        other => other.clone(),
    }
}

/// Carve `ip_block` (eg. `10.0.0.0/16`) into `count` subnet CIDR
/// strings each with a host count of `2^cidr_bits - 2` (matching real
/// `Fn::Cidr`). IPv4 only — returns `None` for IPv6 or malformed
/// inputs, which leaves the value unresolved at the caller.
fn compute_cidr_subnets(ip_block: &str, count: u32, cidr_bits: u32) -> Option<Vec<String>> {
    let (ip_str, prefix_str) = ip_block.split_once('/')?;
    let prefix: u32 = prefix_str.parse().ok()?;
    let ip: std::net::Ipv4Addr = ip_str.parse().ok()?;
    let base: u32 = ip.into();
    // Subnet size in bits = 32 - new_prefix. Real Fn::Cidr cidr_bits
    // is the host portion length, so new_prefix = 32 - cidr_bits.
    let new_prefix = 32u32.checked_sub(cidr_bits)?;
    if new_prefix <= prefix {
        return None;
    }
    let step: u32 = 1u32 << cidr_bits;
    let mut out = Vec::with_capacity(count as usize);
    for i in 0..count {
        let subnet_base = base.checked_add(step.checked_mul(i)?)?;
        let addr = std::net::Ipv4Addr::from(subnet_base);
        out.push(format!("{addr}/{new_prefix}"));
    }
    Some(out)
}

/// Parse a `Fn::GetAtt` argument. Accepts either the array form
/// `["LogicalId", "Attr"]` (also nested attribute paths joined with `.`)
/// or the short string form `"LogicalId.Attr"`.
fn parse_getatt(value: &Value) -> Option<(String, String)> {
    match value {
        Value::Array(arr) if arr.len() >= 2 => {
            let logical_id = arr[0].as_str()?.to_string();
            let parts: Vec<String> = arr[1..]
                .iter()
                .map(|v| match v {
                    Value::String(s) => s.clone(),
                    other => other.to_string(),
                })
                .collect();
            Some((logical_id, parts.join(".")))
        }
        Value::String(s) => {
            let (logical_id, attr) = s.split_once('.')?;
            Some((logical_id.to_string(), attr.to_string()))
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_json_template() {
        let template = r#"{
            "Resources": {
                "MyQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "QueueName": "test-queue"
                    }
                }
            }
        }"#;

        let parsed = parse_template(template, &BTreeMap::new()).unwrap();
        assert_eq!(parsed.resources.len(), 1);
        assert_eq!(parsed.resources[0].logical_id, "MyQueue");
        assert_eq!(parsed.resources[0].resource_type, "AWS::SQS::Queue");
    }

    #[test]
    fn parse_yaml_template() {
        let template = r#"
Resources:
  MyTopic:
    Type: AWS::SNS::Topic
    Properties:
      TopicName: test-topic
"#;

        let parsed = parse_template(template, &BTreeMap::new()).unwrap();
        assert_eq!(parsed.resources.len(), 1);
        assert_eq!(parsed.resources[0].logical_id, "MyTopic");
        assert_eq!(parsed.resources[0].resource_type, "AWS::SNS::Topic");
    }

    #[test]
    fn resolve_ref_parameters() {
        let template = r#"{
            "Resources": {
                "MyQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "QueueName": { "Ref": "QueueNameParam" }
                    }
                }
            }
        }"#;

        let mut params = BTreeMap::new();
        params.insert("QueueNameParam".to_string(), "resolved-queue".to_string());
        let parsed = parse_template(template, &params).unwrap();
        assert_eq!(
            parsed.resources[0].properties["QueueName"],
            Value::String("resolved-queue".to_string())
        );
    }

    #[test]
    fn ref_resolves_physical_id_over_logical_id() {
        let template = r#"{
            "Resources": {
                "MyTopic": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": "my-topic"
                    }
                },
                "MySub": {
                    "Type": "AWS::SNS::Subscription",
                    "Properties": {
                        "TopicArn": { "Ref": "MyTopic" },
                        "Protocol": "sqs",
                        "Endpoint": "arn:aws:sqs:us-east-1:123456789012:q"
                    }
                }
            }
        }"#;

        let mut physical_ids = BTreeMap::new();
        physical_ids.insert(
            "MyTopic".to_string(),
            "arn:aws:sns:us-east-1:123456789012:my-topic".to_string(),
        );

        let parsed =
            parse_template_with_physical_ids(template, &BTreeMap::new(), &physical_ids).unwrap();
        let sub = parsed
            .resources
            .iter()
            .find(|r| r.logical_id == "MySub")
            .unwrap();
        assert_eq!(
            sub.properties["TopicArn"],
            Value::String("arn:aws:sns:us-east-1:123456789012:my-topic".to_string())
        );
    }

    #[test]
    fn ref_without_physical_id_returns_logical_id_for_known_resource() {
        let template = r#"{
            "Resources": {
                "MyTopic": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": "my-topic"
                    }
                },
                "MySub": {
                    "Type": "AWS::SNS::Subscription",
                    "Properties": {
                        "TopicArn": { "Ref": "MyTopic" },
                        "Protocol": "sqs",
                        "Endpoint": "arn:aws:sqs:us-east-1:123456789012:q"
                    }
                }
            }
        }"#;

        // No physical IDs yet — logical ID returned for known resources
        let parsed = parse_template(template, &BTreeMap::new()).unwrap();
        let sub = parsed
            .resources
            .iter()
            .find(|r| r.logical_id == "MySub")
            .unwrap();
        assert_eq!(
            sub.properties["TopicArn"],
            Value::String("MyTopic".to_string())
        );
    }

    #[test]
    fn pseudo_ref_substitutes_when_param_provided() {
        let template = r#"{
            "Resources": {
                "MyQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "QueueArn": {
                            "Fn::Join": ["", [
                                "arn:", {"Ref": "AWS::Partition"}, ":sqs:",
                                {"Ref": "AWS::Region"}, ":", {"Ref": "AWS::AccountId"},
                                ":", {"Ref": "AWS::StackName"}, "-q"
                            ]]
                        }
                    }
                }
            }
        }"#;
        let mut params = BTreeMap::new();
        params.insert("AWS::Region".to_string(), "us-west-2".to_string());
        params.insert("AWS::AccountId".to_string(), "111122223333".to_string());
        params.insert("AWS::Partition".to_string(), "aws".to_string());
        params.insert("AWS::StackName".to_string(), "demo".to_string());

        let parsed = parse_template(template, &params).unwrap();
        assert_eq!(
            parsed.resources[0].properties["QueueArn"],
            Value::String("arn:aws:sqs:us-west-2:111122223333:demo-q".to_string())
        );
    }

    #[test]
    fn pseudo_ref_partition_default_when_unset() {
        let template = r#"{
            "Resources": {
                "MyQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "Partition": {"Ref": "AWS::Partition"},
                        "Suffix": {"Ref": "AWS::URLSuffix"}
                    }
                }
            }
        }"#;
        let parsed = parse_template(template, &BTreeMap::new()).unwrap();
        assert_eq!(
            parsed.resources[0].properties["Partition"],
            Value::String("aws".to_string())
        );
        assert_eq!(
            parsed.resources[0].properties["Suffix"],
            Value::String("amazonaws.com".to_string())
        );
    }

    #[test]
    fn pseudo_ref_passes_through() {
        let template = r#"{
            "Resources": {
                "MyQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "QueueName": { "Ref": "AWS::StackName" }
                    }
                }
            }
        }"#;

        let parsed = parse_template(template, &BTreeMap::new()).unwrap();
        assert_eq!(
            parsed.resources[0].properties["QueueName"],
            Value::String("AWS::StackName".to_string())
        );
    }

    #[test]
    fn fn_sub_resolves_physical_ids() {
        let template = r#"{
            "Resources": {
                "MyTopic": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": "my-topic"
                    }
                },
                "MyParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Name": "/app/topic",
                        "Type": "String",
                        "Value": { "Fn::Sub": "Topic is ${MyTopic}" }
                    }
                }
            }
        }"#;

        let mut physical_ids = BTreeMap::new();
        physical_ids.insert(
            "MyTopic".to_string(),
            "arn:aws:sns:us-east-1:123456789012:my-topic".to_string(),
        );

        let parsed =
            parse_template_with_physical_ids(template, &BTreeMap::new(), &physical_ids).unwrap();
        let param = parsed
            .resources
            .iter()
            .find(|r| r.logical_id == "MyParam")
            .unwrap();
        assert_eq!(
            param.properties["Value"],
            Value::String("Topic is arn:aws:sns:us-east-1:123456789012:my-topic".to_string())
        );
    }

    // ── error paths ──

    #[test]
    fn parse_template_invalid_json_errors() {
        let params = BTreeMap::new();
        let result = parse_template("{not-json}", &params);
        assert!(result.is_err());
    }

    #[test]
    fn parse_template_missing_resources_errors() {
        let params = BTreeMap::new();
        let result = parse_template(r#"{"Description":"no resources"}"#, &params);
        assert!(result.is_err());
    }

    #[test]
    fn parse_template_resources_not_object_errors() {
        let params = BTreeMap::new();
        let result = parse_template(r#"{"Resources": []}"#, &params);
        assert!(result.is_err());
    }

    #[test]
    fn parse_template_missing_type_errors() {
        let params = BTreeMap::new();
        let result = parse_template(r#"{"Resources":{"R":{"Properties":{}}}}"#, &params);
        assert!(result.is_err());
    }

    // ── Fn::GetAtt ──

    #[test]
    fn fn_getatt_resolves_attribute_in_array_form() {
        let template = r#"{
            "Resources": {
                "MyQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": { "QueueName": "q1" }
                },
                "MyTopic": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": "t1",
                        "DataProtectionPolicy": {
                            "Fn::GetAtt": ["MyQueue", "Arn"]
                        }
                    }
                }
            }
        }"#;

        let mut attrs = BTreeMap::new();
        let mut q_attrs = BTreeMap::new();
        q_attrs.insert(
            "Arn".to_string(),
            "arn:aws:sqs:us-east-1:123456789012:q1".to_string(),
        );
        attrs.insert("MyQueue".to_string(), q_attrs);

        let parsed =
            parse_template_with_resolution(template, &BTreeMap::new(), &BTreeMap::new(), &attrs)
                .unwrap();
        let topic = parsed
            .resources
            .iter()
            .find(|r| r.logical_id == "MyTopic")
            .unwrap();
        assert_eq!(
            topic.properties["DataProtectionPolicy"],
            Value::String("arn:aws:sqs:us-east-1:123456789012:q1".to_string())
        );
    }

    #[test]
    fn fn_getatt_resolves_attribute_in_short_string_form() {
        let template = r#"{
            "Resources": {
                "MyTopic": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": "t1",
                        "PolicyArn": { "Fn::GetAtt": "MyQueue.Arn" }
                    }
                }
            }
        }"#;

        let mut attrs = BTreeMap::new();
        let mut q_attrs = BTreeMap::new();
        q_attrs.insert(
            "Arn".to_string(),
            "arn:aws:sqs:us-east-1:123456789012:q1".to_string(),
        );
        attrs.insert("MyQueue".to_string(), q_attrs);

        let parsed =
            parse_template_with_resolution(template, &BTreeMap::new(), &BTreeMap::new(), &attrs)
                .unwrap();
        assert_eq!(
            parsed.resources[0].properties["PolicyArn"],
            Value::String("arn:aws:sqs:us-east-1:123456789012:q1".to_string())
        );
    }

    #[test]
    fn fn_getatt_unknown_resource_returns_placeholder() {
        let template = r#"{
            "Resources": {
                "MyTopic": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": {
                        "TopicName": { "Fn::GetAtt": ["MyQueue", "Arn"] }
                    }
                }
            }
        }"#;

        let parsed = parse_template(template, &BTreeMap::new()).unwrap();
        // Unresolved GetAtt becomes a placeholder; multi-pass provisioning
        // re-resolves once the target is known.
        assert_eq!(
            parsed.resources[0].properties["TopicName"],
            Value::String("MyQueue.Arn".to_string())
        );
    }

    #[test]
    fn fn_getatt_inside_fn_join_resolves() {
        let template = r#"{
            "Resources": {
                "MyParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Name": "/app/q",
                        "Type": "String",
                        "Value": {
                            "Fn::Join": [":", ["queue", { "Fn::GetAtt": ["MyQueue", "Arn"] }]]
                        }
                    }
                }
            }
        }"#;

        let mut attrs = BTreeMap::new();
        let mut q_attrs = BTreeMap::new();
        q_attrs.insert(
            "Arn".to_string(),
            "arn:aws:sqs:us-east-1:123456789012:q1".to_string(),
        );
        attrs.insert("MyQueue".to_string(), q_attrs);

        let parsed =
            parse_template_with_resolution(template, &BTreeMap::new(), &BTreeMap::new(), &attrs)
                .unwrap();
        assert_eq!(
            parsed.resources[0].properties["Value"],
            Value::String("queue:arn:aws:sqs:us-east-1:123456789012:q1".to_string())
        );
    }

    #[test]
    fn fn_sub_resolves_getatt_style_substitution() {
        let template = r#"{
            "Resources": {
                "MyParam": {
                    "Type": "AWS::SSM::Parameter",
                    "Properties": {
                        "Name": "/app/q",
                        "Type": "String",
                        "Value": { "Fn::Sub": "Queue arn is ${MyQueue.Arn}" }
                    }
                }
            }
        }"#;

        let mut attrs = BTreeMap::new();
        let mut q_attrs = BTreeMap::new();
        q_attrs.insert(
            "Arn".to_string(),
            "arn:aws:sqs:us-east-1:123456789012:q1".to_string(),
        );
        attrs.insert("MyQueue".to_string(), q_attrs);

        let parsed =
            parse_template_with_resolution(template, &BTreeMap::new(), &BTreeMap::new(), &attrs)
                .unwrap();
        assert_eq!(
            parsed.resources[0].properties["Value"],
            Value::String("Queue arn is arn:aws:sqs:us-east-1:123456789012:q1".to_string())
        );
    }

    #[test]
    fn parse_template_with_description() {
        let params = BTreeMap::new();
        let parsed = parse_template(
            r#"{"Description":"My template","Resources":{"R":{"Type":"AWS::SQS::Queue"}}}"#,
            &params,
        )
        .unwrap();
        assert_eq!(parsed.description.as_deref(), Some("My template"));
        assert_eq!(parsed.resources.len(), 1);
    }

    type EmptyCtx = (
        BTreeMap<String, String>,
        serde_json::Map<String, Value>,
        BTreeMap<String, String>,
        BTreeMap<String, BTreeMap<String, String>>,
    );

    fn empty() -> EmptyCtx {
        (
            BTreeMap::new(),
            serde_json::Map::new(),
            BTreeMap::new(),
            BTreeMap::new(),
        )
    }

    #[test]
    fn fn_base64_encodes_string() {
        let (p, r, ids, attrs) = empty();
        let v: Value = serde_json::from_str(r#"{"Fn::Base64": "hello"}"#).unwrap();
        let resolved = resolve_refs(&v, &p, &r, &ids, &attrs);
        assert_eq!(resolved, Value::String("aGVsbG8=".to_string()));
    }

    #[test]
    fn fn_split_emits_array() {
        let (p, r, ids, attrs) = empty();
        let v: Value = serde_json::from_str(r#"{"Fn::Split": [",", "a,b,c"]}"#).unwrap();
        let resolved = resolve_refs(&v, &p, &r, &ids, &attrs);
        assert_eq!(resolved, serde_json::json!(["a", "b", "c"]));
    }

    #[test]
    fn fn_select_picks_index() {
        let (p, r, ids, attrs) = empty();
        let v: Value =
            serde_json::from_str(r#"{"Fn::Select": [1, {"Fn::Split": [",", "a,b,c"]}]}"#).unwrap();
        let resolved = resolve_refs(&v, &p, &r, &ids, &attrs);
        assert_eq!(resolved, Value::String("b".to_string()));
    }

    #[test]
    fn fn_length_counts_array() {
        let (p, r, ids, attrs) = empty();
        let v: Value = serde_json::from_str(r#"{"Fn::Length": [1,2,3,4]}"#).unwrap();
        let resolved = resolve_refs(&v, &p, &r, &ids, &attrs);
        assert_eq!(resolved, Value::Number(4.into()));
    }

    #[test]
    fn fn_to_json_string_serializes() {
        let (p, r, ids, attrs) = empty();
        let v: Value =
            serde_json::from_str(r#"{"Fn::ToJsonString": {"a": 1, "b": [2, 3]}}"#).unwrap();
        let resolved = resolve_refs(&v, &p, &r, &ids, &attrs);
        let s = resolved.as_str().unwrap();
        // Order-insensitive: just verify it parses back.
        let parsed: Value = serde_json::from_str(s).unwrap();
        assert_eq!(parsed["a"], serde_json::json!(1));
        assert_eq!(parsed["b"], serde_json::json!([2, 3]));
    }

    #[test]
    fn fn_cidr_carves_subnets() {
        let (p, r, ids, attrs) = empty();
        // Carve 10.0.0.0/16 into 4 /24 subnets (cidr_bits = 8 host bits).
        let v: Value = serde_json::from_str(r#"{"Fn::Cidr": ["10.0.0.0/16", 4, 8]}"#).unwrap();
        let resolved = resolve_refs(&v, &p, &r, &ids, &attrs);
        assert_eq!(
            resolved,
            serde_json::json!(["10.0.0.0/24", "10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24",])
        );
    }

    #[test]
    fn condition_skips_resource_when_false() {
        let template = r#"{
            "Parameters": {"Env": {"Type": "String"}},
            "Conditions": {
                "IsProd": {"Fn::Equals": [{"Ref": "Env"}, "prod"]}
            },
            "Resources": {
                "ProdQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Condition": "IsProd",
                    "Properties": {"QueueName": "prod-q"}
                },
                "AlwaysQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"QueueName": "always-q"}
                }
            }
        }"#;
        let mut params = BTreeMap::new();
        params.insert("Env".to_string(), "dev".to_string());
        let parsed = parse_template(template, &params).unwrap();
        let names: Vec<&str> = parsed
            .resources
            .iter()
            .map(|r| r.logical_id.as_str())
            .collect();
        assert!(names.contains(&"AlwaysQueue"));
        assert!(!names.contains(&"ProdQueue"));
    }

    #[test]
    fn condition_includes_resource_when_true() {
        let template = r#"{
            "Parameters": {"Env": {"Type": "String"}},
            "Conditions": {
                "IsProd": {"Fn::Equals": [{"Ref": "Env"}, "prod"]}
            },
            "Resources": {
                "ProdQueue": {
                    "Type": "AWS::SQS::Queue",
                    "Condition": "IsProd",
                    "Properties": {"QueueName": "prod-q"}
                }
            }
        }"#;
        let mut params = BTreeMap::new();
        params.insert("Env".to_string(), "prod".to_string());
        let parsed = parse_template(template, &params).unwrap();
        assert_eq!(parsed.resources.len(), 1);
    }

    #[test]
    fn fn_if_picks_branch_based_on_condition() {
        let template = r#"{
            "Parameters": {"Env": {"Type": "String"}},
            "Conditions": {
                "IsProd": {"Fn::Equals": [{"Ref": "Env"}, "prod"]}
            },
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "QueueName": {"Fn::If": ["IsProd", "prod-q", "dev-q"]}
                    }
                }
            }
        }"#;
        let mut params = BTreeMap::new();
        params.insert("Env".to_string(), "dev".to_string());
        let parsed = parse_template(template, &params).unwrap();
        assert_eq!(
            parsed.resources[0].properties["QueueName"],
            Value::String("dev-q".to_string())
        );
    }

    #[test]
    fn fn_and_or_not_combine_conditions() {
        let template = r#"{
            "Parameters": {"Env": {"Type": "String"}, "Region": {"Type": "String"}},
            "Conditions": {
                "IsProd": {"Fn::Equals": [{"Ref": "Env"}, "prod"]},
                "IsUsEast": {"Fn::Equals": [{"Ref": "Region"}, "us-east-1"]},
                "IsProdInUsEast": {"Fn::And": [{"Condition": "IsProd"}, {"Condition": "IsUsEast"}]},
                "IsNotProd": {"Fn::Not": [{"Condition": "IsProd"}]},
                "IsAny": {"Fn::Or": [{"Condition": "IsProd"}, {"Condition": "IsNotProd"}]}
            },
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "P1": {"Fn::If": ["IsProdInUsEast", "yes", "no"]},
                        "P2": {"Fn::If": ["IsNotProd", "yes", "no"]},
                        "P3": {"Fn::If": ["IsAny", "yes", "no"]}
                    }
                }
            }
        }"#;
        let mut params = BTreeMap::new();
        params.insert("Env".to_string(), "prod".to_string());
        params.insert("Region".to_string(), "us-east-1".to_string());
        let parsed = parse_template(template, &params).unwrap();
        let p = &parsed.resources[0].properties;
        assert_eq!(p["P1"], Value::String("yes".to_string()));
        assert_eq!(p["P2"], Value::String("no".to_string()));
        assert_eq!(p["P3"], Value::String("yes".to_string()));
    }

    #[test]
    fn fn_find_in_map_resolves_leaf_value() {
        let template = r#"{
            "Mappings": {
                "RegionMap": {
                    "us-east-1": {"AMI": "ami-east"},
                    "us-west-2": {"AMI": "ami-west"}
                }
            },
            "Resources": {
                "Inst": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": {"Fn::FindInMap": ["RegionMap", "us-east-1", "AMI"]}
                    }
                }
            }
        }"#;
        let parsed = parse_template(template, &BTreeMap::new()).unwrap();
        assert_eq!(
            parsed.resources[0].properties["ImageId"],
            Value::String("ami-east".to_string())
        );
    }

    #[test]
    fn fn_find_in_map_resolves_keys_via_ref() {
        let template = r#"{
            "Parameters": {"Region": {"Type": "String"}},
            "Mappings": {
                "RegionMap": {
                    "us-east-1": {"AMI": "ami-east"},
                    "us-west-2": {"AMI": "ami-west"}
                }
            },
            "Resources": {
                "Inst": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": {"Fn::FindInMap": ["RegionMap", {"Ref": "Region"}, "AMI"]}
                    }
                }
            }
        }"#;
        let mut params = BTreeMap::new();
        params.insert("Region".to_string(), "us-west-2".to_string());
        let parsed = parse_template(template, &params).unwrap();
        assert_eq!(
            parsed.resources[0].properties["ImageId"],
            Value::String("ami-west".to_string())
        );
    }

    #[test]
    fn fn_find_in_map_unknown_keys_returns_error() {
        let template = r#"{
            "Mappings": {
                "RegionMap": {
                    "us-east-1": {"AMI": "ami-east"}
                }
            },
            "Resources": {
                "Inst": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": {"Fn::FindInMap": ["RegionMap", "ap-south-1", "AMI"]}
                    }
                }
            }
        }"#;
        let err = parse_template(template, &BTreeMap::new()).unwrap_err();
        assert!(
            err.contains("Unable to get mapping for RegionMap::ap-south-1::AMI"),
            "got: {err}"
        );
    }

    #[test]
    fn fn_find_in_map_four_arg_returns_default_when_missing() {
        let template = r#"{
            "Mappings": {
                "RegionMap": {
                    "us-east-1": {"AMI": "ami-east"}
                }
            },
            "Resources": {
                "Inst": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": {"Fn::FindInMap": [
                            "RegionMap",
                            "ap-south-1",
                            "AMI",
                            {"DefaultValue": "ami-fallback"}
                        ]}
                    }
                }
            }
        }"#;
        let parsed = parse_template(template, &BTreeMap::new()).unwrap();
        assert_eq!(
            parsed.resources[0].properties["ImageId"],
            Value::String("ami-fallback".to_string())
        );
    }

    #[test]
    fn fn_find_in_map_four_arg_prefers_match_over_default() {
        let template = r#"{
            "Mappings": {
                "RegionMap": {
                    "us-east-1": {"AMI": "ami-east"}
                }
            },
            "Resources": {
                "Inst": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": {"Fn::FindInMap": [
                            "RegionMap",
                            "us-east-1",
                            "AMI",
                            {"DefaultValue": "ami-fallback"}
                        ]}
                    }
                }
            }
        }"#;
        let parsed = parse_template(template, &BTreeMap::new()).unwrap();
        assert_eq!(
            parsed.resources[0].properties["ImageId"],
            Value::String("ami-east".to_string())
        );
    }

    #[test]
    fn fn_find_in_map_default_value_is_resolved_intrinsic() {
        let template = r#"{
            "Parameters": {"Fallback": {"Type": "String"}},
            "Mappings": {
                "RegionMap": {
                    "us-east-1": {"AMI": "ami-east"}
                }
            },
            "Resources": {
                "Inst": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": {"Fn::FindInMap": [
                            "RegionMap",
                            "ap-south-1",
                            "AMI",
                            {"DefaultValue": {"Ref": "Fallback"}}
                        ]}
                    }
                }
            }
        }"#;
        let mut params = BTreeMap::new();
        params.insert("Fallback".to_string(), "ami-default".to_string());
        let parsed = parse_template(template, &params).unwrap();
        assert_eq!(
            parsed.resources[0].properties["ImageId"],
            Value::String("ami-default".to_string())
        );
    }

    #[test]
    fn fn_find_in_map_unknown_map_name_errors() {
        let template = r#"{
            "Mappings": {
                "RegionMap": {
                    "us-east-1": {"AMI": "ami-east"}
                }
            },
            "Resources": {
                "Inst": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": {"Fn::FindInMap": ["DoesNotExist", "us-east-1", "AMI"]}
                    }
                }
            }
        }"#;
        let err = parse_template(template, &BTreeMap::new()).unwrap_err();
        assert!(
            err.contains("Unable to get mapping for DoesNotExist::us-east-1::AMI"),
            "got: {err}"
        );
    }

    #[test]
    fn fn_find_in_map_wrong_arg_count_errors() {
        let template = r#"{
            "Mappings": {"M": {"a": {"b": "c"}}},
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "QueueName": {"Fn::FindInMap": ["M", "a"]}
                    }
                }
            }
        }"#;
        let err = parse_template(template, &BTreeMap::new()).unwrap_err();
        assert!(
            err.contains("Fn::FindInMap requires 3 or 4 arguments"),
            "got: {err}"
        );
    }

    #[test]
    fn fn_find_in_map_resolves_via_pseudo_region() {
        let template = r#"{
            "Mappings": {
                "RegionMap": {
                    "us-east-1": {"AMI": "ami-east"},
                    "us-west-2": {"AMI": "ami-west"}
                }
            },
            "Resources": {
                "Inst": {
                    "Type": "AWS::EC2::Instance",
                    "Properties": {
                        "ImageId": {"Fn::FindInMap": [
                            "RegionMap",
                            {"Ref": "AWS::Region"},
                            "AMI"
                        ]}
                    }
                }
            }
        }"#;
        // No AWS::Region in parameters — the pseudo-default ("us-east-1")
        // should kick in so FindInMap still resolves.
        let parsed = parse_template(template, &BTreeMap::new()).unwrap();
        assert_eq!(
            parsed.resources[0].properties["ImageId"],
            Value::String("ami-east".to_string())
        );
    }

    #[test]
    fn fn_find_in_map_alongside_ref_and_sub_still_resolve() {
        let template = r#"{
            "Parameters": {"Env": {"Type": "String"}},
            "Mappings": {
                "EnvMap": {
                    "prod": {"Suffix": "live"},
                    "dev": {"Suffix": "test"}
                }
            },
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "QueueName": {"Fn::FindInMap": ["EnvMap", {"Ref": "Env"}, "Suffix"]},
                        "Tags": [
                            {"Key": "EnvRef", "Value": {"Ref": "Env"}},
                            {"Key": "Subbed", "Value": {"Fn::Sub": "env-${Env}"}}
                        ]
                    }
                }
            }
        }"#;
        let mut params = BTreeMap::new();
        params.insert("Env".to_string(), "prod".to_string());
        let parsed = parse_template(template, &params).unwrap();
        let p = &parsed.resources[0].properties;
        assert_eq!(p["QueueName"], Value::String("live".to_string()));
        assert_eq!(p["Tags"][0]["Value"], Value::String("prod".to_string()));
        assert_eq!(p["Tags"][1]["Value"], Value::String("env-prod".to_string()));
    }

    // ── Conditions: cycle detection + AWS::NoValue removal ──

    #[test]
    fn cyclic_conditions_self_reference_errors() {
        let template = r#"{
            "Conditions": {
                "A": {"Condition": "A"}
            },
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Condition": "A",
                    "Properties": {"QueueName": "q"}
                }
            }
        }"#;
        let err = parse_template(template, &BTreeMap::new()).unwrap_err();
        assert!(err.contains("Circular reference"), "got: {err}");
        assert!(err.contains("'A'"), "got: {err}");
    }

    #[test]
    fn cyclic_conditions_two_step_errors() {
        let template = r#"{
            "Conditions": {
                "A": {"Condition": "B"},
                "B": {"Condition": "A"}
            },
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Condition": "A",
                    "Properties": {"QueueName": "q"}
                }
            }
        }"#;
        let err = parse_template(template, &BTreeMap::new()).unwrap_err();
        assert!(err.contains("Circular reference"), "got: {err}");
    }

    #[test]
    fn condition_referencing_undefined_name_errors() {
        let template = r#"{
            "Conditions": {
                "A": {"Condition": "DoesNotExist"}
            },
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Condition": "A",
                    "Properties": {"QueueName": "q"}
                }
            }
        }"#;
        let err = parse_template(template, &BTreeMap::new()).unwrap_err();
        assert!(err.contains("DoesNotExist"), "got: {err}");
    }

    #[test]
    fn fn_if_no_value_removes_property_from_parent_map() {
        let template = r#"{
            "Parameters": {"WantTags": {"Type": "String"}},
            "Conditions": {
                "HasTags": {"Fn::Equals": [{"Ref": "WantTags"}, "yes"]}
            },
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "QueueName": "q",
                        "Tags": {"Fn::If": [
                            "HasTags",
                            [{"Key": "a", "Value": "b"}],
                            {"Ref": "AWS::NoValue"}
                        ]}
                    }
                }
            }
        }"#;
        let mut params = BTreeMap::new();
        params.insert("WantTags".to_string(), "no".to_string());
        let parsed = parse_template(template, &params).unwrap();
        let props = parsed.resources[0].properties.as_object().unwrap();
        assert!(
            !props.contains_key("Tags"),
            "Tags should be omitted when AWS::NoValue picked, got: {props:?}"
        );
        assert_eq!(
            props.get("QueueName"),
            Some(&Value::String("q".to_string()))
        );
    }

    #[test]
    fn fn_if_no_value_keeps_property_when_branch_concrete() {
        let template = r#"{
            "Parameters": {"WantTags": {"Type": "String"}},
            "Conditions": {
                "HasTags": {"Fn::Equals": [{"Ref": "WantTags"}, "yes"]}
            },
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "QueueName": "q",
                        "Tags": {"Fn::If": [
                            "HasTags",
                            [{"Key": "a", "Value": "b"}],
                            {"Ref": "AWS::NoValue"}
                        ]}
                    }
                }
            }
        }"#;
        let mut params = BTreeMap::new();
        params.insert("WantTags".to_string(), "yes".to_string());
        let parsed = parse_template(template, &params).unwrap();
        let tags = &parsed.resources[0].properties["Tags"];
        assert_eq!(
            tags,
            &serde_json::json!([{"Key": "a", "Value": "b"}]),
            "tags should be the true branch's array"
        );
    }

    #[test]
    fn fn_if_no_value_in_array_drops_element() {
        let template = r#"{
            "Parameters": {"Extra": {"Type": "String"}},
            "Conditions": {
                "HasExtra": {"Fn::Equals": [{"Ref": "Extra"}, "yes"]}
            },
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "Items": [
                            "first",
                            {"Fn::If": ["HasExtra", "second", {"Ref": "AWS::NoValue"}]},
                            "third"
                        ]
                    }
                }
            }
        }"#;
        let mut params = BTreeMap::new();
        params.insert("Extra".to_string(), "no".to_string());
        let parsed = parse_template(template, &params).unwrap();
        assert_eq!(
            parsed.resources[0].properties["Items"],
            serde_json::json!(["first", "third"])
        );
    }

    #[test]
    fn condition_skips_output_when_false() {
        let template = r#"{
            "Parameters": {"Env": {"Type": "String"}},
            "Conditions": {
                "IsProd": {"Fn::Equals": [{"Ref": "Env"}, "prod"]}
            },
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {"QueueName": "q"}
                }
            },
            "Outputs": {
                "ProdName": {
                    "Condition": "IsProd",
                    "Value": "prod-only"
                },
                "Always": {
                    "Value": "shown"
                }
            }
        }"#;
        let mut params = BTreeMap::new();
        params.insert("Env".to_string(), "dev".to_string());
        let parsed = parse_template(template, &params).unwrap();
        let names: Vec<&str> = parsed
            .outputs
            .iter()
            .map(|o| o.logical_id.as_str())
            .collect();
        assert!(names.contains(&"Always"));
        assert!(!names.contains(&"ProdName"));
    }

    #[test]
    fn fn_and_short_circuits_on_false() {
        let template = r#"{
            "Parameters": {"Env": {"Type": "String"}},
            "Conditions": {
                "IsProd": {"Fn::Equals": [{"Ref": "Env"}, "prod"]},
                "Combined": {"Fn::And": [
                    {"Condition": "IsProd"},
                    {"Fn::Equals": [{"Ref": "Env"}, "prod"]}
                ]}
            },
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Condition": "Combined",
                    "Properties": {"QueueName": "q"}
                }
            }
        }"#;
        let mut params = BTreeMap::new();
        params.insert("Env".to_string(), "dev".to_string());
        let parsed = parse_template(template, &params).unwrap();
        assert_eq!(parsed.resources.len(), 0);
    }

    #[test]
    fn fn_or_short_circuits_on_true() {
        let template = r#"{
            "Parameters": {"Env": {"Type": "String"}},
            "Conditions": {
                "IsProd": {"Fn::Equals": [{"Ref": "Env"}, "prod"]},
                "AnyEnv": {"Fn::Or": [
                    {"Condition": "IsProd"},
                    {"Fn::Equals": [{"Ref": "Env"}, "dev"]},
                    {"Fn::Equals": [{"Ref": "Env"}, "stage"]}
                ]}
            },
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Condition": "AnyEnv",
                    "Properties": {"QueueName": "q"}
                }
            }
        }"#;
        let mut params = BTreeMap::new();
        params.insert("Env".to_string(), "stage".to_string());
        let parsed = parse_template(template, &params).unwrap();
        assert_eq!(parsed.resources.len(), 1);
    }

    #[test]
    fn fn_and_rejects_arity_outside_1_to_10() {
        let template = r#"{
            "Conditions": {
                "Empty": {"Fn::And": []}
            },
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Condition": "Empty",
                    "Properties": {"QueueName": "q"}
                }
            }
        }"#;
        let err = parse_template(template, &BTreeMap::new()).unwrap_err();
        assert!(err.contains("Fn::And"), "got: {err}");
    }

    #[test]
    fn condition_evaluation_memoizes_complex_expression() {
        // Both `Outer` branches reuse `Inner`. With memoization the
        // inner condition only resolves once; without it, this would
        // still pass — but the test guards against regressions where
        // re-evaluation triggers double Fn::Equals work.
        let template = r#"{
            "Parameters": {"Env": {"Type": "String"}},
            "Conditions": {
                "Inner": {"Fn::Equals": [{"Ref": "Env"}, "prod"]},
                "OuterA": {"Fn::And": [{"Condition": "Inner"}, {"Condition": "Inner"}]},
                "OuterB": {"Fn::Or": [{"Condition": "Inner"}, {"Condition": "OuterA"}]}
            },
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Condition": "OuterB",
                    "Properties": {"QueueName": "q"}
                }
            }
        }"#;
        let mut params = BTreeMap::new();
        params.insert("Env".to_string(), "prod".to_string());
        let parsed = parse_template(template, &params).unwrap();
        assert_eq!(parsed.resources.len(), 1);
    }

    #[test]
    fn fn_not_rejects_multiple_arguments() {
        let template = r#"{
            "Parameters": {"Env": {"Type": "String"}},
            "Conditions": {
                "IsProd": {"Fn::Equals": [{"Ref": "Env"}, "prod"]},
                "Bad": {"Fn::Not": [
                    {"Condition": "IsProd"},
                    {"Condition": "IsProd"}
                ]}
            },
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Condition": "Bad",
                    "Properties": {"QueueName": "q"}
                }
            }
        }"#;
        let mut params = BTreeMap::new();
        params.insert("Env".to_string(), "prod".to_string());
        let err = parse_template(template, &params).unwrap_err();
        assert!(err.contains("Fn::Not"), "got: {err}");
    }

    #[test]
    fn fn_not_rejects_zero_arguments() {
        let template = r#"{
            "Conditions": {
                "Bad": {"Fn::Not": []}
            },
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Condition": "Bad",
                    "Properties": {"QueueName": "q"}
                }
            }
        }"#;
        let err = parse_template(template, &BTreeMap::new()).unwrap_err();
        assert!(err.contains("Fn::Not"), "got: {err}");
    }

    #[test]
    fn resolve_resource_properties_strips_no_value_at_provision_time() {
        // Mirrors the incremental-provisioning code path which calls
        // resolve_resource_properties_with_attrs after the initial parse.
        // The sentinel must not leak into the resolved properties even
        // when re-resolved with updated physical IDs.
        let template = r#"{
            "Parameters": {"WantTags": {"Type": "String"}},
            "Conditions": {
                "HasTags": {"Fn::Equals": [{"Ref": "WantTags"}, "yes"]}
            },
            "Resources": {
                "Q": {
                    "Type": "AWS::SQS::Queue",
                    "Properties": {
                        "QueueName": "q",
                        "Tags": {"Fn::If": [
                            "HasTags",
                            [{"Key": "a", "Value": "b"}],
                            {"Ref": "AWS::NoValue"}
                        ]}
                    }
                }
            }
        }"#;
        let mut params = BTreeMap::new();
        params.insert("WantTags".to_string(), "no".to_string());
        let parsed = parse_template(template, &params).unwrap();
        let resource = parsed
            .resources
            .iter()
            .find(|r| r.logical_id == "Q")
            .unwrap();
        // First parse already strips Tags.
        assert!(!resource
            .properties
            .as_object()
            .unwrap()
            .contains_key("Tags"));

        // Re-resolve with empty physical IDs (mid-provisioning). The
        // sentinel must still be stripped — no `__fakecloud_aws_no_value__`
        // marker should reach the caller.
        let reresolved = resolve_resource_properties_with_attrs(
            resource,
            template,
            &params,
            &BTreeMap::new(),
            &BTreeMap::new(),
        )
        .unwrap();
        let props = reresolved.properties.as_object().unwrap();
        assert!(
            !props.contains_key("Tags"),
            "Tags should be stripped on re-resolve, got: {props:?}"
        );
        // Sanity: serialized form must not contain the sentinel key.
        let serialized = serde_json::to_string(&reresolved.properties).unwrap();
        assert!(
            !serialized.contains(NO_VALUE_SENTINEL_KEY),
            "sentinel leaked: {serialized}"
        );
    }
}
