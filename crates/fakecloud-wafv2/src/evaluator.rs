//! WAFv2 statement evaluation engine.
//!
//! Walks the rules in a [`WebAcl`], matches each rule's statement against an
//! incoming request, and returns the resolved [`WafAction`]. Rules are
//! evaluated in `Priority` order (ascending). The first rule whose statement
//! matches and that has a non-`Count` action terminates evaluation; `Count`
//! rules continue past. When no rule matches, the WebACL's `DefaultAction`
//! decides Allow vs Block.

use std::collections::{HashMap, HashSet};
use std::net::IpAddr;

use base64::Engine;
use percent_encoding::percent_decode_str;
use regex::Regex;
use serde_json::Value;

use crate::state::{IpSet, RegexPatternSet, WebAcl};

/// Request fields evaluated against WAF statements. Borrowing keeps the
/// evaluator allocation-free for the common request paths.
#[derive(Debug, Clone)]
pub struct WafRequest<'a> {
    pub method: &'a str,
    pub uri: &'a str,
    pub headers: &'a [(String, String)],
    pub body: &'a [u8],
    pub query: &'a str,
    pub source_ip: IpAddr,
    pub country: Option<&'a str>,
}

/// Resolved action returned by [`evaluate`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WafAction {
    Allow,
    Block,
    Count,
    Captcha,
    Challenge,
}

/// Evaluate `req` against `web_acl`. Rules are processed in ascending
/// `Priority`; matching `Count` rules are recorded but do not terminate
/// evaluation. The first matching non-`Count` rule's action is returned;
/// otherwise the WebACL's `DefaultAction` is used.
pub fn evaluate(
    req: &WafRequest,
    web_acl: &WebAcl,
    ipsets: &HashMap<String, IpSet>,
    regex_sets: &HashMap<String, RegexPatternSet>,
) -> WafAction {
    let mut rules: Vec<&Value> = web_acl.rules.iter().collect();
    rules.sort_by_key(|r| r.get("Priority").and_then(Value::as_i64).unwrap_or(0));

    let mut labels: HashSet<String> = HashSet::new();

    for rule in rules {
        let Some(stmt) = rule.get("Statement") else {
            continue;
        };
        if !eval_statement(stmt, req, ipsets, regex_sets, &labels) {
            continue;
        }
        // Add labels produced by this rule so subsequent rules can match.
        if let Some(arr) = rule.get("RuleLabels").and_then(Value::as_array) {
            for label in arr {
                if let Some(name) = label.get("Name").and_then(Value::as_str) {
                    labels.insert(name.to_owned());
                }
            }
        }
        if let Some(action) = rule.get("Action").and_then(rule_action) {
            // Count is non-terminal: keep evaluating subsequent rules.
            if action == WafAction::Count {
                continue;
            }
            return action;
        }
        // Rule with OverrideAction (rule group reference) doesn't terminate
        // here either since we don't expand rule groups in this batch.
    }

    default_action(web_acl)
}

impl WebAcl {
    /// Convenience wrapper around [`evaluate`] for callers holding a `&WebAcl`.
    pub fn evaluate(
        &self,
        req: &WafRequest,
        ipsets: &HashMap<String, IpSet>,
        regex_sets: &HashMap<String, RegexPatternSet>,
    ) -> WafAction {
        evaluate(req, self, ipsets, regex_sets)
    }
}

fn default_action(web_acl: &WebAcl) -> WafAction {
    if web_acl.default_action.get("Block").is_some() {
        WafAction::Block
    } else {
        WafAction::Allow
    }
}

fn rule_action(action: &Value) -> Option<WafAction> {
    if action.get("Allow").is_some() {
        Some(WafAction::Allow)
    } else if action.get("Block").is_some() {
        Some(WafAction::Block)
    } else if action.get("Count").is_some() {
        Some(WafAction::Count)
    } else if action.get("Captcha").is_some() {
        Some(WafAction::Captcha)
    } else if action.get("Challenge").is_some() {
        Some(WafAction::Challenge)
    } else {
        None
    }
}

// ─── Statement dispatch ──────────────────────────────────────────────────

fn eval_statement(
    stmt: &Value,
    req: &WafRequest,
    ipsets: &HashMap<String, IpSet>,
    regex_sets: &HashMap<String, RegexPatternSet>,
    labels: &HashSet<String>,
) -> bool {
    let Some(obj) = stmt.as_object() else {
        return false;
    };

    if let Some(s) = obj.get("ByteMatchStatement") {
        return eval_byte_match(s, req);
    }
    if let Some(s) = obj.get("SqliMatchStatement") {
        return eval_sqli_match(s, req);
    }
    if let Some(s) = obj.get("XssMatchStatement") {
        return eval_xss_match(s, req);
    }
    if let Some(s) = obj.get("GeoMatchStatement") {
        return eval_geo_match(s, req);
    }
    if let Some(s) = obj.get("IPSetReferenceStatement") {
        return eval_ipset_ref(s, req, ipsets);
    }
    if let Some(s) = obj.get("RegexPatternSetReferenceStatement") {
        return eval_regex_set_ref(s, req, regex_sets);
    }
    if let Some(s) = obj.get("RegexMatchStatement") {
        return eval_regex_match(s, req);
    }
    if let Some(s) = obj.get("AndStatement") {
        return eval_and(s, req, ipsets, regex_sets, labels);
    }
    if let Some(s) = obj.get("OrStatement") {
        return eval_or(s, req, ipsets, regex_sets, labels);
    }
    if let Some(s) = obj.get("NotStatement") {
        return eval_not(s, req, ipsets, regex_sets, labels);
    }
    if let Some(s) = obj.get("LabelMatchStatement") {
        return eval_label_match(s, labels);
    }

    // TODO: SizeConstraintStatement
    // TODO: RateBasedStatement
    // TODO: ManagedRuleGroupStatement
    // TODO: RuleGroupReferenceStatement
    false
}

// ─── Logical combinators ─────────────────────────────────────────────────

fn eval_and(
    stmt: &Value,
    req: &WafRequest,
    ipsets: &HashMap<String, IpSet>,
    regex_sets: &HashMap<String, RegexPatternSet>,
    labels: &HashSet<String>,
) -> bool {
    let Some(arr) = stmt.get("Statements").and_then(Value::as_array) else {
        return false;
    };
    !arr.is_empty()
        && arr
            .iter()
            .all(|s| eval_statement(s, req, ipsets, regex_sets, labels))
}

fn eval_or(
    stmt: &Value,
    req: &WafRequest,
    ipsets: &HashMap<String, IpSet>,
    regex_sets: &HashMap<String, RegexPatternSet>,
    labels: &HashSet<String>,
) -> bool {
    let Some(arr) = stmt.get("Statements").and_then(Value::as_array) else {
        return false;
    };
    arr.iter()
        .any(|s| eval_statement(s, req, ipsets, regex_sets, labels))
}

fn eval_not(
    stmt: &Value,
    req: &WafRequest,
    ipsets: &HashMap<String, IpSet>,
    regex_sets: &HashMap<String, RegexPatternSet>,
    labels: &HashSet<String>,
) -> bool {
    let Some(inner) = stmt.get("Statement") else {
        return false;
    };
    !eval_statement(inner, req, ipsets, regex_sets, labels)
}

// ─── Leaf statements ─────────────────────────────────────────────────────

fn eval_byte_match(stmt: &Value, req: &WafRequest) -> bool {
    let Some(needle_b64) = stmt.get("SearchString").and_then(Value::as_str) else {
        return false;
    };
    // SearchString is base64-encoded over the wire; tolerate raw strings too
    // since callers (and tests) frequently pass them unencoded.
    let needle: Vec<u8> = base64::engine::general_purpose::STANDARD
        .decode(needle_b64)
        .unwrap_or_else(|_| needle_b64.as_bytes().to_vec());
    if needle.is_empty() {
        return false;
    }
    let Some(constraint) = stmt.get("PositionalConstraint").and_then(Value::as_str) else {
        return false;
    };
    let transformations = stmt.get("TextTransformations");
    let fields = collect_fields(stmt.get("FieldToMatch"), req);
    fields.iter().any(|raw| {
        let candidate = apply_transformations(raw, transformations);
        positional_match(&candidate, &needle, constraint)
    })
}

fn positional_match(haystack: &[u8], needle: &[u8], constraint: &str) -> bool {
    match constraint {
        "EXACTLY" => haystack == needle,
        "STARTS_WITH" => haystack.starts_with(needle),
        "ENDS_WITH" => haystack.ends_with(needle),
        "CONTAINS" => bytes_contains(haystack, needle),
        "CONTAINS_WORD" => contains_word(haystack, needle),
        _ => false,
    }
}

fn bytes_contains(haystack: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() || needle.len() > haystack.len() {
        return false;
    }
    haystack.windows(needle.len()).any(|w| w == needle)
}

fn contains_word(haystack: &[u8], needle: &[u8]) -> bool {
    if !bytes_contains(haystack, needle) {
        return false;
    }
    // Word boundaries: ascii alnum/underscore on either side disqualifies.
    let n = needle.len();
    haystack.windows(n).enumerate().any(|(i, w)| {
        if w != needle {
            return false;
        }
        let left_ok = i == 0 || !is_word_byte(haystack[i - 1]);
        let right_ok = i + n == haystack.len() || !is_word_byte(haystack[i + n]);
        left_ok && right_ok
    })
}

fn is_word_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_'
}

fn eval_sqli_match(stmt: &Value, req: &WafRequest) -> bool {
    let transformations = stmt.get("TextTransformations");
    let fields = collect_fields(stmt.get("FieldToMatch"), req);
    let tokens: &[&[u8]] = &[
        b"union select",
        b"or 1=1",
        b"' or '1'='1",
        b"'; drop",
        b"--",
        b"/*",
        b"*/",
        b"xp_cmdshell",
    ];
    fields.iter().any(|raw| {
        let lower = lowercase_bytes(&apply_transformations(raw, transformations));
        tokens.iter().any(|t| bytes_contains(&lower, t))
    })
}

fn eval_xss_match(stmt: &Value, req: &WafRequest) -> bool {
    let transformations = stmt.get("TextTransformations");
    let fields = collect_fields(stmt.get("FieldToMatch"), req);
    let tokens: &[&[u8]] = &[
        b"<script",
        b"</script",
        b"javascript:",
        b"onerror=",
        b"onload=",
        b"onclick=",
        b"<iframe",
    ];
    fields.iter().any(|raw| {
        let lower = lowercase_bytes(&apply_transformations(raw, transformations));
        tokens.iter().any(|t| bytes_contains(&lower, t))
    })
}

fn eval_geo_match(stmt: &Value, req: &WafRequest) -> bool {
    let Some(country) = req.country else {
        return false;
    };
    let Some(arr) = stmt.get("CountryCodes").and_then(Value::as_array) else {
        return false;
    };
    arr.iter()
        .filter_map(Value::as_str)
        .any(|c| c.eq_ignore_ascii_case(country))
}

fn eval_ipset_ref(stmt: &Value, req: &WafRequest, ipsets: &HashMap<String, IpSet>) -> bool {
    let Some(arn) = stmt.get("ARN").and_then(Value::as_str) else {
        return false;
    };
    let Some(set) = ipsets.get(arn) else {
        return false;
    };
    set.addresses
        .iter()
        .any(|cidr| cidr_contains(cidr, &req.source_ip))
}

fn eval_regex_set_ref(
    stmt: &Value,
    req: &WafRequest,
    regex_sets: &HashMap<String, RegexPatternSet>,
) -> bool {
    let Some(arn) = stmt.get("ARN").and_then(Value::as_str) else {
        return false;
    };
    let Some(set) = regex_sets.get(arn) else {
        return false;
    };
    let transformations = stmt.get("TextTransformations");
    let fields = collect_fields(stmt.get("FieldToMatch"), req);
    let patterns: Vec<Regex> = set
        .regular_expressions
        .iter()
        .filter_map(|p| p.get("RegexString").and_then(Value::as_str))
        .filter_map(|s| Regex::new(s).ok())
        .collect();
    if patterns.is_empty() {
        return false;
    }
    fields.iter().any(|raw| {
        let candidate = apply_transformations(raw, transformations);
        let Ok(text) = std::str::from_utf8(&candidate) else {
            return false;
        };
        patterns.iter().any(|r| r.is_match(text))
    })
}

fn eval_regex_match(stmt: &Value, req: &WafRequest) -> bool {
    let Some(pattern) = stmt.get("RegexString").and_then(Value::as_str) else {
        return false;
    };
    let Ok(re) = Regex::new(pattern) else {
        return false;
    };
    let transformations = stmt.get("TextTransformations");
    let fields = collect_fields(stmt.get("FieldToMatch"), req);
    fields.iter().any(|raw| {
        let candidate = apply_transformations(raw, transformations);
        std::str::from_utf8(&candidate)
            .map(|t| re.is_match(t))
            .unwrap_or(false)
    })
}

fn eval_label_match(stmt: &Value, labels: &HashSet<String>) -> bool {
    let Some(key) = stmt.get("Key").and_then(Value::as_str) else {
        return false;
    };
    let scope = stmt.get("Scope").and_then(Value::as_str).unwrap_or("LABEL");
    labels.iter().any(|l| match scope {
        // NAMESPACE: match any label whose namespace prefix equals `key`.
        "NAMESPACE" => l.starts_with(key),
        _ => l == key,
    })
}

// ─── FieldToMatch + TextTransformations ──────────────────────────────────

fn collect_fields(field: Option<&Value>, req: &WafRequest) -> Vec<Vec<u8>> {
    let Some(field) = field else {
        return Vec::new();
    };
    let Some(obj) = field.as_object() else {
        return Vec::new();
    };

    if obj.contains_key("Method") {
        return vec![req.method.as_bytes().to_vec()];
    }
    if obj.contains_key("UriPath") {
        return vec![req.uri.as_bytes().to_vec()];
    }
    if obj.contains_key("QueryString") {
        return vec![req.query.as_bytes().to_vec()];
    }
    if obj.contains_key("Body") || obj.contains_key("JsonBody") {
        return vec![req.body.to_vec()];
    }
    if let Some(sh) = obj.get("SingleHeader") {
        if let Some(name) = sh.get("Name").and_then(Value::as_str) {
            return req
                .headers
                .iter()
                .filter(|(k, _)| k.eq_ignore_ascii_case(name))
                .map(|(_, v)| v.as_bytes().to_vec())
                .collect();
        }
    }
    if obj.contains_key("AllHeaders") || obj.contains_key("Headers") {
        return req
            .headers
            .iter()
            .map(|(k, v)| format!("{k}:{v}").into_bytes())
            .collect();
    }
    if let Some(sqa) = obj.get("SingleQueryArgument") {
        if let Some(name) = sqa.get("Name").and_then(Value::as_str) {
            return query_arg_values(req.query, name);
        }
    }
    // TODO: Cookies, JsonBody match-pattern, HeaderOrder, JA3Fingerprint, etc.
    Vec::new()
}

fn query_arg_values(query: &str, name: &str) -> Vec<Vec<u8>> {
    query
        .split('&')
        .filter_map(|kv| {
            let mut parts = kv.splitn(2, '=');
            let k = parts.next()?;
            let v = parts.next().unwrap_or("");
            if k.eq_ignore_ascii_case(name) {
                Some(v.as_bytes().to_vec())
            } else {
                None
            }
        })
        .collect()
}

fn apply_transformations(raw: &[u8], xforms: Option<&Value>) -> Vec<u8> {
    let Some(arr) = xforms.and_then(Value::as_array) else {
        return raw.to_vec();
    };
    let mut ordered: Vec<&Value> = arr.iter().collect();
    ordered.sort_by_key(|t| t.get("Priority").and_then(Value::as_i64).unwrap_or(0));
    let mut current = raw.to_vec();
    for t in ordered {
        let Some(kind) = t.get("Type").and_then(Value::as_str) else {
            continue;
        };
        current = match kind {
            "NONE" => current,
            "LOWERCASE" => lowercase_bytes(&current),
            "URL_DECODE" => url_decode_bytes(&current),
            // TODO: HTML_ENTITY_DECODE, COMPRESS_WHITE_SPACE, CMD_LINE, etc.
            _ => current,
        };
    }
    current
}

fn lowercase_bytes(input: &[u8]) -> Vec<u8> {
    input.iter().map(|b| b.to_ascii_lowercase()).collect()
}

fn url_decode_bytes(input: &[u8]) -> Vec<u8> {
    let Ok(s) = std::str::from_utf8(input) else {
        return input.to_vec();
    };
    percent_decode_str(s).collect()
}

// ─── CIDR matching (no extra deps) ───────────────────────────────────────

fn cidr_contains(cidr: &str, ip: &IpAddr) -> bool {
    let Some((net_str, prefix_str)) = cidr.split_once('/') else {
        // Bare IP — exact match.
        return net_str_eq(cidr, ip);
    };
    let Ok(prefix) = prefix_str.parse::<u8>() else {
        return false;
    };
    match (net_str.parse::<IpAddr>(), ip) {
        (Ok(IpAddr::V4(net)), IpAddr::V4(addr)) if prefix <= 32 => {
            mask_match(&net.octets(), &addr.octets(), prefix)
        }
        (Ok(IpAddr::V6(net)), IpAddr::V6(addr)) if prefix <= 128 => {
            mask_match(&net.octets(), &addr.octets(), prefix)
        }
        _ => false,
    }
}

fn net_str_eq(s: &str, ip: &IpAddr) -> bool {
    s.parse::<IpAddr>().map(|p| p == *ip).unwrap_or(false)
}

fn mask_match(net: &[u8], addr: &[u8], prefix: u8) -> bool {
    let full_bytes = (prefix / 8) as usize;
    let extra_bits = prefix % 8;
    if net.len() != addr.len() || full_bytes > net.len() {
        return false;
    }
    if net[..full_bytes] != addr[..full_bytes] {
        return false;
    }
    if extra_bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - extra_bits);
    (net[full_bytes] & mask) == (addr[full_bytes] & mask)
}

// ─── Tests ───────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::net::Ipv4Addr;

    fn make_acl(default: Value, rules: Vec<Value>) -> WebAcl {
        WebAcl {
            id: "id".into(),
            name: "acl".into(),
            arn: "arn:aws:wafv2:us-east-1:000000000000:regional/webacl/acl/id".into(),
            scope: "REGIONAL".into(),
            default_action: default,
            description: None,
            rules,
            visibility_config: json!({}),
            capacity: 0,
            lock_token: "lt".into(),
            label_namespace: "awswaf:000000000000:webacl:acl:".into(),
            custom_response_bodies: BTreeMap::new(),
            captcha_config: None,
            challenge_config: None,
            token_domains: Vec::new(),
            association_config: None,
            data_protection_config: None,
            on_source_d_do_s_protection_config: None,
            application_config: None,
            retrofitted_by_firewall_manager: false,
            pre_process_firewall_manager_rule_groups: Vec::new(),
            post_process_firewall_manager_rule_groups: Vec::new(),
            managed_by_firewall_manager: false,
            created_time: Utc::now(),
        }
    }

    fn req(uri: &'static str) -> WafRequest<'static> {
        WafRequest {
            method: "GET",
            uri,
            headers: &[],
            body: b"",
            query: "",
            source_ip: IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            country: None,
        }
    }

    fn byte_match_uri_contains(needle: &str, action: Value) -> Value {
        json!({
            "Name": "r",
            "Priority": 0,
            "Action": action,
            "VisibilityConfig": {},
            "Statement": {
                "ByteMatchStatement": {
                    "SearchString": needle,
                    "FieldToMatch": {"UriPath": {}},
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                    "PositionalConstraint": "CONTAINS",
                }
            }
        })
    }

    #[test]
    fn byte_match_contains_returns_block_when_default_allow_with_match() {
        let acl = make_acl(
            json!({"Allow": {}}),
            vec![byte_match_uri_contains("/admin", json!({"Block": {}}))],
        );
        let action = evaluate(&req("/admin/users"), &acl, &HashMap::new(), &HashMap::new());
        assert_eq!(action, WafAction::Block);
    }

    #[test]
    fn byte_match_no_match_returns_default_allow() {
        let acl = make_acl(
            json!({"Allow": {}}),
            vec![byte_match_uri_contains("/admin", json!({"Block": {}}))],
        );
        let action = evaluate(&req("/public"), &acl, &HashMap::new(), &HashMap::new());
        assert_eq!(action, WafAction::Allow);
    }

    #[test]
    fn ip_set_match_blocks_listed_ip() {
        let arn = "arn:aws:wafv2:us-east-1:000000000000:regional/ipset/blocked/abc".to_string();
        let mut sets = HashMap::new();
        sets.insert(
            arn.clone(),
            IpSet {
                id: "abc".into(),
                name: "blocked".into(),
                arn: arn.clone(),
                scope: "REGIONAL".into(),
                description: None,
                ip_address_version: "IPV4".into(),
                addresses: vec!["10.0.0.0/24".into()],
                lock_token: "lt".into(),
                created_time: Utc::now(),
            },
        );
        let acl = make_acl(
            json!({"Allow": {}}),
            vec![json!({
                "Name": "r",
                "Priority": 0,
                "Action": {"Block": {}},
                "VisibilityConfig": {},
                "Statement": {"IPSetReferenceStatement": {"ARN": arn}},
            })],
        );
        let mut r = req("/");
        r.source_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(evaluate(&r, &acl, &sets, &HashMap::new()), WafAction::Block);
    }

    #[test]
    fn geo_match_country_code_blocks() {
        let acl = make_acl(
            json!({"Allow": {}}),
            vec![json!({
                "Name": "r",
                "Priority": 0,
                "Action": {"Block": {}},
                "VisibilityConfig": {},
                "Statement": {"GeoMatchStatement": {"CountryCodes": ["US"]}},
            })],
        );
        let mut r = req("/");
        r.country = Some("US");
        assert_eq!(
            evaluate(&r, &acl, &HashMap::new(), &HashMap::new()),
            WafAction::Block
        );
    }

    #[test]
    fn regex_match_uri_path() {
        let acl = make_acl(
            json!({"Allow": {}}),
            vec![json!({
                "Name": "r",
                "Priority": 0,
                "Action": {"Block": {}},
                "VisibilityConfig": {},
                "Statement": {"RegexMatchStatement": {
                    "RegexString": "^/api/v[0-9]+/admin$",
                    "FieldToMatch": {"UriPath": {}},
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                }},
            })],
        );
        assert_eq!(
            evaluate(
                &req("/api/v2/admin"),
                &acl,
                &HashMap::new(),
                &HashMap::new()
            ),
            WafAction::Block
        );
        assert_eq!(
            evaluate(
                &req("/api/v2/admin/x"),
                &acl,
                &HashMap::new(),
                &HashMap::new()
            ),
            WafAction::Allow
        );
    }

    #[test]
    fn and_statement_requires_all() {
        // Byte match would hit, but geo match needs country=US which the request lacks.
        let acl = make_acl(
            json!({"Allow": {}}),
            vec![json!({
                "Name": "r",
                "Priority": 0,
                "Action": {"Block": {}},
                "VisibilityConfig": {},
                "Statement": {"AndStatement": {"Statements": [
                    {"ByteMatchStatement": {
                        "SearchString": "/admin",
                        "FieldToMatch": {"UriPath": {}},
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        "PositionalConstraint": "CONTAINS",
                    }},
                    {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                ]}},
            })],
        );
        assert_eq!(
            evaluate(&req("/admin"), &acl, &HashMap::new(), &HashMap::new()),
            WafAction::Allow
        );
    }

    #[test]
    fn or_statement_takes_first_match() {
        let acl = make_acl(
            json!({"Allow": {}}),
            vec![json!({
                "Name": "r",
                "Priority": 0,
                "Action": {"Block": {}},
                "VisibilityConfig": {},
                "Statement": {"OrStatement": {"Statements": [
                    {"ByteMatchStatement": {
                        "SearchString": "/admin",
                        "FieldToMatch": {"UriPath": {}},
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        "PositionalConstraint": "CONTAINS",
                    }},
                    {"GeoMatchStatement": {"CountryCodes": ["US"]}},
                ]}},
            })],
        );
        assert_eq!(
            evaluate(&req("/admin/x"), &acl, &HashMap::new(), &HashMap::new()),
            WafAction::Block
        );
    }

    #[test]
    fn not_statement_inverts() {
        let acl = make_acl(
            json!({"Allow": {}}),
            vec![json!({
                "Name": "r",
                "Priority": 0,
                "Action": {"Block": {}},
                "VisibilityConfig": {},
                "Statement": {"NotStatement": {"Statement": {
                    "ByteMatchStatement": {
                        "SearchString": "/admin",
                        "FieldToMatch": {"UriPath": {}},
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        "PositionalConstraint": "CONTAINS",
                    }
                }}},
            })],
        );
        // Inner ByteMatch fails, NOT inverts to true -> Block.
        assert_eq!(
            evaluate(&req("/public"), &acl, &HashMap::new(), &HashMap::new()),
            WafAction::Block
        );
    }

    #[test]
    fn regex_pattern_set_reference() {
        let arn =
            "arn:aws:wafv2:us-east-1:000000000000:regional/regexpatternset/rps/abc".to_string();
        let mut sets = HashMap::new();
        sets.insert(
            arn.clone(),
            RegexPatternSet {
                id: "abc".into(),
                name: "rps".into(),
                arn: arn.clone(),
                scope: "REGIONAL".into(),
                description: None,
                regular_expressions: vec![
                    json!({"RegexString": "^/admin"}),
                    json!({"RegexString": "^/internal"}),
                ],
                lock_token: "lt".into(),
                created_time: Utc::now(),
            },
        );
        let acl = make_acl(
            json!({"Allow": {}}),
            vec![json!({
                "Name": "r",
                "Priority": 0,
                "Action": {"Block": {}},
                "VisibilityConfig": {},
                "Statement": {"RegexPatternSetReferenceStatement": {
                    "ARN": arn,
                    "FieldToMatch": {"UriPath": {}},
                    "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                }},
            })],
        );
        assert_eq!(
            evaluate(&req("/internal/x"), &acl, &HashMap::new(), &sets),
            WafAction::Block
        );
    }

    #[test]
    fn default_action_block_when_no_rules_match_and_default_block() {
        let acl = make_acl(json!({"Block": {}}), vec![]);
        assert_eq!(
            evaluate(&req("/anything"), &acl, &HashMap::new(), &HashMap::new()),
            WafAction::Block
        );
    }

    #[test]
    fn count_action_does_not_terminate() {
        let acl = make_acl(
            json!({"Allow": {}}),
            vec![byte_match_uri_contains("/admin", json!({"Count": {}})), {
                let mut r = byte_match_uri_contains("/admin", json!({"Block": {}}));
                r["Priority"] = json!(1);
                r["Name"] = json!("r2");
                r
            }],
        );
        assert_eq!(
            evaluate(&req("/admin/x"), &acl, &HashMap::new(), &HashMap::new()),
            WafAction::Block
        );
    }

    #[test]
    fn label_match_after_earlier_rule_emits_label() {
        let acl = make_acl(
            json!({"Allow": {}}),
            vec![
                json!({
                    "Name": "tag",
                    "Priority": 0,
                    "Action": {"Count": {}},
                    "VisibilityConfig": {},
                    "RuleLabels": [{"Name": "awswaf:custom:admin"}],
                    "Statement": {"ByteMatchStatement": {
                        "SearchString": "/admin",
                        "FieldToMatch": {"UriPath": {}},
                        "TextTransformations": [{"Priority": 0, "Type": "NONE"}],
                        "PositionalConstraint": "CONTAINS",
                    }},
                }),
                json!({
                    "Name": "block-by-label",
                    "Priority": 1,
                    "Action": {"Block": {}},
                    "VisibilityConfig": {},
                    "Statement": {"LabelMatchStatement": {
                        "Scope": "LABEL",
                        "Key": "awswaf:custom:admin",
                    }},
                }),
            ],
        );
        assert_eq!(
            evaluate(&req("/admin/x"), &acl, &HashMap::new(), &HashMap::new()),
            WafAction::Block
        );
    }
}
