//! Listener-rule matching for the ELBv2 data plane.
//!
//! Each accepted HTTP request is dispatched against the listener
//! rules in priority order. The first rule whose conditions all
//! match decides the action. If no rule matches, the listener's
//! `default_actions` are used.

use http::{HeaderMap, Method, Uri};
use std::net::IpAddr;

use crate::state::{Action, Rule, RuleCondition};

/// Returns true when every condition in `rule` matches the request.
/// AWS rule semantics: a rule matches when ALL its conditions match,
/// and within a single condition, ANY listed value matches.
pub fn rule_matches(
    rule: &Rule,
    method: &Method,
    uri: &Uri,
    host: &str,
    headers: &HeaderMap,
    source_ip: Option<IpAddr>,
) -> bool {
    if rule.conditions.is_empty() {
        return false;
    }
    rule.conditions
        .iter()
        .all(|c| condition_matches(c, method, uri, host, headers, source_ip))
}

fn condition_matches(
    cond: &RuleCondition,
    method: &Method,
    uri: &Uri,
    host: &str,
    headers: &HeaderMap,
    source_ip: Option<IpAddr>,
) -> bool {
    match cond.field.as_str() {
        "host-header" => {
            let candidates = effective_values(&cond.host_header_values, &cond.values);
            candidates.iter().any(|v| host_pattern_matches(v, host))
        }
        "path-pattern" => {
            let candidates = effective_values(&cond.path_pattern_values, &cond.values);
            let path = uri.path();
            candidates.iter().any(|v| path_pattern_matches(v, path))
        }
        "http-request-method" => cond
            .http_request_method_values
            .iter()
            .any(|m| m.eq_ignore_ascii_case(method.as_str())),
        "http-header" => {
            let Some(name) = cond.http_header_name.as_deref() else {
                return false;
            };
            let Ok(hn) = http::HeaderName::try_from(name) else {
                return false;
            };
            let header_values: Vec<&str> = headers
                .get_all(hn)
                .iter()
                .filter_map(|v| v.to_str().ok())
                .collect();
            cond.http_header_values
                .iter()
                .any(|want| header_values.iter().any(|got| pattern_matches(want, got)))
        }
        "query-string" => {
            let pairs = parse_query(uri.query().unwrap_or(""));
            cond.query_string_values.iter().any(|kv| {
                pairs.iter().any(|(k, v)| {
                    let key_ok = match kv.key.as_deref() {
                        None => true,
                        Some(want) => pattern_matches(want, k),
                    };
                    let val_ok = match kv.value.as_deref() {
                        None => true,
                        Some(want) => pattern_matches(want, v),
                    };
                    key_ok && val_ok
                })
            })
        }
        "source-ip" => {
            let Some(ip) = source_ip else { return false };
            cond.source_ip_values
                .iter()
                .any(|cidr| ip_in_cidr(ip, cidr))
        }
        _ => false,
    }
}

fn effective_values<'a>(primary: &'a [String], fallback: &'a [String]) -> Vec<&'a String> {
    if !primary.is_empty() {
        primary.iter().collect()
    } else {
        fallback.iter().collect()
    }
}

/// AWS host-header pattern: case-insensitive, `*` and `?` wildcards.
fn host_pattern_matches(pattern: &str, host: &str) -> bool {
    let host = host.trim_end_matches(':').to_lowercase();
    let host_no_port = host.split(':').next().unwrap_or(&host).to_string();
    pattern_matches_ci(pattern, &host_no_port)
}

/// AWS path-pattern: case-sensitive, `*` and `?` wildcards.
fn path_pattern_matches(pattern: &str, path: &str) -> bool {
    pattern_matches(pattern, path)
}

/// `*` (any sequence including empty) and `?` (one char) glob matcher.
pub fn pattern_matches(pattern: &str, value: &str) -> bool {
    glob(pattern.as_bytes(), value.as_bytes())
}

fn pattern_matches_ci(pattern: &str, value: &str) -> bool {
    glob(
        pattern.to_lowercase().as_bytes(),
        value.to_lowercase().as_bytes(),
    )
}

fn glob(pat: &[u8], val: &[u8]) -> bool {
    let (mut pi, mut vi) = (0, 0);
    let (mut star_p, mut star_v): (Option<usize>, usize) = (None, 0);
    while vi < val.len() {
        if pi < pat.len() && (pat[pi] == b'?' || pat[pi] == val[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < pat.len() && pat[pi] == b'*' {
            star_p = Some(pi);
            star_v = vi;
            pi += 1;
        } else if let Some(sp) = star_p {
            pi = sp + 1;
            star_v += 1;
            vi = star_v;
        } else {
            return false;
        }
    }
    while pi < pat.len() && pat[pi] == b'*' {
        pi += 1;
    }
    pi == pat.len()
}

fn parse_query(q: &str) -> Vec<(String, String)> {
    if q.is_empty() {
        return Vec::new();
    }
    q.split('&')
        .filter_map(|seg| {
            let mut it = seg.splitn(2, '=');
            let k = it.next()?.to_string();
            let v = it.next().unwrap_or("").to_string();
            Some((k, v))
        })
        .collect()
}

/// `cidr` may be `192.168.0.0/24` or a bare IP `10.0.0.5`.
fn ip_in_cidr(ip: IpAddr, cidr: &str) -> bool {
    let (net, bits) = match cidr.split_once('/') {
        Some((n, b)) => match b.parse::<u8>() {
            Ok(b) => (n, b),
            Err(_) => return false,
        },
        None => return cidr.parse::<IpAddr>().map(|n| n == ip).unwrap_or(false),
    };
    let net: IpAddr = match net.parse() {
        Ok(n) => n,
        Err(_) => return false,
    };
    match (net, ip) {
        (IpAddr::V4(n), IpAddr::V4(i)) => v4_in(n.octets(), i.octets(), bits),
        (IpAddr::V6(n), IpAddr::V6(i)) => v6_in(n.octets(), i.octets(), bits),
        _ => false,
    }
}

fn v4_in(net: [u8; 4], ip: [u8; 4], bits: u8) -> bool {
    if bits > 32 {
        return false;
    }
    let n = u32::from_be_bytes(net);
    let i = u32::from_be_bytes(ip);
    let mask = if bits == 0 {
        0
    } else {
        u32::MAX << (32 - bits)
    };
    (n & mask) == (i & mask)
}

fn v6_in(net: [u8; 16], ip: [u8; 16], bits: u8) -> bool {
    if bits > 128 {
        return false;
    }
    let mut net128 = 0u128;
    let mut ip128 = 0u128;
    for i in 0..16 {
        net128 = (net128 << 8) | net[i] as u128;
        ip128 = (ip128 << 8) | ip[i] as u128;
    }
    let mask = if bits == 0 {
        0u128
    } else {
        u128::MAX << (128 - bits)
    };
    (net128 & mask) == (ip128 & mask)
}

/// Walks rules in priority order. Default rules (`is_default=true`)
/// are always considered last. Returns the first matching rule's
/// `actions`, or the listener default actions when nothing matches.
pub fn select_actions<'a>(
    rules: &'a [&'a Rule],
    listener_default: &'a [Action],
    method: &Method,
    uri: &Uri,
    host: &str,
    headers: &HeaderMap,
    source_ip: Option<IpAddr>,
) -> &'a [Action] {
    let mut sorted: Vec<&Rule> = rules.to_vec();
    sorted.sort_by(|a, b| {
        // Default rules always last; non-defaults sorted by integer priority asc.
        if a.is_default && !b.is_default {
            return std::cmp::Ordering::Greater;
        }
        if !a.is_default && b.is_default {
            return std::cmp::Ordering::Less;
        }
        let ap: i64 = a.priority.parse().unwrap_or(i64::MAX);
        let bp: i64 = b.priority.parse().unwrap_or(i64::MAX);
        ap.cmp(&bp)
    });
    for r in &sorted {
        if r.is_default {
            continue;
        }
        if rule_matches(r, method, uri, host, headers, source_ip) {
            return &r.actions;
        }
    }
    // No non-default rule matched. Prefer a stored default rule
    // if present, otherwise fall back to the listener's
    // default_actions slice.
    if let Some(default_rule) = sorted.iter().find(|r| r.is_default) {
        return &default_rule.actions;
    }
    listener_default
}

#[cfg(test)]
mod tests {
    use super::*;

    fn rule_with(field: &str, condition_setup: impl FnOnce(&mut RuleCondition)) -> Rule {
        let mut c = RuleCondition {
            field: field.to_string(),
            values: Vec::new(),
            host_header_values: Vec::new(),
            path_pattern_values: Vec::new(),
            http_header_name: None,
            http_header_values: Vec::new(),
            query_string_values: Vec::new(),
            http_request_method_values: Vec::new(),
            source_ip_values: Vec::new(),
        };
        condition_setup(&mut c);
        Rule {
            arn: "arn".to_string(),
            listener_arn: "l".to_string(),
            priority: "1".to_string(),
            conditions: vec![c],
            actions: Vec::new(),
            is_default: false,
            tags: Vec::new(),
        }
    }

    #[test]
    fn glob_basic() {
        assert!(glob(b"/api/*", b"/api/v1/users"));
        assert!(glob(b"*.example.com", b"www.example.com"));
        assert!(glob(b"/p?th", b"/path"));
        assert!(!glob(b"/api/", b"/api/v1"));
    }

    #[test]
    fn host_header_match_case_insensitive() {
        let r = rule_with("host-header", |c| {
            c.host_header_values = vec!["*.Example.com".into()];
        });
        assert!(rule_matches(
            &r,
            &Method::GET,
            &"/".parse().unwrap(),
            "www.example.com",
            &HeaderMap::new(),
            None,
        ));
    }

    #[test]
    fn path_pattern_matches_glob() {
        let r = rule_with("path-pattern", |c| {
            c.path_pattern_values = vec!["/api/*/users".into()];
        });
        assert!(rule_matches(
            &r,
            &Method::GET,
            &"/api/v2/users".parse().unwrap(),
            "x",
            &HeaderMap::new(),
            None,
        ));
    }

    #[test]
    fn method_match() {
        let r = rule_with("http-request-method", |c| {
            c.http_request_method_values = vec!["POST".into()];
        });
        assert!(rule_matches(
            &r,
            &Method::POST,
            &"/".parse().unwrap(),
            "x",
            &HeaderMap::new(),
            None,
        ));
        assert!(!rule_matches(
            &r,
            &Method::GET,
            &"/".parse().unwrap(),
            "x",
            &HeaderMap::new(),
            None,
        ));
    }

    #[test]
    fn header_match_uses_glob() {
        let r = rule_with("http-header", |c| {
            c.http_header_name = Some("X-Test".into());
            c.http_header_values = vec!["pre*post".into()];
        });
        let mut h = HeaderMap::new();
        h.insert("x-test", "pre-anything-post".parse().unwrap());
        assert!(rule_matches(
            &r,
            &Method::GET,
            &"/".parse().unwrap(),
            "x",
            &h,
            None,
        ));
    }

    #[test]
    fn cidr_v4_match() {
        assert!(ip_in_cidr("10.0.0.5".parse().unwrap(), "10.0.0.0/24"));
        assert!(!ip_in_cidr("10.0.1.5".parse().unwrap(), "10.0.0.0/24"));
    }

    #[test]
    fn cidr_v4_zero_bits_matches_anything() {
        assert!(ip_in_cidr("1.2.3.4".parse().unwrap(), "0.0.0.0/0"));
    }
}
