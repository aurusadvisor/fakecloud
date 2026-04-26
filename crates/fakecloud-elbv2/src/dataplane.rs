//! In-process HTTP routing for ELBv2 ALBs.
//!
//! For each ALB whose `state_code == "active"`, the supervisor binds
//! a TCP listener on `127.0.0.1:0` (OS-allocated). Connections are
//! parsed as HTTP/1.1, matched against the listener rules belonging
//! to that LB, and dispatched to the action: `forward` (round-robin
//! over registered targets in the chosen target group),
//! `fixed-response`, `redirect`, or `authenticate-oidc` /
//! `authenticate-cognito` (501 — declared next-batch).
//!
//! TLS termination, mTLS, and raw NLB TCP are intentionally next-
//! batch work items. The data-plane doc page enumerates the gap.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use parking_lot::Mutex;
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tracing::{debug, trace, warn};
use uuid::Uuid;

use crate::router::{pattern_matches, select_actions};
use crate::state::{Action, Listener, LoadBalancer, Rule, SharedElbv2State, TargetGroup};

const ENV_DISABLE: &str = "FAKECLOUD_ELBV2_DISABLE_DATAPLANE";
const SUPERVISOR_TICK_SECS: u64 = 1;
const STICKY_COOKIE: &str = "AWSALB";

pub fn dataplane_enabled() -> bool {
    !matches!(
        std::env::var(ENV_DISABLE).as_deref(),
        Ok("1") | Ok("true") | Ok("TRUE") | Ok("yes") | Ok("YES")
    )
}

/// Per-LB listener handle. Held in the supervisor map so that a LB
/// removal can drop the JoinHandle and free the OS port.
struct BoundListener {
    #[allow(dead_code)]
    port: u16,
    handle: JoinHandle<()>,
}

impl Drop for BoundListener {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// State shared across the supervisor and per-connection handlers.
#[derive(Clone)]
struct DataPlane {
    state: SharedElbv2State,
    /// Round-robin index per target group ARN (mod target count).
    rr_counters: Arc<Mutex<HashMap<String, usize>>>,
    /// Sticky-session map: `AWSALB` cookie value -> `tg_arn|target_id|target_port`.
    sticky_targets: Arc<Mutex<HashMap<String, String>>>,
    upstream: reqwest::Client,
}

pub fn spawn_dataplane(state: SharedElbv2State) {
    if !dataplane_enabled() {
        debug!("ELBv2 data plane disabled via {ENV_DISABLE}");
        return;
    }
    let upstream = match reqwest::Client::builder()
        .danger_accept_invalid_certs(true)
        // Disable redirects so we surface them as the upstream sees them.
        .redirect(reqwest::redirect::Policy::none())
        // Per-request timeout — keep tight; tests want fast feedback.
        .timeout(Duration::from_secs(30))
        .build()
    {
        Ok(c) => c,
        Err(e) => {
            warn!("ELBv2 data plane: failed to build reqwest client: {e}");
            return;
        }
    };
    let dp = DataPlane {
        state,
        rr_counters: Arc::new(Mutex::new(HashMap::new())),
        sticky_targets: Arc::new(Mutex::new(HashMap::new())),
        upstream,
    };
    tokio::spawn(supervisor_loop(dp));
}

async fn supervisor_loop(dp: DataPlane) {
    let mut bindings: HashMap<String, BoundListener> = HashMap::new();
    let mut tick = tokio::time::interval(Duration::from_secs(SUPERVISOR_TICK_SECS));
    tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        tick.tick().await;
        reconcile(&dp, &mut bindings).await;
    }
}

async fn reconcile(dp: &DataPlane, bindings: &mut HashMap<String, BoundListener>) {
    // 1. Snapshot the set of ALBs that need a listener and their schemes.
    let want: Vec<(String, String)> = {
        let accs = dp.state.read();
        let mut out = Vec::new();
        for (_acct, st) in accs.iter() {
            for lb in st.load_balancers.values() {
                if !lb_should_bind(lb) {
                    continue;
                }
                out.push((lb.arn.clone(), lb.lb_type.clone()));
            }
        }
        out
    };
    let want_set: std::collections::HashSet<&String> = want.iter().map(|(arn, _)| arn).collect();

    // 2. Drop bindings for LBs that no longer exist or are not active.
    bindings.retain(|arn, _| want_set.contains(arn));

    // 3. Bind any new ALB.
    for (arn, lb_type) in want.into_iter() {
        if bindings.contains_key(&arn) {
            continue;
        }
        if !lb_type.eq_ignore_ascii_case("application") {
            // Only ALBs get the in-process HTTP data plane in this
            // batch. NLB raw-TCP and GWLB are explicit next-batch
            // items per the data-plane doc.
            continue;
        }
        match TcpListener::bind(("127.0.0.1", 0)).await {
            Ok(listener) => {
                let port = listener.local_addr().map(|a| a.port()).unwrap_or(0);
                if port == 0 {
                    warn!("ELBv2 data plane: bind returned port 0 for {arn}; skipping");
                    continue;
                }
                {
                    let mut accs = dp.state.write();
                    let owning_account: Option<String> = accs
                        .iter()
                        .find(|(_, s)| s.load_balancers.contains_key(&arn))
                        .map(|(a, _)| a.clone());
                    if let Some(acct) = owning_account {
                        if let Some(st) = accs.get_mut(&acct) {
                            if let Some(lb) = st.load_balancers.get_mut(&arn) {
                                lb.bound_port = Some(port);
                            }
                        }
                    }
                }
                let dp2 = dp.clone();
                let arn2 = arn.clone();
                let handle = tokio::spawn(async move {
                    accept_loop(dp2, arn2, listener).await;
                });
                bindings.insert(arn.clone(), BoundListener { port, handle });
                trace!(arn = %arn, port, "ELBv2 data plane: bound listener");
            }
            Err(e) => {
                warn!("ELBv2 data plane: failed to bind for {arn}: {e}");
            }
        }
    }

    // 4. Clear bound_port for any LB the supervisor is no longer holding.
    let mut accs = dp.state.write();
    let acct_ids: Vec<String> = accs.iter().map(|(a, _)| a.clone()).collect();
    for acct in acct_ids {
        if let Some(st) = accs.get_mut(&acct) {
            for lb in st.load_balancers.values_mut() {
                if !bindings.contains_key(&lb.arn) {
                    lb.bound_port = None;
                }
            }
        }
    }
}

fn lb_should_bind(lb: &LoadBalancer) -> bool {
    lb.state_code == "active"
}

async fn accept_loop(dp: DataPlane, lb_arn: String, listener: TcpListener) {
    loop {
        let (sock, peer_addr) = match listener.accept().await {
            Ok(p) => p,
            Err(e) => {
                debug!(arn = %lb_arn, "accept error: {e}");
                continue;
            }
        };
        let dp2 = dp.clone();
        let lb_arn2 = lb_arn.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(sock);
            let svc = service_fn(move |req| {
                let dp3 = dp2.clone();
                let lb3 = lb_arn2.clone();
                let peer = peer_addr;
                async move { Ok::<_, Infallible>(handle_request(&dp3, &lb3, peer, req).await) }
            });
            if let Err(e) = hyper::server::conn::http1::Builder::new()
                .serve_connection(io, svc)
                .await
            {
                debug!("ELBv2 data plane: connection error: {e}");
            }
        });
    }
}

async fn handle_request(
    dp: &DataPlane,
    lb_arn: &str,
    peer_addr: SocketAddr,
    req: Request<Incoming>,
) -> Response<Full<Bytes>> {
    // Read request fully into memory. Body sizes that matter for ALB
    // tests are small; the streaming-body refactor is its own batch.
    let (parts, body) = req.into_parts();
    let body_bytes = match body.collect().await {
        Ok(c) => c.to_bytes(),
        Err(_) => return canned(StatusCode::BAD_REQUEST, "Bad Request"),
    };

    let host = parts
        .headers
        .get(http::header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let port = parts.uri.port_u16().unwrap_or(0);
    let _ = port;

    // Pick the listener for this connection. ALBs may have multiple
    // listeners (e.g. 80 + 443); we pick the first listener belonging
    // to this LB, since the in-process bind is single-port for now.
    let snap = match snapshot(dp, lb_arn) {
        Some(s) => s,
        None => return canned(StatusCode::SERVICE_UNAVAILABLE, "LB removed"),
    };

    let listener = match snap.listener_for_request(&parts.headers) {
        Some(l) => l,
        None => return canned(StatusCode::BAD_GATEWAY, "No listener"),
    };

    let rules: Vec<&Rule> = snap.rules_for_listener(&listener.arn);
    let actions = select_actions(
        &rules,
        &listener.default_actions,
        &parts.method,
        &parts.uri,
        &host,
        &parts.headers,
        Some(peer_addr.ip()),
    );

    let action = match actions.iter().min_by_key(|a| a.order.unwrap_or(0)) {
        Some(a) => a.clone(),
        None => return canned(StatusCode::BAD_GATEWAY, "No action"),
    };

    match action.action_type.to_lowercase().as_str() {
        "forward" => {
            forward_action(
                dp,
                &snap,
                &action,
                parts.method,
                parts.uri,
                parts.headers,
                body_bytes,
            )
            .await
        }
        "fixed-response" => fixed_response_action(&action),
        "redirect" => redirect_action(&action, &host, &parts.uri),
        "authenticate-oidc" | "authenticate-cognito" => canned(
            StatusCode::NOT_IMPLEMENTED,
            "OIDC/Cognito authenticate-action is on the next-batch ELBv2 list",
        ),
        other => canned(
            StatusCode::BAD_GATEWAY,
            &format!("Unsupported action: {other}"),
        ),
    }
}

/// Snapshot of the rules/listeners/target-groups for one LB taken
/// under the read lock so the per-request handler doesn't re-lock.
struct LbSnapshot {
    listeners: Vec<Listener>,
    rules: Vec<Rule>,
    target_groups: HashMap<String, TargetGroup>,
}

impl LbSnapshot {
    fn listener_for_request(&self, _headers: &HeaderMap) -> Option<&Listener> {
        // The dataplane is single-port per LB in this batch — every
        // request lands on the same hyper bind, so we pick the first
        // HTTP-protocol listener as the active one. HTTPS termination
        // is the next-batch item.
        self.listeners
            .iter()
            .find(|l| {
                l.protocol
                    .as_deref()
                    .map(|p| p.eq_ignore_ascii_case("HTTP"))
                    .unwrap_or(false)
            })
            .or_else(|| self.listeners.first())
    }

    fn rules_for_listener(&self, listener_arn: &str) -> Vec<&Rule> {
        self.rules
            .iter()
            .filter(|r| r.listener_arn == listener_arn)
            .collect()
    }
}

fn snapshot(dp: &DataPlane, lb_arn: &str) -> Option<LbSnapshot> {
    let accs = dp.state.read();
    for (_acct, st) in accs.iter() {
        if st.load_balancers.contains_key(lb_arn) {
            let listeners: Vec<Listener> = st
                .listeners
                .values()
                .filter(|l| l.load_balancer_arn == lb_arn)
                .cloned()
                .collect();
            let listener_arns: std::collections::HashSet<String> =
                listeners.iter().map(|l| l.arn.clone()).collect();
            let rules: Vec<Rule> = st
                .rules
                .values()
                .filter(|r| listener_arns.contains(&r.listener_arn))
                .cloned()
                .collect();
            let target_groups: HashMap<String, TargetGroup> = st
                .target_groups
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            return Some(LbSnapshot {
                listeners,
                rules,
                target_groups,
            });
        }
    }
    None
}

fn fixed_response_action(action: &Action) -> Response<Full<Bytes>> {
    let cfg = match action.fixed_response.as_ref() {
        Some(c) => c,
        None => return canned(StatusCode::BAD_GATEWAY, "fixed-response missing config"),
    };
    let status = cfg
        .status_code
        .parse::<u16>()
        .ok()
        .and_then(|c| StatusCode::from_u16(c).ok())
        .unwrap_or(StatusCode::OK);
    let body = cfg.message_body.clone().unwrap_or_default();
    let content_type = cfg
        .content_type
        .clone()
        .unwrap_or_else(|| "text/plain".into());
    let mut resp = Response::new(Full::new(Bytes::from(body)));
    *resp.status_mut() = status;
    if let Ok(v) = HeaderValue::from_str(&content_type) {
        resp.headers_mut().insert(http::header::CONTENT_TYPE, v);
    }
    resp
}

fn redirect_action(
    action: &Action,
    request_host: &str,
    request_uri: &http::Uri,
) -> Response<Full<Bytes>> {
    let cfg = match action.redirect.as_ref() {
        Some(c) => c,
        None => return canned(StatusCode::BAD_GATEWAY, "redirect missing config"),
    };
    let status = match cfg.status_code.as_str() {
        "HTTP_301" => StatusCode::MOVED_PERMANENTLY,
        "HTTP_302" => StatusCode::FOUND,
        _ => StatusCode::FOUND,
    };
    let proto = cfg.protocol.clone().unwrap_or_else(|| "HTTPS".into());
    let host = cfg.host.clone().unwrap_or_else(|| {
        request_host
            .split(':')
            .next()
            .unwrap_or(request_host)
            .to_string()
    });
    let path = cfg
        .path
        .clone()
        .unwrap_or_else(|| request_uri.path().to_string());
    let query = match (cfg.query.clone(), request_uri.query()) {
        (Some(q), _) if !q.is_empty() => format!("?{q}"),
        (_, Some(q)) if !q.is_empty() => format!("?{q}"),
        _ => String::new(),
    };
    let port = cfg.port.clone();
    let port_seg = port
        .and_then(|p| if p == "#{port}" { None } else { Some(p) })
        .map(|p| format!(":{p}"))
        .unwrap_or_default();
    let location = format!("{proto}://{host}{port_seg}{path}{query}").to_lowercase();
    let mut resp = Response::new(Full::new(Bytes::new()));
    *resp.status_mut() = status;
    if let Ok(v) = HeaderValue::from_str(&location) {
        resp.headers_mut().insert(http::header::LOCATION, v);
    }
    resp
}

async fn forward_action(
    dp: &DataPlane,
    snap: &LbSnapshot,
    action: &Action,
    method: Method,
    uri: http::Uri,
    headers: HeaderMap,
    body: Bytes,
) -> Response<Full<Bytes>> {
    // Prefer `forward.target_groups` (weighted), fall back to the
    // single `target_group_arn` field for legacy actions.
    let target_groups: Vec<(String, i32)> = if let Some(fwd) = action.forward.as_ref() {
        fwd.target_groups
            .iter()
            .map(|t| (t.target_group_arn.clone(), t.weight.unwrap_or(1).max(1)))
            .collect()
    } else if let Some(tg) = action.target_group_arn.as_ref() {
        vec![(tg.clone(), 1)]
    } else {
        return canned(
            StatusCode::BAD_GATEWAY,
            "forward action without target groups",
        );
    };

    let total_weight: i32 = target_groups.iter().map(|(_, w)| *w).sum();
    if total_weight <= 0 {
        return canned(StatusCode::BAD_GATEWAY, "no positive target-group weight");
    }
    // Pick a target group (weighted round-robin). Lock is taken
    // and released within the helper — never across the upstream
    // .await, which would make the future !Send.
    let pick_idx = pick_weighted(
        &dp.rr_counters,
        &format!("tg:{}", action_key(action)),
        &target_groups,
        total_weight as usize,
    );

    let (tg_arn, _w) = target_groups[pick_idx].clone();
    let tg = match snap.target_groups.get(&tg_arn) {
        Some(t) => t,
        None => return canned(StatusCode::SERVICE_UNAVAILABLE, "Target group not found"),
    };

    // Sticky session: if the request carries an AWSALB cookie that
    // maps to a registered target in this TG, prefer that target.
    let sticky_pick: Option<String> = if action
        .forward
        .as_ref()
        .and_then(|f| f.stickiness.as_ref())
        .and_then(|s| s.enabled)
        .unwrap_or(false)
    {
        let cookie = headers
            .get(http::header::COOKIE)
            .and_then(|v| v.to_str().ok())
            .and_then(|c| extract_cookie(c, STICKY_COOKIE).map(str::to_string));
        match cookie {
            Some(c) => {
                let map = dp.sticky_targets.lock();
                map.get(&c).cloned()
            }
            None => None,
        }
    } else {
        None
    };

    let healthy: Vec<&crate::state::TargetDescription> = tg
        .targets
        .iter()
        .filter(|t| t.health.state != "unhealthy" && t.health.state != "unused")
        .collect();
    if healthy.is_empty() {
        return canned(StatusCode::SERVICE_UNAVAILABLE, "No healthy targets");
    }

    let chosen: &crate::state::TargetDescription = if let Some(sticky_key) = sticky_pick.as_ref() {
        // sticky_key format: tg_arn|target_id|target_port
        let parts: Vec<&str> = sticky_key.split('|').collect();
        if parts.len() == 3 && parts[0] == tg_arn {
            let port: Option<i32> = parts[2].parse().ok();
            healthy
                .iter()
                .copied()
                .find(|t| t.id == parts[1] && t.port == port)
                .unwrap_or_else(|| {
                    healthy[round_robin_pick(&dp.rr_counters, &tg_arn, healthy.len())]
                })
        } else {
            healthy[round_robin_pick(&dp.rr_counters, &tg_arn, healthy.len())]
        }
    } else {
        healthy[round_robin_pick(&dp.rr_counters, &tg_arn, healthy.len())]
    };

    // Build upstream URL.
    let scheme = "http";
    let upstream_host = if chosen.id.starts_with("i-") {
        "127.0.0.1".to_string()
    } else {
        chosen.id.clone()
    };
    let upstream_port = chosen.port.or(tg.port).unwrap_or(80);
    let path_and_query = uri.path_and_query().map(|p| p.as_str()).unwrap_or("/");
    let upstream_url = format!("{scheme}://{upstream_host}:{upstream_port}{path_and_query}");

    // Forward via reqwest. Strip hop-by-hop headers; AWS adds
    // X-Forwarded-* headers.
    let mut req_builder = dp.upstream.request(reqwest_method(&method), &upstream_url);
    let mut forwarded_headers = headers.clone();
    strip_hop_by_hop(&mut forwarded_headers);
    let xff = match forwarded_headers
        .get("x-forwarded-for")
        .and_then(|v| v.to_str().ok())
    {
        Some(existing) => format!("{existing}, 127.0.0.1"),
        None => "127.0.0.1".to_string(),
    };
    forwarded_headers.insert(
        HeaderName::from_static("x-forwarded-for"),
        HeaderValue::from_str(&xff).unwrap(),
    );
    forwarded_headers.insert(
        HeaderName::from_static("x-forwarded-proto"),
        HeaderValue::from_static("http"),
    );
    forwarded_headers.insert(
        HeaderName::from_static("x-forwarded-port"),
        HeaderValue::from_str(&upstream_port.to_string()).unwrap(),
    );
    let trace_id = format!("Root=1-{:x}-{}", chrono::Utc::now().timestamp(), short_id());
    forwarded_headers.insert(
        HeaderName::from_static("x-amzn-trace-id"),
        HeaderValue::from_str(&trace_id).unwrap(),
    );
    for (k, v) in forwarded_headers.iter() {
        req_builder = req_builder.header(k.as_str(), v.as_bytes());
    }
    if !body.is_empty() {
        req_builder = req_builder.body(body.to_vec());
    }

    let upstream_resp = match req_builder.send().await {
        Ok(r) => r,
        Err(e) => {
            return canned(StatusCode::BAD_GATEWAY, &format!("Upstream error: {e}"));
        }
    };

    let mut resp = Response::new(Full::new(Bytes::new()));
    *resp.status_mut() = upstream_resp.status();
    let upstream_headers = upstream_resp.headers().clone();
    for (k, v) in upstream_headers.iter() {
        if !is_hop_by_hop(k.as_str()) {
            resp.headers_mut().append(k.clone(), v.clone());
        }
    }

    // Issue / refresh sticky cookie if stickiness is enabled.
    if action
        .forward
        .as_ref()
        .and_then(|f| f.stickiness.as_ref())
        .and_then(|s| s.enabled)
        .unwrap_or(false)
    {
        let key = format!("{tg_arn}|{}|{}", chosen.id, chosen.port.unwrap_or(0));
        let cookie_val = Uuid::new_v4().simple().to_string();
        dp.sticky_targets.lock().insert(cookie_val.clone(), key);
        let duration = action
            .forward
            .as_ref()
            .and_then(|f| f.stickiness.as_ref())
            .and_then(|s| s.duration_seconds)
            .unwrap_or(86400);
        let cookie_header = format!("{STICKY_COOKIE}={cookie_val}; Max-Age={duration}; Path=/");
        if let Ok(v) = HeaderValue::from_str(&cookie_header) {
            resp.headers_mut().append(http::header::SET_COOKIE, v);
        }
    }

    let resp_body = match upstream_resp.bytes().await {
        Ok(b) => b,
        Err(e) => {
            return canned(
                StatusCode::BAD_GATEWAY,
                &format!("Upstream body error: {e}"),
            );
        }
    };
    *resp.body_mut() = Full::new(resp_body);
    resp
}

fn round_robin_pick(
    counters: &Arc<Mutex<HashMap<String, usize>>>,
    tg_arn: &str,
    n: usize,
) -> usize {
    if n == 0 {
        return 0;
    }
    let mut map = counters.lock();
    let c = map.entry(tg_arn.to_string()).or_insert(0);
    let pick = *c % n;
    *c = c.wrapping_add(1);
    pick
}

fn pick_weighted(
    counters: &Arc<Mutex<HashMap<String, usize>>>,
    key: &str,
    target_groups: &[(String, i32)],
    total_weight: usize,
) -> usize {
    if total_weight == 0 {
        return 0;
    }
    let mut map = counters.lock();
    let c = map.entry(key.to_string()).or_insert(0);
    *c = c.wrapping_add(1);
    let mod_n = (*c) % total_weight;
    drop(map);
    let mut chosen = 0usize;
    let mut acc: i32 = 0;
    for (i, (_, w)) in target_groups.iter().enumerate() {
        acc += *w;
        if (mod_n as i32) < acc {
            chosen = i;
            break;
        }
    }
    chosen
}

fn reqwest_method(m: &Method) -> reqwest::Method {
    match m.as_str() {
        "GET" => reqwest::Method::GET,
        "POST" => reqwest::Method::POST,
        "PUT" => reqwest::Method::PUT,
        "DELETE" => reqwest::Method::DELETE,
        "HEAD" => reqwest::Method::HEAD,
        "OPTIONS" => reqwest::Method::OPTIONS,
        "PATCH" => reqwest::Method::PATCH,
        "TRACE" => reqwest::Method::TRACE,
        "CONNECT" => reqwest::Method::CONNECT,
        other => reqwest::Method::from_bytes(other.as_bytes()).unwrap_or(reqwest::Method::GET),
    }
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

fn is_hop_by_hop(name: &str) -> bool {
    let n = name.to_ascii_lowercase();
    HOP_BY_HOP.iter().any(|&h| h == n)
}

fn strip_hop_by_hop(h: &mut HeaderMap) {
    let to_remove: Vec<HeaderName> = h
        .keys()
        .filter(|n| is_hop_by_hop(n.as_str()))
        .cloned()
        .collect();
    for n in to_remove {
        h.remove(n);
    }
}

fn canned(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    let mut r = Response::new(Full::new(Bytes::from(msg.to_string())));
    *r.status_mut() = status;
    r.headers_mut().insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain"),
    );
    r
}

fn action_key(a: &Action) -> String {
    if let Some(fwd) = a.forward.as_ref() {
        fwd.target_groups
            .iter()
            .map(|t| t.target_group_arn.as_str())
            .collect::<Vec<_>>()
            .join(",")
    } else if let Some(tg) = a.target_group_arn.as_ref() {
        tg.clone()
    } else {
        a.action_type.clone()
    }
}

fn extract_cookie<'a>(cookies: &'a str, name: &str) -> Option<&'a str> {
    for piece in cookies.split(';') {
        let piece = piece.trim_start();
        if let Some(rest) = piece.strip_prefix(&format!("{name}=")) {
            return Some(rest.trim_end());
        }
    }
    None
}

fn short_id() -> String {
    let id = Uuid::new_v4();
    id.simple().to_string()[0..16].to_string()
}

// Suppress unused import warning when feature combinations don't
// need this path matcher in release builds.
#[allow(dead_code)]
fn _path_matches(p: &str, s: &str) -> bool {
    pattern_matches(p, s)
}
