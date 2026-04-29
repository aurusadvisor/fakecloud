//! Phase 1 IAM identity-policy evaluator.
//!
//! This module is a **pure function** over a set of policy documents and a
//! request: it does no I/O, no network, no state mutation, and never panics.
//! Dispatch (in batch 6) wires it up by collecting the principal's effective
//! policy set via [`collect_identity_policies`] and calling
//! [`evaluate`].
//!
//! # Phase 1 scope
//!
//! Implemented:
//! - `Effect: "Allow"` / `Effect: "Deny"` with **Deny precedence**: any
//!   matching `Deny` statement wins, regardless of how many `Allow`s match.
//! - `Action` / `NotAction` with `*` and `?` wildcards (case-insensitive
//!   service prefix match, case-sensitive action match — matches AWS).
//! - `Resource` / `NotResource` with `*` and `?` wildcards.
//! - Identity policies attached to users (inline + managed) and to groups
//!   the user belongs to.
//! - Identity policies attached to roles (inline + managed).
//! - Empty effective policy set → implicit deny.
//!
//! **Phase 2** — `Condition` block evaluation is now integrated via
//! [`crate::condition`]. A statement that carries a `Condition` is
//! evaluated against the [`RequestContext`] (populated at dispatch time);
//! the statement applies iff every operator entry matches. Unknown
//! operators / unknown keys / parse errors safe-fail to "statement does
//! not apply" with a `fakecloud::iam::audit` debug log, matching the
//! no-silent-accept rule from Phase 1.
//!
//! **Phase 3** — [`evaluate_with_gates`] and
//! [`evaluate_with_resource_policy_and_gates`] add intersection with
//! optional permission-boundary and session-policy layers. Each layer
//! is evaluated independently with the same matching logic; the final
//! decision requires every present layer to allow, and an explicit
//! `Deny` in any layer still wins.
//!
//! **Not** implemented (returns implicit deny rather than guessing — these
//! are tracked for future phases and documented on `/docs/reference/security`):
//! - Service control policies
//!
use std::collections::HashSet;

use fakecloud_core::auth::{Principal, PrincipalType};
use serde_json::Value;

use crate::condition::{CompiledCondition, ConditionContext};
use crate::state::IamState;

/// Request-time context keys used when evaluating `Condition` blocks.
///
/// This is a re-export of [`ConditionContext`] to keep the evaluator's
/// public API stable while centralizing the context definition in the
/// [`crate::condition`] module.
pub type RequestContext = ConditionContext;

/// The result of evaluating a request against a set of policies.
///
/// `Allow` requires at least one matching `Allow` statement and zero
/// matching `Deny` statements. `ExplicitDeny` indicates at least one
/// matching `Deny` statement (which takes precedence over any `Allow`).
/// `ImplicitDeny` is the catch-all for "no policy spoke to this request".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    Allow,
    ImplicitDeny,
    ExplicitDeny,
}

impl Decision {
    /// Returns true if the request should be allowed.
    pub fn is_allow(self) -> bool {
        matches!(self, Decision::Allow)
    }
}

/// One IAM action to evaluate against a policy set.
///
/// `action` follows the canonical `service:Action` shape (e.g.
/// `s3:GetObject`, `sqs:SendMessage`). `resource` is a fully-qualified
/// AWS ARN; the per-service resource extractors in batches 6-8 produce
/// these.
///
/// `context` carries request-time condition keys (populated at dispatch)
/// used when evaluating statements with a `Condition` block.
#[derive(Debug, Clone)]
pub struct EvalRequest<'a> {
    pub principal: &'a Principal,
    pub action: String,
    pub resource: String,
    pub context: RequestContext,
}

/// Parsed view of a single statement within a policy document.
#[derive(Debug, Clone)]
pub(crate) struct ParsedStatement {
    pub effect: Effect,
    pub action: ActionMatch,
    pub resource: ResourceMatch,
    /// Compiled `Condition` block if the statement carried one. A
    /// statement with `Some(_)` only applies when the compiled block
    /// evaluates to `true` against the request's [`RequestContext`].
    pub condition: Option<CompiledCondition>,
    /// How this statement restricts which principals it applies to.
    /// Identity policies always parse as [`PrincipalPattern::None`];
    /// resource policies may carry a `Principal` or `NotPrincipal` key.
    pub principal: PrincipalPattern,
}

/// `Principal` / `NotPrincipal` pattern on a parsed statement.
///
/// Identity policies never carry `Principal` — they inherit the
/// principal from the attaching identity. Resource policies (S3 bucket
/// policies in the initial Phase 2 rollout) use `Principal` to name
/// which users, accounts, or services the statement grants to.
#[derive(Debug, Clone)]
pub(crate) enum PrincipalPattern {
    /// Statement carried neither `Principal` nor `NotPrincipal`.
    /// Used by all identity-policy statements and by any resource-policy
    /// statement that forgets to name a principal (AWS rejects the
    /// latter at validation time, but the evaluator should not grant
    /// silently if it somehow makes it in).
    None,
    /// Statement carried `Principal` naming the accepted principals.
    /// A request is accepted iff it matches at least one entry.
    Principal(Vec<PrincipalRef>),
    /// Statement carried `NotPrincipal` naming the excluded principals.
    /// A statement with `NotPrincipal` applies to all callers **except**
    /// those matching any entry in the list — the inverse of `Principal`.
    /// If the caller matches ANY entry, the statement does NOT apply.
    /// If the caller matches NONE, the statement applies.
    ///
    /// An empty ref list (all entries were unrecognized principal types)
    /// causes the statement to be skipped with a debug log — we never
    /// silently grant by falling through to "matches everyone".
    NotPrincipal(Vec<PrincipalRef>),
}

/// A single principal reference parsed from a statement's `Principal`
/// key. AWS accepts several shapes; we implement the subset S3 bucket
/// policies actually use in practice.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum PrincipalRef {
    /// `"Principal": "*"` or `"Principal": {"AWS": "*"}`. Matches any
    /// authenticated principal (including cross-account). The
    /// public-bucket idiom.
    AnyAws,
    /// `"Principal": {"AWS": "arn:aws:iam::ACCOUNT:root"}`. Matches any
    /// principal whose `account_id` equals `ACCOUNT`.
    AwsAccountRoot(String),
    /// `"Principal": {"AWS": "arn:aws:iam::ACCOUNT:user/name"}` (or
    /// `role/name`, `assumed-role/...`, etc). Matches a principal
    /// whose ARN equals this string exactly.
    AwsArn(String),
    /// `"Principal": {"Service": "lambda.amazonaws.com"}`. Matches a
    /// principal whose ARN was produced by the named service
    /// assuming a service-linked role (approximated by the role name
    /// including the service host, matching how AWS builds
    /// service-linked role ARNs).
    Service(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Effect {
    Allow,
    Deny,
}

/// Action / NotAction patterns. `Allow` lists are positive matches;
/// `Deny` lists are negative matches (NotAction).
#[derive(Debug, Clone)]
pub(crate) enum ActionMatch {
    Action(Vec<String>),
    NotAction(Vec<String>),
}

/// Resource / NotResource patterns.
#[derive(Debug, Clone)]
pub(crate) enum ResourceMatch {
    Resource(Vec<String>),
    NotResource(Vec<String>),
    /// Statement omitted both `Resource` and `NotResource`. AWS treats
    /// this as "applies to all resources" only inside trust policies; for
    /// identity policies it's a validation error. We treat missing as
    /// wildcard-all to match how some Terraform-generated policies look
    /// in practice, but the evaluator never silently grants more than
    /// the policy text actually says — this maps to the same behavior
    /// as `Resource: ["*"]`.
    Implicit,
}

/// Parsed policy document — only the fields the evaluator needs. Any
/// statement that fails to parse (wrong shape, unknown effect, etc.) is
/// dropped with a warn-level log and the rest of the document is still
/// usable, matching how AWS behaves with invalid statements (the broken
/// statement is ignored, not the whole policy).
#[derive(Debug, Clone, Default)]
pub struct PolicyDocument {
    pub(crate) statements: Vec<ParsedStatement>,
}

impl PolicyDocument {
    /// Parse a policy document from its JSON string form. Returns an
    /// empty document on JSON errors so the caller can fall through to
    /// implicit-deny rather than panicking on malformed state.
    pub fn parse(json: &str) -> Self {
        let value: Value = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(e) => {
                tracing::warn!(error = %e, "failed to parse policy document JSON; ignoring");
                return Self::default();
            }
        };
        Self::from_value(&value)
    }

    /// Parse a policy document from a `serde_json::Value`. Used by both
    /// [`PolicyDocument::parse`] and tests that build inline `serde_json!`
    /// values.
    pub fn from_value(value: &Value) -> Self {
        let statements = match value.get("Statement") {
            Some(Value::Array(arr)) => arr.iter().filter_map(parse_statement).collect::<Vec<_>>(),
            Some(obj @ Value::Object(_)) => parse_statement(obj).into_iter().collect(),
            _ => Vec::new(),
        };
        Self { statements }
    }

    /// Number of parsed statements in this document. Used by tests as a
    /// proxy for "did this statement parse successfully?" without exposing
    /// the internal representation.
    pub fn statement_count(&self) -> usize {
        self.statements.len()
    }
}

fn parse_statement(value: &Value) -> Option<ParsedStatement> {
    let obj = value.as_object()?;
    let effect = match obj.get("Effect")?.as_str()? {
        "Allow" => Effect::Allow,
        "Deny" => Effect::Deny,
        other => {
            tracing::warn!(effect = other, "unknown Effect; ignoring statement");
            return None;
        }
    };
    let action = if let Some(a) = obj.get("Action") {
        ActionMatch::Action(coerce_string_list(a))
    } else if let Some(na) = obj.get("NotAction") {
        ActionMatch::NotAction(coerce_string_list(na))
    } else {
        tracing::warn!("statement has no Action or NotAction; ignoring");
        return None;
    };
    let resource = if let Some(r) = obj.get("Resource") {
        ResourceMatch::Resource(coerce_string_list(r))
    } else if let Some(nr) = obj.get("NotResource") {
        ResourceMatch::NotResource(coerce_string_list(nr))
    } else {
        ResourceMatch::Implicit
    };
    let condition = obj.get("Condition").map(CompiledCondition::parse);
    let principal = if let Some(np) = obj.get("NotPrincipal") {
        PrincipalPattern::NotPrincipal(parse_principal(np))
    } else if let Some(p) = obj.get("Principal") {
        PrincipalPattern::Principal(parse_principal(p))
    } else {
        PrincipalPattern::None
    };
    Some(ParsedStatement {
        effect,
        action,
        resource,
        condition,
        principal,
    })
}

/// Parse a `Principal` JSON value into the list of refs the evaluator
/// can match against a request principal.
///
/// AWS accepts any of:
/// - `"Principal": "*"`
/// - `"Principal": {"AWS": "*"}` or `{"AWS": ["..."]}`
/// - `"Principal": {"Service": "lambda.amazonaws.com"}` (string or array)
/// - `"Principal": {"Federated": "..."}` (unhandled — debug log, drop)
/// - `"Principal": {"CanonicalUser": "..."}` (unhandled — debug log, drop)
///
/// Unknown shapes fall through to an empty ref list, which the matcher
/// treats as "doesn't match" — never silently grant.
fn parse_principal(value: &Value) -> Vec<PrincipalRef> {
    let mut out = Vec::new();
    match value {
        Value::String(s) if s == "*" => out.push(PrincipalRef::AnyAws),
        Value::String(other) => {
            tracing::debug!(
                target: "fakecloud::iam::audit",
                principal = %other,
                "Principal string other than \"*\" is not a recognized shape; skipping"
            );
        }
        Value::Object(map) => {
            for (key, v) in map {
                match key.as_str() {
                    "AWS" => {
                        for s in coerce_string_list(v) {
                            out.push(classify_aws_principal(&s));
                        }
                    }
                    "Service" => {
                        for s in coerce_string_list(v) {
                            out.push(PrincipalRef::Service(s));
                        }
                    }
                    other => {
                        tracing::debug!(
                            target: "fakecloud::iam::audit",
                            principal_type = %other,
                            "Principal type not implemented in this rollout; skipping entry"
                        );
                    }
                }
            }
        }
        _ => {
            tracing::debug!(
                target: "fakecloud::iam::audit",
                "Principal has an unexpected JSON shape; skipping"
            );
        }
    }
    out
}

fn classify_aws_principal(s: &str) -> PrincipalRef {
    if s == "*" {
        return PrincipalRef::AnyAws;
    }
    // `arn:aws:iam::<account>:root` → account root
    if let Some(rest) = s.strip_prefix("arn:aws:iam::") {
        if let Some((account, tail)) = rest.split_once(':') {
            if tail == "root" && !account.is_empty() {
                return PrincipalRef::AwsAccountRoot(account.to_string());
            }
        }
    }
    // A bare 12-digit account ID is shorthand for `<account>:root`.
    if s.len() == 12 && s.chars().all(|c| c.is_ascii_digit()) {
        return PrincipalRef::AwsAccountRoot(s.to_string());
    }
    PrincipalRef::AwsArn(s.to_string())
}

/// Coerce a JSON value into a list of strings. AWS policy schema accepts
/// either a single string or an array of strings for `Action`/`Resource`.
/// Non-string entries are dropped.
fn coerce_string_list(value: &Value) -> Vec<String> {
    match value {
        Value::String(s) => vec![s.clone()],
        Value::Array(arr) => arr
            .iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .collect(),
        _ => Vec::new(),
    }
}

/// Evaluate a request against a set of policy documents.
///
/// Implements AWS's standard identity-policy evaluation logic for Phase 1
/// features only. See the module-level docstring for the exhaustive list
/// of what is and isn't covered.
///
/// # Algorithm
///
/// 1. Walk every statement in every policy.
/// 2. For each statement that matches the request's action *and* resource:
///    - If the statement has a `Condition` block, evaluate it against
///      [`EvalRequest::context`]; skip the statement if the condition
///      does not match.
///    - If `Effect: Deny` → return [`Decision::ExplicitDeny`] immediately.
///    - If `Effect: Allow` → record that we saw an allow.
/// 3. After all statements are scanned: return [`Decision::Allow`] if any
///    allow matched, otherwise [`Decision::ImplicitDeny`].
pub fn evaluate(policies: &[PolicyDocument], request: &EvalRequest<'_>) -> Decision {
    evaluate_with_gates(policies, None, None, request)
}

/// Evaluate `request` against a principal's identity policies plus
/// optional permission-boundary, session-policy, and SCP layers.
///
/// Intersection semantics (applies identically to every gate):
///
/// - `boundary = None` / `session = None` / `scps = None` → the layer
///   is absent and does not gate the decision (pass-through).
/// - `Some(&[])` → the layer is present but empty, which evaluates to
///   `ImplicitDeny` and therefore denies the request. This is how
///   dangling boundary ARNs, empty session policies, and empty SCP
///   sets (e.g. every policy detached from a target) are represented.
/// - Any layer returning `ExplicitDeny` wins immediately (Deny
///   precedence applies across layers, not just within one).
/// - Otherwise the request is allowed iff **every present layer**
///   evaluates to `Allow`. A layer with `ImplicitDeny` caps the
///   intersection to `ImplicitDeny`.
///
/// When `scps` is `Some`, each document in the slice is treated as a
/// separate gate that must allow — the caller already assembled the
/// ordered list (root OU first, account-direct last) via
/// [`crate::scp_resolver`] or equivalent.
pub fn evaluate_with_gates(
    identity: &[PolicyDocument],
    boundary: Option<&[PolicyDocument]>,
    session: Option<&[PolicyDocument]>,
    request: &EvalRequest<'_>,
) -> Decision {
    evaluate_with_gates_and_scps(identity, boundary, session, None, request)
}

/// Full-chain variant of [`evaluate_with_gates`] that also applies an
/// SCP ceiling. See the top-of-module docs for the intersection
/// semantics. Batch 4 added this alongside the 4-arg form so existing
/// callers (and tests) don't have to thread an extra `None` through
/// every evaluation site.
pub fn evaluate_with_gates_and_scps(
    identity: &[PolicyDocument],
    boundary: Option<&[PolicyDocument]>,
    session: Option<&[PolicyDocument]>,
    scps: Option<&[PolicyDocument]>,
    request: &EvalRequest<'_>,
) -> Decision {
    let identity_decision = evaluate_inner(identity, request, false);
    intersect_layers(identity_decision, boundary, session, scps, request)
}

/// Combine an already-computed identity-side decision with the optional
/// boundary, session-policy, and SCP layers. Factored out so the
/// resource-policy variant can apply the same intersection to the
/// identity side before OR/ANDing with the resource-policy side.
fn intersect_layers(
    identity_decision: Decision,
    boundary: Option<&[PolicyDocument]>,
    session: Option<&[PolicyDocument]>,
    scps: Option<&[PolicyDocument]>,
    request: &EvalRequest<'_>,
) -> Decision {
    if matches!(identity_decision, Decision::ExplicitDeny) {
        return Decision::ExplicitDeny;
    }
    // SCP gate sits at the top of the ceiling stack. Each SCP
    // document is a separate layer that must allow (AWS intersects
    // SCPs across the OU path). A single explicit Deny in any SCP
    // short-circuits the evaluation.
    let scp_decision = scps.map(|docs| evaluate_scp_chain(docs, request));
    if matches!(scp_decision, Some(Decision::ExplicitDeny)) {
        if let Some(scps_slice) = scps {
            tracing::debug!(
                target: "fakecloud::iam::audit",
                action = %request.action,
                principal_arn = %request.principal.arn,
                scp_count = scps_slice.len(),
                "SCP ceiling produced ExplicitDeny"
            );
        }
        return Decision::ExplicitDeny;
    }
    let boundary_decision = boundary.map(|policies| evaluate_inner(policies, request, false));
    if matches!(boundary_decision, Some(Decision::ExplicitDeny)) {
        return Decision::ExplicitDeny;
    }
    let session_decision = session.map(|policies| evaluate_inner(policies, request, false));
    if matches!(session_decision, Some(Decision::ExplicitDeny)) {
        return Decision::ExplicitDeny;
    }
    // Intersection: every present layer must allow.
    let identity_allows = matches!(identity_decision, Decision::Allow);
    let boundary_allows = boundary_decision
        .map(|d| matches!(d, Decision::Allow))
        .unwrap_or(true);
    let session_allows = session_decision
        .map(|d| matches!(d, Decision::Allow))
        .unwrap_or(true);
    let scp_allows = scp_decision
        .map(|d| matches!(d, Decision::Allow))
        .unwrap_or(true);
    if identity_allows && boundary_allows && session_allows && scp_allows {
        Decision::Allow
    } else {
        if scps.is_some() && !scp_allows {
            tracing::debug!(
                target: "fakecloud::iam::audit",
                action = %request.action,
                principal_arn = %request.principal.arn,
                "SCP ceiling did not allow action; capped to ImplicitDeny"
            );
        }
        Decision::ImplicitDeny
    }
}

/// Walk an ordered SCP chain (root OU -> descendant OUs -> account)
/// and intersect the per-document decisions. Each document is its own
/// gate: an explicit Deny anywhere wins, otherwise every document
/// must evaluate to Allow for the chain to allow.
fn evaluate_scp_chain(scps: &[PolicyDocument], request: &EvalRequest<'_>) -> Decision {
    if scps.is_empty() {
        // `Some(&[])` means the org exists and applies but no SCPs
        // are attached up the chain. Preserve AWS's deny-by-default
        // ceiling semantics: nothing allowed.
        return Decision::ImplicitDeny;
    }
    let mut all_allow = true;
    for doc in scps {
        match evaluate_inner(std::slice::from_ref(doc), request, false) {
            Decision::ExplicitDeny => return Decision::ExplicitDeny,
            Decision::Allow => {}
            Decision::ImplicitDeny => all_allow = false,
        }
    }
    if all_allow {
        Decision::Allow
    } else {
        Decision::ImplicitDeny
    }
}

/// Evaluate `request` against the principal's identity policies and an
/// optional resource-based policy, combining the two with AWS's
/// cross-account semantics.
///
/// - Either side returning an explicit `Deny` wins immediately.
/// - Same-account (`principal.account_id == resource_account_id`):
///   the request is allowed if identity OR resource grants it.
/// - Cross-account: the request is allowed only if identity AND
///   resource both grant it.
///
/// `resource_account_id` is the 12-digit account that owns the target
/// resource. For S3 bucket policies, dispatch parses this from the
/// resource ARN; S3 ARNs have an empty account field, so the caller
/// is expected to fall back to the server's configured account ID in
/// that case (#381 multi-account alignment).
pub fn evaluate_with_resource_policy(
    identity_policies: &[PolicyDocument],
    resource_policy: Option<&PolicyDocument>,
    request: &EvalRequest<'_>,
    resource_account_id: &str,
) -> Decision {
    evaluate_with_resource_policy_and_gates(
        identity_policies,
        None,
        None,
        resource_policy,
        request,
        resource_account_id,
    )
}

/// Resource-policy variant of [`evaluate_with_gates`].
///
/// The boundary and session policies gate the **identity side** only —
/// they never apply to the resource-policy branch. Rationale: the
/// resource policy is evaluated in the resource's account, and a
/// caller's permission boundary has no authority in another account
/// (this is also how AWS describes it). That shows up here as two
/// separate combinators:
///
/// - Same-account: `(identity ∩ boundary ∩ session) OR resource`.
///   Boundary/session cap the identity side, but a resource-policy
///   grant in the same account still allows the request on its own.
/// - Cross-account: `(identity ∩ boundary ∩ session) AND resource`.
///   Both sides must allow; boundary/session still cap the identity
///   side.
///
/// Explicit Deny from any layer — identity, boundary, session, or
/// resource — wins immediately.
pub fn evaluate_with_resource_policy_and_gates(
    identity_policies: &[PolicyDocument],
    boundary: Option<&[PolicyDocument]>,
    session: Option<&[PolicyDocument]>,
    resource_policy: Option<&PolicyDocument>,
    request: &EvalRequest<'_>,
    resource_account_id: &str,
) -> Decision {
    evaluate_with_resource_policy_and_gates_and_scps(
        identity_policies,
        boundary,
        session,
        None,
        resource_policy,
        request,
        resource_account_id,
    )
}

/// Full-chain variant of
/// [`evaluate_with_resource_policy_and_gates`] that also applies an
/// SCP ceiling on the identity side. SCPs never apply to the
/// resource-policy branch — AWS evaluates the resource policy in the
/// resource's account, and the caller's SCPs have no authority there.
pub fn evaluate_with_resource_policy_and_gates_and_scps(
    identity_policies: &[PolicyDocument],
    boundary: Option<&[PolicyDocument]>,
    session: Option<&[PolicyDocument]>,
    scps: Option<&[PolicyDocument]>,
    resource_policy: Option<&PolicyDocument>,
    request: &EvalRequest<'_>,
    resource_account_id: &str,
) -> Decision {
    let identity_raw = evaluate_inner(identity_policies, request, false);
    if matches!(identity_raw, Decision::ExplicitDeny) {
        return Decision::ExplicitDeny;
    }
    // Apply boundary, session, and SCP gates to the identity side.
    // SCPs only apply to the identity side (never to the resource
    // policy branch) — they are the caller-account ceiling, and AWS
    // evaluates the resource policy in the resource's account.
    let identity_gated = intersect_layers(identity_raw, boundary, session, scps, request);
    if matches!(identity_gated, Decision::ExplicitDeny) {
        return Decision::ExplicitDeny;
    }

    let same_account = request.principal.account_id == resource_account_id;
    // Same-account with no resource policy: preserve the identity-only
    // path so rollouts without a bucket/topic policy behave as before.
    if resource_policy.is_none() && same_account {
        return identity_gated;
    }
    let resource = match resource_policy {
        Some(policy) => evaluate_inner(std::slice::from_ref(policy), request, true),
        None => Decision::ImplicitDeny,
    };
    if matches!(resource, Decision::ExplicitDeny) {
        return Decision::ExplicitDeny;
    }
    let identity_allows = matches!(identity_gated, Decision::Allow);
    let resource_allows = matches!(resource, Decision::Allow);
    let allowed = if same_account {
        identity_allows || resource_allows
    } else {
        identity_allows && resource_allows
    };
    if allowed {
        Decision::Allow
    } else {
        Decision::ImplicitDeny
    }
}

fn evaluate_inner(
    policies: &[PolicyDocument],
    request: &EvalRequest<'_>,
    is_resource_policy: bool,
) -> Decision {
    let mut allowed = false;
    for policy in policies {
        for statement in &policy.statements {
            // Principal / NotPrincipal gate. Identity policies never
            // carry these keys; resource policies must, and a
            // statement without a matching Principal does not apply.
            match &statement.principal {
                PrincipalPattern::None => {
                    if is_resource_policy {
                        // Resource-policy statement with no Principal
                        // does not apply — AWS treats this as a
                        // validation error and we will not silently
                        // grant.
                        tracing::debug!(
                            target: "fakecloud::iam::audit",
                            action = %request.action,
                            "resource policy statement has no Principal; skipping"
                        );
                        continue;
                    }
                }
                PrincipalPattern::Principal(refs) => {
                    if !principal_matches(refs, request.principal) {
                        continue;
                    }
                }
                PrincipalPattern::NotPrincipal(refs) => {
                    if refs.is_empty() {
                        tracing::debug!(
                            target: "fakecloud::iam::audit",
                            action = %request.action,
                            "NotPrincipal has no recognized principal types; statement does not apply"
                        );
                        continue;
                    }
                    // NotPrincipal: statement applies when caller does NOT match any entry.
                    if principal_matches(refs, request.principal) {
                        continue;
                    }
                }
            }
            if !action_matches(&statement.action, &request.action) {
                continue;
            }
            if !resource_matches(&statement.resource, &request.resource) {
                continue;
            }
            if let Some(condition) = &statement.condition {
                if !condition.matches(&request.context) {
                    tracing::debug!(
                        target: "fakecloud::iam::audit",
                        action = %request.action,
                        "condition did not match; statement does not apply"
                    );
                    continue;
                }
            }
            match statement.effect {
                Effect::Deny => return Decision::ExplicitDeny,
                Effect::Allow => allowed = true,
            }
        }
    }
    if allowed {
        Decision::Allow
    } else {
        Decision::ImplicitDeny
    }
}

/// Check whether any entry in a parsed `Principal` list matches the
/// calling principal. An empty list never matches — that's how we
/// keep unimplemented principal types (`Federated`, `CanonicalUser`)
/// from silently granting.
fn principal_matches(refs: &[PrincipalRef], principal: &Principal) -> bool {
    refs.iter().any(|r| match r {
        PrincipalRef::AnyAws => true,
        PrincipalRef::AwsAccountRoot(account) => &principal.account_id == account,
        PrincipalRef::AwsArn(arn) => &principal.arn == arn,
        PrincipalRef::Service(service) => principal_is_service(principal, service),
    })
}

/// Approximate match for a `"Service"` principal. AWS represents a
/// request made by a service (e.g. Lambda invoking something via a
/// service-linked role) as an assumed-role principal whose role ARN
/// contains the service host. We match conservatively: the principal
/// must be an `AssumedRole` whose ARN contains the literal service
/// host string. False matches are avoided because unrelated role
/// names would have to happen to contain `lambda.amazonaws.com` —
/// unlikely in practice and never silently grant to user principals.
fn principal_is_service(principal: &Principal, service: &str) -> bool {
    matches!(principal.principal_type, PrincipalType::AssumedRole)
        && principal.arn.contains(service)
}

fn action_matches(action: &ActionMatch, request_action: &str) -> bool {
    match action {
        ActionMatch::Action(patterns) => patterns
            .iter()
            .any(|p| iam_glob_match(p, request_action, true)),
        ActionMatch::NotAction(patterns) => patterns
            .iter()
            .all(|p| !iam_glob_match(p, request_action, true)),
    }
}

fn resource_matches(resource: &ResourceMatch, request_resource: &str) -> bool {
    match resource {
        ResourceMatch::Resource(patterns) => patterns
            .iter()
            .any(|p| iam_glob_match(p, request_resource, false)),
        ResourceMatch::NotResource(patterns) => patterns
            .iter()
            .all(|p| !iam_glob_match(p, request_resource, false)),
        ResourceMatch::Implicit => true,
    }
}

/// IAM-style glob match supporting `*` (any sequence) and `?` (single
/// character). When `case_insensitive_service_prefix` is true and the
/// pattern looks like an action (`service:Action`), the service prefix is
/// matched case-insensitively while the action name is matched as-is —
/// matches how AWS evaluates Action patterns.
fn iam_glob_match(pattern: &str, value: &str, case_insensitive_service_prefix: bool) -> bool {
    if case_insensitive_service_prefix {
        if let (Some((p_svc, p_act)), Some((v_svc, v_act))) =
            (pattern.split_once(':'), value.split_once(':'))
        {
            if !glob_match(&p_svc.to_ascii_lowercase(), &v_svc.to_ascii_lowercase()) {
                return false;
            }
            return glob_match(p_act, v_act);
        }
    }
    glob_match(pattern, value)
}

/// Plain glob matcher with `*` (zero or more) and `?` (exactly one).
/// Iterative two-pointer implementation — runs in `O(pattern.len() *
/// value.len())` worst case, no backtracking explosions.
fn glob_match(pattern: &str, value: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let v: Vec<char> = value.chars().collect();
    let mut pi = 0usize;
    let mut vi = 0usize;
    let mut star: Option<usize> = None;
    let mut star_v: usize = 0;
    while vi < v.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == v[vi]) {
            pi += 1;
            vi += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            star_v = vi;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            star_v += 1;
            vi = star_v;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// Collect every identity policy that should be considered when
/// evaluating a request from `principal`.
///
/// Phase 1 walks identity policies only (user inline + managed, group
/// inline + managed via membership, role inline + managed). Resource
/// policies, permission boundaries, and SCPs are not consulted —
/// see the module-level scope notes.
///
/// The returned vector is the **deduplicated** set of policy documents,
/// parsed and ready to feed into [`evaluate`]. Unknown managed policy
/// ARNs are skipped with a debug log.
pub fn collect_identity_policies(state: &IamState, principal: &Principal) -> Vec<PolicyDocument> {
    let mut docs = Vec::new();
    let mut seen_managed: HashSet<String> = HashSet::new();
    match principal.principal_type {
        PrincipalType::User => {
            if let Some(user_name) = user_name_from_arn(&principal.arn) {
                collect_user_policies(state, user_name, &mut docs, &mut seen_managed);
            }
        }
        PrincipalType::AssumedRole => {
            if let Some(role_name) = role_name_from_assumed_role_arn(&principal.arn) {
                collect_role_policies(state, role_name, &mut docs, &mut seen_managed);
            }
        }
        PrincipalType::Root => {
            // Root bypasses evaluation; the caller (dispatch) should
            // short-circuit via `Principal::is_root` before reaching here.
            // Returning an empty vec means an explicit `Allow` is required,
            // which is the safe default if a caller forgets to bypass.
        }
        PrincipalType::FederatedUser | PrincipalType::Unknown => {
            // No identity-policy story for these in Phase 1.
        }
    }
    docs
}

fn collect_user_policies(
    state: &IamState,
    user_name: &str,
    docs: &mut Vec<PolicyDocument>,
    seen_managed: &mut HashSet<String>,
) {
    if let Some(inline) = state.user_inline_policies.get(user_name) {
        for doc in inline.values() {
            docs.push(PolicyDocument::parse(doc));
        }
    }
    if let Some(arns) = state.user_policies.get(user_name) {
        for arn in arns {
            if !seen_managed.insert(arn.clone()) {
                continue;
            }
            if let Some(doc) = managed_policy_default_document(state, arn) {
                docs.push(PolicyDocument::parse(&doc));
            }
        }
    }
    // Group memberships: walk every group whose members include the user.
    for (group_name, group) in &state.groups {
        if !group.members.iter().any(|m| m == user_name) {
            continue;
        }
        for doc in group.inline_policies.values() {
            docs.push(PolicyDocument::parse(doc));
        }
        for arn in &group.attached_policies {
            if !seen_managed.insert(arn.clone()) {
                continue;
            }
            if let Some(doc) = managed_policy_default_document(state, arn) {
                docs.push(PolicyDocument::parse(&doc));
            }
        }
        let _ = group_name;
    }
}

fn collect_role_policies(
    state: &IamState,
    role_name: &str,
    docs: &mut Vec<PolicyDocument>,
    seen_managed: &mut HashSet<String>,
) {
    if let Some(inline) = state.role_inline_policies.get(role_name) {
        for doc in inline.values() {
            docs.push(PolicyDocument::parse(doc));
        }
    }
    if let Some(arns) = state.role_policies.get(role_name) {
        for arn in arns {
            if !seen_managed.insert(arn.clone()) {
                continue;
            }
            if let Some(doc) = managed_policy_default_document(state, arn) {
                docs.push(PolicyDocument::parse(&doc));
            }
        }
    }
}

/// Look up the permission-boundary policy document attached to
/// `principal`, if any.
///
/// Returns:
/// - `None` — the principal has no boundary set, OR the principal is
///   exempt from boundary evaluation (account root, service-linked
///   role, or an unhandled principal type like a federated user). The
///   caller should treat this as "boundary layer absent"
///   (pass-through) when calling [`evaluate_with_gates`].
/// - `Some(vec![])` — a boundary ARN is set but does not resolve to
///   a known managed policy (dangling ARN, or the user/role was found
///   but its boundary points at a deleted policy). The caller must
///   treat this as **deny-all** — matching AWS's behavior when a
///   permission boundary is deleted, the principal can no longer
///   perform any action until the boundary is re-attached or removed.
///   Emits a `fakecloud::iam::audit` debug log.
/// - `Some(vec![doc])` — the boundary resolves to a policy document.
///
/// Service-linked roles are detected by the `AWSServiceRoleFor` name
/// prefix (AWS rejects attaching boundaries to SLRs at the API layer
/// anyway; this is defense-in-depth).
pub fn collect_boundary_policies(
    state: &IamState,
    principal: &Principal,
) -> Option<Vec<PolicyDocument>> {
    if principal.is_root() {
        return None;
    }
    let boundary_arn = match principal.principal_type {
        PrincipalType::User => {
            let user_name = user_name_from_arn(&principal.arn)?;
            let user = state.users.get(user_name)?;
            user.permissions_boundary.clone()?
        }
        PrincipalType::AssumedRole => {
            let role_name = role_name_from_assumed_role_arn(&principal.arn)?;
            if role_name.starts_with("AWSServiceRoleFor") {
                // Service-linked roles are exempt from boundary
                // evaluation — AWS rejects attaching one at the API
                // layer, but if state has been force-injected we
                // still bypass to match documented semantics.
                return None;
            }
            let role = state.roles.get(role_name)?;
            role.permissions_boundary.clone()?
        }
        // No boundary story for root / federated / unknown.
        _ => return None,
    };
    match managed_policy_default_document(state, &boundary_arn) {
        Some(doc) => Some(vec![PolicyDocument::parse(&doc)]),
        None => {
            tracing::debug!(
                target: "fakecloud::iam::audit",
                principal_arn = %principal.arn,
                boundary_arn = %boundary_arn,
                "permission boundary ARN does not resolve to a known managed policy; denying all actions"
            );
            Some(Vec::new())
        }
    }
}

fn managed_policy_default_document(state: &IamState, arn: &str) -> Option<String> {
    let policy = state.policies.get(arn)?;
    policy
        .versions
        .iter()
        .find(|v| v.is_default)
        .or_else(|| policy.versions.first())
        .map(|v| v.document.clone())
}

/// Extract the bare `user_name` component from an IAM user ARN.
///
/// IAM users can be created with a non-default path (e.g. `/engineering/`),
/// which produces ARNs of the form
/// `arn:aws:iam::123456789012:user/engineering/alice`. `IamState` indexes
/// users by the bare name (`alice`), so returning the full
/// `engineering/alice` would silently miss the user and make
/// `collect_user_policies` return an empty set — the evaluator would then
/// issue an incorrect implicit deny for every pathed user.
/// (Identified by cubic on PR #392.)
fn user_name_from_arn(arn: &str) -> Option<&str> {
    let after = arn.rsplit_once(":user/").map(|(_, name)| name)?;
    // Bare name is the last segment; the rest is the path.
    Some(after.rsplit('/').next().unwrap_or(after))
}

fn role_name_from_assumed_role_arn(arn: &str) -> Option<&str> {
    // `arn:aws:sts::<account>:assumed-role/<role-name>/<session>`
    let after = arn.rsplit_once(":assumed-role/")?.1;
    Some(after.split('/').next().unwrap_or(after))
}

#[cfg(test)]
#[allow(clippy::cloned_ref_to_slice_refs)]
mod tests {
    use super::*;
    use fakecloud_aws::arn::Arn;
    use serde_json::json;

    fn principal_user(arn: &str) -> Principal {
        Principal {
            arn: arn.to_string(),
            user_id: "AIDA".into(),
            account_id: "123456789012".into(),
            principal_type: PrincipalType::User,
            source_identity: None,
            tags: None,
        }
    }

    fn req<'a>(principal: &'a Principal, action: &str, resource: &str) -> EvalRequest<'a> {
        EvalRequest {
            principal,
            action: action.to_string(),
            resource: resource.to_string(),
            context: RequestContext::default(),
        }
    }

    fn doc(json: serde_json::Value) -> PolicyDocument {
        PolicyDocument::from_value(&json)
    }

    // --- glob_match -----------------------------------------------------

    #[test]
    fn glob_literal_match() {
        assert!(glob_match("foo", "foo"));
        assert!(!glob_match("foo", "bar"));
    }

    #[test]
    fn glob_star_matches_any() {
        assert!(glob_match("*", "foo"));
        assert!(glob_match("*", ""));
        assert!(glob_match("foo*", "foobar"));
        assert!(glob_match("*bar", "foobar"));
        assert!(glob_match("f*r", "foobar"));
        assert!(!glob_match("foo*", "fo"));
    }

    #[test]
    fn glob_question_mark_matches_one() {
        assert!(glob_match("f?o", "foo"));
        assert!(!glob_match("f?o", "fo"));
        assert!(!glob_match("f?o", "foo!"));
    }

    #[test]
    fn glob_no_backtracking_explosion() {
        // Pattern that would blow up a naive recursive matcher.
        assert!(!glob_match("a*a*a*a*a*b", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"));
    }

    // --- iam_glob_match (action specifics) ------------------------------

    #[test]
    fn iam_action_service_prefix_is_case_insensitive() {
        assert!(iam_glob_match("S3:GetObject", "s3:GetObject", true));
        assert!(iam_glob_match("s3:GetObject", "S3:GetObject", true));
    }

    #[test]
    fn iam_action_name_is_case_sensitive() {
        // Action name is case-sensitive in AWS.
        assert!(!iam_glob_match("s3:getobject", "s3:GetObject", true));
        assert!(iam_glob_match("s3:GetObject", "s3:GetObject", true));
    }

    #[test]
    fn iam_action_supports_wildcards() {
        assert!(iam_glob_match("s3:Get*", "s3:GetObject", true));
        assert!(iam_glob_match("s3:*", "s3:DeleteObject", true));
        assert!(iam_glob_match("*", "s3:GetObject", true));
        assert!(!iam_glob_match("s3:Get*", "s3:PutObject", true));
    }

    // --- evaluate -------------------------------------------------------

    #[test]
    fn empty_policy_set_is_implicit_deny() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        assert_eq!(
            evaluate(&[], &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key")),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn allow_with_matching_action_and_resource() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = doc(json!({
            "Version": "2012-10-17",
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/key"
            }]
        }));
        assert_eq!(
            evaluate(
                &[policy],
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::Allow
        );
    }

    #[test]
    fn deny_takes_precedence_over_allow() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let allow = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        }));
        let deny = doc(json!({
            "Statement": [{
                "Effect": "Deny",
                "Action": "s3:DeleteObject",
                "Resource": "*"
            }]
        }));
        assert_eq!(
            evaluate(
                &[allow.clone(), deny.clone()],
                &req(&p, "s3:DeleteObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::ExplicitDeny
        );
        // Order doesn't matter — Deny still wins when listed first.
        assert_eq!(
            evaluate(
                &[deny, allow],
                &req(&p, "s3:DeleteObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::ExplicitDeny
        );
    }

    #[test]
    fn allow_with_wrong_action_is_implicit_deny() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        }));
        assert_eq!(
            evaluate(
                &[policy],
                &req(&p, "s3:DeleteObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn allow_with_wrong_resource_is_implicit_deny() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::other-bucket/*"
            }]
        }));
        assert_eq!(
            evaluate(
                &[policy],
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn resource_wildcard_matches_arn_path() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/*"
            }]
        }));
        assert_eq!(
            evaluate(
                &[policy],
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/path/to/key")
            ),
            Decision::Allow
        );
    }

    #[test]
    fn not_action_excludes_listed_actions() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "NotAction": "s3:DeleteObject",
                "Resource": "*"
            }]
        }));
        // Allowed because GetObject is not in NotAction.
        assert_eq!(
            evaluate(
                &[policy.clone()],
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::Allow
        );
        // Implicit-denied because DeleteObject is in NotAction (no allow matches).
        assert_eq!(
            evaluate(
                &[policy],
                &req(&p, "s3:DeleteObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn not_resource_excludes_listed_resources() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "NotResource": "arn:aws:s3:::secret-bucket/*"
            }]
        }));
        assert_eq!(
            evaluate(
                &[policy.clone()],
                &req(&p, "s3:GetObject", "arn:aws:s3:::public-bucket/key")
            ),
            Decision::Allow
        );
        assert_eq!(
            evaluate(
                &[policy],
                &req(&p, "s3:GetObject", "arn:aws:s3:::secret-bucket/key")
            ),
            Decision::ImplicitDeny
        );
    }

    fn req_with_ctx<'a>(
        principal: &'a Principal,
        action: &str,
        resource: &str,
        context: RequestContext,
    ) -> EvalRequest<'a> {
        EvalRequest {
            principal,
            action: action.to_string(),
            resource: resource.to_string(),
            context,
        }
    }

    fn ctx_alice() -> RequestContext {
        RequestContext {
            aws_username: Some("alice".into()),
            aws_principal_arn: Some("arn:aws:iam::123456789012:user/alice".into()),
            aws_principal_account: Some("123456789012".into()),
            aws_principal_type: Some("User".into()),
            aws_userid: Some("AIDA".into()),
            ..Default::default()
        }
    }

    #[test]
    fn condition_string_equals_username_allows_match() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": { "StringEquals": { "aws:username": "alice" } }
            }]
        }));
        assert_eq!(
            evaluate(
                &[policy],
                &req_with_ctx(&p, "s3:GetObject", "arn:aws:s3:::bucket/key", ctx_alice())
            ),
            Decision::Allow
        );
    }

    #[test]
    fn condition_string_equals_username_denies_mismatch() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": { "StringEquals": { "aws:username": "bob" } }
            }]
        }));
        assert_eq!(
            evaluate(
                &[policy],
                &req_with_ctx(&p, "s3:GetObject", "arn:aws:s3:::bucket/key", ctx_alice())
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn deny_with_condition_fires_when_condition_matches() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        // Deny-MFA-absent + unconditional Allow => the Deny only fires
        // when the SecureTransport context value is false. Deny precedence
        // beats the unconditional Allow.
        let policy = doc(json!({
            "Statement": [
                {
                    "Effect": "Deny",
                    "Action": "*",
                    "Resource": "*",
                    "Condition": { "Bool": { "aws:SecureTransport": "false" } }
                },
                {
                    "Effect": "Allow",
                    "Action": "s3:GetObject",
                    "Resource": "*"
                }
            ]
        }));
        let mut ctx = ctx_alice();
        ctx.aws_secure_transport = Some(false);
        assert_eq!(
            evaluate(
                &[policy.clone()],
                &req_with_ctx(&p, "s3:GetObject", "arn:aws:s3:::bucket/key", ctx)
            ),
            Decision::ExplicitDeny
        );
        // When the request IS secure, the conditional Deny should not
        // fire and the Allow wins.
        let mut ctx_secure = ctx_alice();
        ctx_secure.aws_secure_transport = Some(true);
        assert_eq!(
            evaluate(
                &[policy],
                &req_with_ctx(&p, "s3:GetObject", "arn:aws:s3:::bucket/key", ctx_secure)
            ),
            Decision::Allow
        );
    }

    #[test]
    fn condition_ip_address_allows_within_cidr() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": { "IpAddress": { "aws:SourceIp": "10.0.0.0/24" } }
            }]
        }));
        let mut ctx = ctx_alice();
        ctx.aws_source_ip = Some("10.0.0.17".parse().unwrap());
        assert_eq!(
            evaluate(
                &[policy.clone()],
                &req_with_ctx(&p, "s3:GetObject", "arn:aws:s3:::bucket/key", ctx)
            ),
            Decision::Allow
        );
        let mut wrong = ctx_alice();
        wrong.aws_source_ip = Some("192.168.1.1".parse().unwrap());
        assert_eq!(
            evaluate(
                &[policy],
                &req_with_ctx(&p, "s3:GetObject", "arn:aws:s3:::bucket/key", wrong)
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn condition_date_less_than_blocks_expired() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {
                    "DateLessThan": { "aws:CurrentTime": "2020-01-01T00:00:00Z" }
                }
            }]
        }));
        let mut ctx = ctx_alice();
        ctx.aws_current_time = Some(
            chrono::DateTime::parse_from_rfc3339("2024-06-15T12:00:00Z")
                .unwrap()
                .with_timezone(&chrono::Utc),
        );
        assert_eq!(
            evaluate(
                &[policy],
                &req_with_ctx(&p, "s3:GetObject", "arn:aws:s3:::bucket/key", ctx)
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn condition_missing_key_without_if_exists_denies() {
        // Context has no SourceIp; the IpAddress operator should
        // safe-fail, making the statement not apply.
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": { "IpAddress": { "aws:SourceIp": "10.0.0.0/8" } }
            }]
        }));
        assert_eq!(
            evaluate(
                &[policy],
                &req_with_ctx(&p, "s3:GetObject", "arn:aws:s3:::bucket/key", ctx_alice())
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn condition_if_exists_passes_on_missing_key() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "IpAddressIfExists": { "aws:SourceIp": "10.0.0.0/8" }
                }
            }]
        }));
        // SourceIp not populated; IfExists => condition passes.
        assert_eq!(
            evaluate(
                &[policy],
                &req_with_ctx(&p, "s3:GetObject", "arn:aws:s3:::bucket/key", ctx_alice())
            ),
            Decision::Allow
        );
    }

    #[test]
    fn condition_multiple_operators_all_must_match() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": {
                    "StringEquals": { "aws:username": "alice" },
                    "IpAddress":    { "aws:SourceIp": "10.0.0.0/24" }
                }
            }]
        }));
        let mut ctx = ctx_alice();
        ctx.aws_source_ip = Some("10.0.0.1".parse().unwrap());
        assert_eq!(
            evaluate(
                &[policy.clone()],
                &req_with_ctx(&p, "s3:GetObject", "arn:aws:s3:::bucket/key", ctx)
            ),
            Decision::Allow
        );
        let mut wrong_ip = ctx_alice();
        wrong_ip.aws_source_ip = Some("192.168.1.1".parse().unwrap());
        assert_eq!(
            evaluate(
                &[policy],
                &req_with_ctx(&p, "s3:GetObject", "arn:aws:s3:::bucket/key", wrong_ip)
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn condition_unknown_operator_fails_closed() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*",
                "Condition": { "NotARealOperator": { "aws:username": "alice" } }
            }]
        }));
        assert_eq!(
            evaluate(
                &[policy],
                &req_with_ctx(&p, "s3:GetObject", "arn:aws:s3:::bucket/key", ctx_alice())
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn array_action_matches_any_entry() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": ["s3:GetObject", "s3:PutObject"],
                "Resource": "*"
            }]
        }));
        assert_eq!(
            evaluate(
                &[policy.clone()],
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::Allow
        );
        assert_eq!(
            evaluate(
                &[policy],
                &req(&p, "s3:PutObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::Allow
        );
    }

    #[test]
    fn statement_without_effect_is_dropped() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = doc(json!({
            "Statement": [
                { "Action": "s3:GetObject", "Resource": "*" },
                { "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*" }
            ]
        }));
        // The dropped statement doesn't contribute, but the second
        // valid one still grants the request.
        assert_eq!(policy.statement_count(), 1);
        assert_eq!(
            evaluate(
                &[policy],
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::Allow
        );
    }

    #[test]
    fn statement_without_action_is_dropped() {
        let policy = doc(json!({
            "Statement": [{ "Effect": "Allow", "Resource": "*" }]
        }));
        assert_eq!(policy.statement_count(), 0);
    }

    #[test]
    fn implicit_resource_acts_like_wildcard() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = doc(json!({
            "Statement": [{ "Effect": "Allow", "Action": "s3:GetObject" }]
        }));
        assert_eq!(
            evaluate(
                &[policy],
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::Allow
        );
    }

    #[test]
    fn malformed_policy_json_is_implicit_deny() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = PolicyDocument::parse("{ this is not valid json");
        assert_eq!(policy.statement_count(), 0);
        assert_eq!(
            evaluate(
                &[policy],
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn deny_short_circuits_after_match() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let policy = doc(json!({
            "Statement": [
                { "Effect": "Deny", "Action": "*", "Resource": "*" },
                { "Effect": "Allow", "Action": "s3:GetObject", "Resource": "*" }
            ]
        }));
        assert_eq!(
            evaluate(
                &[policy],
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::ExplicitDeny
        );
    }

    #[test]
    fn user_name_from_arn_strips_iam_path() {
        // Default path — bare user name.
        assert_eq!(
            user_name_from_arn("arn:aws:iam::123456789012:user/alice"),
            Some("alice")
        );
        // Non-default path — must return the bare name, not
        // `engineering/alice`. IamState indexes users by the bare name,
        // so returning the path would silently drop pathed users from
        // policy evaluation (identified by cubic on PR #392).
        assert_eq!(
            user_name_from_arn("arn:aws:iam::123456789012:user/engineering/alice"),
            Some("alice")
        );
        assert_eq!(
            user_name_from_arn("arn:aws:iam::123456789012:user/path/to/alice"),
            Some("alice")
        );
        assert_eq!(user_name_from_arn("arn:aws:iam::123456789012:role/r"), None);
    }

    #[test]
    fn collect_identity_policies_resolves_pathed_user() {
        // Regression guard for the pathed-user bug: a user created under
        // `/engineering/` must still have their inline policies picked up
        // by the evaluator.
        use crate::state::IamUser;
        use chrono::Utc;
        let mut state = IamState::new("123456789012");
        state.users.insert(
            "alice".to_string(),
            IamUser {
                user_name: "alice".into(),
                user_id: "AIDAALICE".into(),
                arn: "arn:aws:iam::123456789012:user/engineering/alice".into(),
                path: "/engineering/".into(),
                created_at: Utc::now(),
                tags: Vec::new(),
                permissions_boundary: None,
            },
        );
        let mut inline = std::collections::BTreeMap::new();
        inline.insert(
            "AllowGet".to_string(),
            r#"{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#
                .to_string(),
        );
        state
            .user_inline_policies
            .insert("alice".to_string(), inline);

        let principal = Principal {
            arn: "arn:aws:iam::123456789012:user/engineering/alice".to_string(),
            user_id: "AIDAALICE".to_string(),
            account_id: "123456789012".to_string(),
            principal_type: PrincipalType::User,
            source_identity: None,
            tags: None,
        };
        let docs = collect_identity_policies(&state, &principal);
        assert_eq!(docs.len(), 1, "pathed user's inline policy was missed");
        assert_eq!(
            evaluate(
                &docs,
                &req(&principal, "s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::Allow
        );
    }

    #[test]
    fn role_name_from_assumed_role_arn_strips_session() {
        assert_eq!(
            role_name_from_assumed_role_arn("arn:aws:sts::123456789012:assumed-role/ops/session-1"),
            Some("ops")
        );
    }

    // --- collect_identity_policies --------------------------------------

    #[test]
    fn collect_identity_policies_picks_up_user_inline() {
        use crate::state::IamUser;
        use chrono::Utc;
        let mut state = IamState::new("123456789012");
        state.users.insert(
            "alice".to_string(),
            IamUser {
                user_name: "alice".into(),
                user_id: "AIDAALICE".into(),
                arn: "arn:aws:iam::123456789012:user/alice".into(),
                path: "/".into(),
                created_at: Utc::now(),
                tags: Vec::new(),
                permissions_boundary: None,
            },
        );
        let mut inline = std::collections::BTreeMap::new();
        inline.insert(
            "AllowGet".to_string(),
            r#"{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#
                .to_string(),
        );
        state
            .user_inline_policies
            .insert("alice".to_string(), inline);

        let principal = principal_user("arn:aws:iam::123456789012:user/alice");
        let docs = collect_identity_policies(&state, &principal);
        assert_eq!(docs.len(), 1);
        assert_eq!(
            evaluate(
                &docs,
                &req(&principal, "s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::Allow
        );
    }

    #[test]
    fn collect_identity_policies_picks_up_managed_via_groups() {
        use crate::state::{IamGroup, IamPolicy, IamUser, PolicyVersion};
        use chrono::Utc;
        let mut state = IamState::new("123456789012");
        state.users.insert(
            "alice".to_string(),
            IamUser {
                user_name: "alice".into(),
                user_id: "AIDAALICE".into(),
                arn: "arn:aws:iam::123456789012:user/alice".into(),
                path: "/".into(),
                created_at: Utc::now(),
                tags: Vec::new(),
                permissions_boundary: None,
            },
        );
        let policy_arn = "arn:aws:iam::123456789012:policy/AllowGet".to_string();
        state.policies.insert(
            policy_arn.clone(),
            IamPolicy {
                policy_name: "AllowGet".into(),
                policy_id: "ANPA1".into(),
                arn: policy_arn.clone(),
                path: "/".into(),
                description: "".into(),
                created_at: Utc::now(),
                tags: Vec::new(),
                default_version_id: "v1".into(),
                versions: vec![PolicyVersion {
                    version_id: "v1".into(),
                    document: r#"{"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#.into(),
                    is_default: true,
                    created_at: Utc::now(),
                }],
                next_version_num: 2,
                attachment_count: 1,
            },
        );
        state.groups.insert(
            "readers".to_string(),
            IamGroup {
                group_name: "readers".into(),
                group_id: "AGPA1".into(),
                arn: "arn:aws:iam::123456789012:group/readers".into(),
                path: "/".into(),
                created_at: Utc::now(),
                members: vec!["alice".into()],
                inline_policies: std::collections::BTreeMap::new(),
                attached_policies: vec![policy_arn],
            },
        );
        let principal = principal_user("arn:aws:iam::123456789012:user/alice");
        let docs = collect_identity_policies(&state, &principal);
        assert_eq!(docs.len(), 1);
        assert_eq!(
            evaluate(
                &docs,
                &req(&principal, "s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::Allow
        );
    }

    #[test]
    fn collect_identity_policies_for_root_returns_empty() {
        let state = IamState::new("123456789012");
        let principal = Principal {
            arn: "arn:aws:iam::123456789012:root".into(),
            user_id: "ROOT".into(),
            account_id: "123456789012".into(),
            principal_type: PrincipalType::Root,
            source_identity: None,
            tags: None,
        };
        // Root short-circuits via Principal::is_root in dispatch; here we
        // just assert collect_identity_policies doesn't synthesize a
        // wildcard allow on its behalf.
        assert!(collect_identity_policies(&state, &principal).is_empty());
    }

    // --- resource-policy cross-account evaluation -----------------------

    const ACCT_A: &str = "111111111111";
    const ACCT_B: &str = "222222222222";

    fn principal_in(account: &str, user: &str) -> Principal {
        Principal {
            arn: Arn::global("iam", account, &format!("user/{user}")).to_string(),
            user_id: format!("AIDA{user}"),
            account_id: account.into(),
            principal_type: PrincipalType::User,
            source_identity: None,
            tags: None,
        }
    }

    fn assumed_role_principal(account: &str, role_arn_tail: &str) -> Principal {
        Principal {
            arn: Arn::global("sts", account, &format!("assumed-role/{role_arn_tail}")).to_string(),
            user_id: "AROAEXAMPLE".into(),
            account_id: account.into(),
            principal_type: PrincipalType::AssumedRole,
            source_identity: None,
            tags: None,
        }
    }

    fn eval_cross(
        identity: Option<serde_json::Value>,
        resource: Option<serde_json::Value>,
        principal: &Principal,
        resource_account_id: &str,
    ) -> Decision {
        let identity_docs: Vec<PolicyDocument> = identity.into_iter().map(doc).collect();
        let resource_doc = resource.map(doc);
        let request = req(principal, "s3:GetObject", "arn:aws:s3:::bucket/key");
        evaluate_with_resource_policy(
            &identity_docs,
            resource_doc.as_ref(),
            &request,
            resource_account_id,
        )
    }

    fn allow_get_wildcard() -> serde_json::Value {
        json!({"Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]})
    }

    fn deny_get_wildcard() -> serde_json::Value {
        json!({"Statement":[{"Effect":"Deny","Action":"s3:GetObject","Resource":"*"}]})
    }

    fn resource_allow_for(principal_arn: &str) -> serde_json::Value {
        json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": principal_arn},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/key"
            }]
        })
    }

    #[test]
    fn same_account_identity_only_allow() {
        let p = principal_in(ACCT_A, "alice");
        assert_eq!(
            eval_cross(Some(allow_get_wildcard()), None, &p, ACCT_A),
            Decision::Allow
        );
    }

    #[test]
    fn same_account_resource_only_allow_via_user_arn() {
        let p = principal_in(ACCT_A, "alice");
        let resource = resource_allow_for(&p.arn);
        assert_eq!(
            eval_cross(None, Some(resource), &p, ACCT_A),
            Decision::Allow
        );
    }

    #[test]
    fn same_account_both_allow() {
        let p = principal_in(ACCT_A, "alice");
        assert_eq!(
            eval_cross(
                Some(allow_get_wildcard()),
                Some(resource_allow_for(&p.arn)),
                &p,
                ACCT_A,
            ),
            Decision::Allow
        );
    }

    #[test]
    fn same_account_neither_allows_is_implicit_deny() {
        let p = principal_in(ACCT_A, "alice");
        assert_eq!(eval_cross(None, None, &p, ACCT_A), Decision::ImplicitDeny);
    }

    #[test]
    fn identity_deny_blocks_resource_allow() {
        let p = principal_in(ACCT_A, "alice");
        let resource = resource_allow_for(&p.arn);
        assert_eq!(
            eval_cross(Some(deny_get_wildcard()), Some(resource), &p, ACCT_A),
            Decision::ExplicitDeny
        );
    }

    #[test]
    fn resource_deny_blocks_identity_allow() {
        let p = principal_in(ACCT_A, "alice");
        let resource_deny = json!({
            "Statement": [{
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        });
        assert_eq!(
            eval_cross(Some(allow_get_wildcard()), Some(resource_deny), &p, ACCT_A,),
            Decision::ExplicitDeny
        );
    }

    #[test]
    fn cross_account_identity_only_is_implicit_deny() {
        // Resource lives in B, principal in A. Identity grants, resource
        // policy silent -> cross-account semantics require both.
        let p = principal_in(ACCT_A, "alice");
        assert_eq!(
            eval_cross(Some(allow_get_wildcard()), None, &p, ACCT_B),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn cross_account_resource_only_is_implicit_deny() {
        // Resource lives in B and grants via its policy; principal in A
        // has no identity policy → cross-account requires identity too.
        let p = principal_in(ACCT_A, "alice");
        let resource = resource_allow_for(&p.arn);
        assert_eq!(
            eval_cross(None, Some(resource), &p, ACCT_B),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn cross_account_both_allow_succeeds() {
        let p = principal_in(ACCT_A, "alice");
        let resource = resource_allow_for(&p.arn);
        assert_eq!(
            eval_cross(Some(allow_get_wildcard()), Some(resource), &p, ACCT_B),
            Decision::Allow
        );
    }

    #[test]
    fn principal_wildcard_star_matches_any_principal() {
        let p = principal_in(ACCT_A, "alice");
        let resource = json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        });
        assert_eq!(
            eval_cross(None, Some(resource), &p, ACCT_A),
            Decision::Allow
        );
    }

    #[test]
    fn principal_aws_star_matches_any_principal() {
        let p = principal_in(ACCT_A, "alice");
        let resource = json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "*"},
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        });
        assert_eq!(
            eval_cross(None, Some(resource), &p, ACCT_A),
            Decision::Allow
        );
    }

    #[test]
    fn principal_account_root_matches_any_user_in_account() {
        let p = principal_in(ACCT_A, "alice");
        let resource = resource_allow_for("arn:aws:iam::111111111111:root");
        assert_eq!(
            eval_cross(None, Some(resource), &p, ACCT_A),
            Decision::Allow
        );
    }

    #[test]
    fn principal_account_root_does_not_match_other_account() {
        let p = principal_in(ACCT_A, "alice");
        let resource = resource_allow_for("arn:aws:iam::222222222222:root");
        assert_eq!(
            eval_cross(None, Some(resource), &p, ACCT_A),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn principal_user_arn_exact_match() {
        let p = principal_in(ACCT_A, "alice");
        let resource = resource_allow_for("arn:aws:iam::111111111111:user/alice");
        assert_eq!(
            eval_cross(None, Some(resource), &p, ACCT_A),
            Decision::Allow
        );
    }

    #[test]
    fn principal_user_arn_mismatch_is_deny() {
        let p = principal_in(ACCT_A, "alice");
        let resource = resource_allow_for("arn:aws:iam::111111111111:user/bob");
        assert_eq!(
            eval_cross(None, Some(resource), &p, ACCT_A),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn principal_service_matches_assumed_role_containing_service_host() {
        let p = assumed_role_principal(
            ACCT_A,
            "AWSServiceRoleForLambda.lambda.amazonaws.com/session",
        );
        let resource = json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        });
        assert_eq!(
            eval_cross(None, Some(resource), &p, ACCT_A),
            Decision::Allow
        );
    }

    #[test]
    fn principal_service_does_not_match_unrelated_user() {
        let p = principal_in(ACCT_A, "alice");
        let resource = json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"Service": "lambda.amazonaws.com"},
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        });
        assert_eq!(
            eval_cross(None, Some(resource), &p, ACCT_A),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn not_principal_deny_excludes_named_user() {
        // NotPrincipal + Deny: deny everyone EXCEPT bob.
        // Alice is not bob -> deny applies -> ExplicitDeny.
        let alice = principal_in(ACCT_A, "alice");
        let resource = json!({
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "*"
                },
                {
                    "Effect": "Deny",
                    "NotPrincipal": {"AWS": Arn::global("iam", ACCT_A, "user/bob").to_string()},
                    "Action": "s3:GetObject",
                    "Resource": "*"
                }
            ]
        });
        assert_eq!(
            eval_cross(None, Some(resource.clone()), &alice, ACCT_A),
            Decision::ExplicitDeny
        );

        // Bob IS the named principal -> deny does NOT apply -> Allow from first statement.
        let bob = principal_in(ACCT_A, "bob");
        assert_eq!(
            eval_cross(None, Some(resource), &bob, ACCT_A),
            Decision::Allow
        );
    }

    #[test]
    fn not_principal_allow_excludes_named_user() {
        // NotPrincipal + Allow: allow everyone EXCEPT bob.
        // Alice is not bob -> allow applies.
        let alice = principal_in(ACCT_A, "alice");
        let resource = json!({
            "Statement": [{
                "Effect": "Allow",
                "NotPrincipal": {"AWS": Arn::global("iam", ACCT_A, "user/bob").to_string()},
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        });
        assert_eq!(
            eval_cross(None, Some(resource.clone()), &alice, ACCT_A),
            Decision::Allow
        );

        // Bob IS the named principal -> allow does NOT apply -> ImplicitDeny.
        let bob = principal_in(ACCT_A, "bob");
        assert_eq!(
            eval_cross(None, Some(resource), &bob, ACCT_A),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn not_principal_with_star_never_applies() {
        // NotPrincipal: "*" matches everyone, so the statement never applies.
        let alice = principal_in(ACCT_A, "alice");
        let resource = json!({
            "Statement": [{
                "Effect": "Allow",
                "NotPrincipal": "*",
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        });
        assert_eq!(
            eval_cross(None, Some(resource), &alice, ACCT_A),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn not_principal_with_account_root() {
        // NotPrincipal names account root. AwsAccountRoot matches
        // any principal in that account, so alice (in ACCT_A) matches
        // the NotPrincipal list and the statement does NOT apply.
        let alice = principal_in(ACCT_A, "alice");
        let resource = json!({
            "Statement": [{
                "Effect": "Allow",
                "NotPrincipal": {"AWS": Arn::global("iam", ACCT_A, "root").to_string()},
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        });
        assert_eq!(
            eval_cross(None, Some(resource.clone()), &alice, ACCT_A),
            Decision::ImplicitDeny
        );

        // A user in a DIFFERENT account does NOT match ACCT_A root,
        // so the Deny statement applies. With a Deny+NotPrincipal pattern
        // this means the cross-account user gets denied.
        let eve = principal_in(ACCT_B, "eve");
        let resource_deny = json!({
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": "*",
                    "Action": "s3:GetObject",
                    "Resource": "*"
                },
                {
                    "Effect": "Deny",
                    "NotPrincipal": {"AWS": Arn::global("iam", ACCT_A, "root").to_string()},
                    "Action": "s3:GetObject",
                    "Resource": "*"
                }
            ]
        });
        // Eve (ACCT_B) doesn't match ACCT_A root, so Deny applies.
        assert_eq!(
            eval_cross(None, Some(resource_deny.clone()), &eve, ACCT_A),
            Decision::ExplicitDeny
        );
        // Alice (ACCT_A) matches ACCT_A root, so Deny does NOT apply -> Allow.
        assert_eq!(
            eval_cross(None, Some(resource_deny), &alice, ACCT_A),
            Decision::Allow
        );
    }

    #[test]
    fn not_principal_with_unrecognized_type_safe_skips() {
        // NotPrincipal with only Federated type (unrecognized) ->
        // empty refs list -> statement skipped safely.
        let alice = principal_in(ACCT_A, "alice");
        let resource = json!({
            "Statement": [{
                "Effect": "Allow",
                "NotPrincipal": {"Federated": "cognito-identity.amazonaws.com"},
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        });
        assert_eq!(
            eval_cross(None, Some(resource), &alice, ACCT_A),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn not_principal_with_multiple_entries() {
        // NotPrincipal with multiple users. Statement applies only
        // to callers matching NONE of the entries.
        let alice = principal_in(ACCT_A, "alice");
        let bob = principal_in(ACCT_A, "bob");
        let charlie = principal_in(ACCT_A, "charlie");
        let resource = json!({
            "Statement": [{
                "Effect": "Deny",
                "NotPrincipal": {"AWS": [
                    Arn::global("iam", ACCT_A, "user/alice").to_string(),
                    Arn::global("iam", ACCT_A, "user/bob").to_string()
                ]},
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        });
        // Alice and bob are in the list -> deny does NOT apply
        assert_eq!(
            eval_cross(None, Some(resource.clone()), &alice, ACCT_A),
            Decision::ImplicitDeny
        );
        assert_eq!(
            eval_cross(None, Some(resource.clone()), &bob, ACCT_A),
            Decision::ImplicitDeny
        );
        // Charlie is NOT in the list -> deny applies
        assert_eq!(
            eval_cross(None, Some(resource), &charlie, ACCT_A),
            Decision::ExplicitDeny
        );
    }

    #[test]
    fn resource_policy_statement_without_principal_is_skipped() {
        // Malformed resource policy (missing Principal entirely) must
        // not silently grant to everyone.
        let p = principal_in(ACCT_A, "alice");
        let resource = json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        });
        assert_eq!(
            eval_cross(None, Some(resource), &p, ACCT_A),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn resource_policy_condition_block_gates_access() {
        // Regression guard: Phase 2 condition evaluation still applies
        // to resource-policy statements.
        use crate::condition::ConditionContext;
        use std::net::IpAddr;

        let p = principal_in(ACCT_A, "alice");
        let resource = json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "*",
                "Condition": {
                    "IpAddress": {"aws:SourceIp": "10.0.0.0/8"}
                }
            }]
        });
        let resource_doc = doc(resource);

        let ctx_ok = ConditionContext {
            aws_source_ip: Some("10.1.2.3".parse::<IpAddr>().unwrap()),
            ..ConditionContext::default()
        };
        let req_ok = EvalRequest {
            principal: &p,
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::bucket/key".to_string(),
            context: ctx_ok,
        };
        assert_eq!(
            evaluate_with_resource_policy(&[], Some(&resource_doc), &req_ok, ACCT_A),
            Decision::Allow
        );

        let ctx_bad = ConditionContext {
            aws_source_ip: Some("8.8.8.8".parse::<IpAddr>().unwrap()),
            ..ConditionContext::default()
        };
        let req_bad = EvalRequest {
            principal: &p,
            action: "s3:GetObject".to_string(),
            resource: "arn:aws:s3:::bucket/key".to_string(),
            context: ctx_bad,
        };
        assert_eq!(
            evaluate_with_resource_policy(&[], Some(&resource_doc), &req_bad, ACCT_A),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn classify_aws_principal_recognizes_bare_account_id() {
        assert_eq!(
            classify_aws_principal("111111111111"),
            PrincipalRef::AwsAccountRoot("111111111111".to_string())
        );
    }

    #[test]
    fn classify_aws_principal_recognizes_root_arn() {
        assert_eq!(
            classify_aws_principal("arn:aws:iam::111111111111:root"),
            PrincipalRef::AwsAccountRoot("111111111111".to_string())
        );
    }

    #[test]
    fn classify_aws_principal_keeps_user_arn_as_arn() {
        assert_eq!(
            classify_aws_principal("arn:aws:iam::111111111111:user/alice"),
            PrincipalRef::AwsArn("arn:aws:iam::111111111111:user/alice".to_string())
        );
    }

    // --- evaluate_with_gates (Phase 3) ---------------------------------

    fn allow_all() -> PolicyDocument {
        doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "*",
                "Resource": "*"
            }]
        }))
    }

    fn allow_get_object() -> PolicyDocument {
        doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Action": "s3:GetObject",
                "Resource": "*"
            }]
        }))
    }

    fn deny_put_object() -> PolicyDocument {
        doc(json!({
            "Statement": [{
                "Effect": "Deny",
                "Action": "s3:PutObject",
                "Resource": "*"
            }]
        }))
    }

    #[test]
    fn gates_absent_behaves_like_phase2_allow() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let identity = [allow_all()];
        assert_eq!(
            evaluate_with_gates(
                &identity,
                None,
                None,
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::Allow
        );
    }

    #[test]
    fn gates_absent_behaves_like_phase2_implicit_deny() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        assert_eq!(
            evaluate_with_gates(
                &[],
                None,
                None,
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn boundary_caps_identity_allow() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let identity = [allow_all()];
        let boundary = [allow_get_object()];
        // Action covered by both identity and boundary → Allow.
        assert_eq!(
            evaluate_with_gates(
                &identity,
                Some(&boundary),
                None,
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::Allow
        );
        // Action covered by identity but not boundary → ImplicitDeny.
        assert_eq!(
            evaluate_with_gates(
                &identity,
                Some(&boundary),
                None,
                &req(&p, "s3:PutObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn empty_boundary_denies_everything() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let identity = [allow_all()];
        let boundary: [PolicyDocument; 0] = [];
        // Dangling / unresolved boundary ARN → caller passes Some(&[])
        // which must deny everything.
        assert_eq!(
            evaluate_with_gates(
                &identity,
                Some(&boundary),
                None,
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn explicit_deny_in_boundary_wins() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let identity = [allow_all()];
        let boundary = [deny_put_object()];
        assert_eq!(
            evaluate_with_gates(
                &identity,
                Some(&boundary),
                None,
                &req(&p, "s3:PutObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::ExplicitDeny
        );
    }

    #[test]
    fn identity_implicit_with_boundary_allow_is_implicit_deny() {
        // Boundary doesn't grant — only caps. If identity is silent,
        // the request must still deny.
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let boundary = [allow_all()];
        assert_eq!(
            evaluate_with_gates(
                &[],
                Some(&boundary),
                None,
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn session_policy_caps_identity_allow() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let identity = [allow_all()];
        let session = [allow_get_object()];
        assert_eq!(
            evaluate_with_gates(
                &identity,
                None,
                Some(&session),
                &req(&p, "s3:PutObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::ImplicitDeny
        );
        assert_eq!(
            evaluate_with_gates(
                &identity,
                None,
                Some(&session),
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::Allow
        );
    }

    #[test]
    fn session_policy_explicit_deny_wins() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let identity = [allow_all()];
        let session = [deny_put_object()];
        assert_eq!(
            evaluate_with_gates(
                &identity,
                None,
                Some(&session),
                &req(&p, "s3:PutObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::ExplicitDeny
        );
    }

    #[test]
    fn boundary_and_session_must_both_allow() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let identity = [allow_all()];
        let boundary = [allow_all()];
        let session = [allow_get_object()];
        // Session caps to GetObject only.
        assert_eq!(
            evaluate_with_gates(
                &identity,
                Some(&boundary),
                Some(&session),
                &req(&p, "s3:PutObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::ImplicitDeny
        );
        assert_eq!(
            evaluate_with_gates(
                &identity,
                Some(&boundary),
                Some(&session),
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key")
            ),
            Decision::Allow
        );
    }

    // --- evaluate_with_resource_policy_and_gates -----------------------

    #[test]
    fn resource_policy_gated_same_account_resource_bypasses_boundary() {
        // Same-account grant via a resource policy does NOT need the
        // identity side (or the boundary/session gates) to allow —
        // resource policies in the same account stand on their own.
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let identity: [PolicyDocument; 0] = [];
        let boundary: [PolicyDocument; 0] = []; // deny-all boundary
        let resource = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": {"AWS": "arn:aws:iam::123456789012:user/alice"},
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/key"
            }]
        }));
        assert_eq!(
            evaluate_with_resource_policy_and_gates(
                &identity,
                Some(&boundary),
                None,
                Some(&resource),
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key"),
                "123456789012"
            ),
            Decision::Allow
        );
    }

    #[test]
    fn resource_policy_gated_cross_account_identity_must_allow() {
        // Cross-account: identity AND resource must both allow. Even
        // with a resource-policy grant, if identity is implicit-deny
        // the call is denied.
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let identity: [PolicyDocument; 0] = [];
        let resource = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/key"
            }]
        }));
        assert_eq!(
            evaluate_with_resource_policy_and_gates(
                &identity,
                None,
                None,
                Some(&resource),
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key"),
                "999999999999"
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn resource_policy_gated_cross_account_boundary_caps_identity_side() {
        // Cross-account, identity allows, resource allows, but the
        // caller's boundary is empty (deny-all) → identity side is
        // gated to ImplicitDeny and the AND denies the call.
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let identity = [allow_all()];
        let boundary: [PolicyDocument; 0] = [];
        let resource = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": "arn:aws:s3:::bucket/key"
            }]
        }));
        assert_eq!(
            evaluate_with_resource_policy_and_gates(
                &identity,
                Some(&boundary),
                None,
                Some(&resource),
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key"),
                "999999999999"
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn resource_policy_gated_explicit_deny_in_session_wins() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let identity = [allow_all()];
        let session = [deny_put_object()];
        let resource = doc(json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::bucket/*"
            }]
        }));
        assert_eq!(
            evaluate_with_resource_policy_and_gates(
                &identity,
                None,
                Some(&session),
                Some(&resource),
                &req(&p, "s3:PutObject", "arn:aws:s3:::bucket/key"),
                "123456789012"
            ),
            Decision::ExplicitDeny
        );
    }

    // --- Batch 4: SCP ceiling layer -------------------------------------

    #[test]
    fn scp_caps_identity_allow_all() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let identity = [allow_all()];
        let scps = [allow_get_object()];
        assert_eq!(
            evaluate_with_gates_and_scps(
                &identity,
                None,
                None,
                Some(&scps),
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key"),
            ),
            Decision::Allow
        );
        assert_eq!(
            evaluate_with_gates_and_scps(
                &identity,
                None,
                None,
                Some(&scps),
                &req(&p, "s3:PutObject", "arn:aws:s3:::bucket/key"),
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn scp_explicit_deny_wins() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let identity = [allow_all()];
        let scps = [deny_put_object()];
        assert_eq!(
            evaluate_with_gates_and_scps(
                &identity,
                None,
                None,
                Some(&scps),
                &req(&p, "s3:PutObject", "arn:aws:s3:::bucket/key"),
            ),
            Decision::ExplicitDeny
        );
    }

    #[test]
    fn scp_empty_chain_denies_everything() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let identity = [allow_all()];
        let scps: [PolicyDocument; 0] = [];
        // Some(&[]) means the org applies but no SCP allow-all reaches
        // the account path (e.g. FullAWSAccess detached and nothing
        // else attached). Deny-by-default.
        assert_eq!(
            evaluate_with_gates_and_scps(
                &identity,
                None,
                None,
                Some(&scps),
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key"),
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn scp_none_preserves_identity_only_decision() {
        // None = off-by-default. Evaluation must match the no-SCP
        // path bit-for-bit, preserving the zero-behavior-change
        // contract when no organization exists.
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let identity = [allow_all()];
        let with_scps = evaluate_with_gates_and_scps(
            &identity,
            None,
            None,
            None,
            &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key"),
        );
        let without = evaluate_with_gates(
            &identity,
            None,
            None,
            &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key"),
        );
        assert_eq!(with_scps, without);
        assert_eq!(with_scps, Decision::Allow);
    }

    #[test]
    fn scp_chain_intersects_across_ancestors() {
        // Two SCPs up the path: outer Allow *, inner Allow only
        // s3:GetObject. AWS intersects — action must be in every one.
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let identity = [allow_all()];
        let scps = [allow_all(), allow_get_object()];
        assert_eq!(
            evaluate_with_gates_and_scps(
                &identity,
                None,
                None,
                Some(&scps),
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key"),
            ),
            Decision::Allow
        );
        assert_eq!(
            evaluate_with_gates_and_scps(
                &identity,
                None,
                None,
                Some(&scps),
                &req(&p, "s3:PutObject", "arn:aws:s3:::bucket/key"),
            ),
            Decision::ImplicitDeny
        );
    }

    #[test]
    fn scp_intersects_with_boundary_and_session() {
        let p = principal_user("arn:aws:iam::123456789012:user/alice");
        let identity = [allow_all()];
        let boundary = [allow_all()];
        let session = [allow_all()];
        let scps = [allow_get_object()];
        assert_eq!(
            evaluate_with_gates_and_scps(
                &identity,
                Some(&boundary),
                Some(&session),
                Some(&scps),
                &req(&p, "s3:PutObject", "arn:aws:s3:::bucket/key"),
            ),
            Decision::ImplicitDeny
        );
        assert_eq!(
            evaluate_with_gates_and_scps(
                &identity,
                Some(&boundary),
                Some(&session),
                Some(&scps),
                &req(&p, "s3:GetObject", "arn:aws:s3:::bucket/key"),
            ),
            Decision::Allow
        );
    }

    #[test]
    fn scp_caps_identity_side_of_resource_policy() {
        // Cross-account resource policy grants PutObject; caller's SCP
        // allows only GetObject. Identity side is gated by SCP →
        // cross-account AND means the whole thing denies.
        let p = principal_user("arn:aws:iam::111111111111:user/alice");
        let identity = [allow_all()];
        let resource = doc(serde_json::json!({
            "Statement": [{
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:PutObject",
                "Resource": "arn:aws:s3:::bucket/*"
            }]
        }));
        let scps = [allow_get_object()];
        assert_eq!(
            evaluate_with_resource_policy_and_gates_and_scps(
                &identity,
                None,
                None,
                Some(&scps),
                Some(&resource),
                &req(&p, "s3:PutObject", "arn:aws:s3:::bucket/key"),
                "222222222222",
            ),
            Decision::ImplicitDeny
        );
    }
}
