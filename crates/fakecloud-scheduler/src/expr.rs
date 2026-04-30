//! Schedule expression parsing and matching.
//!
//! EventBridge Scheduler supports three expression forms:
//! - `at(yyyy-mm-ddThh:mm:ss)` — one-shot execution at a specific instant
//! - `rate(N unit)` — recurring every N minutes|hours|days (SECONDS NOT
//!   allowed by AWS, but fakecloud accepts them for fast-iteration tests)
//! - `cron(min hour dom month dow year)` — six-field recurring expression
//!
//! The matching logic mirrors the simplified cron implementation in
//! `fakecloud-eventbridge::scheduler`: each field is either a wildcard
//! (`*` / `?`) or a single numeric value. Full cron syntax (ranges,
//! lists, step values) is not currently supported — the firing loop
//! simply skips schedules whose expressions don't match this grammar.

use chrono::{DateTime, Datelike, NaiveDateTime, TimeZone, Timelike, Utc};
use std::time::Duration;

/// Parsed schedule expression.
#[derive(Debug, Clone)]
pub enum Expr {
    /// One-shot `at(...)` expression, resolved to a wall-clock instant.
    At(DateTime<Utc>),
    /// Recurring `rate(...)` expression.
    Rate(Duration),
    /// Recurring `cron(...)` expression.
    Cron(CronExpr),
}

#[derive(Debug, Clone)]
pub struct CronExpr {
    pub minute: CronField,
    pub hour: CronField,
    pub day_of_month: CronField,
    pub month: CronField,
    pub day_of_week: CronField,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CronField {
    Any,
    Value(u32),
}

/// Parse a schedule expression. Returns `None` on any shape we don't
/// recognize — the firing loop treats unparseable schedules as
/// permanently disabled (they never fire, they never error).
pub fn parse(expr: &str) -> Option<Expr> {
    let expr = expr.trim();
    if let Some(inner) = expr.strip_prefix("at(").and_then(|s| s.strip_suffix(')')) {
        return parse_at(inner.trim());
    }
    if let Some(inner) = expr.strip_prefix("rate(").and_then(|s| s.strip_suffix(')')) {
        return parse_rate(inner.trim());
    }
    if let Some(inner) = expr.strip_prefix("cron(").and_then(|s| s.strip_suffix(')')) {
        return parse_cron(inner.trim());
    }
    None
}

fn parse_at(inner: &str) -> Option<Expr> {
    // AWS docs: at(yyyy-mm-ddThh:mm:ss) — no timezone, no fractional seconds
    let dt = NaiveDateTime::parse_from_str(inner, "%Y-%m-%dT%H:%M:%S").ok()?;
    Some(Expr::At(Utc.from_utc_datetime(&dt)))
}

fn parse_rate(inner: &str) -> Option<Expr> {
    let parts: Vec<&str> = inner.split_whitespace().collect();
    if parts.len() != 2 {
        return None;
    }
    let value: u64 = parts[0].parse().ok()?;
    let secs = match parts[1] {
        "second" | "seconds" => value,
        "minute" | "minutes" => value * 60,
        "hour" | "hours" => value * 3600,
        "day" | "days" => value * 86400,
        _ => return None,
    };
    Some(Expr::Rate(Duration::from_secs(secs)))
}

fn parse_cron(inner: &str) -> Option<Expr> {
    let parts: Vec<&str> = inner.split_whitespace().collect();
    if parts.len() != 6 {
        return None;
    }
    // Reject tokens we don't understand (ranges, lists, step values,
    // month/weekday name shorthands). Falling back to wildcard would
    // cause unsupported schedules to fire every minute instead of
    // being silently disabled. `year` (parts[5]) is accepted but not
    // enforced at fire time — matches existing eventbridge behavior.
    Some(Expr::Cron(CronExpr {
        minute: parse_cron_field(parts[0])?,
        hour: parse_cron_field(parts[1])?,
        day_of_month: parse_cron_field(parts[2])?,
        month: parse_cron_field(parts[3])?,
        day_of_week: parse_cron_field(parts[4])?,
    }))
}

fn parse_cron_field(s: &str) -> Option<CronField> {
    if s == "*" || s == "?" {
        return Some(CronField::Any);
    }
    s.parse::<u32>().ok().map(CronField::Value)
}

/// Decide whether `expr` is due to fire, given its `last_fired` time
/// (if any) and the current wall clock `now`.
///
/// Contract per expression kind:
/// - `At(t)`: fires once when `now >= t` AND `last_fired` is `None`.
///   The ticker consumes this by deleting/disabling the schedule after
///   the first fire so subsequent ticks don't re-fire it.
/// - `Rate(d)`: fires if never fired (bootstraps on first tick), or if
///   `now - last_fired >= d`.
/// - `Cron(c)`: fires when every field matches the current minute AND
///   we haven't already fired within this same minute (ticker
///   dedupe lives outside this function — see `CronFireTracker`).
pub fn is_due(expr: &Expr, last_fired: Option<DateTime<Utc>>, now: DateTime<Utc>) -> bool {
    match expr {
        Expr::At(t) => last_fired.is_none() && now >= *t,
        Expr::Rate(d) => match last_fired {
            Some(last) => {
                now.signed_duration_since(last)
                    .to_std()
                    .unwrap_or(Duration::ZERO)
                    >= *d
            }
            None => true,
        },
        Expr::Cron(c) => matches_cron(c, now),
    }
}

/// Check whether each cron field matches the fields of `now`. The
/// per-minute dedupe has to live in the ticker because we need to
/// track fires across multiple calls without mutating the cron state.
pub fn matches_cron(c: &CronExpr, now: DateTime<Utc>) -> bool {
    matches_cron_fields(
        c,
        now.minute(),
        now.hour(),
        now.day(),
        now.month(),
        now.weekday().num_days_from_sunday(),
    )
}

/// `matches_cron` evaluated against the local time in IANA timezone `tz`.
/// AWS Scheduler interprets cron in `ScheduleExpressionTimezone` rather
/// than UTC; unknown names fall back to UTC so we never silently lose a
/// schedule (the service layer rejects bad names at create time).
pub fn matches_cron_in_tz(c: &CronExpr, now: DateTime<Utc>, tz: &str) -> bool {
    match tz.parse::<chrono_tz::Tz>() {
        Ok(tz) => {
            let local = now.with_timezone(&tz);
            matches_cron_fields(
                c,
                local.minute(),
                local.hour(),
                local.day(),
                local.month(),
                local.weekday().num_days_from_sunday(),
            )
        }
        Err(_) => matches_cron(c, now),
    }
}

fn matches_cron_fields(
    c: &CronExpr,
    minute: u32,
    hour: u32,
    day: u32,
    month: u32,
    day_of_week: u32,
) -> bool {
    let match_field = |f: &CronField, actual: u32| -> bool {
        matches!(f, CronField::Any) || matches!(f, CronField::Value(v) if *v == actual)
    };
    match_field(&c.minute, minute)
        && match_field(&c.hour, hour)
        && match_field(&c.day_of_month, day)
        && match_field(&c.month, month)
        && match_field(&c.day_of_week, day_of_week)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_rate_forms() {
        assert!(matches!(parse("rate(1 minute)"), Some(Expr::Rate(_))));
        assert!(matches!(parse("rate(5 minutes)"), Some(Expr::Rate(_))));
        assert!(matches!(parse("rate(1 hour)"), Some(Expr::Rate(_))));
        assert!(matches!(parse("rate(2 days)"), Some(Expr::Rate(_))));
        assert!(matches!(parse("rate(1 second)"), Some(Expr::Rate(_))));
    }

    #[test]
    fn parse_rate_rejects_bad_unit_and_shape() {
        assert!(parse("rate(1 fortnight)").is_none());
        assert!(parse("rate(abc minutes)").is_none());
        assert!(parse("rate(5)").is_none());
    }

    #[test]
    fn parse_at_utc() {
        let e = parse("at(2030-01-01T12:00:00)").unwrap();
        match e {
            Expr::At(t) => assert_eq!(t.timestamp(), 1893499200),
            _ => panic!("expected At"),
        }
    }

    #[test]
    fn parse_at_rejects_garbage() {
        assert!(parse("at(2030-01-01)").is_none());
        assert!(parse("at(nope)").is_none());
        assert!(parse("at()").is_none());
    }

    #[test]
    fn parse_cron_shape() {
        assert!(matches!(parse("cron(* * * * ? *)"), Some(Expr::Cron(_))));
        assert!(matches!(parse("cron(0 12 * * ? *)"), Some(Expr::Cron(_))));
        assert!(parse("cron(1 2 3)").is_none());
    }

    #[test]
    fn parse_cron_rejects_unsupported_tokens() {
        // Non-numeric, non-wildcard tokens are now rejected instead
        // of being silently converted to wildcards (which would make
        // every unsupported schedule fire every minute).
        assert!(parse("cron(*/5 * * * ? *)").is_none());
        assert!(parse("cron(1,3,5 * * * ? *)").is_none());
        assert!(parse("cron(1-3 * * * ? *)").is_none());
        assert!(parse("cron(xyz 12 * * ? *)").is_none());
    }

    #[test]
    fn parse_unknown_returns_none() {
        assert!(parse("every day at noon").is_none());
        assert!(parse("").is_none());
        assert!(parse("at").is_none());
    }

    #[test]
    fn matches_cron_in_tz_uses_local_hour() {
        // 12:00 UTC == 04:00 America/Los_Angeles in winter.
        // A schedule of "cron(0 4 * * ? *)" in LA tz must match,
        // but the same schedule against the UTC-only matcher must miss.
        let now = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();
        let cron = parse("cron(0 4 * * ? *)").unwrap();
        let cron = match cron {
            Expr::Cron(c) => c,
            _ => panic!("expected Cron"),
        };
        assert!(matches_cron_in_tz(&cron, now, "America/Los_Angeles"));
        assert!(!matches_cron(&cron, now));
    }

    #[test]
    fn matches_cron_in_tz_falls_back_to_utc_for_unknown_zone() {
        // Hour 12 UTC matches "cron(0 12 * * ? *)" if tz is unparseable.
        let now = Utc.with_ymd_and_hms(2026, 1, 15, 12, 0, 0).unwrap();
        let cron = match parse("cron(0 12 * * ? *)").unwrap() {
            Expr::Cron(c) => c,
            _ => panic!("expected Cron"),
        };
        assert!(matches_cron_in_tz(&cron, now, "Not/A_Real_Zone"));
    }

    #[test]
    fn is_due_at_fires_once_after_target() {
        let t = Utc.with_ymd_and_hms(2030, 1, 1, 12, 0, 0).unwrap();
        let expr = Expr::At(t);
        assert!(!is_due(&expr, None, t - chrono::Duration::seconds(1)));
        assert!(is_due(&expr, None, t));
        assert!(is_due(&expr, None, t + chrono::Duration::seconds(10)));
        assert!(!is_due(&expr, Some(t), t + chrono::Duration::seconds(10)));
    }

    #[test]
    fn is_due_rate_fires_on_bootstrap_and_after_interval() {
        let expr = Expr::Rate(Duration::from_secs(60));
        let now = Utc.with_ymd_and_hms(2026, 1, 1, 0, 0, 0).unwrap();
        assert!(is_due(&expr, None, now));
        assert!(!is_due(
            &expr,
            Some(now),
            now + chrono::Duration::seconds(30)
        ));
        assert!(is_due(
            &expr,
            Some(now),
            now + chrono::Duration::seconds(60)
        ));
        assert!(is_due(
            &expr,
            Some(now),
            now + chrono::Duration::seconds(61)
        ));
    }

    #[test]
    fn is_due_cron_wildcards_always_match() {
        let c = CronExpr {
            minute: CronField::Any,
            hour: CronField::Any,
            day_of_month: CronField::Any,
            month: CronField::Any,
            day_of_week: CronField::Any,
        };
        let now = Utc.with_ymd_and_hms(2026, 5, 15, 10, 30, 0).unwrap();
        assert!(is_due(&Expr::Cron(c), None, now));
    }

    #[test]
    fn is_due_cron_specific_minute_mismatch() {
        let c = CronExpr {
            minute: CronField::Value(45),
            hour: CronField::Any,
            day_of_month: CronField::Any,
            month: CronField::Any,
            day_of_week: CronField::Any,
        };
        let now = Utc.with_ymd_and_hms(2026, 5, 15, 10, 30, 0).unwrap();
        assert!(!is_due(&Expr::Cron(c), None, now));
    }
}
