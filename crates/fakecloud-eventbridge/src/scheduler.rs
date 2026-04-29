use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{Datelike, Timelike, Utc};
use serde_json::json;

use fakecloud_core::delivery::DeliveryBus;
use fakecloud_lambda::runtime::ContainerRuntime;
use fakecloud_lambda::{LambdaInvocation, SharedLambdaState};
use fakecloud_logs::SharedLogsState;

use crate::state::SharedEventBridgeState;

/// Parsed schedule expression.
enum Schedule {
    /// Rate-based: fire every `interval` duration.
    Rate(Duration),
    /// Cron-based: `cron(min hour dom month dow year)`.
    Cron(CronExpr),
}

/// A simplified cron expression with 6 fields: min hour dom month dow year.
/// Each field is either `Any` (wildcard) or a specific numeric value.
struct CronExpr {
    minute: CronField,
    hour: CronField,
    day_of_month: CronField,
    month: CronField,
    day_of_week: CronField,
    // year is parsed but not checked (always matches)
}

enum CronField {
    Any,
    Value(u32),
}

fn parse_schedule(expr: &str) -> Option<Schedule> {
    let expr = expr.trim();
    if let Some(inner) = expr.strip_prefix("rate(").and_then(|s| s.strip_suffix(')')) {
        return parse_rate(inner.trim());
    }
    if let Some(inner) = expr.strip_prefix("cron(").and_then(|s| s.strip_suffix(')')) {
        return parse_cron(inner.trim());
    }
    None
}

fn parse_rate(inner: &str) -> Option<Schedule> {
    let parts: Vec<&str> = inner.split_whitespace().collect();
    if parts.len() != 2 {
        return None;
    }
    let value: u64 = parts[0].parse().ok()?;
    let unit = parts[1];
    let secs = match unit {
        "second" | "seconds" => value,
        "minute" | "minutes" => value * 60,
        "hour" | "hours" => value * 3600,
        "day" | "days" => value * 86400,
        _ => return None,
    };
    Some(Schedule::Rate(Duration::from_secs(secs)))
}

fn parse_cron(inner: &str) -> Option<Schedule> {
    let parts: Vec<&str> = inner.split_whitespace().collect();
    if parts.len() != 6 {
        return None;
    }
    Some(Schedule::Cron(CronExpr {
        minute: parse_cron_field(parts[0]),
        hour: parse_cron_field(parts[1]),
        day_of_month: parse_cron_field(parts[2]),
        month: parse_cron_field(parts[3]),
        day_of_week: parse_cron_field(parts[4]),
        // year field parsed but not stored (always matches)
    }))
}

fn parse_cron_field(s: &str) -> CronField {
    if s == "*" || s == "?" {
        return CronField::Any;
    }
    match s.parse::<u32>() {
        Ok(v) => CronField::Value(v),
        Err(_) => CronField::Any,
    }
}

fn cron_matches_now(cron: &CronExpr) -> bool {
    let now = Utc::now();
    let matches_field = |field: &CronField, actual: u32| -> bool {
        match field {
            CronField::Any => true,
            CronField::Value(v) => *v == actual,
        }
    };
    matches_field(&cron.minute, now.minute())
        && matches_field(&cron.hour, now.hour())
        && matches_field(&cron.day_of_month, now.day())
        && matches_field(&cron.month, now.month())
        && matches_field(&cron.day_of_week, now.weekday().num_days_from_sunday())
}

/// Background scheduler that fires scheduled EventBridge rules.
pub struct Scheduler {
    state: SharedEventBridgeState,
    delivery: Arc<DeliveryBus>,
    lambda_state: Option<SharedLambdaState>,
    logs_state: Option<SharedLogsState>,
    container_runtime: Option<Arc<ContainerRuntime>>,
}

impl Scheduler {
    pub fn new(state: SharedEventBridgeState, delivery: Arc<DeliveryBus>) -> Self {
        Self {
            state,
            delivery,
            lambda_state: None,
            logs_state: None,
            container_runtime: None,
        }
    }

    pub fn with_lambda(mut self, lambda_state: SharedLambdaState) -> Self {
        self.lambda_state = Some(lambda_state);
        self
    }

    pub fn with_logs(mut self, logs_state: SharedLogsState) -> Self {
        self.logs_state = Some(logs_state);
        self
    }

    pub fn with_runtime(mut self, runtime: Arc<ContainerRuntime>) -> Self {
        self.container_runtime = Some(runtime);
        self
    }

    pub async fn run(self) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        // Track last-fired-minute for cron to avoid firing multiple times in the same minute
        // Keyed by (bus_name, rule_name) to distinguish same-named rules on different buses
        let mut cron_last_minute: HashMap<crate::state::RuleKey, (u32, u32)> = HashMap::new();

        loop {
            interval.tick().await;
            self.tick(&mut cron_last_minute);
        }
    }

    fn tick(&self, cron_last_minute: &mut HashMap<crate::state::RuleKey, (u32, u32)>) {
        let now = Utc::now();

        // Collect rules that need to fire (to avoid holding lock during delivery)
        // Each entry includes the account_id that owns the rule
        let mut to_fire: Vec<(String, String, String, Vec<crate::state::EventTarget>)> = Vec::new();

        {
            let mut accounts = self.state.write();
            for (account_id, state) in accounts.iter_mut() {
                let account_id = account_id.to_string();
                let region = state.region.clone();
                let rule_keys: Vec<crate::state::RuleKey> = state.rules.keys().cloned().collect();

                for key in rule_keys {
                    let rule = match state.rules.get(&key) {
                        Some(r) => r,
                        None => continue,
                    };
                    let name = rule.name.clone();

                    if rule.state != "ENABLED" {
                        continue;
                    }

                    let schedule_expr = match &rule.schedule_expression {
                        Some(s) => s.clone(),
                        None => continue,
                    };

                    if rule.targets.is_empty() {
                        continue;
                    }

                    let schedule = match parse_schedule(&schedule_expr) {
                        Some(s) => s,
                        None => continue,
                    };

                    let should_fire = match &schedule {
                        Schedule::Rate(duration) => match rule.last_fired {
                            Some(last) => {
                                let elapsed = now.signed_duration_since(last);
                                elapsed.to_std().unwrap_or(Duration::ZERO) >= *duration
                            }
                            None => true, // Never fired, fire immediately
                        },
                        Schedule::Cron(cron) => {
                            if !cron_matches_now(cron) {
                                false
                            } else {
                                // Avoid firing multiple times in the same minute
                                let current = (now.hour(), now.minute());
                                let last = cron_last_minute.get(&key);
                                if last == Some(&current) {
                                    false
                                } else {
                                    cron_last_minute.insert(key.clone(), current);
                                    true
                                }
                            }
                        }
                    };

                    if should_fire {
                        let targets = rule.targets.clone();
                        // Update last_fired while we hold the write lock
                        if let Some(r) = state.rules.get_mut(&key) {
                            r.last_fired = Some(now);
                        }
                        to_fire.push((account_id.clone(), region.clone(), name, targets));
                    }
                }
            }
        }
        // Lock is dropped here

        // Deliver events
        for (account_id, region, rule_name, targets) in to_fire {
            let event_id = uuid::Uuid::new_v4().to_string();
            let event_json = json!({
                "version": "0",
                "id": event_id,
                "source": "aws.events",
                "detail-type": "Scheduled Event",
                "detail": {},
                "time": now.to_rfc3339(),
                "region": region,
            });
            let event_str = event_json.to_string();

            tracing::debug!(rule = %rule_name, targets = targets.len(), "scheduler firing");

            for target in &targets {
                let arn = &target.arn;
                if arn.contains(":sqs:") {
                    self.delivery.send_to_sqs(arn, &event_str, &HashMap::new());
                } else if arn.contains(":sns:") {
                    self.delivery
                        .publish_to_sns(arn, &event_str, Some("Scheduled Event"));
                } else if arn.contains(":lambda:") {
                    tracing::info!(
                        function_arn = %arn,
                        payload = %event_str,
                        "Scheduler delivering to Lambda function"
                    );
                    let mut eb_accounts = self.state.write();
                    let eb_state = eb_accounts.get_or_create(&account_id);
                    eb_state
                        .lambda_invocations
                        .push(crate::state::LambdaInvocation {
                            function_arn: arn.clone(),
                            payload: event_str.clone(),
                            timestamp: now,
                        });
                    drop(eb_accounts);
                    if let Some(ref ls) = self.lambda_state {
                        ls.write()
                            .get_or_create(&account_id)
                            .invocations
                            .push(LambdaInvocation {
                                function_arn: arn.clone(),
                                payload: event_str.clone(),
                                timestamp: now,
                                source: "aws:events".to_string(),
                            });
                    }
                    crate::service::invoke_lambda_async(
                        &self.container_runtime,
                        &self.lambda_state,
                        arn,
                        &event_str,
                    );
                } else if arn.contains(":logs:") {
                    tracing::info!(
                        log_group_arn = %arn,
                        payload = %event_str,
                        "Scheduler delivering to CloudWatch Logs"
                    );
                    let mut eb_accounts = self.state.write();
                    let eb_state = eb_accounts.get_or_create(&account_id);
                    eb_state.log_deliveries.push(crate::state::LogDelivery {
                        log_group_arn: arn.clone(),
                        payload: event_str.clone(),
                        timestamp: now,
                    });
                    drop(eb_accounts);
                    if let Some(ref log_state) = self.logs_state {
                        crate::service::deliver_to_logs(log_state, arn, &event_str, now);
                    }
                } else if arn.contains(":states:") {
                    tracing::info!(
                        state_machine_arn = %arn,
                        "Scheduler delivering to Step Functions"
                    );
                    self.delivery.start_stepfunctions_execution(arn, &event_str);
                    let mut eb_accounts = self.state.write();
                    let eb_state = eb_accounts.get_or_create(&account_id);
                    eb_state
                        .step_function_executions
                        .push(crate::state::StepFunctionExecution {
                            state_machine_arn: arn.clone(),
                            payload: event_str.clone(),
                            timestamp: now,
                        });
                } else if arn.starts_with("https://") || arn.starts_with("http://") {
                    let url = arn.clone();
                    let payload = event_str.clone();
                    tokio::spawn(async move {
                        let client = reqwest::Client::new();
                        let result = client
                            .post(&url)
                            .header("Content-Type", "application/json")
                            .body(payload)
                            .send()
                            .await;
                        if let Err(e) = result {
                            tracing::warn!(
                                endpoint = %url,
                                error = %e,
                                "Scheduler HTTP target delivery failed"
                            );
                        }
                    });
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    #[test]
    fn parse_rate_minutes() {
        let s = parse_schedule("rate(5 minutes)");
        assert!(matches!(s, Some(Schedule::Rate(d)) if d == Duration::from_secs(300)));
    }

    #[test]
    fn parse_rate_singular() {
        let s = parse_schedule("rate(1 hour)");
        assert!(matches!(s, Some(Schedule::Rate(d)) if d == Duration::from_secs(3600)));
    }

    #[test]
    fn parse_rate_seconds() {
        let s = parse_schedule("rate(1 second)");
        assert!(matches!(s, Some(Schedule::Rate(d)) if d == Duration::from_secs(1)));
    }

    #[test]
    fn parse_rate_days() {
        let s = parse_schedule("rate(2 days)");
        assert!(matches!(s, Some(Schedule::Rate(d)) if d == Duration::from_secs(172800)));
    }

    #[test]
    fn parse_cron_all_wildcards() {
        let s = parse_schedule("cron(* * * * ? *)");
        assert!(matches!(s, Some(Schedule::Cron(_))));
    }

    #[test]
    fn parse_cron_specific_values() {
        let s = parse_schedule("cron(0 12 * * ? *)");
        match s {
            Some(Schedule::Cron(c)) => {
                assert!(matches!(c.minute, CronField::Value(0)));
                assert!(matches!(c.hour, CronField::Value(12)));
                assert!(matches!(c.day_of_month, CronField::Any));
                assert!(matches!(c.month, CronField::Any));
                assert!(matches!(c.day_of_week, CronField::Any));
            }
            _ => panic!("expected cron"),
        }
    }

    #[test]
    fn parse_invalid_returns_none() {
        assert!(parse_schedule("invalid").is_none());
        assert!(parse_schedule("rate()").is_none());
        assert!(parse_schedule("rate(abc minutes)").is_none());
        assert!(parse_schedule("cron(1 2 3)").is_none());
    }

    #[test]
    fn parse_rate_zero_is_valid() {
        let s = parse_schedule("rate(0 seconds)");
        assert!(matches!(s, Some(Schedule::Rate(d)) if d == Duration::ZERO));
    }

    #[test]
    fn parse_rate_unknown_unit_rejected() {
        assert!(parse_schedule("rate(1 fortnight)").is_none());
    }

    #[test]
    fn parse_cron_question_mark_is_any() {
        let s = parse_schedule("cron(? ? ? ? ? ?)");
        assert!(matches!(s, Some(Schedule::Cron(_))));
    }

    #[test]
    fn parse_cron_non_numeric_field_is_any() {
        let s = parse_schedule("cron(xyz 12 * * ? *)");
        match s {
            Some(Schedule::Cron(c)) => assert!(matches!(c.minute, CronField::Any)),
            _ => panic!("expected cron"),
        }
    }

    #[test]
    fn cron_wildcard_always_matches() {
        let cron = CronExpr {
            minute: CronField::Any,
            hour: CronField::Any,
            day_of_month: CronField::Any,
            month: CronField::Any,
            day_of_week: CronField::Any,
        };
        assert!(cron_matches_now(&cron));
    }

    #[test]
    fn cron_impossible_minute_never_matches() {
        let cron = CronExpr {
            minute: CronField::Value(99),
            hour: CronField::Any,
            day_of_month: CronField::Any,
            month: CronField::Any,
            day_of_week: CronField::Any,
        };
        assert!(!cron_matches_now(&cron));
    }

    mod tick_tests {
        use super::*;
        use crate::state::{
            EventBridgeState, EventRule, EventTarget as EbTarget, RuleKey, SharedEventBridgeState,
        };
        use fakecloud_core::delivery::{
            EventBridgeDelivery, KinesisDelivery, SnsDelivery, SqsDelivery, StepFunctionsDelivery,
        };
        use parking_lot::RwLock;
        use std::sync::Mutex;

        #[derive(Default)]
        struct Recorder {
            sqs: Mutex<Vec<(String, String)>>,
            sns: Mutex<Vec<(String, String)>>,
            stepfunctions: Mutex<Vec<(String, String)>>,
        }

        impl SqsDelivery for Recorder {
            fn deliver_to_queue(&self, arn: &str, body: &str, _attrs: &HashMap<String, String>) {
                self.sqs
                    .lock()
                    .unwrap()
                    .push((arn.to_string(), body.to_string()));
            }

            fn deliver_to_queue_with_attrs(
                &self,
                arn: &str,
                body: &str,
                _attrs: &HashMap<String, fakecloud_core::delivery::SqsMessageAttribute>,
                _group: Option<&str>,
                _dedup: Option<&str>,
            ) {
                self.sqs
                    .lock()
                    .unwrap()
                    .push((arn.to_string(), body.to_string()));
            }
        }

        impl SnsDelivery for Recorder {
            fn publish_to_topic(&self, arn: &str, msg: &str, _subject: Option<&str>) {
                self.sns
                    .lock()
                    .unwrap()
                    .push((arn.to_string(), msg.to_string()));
            }
        }

        impl StepFunctionsDelivery for Recorder {
            fn start_execution(&self, arn: &str, input: &str) {
                self.stepfunctions
                    .lock()
                    .unwrap()
                    .push((arn.to_string(), input.to_string()));
            }
        }

        impl EventBridgeDelivery for Recorder {
            fn put_event(&self, _source: &str, _detail_type: &str, _detail: &str, _bus: &str) {}
        }

        impl KinesisDelivery for Recorder {
            fn put_record(&self, _stream_arn: &str, _data: &str, _partition_key: &str) {}
        }

        fn make_state() -> (SharedEventBridgeState, EventBridgeState) {
            let state = EventBridgeState::new("123456789012", "us-east-1");
            let shared = Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            ));
            (shared, state)
        }

        fn make_rule(name: &str, schedule: &str, target_arn: &str) -> EventRule {
            EventRule {
                name: name.to_string(),
                arn: format!("arn:aws:events:us-east-1:123456789012:rule/{name}"),
                event_bus_name: "default".to_string(),
                event_pattern: None,
                schedule_expression: Some(schedule.to_string()),
                state: "ENABLED".to_string(),
                description: None,
                role_arn: None,
                managed_by: None,
                created_by: None,
                targets: vec![EbTarget {
                    id: "t1".to_string(),
                    arn: target_arn.to_string(),
                    input: None,
                    input_path: None,
                    input_transformer: None,
                    sqs_parameters: None,
                }],
                tags: BTreeMap::new(),
                last_fired: None,
            }
        }

        fn build_scheduler(state: SharedEventBridgeState, recorder: Arc<Recorder>) -> Scheduler {
            let bus = Arc::new(
                DeliveryBus::new()
                    .with_sqs(recorder.clone())
                    .with_sns(recorder.clone())
                    .with_stepfunctions(recorder.clone()),
            );
            Scheduler::new(state, bus)
        }

        #[test]
        fn tick_disabled_rule_is_skipped() {
            let (shared, _) = make_state();
            {
                let mut s_accounts = shared.write();
                let s = s_accounts.default_mut();
                let mut rule = make_rule("r", "rate(1 second)", "arn:aws:sqs:us-east-1:123:q");
                rule.state = "DISABLED".to_string();
                s.rules
                    .insert(("default".to_string(), "r".to_string()), rule);
            }
            let recorder = Arc::new(Recorder::default());
            let scheduler = build_scheduler(shared.clone(), recorder.clone());
            let mut last = HashMap::<RuleKey, (u32, u32)>::new();
            scheduler.tick(&mut last);
            assert!(recorder.sqs.lock().unwrap().is_empty());
        }

        #[test]
        fn tick_rule_without_targets_is_skipped() {
            let (shared, _) = make_state();
            {
                let mut s_accounts = shared.write();
                let s = s_accounts.default_mut();
                let mut rule = make_rule("r", "rate(1 second)", "arn:aws:sqs:us-east-1:123:q");
                rule.targets.clear();
                s.rules
                    .insert(("default".to_string(), "r".to_string()), rule);
            }
            let recorder = Arc::new(Recorder::default());
            let scheduler = build_scheduler(shared.clone(), recorder.clone());
            let mut last = HashMap::<RuleKey, (u32, u32)>::new();
            scheduler.tick(&mut last);
            assert!(recorder.sqs.lock().unwrap().is_empty());
        }

        #[test]
        fn tick_invalid_schedule_is_skipped() {
            let (shared, _) = make_state();
            {
                let mut s_accounts = shared.write();
                let s = s_accounts.default_mut();
                let rule = make_rule("r", "bogus", "arn:aws:sqs:us-east-1:123:q");
                s.rules
                    .insert(("default".to_string(), "r".to_string()), rule);
            }
            let recorder = Arc::new(Recorder::default());
            let scheduler = build_scheduler(shared.clone(), recorder.clone());
            let mut last = HashMap::<RuleKey, (u32, u32)>::new();
            scheduler.tick(&mut last);
            assert!(recorder.sqs.lock().unwrap().is_empty());
        }

        #[test]
        fn tick_fires_rate_rule_to_sqs_target() {
            let (shared, _) = make_state();
            let q_arn = "arn:aws:sqs:us-east-1:123456789012:q1".to_string();
            {
                let mut s_accounts = shared.write();
                let s = s_accounts.default_mut();
                let rule = make_rule("r", "rate(1 second)", &q_arn);
                s.rules
                    .insert(("default".to_string(), "r".to_string()), rule);
            }
            let recorder = Arc::new(Recorder::default());
            let scheduler = build_scheduler(shared.clone(), recorder.clone());
            let mut last = HashMap::<RuleKey, (u32, u32)>::new();
            scheduler.tick(&mut last);
            let calls = recorder.sqs.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0, q_arn);
            let payload: serde_json::Value = serde_json::from_str(&calls[0].1).unwrap();
            assert_eq!(payload["detail-type"], "Scheduled Event");
            assert_eq!(payload["source"], "aws.events");
        }

        #[test]
        fn tick_fires_to_sns_target() {
            let (shared, _) = make_state();
            let topic_arn = "arn:aws:sns:us-east-1:123456789012:t1".to_string();
            {
                let mut s_accounts = shared.write();
                let s = s_accounts.default_mut();
                let rule = make_rule("r", "rate(1 second)", &topic_arn);
                s.rules
                    .insert(("default".to_string(), "r".to_string()), rule);
            }
            let recorder = Arc::new(Recorder::default());
            let scheduler = build_scheduler(shared.clone(), recorder.clone());
            let mut last = HashMap::<RuleKey, (u32, u32)>::new();
            scheduler.tick(&mut last);
            let calls = recorder.sns.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0, topic_arn);
        }

        #[test]
        fn tick_fires_to_stepfunctions_target() {
            let (shared, _) = make_state();
            let sm_arn = "arn:aws:states:us-east-1:123456789012:stateMachine:m1".to_string();
            {
                let mut s_accounts = shared.write();
                let s = s_accounts.default_mut();
                let rule = make_rule("r", "rate(1 second)", &sm_arn);
                s.rules
                    .insert(("default".to_string(), "r".to_string()), rule);
            }
            let recorder = Arc::new(Recorder::default());
            let scheduler = build_scheduler(shared.clone(), recorder.clone());
            let mut last = HashMap::<RuleKey, (u32, u32)>::new();
            scheduler.tick(&mut last);
            let calls = recorder.stepfunctions.lock().unwrap();
            assert_eq!(calls.len(), 1);
            assert_eq!(calls[0].0, sm_arn);
            let _mas = shared.read();
            let guard = _mas.default_ref();

            assert_eq!(guard.step_function_executions.len(), 1);
        }

        #[test]
        fn tick_lambda_target_records_invocation() {
            let (shared, _) = make_state();
            let fn_arn = "arn:aws:lambda:us-east-1:123456789012:function:F".to_string();
            {
                let mut s_accounts = shared.write();
                let s = s_accounts.default_mut();
                let rule = make_rule("r", "rate(1 second)", &fn_arn);
                s.rules
                    .insert(("default".to_string(), "r".to_string()), rule);
            }
            let recorder = Arc::new(Recorder::default());
            let scheduler = build_scheduler(shared.clone(), recorder.clone());
            let mut last = HashMap::<RuleKey, (u32, u32)>::new();
            scheduler.tick(&mut last);
            let _mas = shared.read();
            let guard = _mas.default_ref();

            assert_eq!(guard.lambda_invocations.len(), 1);
            assert_eq!(guard.lambda_invocations[0].function_arn, fn_arn);
        }

        #[test]
        fn tick_logs_target_records_delivery() {
            let (shared, _) = make_state();
            let lg_arn = "arn:aws:logs:us-east-1:123456789012:log-group:lg".to_string();
            {
                let mut s_accounts = shared.write();
                let s = s_accounts.default_mut();
                let rule = make_rule("r", "rate(1 second)", &lg_arn);
                s.rules
                    .insert(("default".to_string(), "r".to_string()), rule);
            }
            let recorder = Arc::new(Recorder::default());
            let scheduler = build_scheduler(shared.clone(), recorder.clone());
            let mut last = HashMap::<RuleKey, (u32, u32)>::new();
            scheduler.tick(&mut last);
            let _mas = shared.read();
            let guard = _mas.default_ref();

            assert_eq!(guard.log_deliveries.len(), 1);
            assert_eq!(guard.log_deliveries[0].log_group_arn, lg_arn);
        }

        #[test]
        fn tick_updates_last_fired() {
            let (shared, _) = make_state();
            {
                let mut s_accounts = shared.write();
                let s = s_accounts.default_mut();
                let rule = make_rule("r", "rate(1 second)", "arn:aws:sqs:us-east-1:123:q");
                s.rules
                    .insert(("default".to_string(), "r".to_string()), rule);
            }
            let recorder = Arc::new(Recorder::default());
            let scheduler = build_scheduler(shared.clone(), recorder.clone());
            let mut last = HashMap::<RuleKey, (u32, u32)>::new();
            scheduler.tick(&mut last);
            let _mas = shared.read();
            let guard = _mas.default_ref();

            let rule = guard
                .rules
                .get(&("default".to_string(), "r".to_string()))
                .unwrap();
            assert!(rule.last_fired.is_some());
        }
    }
}
