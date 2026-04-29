//! Background firing loop for EventBridge Scheduler.
//!
//! A single tokio task scans every enabled schedule once per second,
//! fires the ones whose expressions are due, updates `last_fired`, and
//! handles `ActionAfterCompletion=DELETE` for one-shot `at(...)` runs.
//! Delivery itself lives in `delivery.rs`.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Datelike, Timelike, Utc};

use fakecloud_core::delivery::DeliveryBus;

use crate::delivery::{deliver_target, route_to_dlq};
use crate::expr::{self, Expr};
use crate::state::{ScheduleKey, SharedSchedulerState};

pub struct Ticker {
    state: SharedSchedulerState,
    delivery: Arc<DeliveryBus>,
}

impl Ticker {
    pub fn new(state: SharedSchedulerState, delivery: Arc<DeliveryBus>) -> Self {
        Self { state, delivery }
    }

    pub async fn run(self) {
        let mut interval = tokio::time::interval(Duration::from_secs(1));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        // (hour, minute) pair of the last cron fire, keyed by schedule
        // identity — keeps cron schedules from firing multiple times
        // inside the same minute when the 1s tick runs 60+ times.
        let mut cron_last_minute: HashMap<(String, ScheduleKey), CronFireStamp> = HashMap::new();
        loop {
            interval.tick().await;
            self.tick(&mut cron_last_minute);
        }
    }

    fn tick(&self, cron_last_minute: &mut HashMap<(String, ScheduleKey), CronFireStamp>) {
        let now = Utc::now();
        // Phase 1: collect due schedules while holding a short write lock.
        let mut due: Vec<(String, ScheduleKey)> = Vec::new();
        let mut post_fire_actions: Vec<(String, ScheduleKey, PostFire)> = Vec::new();
        {
            let mut accounts = self.state.write();
            let account_ids: Vec<String> = accounts.iter().map(|(id, _)| id.to_string()).collect();
            for account_id in account_ids {
                let Some(state) = accounts.get_mut(&account_id) else {
                    continue;
                };
                let keys: Vec<ScheduleKey> = state.schedules.keys().cloned().collect();
                for key in keys {
                    let Some(sched) = state.schedules.get(&key) else {
                        continue;
                    };
                    if sched.state != "ENABLED" {
                        continue;
                    }
                    if let Some(end) = sched.end_date {
                        if now > end {
                            continue;
                        }
                    }
                    if let Some(start) = sched.start_date {
                        if now < start {
                            continue;
                        }
                    }
                    let Some(expr) = expr::parse(&sched.schedule_expression) else {
                        continue;
                    };
                    if !is_due_with_dedup(
                        &expr,
                        sched.last_fired,
                        now,
                        &(account_id.clone(), key.clone()),
                        cron_last_minute,
                    ) {
                        continue;
                    }
                    if let Some(sched_mut) = state.schedules.get_mut(&key) {
                        sched_mut.last_fired = Some(now);
                        let post = post_fire_action(&expr, sched_mut);
                        post_fire_actions.push((account_id.clone(), key.clone(), post));
                    }
                    due.push((account_id.clone(), key));
                }
            }
        }

        // Phase 2: deliver without holding the state lock.
        let mut fired: Vec<(String, ScheduleKey)> = Vec::with_capacity(due.len());
        for (account_id, key) in &due {
            let snapshot = {
                let accounts = self.state.read();
                accounts
                    .get(account_id)
                    .and_then(|s| s.schedules.get(key).cloned())
            };
            let Some(sched) = snapshot else {
                continue;
            };
            match deliver_target(&self.delivery, &sched) {
                Ok(()) => {
                    tracing::debug!(
                        schedule = %sched.name,
                        group = %sched.group_name,
                        target = %sched.target.arn,
                        "scheduler: fired"
                    );
                }
                Err(err) => {
                    route_to_dlq(
                        &self.delivery,
                        &sched,
                        "TargetDeliveryFailed",
                        &err.to_string(),
                    );
                }
            }
            fired.push((account_id.clone(), key.clone()));
        }

        // Phase 3: apply post-fire actions (DELETE on completion for at()).
        if !post_fire_actions.is_empty() {
            let mut accounts = self.state.write();
            for (account_id, key, post) in post_fire_actions {
                let Some(state) = accounts.get_mut(&account_id) else {
                    continue;
                };
                match post {
                    PostFire::Delete => {
                        state.schedules.remove(&key);
                    }
                    PostFire::None => {}
                }
            }
        }
    }
}

enum PostFire {
    None,
    Delete,
}

fn post_fire_action(expr: &Expr, schedule: &crate::state::Schedule) -> PostFire {
    if matches!(expr, Expr::At(_)) && schedule.action_after_completion == "DELETE" {
        PostFire::Delete
    } else {
        PostFire::None
    }
}

/// Identity of the last minute-slot a cron schedule fired in. Keyed
/// by full (year, ordinal, hour, minute) so subsequent days of the
/// same (hour, minute) are treated as fresh fires.
#[derive(Clone, Copy, PartialEq, Eq)]
struct CronFireStamp {
    year: i32,
    ordinal: u32,
    hour: u32,
    minute: u32,
}

impl CronFireStamp {
    fn from(now: DateTime<Utc>) -> Self {
        Self {
            year: now.year(),
            ordinal: now.ordinal(),
            hour: now.hour(),
            minute: now.minute(),
        }
    }
}

fn is_due_with_dedup(
    expr: &Expr,
    last_fired: Option<DateTime<Utc>>,
    now: DateTime<Utc>,
    key: &(String, ScheduleKey),
    cron_last_minute: &mut HashMap<(String, ScheduleKey), CronFireStamp>,
) -> bool {
    match expr {
        Expr::Cron(c) => {
            if !expr::matches_cron(c, now) {
                return false;
            }
            let current = CronFireStamp::from(now);
            if cron_last_minute.get(key) == Some(&current) {
                return false;
            }
            cron_last_minute.insert(key.clone(), current);
            true
        }
        _ => expr::is_due(expr, last_fired, now),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{FlexibleTimeWindow, Schedule, SharedSchedulerState, Target};
    use chrono::Utc;
    use fakecloud_core::delivery::{SqsDelivery, SqsDeliveryError, SqsMessageAttribute};
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::sync::Arc;
    use std::sync::Mutex;

    const ACCOUNT: &str = "111122223333";

    fn make_state() -> SharedSchedulerState {
        Arc::new(RwLock::new(
            fakecloud_core::multi_account::MultiAccountState::new(ACCOUNT, "us-east-1", ""),
        ))
    }

    fn seed_schedule(state: &SharedSchedulerState, name: &str, expr: &str, target_arn: &str) {
        let now = Utc::now();
        let mut accounts = state.write();
        let s = accounts.get_or_create(ACCOUNT);
        s.schedules.insert(
            ("default".to_string(), name.to_string()),
            Schedule {
                arn: format!("arn:aws:scheduler:us-east-1:{ACCOUNT}:schedule/default/{name}"),
                name: name.to_string(),
                group_name: "default".to_string(),
                schedule_expression: expr.to_string(),
                schedule_expression_timezone: None,
                start_date: None,
                end_date: None,
                description: None,
                state: "ENABLED".to_string(),
                kms_key_arn: None,
                action_after_completion: "NONE".to_string(),
                flexible_time_window: FlexibleTimeWindow::default(),
                target: Target {
                    arn: target_arn.to_string(),
                    role_arn: "arn:aws:iam::1:role/s".to_string(),
                    input: Some(r#"{"msg":"hello"}"#.to_string()),
                    dead_letter_config: None,
                    retry_policy: None,
                    sqs_parameters: None,
                    ecs_parameters: None,
                    eventbridge_parameters: None,
                    kinesis_parameters: None,
                    sagemaker_pipeline_parameters: None,
                },
                creation_date: now,
                last_modification_date: now,
                last_fired: None,
            },
        );
    }

    #[derive(Default)]
    struct Recorder {
        calls: Mutex<Vec<(String, String)>>,
    }
    impl SqsDelivery for Recorder {
        fn deliver_to_queue(&self, _arn: &str, _body: &str, _a: &HashMap<String, String>) {}

        fn try_deliver_to_queue_with_attrs(
            &self,
            queue_arn: &str,
            message_body: &str,
            _attrs: &HashMap<String, SqsMessageAttribute>,
            _g: Option<&str>,
            _d: Option<&str>,
        ) -> Result<(), SqsDeliveryError> {
            self.calls
                .lock()
                .unwrap()
                .push((queue_arn.to_string(), message_body.to_string()));
            Ok(())
        }
    }

    #[test]
    fn rate_schedule_fires_on_first_tick_and_delivers_input() {
        let state = make_state();
        seed_schedule(
            &state,
            "r",
            "rate(1 minute)",
            "arn:aws:sqs:us-east-1:111122223333:q",
        );
        let rec = Arc::new(Recorder::default());
        let bus = Arc::new(DeliveryBus::new().with_sqs(rec.clone()));
        let ticker = Ticker::new(state.clone(), bus);
        let mut cron = HashMap::new();
        ticker.tick(&mut cron);
        let calls = rec.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, "arn:aws:sqs:us-east-1:111122223333:q");
        assert_eq!(calls[0].1, r#"{"msg":"hello"}"#);
    }

    #[test]
    fn disabled_schedule_does_not_fire() {
        let state = make_state();
        seed_schedule(
            &state,
            "r",
            "rate(1 minute)",
            "arn:aws:sqs:us-east-1:111122223333:q",
        );
        {
            let mut accounts = state.write();
            let s = accounts.get_or_create(ACCOUNT);
            s.schedules
                .get_mut(&("default".to_string(), "r".to_string()))
                .unwrap()
                .state = "DISABLED".to_string();
        }
        let rec = Arc::new(Recorder::default());
        let bus = Arc::new(DeliveryBus::new().with_sqs(rec.clone()));
        let ticker = Ticker::new(state.clone(), bus);
        let mut cron = HashMap::new();
        ticker.tick(&mut cron);
        assert!(rec.calls.lock().unwrap().is_empty());
    }

    #[test]
    fn at_one_shot_with_delete_after_fire_removes_schedule() {
        let state = make_state();
        // `at(2000-01-01T00:00:00)` is always in the past so it fires on first tick.
        seed_schedule(
            &state,
            "once",
            "at(2000-01-01T00:00:00)",
            "arn:aws:sqs:us-east-1:111122223333:dest",
        );
        {
            let mut accounts = state.write();
            let s = accounts.get_or_create(ACCOUNT);
            s.schedules
                .get_mut(&("default".to_string(), "once".to_string()))
                .unwrap()
                .action_after_completion = "DELETE".to_string();
        }
        let rec = Arc::new(Recorder::default());
        let bus = Arc::new(DeliveryBus::new().with_sqs(rec.clone()));
        let ticker = Ticker::new(state.clone(), bus);
        let mut cron = HashMap::new();
        ticker.tick(&mut cron);
        assert_eq!(rec.calls.lock().unwrap().len(), 1);
        let accounts = state.read();
        let s = accounts.get(ACCOUNT).unwrap();
        assert!(!s
            .schedules
            .contains_key(&("default".to_string(), "once".to_string())));
    }

    #[test]
    fn dlq_receives_failed_delivery_with_headers() {
        let state = make_state();
        seed_schedule(
            &state,
            "dlqtest",
            "rate(1 minute)",
            "arn:aws:sqs:us-east-1:111122223333:missing",
        );
        {
            let mut accounts = state.write();
            let s = accounts.get_or_create(ACCOUNT);
            s.schedules
                .get_mut(&("default".to_string(), "dlqtest".to_string()))
                .unwrap()
                .target
                .dead_letter_config = Some(crate::state::DeadLetterConfig {
                arn: Some("arn:aws:sqs:us-east-1:111122223333:dlq".to_string()),
            });
        }

        // Recorder that fails on missing queue and records everything else.
        struct FailingRecorder {
            calls: Mutex<Vec<(String, HashMap<String, SqsMessageAttribute>)>>,
        }
        impl SqsDelivery for FailingRecorder {
            fn deliver_to_queue(&self, _a: &str, _b: &str, _c: &HashMap<String, String>) {}
            fn try_deliver_to_queue_with_attrs(
                &self,
                queue_arn: &str,
                _body: &str,
                attrs: &HashMap<String, SqsMessageAttribute>,
                _g: Option<&str>,
                _d: Option<&str>,
            ) -> Result<(), SqsDeliveryError> {
                if queue_arn.ends_with(":missing") {
                    return Err(SqsDeliveryError::QueueNotFound(queue_arn.to_string()));
                }
                self.calls
                    .lock()
                    .unwrap()
                    .push((queue_arn.to_string(), attrs.clone()));
                Ok(())
            }
        }

        let rec = Arc::new(FailingRecorder {
            calls: Mutex::new(Vec::new()),
        });
        let bus = Arc::new(DeliveryBus::new().with_sqs(rec.clone()));
        let ticker = Ticker::new(state.clone(), bus);
        let mut cron = HashMap::new();
        ticker.tick(&mut cron);
        let calls = rec.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert!(calls[0].0.ends_with(":dlq"));
        assert!(calls[0].1.contains_key("X-Amz-Scheduler-Attempt"));
    }

    #[test]
    fn end_date_past_prevents_firing() {
        let state = make_state();
        seed_schedule(
            &state,
            "ended",
            "rate(1 minute)",
            "arn:aws:sqs:us-east-1:111122223333:q",
        );
        {
            let mut accounts = state.write();
            let s = accounts.get_or_create(ACCOUNT);
            s.schedules
                .get_mut(&("default".to_string(), "ended".to_string()))
                .unwrap()
                .end_date = Some(Utc::now() - chrono::Duration::hours(1));
        }
        let rec = Arc::new(Recorder::default());
        let bus = Arc::new(DeliveryBus::new().with_sqs(rec.clone()));
        let ticker = Ticker::new(state.clone(), bus);
        let mut cron = HashMap::new();
        ticker.tick(&mut cron);
        assert!(rec.calls.lock().unwrap().is_empty());
    }
}
