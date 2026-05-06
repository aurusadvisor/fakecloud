//! Background watcher that consumes CloudWatch metric samples and
//! applies scaling decisions to real resources (today: DynamoDB).
//!
//! On each tick we walk every scaling policy:
//!  - `TargetTrackingScaling`: look up the predefined metric, divide
//!    the latest sample by the configured `TargetValue`, and resize
//!    the DDB table so utilisation tracks the target. Honours
//!    `ScaleInCooldown` / `ScaleOutCooldown`.
//!  - `StepScaling`: poll the configured alarm state. When the alarm
//!    is in `ALARM`, walk the step adjustments and apply the matching
//!    one to the DDB table. Honours `Cooldown`.
//!
//! Every applied or skipped decision lands as a `ScalingActivity`
//! row so `DescribeScalingActivities` shows real history.

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use serde_json::Value;
use uuid::Uuid;

use crate::hooks::{DynamoDbCapacityHook, MetricReader};
use crate::state::{
    NotScaledReason, ScalableTarget, ScalingActivity, ScalingPolicy,
    SharedApplicationAutoScalingState,
};

/// AWS dimension strings for DynamoDB capacity scaling targets.
pub const DDB_READ_DIM: &str = "dynamodb:table:ReadCapacityUnits";
pub const DDB_WRITE_DIM: &str = "dynamodb:table:WriteCapacityUnits";

/// Predefined CloudWatch metric types Application Auto Scaling knows
/// for DynamoDB.
const DDB_READ_METRIC: &str = "DynamoDBReadCapacityUtilization";
const DDB_WRITE_METRIC: &str = "DynamoDBWriteCapacityUtilization";

/// Default region used to resolve metrics when a target was registered
/// without a region context. Application Auto Scaling targets are
/// regional in AWS, but our state only carries the account on the
/// target itself; the watcher is wired with the server's default
/// region so DDB lookups still resolve.
pub struct ScalingWatcher {
    state: SharedApplicationAutoScalingState,
    metric_reader: Arc<dyn MetricReader>,
    ddb_hook: Arc<dyn DynamoDbCapacityHook>,
    region: String,
    interval: Duration,
}

impl ScalingWatcher {
    pub fn new(
        state: SharedApplicationAutoScalingState,
        metric_reader: Arc<dyn MetricReader>,
        ddb_hook: Arc<dyn DynamoDbCapacityHook>,
        region: impl Into<String>,
    ) -> Self {
        Self {
            state,
            metric_reader,
            ddb_hook,
            region: region.into(),
            interval: Duration::from_secs(15),
        }
    }

    pub fn with_interval(mut self, interval: Duration) -> Self {
        self.interval = interval;
        self
    }

    /// Drive a single tick. Exposed for the admin endpoint and tests so
    /// callers don't have to wait on the wall-clock interval.
    pub fn tick_once(&self) -> usize {
        let mut applied = 0;
        // Collect (account, policy_clone, target_clone) snapshots first so
        // we can release the read lock before running the hooks (which may
        // themselves take other locks via the server wiring).
        struct Job {
            account_id: String,
            policy: ScalingPolicy,
            target: ScalableTarget,
            current: i64,
        }
        let mut jobs: Vec<Job> = Vec::new();
        {
            let guard = self.state.read();
            for (account_id, account) in guard.accounts.iter() {
                for policy in account.scaling_policies.values() {
                    if policy.service_namespace != "dynamodb" {
                        continue;
                    }
                    let key = (
                        policy.service_namespace.clone(),
                        policy.resource_id.clone(),
                        policy.scalable_dimension.clone(),
                    );
                    let Some(target) = account.scalable_targets.get(&key) else {
                        continue;
                    };
                    if suspended_for(target, policy) {
                        continue;
                    }
                    let Some(table) = ddb_table_from_resource(&policy.resource_id) else {
                        continue;
                    };
                    let Some((read_cur, write_cur)) =
                        self.ddb_hook
                            .current_capacity(account_id, &self.region, table)
                    else {
                        continue;
                    };
                    let current = match policy.scalable_dimension.as_str() {
                        DDB_READ_DIM => read_cur,
                        DDB_WRITE_DIM => write_cur,
                        _ => continue,
                    };
                    jobs.push(Job {
                        account_id: account_id.clone(),
                        policy: policy.clone(),
                        target: target.clone(),
                        current,
                    });
                }
            }
        }

        for job in jobs {
            if self.process_policy(&job.account_id, &job.policy, &job.target, job.current) {
                applied += 1;
            }
        }
        applied
    }

    /// Long-running loop that ticks at `self.interval` until the
    /// process exits.
    pub async fn run(self) {
        let mut interval = tokio::time::interval(self.interval);
        // Skip the immediate first tick — the server is still wiring
        // services up.
        interval.tick().await;
        loop {
            interval.tick().await;
            let _ = self.tick_once();
        }
    }

    fn process_policy(
        &self,
        account_id: &str,
        policy: &ScalingPolicy,
        target: &ScalableTarget,
        current: i64,
    ) -> bool {
        match policy.policy_type.as_str() {
            "TargetTrackingScaling" => {
                self.process_target_tracking(account_id, policy, target, current)
            }
            "StepScaling" => self.process_step_scaling(account_id, policy, target, current),
            _ => false,
        }
    }

    fn process_target_tracking(
        &self,
        account_id: &str,
        policy: &ScalingPolicy,
        target: &ScalableTarget,
        current: i64,
    ) -> bool {
        let Some(cfg) = policy.target_tracking_scaling_policy_configuration.as_ref() else {
            return false;
        };
        let target_value = cfg.get("TargetValue").and_then(Value::as_f64);
        let Some(target_value) = target_value else {
            return false;
        };
        if target_value <= 0.0 {
            return false;
        }
        let Some(metric_name) = predefined_metric_for(cfg, &policy.scalable_dimension) else {
            return false;
        };
        let Some(table) = ddb_table_from_resource(&policy.resource_id) else {
            return false;
        };
        let mut dims = BTreeMap::new();
        dims.insert("TableName".to_string(), table.to_string());
        let utilisation = self.metric_reader.latest_sample(
            account_id,
            &self.region,
            "AWS/DynamoDB",
            metric_name,
            &dims,
        );
        let Some(utilisation) = utilisation else {
            return false;
        };

        // desired = current * (utilisation / target_value), then
        // clamped to [min, max] and rounded up so we don't drop below
        // the bound a fractional capacity implies.
        let raw = (current as f64) * (utilisation / target_value);
        let mut desired = raw.ceil() as i64;
        if desired < target.min_capacity as i64 {
            desired = target.min_capacity as i64;
        }
        if desired > target.max_capacity as i64 {
            desired = target.max_capacity as i64;
        }
        if desired == current {
            return false;
        }

        let scale_out = desired > current;
        let cooldown_secs = cfg
            .get(if scale_out {
                "ScaleOutCooldown"
            } else {
                "ScaleInCooldown"
            })
            .and_then(Value::as_i64)
            .unwrap_or(0);
        if let Some(prev) = policy.last_applied_at {
            if cooldown_secs > 0
                && Utc::now().signed_duration_since(prev).num_seconds() < cooldown_secs
            {
                self.record_cooldown_skip(
                    account_id,
                    policy,
                    target,
                    current,
                    desired,
                    "TargetTracking",
                );
                return false;
            }
        }

        self.apply_ddb_capacity(
            account_id,
            policy,
            target,
            current,
            desired,
            "TargetTracking",
        )
    }

    fn process_step_scaling(
        &self,
        account_id: &str,
        policy: &ScalingPolicy,
        target: &ScalableTarget,
        current: i64,
    ) -> bool {
        let Some(cfg) = policy.step_scaling_policy_configuration.as_ref() else {
            return false;
        };
        let adjustment_type = cfg
            .get("AdjustmentType")
            .and_then(Value::as_str)
            .unwrap_or("ChangeInCapacity")
            .to_string();
        let cooldown_secs = cfg.get("Cooldown").and_then(Value::as_i64).unwrap_or(0);

        // Step scaling fires off CloudWatch alarm transitions. There
        // are two paths to discover the firing alarm:
        //   1. `policy.alarms` — populated by tests / future wiring
        //      where alarms are explicitly attached to the policy.
        //   2. CloudWatch alarms whose `AlarmActions` list contains
        //      this policy's ARN — the canonical AWS model: customers
        //      `PutMetricAlarm` with the policy ARN as an action and
        //      the alarm transition fires the policy. We resolve that
        //      via the metric reader to keep this crate decoupled
        //      from the cloudwatch state.
        let attached_in_alarm = policy.alarms.iter().any(|a| {
            self.metric_reader
                .alarm_state(account_id, &self.region, &a.alarm_name)
                .as_deref()
                == Some("ALARM")
        });
        let action_alarms_firing =
            self.metric_reader
                .alarms_firing_for_action(account_id, &self.region, &policy.arn);
        if !attached_in_alarm && action_alarms_firing.is_empty() {
            return false;
        }

        // Pick the first step adjustment whose lower bound matches.
        // Real AWS computes a "metric interval" relative to the alarm
        // threshold; for the fakecloud watcher we approximate with the
        // configured lower bound (treating the alarm fire itself as
        // the breach signal).
        let adjustments = cfg
            .get("StepAdjustments")
            .and_then(Value::as_array)
            .cloned()
            .unwrap_or_default();
        let Some(adj) = adjustments.first() else {
            return false;
        };
        let adjustment = adj
            .get("ScalingAdjustment")
            .and_then(Value::as_i64)
            .unwrap_or(0);
        if adjustment == 0 {
            return false;
        }
        let mut desired = match adjustment_type.as_str() {
            "ExactCapacity" => adjustment,
            "PercentChangeInCapacity" => {
                let pct = adjustment as f64 / 100.0;
                let delta = (current as f64 * pct).round() as i64;
                let min_step = cfg
                    .get("MinAdjustmentMagnitude")
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                let signed_delta = if delta == 0 && adjustment != 0 {
                    if adjustment > 0 {
                        1
                    } else {
                        -1
                    }
                } else {
                    delta
                };
                let bumped = if signed_delta.abs() < min_step {
                    if signed_delta >= 0 {
                        min_step
                    } else {
                        -min_step
                    }
                } else {
                    signed_delta
                };
                current + bumped
            }
            _ => current + adjustment, // ChangeInCapacity
        };
        if desired < target.min_capacity as i64 {
            desired = target.min_capacity as i64;
        }
        if desired > target.max_capacity as i64 {
            desired = target.max_capacity as i64;
        }
        if desired == current {
            return false;
        }
        if let Some(prev) = policy.last_applied_at {
            if cooldown_secs > 0
                && Utc::now().signed_duration_since(prev).num_seconds() < cooldown_secs
            {
                self.record_cooldown_skip(
                    account_id,
                    policy,
                    target,
                    current,
                    desired,
                    "StepScaling",
                );
                return false;
            }
        }

        self.apply_ddb_capacity(account_id, policy, target, current, desired, "StepScaling")
    }

    fn apply_ddb_capacity(
        &self,
        account_id: &str,
        policy: &ScalingPolicy,
        target: &ScalableTarget,
        current: i64,
        desired: i64,
        cause_kind: &str,
    ) -> bool {
        let Some(table) = ddb_table_from_resource(&policy.resource_id) else {
            return false;
        };
        let (read, write) = match policy.scalable_dimension.as_str() {
            DDB_READ_DIM => (Some(desired), None),
            DDB_WRITE_DIM => (None, Some(desired)),
            _ => return false,
        };
        let now = Utc::now();
        let result = self
            .ddb_hook
            .set_capacity(account_id, &self.region, table, read, write);

        let mut state = self.state.write();
        let account = state.accounts.entry(account_id.to_string()).or_default();
        // Refresh the policy's last_applied_at on success so cooldowns
        // trigger; on failure leave it untouched so the next tick can
        // retry without waiting for the cooldown.
        let policy_key = (
            policy.service_namespace.clone(),
            policy.resource_id.clone(),
            policy.scalable_dimension.clone(),
            policy.policy_name.clone(),
        );
        let activity = match result {
            Ok(()) => {
                if let Some(p) = account.scaling_policies.get_mut(&policy_key) {
                    p.last_applied_at = Some(now);
                }
                ScalingActivity {
                    activity_id: Uuid::new_v4().to_string(),
                    service_namespace: policy.service_namespace.clone(),
                    resource_id: policy.resource_id.clone(),
                    scalable_dimension: policy.scalable_dimension.clone(),
                    description: format!(
                        "Setting {direction} capacity to {desired} for {res}",
                        direction = if desired > current { "min" } else { "max" },
                        res = policy.resource_id,
                    ),
                    cause: format!(
                        "policy {policy_name} ({cause_kind}) applied; previous capacity {current}",
                        policy_name = policy.policy_name,
                    ),
                    start_time: now,
                    end_time: Some(now),
                    status_code: "Successful".to_string(),
                    status_message: Some(format!("Successfully set {desired}")),
                    details: None,
                    not_scaled_reasons: Vec::new(),
                }
            }
            Err(err) => ScalingActivity {
                activity_id: Uuid::new_v4().to_string(),
                service_namespace: policy.service_namespace.clone(),
                resource_id: policy.resource_id.clone(),
                scalable_dimension: policy.scalable_dimension.clone(),
                description: format!(
                    "Failed to set capacity to {desired} for {res}",
                    res = policy.resource_id,
                ),
                cause: format!(
                    "policy {policy_name} ({cause_kind}) failed",
                    policy_name = policy.policy_name,
                ),
                start_time: now,
                end_time: Some(now),
                status_code: "Failed".to_string(),
                status_message: Some(err),
                details: None,
                not_scaled_reasons: vec![NotScaledReason {
                    code: "FailedToProvisionCapacity".to_string(),
                    max_capacity: Some(target.max_capacity),
                    min_capacity: Some(target.min_capacity),
                    current_capacity: Some(current as i32),
                }],
            },
        };
        let success = activity.status_code == "Successful";
        account.scaling_activities.push(activity);
        success
    }

    fn record_cooldown_skip(
        &self,
        account_id: &str,
        policy: &ScalingPolicy,
        target: &ScalableTarget,
        current: i64,
        desired: i64,
        cause_kind: &str,
    ) {
        let now = Utc::now();
        let mut state = self.state.write();
        let account = state.accounts.entry(account_id.to_string()).or_default();
        account.scaling_activities.push(ScalingActivity {
            activity_id: Uuid::new_v4().to_string(),
            service_namespace: policy.service_namespace.clone(),
            resource_id: policy.resource_id.clone(),
            scalable_dimension: policy.scalable_dimension.clone(),
            description: format!(
                "Skipping scale {direction} to {desired} on {res} (cooldown)",
                direction = if desired > current { "out" } else { "in" },
                res = policy.resource_id,
            ),
            cause: format!(
                "policy {policy_name} ({cause_kind}) within cooldown",
                policy_name = policy.policy_name,
            ),
            start_time: now,
            end_time: Some(now),
            status_code: "Failed".to_string(),
            status_message: Some("Cooldown in effect".to_string()),
            details: None,
            not_scaled_reasons: vec![NotScaledReason {
                code: "Cooldown".to_string(),
                max_capacity: Some(target.max_capacity),
                min_capacity: Some(target.min_capacity),
                current_capacity: Some(current as i32),
            }],
        });
    }
}

fn predefined_metric_for(cfg: &Value, dimension: &str) -> Option<&'static str> {
    let predefined = cfg.get("PredefinedMetricSpecification")?;
    let metric_type = predefined.get("PredefinedMetricType")?.as_str()?;
    match metric_type {
        "DynamoDBReadCapacityUtilization" => Some(DDB_READ_METRIC),
        "DynamoDBWriteCapacityUtilization" => Some(DDB_WRITE_METRIC),
        _ => match dimension {
            DDB_READ_DIM => Some(DDB_READ_METRIC),
            DDB_WRITE_DIM => Some(DDB_WRITE_METRIC),
            _ => None,
        },
    }
}

fn ddb_table_from_resource(resource_id: &str) -> Option<&str> {
    // Resource format: "table/<name>" or "table/<name>/index/<idx>".
    let rest = resource_id.strip_prefix("table/")?;
    Some(rest.split('/').next().unwrap_or(rest))
}

/// Same as `ddb_table_from_resource`, but visible to sibling modules
/// (`scheduled_executor`) so we don't duplicate the parsing rule.
pub(crate) fn ddb_table_from_resource_public(resource_id: &str) -> Option<&str> {
    ddb_table_from_resource(resource_id)
}

fn suspended_for(target: &ScalableTarget, policy: &ScalingPolicy) -> bool {
    let Some(s) = target.suspended_state.as_ref() else {
        return false;
    };
    // Treat a fully suspended target as opt-out for both directions.
    // The watcher can't tell yet whether a single tick will scale in or
    // out, so we suspend when either side is paused.
    let in_sus = s.dynamic_scaling_in_suspended.unwrap_or(false);
    let out_sus = s.dynamic_scaling_out_suspended.unwrap_or(false);
    if !in_sus && !out_sus {
        return false;
    }
    // Step scaling alarms set scale-out semantics; assume out for both
    // policy types unless the policy is explicitly only one direction.
    let _ = policy;
    in_sus && out_sus
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{
        Alarm, ApplicationAutoScalingAccounts, ScalableTarget, ScalingPolicy,
        SharedApplicationAutoScalingState,
    };
    use parking_lot::RwLock;
    use serde_json::json;
    use std::collections::BTreeMap;
    use std::sync::atomic::{AtomicI64, Ordering};
    use std::sync::Mutex;

    struct StubMetric {
        value: f64,
        alarm_state: Option<String>,
    }
    impl MetricReader for StubMetric {
        fn latest_sample(
            &self,
            _account: &str,
            _region: &str,
            _ns: &str,
            _name: &str,
            _dims: &BTreeMap<String, String>,
        ) -> Option<f64> {
            Some(self.value)
        }
        fn alarm_state(&self, _account: &str, _region: &str, _alarm: &str) -> Option<String> {
            self.alarm_state.clone()
        }
        fn alarms_firing_for_action(
            &self,
            _account: &str,
            _region: &str,
            _policy_arn: &str,
        ) -> Vec<String> {
            Vec::new()
        }
    }

    struct StubDdb {
        read: AtomicI64,
        write: AtomicI64,
        calls: Mutex<Vec<(Option<i64>, Option<i64>)>>,
    }
    impl DynamoDbCapacityHook for StubDdb {
        fn current_capacity(&self, _a: &str, _r: &str, _t: &str) -> Option<(i64, i64)> {
            Some((
                self.read.load(Ordering::Relaxed),
                self.write.load(Ordering::Relaxed),
            ))
        }
        fn set_capacity(
            &self,
            _a: &str,
            _r: &str,
            _t: &str,
            read: Option<i64>,
            write: Option<i64>,
        ) -> Result<(), String> {
            if let Some(r) = read {
                self.read.store(r, Ordering::Relaxed);
            }
            if let Some(w) = write {
                self.write.store(w, Ordering::Relaxed);
            }
            self.calls.lock().unwrap().push((read, write));
            Ok(())
        }
    }

    fn fixture(
        ddb_read: i64,
    ) -> (
        SharedApplicationAutoScalingState,
        Arc<StubDdb>,
        Arc<StubMetric>,
    ) {
        let state: SharedApplicationAutoScalingState =
            Arc::new(RwLock::new(ApplicationAutoScalingAccounts::new()));
        let now = Utc::now();
        {
            let mut guard = state.write();
            let acct = guard
                .accounts
                .entry("123456789012".to_string())
                .or_default();
            acct.scalable_targets.insert(
                (
                    "dynamodb".to_string(),
                    "table/orders".to_string(),
                    DDB_READ_DIM.to_string(),
                ),
                ScalableTarget {
                    arn: "arn:aws:application-autoscaling:::scalable-target/abc".to_string(),
                    service_namespace: "dynamodb".to_string(),
                    resource_id: "table/orders".to_string(),
                    scalable_dimension: DDB_READ_DIM.to_string(),
                    min_capacity: 5,
                    max_capacity: 100,
                    role_arn: "role".to_string(),
                    creation_time: now,
                    suspended_state: None,
                    predicted_capacity: None,
                },
            );
        }
        let hook = Arc::new(StubDdb {
            read: AtomicI64::new(ddb_read),
            write: AtomicI64::new(5),
            calls: Mutex::new(Vec::new()),
        });
        let metric = Arc::new(StubMetric {
            value: 90.0,
            alarm_state: None,
        });
        (state, hook, metric)
    }

    #[test]
    fn target_tracking_scales_out_to_match_target() {
        let (state, ddb, metric) = fixture(10);
        {
            let mut guard = state.write();
            let acct = guard.accounts.get_mut("123456789012").unwrap();
            acct.scaling_policies.insert(
                (
                    "dynamodb".to_string(),
                    "table/orders".to_string(),
                    DDB_READ_DIM.to_string(),
                    "tt".to_string(),
                ),
                ScalingPolicy {
                    arn: "arn:p".to_string(),
                    policy_name: "tt".to_string(),
                    service_namespace: "dynamodb".to_string(),
                    resource_id: "table/orders".to_string(),
                    scalable_dimension: DDB_READ_DIM.to_string(),
                    policy_type: "TargetTrackingScaling".to_string(),
                    creation_time: Utc::now(),
                    step_scaling_policy_configuration: None,
                    target_tracking_scaling_policy_configuration: Some(json!({
                        "TargetValue": 60.0,
                        "PredefinedMetricSpecification": {
                            "PredefinedMetricType": "DynamoDBReadCapacityUtilization"
                        },
                    })),
                    predictive_scaling_policy_configuration: None,
                    alarms: vec![],
                    last_applied_at: None,
                },
            );
        }
        let watcher = ScalingWatcher::new(state.clone(), metric, ddb.clone(), "us-east-1");
        let applied = watcher.tick_once();
        assert_eq!(applied, 1, "should scale out once");
        // utilisation 90, target 60 => factor 1.5, current 10 => desired 15.
        assert_eq!(ddb.read.load(Ordering::Relaxed), 15);
    }

    #[test]
    fn step_scaling_applies_when_alarm_fires() {
        let (state, ddb, _) = fixture(10);
        {
            let mut guard = state.write();
            let acct = guard.accounts.get_mut("123456789012").unwrap();
            acct.scaling_policies.insert(
                (
                    "dynamodb".to_string(),
                    "table/orders".to_string(),
                    DDB_READ_DIM.to_string(),
                    "step".to_string(),
                ),
                ScalingPolicy {
                    arn: "arn:p".to_string(),
                    policy_name: "step".to_string(),
                    service_namespace: "dynamodb".to_string(),
                    resource_id: "table/orders".to_string(),
                    scalable_dimension: DDB_READ_DIM.to_string(),
                    policy_type: "StepScaling".to_string(),
                    creation_time: Utc::now(),
                    step_scaling_policy_configuration: Some(json!({
                        "AdjustmentType": "ChangeInCapacity",
                        "StepAdjustments": [{
                            "MetricIntervalLowerBound": 0.0,
                            "ScalingAdjustment": 5,
                        }],
                    })),
                    target_tracking_scaling_policy_configuration: None,
                    predictive_scaling_policy_configuration: None,
                    alarms: vec![Alarm {
                        alarm_name: "burn".to_string(),
                        alarm_arn: "arn:aws:cloudwatch:::alarm/burn".to_string(),
                    }],
                    last_applied_at: None,
                },
            );
        }
        let metric = Arc::new(StubMetric {
            value: 0.0,
            alarm_state: Some("ALARM".to_string()),
        });
        let watcher = ScalingWatcher::new(state.clone(), metric, ddb.clone(), "us-east-1");
        let applied = watcher.tick_once();
        assert_eq!(applied, 1);
        assert_eq!(ddb.read.load(Ordering::Relaxed), 15);
    }

    #[test]
    fn target_tracking_no_change_when_at_target() {
        let (state, ddb, _) = fixture(10);
        {
            let mut guard = state.write();
            let acct = guard.accounts.get_mut("123456789012").unwrap();
            acct.scaling_policies.insert(
                (
                    "dynamodb".to_string(),
                    "table/orders".to_string(),
                    DDB_READ_DIM.to_string(),
                    "tt".to_string(),
                ),
                ScalingPolicy {
                    arn: "arn:p".to_string(),
                    policy_name: "tt".to_string(),
                    service_namespace: "dynamodb".to_string(),
                    resource_id: "table/orders".to_string(),
                    scalable_dimension: DDB_READ_DIM.to_string(),
                    policy_type: "TargetTrackingScaling".to_string(),
                    creation_time: Utc::now(),
                    step_scaling_policy_configuration: None,
                    target_tracking_scaling_policy_configuration: Some(json!({
                        "TargetValue": 70.0,
                        "PredefinedMetricSpecification": {
                            "PredefinedMetricType": "DynamoDBReadCapacityUtilization"
                        },
                    })),
                    predictive_scaling_policy_configuration: None,
                    alarms: vec![],
                    last_applied_at: None,
                },
            );
        }
        let metric = Arc::new(StubMetric {
            value: 70.0,
            alarm_state: None,
        });
        let watcher = ScalingWatcher::new(state, metric, ddb.clone(), "us-east-1");
        let applied = watcher.tick_once();
        assert_eq!(applied, 0);
        assert_eq!(ddb.read.load(Ordering::Relaxed), 10);
    }
}
