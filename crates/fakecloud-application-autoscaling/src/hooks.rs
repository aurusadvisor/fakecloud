//! Cross-service hooks the Application Auto Scaling watcher uses to
//! observe metrics and apply scaling decisions on real resources.
//!
//! Each hook is an in-process trait so we don't introduce a circular
//! dependency back into the service crates that own the underlying
//! state (CloudWatch metrics, DynamoDB tables, etc.). The
//! `fakecloud-server` binary wires concrete impls at startup.

use std::collections::BTreeMap;

/// Reads the latest sample of a CloudWatch metric. Returns `None` when
/// the metric has no data points or the alarm/metric isn't wired.
///
/// `dimensions` matches the AWS metric dimensions exactly (e.g. for
/// DynamoDB `ReadCapacityUtilization`, `{TableName: "..."}`).
pub trait MetricReader: Send + Sync {
    fn latest_sample(
        &self,
        account_id: &str,
        region: &str,
        namespace: &str,
        metric_name: &str,
        dimensions: &BTreeMap<String, String>,
    ) -> Option<f64>;

    /// Returns the alarm's current state value (`OK` | `ALARM` |
    /// `INSUFFICIENT_DATA`) so step scaling policies can react when
    /// their action ARN is configured as an alarm action. Real AWS
    /// drives step scaling off SNS-style alarm action publishes; we
    /// poll the alarm state instead because that's what fakecloud
    /// already records.
    fn alarm_state(&self, account_id: &str, region: &str, alarm_name: &str) -> Option<String>;

    /// Returns the names of all alarms in the account+region whose
    /// `AlarmActions` list contains `policy_arn` and whose state is
    /// currently `ALARM`. Used by step scaling policies, which fire
    /// when an alarm wired through `PutMetricAlarm` (with the policy
    /// ARN as an action) breaches its threshold.
    fn alarms_firing_for_action(
        &self,
        account_id: &str,
        region: &str,
        policy_arn: &str,
    ) -> Vec<String>;
}

/// Applies a desired-count change to an ECS service. Used when a scaling
/// target's `ServiceNamespace == ecs`.
pub trait EcsServiceHook: Send + Sync {
    /// Returns the service's current `desiredCount`, or `None` when the
    /// cluster or service doesn't exist.
    fn current_desired_count(
        &self,
        account_id: &str,
        region: &str,
        cluster_name: &str,
        service_name: &str,
    ) -> Option<i32>;

    /// Sets the service's `desiredCount` and returns `Ok(())` on success.
    /// Returns `Err` when the cluster/service is missing so the caller
    /// can log a `NotScaled` activity.
    fn set_desired_count(
        &self,
        account_id: &str,
        region: &str,
        cluster_name: &str,
        service_name: &str,
        desired_count: i32,
    ) -> Result<(), String>;
}

/// Applies a capacity change to a DynamoDB table. Used when a scaling
/// target's `ServiceNamespace == dynamodb`. `dimension` is the AWS
/// `ScalableDimension` string and selects read vs write capacity.
pub trait DynamoDbCapacityHook: Send + Sync {
    /// Returns the table's current provisioned capacity for the given
    /// dimension, or `None` when the table doesn't exist / isn't on
    /// PROVISIONED billing mode.
    fn current_capacity(
        &self,
        account_id: &str,
        region: &str,
        table_name: &str,
    ) -> Option<(i64, i64)>;

    /// Sets the table's provisioned capacity. `read` and `write` are
    /// `Some` only for the dimension that actually changed; the impl
    /// should preserve the other side. Returns Err on unknown table
    /// or invalid value so the caller can log a NotScaled activity.
    fn set_capacity(
        &self,
        account_id: &str,
        region: &str,
        table_name: &str,
        read: Option<i64>,
        write: Option<i64>,
    ) -> Result<(), String>;
}
