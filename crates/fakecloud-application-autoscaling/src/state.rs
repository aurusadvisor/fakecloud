//! In-memory state for Application Auto Scaling.

use std::collections::BTreeMap;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use parking_lot::RwLock;
use serde::{Deserialize, Serialize};

pub type SharedApplicationAutoScalingState = Arc<RwLock<ApplicationAutoScalingAccounts>>;

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ApplicationAutoScalingAccounts {
    pub accounts: BTreeMap<String, AccountState>,
}

impl ApplicationAutoScalingAccounts {
    pub fn new() -> Self {
        Self::default()
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
pub struct AccountState {
    /// Keyed by (ServiceNamespace, ResourceId, ScalableDimension).
    pub scalable_targets: BTreeMap<TargetKey, ScalableTarget>,
    /// Keyed by (ServiceNamespace, ResourceId, ScalableDimension, PolicyName).
    pub scaling_policies: BTreeMap<PolicyKey, ScalingPolicy>,
    /// Keyed by (ServiceNamespace, ResourceId, ScalableDimension, ScheduledActionName).
    pub scheduled_actions: BTreeMap<ScheduledKey, ScheduledAction>,
    /// Scaling activities, newest first.
    pub scaling_activities: Vec<ScalingActivity>,
    /// Tags keyed by ARN.
    pub tags: BTreeMap<String, BTreeMap<String, String>>,
}

pub type TargetKey = (String, String, String);
pub type PolicyKey = (String, String, String, String);
pub type ScheduledKey = (String, String, String, String);

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalableTarget {
    pub arn: String,
    pub service_namespace: String,
    pub resource_id: String,
    pub scalable_dimension: String,
    pub min_capacity: i32,
    pub max_capacity: i32,
    pub role_arn: String,
    pub creation_time: DateTime<Utc>,
    pub suspended_state: Option<SuspendedState>,
    pub predicted_capacity: Option<i32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SuspendedState {
    pub dynamic_scaling_in_suspended: Option<bool>,
    pub dynamic_scaling_out_suspended: Option<bool>,
    pub scheduled_scaling_suspended: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingPolicy {
    pub arn: String,
    pub policy_name: String,
    pub service_namespace: String,
    pub resource_id: String,
    pub scalable_dimension: String,
    pub policy_type: String,
    pub creation_time: DateTime<Utc>,
    pub step_scaling_policy_configuration: Option<serde_json::Value>,
    pub target_tracking_scaling_policy_configuration: Option<serde_json::Value>,
    pub predictive_scaling_policy_configuration: Option<serde_json::Value>,
    pub alarms: Vec<Alarm>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Alarm {
    pub alarm_name: String,
    pub alarm_arn: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduledAction {
    pub arn: String,
    pub scheduled_action_name: String,
    pub service_namespace: String,
    pub resource_id: String,
    pub scalable_dimension: Option<String>,
    pub schedule: String,
    pub timezone: Option<String>,
    pub start_time: Option<DateTime<Utc>>,
    pub end_time: Option<DateTime<Utc>>,
    pub scalable_target_action: Option<ScalableTargetAction>,
    pub creation_time: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalableTargetAction {
    pub min_capacity: Option<i32>,
    pub max_capacity: Option<i32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScalingActivity {
    pub activity_id: String,
    pub service_namespace: String,
    pub resource_id: String,
    pub scalable_dimension: String,
    pub description: String,
    pub cause: String,
    pub start_time: DateTime<Utc>,
    pub end_time: Option<DateTime<Utc>>,
    pub status_code: String,
    pub status_message: Option<String>,
    pub details: Option<String>,
    pub not_scaled_reasons: Vec<NotScaledReason>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotScaledReason {
    pub code: String,
    pub max_capacity: Option<i32>,
    pub min_capacity: Option<i32>,
    pub current_capacity: Option<i32>,
}
