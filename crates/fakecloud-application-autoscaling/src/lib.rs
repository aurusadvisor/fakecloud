pub mod hooks;
pub mod scheduled_executor;
pub(crate) mod service;
pub(crate) mod state;
pub mod ticker;

pub use hooks::{DynamoDbCapacityHook, EcsServiceHook, MetricReader};
pub use scheduled_executor::ScheduledActionExecutor;
pub use service::ApplicationAutoScalingService;
pub use state::{
    AccountState, Alarm, ApplicationAutoScalingAccounts, NotScaledReason, PolicyKey,
    ScalableTarget, ScalableTargetAction, ScalingActivity, ScalingPolicy, ScheduledAction,
    ScheduledKey, SharedApplicationAutoScalingState, SuspendedState, TargetKey,
};
pub use ticker::ScalingWatcher;
