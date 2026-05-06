pub mod hooks;
pub(crate) mod service;
pub(crate) mod state;
pub mod ticker;

pub use hooks::{DynamoDbCapacityHook, MetricReader};
pub use service::ApplicationAutoScalingService;
pub use state::{ApplicationAutoScalingAccounts, SharedApplicationAutoScalingState};
pub use ticker::ScalingWatcher;
