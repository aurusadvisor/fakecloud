//! Implements the `StepFunctionsDelivery` trait for real Step Functions execution.

use std::sync::Arc;

use fakecloud_core::delivery::{DeliveryBus, StepFunctionsDelivery};
use fakecloud_dynamodb::SharedDynamoDbState;
use fakecloud_stepfunctions::SharedStepFunctionsState;

/// Starts Step Functions executions from cross-service delivery (EventBridge, Scheduler).
pub struct StepFunctionsDeliveryImpl {
    state: SharedStepFunctionsState,
    delivery: Option<Arc<DeliveryBus>>,
    dynamodb_state: Option<SharedDynamoDbState>,
}

impl StepFunctionsDeliveryImpl {
    pub fn new(
        state: SharedStepFunctionsState,
        delivery: Option<Arc<DeliveryBus>>,
        dynamodb_state: Option<SharedDynamoDbState>,
    ) -> Self {
        Self {
            state,
            delivery,
            dynamodb_state,
        }
    }
}

impl StepFunctionsDelivery for StepFunctionsDeliveryImpl {
    fn start_execution(&self, state_machine_arn: &str, input: &str) {
        tracing::info!(
            state_machine_arn,
            "Step Functions delivery: starting execution"
        );
        fakecloud_stepfunctions::start_execution_from_delivery(
            &self.state,
            &self.delivery,
            &self.dynamodb_state,
            state_machine_arn,
            input,
        );
    }
}
