use std::sync::Arc;

use async_trait::async_trait;
use http::{Method, StatusCode};
use serde_json::{json, Value};
use tokio::sync::Mutex as AsyncMutex;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
use fakecloud_persistence::SnapshotStore;

use crate::models;
use crate::state::{
    BedrockSnapshot, BedrockState, SharedBedrockState, BEDROCK_SNAPSHOT_SCHEMA_VERSION,
};

pub struct BedrockService {
    state: SharedBedrockState,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    snapshot_lock: Arc<AsyncMutex<()>>,
}

fn is_read_only_action(action: &str) -> bool {
    matches!(
        action,
        "ListFoundationModels"
            | "GetFoundationModel"
            | "ListTagsForResource"
            | "GetGuardrail"
            | "ListGuardrails"
            | "GetCustomModel"
            | "ListCustomModels"
            | "GetCustomModelDeployment"
            | "ListCustomModelDeployments"
            | "GetModelImportJob"
            | "ListModelImportJobs"
            | "GetImportedModel"
            | "ListImportedModels"
            | "GetModelCopyJob"
            | "ListModelCopyJobs"
            | "GetModelInvocationJob"
            | "ListModelInvocationJobs"
            | "GetEvaluationJob"
            | "ListEvaluationJobs"
            | "GetInferenceProfile"
            | "ListInferenceProfiles"
            | "GetPromptRouter"
            | "ListPromptRouters"
            | "GetResourcePolicy"
            | "GetMarketplaceModelEndpoint"
            | "ListMarketplaceModelEndpoints"
            | "ListFoundationModelAgreementOffers"
            | "GetFoundationModelAvailability"
            | "GetUseCaseForModelAccess"
            | "ListEnforcedGuardrailsConfiguration"
            | "GetAutomatedReasoningPolicy"
            | "ListAutomatedReasoningPolicies"
            | "ExportAutomatedReasoningPolicyVersion"
            | "GetAutomatedReasoningPolicyTestCase"
            | "ListAutomatedReasoningPolicyTestCases"
            | "GetAutomatedReasoningPolicyBuildWorkflow"
            | "ListAutomatedReasoningPolicyBuildWorkflows"
            | "GetAutomatedReasoningPolicyBuildWorkflowResultAssets"
            | "GetAutomatedReasoningPolicyTestResult"
            | "ListAutomatedReasoningPolicyTestResults"
            | "GetAutomatedReasoningPolicyAnnotations"
            | "GetAutomatedReasoningPolicyNextScenario"
            | "GetModelCustomizationJob"
            | "ListModelCustomizationJobs"
            | "GetProvisionedModelThroughput"
            | "ListProvisionedModelThroughputs"
            | "GetModelInvocationLoggingConfiguration"
            | "GetAsyncInvoke"
            | "ListAsyncInvokes"
            | "InvokeModel"
            | "InvokeModelWithResponseStream"
            | "InvokeModelWithBidirectionalStream"
            | "Converse"
            | "ConverseStream"
            | "CountTokens"
            | "ApplyGuardrail"
    )
}

impl BedrockService {
    pub fn new(state: SharedBedrockState) -> Self {
        Self {
            state,
            snapshot_store: None,
            snapshot_lock: Arc::new(AsyncMutex::new(())),
        }
    }

    pub fn with_snapshot_store(mut self, store: Arc<dyn SnapshotStore>) -> Self {
        self.snapshot_store = Some(store);
        self
    }

    async fn save_snapshot(&self) {
        let Some(store) = self.snapshot_store.clone() else {
            return;
        };
        let _guard = self.snapshot_lock.lock().await;
        let snapshot = BedrockSnapshot {
            schema_version: BEDROCK_SNAPSHOT_SCHEMA_VERSION,
            state: None,
            accounts: Some(self.state.read().clone()),
        };
        let join = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let bytes = serde_json::to_vec(&snapshot)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            store.save(&bytes)
        })
        .await;
        match join {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(%err, "failed to write bedrock snapshot"),
            Err(err) => tracing::error!(%err, "bedrock snapshot task panicked"),
        }
    }

    fn resolve_action(req: &AwsRequest) -> Option<(&str, Option<String>, Option<String>)> {
        let segs = &req.path_segments;
        if segs.is_empty() {
            return None;
        }

        let decode = |s: &str| {
            percent_encoding::percent_decode_str(s)
                .decode_utf8_lossy()
                .into_owned()
        };

        match (req.method.clone(), segs.len()) {
            // Foundation models
            (Method::GET, 1) if segs[0] == "foundation-models" => {
                Some(("ListFoundationModels", None, None))
            }
            (Method::GET, 2) if segs[0] == "foundation-models" => {
                Some(("GetFoundationModel", Some(decode(&segs[1])), None))
            }

            // Guardrails
            (Method::POST, 1) if segs[0] == "guardrails" => Some(("CreateGuardrail", None, None)),
            (Method::GET, 1) if segs[0] == "guardrails" => Some(("ListGuardrails", None, None)),
            (Method::GET, 2) if segs[0] == "guardrails" => {
                Some(("GetGuardrail", Some(decode(&segs[1])), None))
            }
            (Method::PUT, 2) if segs[0] == "guardrails" => {
                Some(("UpdateGuardrail", Some(decode(&segs[1])), None))
            }
            (Method::DELETE, 2) if segs[0] == "guardrails" => {
                Some(("DeleteGuardrail", Some(decode(&segs[1])), None))
            }
            (Method::POST, 2) if segs[0] == "guardrails" => {
                Some(("CreateGuardrailVersion", Some(decode(&segs[1])), None))
            }

            // Custom models
            (Method::POST, 2) if segs[0] == "custom-models" && segs[1] == "create-custom-model" => {
                Some(("CreateCustomModel", None, None))
            }
            (Method::GET, 1) if segs[0] == "custom-models" => {
                Some(("ListCustomModels", None, None))
            }
            (Method::GET, 2) if segs[0] == "custom-models" => {
                Some(("GetCustomModel", Some(decode(&segs[1])), None))
            }
            (Method::DELETE, 2) if segs[0] == "custom-models" => {
                Some(("DeleteCustomModel", Some(decode(&segs[1])), None))
            }

            // Custom model deployments
            (Method::POST, 2)
                if segs[0] == "model-customization" && segs[1] == "custom-model-deployments" =>
            {
                Some(("CreateCustomModelDeployment", None, None))
            }
            (Method::GET, 2)
                if segs[0] == "model-customization" && segs[1] == "custom-model-deployments" =>
            {
                Some(("ListCustomModelDeployments", None, None))
            }
            (Method::GET, 3)
                if segs[0] == "model-customization" && segs[1] == "custom-model-deployments" =>
            {
                Some(("GetCustomModelDeployment", Some(decode(&segs[2])), None))
            }
            (Method::PATCH, 3)
                if segs[0] == "model-customization" && segs[1] == "custom-model-deployments" =>
            {
                Some(("UpdateCustomModelDeployment", Some(decode(&segs[2])), None))
            }
            (Method::DELETE, 3)
                if segs[0] == "model-customization" && segs[1] == "custom-model-deployments" =>
            {
                Some(("DeleteCustomModelDeployment", Some(decode(&segs[2])), None))
            }

            // Model import jobs
            (Method::POST, 1) if segs[0] == "model-import-jobs" => {
                Some(("CreateModelImportJob", None, None))
            }
            (Method::GET, 1) if segs[0] == "model-import-jobs" => {
                Some(("ListModelImportJobs", None, None))
            }
            (Method::GET, 2) if segs[0] == "model-import-jobs" => {
                Some(("GetModelImportJob", Some(decode(&segs[1])), None))
            }

            // Imported models
            (Method::GET, 1) if segs[0] == "imported-models" => {
                Some(("ListImportedModels", None, None))
            }
            (Method::GET, 2) if segs[0] == "imported-models" => {
                Some(("GetImportedModel", Some(decode(&segs[1])), None))
            }
            (Method::DELETE, 2) if segs[0] == "imported-models" => {
                Some(("DeleteImportedModel", Some(decode(&segs[1])), None))
            }

            // Model copy jobs
            (Method::POST, 1) if segs[0] == "model-copy-jobs" => {
                Some(("CreateModelCopyJob", None, None))
            }
            (Method::GET, 1) if segs[0] == "model-copy-jobs" => {
                Some(("ListModelCopyJobs", None, None))
            }
            (Method::GET, 2) if segs[0] == "model-copy-jobs" => {
                Some(("GetModelCopyJob", Some(decode(&segs[1])), None))
            }

            // Model invocation jobs (batch inference)
            (Method::POST, 1) if segs[0] == "model-invocation-job" => {
                Some(("CreateModelInvocationJob", None, None))
            }
            (Method::GET, 1) if segs[0] == "model-invocation-jobs" => {
                Some(("ListModelInvocationJobs", None, None))
            }
            (Method::GET, 2) if segs[0] == "model-invocation-job" => {
                Some(("GetModelInvocationJob", Some(decode(&segs[1])), None))
            }
            (Method::POST, 3) if segs[0] == "model-invocation-job" && segs[2] == "stop" => {
                Some(("StopModelInvocationJob", Some(decode(&segs[1])), None))
            }

            // Evaluation jobs
            (Method::POST, 1) if segs[0] == "evaluation-jobs" => {
                Some(("CreateEvaluationJob", None, None))
            }
            (Method::GET, 1) if segs[0] == "evaluation-jobs" => {
                Some(("ListEvaluationJobs", None, None))
            }
            (Method::GET, 2) if segs[0] == "evaluation-jobs" => {
                Some(("GetEvaluationJob", Some(decode(&segs[1])), None))
            }
            (Method::POST, 3) if segs[0] == "evaluation-job" && segs[2] == "stop" => {
                Some(("StopEvaluationJob", Some(decode(&segs[1])), None))
            }
            (Method::POST, 2) if segs[0] == "evaluation-jobs" && segs[1] == "batch-delete" => {
                Some(("BatchDeleteEvaluationJob", None, None))
            }

            // Inference profiles
            (Method::POST, 1) if segs[0] == "inference-profiles" => {
                Some(("CreateInferenceProfile", None, None))
            }
            (Method::GET, 1) if segs[0] == "inference-profiles" => {
                Some(("ListInferenceProfiles", None, None))
            }
            (Method::GET, 2) if segs[0] == "inference-profiles" => {
                Some(("GetInferenceProfile", Some(decode(&segs[1])), None))
            }
            (Method::DELETE, 2) if segs[0] == "inference-profiles" => {
                Some(("DeleteInferenceProfile", Some(decode(&segs[1])), None))
            }

            // Prompt routers
            (Method::POST, 1) if segs[0] == "prompt-routers" => {
                Some(("CreatePromptRouter", None, None))
            }
            (Method::GET, 1) if segs[0] == "prompt-routers" => {
                Some(("ListPromptRouters", None, None))
            }
            (Method::GET, 2) if segs[0] == "prompt-routers" => {
                Some(("GetPromptRouter", Some(decode(&segs[1])), None))
            }
            (Method::DELETE, 2) if segs[0] == "prompt-routers" => {
                Some(("DeletePromptRouter", Some(decode(&segs[1])), None))
            }

            // Resource policies
            (Method::POST, 1) if segs[0] == "resource-policy" => {
                Some(("PutResourcePolicy", None, None))
            }
            (Method::GET, 2) if segs[0] == "resource-policy" => {
                Some(("GetResourcePolicy", Some(decode(&segs[1])), None))
            }
            (Method::DELETE, 2) if segs[0] == "resource-policy" => {
                Some(("DeleteResourcePolicy", Some(decode(&segs[1])), None))
            }

            // Marketplace model endpoints
            (Method::POST, 2) if segs[0] == "marketplace-model" && segs[1] == "endpoints" => {
                Some(("CreateMarketplaceModelEndpoint", None, None))
            }
            (Method::GET, 2) if segs[0] == "marketplace-model" && segs[1] == "endpoints" => {
                Some(("ListMarketplaceModelEndpoints", None, None))
            }
            (Method::GET, 3) if segs[0] == "marketplace-model" && segs[1] == "endpoints" => {
                Some(("GetMarketplaceModelEndpoint", Some(decode(&segs[2])), None))
            }
            (Method::PATCH, 3) if segs[0] == "marketplace-model" && segs[1] == "endpoints" => {
                Some((
                    "UpdateMarketplaceModelEndpoint",
                    Some(decode(&segs[2])),
                    None,
                ))
            }
            (Method::DELETE, 3) if segs[0] == "marketplace-model" && segs[1] == "endpoints" => {
                Some((
                    "DeleteMarketplaceModelEndpoint",
                    Some(decode(&segs[2])),
                    None,
                ))
            }
            (Method::POST, 4)
                if segs[0] == "marketplace-model"
                    && segs[1] == "endpoints"
                    && segs[3] == "registration" =>
            {
                Some((
                    "RegisterMarketplaceModelEndpoint",
                    Some(decode(&segs[2])),
                    None,
                ))
            }
            (Method::DELETE, 4)
                if segs[0] == "marketplace-model"
                    && segs[1] == "endpoints"
                    && segs[3] == "registration" =>
            {
                Some((
                    "DeregisterMarketplaceModelEndpoint",
                    Some(decode(&segs[2])),
                    None,
                ))
            }

            // Foundation model agreements
            (Method::POST, 1) if segs[0] == "create-foundation-model-agreement" => {
                Some(("CreateFoundationModelAgreement", None, None))
            }
            (Method::POST, 1) if segs[0] == "delete-foundation-model-agreement" => {
                Some(("DeleteFoundationModelAgreement", None, None))
            }
            (Method::GET, 2) if segs[0] == "list-foundation-model-agreement-offers" => Some((
                "ListFoundationModelAgreementOffers",
                Some(decode(&segs[1])),
                None,
            )),
            (Method::GET, 2) if segs[0] == "foundation-model-availability" => Some((
                "GetFoundationModelAvailability",
                Some(decode(&segs[1])),
                None,
            )),
            (Method::GET, 1) if segs[0] == "use-case-for-model-access" => {
                Some(("GetUseCaseForModelAccess", None, None))
            }
            (Method::POST, 1) if segs[0] == "use-case-for-model-access" => {
                Some(("PutUseCaseForModelAccess", None, None))
            }

            // Enforced guardrails
            (Method::PUT, 1) if segs[0] == "enforcedGuardrailsConfiguration" => {
                Some(("PutEnforcedGuardrailConfiguration", None, None))
            }
            (Method::GET, 1) if segs[0] == "enforcedGuardrailsConfiguration" => {
                Some(("ListEnforcedGuardrailsConfiguration", None, None))
            }
            (Method::DELETE, 2) if segs[0] == "enforcedGuardrailsConfiguration" => Some((
                "DeleteEnforcedGuardrailConfiguration",
                Some(decode(&segs[1])),
                None,
            )),

            // Automated reasoning build workflows (longer paths first)
            (Method::GET, 7)
                if segs[0] == "automated-reasoning-policies"
                    && segs[2] == "build-workflows"
                    && segs[4] == "test-cases"
                    && segs[6] == "test-results" =>
            {
                Some((
                    "GetAutomatedReasoningPolicyTestResult",
                    Some(decode(&segs[1])),
                    Some(format!("{}:{}", decode(&segs[3]), decode(&segs[5]))),
                ))
            }
            (Method::POST, 5)
                if segs[0] == "automated-reasoning-policies"
                    && segs[2] == "build-workflows"
                    && segs[4] == "start" =>
            {
                Some((
                    "StartAutomatedReasoningPolicyBuildWorkflow",
                    Some(decode(&segs[1])),
                    Some(decode(&segs[3])),
                ))
            }
            (Method::POST, 5)
                if segs[0] == "automated-reasoning-policies"
                    && segs[2] == "build-workflows"
                    && segs[4] == "cancel" =>
            {
                Some((
                    "CancelAutomatedReasoningPolicyBuildWorkflow",
                    Some(decode(&segs[1])),
                    Some(decode(&segs[3])),
                ))
            }
            (Method::POST, 5)
                if segs[0] == "automated-reasoning-policies"
                    && segs[2] == "build-workflows"
                    && segs[4] == "test-workflows" =>
            {
                Some((
                    "StartAutomatedReasoningPolicyTestWorkflow",
                    Some(decode(&segs[1])),
                    Some(decode(&segs[3])),
                ))
            }
            (Method::GET, 5)
                if segs[0] == "automated-reasoning-policies"
                    && segs[2] == "build-workflows"
                    && segs[4] == "result-assets" =>
            {
                Some((
                    "GetAutomatedReasoningPolicyBuildWorkflowResultAssets",
                    Some(decode(&segs[1])),
                    Some(decode(&segs[3])),
                ))
            }
            (Method::GET, 5)
                if segs[0] == "automated-reasoning-policies"
                    && segs[2] == "build-workflows"
                    && segs[4] == "annotations" =>
            {
                Some((
                    "GetAutomatedReasoningPolicyAnnotations",
                    Some(decode(&segs[1])),
                    Some(decode(&segs[3])),
                ))
            }
            (Method::PATCH, 5)
                if segs[0] == "automated-reasoning-policies"
                    && segs[2] == "build-workflows"
                    && segs[4] == "annotations" =>
            {
                Some((
                    "UpdateAutomatedReasoningPolicyAnnotations",
                    Some(decode(&segs[1])),
                    Some(decode(&segs[3])),
                ))
            }
            (Method::GET, 5)
                if segs[0] == "automated-reasoning-policies"
                    && segs[2] == "build-workflows"
                    && segs[4] == "scenarios" =>
            {
                Some((
                    "GetAutomatedReasoningPolicyNextScenario",
                    Some(decode(&segs[1])),
                    Some(decode(&segs[3])),
                ))
            }
            (Method::GET, 5)
                if segs[0] == "automated-reasoning-policies"
                    && segs[2] == "build-workflows"
                    && segs[4] == "test-results" =>
            {
                Some((
                    "ListAutomatedReasoningPolicyTestResults",
                    Some(decode(&segs[1])),
                    Some(decode(&segs[3])),
                ))
            }
            (Method::GET, 4)
                if segs[0] == "automated-reasoning-policies" && segs[2] == "build-workflows" =>
            {
                Some((
                    "GetAutomatedReasoningPolicyBuildWorkflow",
                    Some(decode(&segs[1])),
                    Some(decode(&segs[3])),
                ))
            }
            (Method::DELETE, 4)
                if segs[0] == "automated-reasoning-policies" && segs[2] == "build-workflows" =>
            {
                Some((
                    "DeleteAutomatedReasoningPolicyBuildWorkflow",
                    Some(decode(&segs[1])),
                    Some(decode(&segs[3])),
                ))
            }
            (Method::GET, 3)
                if segs[0] == "automated-reasoning-policies" && segs[2] == "build-workflows" =>
            {
                Some((
                    "ListAutomatedReasoningPolicyBuildWorkflows",
                    Some(decode(&segs[1])),
                    None,
                ))
            }

            // Automated reasoning policies
            (Method::POST, 1) if segs[0] == "automated-reasoning-policies" => {
                Some(("CreateAutomatedReasoningPolicy", None, None))
            }
            (Method::GET, 1) if segs[0] == "automated-reasoning-policies" => {
                Some(("ListAutomatedReasoningPolicies", None, None))
            }
            (Method::GET, 2) if segs[0] == "automated-reasoning-policies" => {
                Some(("GetAutomatedReasoningPolicy", Some(decode(&segs[1])), None))
            }
            (Method::PATCH, 2) if segs[0] == "automated-reasoning-policies" => Some((
                "UpdateAutomatedReasoningPolicy",
                Some(decode(&segs[1])),
                None,
            )),
            (Method::DELETE, 2) if segs[0] == "automated-reasoning-policies" => Some((
                "DeleteAutomatedReasoningPolicy",
                Some(decode(&segs[1])),
                None,
            )),
            (Method::POST, 3)
                if segs[0] == "automated-reasoning-policies" && segs[2] == "versions" =>
            {
                Some((
                    "CreateAutomatedReasoningPolicyVersion",
                    Some(decode(&segs[1])),
                    None,
                ))
            }
            (Method::GET, 3)
                if segs[0] == "automated-reasoning-policies" && segs[2] == "export" =>
            {
                Some((
                    "ExportAutomatedReasoningPolicyVersion",
                    Some(decode(&segs[1])),
                    None,
                ))
            }
            (Method::POST, 3)
                if segs[0] == "automated-reasoning-policies" && segs[2] == "test-cases" =>
            {
                Some((
                    "CreateAutomatedReasoningPolicyTestCase",
                    Some(decode(&segs[1])),
                    None,
                ))
            }
            (Method::GET, 3)
                if segs[0] == "automated-reasoning-policies" && segs[2] == "test-cases" =>
            {
                Some((
                    "ListAutomatedReasoningPolicyTestCases",
                    Some(decode(&segs[1])),
                    None,
                ))
            }
            (Method::GET, 4)
                if segs[0] == "automated-reasoning-policies" && segs[2] == "test-cases" =>
            {
                Some((
                    "GetAutomatedReasoningPolicyTestCase",
                    Some(decode(&segs[1])),
                    Some(decode(&segs[3])),
                ))
            }
            (Method::PATCH, 4)
                if segs[0] == "automated-reasoning-policies" && segs[2] == "test-cases" =>
            {
                Some((
                    "UpdateAutomatedReasoningPolicyTestCase",
                    Some(decode(&segs[1])),
                    Some(decode(&segs[3])),
                ))
            }
            (Method::DELETE, 4)
                if segs[0] == "automated-reasoning-policies" && segs[2] == "test-cases" =>
            {
                Some((
                    "DeleteAutomatedReasoningPolicyTestCase",
                    Some(decode(&segs[1])),
                    Some(decode(&segs[3])),
                ))
            }

            // Model customization jobs
            (Method::POST, 1) if segs[0] == "model-customization-jobs" => {
                Some(("CreateModelCustomizationJob", None, None))
            }
            (Method::GET, 1) if segs[0] == "model-customization-jobs" => {
                Some(("ListModelCustomizationJobs", None, None))
            }
            (Method::GET, 2) if segs[0] == "model-customization-jobs" => {
                Some(("GetModelCustomizationJob", Some(decode(&segs[1])), None))
            }
            (Method::POST, 3) if segs[0] == "model-customization-jobs" && segs[2] == "stop" => {
                Some(("StopModelCustomizationJob", Some(decode(&segs[1])), None))
            }

            // Provisioned model throughput
            (Method::POST, 1) if segs[0] == "provisioned-model-throughput" => {
                Some(("CreateProvisionedModelThroughput", None, None))
            }
            (Method::GET, 1) if segs[0] == "provisioned-model-throughputs" => {
                Some(("ListProvisionedModelThroughputs", None, None))
            }
            (Method::GET, 2) if segs[0] == "provisioned-model-throughput" => Some((
                "GetProvisionedModelThroughput",
                Some(decode(&segs[1])),
                None,
            )),
            (Method::PATCH, 2) if segs[0] == "provisioned-model-throughput" => Some((
                "UpdateProvisionedModelThroughput",
                Some(decode(&segs[1])),
                None,
            )),
            (Method::DELETE, 2) if segs[0] == "provisioned-model-throughput" => Some((
                "DeleteProvisionedModelThroughput",
                Some(decode(&segs[1])),
                None,
            )),

            // Logging configuration
            (Method::PUT, 2) if segs[0] == "logging" && segs[1] == "modelinvocations" => {
                Some(("PutModelInvocationLoggingConfiguration", None, None))
            }
            (Method::GET, 2) if segs[0] == "logging" && segs[1] == "modelinvocations" => {
                Some(("GetModelInvocationLoggingConfiguration", None, None))
            }
            (Method::DELETE, 2) if segs[0] == "logging" && segs[1] == "modelinvocations" => {
                Some(("DeleteModelInvocationLoggingConfiguration", None, None))
            }

            // Runtime: ApplyGuardrail — POST /guardrail/{id}/version/{version}/apply
            (Method::POST, 5)
                if segs[0] == "guardrail" && segs[2] == "version" && segs[4] == "apply" =>
            {
                Some((
                    "ApplyGuardrail",
                    Some(decode(&segs[1])),
                    Some(decode(&segs[3])),
                ))
            }

            // Runtime: model operations
            (Method::POST, 3) if segs[0] == "model" && segs[2] == "invoke" => {
                Some(("InvokeModel", Some(decode(&segs[1])), None))
            }
            (Method::POST, 3) if segs[0] == "model" && segs[2] == "invoke-with-response-stream" => {
                Some((
                    "InvokeModelWithResponseStream",
                    Some(decode(&segs[1])),
                    None,
                ))
            }
            (Method::POST, 3)
                if segs[0] == "model" && segs[2] == "invoke-with-bidirectional-stream" =>
            {
                Some((
                    "InvokeModelWithBidirectionalStream",
                    Some(decode(&segs[1])),
                    None,
                ))
            }
            (Method::POST, 3) if segs[0] == "model" && segs[2] == "converse" => {
                Some(("Converse", Some(decode(&segs[1])), None))
            }
            (Method::POST, 3) if segs[0] == "model" && segs[2] == "converse-stream" => {
                Some(("ConverseStream", Some(decode(&segs[1])), None))
            }
            (Method::POST, 3) if segs[0] == "model" && segs[2] == "count-tokens" => {
                Some(("CountTokens", Some(decode(&segs[1])), None))
            }

            // Runtime: async invoke
            (Method::POST, 1) if segs[0] == "async-invoke" => {
                Some(("StartAsyncInvoke", None, None))
            }
            (Method::GET, 1) if segs[0] == "async-invoke" => Some(("ListAsyncInvokes", None, None)),
            (Method::GET, 2) if segs[0] == "async-invoke" => {
                Some(("GetAsyncInvoke", Some(decode(&segs[1])), None))
            }

            // Tags — all POST with ARN in body
            (Method::POST, 1) if segs[0] == "tagResource" => Some(("TagResource", None, None)),
            (Method::POST, 1) if segs[0] == "untagResource" => Some(("UntagResource", None, None)),
            (Method::POST, 1) if segs[0] == "listTagsForResource" => {
                Some(("ListTagsForResource", None, None))
            }

            _ => None,
        }
    }

    fn list_foundation_models(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mut model_summaries: Vec<Value> = vec![];

        let by_provider = req.query_params.get("byProvider");
        let by_output_modality = req.query_params.get("byOutputModality");
        let by_input_modality = req.query_params.get("byInputModality");
        let by_customization_type = req.query_params.get("byCustomizationType");
        let by_inference_type = req.query_params.get("byInferenceType");

        for model in models::FOUNDATION_MODELS {
            if let Some(provider) = by_provider {
                if model.provider_name != provider.as_str() {
                    continue;
                }
            }
            if let Some(modality) = by_output_modality {
                if !model.output_modalities.contains(&modality.as_str()) {
                    continue;
                }
            }
            if let Some(modality) = by_input_modality {
                if !model.input_modalities.contains(&modality.as_str()) {
                    continue;
                }
            }
            if let Some(customization) = by_customization_type {
                if !model
                    .customizations_supported
                    .contains(&customization.as_str())
                {
                    continue;
                }
            }
            if let Some(inference) = by_inference_type {
                if !model
                    .inference_types_supported
                    .contains(&inference.as_str())
                {
                    continue;
                }
            }
            model_summaries.push(model.to_summary_json());
        }

        Ok(AwsResponse::ok_json(json!({
            "modelSummaries": model_summaries
        })))
    }

    fn get_foundation_model(
        &self,
        req: &AwsRequest,
        model_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let model = models::find_model(model_id).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!("Could not find model {model_id}"),
            )
        })?;

        Ok(AwsResponse::ok_json(
            model.to_detail_json(&req.region, &req.account_id),
        ))
    }

    fn tag_resource(
        &self,
        req: &AwsRequest,
        resource_arn: &str,
        body: &Value,
    ) -> Result<AwsResponse, AwsServiceError> {
        let tags = body.get("tags").and_then(|t| t.as_array()).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                "tags is required",
            )
        })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let resource_tags = state.tags.entry(resource_arn.to_string()).or_default();
        for tag in tags {
            let key = tag["key"].as_str().unwrap_or_default();
            let value = tag["value"].as_str().unwrap_or_default();
            resource_tags.insert(key.to_string(), value.to_string());
        }

        Ok(AwsResponse::json(StatusCode::OK, "{}".to_string()))
    }

    fn untag_resource_from_body(
        &self,
        account_id: &str,
        resource_arn: &str,
        tag_keys: &[String],
    ) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        if let Some(resource_tags) = state.tags.get_mut(resource_arn) {
            for key in tag_keys {
                resource_tags.remove(key);
            }
        }

        Ok(AwsResponse::json(StatusCode::OK, "{}".to_string()))
    }

    fn list_tags_for_resource(
        &self,
        req: &AwsRequest,
        resource_arn: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let empty = BedrockState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let tags = state.tags.get(resource_arn);
        let tags_arr: Vec<Value> = match tags {
            Some(t) => {
                let mut arr: Vec<Value> = t
                    .iter()
                    .map(|(k, v)| json!({"key": k, "value": v}))
                    .collect();
                arr.sort_by(|a, b| {
                    a["key"]
                        .as_str()
                        .unwrap_or("")
                        .cmp(b["key"].as_str().unwrap_or(""))
                });
                arr
            }
            None => Vec::new(),
        };

        Ok(AwsResponse::ok_json(json!({ "tags": tags_arr })))
    }
}

#[async_trait]
impl AwsService for BedrockService {
    fn service_name(&self) -> &str {
        "bedrock"
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let (action, resource_id, extra_id) =
            Self::resolve_action(&req).ok_or_else(|| AwsServiceError::ActionNotImplemented {
                service: "bedrock".to_string(),
                action: format!("{} {}", req.method, req.raw_path),
            })?;

        let mutates = !is_read_only_action(action);
        let body = req.json_body();

        let result = match action {
            "ListFoundationModels" => self.list_foundation_models(&req),
            "GetFoundationModel" => {
                self.get_foundation_model(&req, &resource_id.unwrap_or_default())
            }
            "TagResource" => {
                let arn = body["resourceARN"]
                    .as_str()
                    .filter(|s| !s.is_empty())
                    .ok_or_else(|| {
                        AwsServiceError::aws_error(
                            StatusCode::BAD_REQUEST,
                            "ValidationException",
                            "resourceARN is required",
                        )
                    })?;
                self.tag_resource(&req, arn, &body)
            }
            "UntagResource" => {
                let arn = body["resourceARN"].as_str().unwrap_or_default();
                let tag_keys: Vec<String> = body["tagKeys"]
                    .as_array()
                    .map(|arr| {
                        arr.iter()
                            .filter_map(|v| v.as_str().map(String::from))
                            .collect()
                    })
                    .unwrap_or_default();
                self.untag_resource_from_body(&req.account_id, arn, &tag_keys)
            }
            "ListTagsForResource" => {
                let arn = body["resourceARN"].as_str().unwrap_or_default();
                self.list_tags_for_resource(&req, arn)
            }
            "CreateGuardrail" => crate::guardrails::create_guardrail(&self.state, &req, &body),
            "GetGuardrail" => crate::guardrails::get_guardrail(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            "ListGuardrails" => crate::guardrails::list_guardrails(&self.state, &req),
            "UpdateGuardrail" => crate::guardrails::update_guardrail(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
                &body,
            ),
            "DeleteGuardrail" => crate::guardrails::delete_guardrail(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            "CreateGuardrailVersion" => crate::guardrails::create_guardrail_version(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
                &body,
            ),
            "ApplyGuardrail" => crate::guardrails::apply_guardrail(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
                &extra_id.unwrap_or_default(),
                &req.body,
            ),
            // Custom models
            "CreateCustomModel" => {
                crate::custom_models::create_custom_model(&self.state, &req, &body)
            }
            "GetCustomModel" => crate::custom_models::get_custom_model(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            "ListCustomModels" => crate::custom_models::list_custom_models(&self.state, &req),
            "DeleteCustomModel" => crate::custom_models::delete_custom_model(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            // Custom model deployments
            "CreateCustomModelDeployment" => {
                crate::custom_model_deployments::create_custom_model_deployment(
                    &self.state,
                    &req,
                    &body,
                )
            }
            "GetCustomModelDeployment" => {
                crate::custom_model_deployments::get_custom_model_deployment(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                )
            }
            "ListCustomModelDeployments" => {
                crate::custom_model_deployments::list_custom_model_deployments(&self.state, &req)
            }
            "UpdateCustomModelDeployment" => {
                crate::custom_model_deployments::update_custom_model_deployment(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    &body,
                )
            }
            "DeleteCustomModelDeployment" => {
                crate::custom_model_deployments::delete_custom_model_deployment(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                )
            }
            // Model import jobs
            "CreateModelImportJob" => {
                crate::model_import::create_model_import_job(&self.state, &req, &body)
            }
            "GetModelImportJob" => crate::model_import::get_model_import_job(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            "ListModelImportJobs" => crate::model_import::list_model_import_jobs(&self.state, &req),
            "GetImportedModel" => crate::model_import::get_imported_model(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            "ListImportedModels" => crate::model_import::list_imported_models(&self.state, &req),
            "DeleteImportedModel" => crate::model_import::delete_imported_model(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            // Model copy jobs
            "CreateModelCopyJob" => {
                crate::model_copy::create_model_copy_job(&self.state, &req, &body)
            }
            "GetModelCopyJob" => crate::model_copy::get_model_copy_job(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            "ListModelCopyJobs" => crate::model_copy::list_model_copy_jobs(&self.state, &req),
            // Model invocation jobs
            "CreateModelInvocationJob" => {
                crate::invocation_jobs::create_model_invocation_job(&self.state, &req, &body)
            }
            "GetModelInvocationJob" => crate::invocation_jobs::get_model_invocation_job(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            "ListModelInvocationJobs" => {
                crate::invocation_jobs::list_model_invocation_jobs(&self.state, &req)
            }
            "StopModelInvocationJob" => crate::invocation_jobs::stop_model_invocation_job(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            // Evaluation jobs
            "CreateEvaluationJob" => {
                crate::evaluation::create_evaluation_job(&self.state, &req, &body)
            }
            "GetEvaluationJob" => crate::evaluation::get_evaluation_job(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            "ListEvaluationJobs" => crate::evaluation::list_evaluation_jobs(&self.state, &req),
            "StopEvaluationJob" => crate::evaluation::stop_evaluation_job(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            "BatchDeleteEvaluationJob" => {
                crate::evaluation::batch_delete_evaluation_job(&self.state, &req, &body)
            }
            // Inference profiles
            "CreateInferenceProfile" => {
                crate::inference_profiles::create_inference_profile(&self.state, &req, &body)
            }
            "GetInferenceProfile" => crate::inference_profiles::get_inference_profile(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            "ListInferenceProfiles" => {
                crate::inference_profiles::list_inference_profiles(&self.state, &req)
            }
            "DeleteInferenceProfile" => crate::inference_profiles::delete_inference_profile(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            // Prompt routers
            "CreatePromptRouter" => {
                crate::prompt_routers::create_prompt_router(&self.state, &req, &body)
            }
            "GetPromptRouter" => crate::prompt_routers::get_prompt_router(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            "ListPromptRouters" => crate::prompt_routers::list_prompt_routers(&self.state, &req),
            "DeletePromptRouter" => crate::prompt_routers::delete_prompt_router(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            // Resource policies
            "PutResourcePolicy" => {
                crate::resource_policies::put_resource_policy(&self.state, &req, &body)
            }
            "GetResourcePolicy" => crate::resource_policies::get_resource_policy(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            "DeleteResourcePolicy" => crate::resource_policies::delete_resource_policy(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            // Marketplace model endpoints
            "CreateMarketplaceModelEndpoint" => {
                crate::marketplace::create_marketplace_model_endpoint(&self.state, &req, &body)
            }
            "GetMarketplaceModelEndpoint" => crate::marketplace::get_marketplace_model_endpoint(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            "ListMarketplaceModelEndpoints" => {
                crate::marketplace::list_marketplace_model_endpoints(&self.state, &req)
            }
            "UpdateMarketplaceModelEndpoint" => {
                crate::marketplace::update_marketplace_model_endpoint(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    &body,
                )
            }
            "DeleteMarketplaceModelEndpoint" => {
                crate::marketplace::delete_marketplace_model_endpoint(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                )
            }
            "RegisterMarketplaceModelEndpoint" => {
                crate::marketplace::register_marketplace_model_endpoint(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                )
            }
            "DeregisterMarketplaceModelEndpoint" => {
                crate::marketplace::deregister_marketplace_model_endpoint(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                )
            }
            // Foundation model agreements
            "CreateFoundationModelAgreement" => {
                crate::foundation_model_agreements::create_foundation_model_agreement(
                    &self.state,
                    &req,
                    &body,
                )
            }
            "DeleteFoundationModelAgreement" => {
                crate::foundation_model_agreements::delete_foundation_model_agreement(
                    &self.state,
                    &req,
                    &body,
                )
            }
            "ListFoundationModelAgreementOffers" => {
                crate::foundation_model_agreements::list_foundation_model_agreement_offers(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                )
            }
            "GetFoundationModelAvailability" => {
                crate::foundation_model_agreements::get_foundation_model_availability(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                )
            }
            "GetUseCaseForModelAccess" => {
                crate::foundation_model_agreements::get_use_case_for_model_access(&self.state, &req)
            }
            "PutUseCaseForModelAccess" => {
                crate::foundation_model_agreements::put_use_case_for_model_access(
                    &self.state,
                    &req,
                    &body,
                )
            }
            // Enforced guardrails
            "PutEnforcedGuardrailConfiguration" => {
                crate::enforced_guardrails::put_enforced_guardrail_configuration(
                    &self.state,
                    &req,
                    &body,
                )
            }
            "ListEnforcedGuardrailsConfiguration" => {
                crate::enforced_guardrails::list_enforced_guardrails_configuration(
                    &self.state,
                    &req,
                )
            }
            "DeleteEnforcedGuardrailConfiguration" => {
                crate::enforced_guardrails::delete_enforced_guardrail_configuration(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                )
            }
            // Automated reasoning policies
            "CreateAutomatedReasoningPolicy" => {
                crate::automated_reasoning::create_automated_reasoning_policy(
                    &self.state,
                    &req,
                    &body,
                )
            }
            "GetAutomatedReasoningPolicy" => {
                crate::automated_reasoning::get_automated_reasoning_policy(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                )
            }
            "ListAutomatedReasoningPolicies" => {
                crate::automated_reasoning::list_automated_reasoning_policies(&self.state, &req)
            }
            "UpdateAutomatedReasoningPolicy" => {
                crate::automated_reasoning::update_automated_reasoning_policy(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    &body,
                )
            }
            "DeleteAutomatedReasoningPolicy" => {
                crate::automated_reasoning::delete_automated_reasoning_policy(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                )
            }
            "CreateAutomatedReasoningPolicyVersion" => {
                crate::automated_reasoning::create_automated_reasoning_policy_version(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    &body,
                )
            }
            "ExportAutomatedReasoningPolicyVersion" => {
                crate::automated_reasoning::export_automated_reasoning_policy_version(
                    &self.state,
                    &resource_id.unwrap_or_default(),
                    &req,
                )
            }
            "CreateAutomatedReasoningPolicyTestCase" => {
                crate::automated_reasoning::create_automated_reasoning_policy_test_case(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    &body,
                )
            }
            "GetAutomatedReasoningPolicyTestCase" => {
                crate::automated_reasoning::get_automated_reasoning_policy_test_case(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    extra_id.as_deref().unwrap_or_default(),
                )
            }
            "ListAutomatedReasoningPolicyTestCases" => {
                crate::automated_reasoning::list_automated_reasoning_policy_test_cases(
                    &self.state,
                    &resource_id.unwrap_or_default(),
                    &req,
                )
            }
            "UpdateAutomatedReasoningPolicyTestCase" => {
                crate::automated_reasoning::update_automated_reasoning_policy_test_case(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    extra_id.as_deref().unwrap_or_default(),
                    &body,
                )
            }
            "DeleteAutomatedReasoningPolicyTestCase" => {
                crate::automated_reasoning::delete_automated_reasoning_policy_test_case(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    extra_id.as_deref().unwrap_or_default(),
                )
            }
            // Automated reasoning build workflows
            "StartAutomatedReasoningPolicyBuildWorkflow" => {
                crate::automated_reasoning_workflows::start_build_workflow(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    extra_id.as_deref().unwrap_or_default(),
                )
            }
            "GetAutomatedReasoningPolicyBuildWorkflow" => {
                crate::automated_reasoning_workflows::get_build_workflow(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    extra_id.as_deref().unwrap_or_default(),
                )
            }
            "ListAutomatedReasoningPolicyBuildWorkflows" => {
                crate::automated_reasoning_workflows::list_build_workflows(
                    &self.state,
                    &resource_id.unwrap_or_default(),
                    &req,
                )
            }
            "CancelAutomatedReasoningPolicyBuildWorkflow" => {
                crate::automated_reasoning_workflows::cancel_build_workflow(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    extra_id.as_deref().unwrap_or_default(),
                )
            }
            "DeleteAutomatedReasoningPolicyBuildWorkflow" => {
                crate::automated_reasoning_workflows::delete_build_workflow(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    extra_id.as_deref().unwrap_or_default(),
                )
            }
            "GetAutomatedReasoningPolicyBuildWorkflowResultAssets" => {
                crate::automated_reasoning_workflows::get_build_workflow_result_assets(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    extra_id.as_deref().unwrap_or_default(),
                )
            }
            "StartAutomatedReasoningPolicyTestWorkflow" => {
                crate::automated_reasoning_workflows::start_test_workflow(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    extra_id.as_deref().unwrap_or_default(),
                )
            }
            "GetAutomatedReasoningPolicyTestResult" => {
                let extra = extra_id.unwrap_or_default();
                let parts: Vec<&str> = extra.splitn(2, ':').collect();
                let workflow_id = parts.first().copied().unwrap_or_default();
                let test_case_id = parts.get(1).copied().unwrap_or_default();
                crate::automated_reasoning_workflows::get_test_result(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    workflow_id,
                    test_case_id,
                )
            }
            "ListAutomatedReasoningPolicyTestResults" => {
                crate::automated_reasoning_workflows::list_test_results(
                    &self.state,
                    &resource_id.unwrap_or_default(),
                    extra_id.as_deref().unwrap_or_default(),
                    &req,
                )
            }
            "GetAutomatedReasoningPolicyAnnotations" => {
                crate::automated_reasoning_workflows::get_annotations(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    extra_id.as_deref().unwrap_or_default(),
                )
            }
            "UpdateAutomatedReasoningPolicyAnnotations" => {
                crate::automated_reasoning_workflows::update_annotations(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    extra_id.as_deref().unwrap_or_default(),
                    &body,
                )
            }
            "GetAutomatedReasoningPolicyNextScenario" => {
                crate::automated_reasoning_workflows::get_next_scenario(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    extra_id.as_deref().unwrap_or_default(),
                )
            }
            // Model customization jobs
            "CreateModelCustomizationJob" => {
                crate::customization::create_model_customization_job(&self.state, &req, &body)
            }
            "GetModelCustomizationJob" => crate::customization::get_model_customization_job(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            "ListModelCustomizationJobs" => {
                crate::customization::list_model_customization_jobs(&self.state, &req)
            }
            "StopModelCustomizationJob" => crate::customization::stop_model_customization_job(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            // Provisioned model throughput
            "CreateProvisionedModelThroughput" => {
                crate::throughput::create_provisioned_model_throughput(&self.state, &req, &body)
            }
            "GetProvisionedModelThroughput" => crate::throughput::get_provisioned_model_throughput(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            "ListProvisionedModelThroughputs" => {
                crate::throughput::list_provisioned_model_throughputs(&self.state, &req)
            }
            "UpdateProvisionedModelThroughput" => {
                crate::throughput::update_provisioned_model_throughput(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                    &body,
                )
            }
            "DeleteProvisionedModelThroughput" => {
                crate::throughput::delete_provisioned_model_throughput(
                    &self.state,
                    &req,
                    &resource_id.unwrap_or_default(),
                )
            }
            // Logging configuration
            "PutModelInvocationLoggingConfiguration" => {
                crate::logging::put_model_invocation_logging_configuration(&self.state, &req, &body)
            }
            "GetModelInvocationLoggingConfiguration" => {
                crate::logging::get_model_invocation_logging_configuration(&self.state, &req)
            }
            "DeleteModelInvocationLoggingConfiguration" => {
                crate::logging::delete_model_invocation_logging_configuration(&self.state, &req)
            }
            // Runtime operations
            "InvokeModel" => crate::invoke::invoke_model(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
                &req.body,
            ),
            "CountTokens" => crate::invoke::count_tokens(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
                &req.body,
            ),
            "Converse" => crate::converse::converse(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
                &req.body,
            ),
            "InvokeModelWithResponseStream" | "InvokeModelWithBidirectionalStream" => {
                let model_id = resource_id.unwrap_or_default();
                if let Some(fault) = crate::faults::take_matching_fault(
                    &self.state,
                    &req,
                    &model_id,
                    "InvokeModelWithResponseStream",
                ) {
                    crate::faults::record_faulted_invocation(
                        &self.state,
                        &req,
                        &model_id,
                        &req.body,
                        &fault,
                    );
                    return Err(crate::faults::fault_to_error(&fault));
                }
                let response_text =
                    crate::streaming::get_response_text(&self.state, &req, &model_id, &req.body);
                let body =
                    crate::streaming::build_invoke_stream_response(&model_id, &response_text);

                // Record invocation
                {
                    let mut accts = self.state.write();
                    let s = accts.get_or_create(&req.account_id);
                    s.invocations.push(crate::state::ModelInvocation {
                        model_id: model_id.clone(),
                        input: String::from_utf8_lossy(&req.body).to_string(),
                        output: response_text,
                        timestamp: chrono::Utc::now(),
                        error: None,
                    });
                }

                Ok(AwsResponse {
                    status: http::StatusCode::OK,
                    content_type: "application/vnd.amazon.eventstream".to_string(),
                    body: bytes::Bytes::from(body).into(),
                    headers: http::HeaderMap::new(),
                })
            }
            "ConverseStream" => {
                let model_id = resource_id.unwrap_or_default();
                if let Some(fault) = crate::faults::take_matching_fault(
                    &self.state,
                    &req,
                    &model_id,
                    "ConverseStream",
                ) {
                    crate::faults::record_faulted_invocation(
                        &self.state,
                        &req,
                        &model_id,
                        &req.body,
                        &fault,
                    );
                    return Err(crate::faults::fault_to_error(&fault));
                }
                let response_text =
                    crate::streaming::get_response_text(&self.state, &req, &model_id, &req.body);
                let body = crate::streaming::build_converse_stream_response(&response_text);

                // Record invocation
                {
                    let mut accts = self.state.write();
                    let s = accts.get_or_create(&req.account_id);
                    s.invocations.push(crate::state::ModelInvocation {
                        model_id: model_id.clone(),
                        input: String::from_utf8_lossy(&req.body).to_string(),
                        output: response_text,
                        timestamp: chrono::Utc::now(),
                        error: None,
                    });
                }

                Ok(AwsResponse {
                    status: http::StatusCode::OK,
                    content_type: "application/vnd.amazon.eventstream".to_string(),
                    body: bytes::Bytes::from(body).into(),
                    headers: http::HeaderMap::new(),
                })
            }
            // Async invoke
            "StartAsyncInvoke" => crate::async_invoke::start_async_invoke(&self.state, &req, &body),
            "GetAsyncInvoke" => crate::async_invoke::get_async_invoke(
                &self.state,
                &req,
                &resource_id.unwrap_or_default(),
            ),
            "ListAsyncInvokes" => crate::async_invoke::list_async_invokes(&self.state, &req),

            _ => Err(AwsServiceError::ActionNotImplemented {
                service: "bedrock".to_string(),
                action: action.to_string(),
            }),
        };
        if mutates && matches!(result.as_ref(), Ok(resp) if resp.status.is_success()) {
            self.save_snapshot().await;
        }
        result
    }

    fn supported_actions(&self) -> &[&str] {
        &[
            "ListFoundationModels",
            "GetFoundationModel",
            "TagResource",
            "UntagResource",
            "ListTagsForResource",
            "CreateGuardrail",
            "GetGuardrail",
            "ListGuardrails",
            "UpdateGuardrail",
            "DeleteGuardrail",
            "CreateGuardrailVersion",
            "ApplyGuardrail",
            "CreateCustomModel",
            "GetCustomModel",
            "ListCustomModels",
            "DeleteCustomModel",
            "CreateCustomModelDeployment",
            "GetCustomModelDeployment",
            "ListCustomModelDeployments",
            "UpdateCustomModelDeployment",
            "DeleteCustomModelDeployment",
            "CreateModelImportJob",
            "GetModelImportJob",
            "ListModelImportJobs",
            "GetImportedModel",
            "ListImportedModels",
            "DeleteImportedModel",
            "CreateModelCopyJob",
            "GetModelCopyJob",
            "ListModelCopyJobs",
            "CreateModelInvocationJob",
            "GetModelInvocationJob",
            "ListModelInvocationJobs",
            "StopModelInvocationJob",
            "CreateEvaluationJob",
            "GetEvaluationJob",
            "ListEvaluationJobs",
            "StopEvaluationJob",
            "BatchDeleteEvaluationJob",
            "CreateInferenceProfile",
            "GetInferenceProfile",
            "ListInferenceProfiles",
            "DeleteInferenceProfile",
            "CreatePromptRouter",
            "GetPromptRouter",
            "ListPromptRouters",
            "DeletePromptRouter",
            "PutResourcePolicy",
            "GetResourcePolicy",
            "DeleteResourcePolicy",
            "CreateMarketplaceModelEndpoint",
            "GetMarketplaceModelEndpoint",
            "ListMarketplaceModelEndpoints",
            "UpdateMarketplaceModelEndpoint",
            "DeleteMarketplaceModelEndpoint",
            "RegisterMarketplaceModelEndpoint",
            "DeregisterMarketplaceModelEndpoint",
            "CreateFoundationModelAgreement",
            "DeleteFoundationModelAgreement",
            "ListFoundationModelAgreementOffers",
            "GetFoundationModelAvailability",
            "GetUseCaseForModelAccess",
            "PutUseCaseForModelAccess",
            "PutEnforcedGuardrailConfiguration",
            "ListEnforcedGuardrailsConfiguration",
            "DeleteEnforcedGuardrailConfiguration",
            "CreateAutomatedReasoningPolicy",
            "GetAutomatedReasoningPolicy",
            "ListAutomatedReasoningPolicies",
            "UpdateAutomatedReasoningPolicy",
            "DeleteAutomatedReasoningPolicy",
            "CreateAutomatedReasoningPolicyVersion",
            "ExportAutomatedReasoningPolicyVersion",
            "CreateAutomatedReasoningPolicyTestCase",
            "GetAutomatedReasoningPolicyTestCase",
            "ListAutomatedReasoningPolicyTestCases",
            "UpdateAutomatedReasoningPolicyTestCase",
            "DeleteAutomatedReasoningPolicyTestCase",
            "StartAutomatedReasoningPolicyBuildWorkflow",
            "GetAutomatedReasoningPolicyBuildWorkflow",
            "ListAutomatedReasoningPolicyBuildWorkflows",
            "CancelAutomatedReasoningPolicyBuildWorkflow",
            "DeleteAutomatedReasoningPolicyBuildWorkflow",
            "GetAutomatedReasoningPolicyBuildWorkflowResultAssets",
            "StartAutomatedReasoningPolicyTestWorkflow",
            "GetAutomatedReasoningPolicyTestResult",
            "ListAutomatedReasoningPolicyTestResults",
            "GetAutomatedReasoningPolicyAnnotations",
            "UpdateAutomatedReasoningPolicyAnnotations",
            "GetAutomatedReasoningPolicyNextScenario",
            "CreateModelCustomizationJob",
            "GetModelCustomizationJob",
            "ListModelCustomizationJobs",
            "StopModelCustomizationJob",
            "CreateProvisionedModelThroughput",
            "GetProvisionedModelThroughput",
            "ListProvisionedModelThroughputs",
            "UpdateProvisionedModelThroughput",
            "DeleteProvisionedModelThroughput",
            "PutModelInvocationLoggingConfiguration",
            "GetModelInvocationLoggingConfiguration",
            "DeleteModelInvocationLoggingConfiguration",
            "InvokeModel",
            "InvokeModelWithResponseStream",
            "InvokeModelWithBidirectionalStream",
            "Converse",
            "ConverseStream",
            "CountTokens",
            "StartAsyncInvoke",
            "GetAsyncInvoke",
            "ListAsyncInvokes",
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use http::{HeaderMap, Method};
    use parking_lot::RwLock;
    use serde_json::Value;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn make_state() -> SharedBedrockState {
        Arc::new(RwLock::new(
            fakecloud_core::multi_account::MultiAccountState::new(
                "123456789012",
                "us-east-1",
                "http://localhost:4566",
            ),
        ))
    }

    fn make_request(method: Method, path: &str, body: &str) -> AwsRequest {
        let raw_path = path.to_string();
        let segs: Vec<String> = raw_path
            .trim_start_matches('/')
            .split('/')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_string())
            .collect();
        AwsRequest {
            service: "bedrock".to_string(),
            action: String::new(),
            region: "us-east-1".to_string(),
            account_id: "123456789012".to_string(),
            request_id: "test-id".to_string(),
            headers: HeaderMap::new(),
            query_params: HashMap::new(),
            body: Bytes::from(body.to_string()),
            body_stream: parking_lot::Mutex::new(None),
            path_segments: segs,
            raw_path,
            raw_query: String::new(),
            method,
            is_query_protocol: false,
            access_key_id: None,
            principal: None,
        }
    }

    fn make_request_with_query(
        method: Method,
        path: &str,
        body: &str,
        query: HashMap<String, String>,
    ) -> AwsRequest {
        let mut req = make_request(method, path, body);
        req.query_params = query;
        req
    }

    fn expect_err(result: Result<AwsResponse, AwsServiceError>) -> AwsServiceError {
        match result {
            Err(e) => e,
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    fn body_json(resp: &AwsResponse) -> Value {
        serde_json::from_slice(resp.body.expect_bytes()).unwrap()
    }

    // ── resolve_action routing ──

    #[test]
    fn resolve_action_list_foundation_models() {
        let req = make_request(Method::GET, "/foundation-models", "");
        let (action, id, _) = BedrockService::resolve_action(&req).unwrap();
        assert_eq!(action, "ListFoundationModels");
        assert!(id.is_none());
    }

    #[test]
    fn resolve_action_get_foundation_model() {
        let req = make_request(
            Method::GET,
            "/foundation-models/anthropic.claude-3-5-sonnet-20241022-v2:0",
            "",
        );
        let (action, id, _) = BedrockService::resolve_action(&req).unwrap();
        assert_eq!(action, "GetFoundationModel");
        assert_eq!(id.unwrap(), "anthropic.claude-3-5-sonnet-20241022-v2:0");
    }

    #[test]
    fn resolve_action_guardrail_crud() {
        let req = make_request(Method::POST, "/guardrails", "{}");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "CreateGuardrail"
        );

        let req = make_request(Method::GET, "/guardrails", "");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "ListGuardrails"
        );

        let req = make_request(Method::GET, "/guardrails/abc123", "");
        let (action, id, _) = BedrockService::resolve_action(&req).unwrap();
        assert_eq!(action, "GetGuardrail");
        assert_eq!(id.unwrap(), "abc123");

        let req = make_request(Method::PUT, "/guardrails/abc123", "{}");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "UpdateGuardrail"
        );

        let req = make_request(Method::DELETE, "/guardrails/abc123", "");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "DeleteGuardrail"
        );
    }

    #[test]
    fn resolve_action_invoke_model() {
        let req = make_request(Method::POST, "/model/anthropic.claude-v2/invoke", "{}");
        let (action, id, _) = BedrockService::resolve_action(&req).unwrap();
        assert_eq!(action, "InvokeModel");
        assert_eq!(id.unwrap(), "anthropic.claude-v2");
    }

    #[test]
    fn resolve_action_converse() {
        let req = make_request(Method::POST, "/model/anthropic.claude-v2/converse", "{}");
        let (action, id, _) = BedrockService::resolve_action(&req).unwrap();
        assert_eq!(action, "Converse");
        assert_eq!(id.unwrap(), "anthropic.claude-v2");
    }

    #[test]
    fn resolve_action_converse_stream() {
        let req = make_request(
            Method::POST,
            "/model/anthropic.claude-v2/converse-stream",
            "{}",
        );
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "ConverseStream"
        );
    }

    #[test]
    fn resolve_action_invoke_stream() {
        let req = make_request(Method::POST, "/model/m1/invoke-with-response-stream", "{}");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "InvokeModelWithResponseStream"
        );
    }

    #[test]
    fn resolve_action_tags() {
        let req = make_request(Method::POST, "/tagResource", "{}");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "TagResource"
        );

        let req = make_request(Method::POST, "/untagResource", "{}");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "UntagResource"
        );

        let req = make_request(Method::POST, "/listTagsForResource", "{}");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "ListTagsForResource"
        );
    }

    #[test]
    fn resolve_action_logging() {
        let req = make_request(Method::PUT, "/logging/modelinvocations", "{}");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "PutModelInvocationLoggingConfiguration"
        );

        let req = make_request(Method::GET, "/logging/modelinvocations", "");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "GetModelInvocationLoggingConfiguration"
        );

        let req = make_request(Method::DELETE, "/logging/modelinvocations", "");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "DeleteModelInvocationLoggingConfiguration"
        );
    }

    #[test]
    fn resolve_action_custom_models() {
        let req = make_request(Method::POST, "/custom-models/create-custom-model", "{}");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "CreateCustomModel"
        );

        let req = make_request(Method::GET, "/custom-models", "");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "ListCustomModels"
        );

        let req = make_request(Method::GET, "/custom-models/my-model", "");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "GetCustomModel"
        );

        let req = make_request(Method::DELETE, "/custom-models/my-model", "");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "DeleteCustomModel"
        );
    }

    #[test]
    fn resolve_action_inference_profiles() {
        let req = make_request(Method::POST, "/inference-profiles", "{}");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "CreateInferenceProfile"
        );

        let req = make_request(Method::GET, "/inference-profiles", "");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "ListInferenceProfiles"
        );

        let req = make_request(Method::GET, "/inference-profiles/ip-1", "");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "GetInferenceProfile"
        );

        let req = make_request(Method::DELETE, "/inference-profiles/ip-1", "");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "DeleteInferenceProfile"
        );
    }

    #[test]
    fn resolve_action_provisioned_throughput() {
        let req = make_request(Method::POST, "/provisioned-model-throughput", "{}");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "CreateProvisionedModelThroughput"
        );

        let req = make_request(Method::GET, "/provisioned-model-throughputs", "");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "ListProvisionedModelThroughputs"
        );
    }

    #[test]
    fn resolve_action_async_invoke() {
        let req = make_request(Method::POST, "/async-invoke", "{}");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "StartAsyncInvoke"
        );

        let req = make_request(Method::GET, "/async-invoke", "");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "ListAsyncInvokes"
        );

        let req = make_request(Method::GET, "/async-invoke/inv-1", "");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "GetAsyncInvoke"
        );
    }

    #[test]
    fn resolve_action_unknown_returns_none() {
        let req = make_request(Method::POST, "/nonexistent", "{}");
        assert!(BedrockService::resolve_action(&req).is_none());
    }

    #[test]
    fn resolve_action_apply_guardrail() {
        let req = make_request(Method::POST, "/guardrail/g1/version/1/apply", "{}");
        let (action, id, extra) = BedrockService::resolve_action(&req).unwrap();
        assert_eq!(action, "ApplyGuardrail");
        assert_eq!(id.unwrap(), "g1");
        assert_eq!(extra.unwrap(), "1");
    }

    #[test]
    fn resolve_action_resource_policy() {
        let req = make_request(Method::POST, "/resource-policy", "{}");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "PutResourcePolicy"
        );

        let req = make_request(Method::GET, "/resource-policy/arn:aws:something", "");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "GetResourcePolicy"
        );

        let req = make_request(Method::DELETE, "/resource-policy/arn:aws:something", "");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "DeleteResourcePolicy"
        );
    }

    #[test]
    fn resolve_action_count_tokens() {
        let req = make_request(Method::POST, "/model/m1/count-tokens", "{}");
        assert_eq!(
            BedrockService::resolve_action(&req).unwrap().0,
            "CountTokens"
        );
    }

    // ── ListFoundationModels ──

    #[tokio::test]
    async fn list_foundation_models_returns_models() {
        let state = make_state();
        let svc = BedrockService::new(state);
        let req = make_request(Method::GET, "/foundation-models", "");
        let resp = svc.handle(req).await.unwrap();
        let b = body_json(&resp);
        let models = b["modelSummaries"].as_array().unwrap();
        assert!(!models.is_empty());
        // Each model has required fields
        let first = &models[0];
        assert!(first["modelId"].as_str().is_some());
        assert!(first["providerName"].as_str().is_some());
    }

    #[tokio::test]
    async fn list_foundation_models_filter_by_provider() {
        let state = make_state();
        let svc = BedrockService::new(state);
        let mut query = HashMap::new();
        query.insert("byProvider".to_string(), "Anthropic".to_string());
        let req = make_request_with_query(Method::GET, "/foundation-models", "", query);
        let resp = svc.handle(req).await.unwrap();
        let b = body_json(&resp);
        let models = b["modelSummaries"].as_array().unwrap();
        assert!(!models.is_empty());
        for m in models {
            assert_eq!(m["providerName"], "Anthropic");
        }
    }

    #[tokio::test]
    async fn list_foundation_models_filter_by_output_modality() {
        let state = make_state();
        let svc = BedrockService::new(state);
        let mut query = HashMap::new();
        query.insert("byOutputModality".to_string(), "IMAGE".to_string());
        let req = make_request_with_query(Method::GET, "/foundation-models", "", query);
        let resp = svc.handle(req).await.unwrap();
        let b = body_json(&resp);
        let models = b["modelSummaries"].as_array().unwrap();
        for m in models {
            let output = m["outputModalities"].as_array().unwrap();
            assert!(output.iter().any(|v| v == "IMAGE"));
        }
    }

    // ── GetFoundationModel ──

    #[tokio::test]
    async fn get_foundation_model_found() {
        let state = make_state();
        let svc = BedrockService::new(state);
        let req = make_request(
            Method::GET,
            "/foundation-models/anthropic.claude-3-5-sonnet-20241022-v2:0",
            "",
        );
        let resp = svc.handle(req).await.unwrap();
        let b = body_json(&resp);
        assert_eq!(
            b["modelDetails"]["modelId"],
            "anthropic.claude-3-5-sonnet-20241022-v2:0"
        );
        assert!(b["modelDetails"]["modelArn"]
            .as_str()
            .unwrap()
            .contains("foundation-model"));
    }

    #[tokio::test]
    async fn get_foundation_model_not_found() {
        let state = make_state();
        let svc = BedrockService::new(state);
        let req = make_request(Method::GET, "/foundation-models/nonexistent.model", "");
        let err = expect_err(svc.handle(req).await);
        assert!(err.to_string().contains("ResourceNotFoundException"));
    }

    // ── Tags ──

    #[tokio::test]
    async fn tag_list_untag_resource() {
        let state = make_state();
        let svc = BedrockService::new(state);

        let arn = "arn:aws:bedrock:us-east-1:123456789012:guardrail/g1";
        let body = serde_json::json!({
            "resourceARN": arn,
            "tags": [{"key": "env", "value": "prod"}, {"key": "team", "value": "ml"}],
        });
        let req = make_request(Method::POST, "/tagResource", &body.to_string());
        svc.handle(req).await.unwrap();

        // List tags
        let body = serde_json::json!({"resourceARN": arn});
        let req = make_request(Method::POST, "/listTagsForResource", &body.to_string());
        let resp = svc.handle(req).await.unwrap();
        let b = body_json(&resp);
        let tags = b["tags"].as_array().unwrap();
        assert_eq!(tags.len(), 2);

        // Untag
        let body = serde_json::json!({
            "resourceARN": arn,
            "tagKeys": ["env"],
        });
        let req = make_request(Method::POST, "/untagResource", &body.to_string());
        svc.handle(req).await.unwrap();

        // List again
        let body = serde_json::json!({"resourceARN": arn});
        let req = make_request(Method::POST, "/listTagsForResource", &body.to_string());
        let resp = svc.handle(req).await.unwrap();
        let b = body_json(&resp);
        let tags = b["tags"].as_array().unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags[0]["key"], "team");
    }

    #[tokio::test]
    async fn tag_resource_requires_arn() {
        let state = make_state();
        let svc = BedrockService::new(state);

        let body = serde_json::json!({
            "tags": [{"key": "a", "value": "b"}],
        });
        let req = make_request(Method::POST, "/tagResource", &body.to_string());
        let err = expect_err(svc.handle(req).await);
        assert!(err.to_string().contains("ValidationException"));
    }

    #[tokio::test]
    async fn tag_resource_requires_tags() {
        let state = make_state();
        let svc = BedrockService::new(state);

        let body = serde_json::json!({
            "resourceARN": "arn:aws:bedrock:us-east-1:123456789012:guardrail/g1",
        });
        let req = make_request(Method::POST, "/tagResource", &body.to_string());
        let err = expect_err(svc.handle(req).await);
        assert!(err.to_string().contains("ValidationException"));
    }

    // ── Guardrails ──

    #[tokio::test]
    async fn guardrail_crud() {
        let state = make_state();
        let svc = BedrockService::new(state);

        // Create
        let body = serde_json::json!({
            "name": "my-guardrail",
            "blockedInputMessaging": "Blocked input",
            "blockedOutputsMessaging": "Blocked output",
        });
        let req = make_request(Method::POST, "/guardrails", &body.to_string());
        let resp = svc.handle(req).await.unwrap();
        assert_eq!(resp.status, StatusCode::CREATED);
        let b = body_json(&resp);
        let gid = b["guardrailId"].as_str().unwrap().to_string();
        assert_eq!(b["version"], "DRAFT");

        // Get
        let req = make_request(Method::GET, &format!("/guardrails/{gid}"), "");
        let resp = svc.handle(req).await.unwrap();
        let b = body_json(&resp);
        assert_eq!(b["name"], "my-guardrail");
        assert_eq!(b["status"], "READY");

        // List
        let req = make_request(Method::GET, "/guardrails", "");
        let resp = svc.handle(req).await.unwrap();
        let b = body_json(&resp);
        assert_eq!(b["guardrails"].as_array().unwrap().len(), 1);

        // Update
        let body = serde_json::json!({
            "name": "updated-guardrail",
            "blockedInputMessaging": "New blocked",
            "blockedOutputsMessaging": "New blocked out",
        });
        let req = make_request(
            Method::PUT,
            &format!("/guardrails/{gid}"),
            &body.to_string(),
        );
        svc.handle(req).await.unwrap();

        // Verify update
        let req = make_request(Method::GET, &format!("/guardrails/{gid}"), "");
        let resp = svc.handle(req).await.unwrap();
        let b = body_json(&resp);
        assert_eq!(b["name"], "updated-guardrail");

        // Delete
        let req = make_request(Method::DELETE, &format!("/guardrails/{gid}"), "");
        svc.handle(req).await.unwrap();

        // Get should fail
        let req = make_request(Method::GET, &format!("/guardrails/{gid}"), "");
        assert!(svc.handle(req).await.is_err());
    }

    #[tokio::test]
    async fn guardrail_not_found() {
        let state = make_state();
        let svc = BedrockService::new(state);

        let req = make_request(Method::GET, "/guardrails/nonexistent", "");
        let err = expect_err(svc.handle(req).await);
        assert!(err.to_string().contains("ResourceNotFoundException"));
    }

    // ── InvokeModel ──

    #[tokio::test]
    async fn invoke_model_anthropic() {
        let state = make_state();
        let svc = BedrockService::new(state);

        let body = serde_json::json!({
            "messages": [{"role": "user", "content": "Hello"}],
        });
        let req = make_request(
            Method::POST,
            "/model/anthropic.claude-v2/invoke",
            &body.to_string(),
        );
        let resp = svc.handle(req).await.unwrap();
        assert_eq!(resp.status, StatusCode::OK);
        let b: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        assert_eq!(b["type"], "message");
        assert_eq!(b["role"], "assistant");
    }

    #[tokio::test]
    async fn invoke_model_amazon_titan() {
        let state = make_state();
        let svc = BedrockService::new(state);

        let body = serde_json::json!({"inputText": "Hello"});
        let req = make_request(
            Method::POST,
            "/model/amazon.titan-text-express-v1/invoke",
            &body.to_string(),
        );
        let resp = svc.handle(req).await.unwrap();
        let b: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        assert!(!b["results"].as_array().unwrap().is_empty());
    }

    #[tokio::test]
    async fn invoke_model_meta_llama() {
        let state = make_state();
        let svc = BedrockService::new(state);

        let body = serde_json::json!({"prompt": "Hello"});
        let req = make_request(
            Method::POST,
            "/model/meta.llama3-70b-instruct-v1:0/invoke",
            &body.to_string(),
        );
        let resp = svc.handle(req).await.unwrap();
        let b: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        assert!(b["generation"].as_str().is_some());
    }

    #[tokio::test]
    async fn invoke_model_cohere() {
        let state = make_state();
        let svc = BedrockService::new(state);

        let body = serde_json::json!({"prompt": "Hello"});
        let req = make_request(
            Method::POST,
            "/model/cohere.command-r-v1:0/invoke",
            &body.to_string(),
        );
        let resp = svc.handle(req).await.unwrap();
        let b: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        assert!(b["generations"].as_array().is_some());
    }

    #[tokio::test]
    async fn invoke_model_mistral() {
        let state = make_state();
        let svc = BedrockService::new(state);

        let body = serde_json::json!({"prompt": "Hello"});
        let req = make_request(
            Method::POST,
            "/model/mistral.mistral-7b-instruct-v0:2/invoke",
            &body.to_string(),
        );
        let resp = svc.handle(req).await.unwrap();
        let b: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        assert!(b["outputs"].as_array().is_some());
    }

    #[tokio::test]
    async fn invoke_model_records_invocation() {
        let state = make_state();
        let svc = BedrockService::new(state.clone());

        let body = serde_json::json!({"prompt": "test"});
        let req = make_request(
            Method::POST,
            "/model/anthropic.claude-v2/invoke",
            &body.to_string(),
        );
        svc.handle(req).await.unwrap();

        let _accts = state.read();
        let s = _accts.default_ref();
        assert_eq!(s.invocations.len(), 1);
        assert_eq!(s.invocations[0].model_id, "anthropic.claude-v2");
    }

    #[tokio::test]
    async fn invoke_model_titan_embed() {
        let state = make_state();
        let svc = BedrockService::new(state);

        let body = serde_json::json!({"inputText": "Hello"});
        let req = make_request(
            Method::POST,
            "/model/amazon.titan-embed-text-v1/invoke",
            &body.to_string(),
        );
        let resp = svc.handle(req).await.unwrap();
        let b: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        assert!(b["embedding"].as_array().is_some());
    }

    // ── Converse ──

    #[tokio::test]
    async fn converse_basic() {
        let state = make_state();
        let svc = BedrockService::new(state);

        let body = serde_json::json!({
            "messages": [{"role": "user", "content": [{"text": "Hello world"}]}],
        });
        let req = make_request(
            Method::POST,
            "/model/anthropic.claude-v2/converse",
            &body.to_string(),
        );
        let resp = svc.handle(req).await.unwrap();
        let b = body_json(&resp);
        assert_eq!(b["stopReason"], "end_turn");
        assert!(b["usage"]["inputTokens"].as_u64().is_some());
        assert!(b["output"]["message"]["content"][0]["text"]
            .as_str()
            .is_some());
    }

    #[tokio::test]
    async fn converse_with_tool_config() {
        let state = make_state();
        let svc = BedrockService::new(state);

        let body = serde_json::json!({
            "messages": [{"role": "user", "content": [{"text": "Use the tool"}]}],
            "toolConfig": {
                "tools": [{"toolSpec": {"name": "calculator", "description": "calc"}}]
            },
        });
        let req = make_request(
            Method::POST,
            "/model/anthropic.claude-v2/converse",
            &body.to_string(),
        );
        let resp = svc.handle(req).await.unwrap();
        let b = body_json(&resp);
        assert_eq!(b["stopReason"], "tool_use");
        let content = b["output"]["message"]["content"].as_array().unwrap();
        assert!(content.iter().any(|c| c.get("toolUse").is_some()));
    }

    // ── CountTokens ──

    #[tokio::test]
    async fn count_tokens_basic() {
        let state = make_state();
        let svc = BedrockService::new(state);

        let body = serde_json::json!({
            "input": {
                "converse": {
                    "messages": [{"role": "user", "content": [{"text": "hello world foo bar"}]}]
                }
            }
        });
        let req = make_request(
            Method::POST,
            "/model/anthropic.claude-v2/count-tokens",
            &body.to_string(),
        );
        let resp = svc.handle(req).await.unwrap();
        let b = body_json(&resp);
        assert!(b["inputTokens"].as_u64().unwrap() > 0);
    }

    // ── Logging ──

    #[tokio::test]
    async fn logging_configuration_crud() {
        let state = make_state();
        let svc = BedrockService::new(state);

        // Get before put -> empty
        let req = make_request(Method::GET, "/logging/modelinvocations", "");
        let resp = svc.handle(req).await.unwrap();
        let b = body_json(&resp);
        assert!(b.get("loggingConfig").is_none());

        // Put
        let body = serde_json::json!({
            "loggingConfig": {
                "textDataDeliveryEnabled": true,
                "imageDataDeliveryEnabled": false,
                "s3Config": {"bucketName": "my-bucket", "keyPrefix": "logs/"},
            }
        });
        let req = make_request(Method::PUT, "/logging/modelinvocations", &body.to_string());
        svc.handle(req).await.unwrap();

        // Get after put
        let req = make_request(Method::GET, "/logging/modelinvocations", "");
        let resp = svc.handle(req).await.unwrap();
        let b = body_json(&resp);
        assert_eq!(b["loggingConfig"]["textDataDeliveryEnabled"], true);
        assert_eq!(b["loggingConfig"]["imageDataDeliveryEnabled"], false);
        assert_eq!(b["loggingConfig"]["s3Config"]["bucketName"], "my-bucket");

        // Delete
        let req = make_request(Method::DELETE, "/logging/modelinvocations", "");
        svc.handle(req).await.unwrap();

        // Get after delete -> empty again
        let req = make_request(Method::GET, "/logging/modelinvocations", "");
        let resp = svc.handle(req).await.unwrap();
        let b = body_json(&resp);
        assert!(b.get("loggingConfig").is_none());
    }

    // ── Resource policies ──

    #[tokio::test]
    async fn resource_policy_crud() {
        let state = make_state();
        let svc = BedrockService::new(state);

        // Use a simple ID for the path (no slashes) since path-based routing
        // splits on /. The ARN goes in the body for Put.
        let arn = "my-resource-arn";
        let policy = r#"{"Version":"2012-10-17","Statement":[]}"#;

        // Put
        let body = serde_json::json!({
            "resourceArn": arn,
            "resourcePolicy": policy,
        });
        let req = make_request(Method::POST, "/resource-policy", &body.to_string());
        let resp = svc.handle(req).await.unwrap();
        let b = body_json(&resp);
        assert_eq!(b["resourceArn"], arn);
        assert!(b["revisionId"].as_str().is_some());

        // Get — path segment must be a single segment
        let req = make_request(Method::GET, &format!("/resource-policy/{arn}"), "");
        let resp = svc.handle(req).await.unwrap();
        let b = body_json(&resp);
        assert_eq!(b["resourcePolicy"], policy);

        // Delete
        let req = make_request(Method::DELETE, &format!("/resource-policy/{arn}"), "");
        svc.handle(req).await.unwrap();

        // Get after delete -> not found
        let req = make_request(Method::GET, &format!("/resource-policy/{arn}"), "");
        assert!(svc.handle(req).await.is_err());
    }

    // ── Streaming ──

    #[tokio::test]
    async fn invoke_model_with_response_stream() {
        let state = make_state();
        let svc = BedrockService::new(state);

        let body = serde_json::json!({"prompt": "Hello"});
        let req = make_request(
            Method::POST,
            "/model/anthropic.claude-v2/invoke-with-response-stream",
            &body.to_string(),
        );
        let resp = svc.handle(req).await.unwrap();
        assert_eq!(resp.status, StatusCode::OK);
        assert_eq!(resp.content_type, "application/vnd.amazon.eventstream");
        assert!(!resp.body.expect_bytes().is_empty());
    }

    #[tokio::test]
    async fn converse_stream() {
        let state = make_state();
        let svc = BedrockService::new(state);

        let body = serde_json::json!({
            "messages": [{"role": "user", "content": [{"text": "Hello"}]}],
        });
        let req = make_request(
            Method::POST,
            "/model/anthropic.claude-v2/converse-stream",
            &body.to_string(),
        );
        let resp = svc.handle(req).await.unwrap();
        assert_eq!(resp.content_type, "application/vnd.amazon.eventstream");
        assert!(!resp.body.expect_bytes().is_empty());
    }

    // ── Unknown route ──

    #[tokio::test]
    async fn unknown_route_returns_error() {
        let state = make_state();
        let svc = BedrockService::new(state);

        let req = make_request(Method::POST, "/nonexistent/route", "{}");
        assert!(svc.handle(req).await.is_err());
    }

    // ── Custom Models CRUD (direct handler calls to avoid ARN-in-path issues) ──

    #[test]
    fn custom_model_crud() {
        let state = make_state();
        let req = make_request(
            Method::POST,
            "/custom-models/create-custom-model",
            r#"{"modelName":"my-model"}"#,
        );
        let body = req.json_body();
        let resp = crate::custom_models::create_custom_model(&state, &req, &body).unwrap();
        assert_eq!(resp.status, StatusCode::CREATED);
        let b = body_json(&resp);
        let arn = b["modelArn"].as_str().unwrap();

        let resp = crate::custom_models::get_custom_model(&state, &req, arn).unwrap();
        let b = body_json(&resp);
        assert_eq!(b["modelName"], "my-model");

        let resp = crate::custom_models::list_custom_models(&state, &req).unwrap();
        let b = body_json(&resp);
        assert_eq!(b["modelSummaries"].as_array().unwrap().len(), 1);

        crate::custom_models::delete_custom_model(&state, &req, arn).unwrap();
        assert!(crate::custom_models::get_custom_model(&state, &req, arn).is_err());
    }

    #[test]
    fn custom_model_deployment_crud() {
        let state = make_state();
        let req = make_request(
            Method::POST,
            "/",
            r#"{"modelDeploymentName":"dep1","modelArn":"m1"}"#,
        );
        let body = req.json_body();
        let resp =
            crate::custom_model_deployments::create_custom_model_deployment(&state, &req, &body)
                .unwrap();
        let b = body_json(&resp);
        let arn = b["customModelDeploymentArn"].as_str().unwrap();

        crate::custom_model_deployments::get_custom_model_deployment(&state, &req, arn).unwrap();

        let resp =
            crate::custom_model_deployments::list_custom_model_deployments(&state, &req).unwrap();
        let b = body_json(&resp);
        assert!(!b["modelDeploymentSummaries"].as_array().unwrap().is_empty());

        let upd = serde_json::json!({"desiredModelUnits": 2});
        crate::custom_model_deployments::update_custom_model_deployment(&state, &req, arn, &upd)
            .unwrap();
        crate::custom_model_deployments::delete_custom_model_deployment(&state, &req, arn).unwrap();
    }

    #[test]
    fn model_import_job_crud() {
        let state = make_state();
        let req = make_request(
            Method::POST,
            "/",
            r#"{"jobName":"imp","importedModelName":"m","roleArn":"arn:aws:iam::1:role/r","modelDataSource":{"s3DataSource":{"s3Uri":"s3://b"}}}"#,
        );
        let body = req.json_body();
        let resp = crate::model_import::create_model_import_job(&state, &req, &body).unwrap();
        let b = body_json(&resp);
        let arn = b["jobArn"].as_str().unwrap();

        crate::model_import::get_model_import_job(&state, &req, arn).unwrap();
        let resp = crate::model_import::list_model_import_jobs(&state, &req).unwrap();
        let b = body_json(&resp);
        assert!(!b["modelImportJobSummaries"].as_array().unwrap().is_empty());

        let resp = crate::model_import::list_imported_models(&state, &req).unwrap();
        let b = body_json(&resp);
        assert!(!b["modelSummaries"].as_array().unwrap().is_empty());
    }

    #[test]
    fn model_copy_job_crud() {
        let state = make_state();
        let req = make_request(
            Method::POST,
            "/",
            r#"{"sourceModelArn":"arn:aws:bedrock:us-west-2:1:fm/m","targetModelName":"cp"}"#,
        );
        let body = req.json_body();
        let resp = crate::model_copy::create_model_copy_job(&state, &req, &body).unwrap();
        let b = body_json(&resp);
        let arn = b["jobArn"].as_str().unwrap();

        crate::model_copy::get_model_copy_job(&state, &req, arn).unwrap();
        let resp = crate::model_copy::list_model_copy_jobs(&state, &req).unwrap();
        let b = body_json(&resp);
        assert!(!b["modelCopyJobSummaries"].as_array().unwrap().is_empty());
    }

    #[test]
    fn invocation_job_crud() {
        let state = make_state();
        let req = make_request(
            Method::POST,
            "/",
            r#"{"jobName":"batch","modelId":"m","roleArn":"arn:aws:iam::1:role/r","inputDataConfig":{"s3InputDataConfig":{"s3Uri":"s3://i"}},"outputDataConfig":{"s3OutputDataConfig":{"s3Uri":"s3://o"}}}"#,
        );
        let body = req.json_body();
        let resp =
            crate::invocation_jobs::create_model_invocation_job(&state, &req, &body).unwrap();
        let b = body_json(&resp);
        let arn = b["jobArn"].as_str().unwrap();

        crate::invocation_jobs::get_model_invocation_job(&state, &req, arn).unwrap();
        let resp = crate::invocation_jobs::list_model_invocation_jobs(&state, &req).unwrap();
        let b = body_json(&resp);
        assert!(!b["invocationJobSummaries"].as_array().unwrap().is_empty());
        crate::invocation_jobs::stop_model_invocation_job(&state, &req, arn).unwrap();
    }

    #[test]
    fn evaluation_job_crud() {
        let state = make_state();
        let req = make_request(
            Method::POST,
            "/",
            r#"{"jobName":"eval","roleArn":"arn:aws:iam::1:role/r","evaluationConfig":{},"inferenceConfig":{},"outputDataConfig":{"s3Uri":"s3://o"}}"#,
        );
        let body = req.json_body();
        let resp = crate::evaluation::create_evaluation_job(&state, &req, &body).unwrap();
        let b = body_json(&resp);
        let arn = b["jobArn"].as_str().unwrap();

        crate::evaluation::get_evaluation_job(&state, &req, arn).unwrap();
        let resp = crate::evaluation::list_evaluation_jobs(&state, &req).unwrap();
        let b = body_json(&resp);
        assert!(!b["jobSummaries"].as_array().unwrap().is_empty());
    }

    #[test]
    fn inference_profile_crud() {
        let state = make_state();
        let req = make_request(
            Method::POST,
            "/",
            r#"{"inferenceProfileName":"prof","modelSource":{"copyFrom":"arn:aws:bedrock:us-east-1::fm/m"}}"#,
        );
        let body = req.json_body();
        let resp =
            crate::inference_profiles::create_inference_profile(&state, &req, &body).unwrap();
        let b = body_json(&resp);
        let arn = b["inferenceProfileArn"].as_str().unwrap();

        crate::inference_profiles::get_inference_profile(&state, &req, arn).unwrap();
        let resp = crate::inference_profiles::list_inference_profiles(&state, &req).unwrap();
        let b = body_json(&resp);
        assert!(!b["inferenceProfileSummaries"]
            .as_array()
            .unwrap()
            .is_empty());
        crate::inference_profiles::delete_inference_profile(&state, &req, arn).unwrap();
    }

    #[test]
    fn prompt_router_crud() {
        let state = make_state();
        let req = make_request(
            Method::POST,
            "/",
            r#"{"promptRouterName":"rt","models":[{"modelArn":"arn:aws:bedrock:us-east-1::fm/m"}],"fallbackModel":{"modelArn":"arn:aws:bedrock:us-east-1::fm/m"},"routingCriteria":{"responseQualityDifference":0.5}}"#,
        );
        let body = req.json_body();
        let resp = crate::prompt_routers::create_prompt_router(&state, &req, &body).unwrap();
        let b = body_json(&resp);
        let arn = b["promptRouterArn"].as_str().unwrap();

        crate::prompt_routers::get_prompt_router(&state, &req, arn).unwrap();
        let resp = crate::prompt_routers::list_prompt_routers(&state, &req).unwrap();
        let b = body_json(&resp);
        assert!(!b["promptRouterSummaries"].as_array().unwrap().is_empty());
        crate::prompt_routers::delete_prompt_router(&state, &req, arn).unwrap();
    }

    #[test]
    fn customization_job_crud() {
        let state = make_state();
        let req = make_request(
            Method::POST,
            "/",
            r#"{"jobName":"ft","customModelName":"cm","roleArn":"arn:aws:iam::1:role/r","baseModelIdentifier":"m","trainingDataConfig":{"s3Uri":"s3://t"},"outputDataConfig":{"s3Uri":"s3://o"}}"#,
        );
        let body = req.json_body();
        let resp =
            crate::customization::create_model_customization_job(&state, &req, &body).unwrap();
        let b = body_json(&resp);
        let arn = b["jobArn"].as_str().unwrap();

        crate::customization::get_model_customization_job(&state, &req, arn).unwrap();
        let resp = crate::customization::list_model_customization_jobs(&state, &req).unwrap();
        let b = body_json(&resp);
        assert!(!b["modelCustomizationJobSummaries"]
            .as_array()
            .unwrap()
            .is_empty());
    }

    #[test]
    fn provisioned_throughput_crud() {
        let state = make_state();
        let req = make_request(
            Method::POST,
            "/",
            r#"{"provisionedModelName":"pt","modelId":"m","modelUnits":1}"#,
        );
        let body = req.json_body();
        let resp =
            crate::throughput::create_provisioned_model_throughput(&state, &req, &body).unwrap();
        let b = body_json(&resp);
        let arn = b["provisionedModelArn"].as_str().unwrap();

        crate::throughput::get_provisioned_model_throughput(&state, &req, arn).unwrap();
        let resp = crate::throughput::list_provisioned_model_throughputs(&state, &req).unwrap();
        let b = body_json(&resp);
        assert!(!b["provisionedModelSummaries"]
            .as_array()
            .unwrap()
            .is_empty());

        let upd = serde_json::json!({"desiredModelUnits": 2});
        crate::throughput::update_provisioned_model_throughput(&state, &req, arn, &upd).unwrap();
        crate::throughput::delete_provisioned_model_throughput(&state, &req, arn).unwrap();
    }

    #[test]
    fn marketplace_endpoint_crud() {
        let state = make_state();
        let req = make_request(
            Method::POST,
            "/",
            r#"{"endpointName":"ep","modelSourceIdentifier":"arn:aws:sm:us-east-1:1:mp/p","endpointConfig":{"sageMaker":{"initialInstanceCount":1,"instanceType":"ml.g5.xlarge"}}}"#,
        );
        let body = req.json_body();
        let resp =
            crate::marketplace::create_marketplace_model_endpoint(&state, &req, &body).unwrap();
        let b = body_json(&resp);
        let arn = b["marketplaceModelEndpointArn"].as_str().unwrap();

        crate::marketplace::get_marketplace_model_endpoint(&state, &req, arn).unwrap();
        let resp = crate::marketplace::list_marketplace_model_endpoints(&state, &req).unwrap();
        let b = body_json(&resp);
        assert!(!b["marketplaceModelEndpoints"]
            .as_array()
            .unwrap()
            .is_empty());
        crate::marketplace::delete_marketplace_model_endpoint(&state, &req, arn).unwrap();
    }

    #[test]
    fn async_invoke_crud() {
        let state = make_state();
        let req = make_request(
            Method::POST,
            "/",
            r#"{"modelId":"m","modelInput":{"prompt":"t"},"outputDataConfig":{"s3OutputDataConfig":{"s3Uri":"s3://o"}}}"#,
        );
        let body = req.json_body();
        let resp = crate::async_invoke::start_async_invoke(&state, &req, &body).unwrap();
        let b = body_json(&resp);
        let arn = b["invocationArn"].as_str().unwrap();

        crate::async_invoke::get_async_invoke(&state, &req, arn).unwrap();
        let resp = crate::async_invoke::list_async_invokes(&state, &req).unwrap();
        let b = body_json(&resp);
        assert!(!b["asyncInvokeSummaries"].as_array().unwrap().is_empty());
    }

    #[test]
    fn automated_reasoning_policy_crud() {
        let state = make_state();
        let req = make_request(
            Method::POST,
            "/",
            r#"{"policyName":"pol","policyDocument":{"rules":[]}}"#,
        );
        let body = req.json_body();
        let resp =
            crate::automated_reasoning::create_automated_reasoning_policy(&state, &req, &body)
                .unwrap();
        let b = body_json(&resp);
        let arn = b["policyArn"].as_str().unwrap();

        crate::automated_reasoning::get_automated_reasoning_policy(&state, &req, arn).unwrap();
        let resp =
            crate::automated_reasoning::list_automated_reasoning_policies(&state, &req).unwrap();
        let b = body_json(&resp);
        assert!(!b["policySummaries"].as_array().unwrap().is_empty());

        let upd = serde_json::json!({"description": "updated"});
        crate::automated_reasoning::update_automated_reasoning_policy(&state, &req, arn, &upd)
            .unwrap();
        crate::automated_reasoning::delete_automated_reasoning_policy(&state, &req, arn).unwrap();
    }

    #[test]
    fn foundation_model_agreement_and_use_case() {
        let state = make_state();
        let req = make_request(Method::POST, "/", r#"{"modelId":"m","offerToken":"t"}"#);
        let body = req.json_body();
        crate::foundation_model_agreements::create_foundation_model_agreement(&state, &req, &body)
            .unwrap();

        crate::foundation_model_agreements::get_use_case_for_model_access(&state, &req).unwrap();
    }

    #[test]
    fn enforced_guardrail_config() {
        let state = make_state();
        let body = serde_json::json!({"guardrailIdentifier":"g1","guardrailVersion":"1","modelArn":"arn:m"});
        let req = make_request(Method::POST, "/", "{}");
        crate::enforced_guardrails::put_enforced_guardrail_configuration(&state, &req, &body)
            .unwrap();

        let req = make_request(Method::GET, "/", "");
        crate::enforced_guardrails::list_enforced_guardrails_configuration(&state, &req).unwrap();
    }

    #[tokio::test]
    async fn unknown_route_returns_error_b() {
        let state = make_state();
        let svc = BedrockService::new(state);
        let req = make_request(Method::POST, "/unknown/route", "");
        assert!(svc.handle(req).await.is_err());
    }

    #[test]
    fn automated_reasoning_policy_not_found_get() {
        let state = make_state();
        let req = make_request(Method::GET, "/", "{}");
        let result = crate::automated_reasoning::get_automated_reasoning_policy(
            &state,
            &req,
            "arn:aws:bedrock:us-east-1:123:automated-reasoning-policy/ghost",
        );
        assert!(result.is_err());
    }

    #[test]
    fn automated_reasoning_policy_delete_not_found() {
        let state = make_state();
        let req = make_request(Method::DELETE, "/", "{}");
        let result = crate::automated_reasoning::delete_automated_reasoning_policy(
            &state,
            &req,
            "arn:aws:bedrock:us-east-1:123:automated-reasoning-policy/ghost",
        );
        assert!(result.is_err());
    }
}
