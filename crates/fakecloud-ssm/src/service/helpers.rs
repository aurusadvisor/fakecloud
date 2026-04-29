use super::*;

/// Actions that do NOT mutate SSM state. Everything else triggers a
/// snapshot save on HTTP 2xx. Listing non-mutating actions (rather than
/// mutating ones) is safer here because SSM has ~150 actions and the
/// read-only set is small and stable.
pub(crate) fn is_read_only_action(action: &str) -> bool {
    matches!(
        action,
        "GetParameter"
            | "GetParameters"
            | "GetParametersByPath"
            | "DescribeParameters"
            | "GetParameterHistory"
            | "ListTagsForResource"
            | "GetDocument"
            | "DescribeDocument"
            | "ListDocuments"
            | "DescribeDocumentPermission"
            | "ListCommands"
            | "GetCommandInvocation"
            | "ListCommandInvocations"
            | "DescribeMaintenanceWindows"
            | "GetMaintenanceWindow"
            | "DescribeMaintenanceWindowTargets"
            | "DescribeMaintenanceWindowTasks"
            | "DescribePatchBaselines"
            | "GetPatchBaseline"
            | "GetPatchBaselineForPatchGroup"
            | "DescribePatchGroups"
            | "DescribeAssociation"
            | "ListAssociations"
            | "ListAssociationVersions"
            | "DescribeAssociationExecutions"
            | "DescribeAssociationExecutionTargets"
            | "GetOpsItem"
            | "DescribeOpsItems"
            | "ListDocumentVersions"
            | "ListDocumentMetadataHistory"
            | "GetResourcePolicies"
            | "GetInventory"
            | "GetInventorySchema"
            | "ListInventoryEntries"
            | "DescribeInventoryDeletions"
            | "ListComplianceItems"
            | "ListComplianceSummaries"
            | "ListResourceComplianceSummaries"
            | "GetMaintenanceWindowTask"
            | "GetMaintenanceWindowExecution"
            | "GetMaintenanceWindowExecutionTask"
            | "GetMaintenanceWindowExecutionTaskInvocation"
            | "DescribeMaintenanceWindowExecutions"
            | "DescribeMaintenanceWindowExecutionTasks"
            | "DescribeMaintenanceWindowExecutionTaskInvocations"
            | "DescribeMaintenanceWindowSchedule"
            | "DescribeMaintenanceWindowsForTarget"
            | "DescribeInstancePatchStates"
            | "DescribeInstancePatchStatesForPatchGroup"
            | "DescribeInstancePatches"
            | "DescribeEffectivePatchesForPatchBaseline"
            | "GetDeployablePatchSnapshotForInstance"
            | "ListResourceDataSync"
            | "ListOpsItemRelatedItems"
            | "ListOpsItemEvents"
            | "GetOpsMetadata"
            | "ListOpsMetadata"
            | "GetOpsSummary"
            | "GetAutomationExecution"
            | "DescribeAutomationExecutions"
            | "DescribeAutomationStepExecutions"
            | "GetExecutionPreview"
            | "DescribeSessions"
            | "GetAccessToken"
            | "DescribeActivations"
            | "DescribeInstanceInformation"
            | "DescribeInstanceProperties"
            | "ListNodes"
            | "ListNodesSummary"
            | "DescribeEffectiveInstanceAssociations"
            | "DescribeInstanceAssociationsStatus"
            | "GetConnectionStatus"
            | "GetCalendarState"
            | "DescribePatchGroupState"
            | "DescribePatchProperties"
            | "DescribeAvailablePatches"
            | "GetDefaultPatchBaseline"
            | "GetServiceSetting"
    )
}

pub(crate) fn missing(name: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ValidationException",
        format!("The request must contain the parameter {name}"),
    )
}
