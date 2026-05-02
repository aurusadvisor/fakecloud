use async_trait::async_trait;
use chrono::Utc;
use http::StatusCode;
use std::collections::BTreeMap;
use std::sync::Arc;

use fakecloud_core::delivery::DeliveryBus;
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
use fakecloud_dynamodb::SharedDynamoDbState;
use fakecloud_eventbridge::SharedEventBridgeState;
use fakecloud_iam::SharedIamState;
use fakecloud_logs::SharedLogsState;
use fakecloud_persistence::SnapshotStore;
use fakecloud_s3::SharedS3State;
use fakecloud_sns::SharedSnsState;
use fakecloud_sqs::SharedSqsState;
use fakecloud_ssm::SharedSsmState;
use tokio::sync::Mutex as AsyncMutex;

use crate::resource_provisioner::ResourceProvisioner;
use crate::state;
use crate::state::{
    CloudFormationSnapshot, CloudFormationState, SharedCloudFormationState, Stack, StackResource,
    CLOUDFORMATION_SNAPSHOT_SCHEMA_VERSION,
};
use crate::template;
use crate::xml_responses;

/// Multi-pass provisioning for all resources in a parsed template.
///
/// Resources may `Ref` each other in either direction, and JSON object
/// iteration order isn't stable, so a single forward pass isn't enough
/// to resolve them. We loop: each pass tries every pending resource, and
/// any resource whose `Ref` targets are still unknown just stays pending
/// for the next pass. When no pass makes progress we report the first
/// pending failure and rollback.
fn provision_stack_resources(
    provisioner: &ResourceProvisioner,
    resource_defs: &[template::ResourceDefinition],
    template_body: &str,
    parameters: &BTreeMap<String, String>,
) -> Result<Vec<StackResource>, AwsServiceError> {
    let mut resources = Vec::new();
    let mut physical_ids: BTreeMap<String, String> = BTreeMap::new();
    let mut attributes: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut pending: Vec<&template::ResourceDefinition> = resource_defs.iter().collect();
    let max_passes = pending.len() + 1;

    for _ in 0..max_passes {
        if pending.is_empty() {
            break;
        }
        let mut still_pending = Vec::new();
        let mut made_progress = false;

        for resource_def in pending {
            let resolved_def = template::resolve_resource_properties_with_attrs(
                resource_def,
                template_body,
                parameters,
                &physical_ids,
                &attributes,
            )
            .map_err(|e| {
                AwsServiceError::aws_error(StatusCode::BAD_REQUEST, "ValidationError", e)
            })?;

            match provisioner.create_resource(&resolved_def) {
                Ok(stack_resource) => {
                    physical_ids.insert(
                        stack_resource.logical_id.clone(),
                        stack_resource.physical_id.clone(),
                    );
                    attributes.insert(
                        stack_resource.logical_id.clone(),
                        stack_resource.attributes.clone(),
                    );
                    resources.push(stack_resource);
                    made_progress = true;
                }
                Err(_) => still_pending.push(resource_def),
            }
        }

        pending = still_pending;
        if !made_progress && !pending.is_empty() {
            // No progress — report the first failure and rollback anything
            // we already created.
            let resource_def = pending[0];
            let resolved_def = template::resolve_resource_properties_with_attrs(
                resource_def,
                template_body,
                parameters,
                &physical_ids,
                &attributes,
            )
            .unwrap_or_else(|_| resource_def.clone());
            let err = provisioner.create_resource(&resolved_def).unwrap_err();
            for r in &resources {
                let _ = provisioner.delete_resource(r);
            }
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationError",
                format!(
                    "Failed to create resource {}: {err}",
                    resource_def.logical_id
                ),
            ));
        }
    }

    Ok(resources)
}

/// State references for every service CloudFormation can provision resources in.
pub struct CloudFormationDeps {
    pub sqs: SharedSqsState,
    pub sns: SharedSnsState,
    pub ssm: SharedSsmState,
    pub iam: SharedIamState,
    pub s3: SharedS3State,
    pub eventbridge: SharedEventBridgeState,
    pub dynamodb: SharedDynamoDbState,
    pub logs: SharedLogsState,
    pub lambda: fakecloud_lambda::SharedLambdaState,
    pub secretsmanager: fakecloud_secretsmanager::SharedSecretsManagerState,
    pub kinesis: fakecloud_kinesis::SharedKinesisState,
    pub kms: fakecloud_kms::SharedKmsState,
    pub ecr: fakecloud_ecr::SharedEcrState,
    pub cloudwatch: fakecloud_cloudwatch::SharedCloudWatchState,
    pub elbv2: fakecloud_elbv2::SharedElbv2State,
    pub organizations: fakecloud_organizations::SharedOrganizationsState,
    pub cognito: fakecloud_cognito::SharedCognitoState,
    pub rds: fakecloud_rds::SharedRdsState,
    pub ecs: fakecloud_ecs::SharedEcsState,
    pub acm: fakecloud_acm::SharedAcmState,
    pub elasticache: fakecloud_elasticache::SharedElastiCacheState,
    pub route53: fakecloud_route53::SharedRoute53State,
    pub cloudfront: fakecloud_cloudfront::SharedCloudFrontState,
    pub stepfunctions: fakecloud_stepfunctions::SharedStepFunctionsState,
    pub wafv2: fakecloud_wafv2::SharedWafv2State,
    pub apigateway: fakecloud_apigateway::SharedApiGatewayState,
    pub apigatewayv2: fakecloud_apigatewayv2::SharedApiGatewayV2State,
    pub ses: fakecloud_ses::SharedSesState,
    pub delivery: Arc<DeliveryBus>,
}

pub struct CloudFormationService {
    pub(crate) state: SharedCloudFormationState,
    deps: CloudFormationDeps,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    snapshot_lock: Arc<AsyncMutex<()>>,
}

impl CloudFormationService {
    pub fn new(state: SharedCloudFormationState, deps: CloudFormationDeps) -> Self {
        Self {
            state,
            deps,
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
        let snapshot = CloudFormationSnapshot {
            schema_version: CLOUDFORMATION_SNAPSHOT_SCHEMA_VERSION,
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
            Ok(Err(err)) => tracing::error!(%err, "failed to write cloudformation snapshot"),
            Err(err) => tracing::error!(%err, "cloudformation snapshot task panicked"),
        }
    }

    pub(crate) fn provisioner(
        &self,
        stack_id: &str,
        account_id: &str,
        region: &str,
    ) -> ResourceProvisioner {
        ResourceProvisioner {
            sqs_state: self.deps.sqs.clone(),
            sns_state: self.deps.sns.clone(),
            ssm_state: self.deps.ssm.clone(),
            iam_state: self.deps.iam.clone(),
            s3_state: self.deps.s3.clone(),
            eventbridge_state: self.deps.eventbridge.clone(),
            dynamodb_state: self.deps.dynamodb.clone(),
            logs_state: self.deps.logs.clone(),
            lambda_state: self.deps.lambda.clone(),
            secretsmanager_state: self.deps.secretsmanager.clone(),
            kinesis_state: self.deps.kinesis.clone(),
            kms_state: self.deps.kms.clone(),
            ecr_state: self.deps.ecr.clone(),
            cloudwatch_state: self.deps.cloudwatch.clone(),
            elbv2_state: self.deps.elbv2.clone(),
            organizations_state: self.deps.organizations.clone(),
            cognito_state: self.deps.cognito.clone(),
            rds_state: self.deps.rds.clone(),
            ecs_state: self.deps.ecs.clone(),
            acm_state: self.deps.acm.clone(),
            elasticache_state: self.deps.elasticache.clone(),
            route53_state: self.deps.route53.clone(),
            cloudfront_state: self.deps.cloudfront.clone(),
            stepfunctions_state: self.deps.stepfunctions.clone(),
            wafv2_state: self.deps.wafv2.clone(),
            apigateway_state: self.deps.apigateway.clone(),
            apigatewayv2_state: self.deps.apigatewayv2.clone(),
            ses_state: self.deps.ses.clone(),
            delivery: self.deps.delivery.clone(),
            account_id: account_id.to_string(),
            region: region.to_string(),
            stack_id: stack_id.to_string(),
        }
    }

    fn get_param(req: &AwsRequest, key: &str) -> Option<String> {
        // Check query params first (for Query protocol)
        if let Some(v) = req.query_params.get(key) {
            return Some(v.clone());
        }
        // Then check form-encoded body
        let body_params = fakecloud_core::protocol::parse_query_body(&req.body);
        body_params.get(key).cloned()
    }

    pub(crate) fn get_all_params(req: &AwsRequest) -> BTreeMap<String, String> {
        let mut params: BTreeMap<String, String> = req.query_params.clone().into_iter().collect();
        let body_params = fakecloud_core::protocol::parse_query_body(&req.body);
        for (k, v) in body_params {
            params.entry(k).or_insert(v);
        }
        params
    }

    pub(crate) fn extract_tags(params: &BTreeMap<String, String>) -> BTreeMap<String, String> {
        let mut tags = BTreeMap::new();
        for i in 1.. {
            let key_param = format!("Tags.member.{i}.Key");
            let value_param = format!("Tags.member.{i}.Value");
            match (params.get(&key_param), params.get(&value_param)) {
                (Some(k), Some(v)) => {
                    tags.insert(k.clone(), v.clone());
                }
                _ => break,
            }
        }
        tags
    }

    pub(crate) fn extract_parameters(
        params: &BTreeMap<String, String>,
    ) -> BTreeMap<String, String> {
        let mut result = BTreeMap::new();
        for i in 1.. {
            let key_param = format!("Parameters.member.{i}.ParameterKey");
            let value_param = format!("Parameters.member.{i}.ParameterValue");
            match (params.get(&key_param), params.get(&value_param)) {
                (Some(k), Some(v)) => {
                    result.insert(k.clone(), v.clone());
                }
                _ => break,
            }
        }
        result
    }

    pub(crate) fn extract_notification_arns(params: &BTreeMap<String, String>) -> Vec<String> {
        let mut arns = Vec::new();
        for i in 1.. {
            let key = format!("NotificationARNs.member.{i}");
            match params.get(&key) {
                Some(arn) => arns.push(arn.clone()),
                None => break,
            }
        }
        arns
    }

    fn send_stack_notification(
        delivery: &DeliveryBus,
        notification_arns: &[String],
        stack_name: &str,
        stack_id: &str,
        status: &str,
    ) {
        if notification_arns.is_empty() {
            return;
        }
        let message = format!(
            "StackId='{}'\nTimestamp='{}'\nEventId='{}'\nLogicalResourceId='{}'\nResourceStatus='{}'\nResourceType='AWS::CloudFormation::Stack'\nStackName='{}'",
            stack_id,
            chrono::Utc::now().format("%Y-%m-%dT%H:%M:%S%.3fZ"),
            uuid::Uuid::new_v4(),
            stack_name,
            status,
            stack_name,
        );
        for arn in notification_arns {
            delivery.publish_to_sns(arn, &message, Some("AWS CloudFormation Notification"));
        }
    }

    /// Build a Fn::ImportValue lookup map across every stack in the
    /// account: each stack's exported outputs map their `ExportName` to
    /// the resolved value.
    fn collect_account_imports(
        state: &SharedCloudFormationState,
        account_id: &str,
        skip_stack: Option<&str>,
    ) -> BTreeMap<String, String> {
        let mut imports = BTreeMap::new();
        let accounts = state.read();
        let Some(state) = accounts.get(account_id) else {
            return imports;
        };
        for stack in state.stacks.values() {
            if matches!(skip_stack, Some(skip) if skip == stack.name) {
                continue;
            }
            if stack.status == "DELETE_COMPLETE" {
                continue;
            }
            for output in &stack.outputs {
                if let Some(export) = &output.export_name {
                    imports.insert(export.clone(), output.value.clone());
                }
            }
        }
        imports
    }

    /// Resolve every `Outputs.*` entry in `template_body` after the stack
    /// has been provisioned. `resources` is the post-create / post-update
    /// vec; we rebuild the physical-id and attribute maps from it before
    /// invoking the template parser.
    fn resolve_template_outputs(
        template_body: &str,
        parameters: &BTreeMap<String, String>,
        resources: &[StackResource],
        state: &SharedCloudFormationState,
    ) -> Vec<state::StackOutput> {
        let value: serde_json::Value = if template_body.trim_start().starts_with('{') {
            match serde_json::from_str(template_body) {
                Ok(v) => v,
                Err(_) => return Vec::new(),
            }
        } else {
            match serde_yaml::from_str(template_body) {
                Ok(v) => v,
                Err(_) => return Vec::new(),
            }
        };

        let resources_obj = match value.get("Resources").and_then(|v| v.as_object()) {
            Some(o) => o.clone(),
            None => return Vec::new(),
        };

        let mut physical_ids: BTreeMap<String, String> = BTreeMap::new();
        let mut attributes: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
        for r in resources {
            physical_ids.insert(r.logical_id.clone(), r.physical_id.clone());
            attributes.insert(r.logical_id.clone(), r.attributes.clone());
        }

        let imports = {
            let accounts = state.read();
            let mut out = BTreeMap::new();
            // Walk every account so cross-stack imports work even if
            // future use-cases serve mixed accounts.
            for (_account, st) in accounts.iter() {
                for stack in st.stacks.values() {
                    if stack.status == "DELETE_COMPLETE" {
                        continue;
                    }
                    for o in &stack.outputs {
                        if let Some(export) = &o.export_name {
                            out.insert(export.clone(), o.value.clone());
                        }
                    }
                }
            }
            out
        };

        let parsed = template::parse_outputs(
            &value,
            parameters,
            &resources_obj,
            &physical_ids,
            &attributes,
            &imports,
        );

        parsed
            .into_iter()
            .map(|o| state::StackOutput {
                key: o.logical_id,
                value: o.value,
                description: o.description,
                export_name: o.export_name,
            })
            .collect()
    }

    /// Reject creates/updates whose outputs would re-export a name that
    /// another live stack already exports. Mirrors real CloudFormation.
    fn ensure_export_uniqueness(
        state: &SharedCloudFormationState,
        account_id: &str,
        stack_name: &str,
        outputs: &[state::StackOutput],
    ) -> Result<(), AwsServiceError> {
        let existing = Self::collect_account_imports(state, account_id, Some(stack_name));
        for o in outputs {
            if let Some(export) = &o.export_name {
                if existing.contains_key(export) {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "ValidationError",
                        format!("Export with name {export} is already exported by another stack"),
                    ));
                }
            }
        }
        Ok(())
    }

    fn create_stack(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let params = Self::get_all_params(req);

        let stack_name = params.get("StackName").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationError",
                "StackName is required",
            )
        })?;

        let template_body = params.get("TemplateBody").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationError",
                "TemplateBody is required",
            )
        })?;

        // Check if stack already exists and is not deleted
        {
            let accounts = self.state.read();
            let empty = CloudFormationState::new(&req.account_id, &req.region);
            let state = accounts.get(&req.account_id).unwrap_or(&empty);
            if let Some(existing) = state.stacks.get(stack_name.as_str()) {
                if existing.status != "DELETE_COMPLETE" {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "AlreadyExistsException",
                        format!("Stack [{stack_name}] already exists"),
                    ));
                }
            }
        }

        let tags = Self::extract_tags(&params);
        let mut parameters = Self::extract_parameters(&params);
        let notification_arns = Self::extract_notification_arns(&params);

        // Seed AWS::* pseudo-parameters with stack-context values so
        // resolve_refs can substitute them into resource properties.
        let stack_id = format!(
            "arn:aws:cloudformation:{}:{}:stack/{}/{}",
            req.region,
            req.account_id,
            stack_name,
            uuid::Uuid::new_v4()
        );
        parameters
            .entry("AWS::Region".to_string())
            .or_insert_with(|| req.region.clone());
        parameters
            .entry("AWS::AccountId".to_string())
            .or_insert_with(|| req.account_id.clone());
        parameters
            .entry("AWS::StackId".to_string())
            .or_insert_with(|| stack_id.clone());
        parameters
            .entry("AWS::StackName".to_string())
            .or_insert_with(|| stack_name.clone());
        parameters
            .entry("AWS::Partition".to_string())
            .or_insert_with(|| "aws".to_string());
        parameters
            .entry("AWS::URLSuffix".to_string())
            .or_insert_with(|| "amazonaws.com".to_string());

        // First pass: parse to get resource definitions (without physical ID resolution)
        let parsed = template::parse_template(template_body, &parameters).map_err(|e| {
            AwsServiceError::aws_error(StatusCode::BAD_REQUEST, "ValidationError", e)
        })?;

        let provisioner = self.provisioner(&stack_id, &req.account_id, &req.region);
        let resources =
            provision_stack_resources(&provisioner, &parsed.resources, template_body, &parameters)?;

        let outputs =
            Self::resolve_template_outputs(template_body, &parameters, &resources, &self.state);

        Self::ensure_export_uniqueness(&self.state, &req.account_id, stack_name, &outputs)?;

        let stack = Stack {
            name: stack_name.clone(),
            stack_id: stack_id.clone(),
            template: template_body.clone(),
            status: "CREATE_COMPLETE".to_string(),
            resources,
            parameters,
            tags,
            created_at: Utc::now(),
            updated_at: None,
            description: parsed.description,
            notification_arns: notification_arns.clone(),
            outputs,
        };

        {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&req.account_id);
            state.stacks.insert(stack_name.clone(), stack);
        }

        Self::send_stack_notification(
            &self.deps.delivery,
            &notification_arns,
            stack_name,
            &stack_id,
            "CREATE_COMPLETE",
        );

        Ok(AwsResponse::xml(
            StatusCode::OK,
            xml_responses::create_stack_response(&stack_id, &req.request_id),
        ))
    }

    fn delete_stack(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let stack_name = Self::get_param(req, "StackName").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationError",
                "StackName is required",
            )
        })?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        // Find stack by name or stack ID
        let stack = state.stacks.values_mut().find(|s| {
            (s.name == stack_name || s.stack_id == stack_name) && s.status != "DELETE_COMPLETE"
        });

        if let Some(stack) = stack {
            let stack_id = stack.stack_id.clone();
            let stack_name_for_notif = stack.name.clone();
            let notification_arns = stack.notification_arns.clone();
            let resources: Vec<_> = stack.resources.clone();

            // Build the provisioner while we still have the stack_id
            // Drop the write lock temporarily so the provisioner can read state
            drop(accounts);
            let provisioner = self.provisioner(&stack_id, &req.account_id, &req.region);

            // Delete resources in reverse order
            for resource in resources.iter().rev() {
                let _ = provisioner.delete_resource(resource);
            }

            // Re-acquire the write lock to update stack status
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&req.account_id);
            if let Some(stack) = state.stacks.values_mut().find(|s| s.stack_id == stack_id) {
                stack.status = "DELETE_COMPLETE".to_string();
                stack.resources.clear();
            }
            drop(accounts);

            Self::send_stack_notification(
                &self.deps.delivery,
                &notification_arns,
                &stack_name_for_notif,
                &stack_id,
                "DELETE_COMPLETE",
            );
        }

        Ok(AwsResponse::xml(
            StatusCode::OK,
            xml_responses::delete_stack_response(&req.request_id),
        ))
    }

    fn describe_stacks(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let stack_name = Self::get_param(req, "StackName");

        let accounts = self.state.read();
        let empty = CloudFormationState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let stacks: Vec<Stack> = if let Some(ref name) = stack_name {
            state
                .stacks
                .values()
                .filter(|s| {
                    (s.name == *name || s.stack_id == *name) && s.status != "DELETE_COMPLETE"
                })
                .cloned()
                .collect()
        } else {
            state
                .stacks
                .values()
                .filter(|s| s.status != "DELETE_COMPLETE")
                .cloned()
                .collect()
        };

        if let Some(ref name) = stack_name {
            if stacks.is_empty() {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationError",
                    format!("Stack with id {name} does not exist"),
                ));
            }
        }

        Ok(AwsResponse::xml(
            StatusCode::OK,
            xml_responses::describe_stacks_response(&stacks, &req.request_id),
        ))
    }

    fn list_stacks(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let accounts = self.state.read();
        let empty = CloudFormationState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let stacks: Vec<Stack> = state.stacks.values().cloned().collect();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            xml_responses::list_stacks_response(&stacks, &req.request_id),
        ))
    }

    fn list_stack_resources(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let stack_name = Self::get_param(req, "StackName").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationError",
                "StackName is required",
            )
        })?;

        let accounts = self.state.read();
        let empty = CloudFormationState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let stack = state
            .stacks
            .values()
            .find(|s| {
                (s.name == stack_name || s.stack_id == stack_name) && s.status != "DELETE_COMPLETE"
            })
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationError",
                    format!("Stack [{stack_name}] does not exist"),
                )
            })?;

        Ok(AwsResponse::xml(
            StatusCode::OK,
            xml_responses::list_stack_resources_response(&stack.resources, &req.request_id),
        ))
    }

    fn describe_stack_resources(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let stack_name = Self::get_param(req, "StackName").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationError",
                "StackName is required",
            )
        })?;

        let accounts = self.state.read();
        let empty = CloudFormationState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let stack = state
            .stacks
            .values()
            .find(|s| {
                (s.name == stack_name || s.stack_id == stack_name) && s.status != "DELETE_COMPLETE"
            })
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationError",
                    format!("Stack [{stack_name}] does not exist"),
                )
            })?;

        Ok(AwsResponse::xml(
            StatusCode::OK,
            xml_responses::describe_stack_resources_response(
                &stack.resources,
                &stack.name,
                &req.request_id,
            ),
        ))
    }

    fn update_stack(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mut input = UpdateStackInput::from_params(req)?;

        // Get stack_id before write lock for the provisioner
        let found_stack_id = {
            let accounts = self.state.read();
            let empty = CloudFormationState::new(&req.account_id, &req.region);
            let state = accounts.get(&req.account_id).unwrap_or(&empty);
            state
                .stacks
                .values()
                .find(|s| {
                    (s.name == input.stack_name || s.stack_id == input.stack_name)
                        && s.status != "DELETE_COMPLETE"
                })
                .map(|s| s.stack_id.clone())
                .unwrap_or_default()
        };

        // Seed pseudo-parameters before parsing — the StackId is now known
        // (after the read above) so resolve_refs sees the same values that
        // the original CreateStack invocation used.
        input
            .parameters
            .entry("AWS::Region".to_string())
            .or_insert_with(|| req.region.clone());
        input
            .parameters
            .entry("AWS::AccountId".to_string())
            .or_insert_with(|| req.account_id.clone());
        input
            .parameters
            .entry("AWS::StackId".to_string())
            .or_insert_with(|| found_stack_id.clone());
        input
            .parameters
            .entry("AWS::StackName".to_string())
            .or_insert_with(|| input.stack_name.clone());
        input
            .parameters
            .entry("AWS::Partition".to_string())
            .or_insert_with(|| "aws".to_string());
        input
            .parameters
            .entry("AWS::URLSuffix".to_string())
            .or_insert_with(|| "amazonaws.com".to_string());

        let parsed =
            template::parse_template(&input.template_body, &input.parameters).map_err(|e| {
                AwsServiceError::aws_error(StatusCode::BAD_REQUEST, "ValidationError", e)
            })?;

        let provisioner = self.provisioner(&found_stack_id, &req.account_id, &req.region);

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let stack = state
            .stacks
            .values_mut()
            .find(|s| {
                (s.name == input.stack_name || s.stack_id == input.stack_name)
                    && s.status != "DELETE_COMPLETE"
            })
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationError",
                    format!("Stack [{}] does not exist", input.stack_name),
                )
            })?;

        let update_result = apply_resource_updates(
            stack,
            &parsed.resources,
            &input.template_body,
            &input.parameters,
            &provisioner,
        );

        let stack_id = stack.stack_id.clone();
        stack.template = input.template_body.clone();
        stack.status = if update_result.is_err() {
            "UPDATE_FAILED".to_string()
        } else {
            "UPDATE_COMPLETE".to_string()
        };
        stack.parameters = input.parameters.clone();
        if !input.tags.is_empty() {
            stack.tags = input.tags;
        }
        stack.updated_at = Some(Utc::now());
        stack.description = parsed.description;
        if !input.notification_arns.is_empty() {
            stack.notification_arns = input.notification_arns.clone();
        }
        if update_result.is_ok() {
            stack.outputs.clear();
        }
        let resources_snapshot = stack.resources.clone();
        let notification_arns = stack.notification_arns.clone();
        let stack_name_for_notif = stack.name.clone();

        if let Err(error_msg) = update_result {
            drop(accounts);
            Self::send_stack_notification(
                &self.deps.delivery,
                &notification_arns,
                &stack_name_for_notif,
                &stack_id,
                "UPDATE_FAILED",
            );
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationError",
                error_msg,
            ));
        }

        drop(accounts);

        let outputs = Self::resolve_template_outputs(
            &input.template_body,
            &input.parameters,
            &resources_snapshot,
            &self.state,
        );
        Self::ensure_export_uniqueness(&self.state, &req.account_id, &input.stack_name, &outputs)?;
        {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&req.account_id);
            if let Some(stack) = state
                .stacks
                .values_mut()
                .find(|s| s.stack_id == stack_id && s.status != "DELETE_COMPLETE")
            {
                stack.outputs = outputs;
            }
        }

        Self::send_stack_notification(
            &self.deps.delivery,
            &notification_arns,
            &stack_name_for_notif,
            &stack_id,
            "UPDATE_COMPLETE",
        );

        Ok(AwsResponse::xml(
            StatusCode::OK,
            xml_responses::update_stack_response(&stack_id, &req.request_id),
        ))
    }

    fn get_template(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let stack_name = Self::get_param(req, "StackName").ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ValidationError",
                "StackName is required",
            )
        })?;

        let accounts = self.state.read();
        let empty = CloudFormationState::new(&req.account_id, &req.region);
        let state = accounts.get(&req.account_id).unwrap_or(&empty);
        let stack = state
            .stacks
            .values()
            .find(|s| {
                (s.name == stack_name || s.stack_id == stack_name) && s.status != "DELETE_COMPLETE"
            })
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationError",
                    format!("Stack [{stack_name}] does not exist"),
                )
            })?;

        Ok(AwsResponse::xml(
            StatusCode::OK,
            xml_responses::get_template_response(&stack.template, &req.request_id),
        ))
    }
}

#[async_trait]
impl AwsService for CloudFormationService {
    fn service_name(&self) -> &str {
        "cloudformation"
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let action = req.action.as_str();
        // Only ops whose handlers actually write to per-account state
        // need to trigger snapshot persistence. Pass-through ops that
        // return canned IDs but don't touch state are excluded.
        let mutates = matches!(
            action,
            "CreateStack"
                | "DeleteStack"
                | "UpdateStack"
                | "CreateChangeSet"
                | "DeleteChangeSet"
                | "ExecuteChangeSet"
                | "CreateStackSet"
                | "DeleteStackSet"
                | "CreateStackRefactor"
                | "CreateGeneratedTemplate"
                | "DeleteGeneratedTemplate"
                | "SetStackPolicy"
                | "UpdateTerminationProtection"
                | "ActivateOrganizationsAccess"
                | "DeactivateOrganizationsAccess"
        );
        let result = match action {
            "CreateStack" => self.create_stack(&req),
            "DeleteStack" => self.delete_stack(&req),
            "DescribeStacks" => self.describe_stacks(&req),
            "ListStacks" => self.list_stacks(&req),
            "ListStackResources" => self.list_stack_resources(&req),
            "DescribeStackResources" => self.describe_stack_resources(&req),
            "UpdateStack" => self.update_stack(&req),
            "GetTemplate" => self.get_template(&req),
            _ => self.handle_extra_action(&req),
        };
        if mutates && matches!(result.as_ref(), Ok(resp) if resp.status.is_success()) {
            self.save_snapshot().await;
        }
        result
    }

    fn supported_actions(&self) -> &[&str] {
        &[
            "ActivateOrganizationsAccess",
            "ActivateType",
            "BatchDescribeTypeConfigurations",
            "CancelUpdateStack",
            "ContinueUpdateRollback",
            "CreateChangeSet",
            "CreateGeneratedTemplate",
            "CreateStack",
            "CreateStackInstances",
            "CreateStackRefactor",
            "CreateStackSet",
            "DeactivateOrganizationsAccess",
            "DeactivateType",
            "DeleteChangeSet",
            "DeleteGeneratedTemplate",
            "DeleteStack",
            "DeleteStackInstances",
            "DeleteStackSet",
            "DeregisterType",
            "DescribeAccountLimits",
            "DescribeChangeSet",
            "DescribeChangeSetHooks",
            "DescribeEvents",
            "DescribeGeneratedTemplate",
            "DescribeOrganizationsAccess",
            "DescribePublisher",
            "DescribeResourceScan",
            "DescribeStackDriftDetectionStatus",
            "DescribeStackEvents",
            "DescribeStackInstance",
            "DescribeStackRefactor",
            "DescribeStackResource",
            "DescribeStackResourceDrifts",
            "DescribeStackResources",
            "DescribeStackSet",
            "DescribeStackSetOperation",
            "DescribeStacks",
            "DescribeType",
            "DescribeTypeRegistration",
            "DetectStackDrift",
            "DetectStackResourceDrift",
            "DetectStackSetDrift",
            "EstimateTemplateCost",
            "ExecuteChangeSet",
            "ExecuteStackRefactor",
            "GetGeneratedTemplate",
            "GetHookResult",
            "GetStackPolicy",
            "GetTemplate",
            "GetTemplateSummary",
            "ImportStacksToStackSet",
            "ListChangeSets",
            "ListExports",
            "ListGeneratedTemplates",
            "ListHookResults",
            "ListImports",
            "ListResourceScanRelatedResources",
            "ListResourceScanResources",
            "ListResourceScans",
            "ListStackInstanceResourceDrifts",
            "ListStackInstances",
            "ListStackRefactorActions",
            "ListStackRefactors",
            "ListStackResources",
            "ListStackSetAutoDeploymentTargets",
            "ListStackSetOperationResults",
            "ListStackSetOperations",
            "ListStackSets",
            "ListStacks",
            "ListTypeRegistrations",
            "ListTypeVersions",
            "ListTypes",
            "PublishType",
            "RecordHandlerProgress",
            "RegisterPublisher",
            "RegisterType",
            "RollbackStack",
            "SetStackPolicy",
            "SetTypeConfiguration",
            "SetTypeDefaultVersion",
            "SignalResource",
            "StartResourceScan",
            "StopStackSetOperation",
            "TestType",
            "UpdateGeneratedTemplate",
            "UpdateStack",
            "UpdateStackInstances",
            "UpdateStackSet",
            "UpdateTerminationProtection",
            "ValidateTemplate",
        ]
    }
}

/// Parsed + validated inputs for `UpdateStack`.
struct UpdateStackInput {
    stack_name: String,
    template_body: String,
    parameters: BTreeMap<String, String>,
    tags: BTreeMap<String, String>,
    notification_arns: Vec<String>,
}

impl UpdateStackInput {
    fn from_params(req: &AwsRequest) -> Result<Self, AwsServiceError> {
        let params = CloudFormationService::get_all_params(req);

        let stack_name = params
            .get("StackName")
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationError",
                    "StackName is required",
                )
            })?
            .to_string();

        let template_body = params
            .get("TemplateBody")
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ValidationError",
                    "TemplateBody is required",
                )
            })?
            .to_string();

        Ok(Self {
            stack_name,
            template_body,
            parameters: CloudFormationService::extract_parameters(&params),
            tags: CloudFormationService::extract_tags(&params),
            notification_arns: CloudFormationService::extract_notification_arns(&params),
        })
    }
}

/// Apply resource updates: delete removed resources, create new ones.
/// Returns Err(msg) if any resource operation fails.
pub(crate) fn apply_resource_updates(
    stack: &mut crate::state::Stack,
    new_resource_defs: &[template::ResourceDefinition],
    template_body: &str,
    parameters: &BTreeMap<String, String>,
    provisioner: &crate::resource_provisioner::ResourceProvisioner,
) -> Result<(), String> {
    let old_logical_ids: std::collections::HashSet<String> = stack
        .resources
        .iter()
        .map(|r| r.logical_id.clone())
        .collect();
    let new_logical_ids: std::collections::HashSet<String> = new_resource_defs
        .iter()
        .map(|r| r.logical_id.clone())
        .collect();

    // Delete resources no longer in template
    let to_remove: Vec<_> = stack
        .resources
        .iter()
        .filter(|r| !new_logical_ids.contains(&r.logical_id))
        .cloned()
        .collect();
    for resource in &to_remove {
        let _ = provisioner.delete_resource(resource);
    }
    stack
        .resources
        .retain(|r| new_logical_ids.contains(&r.logical_id));

    // Build physical ID + attribute maps from existing resources
    let mut physical_ids: BTreeMap<String, String> = stack
        .resources
        .iter()
        .map(|r| (r.logical_id.clone(), r.physical_id.clone()))
        .collect();
    let mut attributes: BTreeMap<String, BTreeMap<String, String>> = stack
        .resources
        .iter()
        .map(|r| (r.logical_id.clone(), r.attributes.clone()))
        .collect();

    // Create new resources
    for resource_def in new_resource_defs {
        if !old_logical_ids.contains(&resource_def.logical_id) {
            let resolved_def = template::resolve_resource_properties_with_attrs(
                resource_def,
                template_body,
                parameters,
                &physical_ids,
                &attributes,
            )
            .map_err(|e| {
                format!(
                    "Failed to resolve resource {}: {e}",
                    resource_def.logical_id
                )
            })?;

            match provisioner.create_resource(&resolved_def) {
                Ok(stack_resource) => {
                    physical_ids.insert(
                        stack_resource.logical_id.clone(),
                        stack_resource.physical_id.clone(),
                    );
                    attributes.insert(
                        stack_resource.logical_id.clone(),
                        stack_resource.attributes.clone(),
                    );
                    stack.resources.push(stack_resource);
                }
                Err(e) => {
                    tracing::warn!(
                        "Failed to create resource {} during update: {e}",
                        resource_def.logical_id
                    );
                    return Err(format!(
                        "Failed to create resource {}: {e}",
                        resource_def.logical_id
                    ));
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use http::HeaderMap;
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn make_service() -> CloudFormationService {
        let cf_state = Arc::new(RwLock::new(
            fakecloud_core::multi_account::MultiAccountState::new(
                "123456789012",
                "us-east-1",
                "http://localhost:4566",
            ),
        ));
        let deps = CloudFormationDeps {
            sqs: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "http://localhost:4566",
                ),
            )),
            sns: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "http://localhost:4566",
                ),
            )),
            ssm: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "http://localhost:4566",
                ),
            )),
            iam: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            )),
            s3: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            )),
            eventbridge: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            )),
            dynamodb: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            )),
            logs: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            )),
            lambda: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            )),
            secretsmanager: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            )),
            kinesis: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            )),
            kms: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            )),
            ecr: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            )),
            cloudwatch: Arc::new(RwLock::new(fakecloud_cloudwatch::CloudWatchAccounts::new())),
            elbv2: Arc::new(RwLock::new(fakecloud_elbv2::Elbv2Accounts::new())),
            organizations: Arc::new(RwLock::new(None)),
            cognito: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            )),
            rds: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            )),
            ecs: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            )),
            acm: Arc::new(RwLock::new(fakecloud_acm::AcmAccounts::new())),
            elasticache: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            )),
            route53: Arc::new(RwLock::new(fakecloud_route53::Route53Accounts::new())),
            cloudfront: Arc::new(RwLock::new(fakecloud_cloudfront::CloudFrontAccounts::new())),
            stepfunctions: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            )),
            wafv2: Arc::new(RwLock::new(fakecloud_wafv2::Wafv2Accounts::default())),
            apigateway: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            )),
            apigatewayv2: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            )),
            ses: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "",
                ),
            )),
            delivery: Arc::new(DeliveryBus::new()),
        };
        CloudFormationService::new(cf_state, deps)
    }

    fn make_request(action: &str, params: HashMap<String, String>) -> AwsRequest {
        AwsRequest {
            service: "cloudformation".to_string(),
            action: action.to_string(),
            region: "us-east-1".to_string(),
            account_id: "123456789012".to_string(),
            request_id: "test-request-id".to_string(),
            headers: HeaderMap::new(),
            query_params: params,
            body: bytes::Bytes::new(),
            body_stream: parking_lot::Mutex::new(None),
            path_segments: vec![],
            raw_path: "/".to_string(),
            raw_query: String::new(),
            method: http::Method::POST,
            is_query_protocol: true,
            access_key_id: None,
            principal: None,
        }
    }

    #[test]
    fn update_stack_sets_failed_status_on_resource_error() {
        let svc = make_service();

        // Create a stack with just a queue
        let mut create_params = HashMap::new();
        create_params.insert("StackName".to_string(), "test-stack".to_string());
        create_params.insert(
            "TemplateBody".to_string(),
            r#"{"Resources":{"MyQueue":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"q1"}}}}"#.to_string(),
        );
        let req = make_request("CreateStack", create_params);
        let result = svc.create_stack(&req);
        assert!(result.is_ok());

        // Update stack adding an SNS subscription with a non-existent topic
        let mut update_params = HashMap::new();
        update_params.insert("StackName".to_string(), "test-stack".to_string());
        update_params.insert(
            "TemplateBody".to_string(),
            r#"{"Resources":{"MyQueue":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"q1"}},"BadSub":{"Type":"AWS::SNS::Subscription","Properties":{"TopicArn":"arn:aws:sns:us-east-1:123456789012:nope","Protocol":"sqs","Endpoint":"arn:aws:sqs:us-east-1:123456789012:q1"}}}}"#.to_string(),
        );
        let req = make_request("UpdateStack", update_params);
        let result = svc.update_stack(&req);

        // Should return an error
        assert!(result.is_err());

        // Stack status should be UPDATE_FAILED
        let accounts = svc.state.read();
        let state = accounts.get("123456789012").unwrap();
        let stack = state.stacks.get("test-stack").unwrap();
        assert_eq!(stack.status, "UPDATE_FAILED");
    }

    #[test]
    fn create_stack_resolves_ref_to_physical_id() {
        let svc = make_service();

        // Template where subscription Refs the topic
        let template = r#"{
            "Resources": {
                "MyTopic": {
                    "Type": "AWS::SNS::Topic",
                    "Properties": { "TopicName": "ref-test-topic" }
                },
                "MySub": {
                    "Type": "AWS::SNS::Subscription",
                    "Properties": {
                        "TopicArn": { "Ref": "MyTopic" },
                        "Protocol": "sqs",
                        "Endpoint": "arn:aws:sqs:us-east-1:123456789012:some-queue"
                    }
                }
            }
        }"#;

        let mut params = HashMap::new();
        params.insert("StackName".to_string(), "ref-stack".to_string());
        params.insert("TemplateBody".to_string(), template.to_string());
        let req = make_request("CreateStack", params);
        let result = svc.create_stack(&req);
        assert!(result.is_ok(), "CreateStack failed: {:?}", result.err());

        // Verify both resources were created
        let accounts = svc.state.read();
        let state = accounts.get("123456789012").unwrap();
        let stack = state.stacks.get("ref-stack").unwrap();
        assert_eq!(stack.resources.len(), 2);
        assert_eq!(stack.status, "CREATE_COMPLETE");

        // The subscription's physical ID should be an ARN (not just "MyTopic")
        let sub = stack
            .resources
            .iter()
            .find(|r| r.logical_id == "MySub")
            .unwrap();
        assert!(
            sub.physical_id.contains("ref-test-topic"),
            "Subscription physical ID should reference the topic ARN, got: {}",
            sub.physical_id
        );
    }

    // ── Service error paths ──

    #[test]
    fn create_stack_missing_name_errors() {
        let svc = make_service();
        let mut params = HashMap::new();
        params.insert("TemplateBody".to_string(), "{}".to_string());
        let req = make_request("CreateStack", params);
        assert!(svc.create_stack(&req).is_err());
    }

    #[test]
    fn create_stack_missing_template_errors() {
        let svc = make_service();
        let mut params = HashMap::new();
        params.insert("StackName".to_string(), "s".to_string());
        let req = make_request("CreateStack", params);
        assert!(svc.create_stack(&req).is_err());
    }

    #[test]
    fn create_stack_duplicate_errors() {
        let svc = make_service();
        let mut params = HashMap::new();
        params.insert("StackName".to_string(), "dup".to_string());
        params.insert(
            "TemplateBody".to_string(),
            r#"{"Resources":{"Q":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"dq"}}}}"#
                .to_string(),
        );
        let req = make_request("CreateStack", params.clone());
        svc.create_stack(&req).unwrap();
        let req = make_request("CreateStack", params);
        assert!(svc.create_stack(&req).is_err());
    }

    #[test]
    fn create_stack_invalid_template_errors() {
        let svc = make_service();
        let mut params = HashMap::new();
        params.insert("StackName".to_string(), "bad".to_string());
        params.insert("TemplateBody".to_string(), "not json".to_string());
        let req = make_request("CreateStack", params);
        assert!(svc.create_stack(&req).is_err());
    }

    #[test]
    fn delete_stack_unknown_is_noop() {
        let svc = make_service();
        let mut params = HashMap::new();
        params.insert("StackName".to_string(), "ghost".to_string());
        let req = make_request("DeleteStack", params);
        assert!(svc.delete_stack(&req).is_ok());
    }

    #[test]
    fn describe_stacks_nonexistent_errors() {
        let svc = make_service();
        let mut params = HashMap::new();
        params.insert("StackName".to_string(), "ghost".to_string());
        let req = make_request("DescribeStacks", params);
        assert!(svc.describe_stacks(&req).is_err());
    }

    #[test]
    fn describe_stacks_empty_returns_all() {
        let svc = make_service();
        let req = make_request("DescribeStacks", HashMap::new());
        let resp = svc.describe_stacks(&req).unwrap();
        let b = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(b.contains("DescribeStacksResult"));
    }

    #[test]
    fn list_stacks_empty_returns_ok() {
        let svc = make_service();
        let req = make_request("ListStacks", HashMap::new());
        let resp = svc.list_stacks(&req).unwrap();
        let b = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(b.contains("ListStacksResult"));
    }

    #[test]
    fn list_stack_resources_missing_name_errors() {
        let svc = make_service();
        let req = make_request("ListStackResources", HashMap::new());
        assert!(svc.list_stack_resources(&req).is_err());
    }

    #[test]
    fn list_stack_resources_unknown_stack_errors() {
        let svc = make_service();
        let mut params = HashMap::new();
        params.insert("StackName".to_string(), "ghost".to_string());
        let req = make_request("ListStackResources", params);
        assert!(svc.list_stack_resources(&req).is_err());
    }

    #[test]
    fn describe_stack_resources_missing_name_errors() {
        let svc = make_service();
        let req = make_request("DescribeStackResources", HashMap::new());
        assert!(svc.describe_stack_resources(&req).is_err());
    }

    #[test]
    fn get_template_missing_name_errors() {
        let svc = make_service();
        let req = make_request("GetTemplate", HashMap::new());
        assert!(svc.get_template(&req).is_err());
    }

    #[test]
    fn get_template_unknown_stack_errors() {
        let svc = make_service();
        let mut params = HashMap::new();
        params.insert("StackName".to_string(), "ghost".to_string());
        let req = make_request("GetTemplate", params);
        assert!(svc.get_template(&req).is_err());
    }

    #[test]
    fn update_stack_missing_name_errors() {
        let svc = make_service();
        let mut params = HashMap::new();
        params.insert("TemplateBody".to_string(), "{}".to_string());
        let req = make_request("UpdateStack", params);
        assert!(svc.update_stack(&req).is_err());
    }

    #[test]
    fn update_stack_unknown_stack_errors() {
        let svc = make_service();
        let mut params = HashMap::new();
        params.insert("StackName".to_string(), "ghost".to_string());
        params.insert(
            "TemplateBody".to_string(),
            r#"{"Resources":{}}"#.to_string(),
        );
        let req = make_request("UpdateStack", params);
        assert!(svc.update_stack(&req).is_err());
    }

    #[test]
    fn create_stack_resolves_outputs_and_records_export() {
        let svc = make_service();
        let template = r#"{
            "Resources": {
                "Q": {"Type":"AWS::SQS::Queue","Properties":{"QueueName":"out-q"}}
            },
            "Outputs": {
                "QueueUrl": {
                    "Value": {"Ref": "Q"},
                    "Description": "Url",
                    "Export": {"Name": "TheQueueUrl"}
                }
            }
        }"#;
        let mut params = HashMap::new();
        params.insert("StackName".to_string(), "outs".to_string());
        params.insert("TemplateBody".to_string(), template.to_string());
        let req = make_request("CreateStack", params);
        svc.create_stack(&req).expect("create stack");

        let accounts = svc.state.read();
        let stack = accounts
            .get("123456789012")
            .unwrap()
            .stacks
            .get("outs")
            .unwrap();
        assert_eq!(stack.outputs.len(), 1);
        assert_eq!(stack.outputs[0].key, "QueueUrl");
        assert_eq!(stack.outputs[0].export_name.as_deref(), Some("TheQueueUrl"));
        assert!(!stack.outputs[0].value.is_empty());
    }

    #[test]
    fn create_stack_rejects_duplicate_export_name() {
        let svc = make_service();
        let mk = |name: &str| {
            let template = format!(
                r#"{{
                    "Resources": {{"Q":{{"Type":"AWS::SQS::Queue","Properties":{{"QueueName":"q-{name}"}}}}}},
                    "Outputs": {{"QueueUrl":{{"Value":{{"Ref":"Q"}},"Export":{{"Name":"DupExport"}}}}}}
                }}"#
            );
            let mut params = HashMap::new();
            params.insert("StackName".to_string(), name.to_string());
            params.insert("TemplateBody".to_string(), template);
            make_request("CreateStack", params)
        };
        match svc.create_stack(&mk("first")) {
            Ok(_) => {}
            Err(e) => panic!("first stack: {e:?}"),
        }
        match svc.create_stack(&mk("second")) {
            Ok(_) => panic!("expected duplicate-export error"),
            Err(e) => assert!(
                format!("{e:?}").contains("already exported"),
                "expected duplicate-export error, got {e:?}"
            ),
        }
    }

    #[test]
    fn import_value_resolves_against_other_stack_export() {
        let svc = make_service();

        let producer_tpl = r#"{
            "Resources": {"Q":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"prod-q"}}},
            "Outputs": {"Out":{"Value":{"Ref":"Q"},"Export":{"Name":"SharedQueueUrl"}}}
        }"#;
        let mut p = HashMap::new();
        p.insert("StackName".to_string(), "producer".to_string());
        p.insert("TemplateBody".to_string(), producer_tpl.to_string());
        svc.create_stack(&make_request("CreateStack", p))
            .expect("producer");

        let consumer_tpl = r#"{
            "Resources": {"Q2":{"Type":"AWS::SQS::Queue","Properties":{"QueueName":"cons-q"}}},
            "Outputs": {"Imp":{"Value":{"Fn::ImportValue":"SharedQueueUrl"}}}
        }"#;
        let mut p = HashMap::new();
        p.insert("StackName".to_string(), "consumer".to_string());
        p.insert("TemplateBody".to_string(), consumer_tpl.to_string());
        svc.create_stack(&make_request("CreateStack", p))
            .expect("consumer");

        let accounts = svc.state.read();
        let prod_url = accounts
            .get("123456789012")
            .unwrap()
            .stacks
            .get("producer")
            .unwrap()
            .outputs[0]
            .value
            .clone();
        let cons = accounts
            .get("123456789012")
            .unwrap()
            .stacks
            .get("consumer")
            .unwrap();
        assert_eq!(cons.outputs[0].value, prod_url);
    }
}
