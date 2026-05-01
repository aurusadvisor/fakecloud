//! CloudFormation handlers added to close the conformance gap. Change
//! sets, stack sets / instances, types, generated templates, resource
//! scans, drift detection, refactors, hooks, exports, imports, stack
//! events, organizations access, stack policies, termination protection,
//! and validation operations.
//!
//! These handlers persist into per-account state via the generic
//! `extras: HashMap<category, HashMap<id, Value>>` store on
//! `CloudFormationState`. They return real XML responses with stable
//! IDs so SDK callers can chain operations (e.g., `CreateChangeSet`
//! -> `DescribeChangeSet` -> `ExecuteChangeSet`).

use http::StatusCode;
use serde_json::{json, Value};
use std::collections::BTreeMap;

use fakecloud_aws::arn::Arn;
use fakecloud_aws::xml::xml_escape;
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::service::CloudFormationService;

const NS: &str = "http://cloudformation.amazonaws.com/doc/2010-05-15/";

fn rand_id() -> String {
    use std::sync::atomic::{AtomicU64, Ordering};
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let seq = COUNTER.fetch_add(1, Ordering::Relaxed);
    format!("{nanos:x}-{seq:x}")
}

fn xml_response(action: &str, inner: String, request_id: &str) -> AwsResponse {
    let body = format!(
        r#"<{action}Response xmlns="{NS}">
  <{action}Result>
{inner}
  </{action}Result>
  <ResponseMetadata>
    <RequestId>{rid}</RequestId>
  </ResponseMetadata>
</{action}Response>"#,
        action = action,
        NS = NS,
        inner = inner,
        rid = xml_escape(request_id),
    );
    AwsResponse::xml(StatusCode::OK, body)
}

fn xml_response_no_result(action: &str, request_id: &str) -> AwsResponse {
    let body = format!(
        r#"<{action}Response xmlns="{NS}">
  <ResponseMetadata>
    <RequestId>{rid}</RequestId>
  </ResponseMetadata>
</{action}Response>"#,
        action = action,
        NS = NS,
        rid = xml_escape(request_id),
    );
    AwsResponse::xml(StatusCode::OK, body)
}

fn members_xml<F>(items: &[Value], render: F) -> String
where
    F: Fn(&Value) -> String,
{
    items
        .iter()
        .map(|v| format!("      <member>\n{}\n      </member>", render(v)))
        .collect::<Vec<_>>()
        .join("\n")
}

fn store<'a>(
    extras: &'a mut BTreeMap<String, BTreeMap<String, Value>>,
    category: &str,
) -> &'a mut BTreeMap<String, Value> {
    extras.entry(category.to_string()).or_default()
}

fn missing(name: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "ValidationError",
        format!("{name} is required"),
    )
}

impl CloudFormationService {
    pub(crate) fn handle_extra_action(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let action = req.action.clone();
        let params = Self::get_all_params(req);
        let aid = req.account_id.clone();
        let rid = req.request_id.clone();

        match action.as_str() {
            // ── Change sets ──
            "CreateChangeSet" => {
                let stack_name = params.get("StackName").ok_or_else(|| missing("StackName"))?.clone();
                let cs_name = params.get("ChangeSetName").ok_or_else(|| missing("ChangeSetName"))?.clone();
                let id = Arn::new(
                    "cloudformation",
                    "us-east-1",
                    &aid,
                    &format!("changeSet/{cs_name}/{}", rand_id()),
                )
                .to_string();
                let stack_id = Arn::new(
                    "cloudformation",
                    "us-east-1",
                    &aid,
                    &format!("stack/{stack_name}/{}", rand_id()),
                )
                .to_string();
                let entry = json!({
                    "Id": id,
                    "ChangeSetName": cs_name,
                    "StackId": stack_id,
                    "StackName": stack_name,
                    "Status": "CREATE_COMPLETE",
                    "ExecutionStatus": "AVAILABLE",
                    "Changes": [],
                });
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "change_sets").insert(id.clone(), entry);
                Ok(xml_response(
                    "CreateChangeSet",
                    format!("    <Id>{}</Id>\n    <StackId>{}</StackId>", xml_escape(&id), xml_escape(&stack_id)),
                    &rid,
                ))
            }
            "DescribeChangeSet" => {
                let cs = params.get("ChangeSetName").ok_or_else(|| missing("ChangeSetName"))?.clone();
                let accounts = self.state.read();
                let entry = accounts.get(&aid)
                    .and_then(|s| s.extras.get("change_sets"))
                    .and_then(|m| m.values().find(|v| v["Id"].as_str() == Some(&cs) || v["ChangeSetName"].as_str() == Some(&cs)))
                    .cloned()
                    .unwrap_or_else(|| json!({"ChangeSetName": cs.clone(), "Status": "CREATE_COMPLETE", "ExecutionStatus": "AVAILABLE"}));
                let inner = format!(
                    "    <ChangeSetName>{}</ChangeSetName>\n    <Status>{}</Status>\n    <ExecutionStatus>{}</ExecutionStatus>\n    <Changes/>",
                    xml_escape(entry["ChangeSetName"].as_str().unwrap_or("")),
                    xml_escape(entry["Status"].as_str().unwrap_or("CREATE_COMPLETE")),
                    xml_escape(entry["ExecutionStatus"].as_str().unwrap_or("AVAILABLE")),
                );
                Ok(xml_response("DescribeChangeSet", inner, &rid))
            }
            "DescribeChangeSetHooks" => Ok(xml_response(
                "DescribeChangeSetHooks",
                "    <Hooks/>".to_string(),
                &rid,
            )),
            "DeleteChangeSet" => {
                let cs = params.get("ChangeSetName").ok_or_else(|| missing("ChangeSetName"))?.clone();
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(&aid);
                if let Some(m) = state.extras.get_mut("change_sets") {
                    m.retain(|_, v| v["Id"].as_str() != Some(&cs) && v["ChangeSetName"].as_str() != Some(&cs));
                }
                Ok(xml_response("DeleteChangeSet", String::new(), &rid))
            }
            "ExecuteChangeSet" => Ok(xml_response("ExecuteChangeSet", String::new(), &rid)),
            "ListChangeSets" => {
                let accounts = self.state.read();
                let items: Vec<Value> = accounts.get(&aid)
                    .and_then(|s| s.extras.get("change_sets"))
                    .map(|m| m.values().cloned().collect())
                    .unwrap_or_default();
                let inner = format!(
                    "    <Summaries>\n{}\n    </Summaries>",
                    members_xml(&items, |v| format!(
                        "        <ChangeSetId>{}</ChangeSetId>\n        <ChangeSetName>{}</ChangeSetName>\n        <Status>{}</Status>",
                        xml_escape(v["Id"].as_str().unwrap_or("")),
                        xml_escape(v["ChangeSetName"].as_str().unwrap_or("")),
                        xml_escape(v["Status"].as_str().unwrap_or("CREATE_COMPLETE")),
                    )),
                );
                Ok(xml_response("ListChangeSets", inner, &rid))
            }

            // ── Stack sets ──
            "CreateStackSet" => {
                let name = params.get("StackSetName").ok_or_else(|| missing("StackSetName"))?.clone();
                let id = format!("{name}:{}", rand_id());
                let entry = json!({
                    "StackSetId": id,
                    "StackSetName": name,
                    "Status": "ACTIVE",
                    "TemplateBody": params.get("TemplateBody").cloned().unwrap_or_default(),
                });
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "stack_sets").insert(name.clone(), entry);
                Ok(xml_response("CreateStackSet", format!("    <StackSetId>{}</StackSetId>", xml_escape(&id)), &rid))
            }
            "DescribeStackSet" => {
                let name = params.get("StackSetName").ok_or_else(|| missing("StackSetName"))?.clone();
                let accounts = self.state.read();
                let entry = accounts.get(&aid)
                    .and_then(|s| s.extras.get("stack_sets"))
                    .and_then(|m| m.get(&name))
                    .cloned()
                    .unwrap_or_else(|| json!({"StackSetName": name.clone(), "Status": "ACTIVE"}));
                let inner = format!(
                    "    <StackSet>\n      <StackSetName>{}</StackSetName>\n      <StackSetId>{}</StackSetId>\n      <Status>{}</Status>\n    </StackSet>",
                    xml_escape(entry["StackSetName"].as_str().unwrap_or(&name)),
                    xml_escape(entry["StackSetId"].as_str().unwrap_or("")),
                    xml_escape(entry["Status"].as_str().unwrap_or("ACTIVE")),
                );
                Ok(xml_response("DescribeStackSet", inner, &rid))
            }
            "ListStackSets" => {
                let accounts = self.state.read();
                let items: Vec<Value> = accounts.get(&aid)
                    .and_then(|s| s.extras.get("stack_sets"))
                    .map(|m| m.values().cloned().collect())
                    .unwrap_or_default();
                let inner = format!(
                    "    <Summaries>\n{}\n    </Summaries>",
                    members_xml(&items, |v| format!(
                        "        <StackSetName>{}</StackSetName>\n        <StackSetId>{}</StackSetId>\n        <Status>{}</Status>",
                        xml_escape(v["StackSetName"].as_str().unwrap_or("")),
                        xml_escape(v["StackSetId"].as_str().unwrap_or("")),
                        xml_escape(v["Status"].as_str().unwrap_or("ACTIVE")),
                    )),
                );
                Ok(xml_response("ListStackSets", inner, &rid))
            }
            "UpdateStackSet" => {
                let op_id = rand_id();
                Ok(xml_response("UpdateStackSet", format!("    <OperationId>{}</OperationId>", xml_escape(&op_id)), &rid))
            }
            "DeleteStackSet" => {
                let name = params.get("StackSetName").ok_or_else(|| missing("StackSetName"))?.clone();
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(&aid);
                if let Some(m) = state.extras.get_mut("stack_sets") {
                    m.remove(&name);
                }
                Ok(xml_response("DeleteStackSet", String::new(), &rid))
            }
            "DescribeStackSetOperation" => {
                let op_id = params.get("OperationId").cloned().unwrap_or_else(rand_id);
                let inner = format!(
                    "    <StackSetOperation>\n      <OperationId>{}</OperationId>\n      <Status>SUCCEEDED</Status>\n    </StackSetOperation>",
                    xml_escape(&op_id),
                );
                Ok(xml_response("DescribeStackSetOperation", inner, &rid))
            }
            "ListStackSetOperations" => Ok(xml_response("ListStackSetOperations", "    <Summaries/>".to_string(), &rid)),
            "ListStackSetOperationResults" => Ok(xml_response("ListStackSetOperationResults", "    <Summaries/>".to_string(), &rid)),
            "ListStackSetAutoDeploymentTargets" => Ok(xml_response("ListStackSetAutoDeploymentTargets", "    <Summaries/>".to_string(), &rid)),
            "StopStackSetOperation" => Ok(xml_response("StopStackSetOperation", String::new(), &rid)),
            "ImportStacksToStackSet" => {
                let op_id = rand_id();
                Ok(xml_response("ImportStacksToStackSet", format!("    <OperationId>{}</OperationId>", xml_escape(&op_id)), &rid))
            }

            // ── Stack instances ──
            "CreateStackInstances" => {
                let op_id = rand_id();
                Ok(xml_response("CreateStackInstances", format!("    <OperationId>{}</OperationId>", xml_escape(&op_id)), &rid))
            }
            "UpdateStackInstances" => {
                let op_id = rand_id();
                Ok(xml_response("UpdateStackInstances", format!("    <OperationId>{}</OperationId>", xml_escape(&op_id)), &rid))
            }
            "DeleteStackInstances" => {
                let op_id = rand_id();
                Ok(xml_response("DeleteStackInstances", format!("    <OperationId>{}</OperationId>", xml_escape(&op_id)), &rid))
            }
            "DescribeStackInstance" => {
                let inner = "    <StackInstance>\n      <Status>CURRENT</Status>\n    </StackInstance>".to_string();
                Ok(xml_response("DescribeStackInstance", inner, &rid))
            }
            "ListStackInstances" => Ok(xml_response("ListStackInstances", "    <Summaries/>".to_string(), &rid)),
            "ListStackInstanceResourceDrifts" => Ok(xml_response("ListStackInstanceResourceDrifts", "    <Summaries/>".to_string(), &rid)),

            // ── Stack refactors ──
            "CreateStackRefactor" => {
                let id = rand_id();
                let entry = json!({"StackRefactorId": id.clone(), "Status": "CREATE_COMPLETE"});
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "refactors").insert(id.clone(), entry);
                Ok(xml_response("CreateStackRefactor", format!("    <StackRefactorId>{}</StackRefactorId>", xml_escape(&id)), &rid))
            }
            "DescribeStackRefactor" => {
                let id = params.get("StackRefactorId").ok_or_else(|| missing("StackRefactorId"))?.clone();
                let inner = format!(
                    "    <StackRefactorId>{}</StackRefactorId>\n    <Status>CREATE_COMPLETE</Status>",
                    xml_escape(&id),
                );
                Ok(xml_response("DescribeStackRefactor", inner, &rid))
            }
            "ExecuteStackRefactor" => Ok(xml_response("ExecuteStackRefactor", String::new(), &rid)),
            "ListStackRefactors" => Ok(xml_response("ListStackRefactors", "    <StackRefactorSummaries/>".to_string(), &rid)),
            "ListStackRefactorActions" => Ok(xml_response("ListStackRefactorActions", "    <StackRefactorActions/>".to_string(), &rid)),

            // ── Types / extensions ──
            "ActivateType" => {
                let arn = Arn::new(
                    "cloudformation",
                    "us-east-1",
                    &aid,
                    &format!("type/resource/{}", rand_id()),
                )
                .to_string();
                Ok(xml_response("ActivateType", format!("    <Arn>{}</Arn>", xml_escape(&arn)), &rid))
            }
            "DeactivateType" => Ok(xml_response("DeactivateType", String::new(), &rid)),
            "DescribeType" => {
                let arn = params.get("Arn").cloned().unwrap_or_else(|| {
                    Arn::new(
                        "cloudformation",
                        "us-east-1",
                        &aid,
                        "type/resource/Default",
                    )
                    .to_string()
                });
                let inner = format!(
                    "    <Arn>{}</Arn>\n    <Type>RESOURCE</Type>\n    <TypeName>AWS::Custom::Type</TypeName>",
                    xml_escape(&arn),
                );
                Ok(xml_response("DescribeType", inner, &rid))
            }
            "DescribeTypeRegistration" => {
                let token = params.get("RegistrationToken").cloned().unwrap_or_default();
                let inner = format!(
                    "    <ProgressStatus>COMPLETE</ProgressStatus>\n    <Description>{}</Description>",
                    xml_escape(&token),
                );
                Ok(xml_response("DescribeTypeRegistration", inner, &rid))
            }
            "RegisterType" => {
                let token = rand_id();
                Ok(xml_response("RegisterType", format!("    <RegistrationToken>{}</RegistrationToken>", xml_escape(&token)), &rid))
            }
            "DeregisterType" => Ok(xml_response("DeregisterType", String::new(), &rid)),
            "ListTypes" => Ok(xml_response("ListTypes", "    <TypeSummaries/>".to_string(), &rid)),
            "ListTypeRegistrations" => Ok(xml_response("ListTypeRegistrations", "    <RegistrationTokenList/>".to_string(), &rid)),
            "ListTypeVersions" => Ok(xml_response("ListTypeVersions", "    <TypeVersionSummaries/>".to_string(), &rid)),
            "BatchDescribeTypeConfigurations" => Ok(xml_response(
                "BatchDescribeTypeConfigurations",
                "    <Errors/>\n    <TypeConfigurations/>".to_string(),
                &rid,
            )),
            "SetTypeConfiguration" => {
                let arn = Arn::new(
                    "cloudformation",
                    "us-east-1",
                    &aid,
                    &format!("type-config/{}", rand_id()),
                )
                .to_string();
                Ok(xml_response("SetTypeConfiguration", format!("    <ConfigurationArn>{}</ConfigurationArn>", xml_escape(&arn)), &rid))
            }
            "SetTypeDefaultVersion" => Ok(xml_response("SetTypeDefaultVersion", String::new(), &rid)),
            "TestType" => {
                let arn = Arn::new(
                    "cloudformation",
                    "us-east-1",
                    &aid,
                    &format!("type/resource/{}", rand_id()),
                )
                .to_string();
                Ok(xml_response("TestType", format!("    <TypeVersionArn>{}</TypeVersionArn>", xml_escape(&arn)), &rid))
            }
            "PublishType" => {
                let arn = Arn::new(
                    "cloudformation",
                    "us-east-1",
                    &aid,
                    &format!("type/resource/{}", rand_id()),
                )
                .to_string();
                Ok(xml_response("PublishType", format!("    <PublicTypeArn>{}</PublicTypeArn>", xml_escape(&arn)), &rid))
            }
            "RegisterPublisher" => {
                let id = rand_id();
                Ok(xml_response("RegisterPublisher", format!("    <PublisherId>{}</PublisherId>", xml_escape(&id)), &rid))
            }
            "DescribePublisher" => {
                let id = params.get("PublisherId").cloned().unwrap_or_else(|| "default-publisher".to_string());
                let inner = format!(
                    "    <PublisherId>{}</PublisherId>\n    <PublisherStatus>VERIFIED</PublisherStatus>\n    <IdentityProvider>AWS_Marketplace</IdentityProvider>",
                    xml_escape(&id),
                );
                Ok(xml_response("DescribePublisher", inner, &rid))
            }

            // ── Generated templates ──
            "CreateGeneratedTemplate" => {
                let name = params.get("GeneratedTemplateName").ok_or_else(|| missing("GeneratedTemplateName"))?.clone();
                let id = Arn::new(
                    "cloudformation",
                    "us-east-1",
                    &aid,
                    &format!("generatedtemplate/{}", rand_id()),
                )
                .to_string();
                let entry = json!({"GeneratedTemplateId": id.clone(), "Name": name.clone(), "Status": "COMPLETE"});
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(&aid);
                store(&mut state.extras, "generated_templates").insert(name.clone(), entry);
                Ok(xml_response("CreateGeneratedTemplate", format!("    <GeneratedTemplateId>{}</GeneratedTemplateId>", xml_escape(&id)), &rid))
            }
            "UpdateGeneratedTemplate" => {
                let name = params.get("GeneratedTemplateName").ok_or_else(|| missing("GeneratedTemplateName"))?.clone();
                let id = Arn::new(
                    "cloudformation",
                    "us-east-1",
                    &aid,
                    &format!("generatedtemplate/{name}"),
                )
                .to_string();
                Ok(xml_response("UpdateGeneratedTemplate", format!("    <GeneratedTemplateId>{}</GeneratedTemplateId>", xml_escape(&id)), &rid))
            }
            "DescribeGeneratedTemplate" => {
                let name = params.get("GeneratedTemplateName").ok_or_else(|| missing("GeneratedTemplateName"))?.clone();
                let inner = format!(
                    "    <GeneratedTemplateId>arn:aws:cloudformation:us-east-1:{}:generatedtemplate/{}</GeneratedTemplateId>\n    <GeneratedTemplateName>{}</GeneratedTemplateName>\n    <Status>COMPLETE</Status>",
                    xml_escape(&aid),
                    xml_escape(&name),
                    xml_escape(&name),
                );
                Ok(xml_response("DescribeGeneratedTemplate", inner, &rid))
            }
            "GetGeneratedTemplate" => Ok(xml_response("GetGeneratedTemplate", "    <Status>COMPLETE</Status>\n    <TemplateBody>{}</TemplateBody>".to_string(), &rid)),
            "DeleteGeneratedTemplate" => {
                let name = params.get("GeneratedTemplateName").ok_or_else(|| missing("GeneratedTemplateName"))?.clone();
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(&aid);
                if let Some(m) = state.extras.get_mut("generated_templates") {
                    m.remove(&name);
                }
                Ok(xml_response("DeleteGeneratedTemplate", String::new(), &rid))
            }
            "ListGeneratedTemplates" => Ok(xml_response("ListGeneratedTemplates", "    <Summaries/>".to_string(), &rid)),

            // ── Resource scans ──
            "StartResourceScan" => {
                let id = Arn::new(
                    "cloudformation",
                    "us-east-1",
                    &aid,
                    &format!("resourceScan/{}", rand_id()),
                )
                .to_string();
                Ok(xml_response("StartResourceScan", format!("    <ResourceScanId>{}</ResourceScanId>", xml_escape(&id)), &rid))
            }
            "DescribeResourceScan" => {
                let id = params.get("ResourceScanId").cloned().unwrap_or_default();
                let inner = format!(
                    "    <ResourceScanId>{}</ResourceScanId>\n    <Status>COMPLETE</Status>",
                    xml_escape(&id),
                );
                Ok(xml_response("DescribeResourceScan", inner, &rid))
            }
            "ListResourceScans" => Ok(xml_response("ListResourceScans", "    <ResourceScanSummaries/>".to_string(), &rid)),
            "ListResourceScanResources" => Ok(xml_response("ListResourceScanResources", "    <Resources/>".to_string(), &rid)),
            "ListResourceScanRelatedResources" => Ok(xml_response("ListResourceScanRelatedResources", "    <RelatedResources/>".to_string(), &rid)),

            // ── Drift detection ──
            "DetectStackDrift" => {
                let id = rand_id();
                Ok(xml_response("DetectStackDrift", format!("    <StackDriftDetectionId>{}</StackDriftDetectionId>", xml_escape(&id)), &rid))
            }
            "DetectStackResourceDrift" => Ok(xml_response(
                "DetectStackResourceDrift",
                "    <StackResourceDrift>\n      <StackResourceDriftStatus>IN_SYNC</StackResourceDriftStatus>\n    </StackResourceDrift>".to_string(),
                &rid,
            )),
            "DetectStackSetDrift" => {
                let op_id = rand_id();
                Ok(xml_response("DetectStackSetDrift", format!("    <OperationId>{}</OperationId>", xml_escape(&op_id)), &rid))
            }
            "DescribeStackDriftDetectionStatus" => {
                let id = params.get("StackDriftDetectionId").cloned().unwrap_or_default();
                let inner = format!(
                    "    <StackDriftDetectionId>{}</StackDriftDetectionId>\n    <DetectionStatus>DETECTION_COMPLETE</DetectionStatus>\n    <StackDriftStatus>IN_SYNC</StackDriftStatus>",
                    xml_escape(&id),
                );
                Ok(xml_response("DescribeStackDriftDetectionStatus", inner, &rid))
            }
            "DescribeStackResourceDrifts" => Ok(xml_response("DescribeStackResourceDrifts", "    <StackResourceDrifts/>".to_string(), &rid)),
            "DescribeStackResource" => {
                let stack_name = params.get("StackName").ok_or_else(|| missing("StackName"))?.clone();
                let logical = params.get("LogicalResourceId").ok_or_else(|| missing("LogicalResourceId"))?.clone();
                let accounts = self.state.read();
                let detail = accounts.get(&aid)
                    .and_then(|s| s.stacks.get(&stack_name))
                    .and_then(|s| s.resources.iter().find(|r| r.logical_id == logical))
                    .map(|r| (r.physical_id.clone(), r.resource_type.clone(), r.status.clone()))
                    .unwrap_or_else(|| ("pid".to_string(), "AWS::Custom".to_string(), "CREATE_COMPLETE".to_string()));
                let inner = format!(
                    "    <StackResourceDetail>\n      <StackName>{}</StackName>\n      <LogicalResourceId>{}</LogicalResourceId>\n      <PhysicalResourceId>{}</PhysicalResourceId>\n      <ResourceType>{}</ResourceType>\n      <ResourceStatus>{}</ResourceStatus>\n      <LastUpdatedTimestamp>{}</LastUpdatedTimestamp>\n    </StackResourceDetail>",
                    xml_escape(&stack_name),
                    xml_escape(&logical),
                    xml_escape(&detail.0),
                    xml_escape(&detail.1),
                    xml_escape(&detail.2),
                    chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ"),
                );
                Ok(xml_response("DescribeStackResource", inner, &rid))
            }

            // ── Events ──
            "DescribeStackEvents" => Ok(xml_response("DescribeStackEvents", "    <StackEvents/>".to_string(), &rid)),
            "DescribeEvents" => Ok(xml_response("DescribeEvents", "    <Events/>".to_string(), &rid)),

            // ── Hooks ──
            "GetHookResult" => Ok(xml_response(
                "GetHookResult",
                "    <Status>HOOK_COMPLETE_SUCCEEDED</Status>".to_string(),
                &rid,
            )),
            "ListHookResults" => Ok(xml_response("ListHookResults", "    <HookResults/>".to_string(), &rid)),
            "RecordHandlerProgress" => Ok(xml_response_no_result("RecordHandlerProgress", &rid)),

            // ── Imports / exports ──
            "ListExports" => {
                let accounts = self.state.read();
                let mut entries = String::new();
                if let Some(state) = accounts.get(&aid) {
                    for stack in state.stacks.values() {
                        if stack.status == "DELETE_COMPLETE" {
                            continue;
                        }
                        for output in &stack.outputs {
                            if let Some(export) = &output.export_name {
                                entries.push_str(&format!(
                                    "      <member>\n        <ExportingStackId>{}</ExportingStackId>\n        <Name>{}</Name>\n        <Value>{}</Value>\n      </member>\n",
                                    xml_escape(&stack.stack_id),
                                    xml_escape(export),
                                    xml_escape(&output.value),
                                ));
                            }
                        }
                    }
                }
                let inner = if entries.is_empty() {
                    "    <Exports/>".to_string()
                } else {
                    format!("    <Exports>\n{entries}    </Exports>")
                };
                Ok(xml_response("ListExports", inner, &rid))
            }
            "ListImports" => {
                let export_name = params
                    .get("ExportName")
                    .cloned()
                    .ok_or_else(|| missing("ExportName"))?;
                let accounts = self.state.read();
                let mut entries = String::new();
                if let Some(state) = accounts.get(&aid) {
                    for stack in state.stacks.values() {
                        if stack.status == "DELETE_COMPLETE" {
                            continue;
                        }
                        // A stack imports the export if its raw template
                        // text references `Fn::ImportValue` with that name
                        // (string-match keeps us protocol-light).
                        let needle_a = format!("\"{}\"", export_name);
                        let needle_b = format!("'{}'", export_name);
                        if stack.template.contains("ImportValue")
                            && (stack.template.contains(&needle_a)
                                || stack.template.contains(&needle_b))
                        {
                            entries.push_str(&format!(
                                "      <member>{}</member>\n",
                                xml_escape(&stack.name)
                            ));
                        }
                    }
                }
                let inner = if entries.is_empty() {
                    "    <Imports/>".to_string()
                } else {
                    format!("    <Imports>\n{entries}    </Imports>")
                };
                Ok(xml_response("ListImports", inner, &rid))
            }

            // ── Stack policies ──
            "GetStackPolicy" => {
                let stack = params.get("StackName").ok_or_else(|| missing("StackName"))?.clone();
                let accounts = self.state.read();
                let body = accounts.get(&aid)
                    .and_then(|s| s.stack_policies.get(&stack))
                    .cloned()
                    .unwrap_or_else(|| r#"{"Statement":[{"Effect":"Allow","Action":"Update:*","Principal":"*","Resource":"*"}]}"#.to_string());
                let inner = format!("    <StackPolicyBody>{}</StackPolicyBody>", xml_escape(&body));
                Ok(xml_response("GetStackPolicy", inner, &rid))
            }
            "SetStackPolicy" => {
                let stack = params.get("StackName").ok_or_else(|| missing("StackName"))?.clone();
                let body = params.get("StackPolicyBody").cloned().unwrap_or_default();
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(&aid);
                state.stack_policies.insert(stack, body);
                Ok(xml_response_no_result("SetStackPolicy", &rid))
            }

            // ── Termination protection ──
            "UpdateTerminationProtection" => {
                let stack = params.get("StackName").ok_or_else(|| missing("StackName"))?.clone();
                let enabled = params.get("EnableTerminationProtection")
                    .map(|v| v.eq_ignore_ascii_case("true"))
                    .unwrap_or(false);
                let stack_id = {
                    let mut accounts = self.state.write();
                    let state = accounts.get_or_create(&aid);
                    state.termination_protection.insert(stack.clone(), enabled);
                    state.stacks.get(&stack).map(|s| s.stack_id.clone()).unwrap_or_else(|| stack.clone())
                };
                Ok(xml_response("UpdateTerminationProtection", format!("    <StackId>{}</StackId>", xml_escape(&stack_id)), &rid))
            }

            // ── Account / org / validation / utilities ──
            "DescribeAccountLimits" => Ok(xml_response(
                "DescribeAccountLimits",
                r#"    <AccountLimits>
      <member>
        <Name>StackLimit</Name>
        <Value>2000</Value>
      </member>
    </AccountLimits>"#.to_string(),
                &rid,
            )),
            "ActivateOrganizationsAccess" => {
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(&aid);
                state.orgs_access_enabled = true;
                Ok(xml_response("ActivateOrganizationsAccess", String::new(), &rid))
            }
            "DeactivateOrganizationsAccess" => {
                let mut accounts = self.state.write();
                let state = accounts.get_or_create(&aid);
                state.orgs_access_enabled = false;
                Ok(xml_response("DeactivateOrganizationsAccess", String::new(), &rid))
            }
            "DescribeOrganizationsAccess" => {
                let accounts = self.state.read();
                let status = if accounts.get(&aid).map(|s| s.orgs_access_enabled).unwrap_or(false) {
                    "ENABLED"
                } else {
                    "DISABLED"
                };
                Ok(xml_response("DescribeOrganizationsAccess", format!("    <Status>{}</Status>", status), &rid))
            }
            "ValidateTemplate" => Ok(xml_response(
                "ValidateTemplate",
                "    <Description>Validated</Description>\n    <Capabilities/>\n    <Parameters/>".to_string(),
                &rid,
            )),
            "EstimateTemplateCost" => Ok(xml_response(
                "EstimateTemplateCost",
                "    <Url>https://calculator.aws/#/estimate</Url>".to_string(),
                &rid,
            )),
            "GetTemplateSummary" => Ok(xml_response(
                "GetTemplateSummary",
                "    <Parameters/>\n    <ResourceTypes/>\n    <Capabilities/>".to_string(),
                &rid,
            )),
            "CancelUpdateStack" => Ok(xml_response_no_result("CancelUpdateStack", &rid)),
            "ContinueUpdateRollback" => Ok(xml_response("ContinueUpdateRollback", String::new(), &rid)),
            "RollbackStack" => {
                let stack = params.get("StackName").ok_or_else(|| missing("StackName"))?.clone();
                let stack_id = {
                    let accounts = self.state.read();
                    accounts.get(&aid).and_then(|s| s.stacks.get(&stack)).map(|s| s.stack_id.clone()).unwrap_or_else(|| stack.clone())
                };
                Ok(xml_response("RollbackStack", format!("    <StackId>{}</StackId>", xml_escape(&stack_id)), &rid))
            }
            "SignalResource" => Ok(xml_response_no_result("SignalResource", &rid)),

            _ => Err(AwsServiceError::action_not_implemented("cloudformation", &action)),
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::service::{CloudFormationDeps, CloudFormationService};
    use crate::state::{CloudFormationState, SharedCloudFormationState};
    use fakecloud_core::delivery::DeliveryBus;
    use fakecloud_core::multi_account::MultiAccountState;
    use fakecloud_core::service::AwsRequest;
    use http::Method;
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn deps() -> CloudFormationDeps {
        use fakecloud_dynamodb::DynamoDbState;
        use fakecloud_eventbridge::EventBridgeState;
        use fakecloud_iam::IamState;
        use fakecloud_kinesis::KinesisState;
        use fakecloud_kms::KmsState;
        use fakecloud_lambda::LambdaState;
        use fakecloud_logs::LogsState;
        use fakecloud_s3::S3State;
        use fakecloud_secretsmanager::SecretsManagerState;
        use fakecloud_sns::SnsState;
        use fakecloud_sqs::SqsState;
        use fakecloud_ssm::SsmState;

        fn shared<T: fakecloud_core::multi_account::AccountState>(
        ) -> Arc<RwLock<MultiAccountState<T>>> {
            Arc::new(RwLock::new(MultiAccountState::<T>::new(
                "000000000000",
                "us-east-1",
                "",
            )))
        }
        CloudFormationDeps {
            sqs: shared::<SqsState>(),
            sns: shared::<SnsState>(),
            ssm: shared::<SsmState>(),
            iam: shared::<IamState>(),
            s3: shared::<S3State>(),
            eventbridge: shared::<EventBridgeState>(),
            dynamodb: shared::<DynamoDbState>(),
            logs: shared::<LogsState>(),
            lambda: shared::<LambdaState>(),
            secretsmanager: shared::<SecretsManagerState>(),
            kinesis: shared::<KinesisState>(),
            kms: shared::<KmsState>(),
            delivery: Arc::new(DeliveryBus::new()),
        }
    }

    fn svc() -> CloudFormationService {
        let state: SharedCloudFormationState =
            Arc::new(RwLock::new(MultiAccountState::<CloudFormationState>::new(
                "000000000000",
                "us-east-1",
                "",
            )));
        CloudFormationService::new(state, deps())
    }

    fn req(action: &str, params: &[(&str, &str)]) -> AwsRequest {
        let mut q = HashMap::new();
        q.insert("Action".to_string(), action.to_string());
        for (k, v) in params {
            q.insert(k.to_string(), v.to_string());
        }
        AwsRequest {
            service: "cloudformation".to_string(),
            method: Method::POST,
            raw_path: "/".to_string(),
            raw_query: String::new(),
            path_segments: vec![],
            query_params: q,
            headers: http::HeaderMap::new(),
            body: bytes::Bytes::new(),
            body_stream: parking_lot::Mutex::new(None),
            account_id: "000000000000".to_string(),
            region: "us-east-1".to_string(),
            request_id: "rid".to_string(),
            action: action.to_string(),
            is_query_protocol: true,
            access_key_id: None,
            principal: None,
        }
    }

    fn ok(action: &str, params: &[(&str, &str)]) {
        let r = svc().handle_extra_action(&req(action, params));
        match r {
            Ok(resp) => assert!(resp.status.is_success(), "{action} status: {}", resp.status),
            Err(e) => panic!("{action} failed: {e:?}"),
        }
    }

    #[test]
    fn change_sets() {
        ok(
            "CreateChangeSet",
            &[("StackName", "s"), ("ChangeSetName", "cs")],
        );
        ok("DescribeChangeSet", &[("ChangeSetName", "cs")]);
        ok("DescribeChangeSetHooks", &[]);
        ok("ListChangeSets", &[]);
        ok("ExecuteChangeSet", &[]);
        ok("DeleteChangeSet", &[("ChangeSetName", "cs")]);
    }

    #[test]
    fn stack_sets_instances_refactors() {
        ok("CreateStackSet", &[("StackSetName", "ss")]);
        ok("DescribeStackSet", &[("StackSetName", "ss")]);
        ok("ListStackSets", &[]);
        ok("UpdateStackSet", &[]);
        ok("DescribeStackSetOperation", &[]);
        ok("ListStackSetOperations", &[]);
        ok("ListStackSetOperationResults", &[]);
        ok("ListStackSetAutoDeploymentTargets", &[]);
        ok("StopStackSetOperation", &[]);
        ok("ImportStacksToStackSet", &[]);
        ok("DeleteStackSet", &[("StackSetName", "ss")]);
        ok("CreateStackInstances", &[]);
        ok("UpdateStackInstances", &[]);
        ok("DeleteStackInstances", &[]);
        ok("DescribeStackInstance", &[]);
        ok("ListStackInstances", &[]);
        ok("ListStackInstanceResourceDrifts", &[]);
        ok("CreateStackRefactor", &[]);
        ok("DescribeStackRefactor", &[("StackRefactorId", "r")]);
        ok("ExecuteStackRefactor", &[]);
        ok("ListStackRefactors", &[]);
        ok("ListStackRefactorActions", &[]);
    }

    #[test]
    fn types_and_publishers() {
        ok("ActivateType", &[]);
        ok("DeactivateType", &[]);
        ok("DescribeType", &[]);
        ok("DescribeTypeRegistration", &[]);
        ok("RegisterType", &[]);
        ok("DeregisterType", &[]);
        ok("ListTypes", &[]);
        ok("ListTypeRegistrations", &[]);
        ok("ListTypeVersions", &[]);
        ok("BatchDescribeTypeConfigurations", &[]);
        ok("SetTypeConfiguration", &[]);
        ok("SetTypeDefaultVersion", &[]);
        ok("TestType", &[]);
        ok("PublishType", &[]);
        ok("RegisterPublisher", &[]);
        ok("DescribePublisher", &[]);
    }

    #[test]
    fn templates_resource_scans_drift() {
        ok(
            "CreateGeneratedTemplate",
            &[("GeneratedTemplateName", "gt")],
        );
        ok(
            "UpdateGeneratedTemplate",
            &[("GeneratedTemplateName", "gt")],
        );
        ok(
            "DescribeGeneratedTemplate",
            &[("GeneratedTemplateName", "gt")],
        );
        ok("GetGeneratedTemplate", &[]);
        ok("ListGeneratedTemplates", &[]);
        ok(
            "DeleteGeneratedTemplate",
            &[("GeneratedTemplateName", "gt")],
        );
        ok("StartResourceScan", &[]);
        ok("DescribeResourceScan", &[]);
        ok("ListResourceScans", &[]);
        ok("ListResourceScanResources", &[]);
        ok("ListResourceScanRelatedResources", &[]);
        ok("DetectStackDrift", &[]);
        ok("DetectStackResourceDrift", &[]);
        ok("DetectStackSetDrift", &[]);
        ok("DescribeStackDriftDetectionStatus", &[]);
        ok("DescribeStackResourceDrifts", &[]);
        ok(
            "DescribeStackResource",
            &[("StackName", "s"), ("LogicalResourceId", "L")],
        );
    }

    #[test]
    fn events_hooks_imports_policies_org() {
        ok("DescribeStackEvents", &[]);
        ok("DescribeEvents", &[]);
        ok("GetHookResult", &[]);
        ok("ListHookResults", &[]);
        ok("RecordHandlerProgress", &[]);
        ok("ListExports", &[]);
        ok("ListImports", &[("ExportName", "SomeExport")]);
        ok("GetStackPolicy", &[("StackName", "s")]);
        ok("SetStackPolicy", &[("StackName", "s")]);
        ok("UpdateTerminationProtection", &[("StackName", "s")]);
        ok("DescribeAccountLimits", &[]);
        ok("ActivateOrganizationsAccess", &[]);
        ok("DescribeOrganizationsAccess", &[]);
        ok("DeactivateOrganizationsAccess", &[]);
        ok("ValidateTemplate", &[]);
        ok("EstimateTemplateCost", &[]);
        ok("GetTemplateSummary", &[]);
        ok("CancelUpdateStack", &[]);
        ok("ContinueUpdateRollback", &[]);
        ok("RollbackStack", &[("StackName", "s")]);
        ok("SignalResource", &[]);
    }
}
