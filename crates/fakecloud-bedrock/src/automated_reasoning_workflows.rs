use chrono::Utc;
use http::StatusCode;
use serde_json::{json, Value};
use uuid::Uuid;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError};

use crate::state::{AutomatedReasoningBuildWorkflow, SharedBedrockState};

fn find_policy_arn(
    policies: &std::collections::HashMap<String, crate::state::AutomatedReasoningPolicy>,
    identifier: &str,
) -> Option<String> {
    policies
        .iter()
        .find(|(k, p)| {
            *k == identifier
                || p.policy_name == identifier
                || p.policy_arn.ends_with(&format!("/{identifier}"))
        })
        .map(|(k, _)| k.clone())
}

fn require_policy_arn(
    policies: &std::collections::HashMap<String, crate::state::AutomatedReasoningPolicy>,
    identifier: &str,
) -> Result<String, AwsServiceError> {
    find_policy_arn(policies, identifier).ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::NOT_FOUND,
            "ResourceNotFoundException",
            format!("Automated reasoning policy {identifier} not found"),
        )
    })
}

fn workflow_to_json(w: &AutomatedReasoningBuildWorkflow) -> Value {
    json!({
        "buildWorkflowId": w.workflow_id,
        "policyArn": w.policy_arn,
        "workflowType": w.workflow_type,
        "status": w.status,
        "createdAt": w.created_at.to_rfc3339(),
        "updatedAt": w.updated_at.to_rfc3339(),
    })
}

pub fn start_build_workflow(
    state: &SharedBedrockState,
    req: &AwsRequest,
    policy_identifier: &str,
    workflow_type: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let mut accts = state.write();
    let s = accts.get_or_create(&req.account_id);
    let policy_arn = require_policy_arn(&s.automated_reasoning_policies, policy_identifier)?;

    let workflow_id = Uuid::new_v4().to_string();
    let now = Utc::now();
    let workflow = AutomatedReasoningBuildWorkflow {
        workflow_id: workflow_id.clone(),
        policy_arn: policy_arn.clone(),
        workflow_type: workflow_type.to_string(),
        status: "InProgress".to_string(),
        created_at: now,
        updated_at: now,
    };

    s.ar_build_workflows
        .insert((policy_arn, workflow_id.clone()), workflow);

    Ok(AwsResponse::json_value(
        StatusCode::CREATED,
        json!({ "buildWorkflowId": workflow_id }),
    ))
}

pub fn get_build_workflow(
    state: &SharedBedrockState,
    req: &AwsRequest,
    policy_identifier: &str,
    workflow_id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let accts = state.read();
    let empty = crate::state::BedrockState::new(&req.account_id, &req.region);
    let s = accts.get(&req.account_id).unwrap_or(&empty);
    let policy_arn = require_policy_arn(&s.automated_reasoning_policies, policy_identifier)?;

    let workflow = s
        .ar_build_workflows
        .get(&(policy_arn, workflow_id.to_string()))
        .ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!("Build workflow {workflow_id} not found"),
            )
        })?;

    Ok(AwsResponse::ok_json(workflow_to_json(workflow)))
}

pub fn list_build_workflows(
    state: &SharedBedrockState,
    policy_identifier: &str,
    req: &AwsRequest,
) -> Result<AwsResponse, AwsServiceError> {
    let max_results = req
        .query_params
        .get("maxResults")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(100)
        .max(1);
    let next_token = req.query_params.get("nextToken");

    let accts = state.read();
    let empty = crate::state::BedrockState::new(&req.account_id, &req.region);
    let s = accts.get(&req.account_id).unwrap_or(&empty);
    let policy_arn = require_policy_arn(&s.automated_reasoning_policies, policy_identifier)?;

    let mut items: Vec<&AutomatedReasoningBuildWorkflow> = s
        .ar_build_workflows
        .iter()
        .filter(|((arn, _), _)| *arn == policy_arn)
        .map(|(_, w)| w)
        .collect();
    items.sort_by(|a, b| a.workflow_id.cmp(&b.workflow_id));

    let start = if let Some(token) = next_token {
        items
            .iter()
            .position(|w| w.workflow_id.as_str() > token.as_str())
            .unwrap_or(items.len())
    } else {
        0
    };

    let page: Vec<Value> = items
        .iter()
        .skip(start)
        .take(max_results)
        .map(|w| workflow_to_json(w))
        .collect();

    let mut resp = json!({ "buildWorkflowSummaries": page });
    let end = start.saturating_add(max_results);
    if end < items.len() {
        if let Some(last) = items.get(end - 1) {
            resp["nextToken"] = json!(last.workflow_id);
        }
    }

    Ok(AwsResponse::ok_json(resp))
}

pub fn cancel_build_workflow(
    state: &SharedBedrockState,
    req: &AwsRequest,
    policy_identifier: &str,
    workflow_id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let mut accts = state.write();
    let s = accts.get_or_create(&req.account_id);
    let policy_arn = require_policy_arn(&s.automated_reasoning_policies, policy_identifier)?;

    let workflow = s
        .ar_build_workflows
        .get_mut(&(policy_arn, workflow_id.to_string()))
        .ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFoundException",
                format!("Build workflow {workflow_id} not found"),
            )
        })?;

    workflow.status = "Cancelled".to_string();
    workflow.updated_at = Utc::now();

    Ok(AwsResponse::json(StatusCode::OK, "{}".to_string()))
}

pub fn delete_build_workflow(
    state: &SharedBedrockState,
    req: &AwsRequest,
    policy_identifier: &str,
    workflow_id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let mut accts = state.write();
    let s = accts.get_or_create(&req.account_id);
    let policy_arn = require_policy_arn(&s.automated_reasoning_policies, policy_identifier)?;

    let key = (policy_arn.clone(), workflow_id.to_string());
    if s.ar_build_workflows.remove(&key).is_none() {
        return Err(AwsServiceError::aws_error(
            StatusCode::NOT_FOUND,
            "ResourceNotFoundException",
            format!("Build workflow {workflow_id} not found"),
        ));
    }

    // Clean up associated test results and annotations
    s.ar_test_results
        .retain(|(pa, wid, _), _| !(*pa == policy_arn && *wid == workflow_id));
    s.ar_annotations
        .retain(|(pa, wid), _| !(*pa == policy_arn && *wid == workflow_id));

    Ok(AwsResponse::json(StatusCode::OK, "{}".to_string()))
}

pub fn get_build_workflow_result_assets(
    state: &SharedBedrockState,
    req: &AwsRequest,
    policy_identifier: &str,
    workflow_id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let accts = state.read();
    let empty = crate::state::BedrockState::new(&req.account_id, &req.region);
    let s = accts.get(&req.account_id).unwrap_or(&empty);
    let policy_arn = require_policy_arn(&s.automated_reasoning_policies, policy_identifier)?;

    if !s
        .ar_build_workflows
        .contains_key(&(policy_arn, workflow_id.to_string()))
    {
        return Err(AwsServiceError::aws_error(
            StatusCode::NOT_FOUND,
            "ResourceNotFoundException",
            format!("Build workflow {workflow_id} not found"),
        ));
    }

    Ok(AwsResponse::ok_json(json!({ "assets": [] })))
}

pub fn start_test_workflow(
    state: &SharedBedrockState,
    req: &AwsRequest,
    policy_identifier: &str,
    workflow_id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let accts = state.read();
    let empty = crate::state::BedrockState::new(&req.account_id, &req.region);
    let s = accts.get(&req.account_id).unwrap_or(&empty);
    let policy_arn = require_policy_arn(&s.automated_reasoning_policies, policy_identifier)?;

    if !s
        .ar_build_workflows
        .contains_key(&(policy_arn, workflow_id.to_string()))
    {
        return Err(AwsServiceError::aws_error(
            StatusCode::NOT_FOUND,
            "ResourceNotFoundException",
            format!("Build workflow {workflow_id} not found"),
        ));
    }

    let test_workflow_id = Uuid::new_v4().to_string();

    Ok(AwsResponse::ok_json(
        json!({ "testWorkflowId": test_workflow_id }),
    ))
}

pub fn get_test_result(
    state: &SharedBedrockState,
    req: &AwsRequest,
    policy_identifier: &str,
    workflow_id: &str,
    test_case_id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let accts = state.read();
    let empty = crate::state::BedrockState::new(&req.account_id, &req.region);
    let s = accts.get(&req.account_id).unwrap_or(&empty);
    let policy_arn = require_policy_arn(&s.automated_reasoning_policies, policy_identifier)?;

    if !s
        .ar_build_workflows
        .contains_key(&(policy_arn.clone(), workflow_id.to_string()))
    {
        return Err(AwsServiceError::aws_error(
            StatusCode::NOT_FOUND,
            "ResourceNotFoundException",
            format!("Build workflow {workflow_id} not found"),
        ));
    }

    let result = s
        .ar_test_results
        .get(&(
            policy_arn,
            workflow_id.to_string(),
            test_case_id.to_string(),
        ))
        .cloned()
        .unwrap_or_else(|| {
            json!({
                "testCaseId": test_case_id,
                "status": "NotRun",
            })
        });

    Ok(AwsResponse::ok_json(result))
}

pub fn list_test_results(
    state: &SharedBedrockState,
    policy_identifier: &str,
    workflow_id: &str,
    req: &AwsRequest,
) -> Result<AwsResponse, AwsServiceError> {
    let max_results = req
        .query_params
        .get("maxResults")
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(100)
        .max(1);
    let next_token = req.query_params.get("nextToken");

    let accts = state.read();
    let empty = crate::state::BedrockState::new(&req.account_id, &req.region);
    let s = accts.get(&req.account_id).unwrap_or(&empty);
    let policy_arn = require_policy_arn(&s.automated_reasoning_policies, policy_identifier)?;

    if !s
        .ar_build_workflows
        .contains_key(&(policy_arn.clone(), workflow_id.to_string()))
    {
        return Err(AwsServiceError::aws_error(
            StatusCode::NOT_FOUND,
            "ResourceNotFoundException",
            format!("Build workflow {workflow_id} not found"),
        ));
    }

    let mut items: Vec<(&String, &Value)> = s
        .ar_test_results
        .iter()
        .filter(|((pa, wid, _), _)| *pa == policy_arn && *wid == workflow_id)
        .map(|((_, _, tcid), v)| (tcid, v))
        .collect();
    items.sort_by(|a, b| a.0.cmp(b.0));

    let start = if let Some(token) = next_token {
        items
            .iter()
            .position(|(tcid, _)| tcid.as_str() > token.as_str())
            .unwrap_or(items.len())
    } else {
        0
    };

    let page: Vec<&Value> = items
        .iter()
        .skip(start)
        .take(max_results)
        .map(|(_, v)| *v)
        .collect();

    let mut resp = json!({ "testResultSummaries": page });
    let end = start.saturating_add(max_results);
    if end < items.len() {
        if let Some((tcid, _)) = items.get(end - 1) {
            resp["nextToken"] = json!(tcid);
        }
    }

    Ok(AwsResponse::ok_json(resp))
}

pub fn get_annotations(
    state: &SharedBedrockState,
    req: &AwsRequest,
    policy_identifier: &str,
    workflow_id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let accts = state.read();
    let empty = crate::state::BedrockState::new(&req.account_id, &req.region);
    let s = accts.get(&req.account_id).unwrap_or(&empty);
    let policy_arn = require_policy_arn(&s.automated_reasoning_policies, policy_identifier)?;

    if !s
        .ar_build_workflows
        .contains_key(&(policy_arn.clone(), workflow_id.to_string()))
    {
        return Err(AwsServiceError::aws_error(
            StatusCode::NOT_FOUND,
            "ResourceNotFoundException",
            format!("Build workflow {workflow_id} not found"),
        ));
    }

    let annotations = s
        .ar_annotations
        .get(&(policy_arn, workflow_id.to_string()))
        .cloned()
        .unwrap_or_else(|| json!({ "annotations": [] }));

    Ok(AwsResponse::ok_json(annotations))
}

pub fn update_annotations(
    state: &SharedBedrockState,
    req: &AwsRequest,
    policy_identifier: &str,
    workflow_id: &str,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let mut accts = state.write();
    let s = accts.get_or_create(&req.account_id);
    let policy_arn = require_policy_arn(&s.automated_reasoning_policies, policy_identifier)?;

    if !s
        .ar_build_workflows
        .contains_key(&(policy_arn.clone(), workflow_id.to_string()))
    {
        return Err(AwsServiceError::aws_error(
            StatusCode::NOT_FOUND,
            "ResourceNotFoundException",
            format!("Build workflow {workflow_id} not found"),
        ));
    }

    s.ar_annotations
        .insert((policy_arn, workflow_id.to_string()), body.clone());

    Ok(AwsResponse::ok_json(body.clone()))
}

pub fn get_next_scenario(
    state: &SharedBedrockState,
    req: &AwsRequest,
    policy_identifier: &str,
    workflow_id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let accts = state.read();
    let empty = crate::state::BedrockState::new(&req.account_id, &req.region);
    let s = accts.get(&req.account_id).unwrap_or(&empty);
    let policy_arn = require_policy_arn(&s.automated_reasoning_policies, policy_identifier)?;

    if !s
        .ar_build_workflows
        .contains_key(&(policy_arn, workflow_id.to_string()))
    {
        return Err(AwsServiceError::aws_error(
            StatusCode::NOT_FOUND,
            "ResourceNotFoundException",
            format!("Build workflow {workflow_id} not found"),
        ));
    }

    Ok(AwsResponse::ok_json(json!({
        "scenarioId": Uuid::new_v4().to_string(),
        "workflowId": workflow_id,
        "status": "Ready",
        "inputs": [],
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::AutomatedReasoningPolicy;
    use bytes::Bytes;
    use http::{HeaderMap, Method};
    use parking_lot::RwLock;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn shared() -> SharedBedrockState {
        Arc::new(RwLock::new(
            fakecloud_core::multi_account::MultiAccountState::new(
                "123456789012",
                "us-east-1",
                "http://localhost:4566",
            ),
        ))
    }

    fn req() -> AwsRequest {
        AwsRequest {
            service: "bedrock".to_string(),
            action: "a".to_string(),
            method: Method::POST,
            raw_path: "/".to_string(),
            raw_query: String::new(),
            path_segments: vec![],
            query_params: HashMap::new(),
            headers: HeaderMap::new(),
            body: Bytes::new(),
            body_stream: parking_lot::Mutex::new(None),
            account_id: "123456789012".to_string(),
            region: "us-east-1".to_string(),
            request_id: "req".to_string(),
            is_query_protocol: false,
            access_key_id: None,
            principal: None,
        }
    }

    fn seed_policy(state: &SharedBedrockState, name: &str) -> String {
        let arn = format!(
            "arn:aws:bedrock:us-east-1:123456789012:automated-reasoning-policy/{}",
            Uuid::new_v4()
        );
        let now = Utc::now();
        state
            .write()
            .default_mut()
            .automated_reasoning_policies
            .insert(
                arn.clone(),
                AutomatedReasoningPolicy {
                    policy_arn: arn.clone(),
                    policy_name: name.to_string(),
                    description: None,
                    policy_document: json!({}),
                    status: "ACTIVE".to_string(),
                    version: "1".to_string(),
                    versions: vec!["1".to_string()],
                    created_at: now,
                    updated_at: now,
                },
            );
        arn
    }

    fn start_workflow(state: &SharedBedrockState, policy_id: &str) -> String {
        let resp = start_build_workflow(state, &req(), policy_id, "BUILD").unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        v["buildWorkflowId"].as_str().unwrap().to_string()
    }

    #[test]
    fn start_build_workflow_persists_entry() {
        let s = shared();
        let arn = seed_policy(&s, "p1");
        let wid = start_workflow(&s, &arn);
        let w = s
            .read()
            .default_ref()
            .ar_build_workflows
            .get(&(arn.clone(), wid))
            .unwrap()
            .clone();
        assert_eq!(w.workflow_type, "BUILD");
        assert_eq!(w.status, "InProgress");
    }

    #[test]
    fn start_build_workflow_unknown_policy_not_found() {
        let s = shared();
        let err = start_build_workflow(&s, &req(), "missing", "BUILD")
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn get_build_workflow_roundtrip() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let wid = start_workflow(&s, &arn);
        let resp = get_build_workflow(&s, &req(), &arn, &wid).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["buildWorkflowId"], wid);
        assert_eq!(v["status"], "InProgress");
    }

    #[test]
    fn get_build_workflow_unknown_returns_not_found() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let err = get_build_workflow(&s, &req(), &arn, "missing")
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn list_build_workflows_paginates() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        for _ in 0..3 {
            start_workflow(&s, &arn);
        }
        let mut r = req();
        r.query_params
            .insert("maxResults".to_string(), "2".to_string());
        let resp = list_build_workflows(&s, &arn, &r).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["buildWorkflowSummaries"].as_array().unwrap().len(), 2);
        assert!(v["nextToken"].is_string());
    }

    #[test]
    fn list_build_workflows_unknown_policy_not_found() {
        let s = shared();
        let err = list_build_workflows(&s, "miss", &req()).err().unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn cancel_build_workflow_transitions_status() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let wid = start_workflow(&s, &arn);
        cancel_build_workflow(&s, &req(), &arn, &wid).unwrap();
        let guard = s.read();
        let w = &guard.default_ref().ar_build_workflows[&(arn.clone(), wid.clone())];
        assert_eq!(w.status, "Cancelled");
    }

    #[test]
    fn cancel_build_workflow_unknown_returns_not_found() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let err = cancel_build_workflow(&s, &req(), &arn, "miss")
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn delete_build_workflow_cleans_annotations_and_results() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let wid = start_workflow(&s, &arn);
        update_annotations(&s, &req(), &arn, &wid, &json!({"a": 1})).unwrap();
        s.write().default_mut().ar_test_results.insert(
            (arn.clone(), wid.clone(), "tc1".to_string()),
            json!({"t": 1}),
        );
        delete_build_workflow(&s, &req(), &arn, &wid).unwrap();
        let g = s.read();
        assert!(g.default_ref().ar_build_workflows.is_empty());
        assert!(g.default_ref().ar_test_results.is_empty());
        assert!(g.default_ref().ar_annotations.is_empty());
    }

    #[test]
    fn delete_build_workflow_unknown_returns_not_found() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let err = delete_build_workflow(&s, &req(), &arn, "miss")
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn get_build_workflow_result_assets_returns_empty_list() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let wid = start_workflow(&s, &arn);
        let resp = get_build_workflow_result_assets(&s, &req(), &arn, &wid).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["assets"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn get_build_workflow_result_assets_unknown_not_found() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let err = get_build_workflow_result_assets(&s, &req(), &arn, "miss")
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn start_test_workflow_returns_id() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let wid = start_workflow(&s, &arn);
        let resp = start_test_workflow(&s, &req(), &arn, &wid).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert!(v["testWorkflowId"].is_string());
    }

    #[test]
    fn start_test_workflow_unknown_not_found() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let err = start_test_workflow(&s, &req(), &arn, "miss").err().unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn get_test_result_default_when_absent() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let wid = start_workflow(&s, &arn);
        let resp = get_test_result(&s, &req(), &arn, &wid, "tc-x").unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["status"], "NotRun");
        assert_eq!(v["testCaseId"], "tc-x");
    }

    #[test]
    fn get_test_result_returns_stored_value() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let wid = start_workflow(&s, &arn);
        s.write().default_mut().ar_test_results.insert(
            (arn.clone(), wid.clone(), "tc".to_string()),
            json!({"status": "Passed"}),
        );
        let resp = get_test_result(&s, &req(), &arn, &wid, "tc").unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["status"], "Passed");
    }

    #[test]
    fn get_test_result_unknown_workflow_not_found() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let err = get_test_result(&s, &req(), &arn, "miss", "tc")
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn list_test_results_paginates() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let wid = start_workflow(&s, &arn);
        for i in 0..3 {
            s.write().default_mut().ar_test_results.insert(
                (arn.clone(), wid.clone(), format!("tc-{i}")),
                json!({"testCaseId": format!("tc-{i}"), "status": "Passed"}),
            );
        }
        let mut r = req();
        r.query_params
            .insert("maxResults".to_string(), "2".to_string());
        let resp = list_test_results(&s, &arn, &wid, &r).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["testResultSummaries"].as_array().unwrap().len(), 2);
        assert!(v["nextToken"].is_string());
    }

    #[test]
    fn list_test_results_unknown_workflow_not_found() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let err = list_test_results(&s, &arn, "miss", &req()).err().unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn annotations_roundtrip() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let wid = start_workflow(&s, &arn);
        let resp = get_annotations(&s, &req(), &arn, &wid).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["annotations"].as_array().unwrap().len(), 0);

        update_annotations(&s, &req(), &arn, &wid, &json!({"k": "v"})).unwrap();
        let resp = get_annotations(&s, &req(), &arn, &wid).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["k"], "v");
    }

    #[test]
    fn get_annotations_unknown_workflow_not_found() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let err = get_annotations(&s, &req(), &arn, "miss").err().unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn update_annotations_unknown_workflow_not_found() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let err = update_annotations(&s, &req(), &arn, "miss", &json!({}))
            .err()
            .unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }

    #[test]
    fn get_next_scenario_returns_ready() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let wid = start_workflow(&s, &arn);
        let resp = get_next_scenario(&s, &req(), &arn, &wid).unwrap();
        let v: Value =
            serde_json::from_str(std::str::from_utf8(resp.body.expect_bytes()).unwrap()).unwrap();
        assert_eq!(v["status"], "Ready");
        assert_eq!(v["workflowId"], wid);
    }

    #[test]
    fn get_next_scenario_unknown_workflow_not_found() {
        let s = shared();
        let arn = seed_policy(&s, "p");
        let err = get_next_scenario(&s, &req(), &arn, "miss").err().unwrap();
        assert_eq!(err.status(), StatusCode::NOT_FOUND);
    }
}
