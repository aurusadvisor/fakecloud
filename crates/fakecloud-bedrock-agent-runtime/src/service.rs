use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use http::{Method, StatusCode};
use serde_json::{json, Value};

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};

use crate::state::{InvocationRecord, SharedBedrockAgentRuntimeState};

const SUPPORTED_ACTIONS: &[&str] = &[
    "InvokeAgent",
    "InvokeFlow",
    "InvokeInlineAgent",
    "OptimizePrompt",
    "Retrieve",
    "RetrieveAndGenerate",
    "RetrieveAndGenerateStream",
    "CreateSession",
    "DeleteSession",
    "EndSession",
    "GetSession",
    "ListSessions",
    "UpdateSession",
    "CreateInvocation",
    "GetInvocationStep",
    "ListInvocationSteps",
    "ListInvocations",
    "PutInvocationStep",
    "GetFlowExecution",
    "ListFlowExecutionEvents",
    "ListFlowExecutions",
    "StartFlowExecution",
    "StopFlowExecution",
    "GetExecutionFlowSnapshot",
    "GenerateQuery",
    "Rerank",
    "DeleteAgentMemory",
    "GetAgentMemory",
    "TagResource",
    "UntagResource",
    "ListTagsForResource",
];

pub struct BedrockAgentRuntimeService {
    state: SharedBedrockAgentRuntimeState,
    agent_state: Option<fakecloud_bedrock_agent::SharedBedrockAgentState>,
}

impl BedrockAgentRuntimeService {
    pub fn new(state: SharedBedrockAgentRuntimeState) -> Self {
        Self {
            state,
            agent_state: None,
        }
    }

    pub fn with_agent_state(
        mut self,
        agent_state: fakecloud_bedrock_agent::SharedBedrockAgentState,
    ) -> Self {
        self.agent_state = Some(agent_state);
        self
    }

    pub fn shared_state(&self) -> SharedBedrockAgentRuntimeState {
        Arc::clone(&self.state)
    }

    fn resolve_action(req: &AwsRequest) -> Option<(&'static str, Vec<(String, String)>)> {
        let segs = &req.path_segments;
        if segs.is_empty() {
            return None;
        }

        let m = &req.method;
        let mut params = Vec::new();

        // InvokeAgent: POST /agents/{agentId}/agentAliases/{agentAliasId}/...
        if segs.len() >= 4 && segs[0] == "agents" && segs[2] == "agentAliases" && *m == Method::POST
        {
            params.push(("agentId".to_string(), segs[1].clone()));
            params.push(("agentAliasId".to_string(), segs[3].clone()));
            return Some(("InvokeAgent", params));
        }

        // InvokeFlow: POST /flows/{flowIdentifier}/aliases/{flowAliasIdentifier}
        if segs.len() == 4 && segs[0] == "flows" && segs[2] == "aliases" && *m == Method::POST {
            params.push(("flowIdentifier".to_string(), segs[1].clone()));
            params.push(("flowAliasIdentifier".to_string(), segs[3].clone()));
            return Some(("InvokeFlow", params));
        }

        // InvokeInlineAgent: POST /agents/{agentId}
        if segs.len() == 2 && segs[0] == "agents" && *m == Method::POST {
            params.push(("agentId".to_string(), segs[1].clone()));
            return Some(("InvokeInlineAgent", params));
        }

        // OptimizePrompt: POST /optimize-prompt
        if segs.len() == 1 && segs[0] == "optimize-prompt" && *m == Method::POST {
            return Some(("OptimizePrompt", params));
        }

        // Retrieve: POST /knowledgebases/{knowledgeBaseId}/retrieve
        if segs.len() == 3
            && segs[0] == "knowledgebases"
            && segs[2] == "retrieve"
            && *m == Method::POST
        {
            params.push(("knowledgeBaseId".to_string(), segs[1].clone()));
            return Some(("Retrieve", params));
        }

        // RetrieveAndGenerate: POST /retrieveAndGenerate
        if segs.len() == 1 && segs[0] == "retrieveAndGenerate" && *m == Method::POST {
            return Some(("RetrieveAndGenerate", params));
        }

        // RetrieveAndGenerateStream: POST /retrieveAndGenerateStream
        if segs.len() == 1 && segs[0] == "retrieveAndGenerateStream" && *m == Method::POST {
            return Some(("RetrieveAndGenerateStream", params));
        }

        // Sessions
        if segs.len() == 1 && segs[0] == "sessions" && *m == Method::PUT {
            return Some(("CreateSession", params));
        }
        if segs.len() == 1 && segs[0] == "sessions" && *m == Method::POST {
            return Some(("ListSessions", params));
        }
        if segs.len() == 2 && segs[0] == "sessions" {
            params.push(("sessionId".to_string(), segs[1].clone()));
            if *m == Method::GET {
                return Some(("GetSession", params));
            }
            if *m == Method::PUT {
                return Some(("UpdateSession", params));
            }
            if *m == Method::DELETE {
                return Some(("DeleteSession", params));
            }
            if *m == Method::POST {
                return Some(("EndSession", params));
            }
        }

        // Invocations
        if segs.len() == 2 && segs[0] == "invocations" && *m == Method::PUT {
            params.push(("invocationId".to_string(), segs[1].clone()));
            return Some(("CreateInvocation", params));
        }
        if segs.len() == 1 && segs[0] == "invocations" && *m == Method::POST {
            return Some(("ListInvocations", params));
        }
        if segs.len() == 3 && segs[0] == "invocations" && segs[2] == "steps" && *m == Method::PUT {
            params.push(("invocationId".to_string(), segs[1].clone()));
            return Some(("PutInvocationStep", params));
        }
        if segs.len() == 3 && segs[0] == "invocations" && segs[2] == "steps" && *m == Method::POST {
            params.push(("invocationId".to_string(), segs[1].clone()));
            return Some(("ListInvocationSteps", params));
        }
        if segs.len() == 4 && segs[0] == "invocations" && segs[2] == "steps" && *m == Method::GET {
            params.push(("invocationId".to_string(), segs[1].clone()));
            params.push(("stepId".to_string(), segs[3].clone()));
            return Some(("GetInvocationStep", params));
        }

        // Flow executions
        // ListFlowExecutions: GET /flows/{flowIdentifier}/executions
        if segs.len() == 3 && segs[0] == "flows" && segs[2] == "executions" && *m == Method::GET {
            params.push(("flowIdentifier".to_string(), segs[1].clone()));
            return Some(("ListFlowExecutions", params));
        }
        // GetFlowExecution: GET /flows/{flowIdentifier}/aliases/{flowAliasIdentifier}/executions/{executionIdentifier}
        if segs.len() == 6
            && segs[0] == "flows"
            && segs[2] == "aliases"
            && segs[4] == "executions"
            && *m == Method::GET
        {
            params.push(("flowIdentifier".to_string(), segs[1].clone()));
            params.push(("flowAliasIdentifier".to_string(), segs[3].clone()));
            params.push(("executionId".to_string(), segs[5].clone()));
            return Some(("GetFlowExecution", params));
        }
        // StartFlowExecution: POST /flows/{flowIdentifier}/aliases/{flowAliasIdentifier}/executions
        if segs.len() == 5
            && segs[0] == "flows"
            && segs[2] == "aliases"
            && segs[4] == "executions"
            && *m == Method::POST
        {
            params.push(("flowIdentifier".to_string(), segs[1].clone()));
            params.push(("flowAliasIdentifier".to_string(), segs[3].clone()));
            return Some(("StartFlowExecution", params));
        }
        // StopFlowExecution: POST /flows/{flowIdentifier}/aliases/{flowAliasIdentifier}/executions/{executionIdentifier}/stop
        if segs.len() == 7
            && segs[0] == "flows"
            && segs[2] == "aliases"
            && segs[4] == "executions"
            && segs[6] == "stop"
            && *m == Method::POST
        {
            params.push(("flowIdentifier".to_string(), segs[1].clone()));
            params.push(("flowAliasIdentifier".to_string(), segs[3].clone()));
            params.push(("executionId".to_string(), segs[5].clone()));
            return Some(("StopFlowExecution", params));
        }
        // ListFlowExecutionEvents: GET /flows/{flowIdentifier}/aliases/{flowAliasIdentifier}/executions/{executionIdentifier}/events
        if segs.len() == 7
            && segs[0] == "flows"
            && segs[2] == "aliases"
            && segs[4] == "executions"
            && segs[6] == "events"
            && *m == Method::GET
        {
            params.push(("flowIdentifier".to_string(), segs[1].clone()));
            params.push(("flowAliasIdentifier".to_string(), segs[3].clone()));
            params.push(("executionId".to_string(), segs[5].clone()));
            return Some(("ListFlowExecutionEvents", params));
        }
        // GetExecutionFlowSnapshot: GET /flows/{flowIdentifier}/aliases/{flowAliasIdentifier}/executions/{executionIdentifier}/flowsnapshot
        if segs.len() == 7
            && segs[0] == "flows"
            && segs[2] == "aliases"
            && segs[4] == "executions"
            && segs[6] == "flowsnapshot"
            && *m == Method::GET
        {
            params.push(("flowIdentifier".to_string(), segs[1].clone()));
            params.push(("flowAliasIdentifier".to_string(), segs[3].clone()));
            params.push(("executionId".to_string(), segs[5].clone()));
            return Some(("GetExecutionFlowSnapshot", params));
        }

        // GenerateQuery: POST /generate-query
        if segs.len() == 1 && segs[0] == "generate-query" && *m == Method::POST {
            return Some(("GenerateQuery", params));
        }

        // Rerank: POST /rerank
        if segs.len() == 1 && segs[0] == "rerank" && *m == Method::POST {
            return Some(("Rerank", params));
        }

        // Agent memory
        if segs.len() == 3 && segs[0] == "agents" && segs[2] == "memory" && *m == Method::GET {
            params.push(("agentId".to_string(), segs[1].clone()));
            return Some(("GetAgentMemory", params));
        }
        if segs.len() == 3 && segs[0] == "agents" && segs[2] == "memory" && *m == Method::DELETE {
            params.push(("agentId".to_string(), segs[1].clone()));
            return Some(("DeleteAgentMemory", params));
        }

        // Tagging
        if segs.len() == 2 && segs[0] == "tags" && *m == Method::PUT {
            params.push(("resourceArn".to_string(), segs[1].clone()));
            return Some(("TagResource", params));
        }
        if segs.len() == 2 && segs[0] == "tags" && *m == Method::DELETE {
            params.push(("resourceArn".to_string(), segs[1].clone()));
            return Some(("UntagResource", params));
        }
        if segs.len() == 2 && segs[0] == "tags" && *m == Method::GET {
            params.push(("resourceArn".to_string(), segs[1].clone()));
            return Some(("ListTagsForResource", params));
        }

        None
    }
}

fn req_str(body: &Value, key: &str) -> Option<String> {
    body.get(key)
        .and_then(|v| v.as_str())
        .map(|s| s.to_string())
}

fn make_error(status: StatusCode, code: &str, message: &str) -> AwsServiceError {
    AwsServiceError::aws_error(status, code, message)
}

#[async_trait]
impl AwsService for BedrockAgentRuntimeService {
    fn service_name(&self) -> &'static str {
        "bedrock-agent-runtime"
    }

    fn supported_actions(&self) -> &[&'static str] {
        SUPPORTED_ACTIONS
    }

    async fn handle(&self, mut req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let (action, path_params) =
            Self::resolve_action(&req).ok_or_else(|| AwsServiceError::ActionNotImplemented {
                service: "bedrock-agent-runtime".to_string(),
                action: format!("{} {}", req.method, req.raw_path),
            })?;

        req.action = action.to_string();

        let mut body: Value = serde_json::from_slice(&req.body).unwrap_or_default();
        if !path_params.is_empty() {
            if !body.is_object() {
                body = serde_json::Value::Object(serde_json::Map::new());
            }
            for (k, v) in path_params {
                body[k] = serde_json::Value::String(v);
            }
        }

        match action {
            "InvokeAgent" => handle_invoke_agent(self, &req, &body).await,
            "InvokeFlow" => handle_invoke_flow(self, &req, &body).await,
            "InvokeInlineAgent" => handle_invoke_inline_agent(self, &req, &body).await,
            "OptimizePrompt" => handle_optimize_prompt(self, &req, &body).await,
            "Retrieve" => handle_retrieve(self, &req, &body).await,
            "RetrieveAndGenerate" => handle_retrieve_and_generate(self, &req, &body).await,
            "RetrieveAndGenerateStream" => {
                handle_retrieve_and_generate_stream(self, &req, &body).await
            }
            "CreateSession" => handle_create_session(self, &req, &body).await,
            "DeleteSession" => handle_delete_session(self, &req, &body).await,
            "EndSession" => handle_end_session(self, &req, &body).await,
            "GetSession" => handle_get_session(self, &req, &body).await,
            "ListSessions" => handle_list_sessions(self, &req, &body).await,
            "UpdateSession" => handle_update_session(self, &req, &body).await,
            "CreateInvocation" => handle_create_invocation(self, &req, &body).await,
            "GetInvocationStep" => handle_get_invocation_step(self, &req, &body).await,
            "ListInvocationSteps" => handle_list_invocation_steps(self, &req, &body).await,
            "ListInvocations" => handle_list_invocations(self, &req, &body).await,
            "PutInvocationStep" => handle_put_invocation_step(self, &req, &body).await,
            "GetFlowExecution" => handle_get_flow_execution(self, &req, &body).await,
            "ListFlowExecutionEvents" => handle_list_flow_execution_events(self, &req, &body).await,
            "ListFlowExecutions" => handle_list_flow_executions(self, &req, &body).await,
            "StartFlowExecution" => handle_start_flow_execution(self, &req, &body).await,
            "StopFlowExecution" => handle_stop_flow_execution(self, &req, &body).await,
            "GetExecutionFlowSnapshot" => {
                handle_get_execution_flow_snapshot(self, &req, &body).await
            }
            "GenerateQuery" => handle_generate_query(self, &req, &body).await,
            "Rerank" => handle_rerank(self, &req, &body).await,
            "DeleteAgentMemory" => handle_delete_agent_memory(self, &req, &body).await,
            "GetAgentMemory" => handle_get_agent_memory(self, &req, &body).await,
            "TagResource" => handle_tag_resource(self, &req, &body).await,
            "UntagResource" => handle_untag_resource(self, &req, &body).await,
            "ListTagsForResource" => handle_list_tags_for_resource(self, &req, &body).await,
            _ => Err(make_error(
                StatusCode::BAD_REQUEST,
                "ValidationException",
                &format!("Unknown action: {}", action),
            )),
        }
    }
}

// ── Core operation handlers ──────────────────────────────────────────

async fn handle_invoke_agent(
    svc: &BedrockAgentRuntimeService,
    req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let agent_id = req_str(body, "agentId").ok_or_else(|| {
        make_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "agentId is required",
        )
    })?;

    let _agent_alias_id = req_str(body, "agentAliasId").unwrap_or_default();

    let session_id = req_str(body, "sessionId").unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let input_text = req_str(body, "inputText").unwrap_or_default();

    // Look up agent in control-plane state if available
    let agent_name = if let Some(ref agent_state) = svc.agent_state {
        let accounts = agent_state.read();
        if let Some(account) = accounts.accounts.get(&req.account_id) {
            account.agents.get(&agent_id).map(|a| a.agent_name.clone())
        } else {
            None
        }
    } else {
        None
    };

    let agent_name = agent_name.unwrap_or_else(|| "TestAgent".to_string());

    // Generate canned response
    let output = format!("Hello from agent {}. You said: {}", agent_name, input_text);

    // Record invocation
    {
        let mut accts = svc.state.write();
        let s = accts.get_or_create(&req.account_id);
        s.invocations.push(InvocationRecord {
            invocation_id: uuid::Uuid::new_v4().to_string(),
            agent_id: Some(agent_id.clone()),
            flow_id: None,
            input: input_text.clone(),
            output: output.clone(),
            timestamp: Utc::now(),
        });
    }

    // InvokeAgent returns `application/vnd.amazon.eventstream`-framed
    // bytes. We emit a single `chunk` event carrying the canned
    // response. AWS SDK clients deserialize this exactly the same way
    // they do real Bedrock — base64-decoding the `bytes` field of each
    // chunk event back into model output.
    let frame = crate::eventstream::chunk_frame(&output);
    let mut headers = http::HeaderMap::new();
    if let Ok(value) = http::HeaderValue::from_str(&session_id) {
        headers.insert("x-amz-bedrock-agent-session-id", value);
    }
    let _ = json!(null); // keep the macro import alive for other handlers in this module
    Ok(fakecloud_core::service::AwsResponse {
        status: StatusCode::OK,
        content_type: "application/vnd.amazon.eventstream".to_string(),
        body: fakecloud_core::service::ResponseBody::Bytes(frame.into()),
        headers,
    })
}

async fn handle_invoke_flow(
    svc: &BedrockAgentRuntimeService,
    req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let flow_id = req_str(body, "flowIdentifier").ok_or_else(|| {
        make_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "flowIdentifier is required",
        )
    })?;

    let _flow_alias_id = req_str(body, "flowAliasIdentifier").unwrap_or_default();

    let execution_id = uuid::Uuid::new_v4().to_string();
    let input = req_str(body, "input").unwrap_or_default();

    // Record
    {
        let mut accts = svc.state.write();
        let s = accts.get_or_create(&req.account_id);
        s.flow_executions.insert(
            execution_id.clone(),
            crate::state::FlowExecution {
                execution_id: execution_id.clone(),
                flow_id: flow_id.clone(),
                status: "SUCCEEDED".to_string(),
                created_at: Utc::now(),
                updated_at: Utc::now(),
            },
        );
    }

    let document = format!("Flow output for input: {}", input);
    let frame = crate::eventstream::flow_output_frame("StartNode", &document);
    let mut headers = http::HeaderMap::new();
    if let Ok(value) = http::HeaderValue::from_str(&execution_id) {
        headers.insert("x-amz-bedrock-flow-execution-id", value);
    }
    Ok(fakecloud_core::service::AwsResponse {
        status: StatusCode::OK,
        content_type: "application/vnd.amazon.eventstream".to_string(),
        body: fakecloud_core::service::ResponseBody::Bytes(frame.into()),
        headers,
    })
}

async fn handle_invoke_inline_agent(
    _svc: &BedrockAgentRuntimeService,
    _req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let session_id = req_str(body, "sessionId").unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let input_text = req_str(body, "inputText").unwrap_or_default();
    let frame = crate::eventstream::chunk_frame(&format!("Inline agent says: {}", input_text));
    let mut headers = http::HeaderMap::new();
    if let Ok(value) = http::HeaderValue::from_str(&session_id) {
        headers.insert("x-amz-bedrock-agent-session-id", value);
    }
    Ok(fakecloud_core::service::AwsResponse {
        status: StatusCode::OK,
        content_type: "application/vnd.amazon.eventstream".to_string(),
        body: fakecloud_core::service::ResponseBody::Bytes(frame.into()),
        headers,
    })
}

async fn handle_optimize_prompt(
    _svc: &BedrockAgentRuntimeService,
    _req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let prompt_text = req_str(body, "promptText")
        .or_else(|| {
            body.get("prompt")
                .and_then(|p| p.get("promptText"))
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        })
        .unwrap_or_default();

    let optimized = format!("Optimized: {}", prompt_text);

    let response = json!({
        "optimizedPrompt": {
            "optimizedPromptText": optimized,
            "optimizedPromptTemplate": {
                "promptText": optimized,
                "inferenceConfiguration": {
                    "temperature": 0.7,
                    "topP": 0.9,
                    "maxLength": 512
                }
            }
        }
    });

    Ok(AwsResponse::ok_json(response))
}

async fn handle_retrieve(
    _svc: &BedrockAgentRuntimeService,
    _req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let kb_id = req_str(body, "knowledgeBaseId").ok_or_else(|| {
        make_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "knowledgeBaseId is required",
        )
    })?;

    let query = body
        .get("retrievalQuery")
        .and_then(|q| q.get("text"))
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string();

    let response = json!({
        "retrievalResults": [
            {
                "content": {
                    "text": format!("Retrieved result for query '{}' from knowledge base {}", query, kb_id)
                },
                "location": {
                    "type": "S3",
                    "s3Location": {
                        "uri": format!("s3://fakecloud-kb-{}/doc1.txt", kb_id)
                    }
                },
                "score": 0.95
            }
        ]
    });

    Ok(AwsResponse::ok_json(response))
}

async fn handle_retrieve_and_generate(
    _svc: &BedrockAgentRuntimeService,
    _req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let session_id = req_str(body, "sessionId").unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let input = req_str(body, "input").unwrap_or_default();

    let response = json!({
        "sessionId": session_id,
        "output": {
            "text": format!("Generated response for: {}", input)
        },
        "citations": [
            {
                "generatedResponsePart": {
                    "textResponsePart": {
                        "text": format!("Generated response for: {}", input),
                        "span": { "start": 0, "end": 30 }
                    }
                },
                "retrievedReferences": [
                    {
                        "content": {
                            "text": "Reference text from knowledge base"
                        },
                        "location": {
                            "type": "CONFLUENCE",
                            "confluenceLocation": { "url": "https://example.com/doc" }
                        }
                    }
                ]
            }
        ]
    });

    Ok(AwsResponse::ok_json(response))
}

async fn handle_retrieve_and_generate_stream(
    _svc: &BedrockAgentRuntimeService,
    _req: &AwsRequest,
    _body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    // Stub — return an empty stream-like JSON for now
    let response = json!({
        "sessionId": uuid::Uuid::new_v4().to_string(),
        "output": { "text": "" },
        "citations": []
    });
    Ok(AwsResponse::ok_json(response))
}

// ── Session handlers ────────────────────────────────────────────────

async fn handle_create_session(
    svc: &BedrockAgentRuntimeService,
    req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let session_id = req_str(body, "sessionId").unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let now = Utc::now();

    {
        let mut accts = svc.state.write();
        let s = accts.get_or_create(&req.account_id);
        s.sessions.insert(
            session_id.clone(),
            crate::state::Session {
                session_id: session_id.clone(),
                created_at: now,
                updated_at: now,
            },
        );
    }

    let response = json!({
        "sessionId": session_id,
        "createdAt": now.to_rfc3339(),
    });
    Ok(AwsResponse::ok_json(response))
}

async fn handle_delete_session(
    svc: &BedrockAgentRuntimeService,
    req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let session_id = req_str(body, "sessionId").ok_or_else(|| {
        make_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "sessionId is required",
        )
    })?;

    {
        let mut accts = svc.state.write();
        let s = accts.get_or_create(&req.account_id);
        s.sessions.remove(&session_id);
    }

    Ok(AwsResponse::ok_json(json!({})))
}

async fn handle_end_session(
    svc: &BedrockAgentRuntimeService,
    req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let session_id = req_str(body, "sessionId").ok_or_else(|| {
        make_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "sessionId is required",
        )
    })?;

    {
        let mut accts = svc.state.write();
        let s = accts.get_or_create(&req.account_id);
        if let Some(session) = s.sessions.get_mut(&session_id) {
            session.updated_at = Utc::now();
        }
    }

    Ok(AwsResponse::ok_json(json!({})))
}

async fn handle_get_session(
    svc: &BedrockAgentRuntimeService,
    req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let session_id = req_str(body, "sessionId").ok_or_else(|| {
        make_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "sessionId is required",
        )
    })?;

    let accts = svc.state.read();
    let s = accts.accounts.get(&req.account_id).ok_or_else(|| {
        make_error(
            StatusCode::NOT_FOUND,
            "ResourceNotFoundException",
            "Account not found",
        )
    })?;
    let session = s.sessions.get(&session_id).ok_or_else(|| {
        make_error(
            StatusCode::NOT_FOUND,
            "ResourceNotFoundException",
            "Session not found",
        )
    })?;

    let response = json!({
        "sessionId": session.session_id,
        "createdAt": session.created_at.to_rfc3339(),
        "updatedAt": session.updated_at.to_rfc3339(),
    });
    Ok(AwsResponse::ok_json(response))
}

async fn handle_list_sessions(
    svc: &BedrockAgentRuntimeService,
    req: &AwsRequest,
    _body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let accts = svc.state.read();
    let s = accts.accounts.get(&req.account_id);
    let sessions: Vec<Value> = s
        .map(|state| {
            state
                .sessions
                .values()
                .map(|sess| {
                    json!({
                        "sessionId": sess.session_id,
                        "createdAt": sess.created_at.to_rfc3339(),
                        "updatedAt": sess.updated_at.to_rfc3339(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let response = json!({ "sessions": sessions });
    Ok(AwsResponse::ok_json(response))
}

async fn handle_update_session(
    svc: &BedrockAgentRuntimeService,
    req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let session_id = req_str(body, "sessionId").ok_or_else(|| {
        make_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "sessionId is required",
        )
    })?;

    {
        let mut accts = svc.state.write();
        let s = accts.get_or_create(&req.account_id);
        if let Some(session) = s.sessions.get_mut(&session_id) {
            session.updated_at = Utc::now();
        }
    }

    Ok(AwsResponse::ok_json(json!({})))
}

// ── Invocation handlers ─────────────────────────────────────────────

async fn handle_create_invocation(
    svc: &BedrockAgentRuntimeService,
    req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let invocation_id =
        req_str(body, "invocationId").unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    {
        let mut accts = svc.state.write();
        let s = accts.get_or_create(&req.account_id);
        s.invocations.push(InvocationRecord {
            invocation_id: invocation_id.clone(),
            agent_id: req_str(body, "agentId"),
            flow_id: None,
            input: req_str(body, "input").unwrap_or_default(),
            output: String::new(),
            timestamp: Utc::now(),
        });
    }

    let response = json!({ "invocationId": invocation_id });
    Ok(AwsResponse::ok_json(response))
}

async fn handle_get_invocation_step(
    _svc: &BedrockAgentRuntimeService,
    _req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let step_id = req_str(body, "stepId").ok_or_else(|| {
        make_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "stepId is required",
        )
    })?;

    let response = json!({
        "stepId": step_id,
        "stepType": "ACTION_GROUP",
        "status": "COMPLETED",
        "createdAt": Utc::now().to_rfc3339(),
        "updatedAt": Utc::now().to_rfc3339(),
    });
    Ok(AwsResponse::ok_json(response))
}

async fn handle_list_invocation_steps(
    _svc: &BedrockAgentRuntimeService,
    _req: &AwsRequest,
    _body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let response = json!({ "invocationSteps": [] });
    Ok(AwsResponse::ok_json(response))
}

async fn handle_list_invocations(
    svc: &BedrockAgentRuntimeService,
    req: &AwsRequest,
    _body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let accts = svc.state.read();
    let s = accts.accounts.get(&req.account_id);
    let invocations: Vec<Value> = s
        .map(|state| {
            state
                .invocations
                .iter()
                .map(|inv| {
                    json!({
                        "invocationId": inv.invocation_id,
                        "agentId": inv.agent_id,
                        "createdAt": inv.timestamp.to_rfc3339(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let response = json!({ "invocations": invocations });
    Ok(AwsResponse::ok_json(response))
}

async fn handle_put_invocation_step(
    _svc: &BedrockAgentRuntimeService,
    _req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let step_id = req_str(body, "stepId").unwrap_or_else(|| uuid::Uuid::new_v4().to_string());

    let response = json!({
        "stepId": step_id,
        "status": "COMPLETED",
        "createdAt": Utc::now().to_rfc3339(),
        "updatedAt": Utc::now().to_rfc3339(),
    });
    Ok(AwsResponse::ok_json(response))
}

// ── Flow execution handlers ─────────────────────────────────────────

async fn handle_get_flow_execution(
    svc: &BedrockAgentRuntimeService,
    req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let execution_id = req_str(body, "executionId").ok_or_else(|| {
        make_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "executionId is required",
        )
    })?;

    let accts = svc.state.read();
    let s = accts.accounts.get(&req.account_id).ok_or_else(|| {
        make_error(
            StatusCode::NOT_FOUND,
            "ResourceNotFoundException",
            "Account not found",
        )
    })?;
    let exec = s.flow_executions.get(&execution_id).ok_or_else(|| {
        make_error(
            StatusCode::NOT_FOUND,
            "ResourceNotFoundException",
            "Flow execution not found",
        )
    })?;

    let response = json!({
        "executionId": exec.execution_id,
        "flowId": exec.flow_id,
        "status": exec.status,
        "createdAt": exec.created_at.to_rfc3339(),
        "updatedAt": exec.updated_at.to_rfc3339(),
    });
    Ok(AwsResponse::ok_json(response))
}

async fn handle_list_flow_execution_events(
    _svc: &BedrockAgentRuntimeService,
    _req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let _execution_id = req_str(body, "executionId").ok_or_else(|| {
        make_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "executionId is required",
        )
    })?;

    let response = json!({ "events": [] });
    Ok(AwsResponse::ok_json(response))
}

async fn handle_list_flow_executions(
    svc: &BedrockAgentRuntimeService,
    req: &AwsRequest,
    _body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let accts = svc.state.read();
    let s = accts.accounts.get(&req.account_id);
    let executions: Vec<Value> = s
        .map(|state| {
            state
                .flow_executions
                .values()
                .map(|exec| {
                    json!({
                        "executionId": exec.execution_id,
                        "flowId": exec.flow_id,
                        "status": exec.status,
                        "createdAt": exec.created_at.to_rfc3339(),
                        "updatedAt": exec.updated_at.to_rfc3339(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();

    let response = json!({ "executions": executions });
    Ok(AwsResponse::ok_json(response))
}

async fn handle_start_flow_execution(
    svc: &BedrockAgentRuntimeService,
    req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let flow_id = req_str(body, "flowId").unwrap_or_default();
    let execution_id = uuid::Uuid::new_v4().to_string();
    let now = Utc::now();

    {
        let mut accts = svc.state.write();
        let s = accts.get_or_create(&req.account_id);
        s.flow_executions.insert(
            execution_id.clone(),
            crate::state::FlowExecution {
                execution_id: execution_id.clone(),
                flow_id: flow_id.clone(),
                status: "IN_PROGRESS".to_string(),
                created_at: now,
                updated_at: now,
            },
        );
    }

    let response = json!({
        "executionId": execution_id,
        "status": "IN_PROGRESS",
        "createdAt": now.to_rfc3339(),
    });
    Ok(AwsResponse::ok_json(response))
}

async fn handle_stop_flow_execution(
    svc: &BedrockAgentRuntimeService,
    req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let execution_id = req_str(body, "executionId").ok_or_else(|| {
        make_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "executionId is required",
        )
    })?;

    {
        let mut accts = svc.state.write();
        let s = accts.get_or_create(&req.account_id);
        if let Some(exec) = s.flow_executions.get_mut(&execution_id) {
            exec.status = "STOPPED".to_string();
            exec.updated_at = Utc::now();
        }
    }

    let response = json!({ "executionId": execution_id });
    Ok(AwsResponse::ok_json(response))
}

async fn handle_get_execution_flow_snapshot(
    _svc: &BedrockAgentRuntimeService,
    _req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let execution_id = req_str(body, "executionId").ok_or_else(|| {
        make_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "executionId is required",
        )
    })?;

    let response = json!({
        "executionId": execution_id,
        "snapshot": {}
    });
    Ok(AwsResponse::ok_json(response))
}

// ── Other handlers ────────────────────────────────────────────────────

async fn handle_generate_query(
    _svc: &BedrockAgentRuntimeService,
    _req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let input = req_str(body, "input").unwrap_or_default();

    let response = json!({
        "queries": [
            {
                "type": "RETRIEVAL_QUERY",
                "query": input,
            }
        ]
    });
    Ok(AwsResponse::ok_json(response))
}

async fn handle_rerank(
    _svc: &BedrockAgentRuntimeService,
    _req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let sources = body
        .get("sources")
        .and_then(|s| s.as_array())
        .cloned()
        .unwrap_or_default();

    let results: Vec<Value> = sources
        .iter()
        .enumerate()
        .map(|(i, _source)| {
            json!({
                "index": i,
                "relevanceScore": 0.9 - (i as f64 * 0.1),
            })
        })
        .collect();

    let response = json!({ "results": results });
    Ok(AwsResponse::ok_json(response))
}

async fn handle_delete_agent_memory(
    _svc: &BedrockAgentRuntimeService,
    _req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let _agent_id = req_str(body, "agentId").ok_or_else(|| {
        make_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "agentId is required",
        )
    })?;

    Ok(AwsResponse::ok_json(json!({})))
}

async fn handle_get_agent_memory(
    _svc: &BedrockAgentRuntimeService,
    _req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let agent_id = req_str(body, "agentId").ok_or_else(|| {
        make_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "agentId is required",
        )
    })?;

    let response = json!({
        "memoryId": uuid::Uuid::new_v4().to_string(),
        "agentId": agent_id,
        "memoryContents": []
    });
    Ok(AwsResponse::ok_json(response))
}

// ── Tagging handlers ────────────────────────────────────────────────

async fn handle_tag_resource(
    _svc: &BedrockAgentRuntimeService,
    _req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let resource_arn = req_str(body, "resourceArn").ok_or_else(|| {
        make_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "resourceArn is required",
        )
    })?;

    let _tags = body.get("tags").cloned().unwrap_or_default();

    tracing::info!(%resource_arn, "TagResource stub on bedrock-agent-runtime");
    Ok(AwsResponse::ok_json(json!({})))
}

async fn handle_untag_resource(
    _svc: &BedrockAgentRuntimeService,
    req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let resource_arn = req_str(body, "resourceArn").ok_or_else(|| {
        make_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "resourceArn is required",
        )
    })?;

    let _tag_keys = req
        .query_params
        .get("tagKeys")
        .cloned()
        .or_else(|| req_str(body, "tagKeys"))
        .unwrap_or_default();

    tracing::info!(%resource_arn, "UntagResource stub on bedrock-agent-runtime");
    Ok(AwsResponse::ok_json(json!({})))
}

async fn handle_list_tags_for_resource(
    _svc: &BedrockAgentRuntimeService,
    _req: &AwsRequest,
    body: &Value,
) -> Result<AwsResponse, AwsServiceError> {
    let _resource_arn = req_str(body, "resourceArn").ok_or_else(|| {
        make_error(
            StatusCode::BAD_REQUEST,
            "ValidationException",
            "resourceArn is required",
        )
    })?;

    let response = json!({ "tags": {} });
    Ok(AwsResponse::ok_json(response))
}
