use serde::{Deserialize, Serialize};

// ── Health ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct HealthResponse {
    pub status: String,
    pub version: String,
    pub services: Vec<String>,
}

// ── Reset ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetResponse {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResetServiceResponse {
    pub reset: String,
}

// ── RDS ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RdsTag {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RdsInstance {
    pub db_instance_identifier: String,
    pub db_instance_arn: String,
    pub db_instance_class: String,
    pub engine: String,
    pub engine_version: String,
    pub db_instance_status: String,
    pub master_username: String,
    pub db_name: Option<String>,
    pub endpoint_address: String,
    pub port: i32,
    pub allocated_storage: i32,
    pub publicly_accessible: bool,
    pub deletion_protection: bool,
    pub created_at: String,
    pub dbi_resource_id: String,
    pub container_id: String,
    pub host_port: u16,
    pub tags: Vec<RdsTag>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RdsInstancesResponse {
    pub instances: Vec<RdsInstance>,
}

// ── Lambda ──────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LambdaInvocation {
    pub function_arn: String,
    pub payload: String,
    pub source: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LambdaInvocationsResponse {
    pub invocations: Vec<LambdaInvocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WarmContainer {
    pub function_name: String,
    pub runtime: String,
    pub container_id: String,
    pub last_used_secs_ago: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct WarmContainersResponse {
    pub containers: Vec<WarmContainer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvictContainerResponse {
    pub evicted: bool,
}

// ── SES ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SentEmail {
    pub message_id: String,
    pub from: String,
    pub to: Vec<String>,
    #[serde(default)]
    pub cc: Vec<String>,
    #[serde(default)]
    pub bcc: Vec<String>,
    pub subject: Option<String>,
    pub html_body: Option<String>,
    pub text_body: Option<String>,
    pub raw_data: Option<String>,
    pub template_name: Option<String>,
    pub template_data: Option<String>,
    #[serde(default)]
    pub dkim_signature: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SesEmailsResponse {
    pub emails: Vec<SentEmail>,
}

/// Admin payload to flip an identity's `MailFromDomainStatus` for tests.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SesMailFromStatusRequest {
    pub status: String,
}

/// Admin payload to flip the SES account-level `production_access_enabled`
/// flag. fakecloud defaults to `production_access_enabled=true` so users
/// don't have to verify recipients to send mail; flip this to `false` to
/// exercise sandbox-mode semantics (verified-recipient gate, send quotas,
/// etc.).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SesSandboxRequest {
    /// `true` puts the account back into sandbox mode (production access
    /// disabled); `false` re-enables production access.
    pub sandbox: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundEmailRequest {
    pub from: String,
    pub to: Vec<String>,
    pub subject: String,
    pub body: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundActionExecuted {
    pub rule: String,
    pub action_type: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InboundEmailResponse {
    pub message_id: String,
    pub matched_rules: Vec<String>,
    pub actions_executed: Vec<InboundActionExecuted>,
}

// ── SNS ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnsMessage {
    pub message_id: String,
    pub topic_arn: String,
    pub message: String,
    pub subject: Option<String>,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnsMessagesResponse {
    pub messages: Vec<SnsMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnsSmsMessage {
    pub phone_number: String,
    pub message: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SnsSmsResponse {
    pub messages: Vec<SnsSmsMessage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingConfirmation {
    pub subscription_arn: String,
    pub topic_arn: String,
    pub protocol: String,
    pub endpoint: String,
    pub token: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingConfirmationsResponse {
    pub pending_confirmations: Vec<PendingConfirmation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmSubscriptionRequest {
    pub subscription_arn: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmSubscriptionResponse {
    pub confirmed: bool,
}

// ── SQS ─────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SqsMessageInfo {
    pub message_id: String,
    pub body: String,
    pub receive_count: u64,
    pub in_flight: bool,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SqsQueueMessages {
    pub queue_url: String,
    pub queue_name: String,
    pub messages: Vec<SqsMessageInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SqsMessagesResponse {
    pub queues: Vec<SqsQueueMessages>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpirationTickResponse {
    pub expired_messages: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForceDlqResponse {
    pub moved_messages: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetSsmCommandStatusRequest {
    pub account_id: Option<String>,
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SetSsmCommandStatusResponse {
    pub updated: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FailSsmCommandRequest {
    pub account_id: Option<String>,
    /// Optional: target a single invocation. When `None`, every
    /// invocation on the command is flipped to `Failed`.
    pub instance_id: Option<String>,
    /// Optional friendly status detail (e.g. "Script exited with code 7").
    /// Defaults to "Failed".
    pub status_details: Option<String>,
    /// Optional captured stderr to expose via `GetCommandInvocation`.
    pub standard_error_content: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FailSsmCommandResponse {
    pub updated_invocations: usize,
}

/// One emitted parameter-policy event, as recorded by the
/// `/_fakecloud/ssm/parameter-policy-events` admin endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsmParameterPolicyEvent {
    pub parameter_name: String,
    pub parameter_arn: String,
    /// One of `ExpirationRegistered`, `ExpirationNotificationRegistered`,
    /// `NoChangeNotificationRegistered`, `Expiration`,
    /// `ExpirationNotification`, `NoChangeNotification`.
    pub event_type: String,
    pub message: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SsmParameterPolicyEventsResponse {
    pub events: Vec<SsmParameterPolicyEvent>,
}

/// Body shape for `POST /_fakecloud/ssm/sessions/inject`. Drops a fake
/// session record into state without going through StartSession (which
/// returns 501 unless `FAKECLOUD_SSM_SESSION_ECHO=1`). Lets tests assert
/// `DescribeSessions`/`TerminateSession` paths work end-to-end.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InjectSsmSessionRequest {
    pub account_id: Option<String>,
    pub target: String,
    /// Defaults to `Connected`; pass `Terminated` to seed a finished
    /// session.
    pub status: Option<String>,
    /// Defaults to the account-root IAM ARN.
    pub owner: Option<String>,
    pub reason: Option<String>,
    /// Optional explicit session ID. Falls back to the autogenerated
    /// `session-XXXXXXXXXXXX` form when omitted or empty.
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct InjectSsmSessionResponse {
    pub session_id: String,
}

// ── EventBridge ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventBridgeEvent {
    pub event_id: String,
    pub source: String,
    pub detail_type: String,
    pub detail: String,
    pub bus_name: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventBridgeLambdaDelivery {
    pub function_arn: String,
    pub payload: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventBridgeLogDelivery {
    pub log_group_arn: String,
    pub payload: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventBridgeDeliveries {
    pub lambda: Vec<EventBridgeLambdaDelivery>,
    pub logs: Vec<EventBridgeLogDelivery>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventHistoryResponse {
    pub events: Vec<EventBridgeEvent>,
    pub deliveries: EventBridgeDeliveries,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FireRuleRequest {
    pub bus_name: Option<String>,
    pub rule_name: String,
}

// ── RDS aws_lambda extension bridge ─────────────────────────────────

/// Request body for `POST /_fakecloud/rds/lambda-invoke`. The endpoint is
/// the bridge that the PostgreSQL `aws_lambda` extension calls into from
/// inside an RDS DB instance container — it's normally not driven by
/// user code directly.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RdsLambdaInvokeRequest {
    pub function_name: String,
    pub payload: Option<serde_json::Value>,
    pub invocation_type: Option<String>,
    pub region: Option<String>,
}

/// Shape returned by the bridge — mirrors what `aws_lambda.invoke()`
/// returns to SQL callers (RDS/Aurora-compatible).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RdsLambdaInvokeResponse {
    pub status_code: i32,
    pub payload: Option<serde_json::Value>,
    pub executed_version: Option<String>,
    pub log_result: Option<String>,
}

// ── RDS aws_s3 extension bridge ─────────────────────────────────────

/// Request body for `POST /_fakecloud/rds/s3-import`. The endpoint is
/// the bridge that the PostgreSQL `aws_s3` extension calls into to
/// fetch an object from a fakecloud bucket. Body is returned base64
/// encoded so JSON transport stays text-only.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RdsS3ImportRequest {
    pub bucket: String,
    pub key: String,
    pub region: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RdsS3ImportResponse {
    pub bucket: String,
    pub key: String,
    pub body_b64: String,
    pub bytes_processed: i64,
}

/// Request body for `POST /_fakecloud/rds/s3-export`. Bridge equivalent
/// of an S3 PutObject driven from inside the DB container.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RdsS3ExportRequest {
    pub bucket: String,
    pub key: String,
    pub region: Option<String>,
    pub body_b64: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub struct RdsS3ExportResponse {
    pub bucket: String,
    pub key: String,
    pub bytes_uploaded: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FireRuleTarget {
    #[serde(rename = "type")]
    pub target_type: String,
    pub arn: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FireRuleResponse {
    pub targets: Vec<FireRuleTarget>,
}

// ── Scheduler (EventBridge Scheduler) ───────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchedulerSchedule {
    pub account_id: String,
    pub group_name: String,
    pub name: String,
    pub arn: String,
    pub state: String,
    pub schedule_expression: String,
    pub target_arn: String,
    pub last_fired: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SchedulerSchedulesResponse {
    pub schedules: Vec<SchedulerSchedule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FireScheduleResponse {
    pub schedule_arn: String,
    pub target_arn: String,
}

// ── S3 ──────────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct S3Notification {
    pub bucket: String,
    pub key: String,
    pub event_type: String,
    pub timestamp: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct S3NotificationsResponse {
    pub notifications: Vec<S3Notification>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LifecycleTickResponse {
    pub processed_buckets: u64,
    pub expired_objects: u64,
    pub transitioned_objects: u64,
}

// ── DynamoDB ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TtlTickResponse {
    pub expired_items: u64,
}

// ── SecretsManager ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RotationTickResponse {
    pub rotated_secrets: Vec<String>,
}

// ── ElastiCache ─────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElastiCacheCluster {
    pub cache_cluster_id: String,
    pub cache_cluster_status: String,
    pub engine: String,
    pub engine_version: String,
    pub cache_node_type: String,
    pub num_cache_nodes: i32,
    pub replication_group_id: Option<String>,
    pub port: Option<i32>,
    pub host_port: Option<u16>,
    pub container_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElastiCacheClustersResponse {
    pub clusters: Vec<ElastiCacheCluster>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElastiCacheReplicationGroupIntrospection {
    pub replication_group_id: String,
    pub status: String,
    pub description: String,
    pub member_clusters: Vec<String>,
    pub automatic_failover: bool,
    pub multi_az: bool,
    pub engine: String,
    pub engine_version: String,
    pub cache_node_type: String,
    pub num_cache_clusters: i32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElastiCacheReplicationGroupsResponse {
    pub replication_groups: Vec<ElastiCacheReplicationGroupIntrospection>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElastiCacheServerlessCacheIntrospection {
    pub serverless_cache_name: String,
    pub status: String,
    pub engine: String,
    pub engine_version: String,
    pub cache_node_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ElastiCacheServerlessCachesResponse {
    pub serverless_caches: Vec<ElastiCacheServerlessCacheIntrospection>,
}

// ── Step Functions ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StepFunctionsExecution {
    pub execution_arn: String,
    pub state_machine_arn: String,
    pub name: String,
    pub status: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,
    pub start_date: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_date: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct StepFunctionsExecutionsResponse {
    pub executions: Vec<StepFunctionsExecution>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct SfnEnqueueActivityTaskRequest {
    pub activity_arn: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub input: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_seconds: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SfnEnqueueActivityTaskResponse {
    pub task_token: String,
}

// ── Cognito ─────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserConfirmationCodes {
    pub confirmation_code: Option<String>,
    pub attribute_verification_codes: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmationCode {
    pub pool_id: String,
    pub username: String,
    pub code: String,
    #[serde(rename = "type")]
    pub code_type: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attribute: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmationCodesResponse {
    pub codes: Vec<ConfirmationCode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmUserRequest {
    pub user_pool_id: String,
    pub username: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfirmUserResponse {
    pub confirmed: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokenInfo {
    #[serde(rename = "type")]
    pub token_type: String,
    pub username: String,
    pub pool_id: String,
    pub client_id: String,
    pub issued_at: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokensResponse {
    pub tokens: Vec<TokenInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpireTokensRequest {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_pool_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExpireTokensResponse {
    pub expired_tokens: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthEvent {
    pub event_type: String,
    pub username: String,
    pub user_pool_id: String,
    pub client_id: Option<String>,
    pub timestamp: f64,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AuthEventsResponse {
    pub events: Vec<AuthEvent>,
}

// ── API Gateway v2 ──────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiGatewayV2Request {
    pub request_id: String,
    pub api_id: String,
    pub stage: String,
    pub method: String,
    pub path: String,
    pub headers: std::collections::HashMap<String, String>,
    pub query_params: std::collections::HashMap<String, String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
    pub timestamp: String,
    pub status_code: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ApiGatewayV2RequestsResponse {
    pub requests: Vec<ApiGatewayV2Request>,
}

// ── Bedrock ────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BedrockInvocation {
    pub model_id: String,
    pub input: String,
    pub output: String,
    pub timestamp: String,
    /// Error detail for faulted calls, or `None` on success.
    #[serde(default)]
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BedrockInvocationsResponse {
    pub invocations: Vec<BedrockInvocation>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BedrockModelResponseConfig {
    pub status: String,
    pub model_id: String,
}

/// One rule in a per-model response rule list.
///
/// `prompt_contains` is a substring that must appear in the prompt for this
/// rule to match. `None` or an empty string matches any prompt.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BedrockResponseRule {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_contains: Option<String>,
    pub response: String,
}

/// Configuration for a fault to inject on Bedrock runtime calls.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct BedrockFaultRule {
    pub error_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http_status: Option<u16>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub count: Option<u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub operation: Option<String>,
}

/// Server-side view of a queued fault rule.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BedrockFaultRuleState {
    pub error_type: String,
    pub message: String,
    pub http_status: u16,
    pub remaining: u32,
    #[serde(default)]
    pub model_id: Option<String>,
    #[serde(default)]
    pub operation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BedrockFaultsResponse {
    pub faults: Vec<BedrockFaultRuleState>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BedrockStatusResponse {
    pub status: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcrRepository {
    pub repository_name: String,
    pub repository_arn: String,
    pub registry_id: String,
    pub repository_uri: String,
    pub image_tag_mutability: String,
    pub scan_on_push: bool,
    pub created_at: String,
    pub tags: Vec<EcrTag>,
    pub has_policy: bool,
    pub has_lifecycle_policy: bool,
    pub image_count: u64,
    pub layer_count: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcrImage {
    pub repository_name: String,
    pub image_digest: String,
    pub image_tags: Vec<String>,
    pub image_size_in_bytes: u64,
    pub image_manifest_media_type: String,
    pub image_pushed_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcrImagesResponse {
    pub images: Vec<EcrImage>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcrPullThroughRule {
    pub ecr_repository_prefix: String,
    pub upstream_registry_url: String,
    pub upstream_registry: Option<String>,
    pub credential_arn: Option<String>,
    pub custom_role_arn: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcrPullThroughRulesResponse {
    pub rules: Vec<EcrPullThroughRule>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcrTag {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcrRepositoriesResponse {
    pub repositories: Vec<EcrRepository>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcsCluster {
    pub cluster_name: String,
    pub cluster_arn: String,
    pub status: String,
    pub running_tasks_count: i32,
    pub pending_tasks_count: i32,
    pub active_services_count: i32,
    pub registered_container_instances_count: i32,
    pub capacity_providers: Vec<String>,
    pub tags: Vec<EcsTag>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcsTag {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcsClustersResponse {
    pub clusters: Vec<EcsCluster>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcsTaskContainer {
    pub name: String,
    pub image: String,
    pub last_status: String,
    pub exit_code: Option<i64>,
    pub runtime_id: Option<String>,
    pub essential: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcsTask {
    pub task_arn: String,
    pub task_id: String,
    pub cluster_arn: String,
    pub cluster_name: String,
    pub task_definition_arn: String,
    pub family: String,
    pub revision: i32,
    pub last_status: String,
    pub desired_status: String,
    pub launch_type: String,
    pub created_at: String,
    pub started_at: Option<String>,
    pub stopping_at: Option<String>,
    pub stopped_at: Option<String>,
    pub stop_code: Option<String>,
    pub stopped_reason: Option<String>,
    pub containers: Vec<EcsTaskContainer>,
    pub captured_log_bytes: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcsTasksResponse {
    pub tasks: Vec<EcsTask>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcsTaskLogsResponse {
    pub task_arn: String,
    pub logs: String,
    pub last_status: String,
    pub exit_code: Option<i64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct EcsMarkFailedRequest {
    pub exit_code: Option<i64>,
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcsLifecycleEvent {
    pub at: String,
    pub event_type: String,
    pub task_arn: Option<String>,
    pub cluster_arn: Option<String>,
    pub last_status: Option<String>,
    pub detail: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EcsEventsResponse {
    pub events: Vec<EcsLifecycleEvent>,
}

// ── ELBv2 ───────────────────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Elbv2LoadBalancer {
    pub arn: String,
    pub name: String,
    pub dns_name: String,
    pub scheme: String,
    pub vpc_id: String,
    pub state_code: String,
    pub state_reason: Option<String>,
    pub lb_type: String,
    pub ip_address_type: String,
    pub availability_zones: Vec<Elbv2AvailabilityZone>,
    pub security_groups: Vec<String>,
    pub created_time: String,
    pub tags: Vec<Elbv2Tag>,
    /// In-process data plane TCP port for ALBs. `None` for NLB/GWLB
    /// or when the data plane is disabled. Tests connect to
    /// `127.0.0.1:<bound_port>` to reach the routed targets.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bound_port: Option<u16>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Elbv2AvailabilityZone {
    pub zone_name: String,
    pub subnet_id: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Elbv2Tag {
    pub key: String,
    pub value: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Elbv2LoadBalancersResponse {
    pub load_balancers: Vec<Elbv2LoadBalancer>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Elbv2TargetGroup {
    pub arn: String,
    pub name: String,
    pub protocol: Option<String>,
    pub port: Option<i32>,
    pub vpc_id: Option<String>,
    pub target_type: String,
    pub load_balancer_arns: Vec<String>,
    pub targets: Vec<Elbv2Target>,
    pub health_check_protocol: Option<String>,
    pub health_check_port: Option<String>,
    pub health_check_path: Option<String>,
    pub healthy_threshold_count: i32,
    pub unhealthy_threshold_count: i32,
    pub created_time: String,
    pub tags: Vec<Elbv2Tag>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Elbv2Target {
    pub id: String,
    pub port: Option<i32>,
    pub availability_zone: Option<String>,
    pub health_state: String,
    pub health_reason: Option<String>,
    pub health_description: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Elbv2TargetGroupsResponse {
    pub target_groups: Vec<Elbv2TargetGroup>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Elbv2Listener {
    pub arn: String,
    pub load_balancer_arn: String,
    pub port: Option<i32>,
    pub protocol: Option<String>,
    pub ssl_policy: Option<String>,
    pub certificate_arns: Vec<String>,
    pub default_action_type: Option<String>,
    pub default_target_group_arn: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Elbv2ListenersResponse {
    pub listeners: Vec<Elbv2Listener>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Elbv2Rule {
    pub arn: String,
    pub listener_arn: String,
    pub priority: String,
    pub is_default: bool,
    pub condition_fields: Vec<String>,
    pub action_type: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Elbv2RulesResponse {
    pub rules: Vec<Elbv2Rule>,
}

/// Request to bootstrap an IAM admin user in a specific account.
/// Used by `/_fakecloud/iam/create-admin` to solve the multi-account
/// bootstrap problem: there's no per-account root credential, so this
/// endpoint creates a user with full admin access in any account.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAdminRequest {
    pub account_id: String,
    pub user_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAdminResponse {
    pub access_key_id: String,
    pub secret_access_key: String,
    pub account_id: String,
    pub arn: String,
}

/// Body for `POST /_fakecloud/route53/health-checks/{id}/status`. The
/// admin endpoint flips a stored Route 53 health check's reported
/// status (and optionally the last-failure-reason observation) so
/// tests can simulate failover scenarios without a live checker.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Route53HealthCheckStatusRequest {
    /// New status reported by `GetHealthCheckStatus`. One of
    /// `"Success"`, `"Failure"`, `"Timeout"`, `"DnsError"`,
    /// `"InsufficientDataPoints"`, `"Unknown"`.
    pub status: Route53HealthCheckStatusValue,
    /// Optional last-failure observation surfaced by
    /// `GetHealthCheckLastFailureReason` and appended to the
    /// `<Status>` element for failure-flavoured statuses (`Failure`,
    /// `Timeout`, `DnsError`). Ignored when `status` is `Success`,
    /// `InsufficientDataPoints`, or `Unknown`. `None` leaves the prior
    /// value intact.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Discriminator for the admin `status` field. Mirrors the variants of
/// `fakecloud_route53::HealthCheckStatus` without forcing the SDK crate
/// to depend on the route53 crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum Route53HealthCheckStatusValue {
    Success,
    Failure,
    Timeout,
    DnsError,
    InsufficientDataPoints,
    Unknown,
}

/// Response body for `GET /_fakecloud/route53/zones/{id}/dnssec`. Surfaces
/// the deterministic ECDSA P-256 DNSSEC chain-of-trust material for a
/// hosted zone with at least one ACTIVE Key Signing Key. Real Route 53
/// keeps this material inside KMS; fakecloud derives it from the
/// `(zone_id, ksk_name)` pair so persistence reloads, multiple test
/// runs, and verifier code see stable values.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Route53DnssecMaterialResponse {
    /// Hosted zone the material belongs to (without the
    /// `/hostedzone/` prefix).
    pub hosted_zone_id: String,
    /// KSK name used to derive the keypair.
    pub key_signing_key_name: String,
    /// Algorithm number (always `13` for ECDSAP256SHA256).
    pub algorithm: u8,
    /// DNSKEY flags field (always `257` for a KSK).
    pub flags: u16,
    /// Standard DNSKEY key tag (RFC 4034 Appendix B).
    pub key_tag: u16,
    /// DNSKEY public-key wire bytes (`X || Y`, 64 bytes for P-256),
    /// base64-encoded — what would appear in the DNSKEY RDATA.
    pub dnskey_public_key_b64: String,
    /// SHA-256 DS digest hex over the canonical owner name + DNSKEY
    /// RDATA. Equivalent to what the parent zone publishes.
    pub ds_digest_sha256_hex: String,
}

/// Body for `POST /_fakecloud/route53/zones/{id}/dnssec/sign`. Signs an
/// RRset under the zone's first ACTIVE KSK and returns the raw RRSIG
/// fields so tests can verify the signature against
/// `dnskey_public_key_b64` from `Route53DnssecMaterialResponse`.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Route53DnssecSignRequest {
    /// RRset owner name (e.g., `"www.example.com."`). Trailing dot
    /// optional — added if missing.
    pub name: String,
    /// Record type (`"A"`, `"AAAA"`, `"CNAME"`, `"TXT"`, ...).
    #[serde(rename = "type")]
    pub record_type: String,
    /// Original TTL field for the RRSIG.
    pub ttl: u32,
    /// One-or-more RDATA values matching what `ResourceRecord.Value`
    /// would carry on the wire.
    pub rdatas: Vec<String>,
}

/// Response from the DNSSEC sign admin endpoint.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Route53DnssecSignResponse {
    /// Base64-encoded raw `r||s` ECDSA-P256 signature (64 bytes
    /// decoded).
    pub signature_b64: String,
    /// Algorithm number (always `13`).
    pub algorithm: u8,
    /// Key tag of the signing KSK.
    pub key_tag: u16,
    /// Owner name of the signer (the zone name).
    pub signer_name: String,
    /// Unix-time inception (signature validity start).
    pub inception: u32,
    /// Unix-time expiration (signature validity end).
    pub expiration: u32,
    /// Label count for the RRSIG `Labels` field.
    pub labels: u8,
    /// Original TTL echoed back from the request.
    pub original_ttl: u32,
    /// Record type echoed back from the request.
    #[serde(rename = "type")]
    pub rrset_type: String,
}

/// Body for `POST /_fakecloud/acm/certificates/{arn-or-id}/status`. The
/// admin endpoint flips a stored ACM certificate's status (and
/// optionally records a failure reason) so tests can synchronously
/// drive a cert to `ISSUED`, `FAILED`, or `VALIDATION_TIMED_OUT`
/// without waiting on the auto-issue tick.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcmCertificateStatusRequest {
    /// New certificate status. One of `"ISSUED"`, `"FAILED"`,
    /// `"VALIDATION_TIMED_OUT"`. Other ACM statuses are accepted as
    /// raw strings in case callers want to simulate a niche state.
    pub status: String,
    /// Optional failure reason surfaced as `FailureReason` in
    /// `DescribeCertificate`. Ignored when `status = ISSUED`. `None`
    /// leaves the prior value intact.
    #[serde(default)]
    pub reason: Option<String>,
}

/// Body for `POST /_fakecloud/cloudfront/distributions/{id}/status`. The
/// admin endpoint flips a stored CloudFront Distribution's status so
/// tests can synchronously force it into `Deployed` or `InProgress`
/// without waiting on the propagation tick.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CloudFrontDistributionStatusRequest {
    /// New distribution status. Typically `"Deployed"` or `"InProgress"`.
    pub status: String,
}
