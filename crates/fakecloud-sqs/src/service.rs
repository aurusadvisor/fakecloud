use async_trait::async_trait;
use chrono::Utc;
use http::StatusCode;
use md5::Md5;
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

use fakecloud_aws::arn::Arn;
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
use fakecloud_persistence::SnapshotStore;

use crate::state::{
    MessageAttribute, MessageMoveTask, MessageMoveTaskStatus, RedrivePolicy, SharedSqsState,
    SqsMessage, SqsQueue, SqsSnapshot, SqsState, SQS_SNAPSHOT_SCHEMA_VERSION,
};

/// Validate DelaySeconds (0–900) and MaximumMessageSize (1024–1 MiB) if
/// present in the caller-supplied queue attributes. Both match AWS's
/// documented ranges; we return the same error code/message the real
/// service does.
fn validate_create_queue_attributes(
    attrs: &HashMap<String, String>,
) -> Result<(), AwsServiceError> {
    if let Some(ds) = attrs.get("DelaySeconds") {
        match ds.parse::<i64>() {
            Ok(d) if (0..=900).contains(&d) => {}
            _ => {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidAttributeValue",
                    "Invalid value for the parameter DelaySeconds.".to_string(),
                ));
            }
        }
    }

    if let Some(mms) = attrs.get("MaximumMessageSize") {
        if let Ok(size) = mms.parse::<u64>() {
            if !(1024..=1_048_576).contains(&size) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidAttributeValue",
                    "Invalid value for the parameter MaximumMessageSize.",
                ));
            }
        }
    }

    Ok(())
}

/// Names of queue attributes whose stored value is a JSON document.
/// We canonicalize these to compact JSON on write so the round-trip
/// through `GetQueueAttributes` matches what Terraform's `jsonencode`
/// emits — real AWS SQS canonicalizes the same way server-side.
const JSON_VALUED_ATTRS: &[&str] = &["Policy", "RedrivePolicy", "RedriveAllowPolicy"];

/// If the attribute is JSON-valued, parse + re-emit as compact JSON.
/// Otherwise the value is passed through unchanged. Invalid JSON is also
/// passed through; downstream validators reject it with proper errors.
fn canonicalize_json_attr(name: &str, value: String) -> String {
    if !JSON_VALUED_ATTRS.contains(&name) {
        return value;
    }
    match serde_json::from_str::<Value>(&value) {
        Ok(parsed) => serde_json::to_string(&parsed).unwrap_or(value),
        Err(_) => value,
    }
}

/// Parse the JSON stored under the `RedrivePolicy` queue attribute into
/// a typed `RedrivePolicy`. AWS accepts both string and integer encodings
/// of `maxReceiveCount`, so we tolerate both. Returns `None` for any
/// parse failure (the caller treats it as "no redrive policy").
fn parse_redrive_policy(attr_str: &str) -> Option<RedrivePolicy> {
    let rp: Value = serde_json::from_str(attr_str).ok()?;
    let dead_letter_target_arn = rp["deadLetterTargetArn"].as_str()?.to_string();
    let max_receive_count = rp["maxReceiveCount"]
        .as_u64()
        .or_else(|| rp["maxReceiveCount"].as_str()?.parse().ok())?
        as u32;
    Some(RedrivePolicy {
        dead_letter_target_arn,
        max_receive_count,
    })
}

/// Validate FIFO-specific send-message constraints: delay must be 0,
/// MessageGroupId is required, and either MessageDeduplicationId must be
/// supplied or the queue must have ContentBasedDeduplication enabled.
/// No-op for non-FIFO queues.
fn check_fifo_send_constraints(
    queue: &SqsQueue,
    raw_delay: Option<i64>,
    message_group_id: &Option<String>,
    message_dedup_id: &Option<String>,
) -> Result<(), AwsServiceError> {
    if !queue.is_fifo {
        return Ok(());
    }

    let delay = raw_delay.unwrap_or(0);
    if delay != 0 {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterValue",
            format!(
                "Value {delay} for parameter DelaySeconds is invalid. Reason: \
                 The request include parameter that is not valid for this queue type."
            ),
        ));
    }

    if message_group_id.is_none() {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "MissingParameter",
            "The request must contain the parameter MessageGroupId.",
        ));
    }

    if message_dedup_id.is_none()
        && queue
            .attributes
            .get("ContentBasedDeduplication")
            .map(|v| v.as_str())
            != Some("true")
    {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterValue",
            "The queue should either have ContentBasedDeduplication enabled \
             or MessageDeduplicationId provided explicitly",
        ));
    }

    Ok(())
}

/// Per-queue configuration used while processing a SendMessageBatch,
/// read once outside the per-entry loop.
struct BatchSendConfig {
    is_fifo: bool,
    content_based_dedup: bool,
    max_message_size: usize,
    queue_delay: Option<i64>,
    now: chrono::DateTime<Utc>,
}

impl BatchSendConfig {
    fn from_queue(queue: &SqsQueue, now: chrono::DateTime<Utc>) -> Self {
        Self {
            is_fifo: queue.is_fifo,
            content_based_dedup: queue
                .attributes
                .get("ContentBasedDeduplication")
                .map(|v| v.as_str())
                == Some("true"),
            max_message_size: queue
                .attributes
                .get("MaximumMessageSize")
                .and_then(|s| s.parse().ok())
                .unwrap_or(262144),
            queue_delay: queue
                .attributes
                .get("DelaySeconds")
                .and_then(|s| s.parse().ok()),
            now,
        }
    }
}

enum BatchEntryOutcome {
    Success(Value),
    Failure(Value),
}

fn batch_failure(id: &str, code: &str, message: impl Into<String>) -> Value {
    json!({
        "Id": id,
        "SenderFault": true,
        "Code": code,
        "Message": message.into(),
    })
}

/// Process a single SendMessageBatch entry: validate per-entry constraints,
/// enqueue the message, and return either a successful or failed response
/// fragment. Returns `Err` only for errors that AWS signals at the
/// *batch* level (missing MessageGroupId / dedup on FIFO queues).
///
/// `stored_body_override` lets the caller pre-encrypt the message body
/// for SSE-KMS queues without losing the plaintext MD5 the response
/// must return (AWS surfaces the plaintext MD5 even for encrypted
/// queues).
fn process_batch_send_entry(
    queue: &mut SqsQueue,
    entry: &Value,
    cfg: &BatchSendConfig,
    stored_body_override: Option<String>,
) -> Result<BatchEntryOutcome, AwsServiceError> {
    let id = match entry["Id"].as_str() {
        Some(id) => id.to_string(),
        None => {
            return Ok(BatchEntryOutcome::Failure(batch_failure(
                "",
                "MissingParameter",
                "Id is required",
            )))
        }
    };

    let Some(message_body) = entry["MessageBody"].as_str().map(|s| s.to_string()) else {
        return Ok(BatchEntryOutcome::Failure(batch_failure(
            &id,
            "MissingParameter",
            "MessageBody is required",
        )));
    };

    if message_body.len() > cfg.max_message_size {
        return Ok(BatchEntryOutcome::Failure(batch_failure(
            &id,
            "InvalidParameterValue",
            format!(
                "One or more parameters are invalid. Reason: Message must be shorter than {} bytes.",
                cfg.max_message_size
            ),
        )));
    }

    if let Some(d) = val_as_i64(&entry["DelaySeconds"]) {
        if !(0..=900).contains(&d) {
            return Ok(BatchEntryOutcome::Failure(batch_failure(
                &id,
                "InvalidParameterValue",
                format!(
                    "Value {d} for parameter DelaySeconds is invalid. Reason: \
                     Must be between 0 and 900, if provided."
                ),
            )));
        }
    }

    let message_group_id = entry["MessageGroupId"].as_str().map(|s| s.to_string());
    let message_dedup_id = entry["MessageDeduplicationId"]
        .as_str()
        .map(|s| s.to_string());

    if cfg.is_fifo {
        if message_group_id.is_none() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "The request must contain the parameter MessageGroupId.",
            ));
        }
        if message_dedup_id.is_none() && !cfg.content_based_dedup {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                "The queue should either have ContentBasedDeduplication enabled \
                 or MessageDeduplicationId provided explicitly",
            ));
        }
    }

    let delay: i64 = val_as_i64(&entry["DelaySeconds"])
        .or(cfg.queue_delay)
        .unwrap_or(0);
    let visible_at = if delay > 0 {
        Some(cfg.now + chrono::Duration::seconds(delay))
    } else {
        None
    };

    let message_attributes = parse_message_attributes(entry);

    let sequence_number = if cfg.is_fifo {
        let seq = queue.next_sequence_number;
        queue.next_sequence_number += 1;
        Some(seq.to_string())
    } else {
        None
    };

    let md5_of_attrs = if message_attributes.is_empty() {
        None
    } else {
        Some(md5_of_message_attributes(&message_attributes))
    };

    let msg = SqsMessage {
        message_id: uuid::Uuid::new_v4().to_string(),
        receipt_handle: None,
        md5_of_body: md5_hex(&message_body),
        body: stored_body_override.unwrap_or(message_body),
        sent_timestamp: cfg.now.timestamp_millis(),
        attributes: HashMap::new(),
        message_attributes,
        visible_at,
        receive_count: 0,
        message_group_id,
        message_dedup_id,
        created_at: cfg.now,
        sequence_number: sequence_number.clone(),
    };

    let mut entry_resp = json!({
        "Id": id,
        "MessageId": msg.message_id,
        "MD5OfMessageBody": msg.md5_of_body,
    });
    if let Some(seq) = &sequence_number {
        entry_resp["SequenceNumber"] = json!(seq);
    }
    if let Some(md5) = &md5_of_attrs {
        entry_resp["MD5OfMessageAttributes"] = json!(md5);
    }
    queue.messages.push_back(msg);
    Ok(BatchEntryOutcome::Success(entry_resp))
}

/// Verify that the DLQ referenced by `rp` actually exists, and — when
/// the source queue is FIFO — that the DLQ is itself a FIFO queue.
/// Mirrors AWS's constraint that FIFO and standard queues cannot be
/// paired across a redrive boundary.
fn validate_redrive_policy_target(
    state: &SqsState,
    rp: &RedrivePolicy,
    is_fifo: bool,
) -> Result<(), AwsServiceError> {
    let dlq = state
        .queues
        .values()
        .find(|q| q.arn == rp.dead_letter_target_arn);

    let Some(dlq) = dlq else {
        return Err(AwsServiceError::aws_error_with_headers(
            StatusCode::BAD_REQUEST,
            "QueueDoesNotExist",
            format!(
                "Dead letter target does not exist: {}",
                rp.dead_letter_target_arn
            ),
            vec![(
                "x-amzn-query-error".to_string(),
                "AWS.SimpleQueueService.NonExistentQueue;Sender".to_string(),
            )],
        ));
    };

    if is_fifo && !dlq.is_fifo {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterValue",
            "Dead-letter queue must be the same type of queue as the source.",
        ));
    }

    Ok(())
}

pub struct SqsService {
    state: SharedSqsState,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    /// Serializes concurrent snapshot writes so the newest observed
    /// state always wins on disk. Without it, two tasks could race
    /// between read-clone and save, leaving older bytes as the final
    /// on-disk state (P1 in Cubic review).
    snapshot_lock: Arc<AsyncMutex<()>>,
    pub(crate) kms_hook: Option<Arc<dyn fakecloud_core::delivery::KmsHook>>,
    pub(crate) region: String,
}

impl SqsService {
    pub fn new(state: SharedSqsState) -> Self {
        Self {
            state,
            snapshot_store: None,
            snapshot_lock: Arc::new(AsyncMutex::new(())),
            kms_hook: None,
            region: "us-east-1".to_string(),
        }
    }

    pub fn with_snapshot_store(mut self, store: Arc<dyn SnapshotStore>) -> Self {
        self.snapshot_store = Some(store);
        self
    }

    pub fn with_kms_hook(mut self, hook: Arc<dyn fakecloud_core::delivery::KmsHook>) -> Self {
        self.kms_hook = Some(hook);
        self
    }

    pub fn with_region(mut self, region: impl Into<String>) -> Self {
        self.region = region.into();
        self
    }

    /// Encrypt an SQS message body via the configured KMS hook when the
    /// queue has `KmsMasterKeyId` set. Returns the plaintext unchanged
    /// when no hook is wired or the queue isn't encrypted.
    ///
    /// Fail-closed: if the hook errors (key denied, key not found), this
    /// returns `Err` so SendMessage / SendMessageBatch abort with a 500
    /// rather than silently storing plaintext on an "encrypted" queue.
    /// Real AWS surfaces KMS errors back to the caller; fakecloud
    /// matching that behavior is what makes tests catch broken key
    /// policies before they hit prod.
    fn encrypt_message_body(
        &self,
        account_id: &str,
        queue_arn: &str,
        kms_key_id: Option<&str>,
        plaintext: &str,
    ) -> Result<String, AwsServiceError> {
        let Some(hook) = &self.kms_hook else {
            return Ok(plaintext.to_string());
        };
        let Some(key) = kms_key_id.filter(|k| !k.is_empty()) else {
            return Ok(plaintext.to_string());
        };
        let mut ctx = std::collections::HashMap::new();
        ctx.insert("aws:sqs:arn".to_string(), queue_arn.to_string());
        match hook.encrypt(
            account_id,
            &self.region,
            key,
            plaintext.as_bytes(),
            "sqs.amazonaws.com",
            ctx,
        ) {
            Ok(envelope) => Ok(envelope),
            Err(err) => {
                tracing::warn!(queue = %queue_arn, error = %err, "SQS SSE-KMS encrypt failed");
                Err(AwsServiceError::aws_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "KMS.InternalFailureException",
                    format!("Failed to encrypt SQS message via KMS: {err}"),
                ))
            }
        }
    }

    /// Decrypt a stored SQS body via the KMS hook. Caller must gate this
    /// on the queue having `KmsMasterKeyId` set; opaque base64 ciphertext
    /// can't be detected by prefix.
    ///
    /// Fail-closed: a hook error here surfaces as 500
    /// `KMS.InternalFailureException` so callers don't silently see the
    /// raw ciphertext envelope when KMS access is broken.
    fn decrypt_message_body(
        &self,
        account_id: &str,
        queue_arn: &str,
        ciphertext: &str,
    ) -> Result<String, AwsServiceError> {
        let Some(hook) = &self.kms_hook else {
            return Ok(ciphertext.to_string());
        };
        let mut ctx = std::collections::HashMap::new();
        ctx.insert("aws:sqs:arn".to_string(), queue_arn.to_string());
        match hook.decrypt(account_id, ciphertext, "sqs.amazonaws.com", ctx) {
            Ok(bytes) => Ok(String::from_utf8_lossy(&bytes).to_string()),
            Err(err) => {
                tracing::warn!(queue = %queue_arn, error = %err, "SQS SSE-KMS decrypt failed");
                Err(AwsServiceError::aws_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "KMS.InternalFailureException",
                    format!("Failed to decrypt SQS message via KMS: {err}"),
                ))
            }
        }
    }

    /// Persist the current in-memory state as a snapshot. Called after
    /// every successful mutating action. Noop when no store is wired.
    ///
    /// The snapshot lock is held across the clone + serialize + write
    /// sequence so concurrent mutators cannot interleave and leave
    /// stale bytes on disk. Serialization and the blocking write are
    /// offloaded to the blocking pool to keep Tokio worker threads
    /// responsive under write-heavy load.
    async fn save_snapshot(&self) {
        let Some(store) = self.snapshot_store.clone() else {
            return;
        };
        let _guard = self.snapshot_lock.lock().await;
        let snapshot = SqsSnapshot {
            schema_version: SQS_SNAPSHOT_SCHEMA_VERSION,
            accounts: Some(self.state.read().clone()),
            state: None,
        };
        let join = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let bytes = serde_json::to_vec(&snapshot)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            store.save(&bytes)
        })
        .await;
        match join {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(%err, "failed to write sqs snapshot"),
            Err(err) => tracing::error!(%err, "sqs snapshot task panicked"),
        }
    }
}

/// Actions that mutate SQS state. Kept in sync with the dispatch table.
fn is_mutating_action(action: &str) -> bool {
    matches!(
        action,
        "CreateQueue"
            | "DeleteQueue"
            | "SetQueueAttributes"
            | "SendMessage"
            | "SendMessageBatch"
            | "ReceiveMessage"
            | "DeleteMessage"
            | "DeleteMessageBatch"
            | "PurgeQueue"
            | "ChangeMessageVisibility"
            | "ChangeMessageVisibilityBatch"
            | "TagQueue"
            | "UntagQueue"
            | "AddPermission"
            | "RemovePermission"
            | "StartMessageMoveTask"
            | "CancelMessageMoveTask"
    )
}

#[async_trait]
impl AwsService for SqsService {
    fn service_name(&self) -> &str {
        "sqs"
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mutates = is_mutating_action(req.action.as_str());
        let result = match req.action.as_str() {
            "CreateQueue" => self.create_queue(&req),
            "DeleteQueue" => self.delete_queue(&req),
            "ListQueues" => self.list_queues(&req),
            "GetQueueUrl" => self.get_queue_url(&req),
            "GetQueueAttributes" => self.get_queue_attributes(&req),
            "SetQueueAttributes" => self.set_queue_attributes(&req),
            "SendMessage" => self.send_message(&req),
            "SendMessageBatch" => self.send_message_batch(&req),
            "ReceiveMessage" => self.receive_message(&req).await,
            "DeleteMessage" => self.delete_message(&req),
            "DeleteMessageBatch" => self.delete_message_batch(&req),
            "PurgeQueue" => self.purge_queue(&req),
            "ChangeMessageVisibility" => self.change_message_visibility(&req),
            "ChangeMessageVisibilityBatch" => self.change_message_visibility_batch(&req),
            "ListQueueTags" => self.list_queue_tags(&req),
            "TagQueue" => self.tag_queue(&req),
            "UntagQueue" => self.untag_queue(&req),
            "AddPermission" => self.add_permission(&req),
            "RemovePermission" => self.remove_permission(&req),
            "ListDeadLetterSourceQueues" => self.list_dead_letter_source_queues(&req),
            "StartMessageMoveTask" => self.start_message_move_task(&req),
            "CancelMessageMoveTask" => self.cancel_message_move_task(&req),
            "ListMessageMoveTasks" => self.list_message_move_tasks(&req),
            _ => Err(AwsServiceError::action_not_implemented("sqs", &req.action)),
        };
        if mutates && matches!(result.as_ref(), Ok(resp) if resp.status.is_success()) {
            self.save_snapshot().await;
        }
        result
    }

    fn supported_actions(&self) -> &[&str] {
        &[
            "CreateQueue",
            "DeleteQueue",
            "ListQueues",
            "GetQueueUrl",
            "GetQueueAttributes",
            "SetQueueAttributes",
            "SendMessage",
            "SendMessageBatch",
            "ReceiveMessage",
            "DeleteMessage",
            "DeleteMessageBatch",
            "PurgeQueue",
            "ChangeMessageVisibility",
            "ChangeMessageVisibilityBatch",
            "ListQueueTags",
            "TagQueue",
            "UntagQueue",
            "AddPermission",
            "RemovePermission",
            "ListDeadLetterSourceQueues",
            "StartMessageMoveTask",
            "CancelMessageMoveTask",
            "ListMessageMoveTasks",
        ]
    }

    fn iam_enforceable(&self) -> bool {
        true
    }

    /// SQS resources are queue ARNs of the form
    /// `arn:{partition}:sqs:{region}:{account}:{queue-name}`. The queue
    /// name is carried differently depending on the action: queue-targeted
    /// calls pass a `QueueUrl` that we parse to extract the final path
    /// segment; `CreateQueue` and `GetQueueUrl` carry a `QueueName`
    /// parameter instead. Account-level actions (`ListQueues`) target
    /// `*`.
    fn iam_action_for(&self, request: &AwsRequest) -> Option<fakecloud_core::auth::IamAction> {
        static ACTIONS: &[&str] = &[
            "CreateQueue",
            "DeleteQueue",
            "ListQueues",
            "GetQueueUrl",
            "GetQueueAttributes",
            "SetQueueAttributes",
            "SendMessage",
            "SendMessageBatch",
            "ReceiveMessage",
            "DeleteMessage",
            "DeleteMessageBatch",
            "PurgeQueue",
            "ChangeMessageVisibility",
            "ChangeMessageVisibilityBatch",
            "ListQueueTags",
            "TagQueue",
            "UntagQueue",
            "AddPermission",
            "RemovePermission",
            "ListDeadLetterSourceQueues",
            "StartMessageMoveTask",
            "CancelMessageMoveTask",
            "ListMessageMoveTasks",
        ];
        let action = ACTIONS.iter().copied().find(|a| *a == request.action)?;
        let body = parse_body(request);
        let account = request
            .principal
            .as_ref()
            .map(|p| p.account_id.as_str())
            .unwrap_or(request.account_id.as_str());
        let resource = sqs_resource_for(action, account, &request.region, &body);
        Some(fakecloud_core::auth::IamAction {
            service: "sqs",
            action,
            resource,
        })
    }

    fn iam_condition_keys_for(
        &self,
        request: &AwsRequest,
        action: &fakecloud_core::auth::IamAction,
    ) -> std::collections::BTreeMap<String, Vec<String>> {
        let mut out = std::collections::BTreeMap::new();
        if action.action == "SendMessage" {
            let body = parse_body(request);
            let attrs = parse_message_attributes(&body);
            for (name, attr) in &attrs {
                let key = format!("sqs:messageattribute.{name}");
                // String-typed attributes contribute their StringValue.
                // Binary / Number attributes fall back to the data type
                // so the key still shows up for existence-style
                // conditions; evaluators that look for a concrete
                // StringEquals value simply safe-fail on mismatch.
                let value = attr
                    .string_value
                    .clone()
                    .unwrap_or_else(|| attr.data_type.clone());
                out.insert(key, vec![value]);
            }
        }
        out
    }

    fn resource_tags_for(
        &self,
        resource_arn: &str,
    ) -> Option<std::collections::HashMap<String, String>> {
        if resource_arn == "*" {
            return Some(std::collections::HashMap::new());
        }
        // SQS ARN: arn:{partition}:sqs:{region}:{account}:{queue-name}
        let parts: Vec<&str> = resource_arn.split(':').collect();
        if parts.len() < 6 {
            return None;
        }
        let queue_name = parts[5];
        let account_id = parts[4];
        let _accts = self.state.read();
        let state = _accts.get(account_id)?;
        let queue_url = state.name_to_url.get(queue_name)?;
        let queue = state.queues.get(queue_url)?;
        Some(queue.tags.clone())
    }

    fn request_tags_from(
        &self,
        request: &AwsRequest,
        action: &str,
    ) -> Option<std::collections::HashMap<String, String>> {
        match action {
            "CreateQueue" | "TagQueue" => {
                let body = parse_body(request);
                let mut tags = std::collections::HashMap::new();
                // Both CreateQueue and TagQueue send tags as JSON objects
                for field in &["tags", "Tags"] {
                    if let Some(obj) = body[field].as_object() {
                        for (k, v) in obj {
                            if let Some(val) = v.as_str() {
                                tags.insert(k.clone(), val.to_string());
                            }
                        }
                    }
                }
                Some(tags)
            }
            _ => Some(std::collections::HashMap::new()),
        }
    }
}

/// Build the SQS resource ARN for an incoming action. Returns `*` for
/// account-level actions or when the queue can't be identified from the
/// request.
fn sqs_resource_for(action: &str, account: &str, region: &str, body: &Value) -> String {
    let partition = if region.starts_with("cn-") {
        "aws-cn"
    } else if region.starts_with("us-gov-") {
        "aws-us-gov"
    } else {
        "aws"
    };
    let queue_arn = |name: &str| format!("arn:{}:sqs:{}:{}:{}", partition, region, account, name);
    match action {
        "ListQueues" => "*".to_string(),
        "CreateQueue" | "GetQueueUrl" => body
            .get("QueueName")
            .and_then(|v| v.as_str())
            .map(queue_arn)
            .unwrap_or_else(|| "*".to_string()),
        "StartMessageMoveTask" | "ListMessageMoveTasks" => body
            .get("SourceArn")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| "*".to_string()),
        "CancelMessageMoveTask" => "*".to_string(),
        _ => body
            .get("QueueUrl")
            .and_then(|v| v.as_str())
            .and_then(|url| url.rsplit('/').next())
            .map(queue_arn)
            .unwrap_or_else(|| "*".to_string()),
    }
}

/// Background message-move worker. Drains the source queue one message at a
/// time, sleeping `interval` between moves to enforce the requested rate.
/// Updates the matching task's `messages_moved` counter on each move and
/// flips status to `Completed` when the source drains, or `Cancelled` when
/// the cancel flag is set. Exits silently if the source/destination queue
/// or the task itself disappears (e.g. queue deleted while moving).
#[allow(clippy::too_many_arguments)]
async fn run_message_move_task(
    state_handle: SharedSqsState,
    account_id: String,
    region: String,
    task_handle: String,
    source_url: String,
    destination_arn: Option<String>,
    dlq_targets: Vec<String>,
    interval: std::time::Duration,
    cancel_flag: Arc<AtomicBool>,
) {
    enum Step {
        Moved,
        SourceDrained,
        Failed,
    }

    let mut idx: usize = 0;
    loop {
        if cancel_flag.load(Ordering::SeqCst) {
            finalize_move_task(
                &state_handle,
                &account_id,
                &region,
                &task_handle,
                MessageMoveTaskStatus::Cancelled,
            );
            return;
        }

        // Each iteration acquires the write lock for exactly one move and
        // drops it before sleeping or finalizing — `finalize_move_task` also
        // acquires the lock, so we can't hold one when we call it.
        let step: Step = {
            let mut accounts = state_handle.write();
            let state = accounts.get_or_create(&account_id);

            // Source queue must exist (immutable check before any mutation).
            if !state.queues.contains_key(&source_url) {
                drop(accounts);
                finalize_move_task(
                    &state_handle,
                    &account_id,
                    &region,
                    &task_handle,
                    MessageMoveTaskStatus::Failed,
                );
                return;
            }

            // Resolve and verify the target before popping anything off the
            // source — AWS treats the source as the durable copy until the
            // destination commit, so we must never pop a message we can't
            // deliver. If the destination is gone, leave the source untouched
            // and finalize Failed.
            let target_url_opt = if let Some(ref dest_arn) = destination_arn {
                state
                    .queues
                    .values()
                    .find(|q| &q.arn == dest_arn)
                    .map(|q| q.queue_url.clone())
            } else if dlq_targets.is_empty() {
                None
            } else {
                let url = dlq_targets[idx % dlq_targets.len()].clone();
                Some(url)
            };
            match target_url_opt.filter(|u| state.queues.contains_key(u)) {
                None => Step::Failed,
                Some(target_url) => {
                    // Source is guaranteed to exist (checked above); pop one message.
                    let popped = state
                        .queues
                        .get_mut(&source_url)
                        .and_then(|q| q.messages.pop_front());
                    match popped {
                        None => Step::SourceDrained,
                        Some(mut msg) => {
                            msg.visible_at = None;
                            msg.receive_count = 0;
                            match state.queues.get_mut(&target_url) {
                                Some(target_queue) => {
                                    target_queue.messages.push_back(msg);
                                    if destination_arn.is_none() {
                                        idx += 1;
                                    }
                                    if let Some(task) = state
                                        .message_move_tasks
                                        .iter_mut()
                                        .find(|t| t.task_handle == task_handle)
                                    {
                                        task.messages_moved += 1;
                                    }
                                    Step::Moved
                                }
                                None => {
                                    // Target vanished between resolution and
                                    // the get_mut here. Push the message back
                                    // to the source so it isn't lost.
                                    if let Some(source_queue) = state.queues.get_mut(&source_url) {
                                        source_queue.messages.push_front(msg);
                                    }
                                    Step::Failed
                                }
                            }
                        }
                    }
                }
            }
        };

        match step {
            Step::Moved => {
                tokio::time::sleep(interval).await;
            }
            Step::SourceDrained => {
                finalize_move_task(
                    &state_handle,
                    &account_id,
                    &region,
                    &task_handle,
                    MessageMoveTaskStatus::Completed,
                );
                return;
            }
            Step::Failed => {
                finalize_move_task(
                    &state_handle,
                    &account_id,
                    &region,
                    &task_handle,
                    MessageMoveTaskStatus::Failed,
                );
                return;
            }
        }
    }
}

fn finalize_move_task(
    state_handle: &SharedSqsState,
    account_id: &str,
    region: &str,
    task_handle: &str,
    final_status: MessageMoveTaskStatus,
) {
    let _ = region; // currently only used for symmetry with constructor
    let mut accounts = state_handle.write();
    let state = accounts.get_or_create(account_id);
    if let Some(task) = state
        .message_move_tasks
        .iter_mut()
        .find(|t| t.task_handle == task_handle)
    {
        task.status = final_status;
    }
}

/// Parse the request body. SQS supports both JSON protocol (modern SDKs like aws-sdk-rust)
/// and Query protocol (boto3, older SDKs). For Query protocol, params are in query_params.
fn parse_body(req: &AwsRequest) -> Value {
    // Try JSON first
    if let Ok(v) = serde_json::from_slice::<Value>(&req.body) {
        if v.is_object() && !v.as_object().unwrap().is_empty() {
            return v;
        }
    }
    // Fall back to query params (Query protocol / form-encoded)
    if !req.query_params.is_empty() {
        let mut map = serde_json::Map::new();
        for (k, v) in &req.query_params {
            map.insert(k.clone(), Value::String(v.clone()));
        }
        // Handle nested Attribute.N.Name/Value patterns
        let mut attrs = serde_json::Map::new();
        for i in 1..=20 {
            let name_key = format!("Attribute.{i}.Name");
            let value_key = format!("Attribute.{i}.Value");
            if let (Some(name), Some(value)) = (
                req.query_params.get(&name_key),
                req.query_params.get(&value_key),
            ) {
                attrs.insert(name.clone(), Value::String(value.clone()));
            }
        }
        if !attrs.is_empty() {
            map.insert("Attributes".to_string(), Value::Object(attrs));
        }
        // Handle AttributeName.N patterns (used by GetQueueAttributes in query protocol)
        let mut attr_names = Vec::new();
        for i in 1..=20 {
            let key = format!("AttributeName.{i}");
            if let Some(val) = req.query_params.get(&key) {
                attr_names.push(Value::String(val.clone()));
            }
        }
        if !attr_names.is_empty() {
            map.insert("AttributeNames".to_string(), Value::Array(attr_names));
        }
        // Handle batch entry patterns: *Entry.N.Field or *.N.Field
        // e.g. SendMessageBatchRequestEntry.1.Id=foo&SendMessageBatchRequestEntry.1.MessageBody=bar
        // Also: DeleteMessageBatchRequestEntry.1.Id=...&DeleteMessageBatchRequestEntry.1.ReceiptHandle=...
        // Also: ChangeMessageVisibilityBatchRequestEntry.1.Id=...
        let entries = parse_batch_entries(&req.query_params);
        if !entries.is_empty() {
            map.insert("Entries".to_string(), Value::Array(entries));
        }
        return Value::Object(map);
    }
    Value::Object(Default::default())
}

/// Parse batch entry parameters like `SendMessageBatchRequestEntry.1.Id=foo`.
/// Returns a Vec of JSON objects, one per entry index.
fn parse_batch_entries(params: &HashMap<String, String>) -> Vec<Value> {
    use std::collections::BTreeMap;

    // Find all entry-like keys: anything matching *.N.Field pattern
    let mut entries_map: BTreeMap<u32, serde_json::Map<String, Value>> = BTreeMap::new();

    for (key, value) in params {
        // Match patterns like "SomethingEntry.N.Field" or "Entries.member.N.Field"
        let parts: Vec<&str> = key.split('.').collect();
        if parts.len() >= 3 {
            // Try to find the numeric index
            for (i, part) in parts.iter().enumerate() {
                if let Ok(idx) = part.parse::<u32>() {
                    // Everything after the index is the field name
                    let field = parts[i + 1..].join(".");
                    if !field.is_empty() {
                        entries_map
                            .entry(idx)
                            .or_default()
                            .insert(field, Value::String(value.clone()));
                    }
                    break;
                }
            }
        }
    }

    entries_map.into_values().map(Value::Object).collect()
}

/// Extract an i64 from a Value that might be a number or a string (Query protocol sends strings).
fn val_as_i64(v: &Value) -> Option<i64> {
    v.as_i64()
        .or_else(|| v.as_str().and_then(|s| s.parse().ok()))
}

use fakecloud_aws::xml::xml_escape;

const SQS_NS: &str = "http://queue.amazonaws.com/doc/2012-11-05/";

fn xml_wrap(action: &str, inner: &str, request_id: &str) -> String {
    fakecloud_core::query::query_response_xml(action, SQS_NS, inner, request_id)
}

fn xml_metadata_only(action: &str, request_id: &str) -> AwsResponse {
    let xml = fakecloud_core::query::query_metadata_only_xml(action, SQS_NS, request_id);
    AwsResponse::xml(StatusCode::OK, xml)
}

fn sqs_response(action: &str, body: Value, request_id: &str, is_query: bool) -> AwsResponse {
    if !is_query {
        return AwsResponse::ok_json(body);
    }
    let inner = match action {
        "CreateQueue" | "GetQueueUrl" => xml_queue_url_only(&body),
        "ListQueues" => xml_list_queues(&body),
        "SendMessage" => xml_send_message(&body),
        "ReceiveMessage" => xml_receive_message(&body),
        "GetQueueAttributes" => xml_attributes_list(&body),
        "SendMessageBatch" => xml_batch_result(
            &body,
            "SendMessageBatchResultEntry",
            xml_send_message_batch_success,
        ),
        "DeleteMessageBatch" => {
            xml_batch_result(&body, "DeleteMessageBatchResultEntry", xml_id_only_success)
        }
        "ChangeMessageVisibilityBatch" => xml_batch_result(
            &body,
            "ChangeMessageVisibilityBatchResultEntry",
            xml_id_only_success,
        ),
        "ListDeadLetterSourceQueues" => xml_dlq_sources(&body),
        "StartMessageMoveTask" => xml_start_message_move_task(&body),
        "CancelMessageMoveTask" => xml_cancel_message_move_task(&body),
        "ListMessageMoveTasks" => xml_list_message_move_tasks(&body),
        // DeleteQueue, DeleteMessage, PurgeQueue, SetQueueAttributes, ChangeMessageVisibility
        _ => return xml_metadata_only(action, request_id),
    };
    AwsResponse::xml(StatusCode::OK, xml_wrap(action, &inner, request_id))
}

fn xml_queue_url_only(body: &Value) -> String {
    let url = body["QueueUrl"].as_str().unwrap_or("");
    format!("<QueueUrl>{}</QueueUrl>", xml_escape(url))
}

fn xml_list_queues(body: &Value) -> String {
    let mut inner = String::new();
    if let Some(urls) = body["QueueUrls"].as_array() {
        for url in urls {
            if let Some(u) = url.as_str() {
                inner.push_str(&format!("<QueueUrl>{}</QueueUrl>", xml_escape(u)));
            }
        }
    }
    if let Some(token) = body["NextToken"].as_str() {
        inner.push_str(&format!("<NextToken>{}</NextToken>", xml_escape(token)));
    }
    inner
}

fn xml_send_message(body: &Value) -> String {
    let msg_id = body["MessageId"].as_str().unwrap_or("");
    let md5 = body["MD5OfMessageBody"].as_str().unwrap_or("");
    format!(
        "<MessageId>{}</MessageId><MD5OfMessageBody>{}</MD5OfMessageBody>",
        xml_escape(msg_id),
        xml_escape(md5)
    )
}

fn xml_receive_message(body: &Value) -> String {
    let Some(messages) = body["Messages"].as_array() else {
        return String::new();
    };
    let mut inner = String::new();
    for msg in messages {
        inner.push_str("<Message>");
        if let Some(id) = msg["MessageId"].as_str() {
            inner.push_str(&format!("<MessageId>{}</MessageId>", xml_escape(id)));
        }
        if let Some(rh) = msg["ReceiptHandle"].as_str() {
            inner.push_str(&format!(
                "<ReceiptHandle>{}</ReceiptHandle>",
                xml_escape(rh)
            ));
        }
        if let Some(md5) = msg["MD5OfBody"].as_str() {
            inner.push_str(&format!("<MD5OfBody>{}</MD5OfBody>", xml_escape(md5)));
        }
        if let Some(body_str) = msg["Body"].as_str() {
            inner.push_str(&format!("<Body>{}</Body>", xml_escape(body_str)));
        }
        if let Some(attrs) = msg["Attributes"].as_object() {
            for (k, v) in attrs {
                if let Some(val) = v.as_str() {
                    inner.push_str(&format!(
                        "<Attribute><Name>{}</Name><Value>{}</Value></Attribute>",
                        xml_escape(k),
                        xml_escape(val)
                    ));
                }
            }
        }
        if let Some(msg_attrs) = msg["MessageAttributes"].as_object() {
            for (name, attr) in msg_attrs {
                inner.push_str("<MessageAttribute>");
                inner.push_str(&format!("<Name>{}</Name>", xml_escape(name)));
                inner.push_str("<Value>");
                if let Some(dt) = attr["DataType"].as_str() {
                    inner.push_str(&format!("<DataType>{}</DataType>", xml_escape(dt)));
                }
                if let Some(sv) = attr["StringValue"].as_str() {
                    inner.push_str(&format!("<StringValue>{}</StringValue>", xml_escape(sv)));
                }
                inner.push_str("</Value>");
                inner.push_str("</MessageAttribute>");
            }
        }
        inner.push_str("</Message>");
    }
    inner
}

fn xml_attributes_list(body: &Value) -> String {
    let Some(attrs) = body["Attributes"].as_object() else {
        return String::new();
    };
    let mut inner = String::new();
    for (k, v) in attrs {
        let val = v.as_str().unwrap_or("");
        inner.push_str(&format!(
            "<Attribute><Name>{}</Name><Value>{}</Value></Attribute>",
            xml_escape(k),
            xml_escape(val)
        ));
    }
    inner
}

/// Serialize the Successful + Failed arrays for a `*Batch` response, using
/// `success_tag` as the wrapper tag for each successful entry and
/// `success_body` to write the per-entry body. Failed entries always use
/// the shared `BatchResultErrorEntry` shape.
fn xml_batch_result(body: &Value, success_tag: &str, success_body: fn(&Value) -> String) -> String {
    let mut inner = String::new();
    if let Some(successful) = body["Successful"].as_array() {
        for entry in successful {
            inner.push_str(&format!("<{success_tag}>"));
            inner.push_str(&success_body(entry));
            inner.push_str(&format!("</{success_tag}>"));
        }
    }
    if let Some(failed) = body["Failed"].as_array() {
        for entry in failed {
            inner.push_str(&xml_batch_error_entry(entry));
        }
    }
    inner
}

fn xml_id_only_success(entry: &Value) -> String {
    if let Some(id) = entry["Id"].as_str() {
        format!("<Id>{}</Id>", xml_escape(id))
    } else {
        String::new()
    }
}

fn xml_send_message_batch_success(entry: &Value) -> String {
    let mut out = String::new();
    if let Some(id) = entry["Id"].as_str() {
        out.push_str(&format!("<Id>{}</Id>", xml_escape(id)));
    }
    if let Some(msg_id) = entry["MessageId"].as_str() {
        out.push_str(&format!("<MessageId>{}</MessageId>", xml_escape(msg_id)));
    }
    if let Some(md5) = entry["MD5OfMessageBody"].as_str() {
        out.push_str(&format!(
            "<MD5OfMessageBody>{}</MD5OfMessageBody>",
            xml_escape(md5)
        ));
    }
    out
}

fn xml_batch_error_entry(entry: &Value) -> String {
    let mut out = String::from("<BatchResultErrorEntry>");
    if let Some(id) = entry["Id"].as_str() {
        out.push_str(&format!("<Id>{}</Id>", xml_escape(id)));
    }
    if let Some(code) = entry["Code"].as_str() {
        out.push_str(&format!("<Code>{}</Code>", xml_escape(code)));
    }
    if let Some(msg) = entry["Message"].as_str() {
        out.push_str(&format!("<Message>{}</Message>", xml_escape(msg)));
    }
    if let Some(sf) = entry["SenderFault"].as_bool() {
        out.push_str(&format!("<SenderFault>{sf}</SenderFault>"));
    }
    out.push_str("</BatchResultErrorEntry>");
    out
}

fn xml_dlq_sources(body: &Value) -> String {
    let Some(urls) = body["queueUrls"].as_array() else {
        return String::new();
    };
    let mut inner = String::new();
    for url in urls {
        if let Some(u) = url.as_str() {
            inner.push_str(&format!("<QueueUrl>{}</QueueUrl>", xml_escape(u)));
        }
    }
    inner
}

fn xml_start_message_move_task(body: &Value) -> String {
    let handle = body["TaskHandle"].as_str().unwrap_or("");
    format!("<TaskHandle>{}</TaskHandle>", xml_escape(handle))
}

fn xml_cancel_message_move_task(body: &Value) -> String {
    let n = body["ApproximateNumberOfMessagesMoved"]
        .as_u64()
        .unwrap_or(0);
    format!("<ApproximateNumberOfMessagesMoved>{n}</ApproximateNumberOfMessagesMoved>")
}

fn xml_list_message_move_tasks(body: &Value) -> String {
    let Some(results) = body["Results"].as_array() else {
        return String::new();
    };
    let mut inner = String::new();
    for r in results {
        inner.push_str("<ListMessageMoveTasksResultEntry>");
        if let Some(h) = r["TaskHandle"].as_str() {
            inner.push_str(&format!("<TaskHandle>{}</TaskHandle>", xml_escape(h)));
        }
        if let Some(s) = r["Status"].as_str() {
            inner.push_str(&format!("<Status>{}</Status>", xml_escape(s)));
        }
        if let Some(s) = r["SourceArn"].as_str() {
            inner.push_str(&format!("<SourceArn>{}</SourceArn>", xml_escape(s)));
        }
        if let Some(d) = r["DestinationArn"].as_str() {
            inner.push_str(&format!(
                "<DestinationArn>{}</DestinationArn>",
                xml_escape(d)
            ));
        }
        if let Some(m) = r["MaxNumberOfMessagesPerSecond"].as_i64() {
            inner.push_str(&format!(
                "<MaxNumberOfMessagesPerSecond>{m}</MaxNumberOfMessagesPerSecond>"
            ));
        }
        let moved = r["ApproximateNumberOfMessagesMoved"].as_u64().unwrap_or(0);
        inner.push_str(&format!(
            "<ApproximateNumberOfMessagesMoved>{moved}</ApproximateNumberOfMessagesMoved>"
        ));
        if let Some(t) = r["ApproximateNumberOfMessagesToMove"].as_u64() {
            inner.push_str(&format!(
                "<ApproximateNumberOfMessagesToMove>{t}</ApproximateNumberOfMessagesToMove>"
            ));
        }
        if let Some(reason) = r["FailureReason"].as_str() {
            inner.push_str(&format!(
                "<FailureReason>{}</FailureReason>",
                xml_escape(reason)
            ));
        }
        let started = r["StartedTimestamp"].as_i64().unwrap_or(0);
        inner.push_str(&format!("<StartedTimestamp>{started}</StartedTimestamp>"));
        inner.push_str("</ListMessageMoveTasksResultEntry>");
    }
    inner
}

impl SqsService {
    fn create_queue(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let queue_name = body["QueueName"]
            .as_str()
            .ok_or_else(|| missing_param("QueueName"))?
            .to_string();

        let is_fifo = queue_name.ends_with(".fifo");

        // Validate FIFO queue attributes
        if let Some(attrs) = body["Attributes"].as_object() {
            if let Some(fifo_val) = attrs.get("FifoQueue").and_then(|v| v.as_str()) {
                if fifo_val == "true" && !is_fifo {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameterValue",
                        "The queue name must end with the .fifo suffix for a FIFO queue.",
                    ));
                }
            }
        }

        // Validate queue name
        let base_name = if is_fifo {
            queue_name.trim_end_matches(".fifo")
        } else {
            &queue_name
        };
        if !is_valid_queue_name(base_name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                "Can only include alphanumeric characters, hyphens, or underscores. 1 to 80 in length",
            ));
        }

        let mut new_attributes = HashMap::new();
        if let Some(attrs) = body["Attributes"].as_object() {
            for (k, v) in attrs {
                if let Some(s) = v.as_str() {
                    new_attributes.insert(k.trim().to_string(), s.to_string());
                }
            }
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        if let Some(url) = state.name_to_url.get(&queue_name) {
            // Queue exists - check if attributes match
            if let Some(existing) = state.queues.get(url) {
                // If caller passed attributes, check for conflicts
                if !new_attributes.is_empty() {
                    for (k, v) in &new_attributes {
                        if let Some(existing_val) = existing.attributes.get(k.trim()) {
                            // Normalize JSON values for comparison (e.g. RedrivePolicy)
                            let val_matches = if let (Ok(a), Ok(b)) = (
                                serde_json::from_str::<Value>(existing_val),
                                serde_json::from_str::<Value>(v),
                            ) {
                                a == b
                            } else {
                                existing_val == v
                            };
                            if !val_matches {
                                return Err(AwsServiceError::aws_error(
                                    StatusCode::BAD_REQUEST,
                                    "QueueAlreadyExists",
                                    "A queue already exists with the same name and a different value for attribute VisibilityTimeout.",
                                ));
                            }
                        }
                    }
                }
            }
            return Ok(sqs_response(
                "CreateQueue",
                json!({ "QueueUrl": url }),
                &req.request_id,
                req.is_query_protocol,
            ));
        }

        let queue_url = format!("{}/{}/{}", state.endpoint, state.account_id, queue_name);

        let mut attributes = HashMap::new();
        // Default attributes (real AWS SQS defaults).
        attributes.insert("VisibilityTimeout".to_string(), "30".to_string());
        attributes.insert("DelaySeconds".to_string(), "0".to_string());
        attributes.insert("MaximumMessageSize".to_string(), "1048576".to_string());
        attributes.insert("MessageRetentionPeriod".to_string(), "345600".to_string());
        attributes.insert("ReceiveMessageWaitTimeSeconds".to_string(), "0".to_string());
        // Encryption defaults. Since May 2023, real AWS SQS enables SSE-SQS
        // (managed server-side encryption) automatically on every new queue,
        // so `SqsManagedSseEnabled` defaults to "true" when no KMS key is
        // configured. `KmsDataKeyReusePeriodSeconds` always defaults to 300
        // (5 minutes) regardless of which encryption mode is active;
        // Terraform's provider refreshes both on every plan and enforces
        // the default when the resource config doesn't specify one.
        attributes.insert(
            "KmsDataKeyReusePeriodSeconds".to_string(),
            "300".to_string(),
        );
        attributes.insert("SqsManagedSseEnabled".to_string(), "true".to_string());
        if is_fifo {
            attributes.insert("FifoQueue".to_string(), "true".to_string());
            attributes.insert("ContentBasedDeduplication".to_string(), "false".to_string());
            attributes.insert("DeduplicationScope".to_string(), "queue".to_string());
            attributes.insert("FifoThroughputLimit".to_string(), "perQueue".to_string());
        }

        validate_create_queue_attributes(&new_attributes)?;

        // Override with provided attributes (trim keys to handle trailing whitespace).
        // For JSON-valued attributes, canonicalize to compact form so the
        // round-trip through GetQueueAttributes matches what Terraform's
        // `jsonencode` produces. Real AWS SQS does the same canonicalization
        // server-side, and skipping it surfaces as `whitespace changes` drift
        // in the upstream `aws_sqs_queue` acceptance suite.
        for (k, v) in new_attributes {
            let key = k.trim().to_string();
            let value = canonicalize_json_attr(&key, v);
            attributes.insert(key, value);
        }

        // Apply the same SSE-mode mutual-exclusion that SetQueueAttributes
        // does: a KMS key at create time implies SSE-KMS mode, so managed
        // SSE must be disabled. And an explicit `SqsManagedSseEnabled=true`
        // at create time clears any KMS key, matching real AWS behaviour.
        if attributes
            .get("KmsMasterKeyId")
            .is_some_and(|k| !k.is_empty())
        {
            attributes.insert("SqsManagedSseEnabled".to_string(), "false".to_string());
        }
        if attributes.get("SqsManagedSseEnabled").map(String::as_str) == Some("true") {
            attributes.remove("KmsMasterKeyId");
        }

        let redrive_policy = attributes
            .get("RedrivePolicy")
            .and_then(|s| parse_redrive_policy(s));

        if let Some(ref rp) = redrive_policy {
            validate_redrive_policy_target(state, rp, is_fifo)?;
        }

        // RedrivePolicy is already canonicalized to compact JSON above by
        // `canonicalize_json_attr`. We only need the typed `RedrivePolicy`
        // value for runtime DLQ routing decisions; the stored attribute
        // string is what GetQueueAttributes returns and round-trips clean.

        // Parse tags
        let mut tags = HashMap::new();
        if let Some(tags_obj) = body["tags"].as_object() {
            for (k, v) in tags_obj {
                if let Some(s) = v.as_str() {
                    tags.insert(k.clone(), s.to_string());
                }
            }
        }
        // Also check Tags (JSON protocol)
        if let Some(tags_obj) = body["Tags"].as_object() {
            for (k, v) in tags_obj {
                if let Some(s) = v.as_str() {
                    tags.insert(k.clone(), s.to_string());
                }
            }
        }

        let now = Utc::now();
        let created_ts = now.timestamp();

        attributes.insert("CreatedTimestamp".to_string(), created_ts.to_string());
        attributes.insert("LastModifiedTimestamp".to_string(), created_ts.to_string());

        let queue = SqsQueue {
            arn: format!(
                "arn:aws:sqs:{}:{}:{}",
                state.region, state.account_id, queue_name
            ),
            queue_name: queue_name.clone(),
            queue_url: queue_url.clone(),
            created_at: now,
            messages: VecDeque::new(),
            inflight: Vec::new(),
            attributes,
            is_fifo,
            dedup_cache: HashMap::new(),
            redrive_policy,
            tags,
            next_sequence_number: 0,
            permission_labels: Vec::new(),
            receipt_handle_map: HashMap::new(),
        };

        state.name_to_url.insert(queue_name, queue_url.clone());
        state.queues.insert(queue_url.clone(), queue);

        Ok(sqs_response(
            "CreateQueue",
            json!({ "QueueUrl": queue_url }),
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn delete_queue(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let queue_url = body["QueueUrl"]
            .as_str()
            .ok_or_else(|| missing_param("QueueUrl"))?
            .to_string();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let resolved_url = resolve_queue_url(&queue_url, state).ok_or_else(queue_not_found)?;
        let queue = state
            .queues
            .remove(&resolved_url)
            .ok_or_else(queue_not_found)?;
        state.name_to_url.remove(&queue.queue_name);

        Ok(sqs_response(
            "DeleteQueue",
            json!({}),
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn list_queues(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let prefix = body["QueueNamePrefix"].as_str();
        let _accts = self.state.read();
        let _empty = crate::state::SqsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);

        let max_results = body["MaxResults"]
            .as_u64()
            .or_else(|| body["MaxResults"].as_str().and_then(|s| s.parse().ok()))
            .map(|n| n.clamp(1, 1000) as usize)
            .unwrap_or(1000);

        let offset = body["NextToken"]
            .as_str()
            .and_then(|s| s.parse::<usize>().ok())
            .unwrap_or(0);

        let mut all_urls: Vec<String> = state
            .queues
            .values()
            .filter(|q| prefix.map(|p| q.queue_name.starts_with(p)).unwrap_or(true))
            .map(|q| q.queue_url.clone())
            .collect();
        all_urls.sort();

        let total = all_urls.len();
        let page: Vec<String> = all_urls
            .into_iter()
            .skip(offset)
            .take(max_results)
            .collect();
        let next_offset = offset + page.len();

        let mut result = json!({ "QueueUrls": page });
        if next_offset < total {
            result["NextToken"] = json!(next_offset.to_string());
        }

        Ok(sqs_response(
            "ListQueues",
            result,
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn get_queue_url(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let queue_name = body["QueueName"]
            .as_str()
            .ok_or_else(|| missing_param("QueueName"))?;

        let _accts = self.state.read();
        let _empty = crate::state::SqsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);
        let url = state
            .name_to_url
            .get(queue_name)
            .ok_or_else(queue_not_found)?;

        Ok(sqs_response(
            "GetQueueUrl",
            json!({ "QueueUrl": url }),
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn get_queue_attributes(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let queue_url = body["QueueUrl"]
            .as_str()
            .ok_or_else(|| missing_param("QueueUrl"))?;

        let _accts = self.state.read();
        let _empty = crate::state::SqsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);
        let resolved_url = resolve_queue_url(queue_url, state).ok_or_else(queue_not_found)?;
        let queue = state
            .queues
            .get(&resolved_url)
            .ok_or_else(queue_not_found)?;

        // Check what attributes were requested
        let requested_names = body["AttributeNames"]
            .as_array()
            .map(|arr| arr.iter().filter_map(|v| v.as_str()).collect::<Vec<_>>());

        // If no AttributeNames specified, return empty (per AWS behavior for JSON protocol)
        if requested_names.is_none() || requested_names.as_ref().map(|n| n.is_empty()) == Some(true)
        {
            // For query protocol, some clients don't pass AttributeNames and expect empty
            return Ok(sqs_response(
                "GetQueueAttributes",
                json!({}),
                &req.request_id,
                req.is_query_protocol,
            ));
        }

        let names = requested_names.unwrap();
        let want_all = names.contains(&"All");

        // Validate attribute names
        let valid_attrs = [
            "All",
            "Policy",
            "VisibilityTimeout",
            "MaximumMessageSize",
            "MessageRetentionPeriod",
            "ApproximateNumberOfMessages",
            "ApproximateNumberOfMessagesNotVisible",
            "CreatedTimestamp",
            "LastModifiedTimestamp",
            "QueueArn",
            "ApproximateNumberOfMessagesDelayed",
            "DelaySeconds",
            "ReceiveMessageWaitTimeSeconds",
            "RedrivePolicy",
            "FifoQueue",
            "ContentBasedDeduplication",
            "KmsMasterKeyId",
            "KmsDataKeyReusePeriodSeconds",
            "DeduplicationScope",
            "FifoThroughputLimit",
            "RedriveAllowPolicy",
            "SqsManagedSseEnabled",
        ];
        for name in &names {
            if !valid_attrs.contains(name) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidAttributeName",
                    format!("Unknown Attribute {name}."),
                ));
            }
        }

        let now = Utc::now();
        let mut attrs = queue.attributes.clone();
        attrs.insert("QueueArn".to_string(), queue.arn.clone());

        // Count visible messages (not delayed)
        let visible_count = queue
            .messages
            .iter()
            .filter(|m| m.visible_at.map(|v| v <= now).unwrap_or(true))
            .count();
        // Count expired inflight as visible
        let expired_inflight = queue
            .inflight
            .iter()
            .filter(|m| m.visible_at.map(|v| v <= now).unwrap_or(false))
            .count();
        let still_inflight = queue.inflight.len() - expired_inflight;
        attrs.insert(
            "ApproximateNumberOfMessages".to_string(),
            (visible_count + expired_inflight).to_string(),
        );
        attrs.insert(
            "ApproximateNumberOfMessagesNotVisible".to_string(),
            still_inflight.to_string(),
        );
        // Count delayed messages
        let delayed_count = queue
            .messages
            .iter()
            .filter(|m| m.visible_at.map(|v| v > now).unwrap_or(false))
            .count();
        attrs.insert(
            "ApproximateNumberOfMessagesDelayed".to_string(),
            delayed_count.to_string(),
        );

        if !want_all {
            attrs.retain(|k, _| names.contains(&k.as_str()));
        }

        if attrs.is_empty() {
            Ok(sqs_response(
                "GetQueueAttributes",
                json!({}),
                &req.request_id,
                req.is_query_protocol,
            ))
        } else {
            Ok(sqs_response(
                "GetQueueAttributes",
                json!({ "Attributes": attrs }),
                &req.request_id,
                req.is_query_protocol,
            ))
        }
    }

    fn send_message(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        // --- Parse and validate request body WITHOUT holding any lock ---
        let body = parse_body(req);
        let queue_url = body["QueueUrl"]
            .as_str()
            .ok_or_else(|| missing_param("QueueUrl"))?
            .to_string();
        let message_body = body["MessageBody"]
            .as_str()
            .ok_or_else(|| missing_param("MessageBody"))?
            .to_string();

        let message_group_id = body["MessageGroupId"].as_str().map(|s| s.to_string());
        let message_dedup_id = body["MessageDeduplicationId"]
            .as_str()
            .map(|s| s.to_string());

        let message_attributes = parse_message_attributes(&body);
        validate_message_attributes(&message_attributes)?;
        let system_attributes = parse_message_system_attributes(&body);

        // Pre-compute hashes outside the lock to avoid holding it during CPU work
        let md5_of_body = md5_hex(&message_body);
        let md5_of_attrs = if message_attributes.is_empty() {
            None
        } else {
            Some(md5_of_message_attributes(&message_attributes))
        };
        // Validate delay seconds range before acquiring lock
        let raw_delay = val_as_i64(&body["DelaySeconds"]);
        if let Some(d) = raw_delay {
            if !(0..=900).contains(&d) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    format!("Value {d} for parameter DelaySeconds is invalid. Reason: Must be between 0 and 900, if provided."),
                ));
            }
        }

        let request_id = req.request_id.clone();
        let is_query = req.is_query_protocol;

        // --- Acquire write lock ONLY for queue validation + mutation ---
        let (message_id, sequence_number) = {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&req.account_id);
            let resolved_url = resolve_queue_url(&queue_url, state).ok_or_else(queue_not_found)?;
            let queue = state
                .queues
                .get_mut(&resolved_url)
                .ok_or_else(queue_not_found)?;

            check_fifo_send_constraints(queue, raw_delay, &message_group_id, &message_dedup_id)?;

            // FIFO dedup
            let effective_dedup_id = if queue.is_fifo {
                message_dedup_id.clone().or_else(|| {
                    if queue
                        .attributes
                        .get("ContentBasedDeduplication")
                        .map(|v| v.as_str())
                        == Some("true")
                    {
                        Some(sha256_hex(&message_body))
                    } else {
                        None
                    }
                })
            } else {
                None
            };

            if queue.is_fifo {
                if let Some(ref dedup_id) = effective_dedup_id {
                    let now = Utc::now();
                    queue.dedup_cache.retain(|_, expiry| *expiry > now);
                    if queue.dedup_cache.contains_key(dedup_id) {
                        let msg_id = uuid::Uuid::new_v4().to_string();
                        let seq = queue.next_sequence_number;
                        queue.next_sequence_number += 1;
                        let mut resp = json!({
                            "MessageId": msg_id,
                            "MD5OfMessageBody": &md5_of_body,
                            "SequenceNumber": seq.to_string(),
                        });
                        if let Some(ref md5) = md5_of_attrs {
                            resp["MD5OfMessageAttributes"] = json!(md5);
                        }
                        return Ok(sqs_response("SendMessage", resp, &request_id, is_query));
                    }
                    queue
                        .dedup_cache
                        .insert(dedup_id.clone(), now + chrono::Duration::minutes(5));
                }
            }

            // MaximumMessageSize validation
            let max_message_size: usize = queue
                .attributes
                .get("MaximumMessageSize")
                .and_then(|s| s.parse().ok())
                .unwrap_or(262144);
            if message_body.len() > max_message_size {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    format!(
                        "One or more parameters are invalid. Reason: Message must be shorter than {} bytes.",
                        max_message_size
                    ),
                ));
            }

            let delay: i64 = raw_delay
                .or_else(|| {
                    queue
                        .attributes
                        .get("DelaySeconds")
                        .and_then(|s| s.parse().ok())
                })
                .unwrap_or(0);
            let now = Utc::now();
            let visible_at = if delay > 0 {
                Some(now + chrono::Duration::seconds(delay))
            } else {
                None
            };

            let sequence_number = if queue.is_fifo {
                let seq = queue.next_sequence_number;
                queue.next_sequence_number += 1;
                Some(seq.to_string())
            } else {
                None
            };

            // SSE-KMS: encrypt the body via the KMS hook so the in-memory
            // queue holds a fakecloud-kms envelope. md5_of_body keeps the
            // plaintext digest — that's what callers verify against, and
            // matches AWS's behavior of returning the plaintext MD5.
            let kms_key_id = queue
                .attributes
                .get("KmsMasterKeyId")
                .cloned()
                .filter(|s| !s.is_empty());
            let stored_body = self.encrypt_message_body(
                &req.account_id,
                &queue.arn,
                kms_key_id.as_deref(),
                &message_body,
            )?;
            let msg = SqsMessage {
                message_id: uuid::Uuid::new_v4().to_string(),
                receipt_handle: None,
                md5_of_body: md5_of_body.clone(),
                body: stored_body,
                sent_timestamp: now.timestamp_millis(),
                attributes: system_attributes,
                message_attributes,
                visible_at,
                receive_count: 0,
                message_group_id,
                message_dedup_id: effective_dedup_id,
                created_at: now,
                sequence_number: sequence_number.clone(),
            };

            let message_id = msg.message_id.clone();
            queue.messages.push_back(msg);

            (message_id, sequence_number)
        };
        // --- Write lock released, build response ---

        let mut resp = json!({
            "MessageId": message_id,
            "MD5OfMessageBody": md5_of_body,
        });
        if let Some(seq) = &sequence_number {
            resp["SequenceNumber"] = json!(seq);
        }
        if let Some(md5) = &md5_of_attrs {
            resp["MD5OfMessageAttributes"] = json!(md5);
        }

        Ok(sqs_response("SendMessage", resp, &request_id, is_query))
    }

    async fn receive_message(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let queue_url_input = body["QueueUrl"]
            .as_str()
            .ok_or_else(|| missing_param("QueueUrl"))?
            .to_string();

        // Resolve the queue URL (might be a name)
        let queue_url = {
            let _accts = self.state.read();
            let _empty = crate::state::SqsState::new(&req.account_id, &req.region, "");
            let state = _accts.get(&req.account_id).unwrap_or(&_empty);
            resolve_queue_url(&queue_url_input, state).ok_or_else(queue_not_found)?
        };

        let max_messages_raw = val_as_i64(&body["MaxNumberOfMessages"]);
        if let Some(max) = max_messages_raw {
            if !(1..=10).contains(&max) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    format!("Value {max} for parameter MaxNumberOfMessages is invalid. Reason: Must be between 1 and 10, if provided."),
                ));
            }
        }
        let max_messages = max_messages_raw.unwrap_or(1).min(10) as usize;

        let visibility_timeout = val_as_i64(&body["VisibilityTimeout"]);

        let wait_time_raw = val_as_i64(&body["WaitTimeSeconds"]);
        if let Some(wt) = wait_time_raw {
            if !(0..=20).contains(&wt) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    format!("Value {wt} for parameter WaitTimeSeconds is invalid. Reason: Must be between 0 and 20, if provided."),
                ));
            }
        }
        let wait_time_seconds = wait_time_raw.unwrap_or(0).clamp(0, 20) as u64;

        // Parse requested system attributes
        let attribute_names: Option<Vec<String>> = body["AttributeNames"].as_array().map(|arr| {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        });
        // Also check MessageSystemAttributeNames (newer SDK field)
        let sys_attr_names: Option<Vec<String>> =
            body["MessageSystemAttributeNames"].as_array().map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            });
        let requested_sys_attrs = sys_attr_names.or(attribute_names);

        // Parse requested message attributes filter
        let msg_attr_names: Option<Vec<String>> =
            body["MessageAttributeNames"].as_array().map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(String::from))
                    .collect()
            });

        let request_id = req.request_id.clone();
        let is_query = req.is_query_protocol;

        let deadline = if wait_time_seconds > 0 {
            Some(tokio::time::Instant::now() + std::time::Duration::from_secs(wait_time_seconds))
        } else {
            None
        };

        loop {
            let result = self.try_receive_messages(
                &req.account_id,
                &queue_url,
                max_messages,
                visibility_timeout,
            )?;

            if !result.is_empty() || deadline.is_none() {
                return Ok(format_receive_response(
                    &result,
                    &request_id,
                    is_query,
                    requested_sys_attrs.as_deref(),
                    msg_attr_names.as_deref(),
                ));
            }

            let deadline = deadline.unwrap();
            if tokio::time::Instant::now() >= deadline {
                return Ok(format_receive_response(
                    &result,
                    &request_id,
                    is_query,
                    requested_sys_attrs.as_deref(),
                    msg_attr_names.as_deref(),
                ));
            }

            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    fn try_receive_messages(
        &self,
        account_id: &str,
        queue_url: &str,
        max_messages: usize,
        req_visibility_timeout: Option<i64>,
    ) -> Result<Vec<SqsMessage>, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);
        let resolved_url = resolve_queue_url(queue_url, state).ok_or_else(queue_not_found)?;
        let queue = state
            .queues
            .get_mut(&resolved_url)
            .ok_or_else(queue_not_found)?;

        let visibility_timeout: i64 = req_visibility_timeout
            .or_else(|| {
                queue
                    .attributes
                    .get("VisibilityTimeout")
                    .and_then(|s| s.parse().ok())
            })
            .unwrap_or(30);

        let is_fifo = queue.is_fifo;
        let now = Utc::now();

        // MessageRetentionPeriod expiry: remove messages older than the retention period
        let retention_seconds: i64 = queue
            .attributes
            .get("MessageRetentionPeriod")
            .and_then(|s| s.parse().ok())
            .unwrap_or(345600); // default 4 days
        queue
            .messages
            .retain(|m| (now - m.created_at).num_seconds() < retention_seconds);
        queue
            .inflight
            .retain(|m| (now - m.created_at).num_seconds() < retention_seconds);

        // Return expired inflight messages
        let mut returned = Vec::new();
        queue.inflight.retain(|m| {
            if let Some(visible_at) = m.visible_at {
                if visible_at <= now {
                    returned.push(m.clone());
                    return false;
                }
            }
            true
        });
        // For FIFO queues, push returned messages to the FRONT to maintain order
        if is_fifo {
            for mut m in returned.into_iter().rev() {
                m.visible_at = None;
                queue.messages.push_front(m);
            }
        } else {
            for mut m in returned {
                m.visible_at = None;
                queue.messages.push_back(m);
            }
        }

        let redrive_policy = queue.redrive_policy.clone();

        let mut received = Vec::new();
        let mut dlq_messages = Vec::new();

        if is_fifo {
            // FIFO: deliver messages in order, respecting group locking.
            // Groups that already have inflight messages are skipped.
            // Multiple messages from the same group CAN be delivered in one batch.
            let mut remaining = VecDeque::new();

            // Build set of groups that have pre-existing inflight messages
            let inflight_groups: std::collections::HashSet<String> = queue
                .inflight
                .iter()
                .filter_map(|m| m.message_group_id.clone())
                .collect();

            while let Some(mut msg) = queue.messages.pop_front() {
                if let Some(visible_at) = msg.visible_at {
                    if visible_at > now {
                        remaining.push_back(msg);
                        continue;
                    }
                }

                let group = msg.message_group_id.as_deref().unwrap_or("").to_string();

                // Skip groups that already have inflight messages from previous receives
                if inflight_groups.contains(&group) {
                    remaining.push_back(msg);
                    continue;
                }

                if received.len() < max_messages {
                    msg.receive_count += 1;
                    if let Some(ref rp) = redrive_policy {
                        if msg.receive_count > rp.max_receive_count {
                            dlq_messages.push((rp.dead_letter_target_arn.clone(), msg));
                            continue;
                        }
                    }
                    let new_handle = uuid::Uuid::new_v4().to_string();
                    queue
                        .receipt_handle_map
                        .entry(msg.message_id.clone())
                        .or_default()
                        .push(new_handle.clone());
                    msg.receipt_handle = Some(new_handle);
                    msg.visible_at = Some(now + chrono::Duration::seconds(visibility_timeout));
                    received.push(msg);
                } else {
                    remaining.push_back(msg);
                    break;
                }
            }

            while let Some(m) = queue.messages.pop_front() {
                remaining.push_back(m);
            }
            queue.messages = remaining;
        } else {
            // Standard queue with Fair Queues support:
            // When messages have MessageGroupId, prioritize groups with fewer
            // in-flight messages to prevent noisy neighbor starvation.

            // Count in-flight messages per group
            let mut inflight_per_group: HashMap<String, usize> = HashMap::new();
            for m in &queue.inflight {
                if let Some(ref group) = m.message_group_id {
                    *inflight_per_group.entry(group.clone()).or_default() += 1;
                }
            }

            // Collect all visible messages
            let mut visible: Vec<SqsMessage> = Vec::new();
            let mut remaining = VecDeque::new();
            while let Some(msg) = queue.messages.pop_front() {
                if let Some(visible_at) = msg.visible_at {
                    if visible_at > now {
                        remaining.push_back(msg);
                        continue;
                    }
                }
                visible.push(msg);
            }

            // Sort by fairness: messages from groups with fewer in-flight messages come first.
            // Messages without a group ID are treated as having 0 in-flight (highest priority).
            visible.sort_by_key(|m| {
                m.message_group_id
                    .as_ref()
                    .and_then(|g| inflight_per_group.get(g).copied())
                    .unwrap_or(0)
            });

            // Pick up to max_messages from the sorted list
            for mut msg in visible {
                if received.len() < max_messages {
                    msg.receive_count += 1;
                    if let Some(ref rp) = redrive_policy {
                        if msg.receive_count > rp.max_receive_count {
                            dlq_messages.push((rp.dead_letter_target_arn.clone(), msg));
                            continue;
                        }
                    }
                    let new_handle = uuid::Uuid::new_v4().to_string();
                    queue
                        .receipt_handle_map
                        .entry(msg.message_id.clone())
                        .or_default()
                        .push(new_handle.clone());
                    msg.receipt_handle = Some(new_handle);
                    msg.visible_at = Some(now + chrono::Duration::seconds(visibility_timeout));
                    received.push(msg);
                } else {
                    remaining.push_back(msg);
                }
            }

            queue.messages = remaining;
        }

        // SSE-KMS: decrypt the body BEFORE we commit any state changes
        // (inflight push / DLQ move / queue.messages rewrite). A KMS
        // failure here would otherwise leave the queue in a broken state
        // — the message hidden in inflight or moved to DLQ — while the
        // client receives 500 and never sees the body. Real AWS treats
        // KMS failures as a Receive failure that doesn't consume the
        // message; rollback the popped batch by pushing it back onto
        // `queue.messages`.
        let queue_arn = queue.arn.clone();
        let kms_key_id = queue
            .attributes
            .get("KmsMasterKeyId")
            .cloned()
            .filter(|s| !s.is_empty());
        if kms_key_id.is_some() && self.kms_hook.is_some() {
            // Decrypt into a side buffer first; only commit the
            // plaintext bodies back onto `received` once the entire
            // batch decrypts cleanly. Otherwise a partial decrypt would
            // leak plaintext back onto the queue during rollback.
            let mut plaintexts: Vec<String> = Vec::with_capacity(received.len());
            for msg in received.iter() {
                match self.decrypt_message_body(account_id, &queue_arn, &msg.body) {
                    Ok(plain) => plaintexts.push(plain),
                    Err(err) => {
                        // Rollback the popped batch (both would-be-received
                        // and would-be-DLQ messages) onto the front of the
                        // queue with their original ciphertext bodies and
                        // their receive_count restored, so the next receive
                        // can retry once KMS recovers.
                        let mut rollback: VecDeque<SqsMessage> = VecDeque::new();
                        for (_, mut m) in dlq_messages.into_iter() {
                            m.receive_count = m.receive_count.saturating_sub(1);
                            m.visible_at = None;
                            m.receipt_handle = None;
                            rollback.push_back(m);
                        }
                        for mut m in received.into_iter() {
                            m.receive_count = m.receive_count.saturating_sub(1);
                            m.visible_at = None;
                            m.receipt_handle = None;
                            rollback.push_back(m);
                        }
                        for m in rollback.into_iter().rev() {
                            queue.messages.push_front(m);
                        }
                        return Err(err);
                    }
                }
            }
            for (msg, plain) in received.iter_mut().zip(plaintexts) {
                msg.body = plain;
            }
        }

        for msg in &received {
            queue.inflight.push(msg.clone());
        }

        // Move messages to DLQ
        for (dlq_arn, mut msg) in dlq_messages {
            if let Some(dlq) = state.queues.values_mut().find(|q| q.arn == dlq_arn) {
                msg.receipt_handle = None;
                msg.visible_at = None;
                dlq.messages.push_back(msg);
            }
        }

        Ok(received)
    }

    fn delete_message(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let queue_url = body["QueueUrl"]
            .as_str()
            .ok_or_else(|| missing_param("QueueUrl"))?;
        let receipt_handle = body["ReceiptHandle"]
            .as_str()
            .ok_or_else(|| missing_param("ReceiptHandle"))?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let resolved_url = resolve_queue_url(queue_url, state).ok_or_else(queue_not_found)?;
        let queue = state
            .queues
            .get_mut(&resolved_url)
            .ok_or_else(queue_not_found)?;

        // Find the message_id associated with this receipt handle
        let message_id = find_message_id_for_receipt(queue, receipt_handle);

        if let Some(msg_id) = message_id {
            // Delete by message_id (any receipt handle for this message works)
            // Keep the receipt_handle_map entry so subsequent deletes are idempotent
            queue.inflight.retain(|m| m.message_id != msg_id);
            queue.messages.retain(|m| m.message_id != msg_id);
        } else {
            // Receipt handle not found - error
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ReceiptHandleIsInvalid",
                "The input receipt handle is invalid.",
            ));
        }

        Ok(sqs_response(
            "DeleteMessage",
            json!({}),
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn purge_queue(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let queue_url = body["QueueUrl"]
            .as_str()
            .ok_or_else(|| missing_param("QueueUrl"))?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let resolved_url = resolve_queue_url(queue_url, state).ok_or_else(queue_not_found)?;
        let queue = state
            .queues
            .get_mut(&resolved_url)
            .ok_or_else(queue_not_found)?;

        queue.messages.clear();
        queue.inflight.clear();

        Ok(sqs_response(
            "PurgeQueue",
            json!({}),
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn change_message_visibility(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let queue_url = body["QueueUrl"]
            .as_str()
            .ok_or_else(|| missing_param("QueueUrl"))?;
        let receipt_handle = body["ReceiptHandle"]
            .as_str()
            .ok_or_else(|| missing_param("ReceiptHandle"))?;
        let visibility_timeout = val_as_i64(&body["VisibilityTimeout"])
            .ok_or_else(|| missing_param("VisibilityTimeout"))?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let resolved_url = resolve_queue_url(queue_url, state).ok_or_else(queue_not_found)?;
        let queue = state
            .queues
            .get_mut(&resolved_url)
            .ok_or_else(queue_not_found)?;

        let now = Utc::now();

        // Find the message_id associated with this receipt handle
        let message_id = find_message_id_for_receipt(queue, receipt_handle);

        if let Some(msg_id) = message_id {
            let new_visible_at = Some(now + chrono::Duration::seconds(visibility_timeout));
            let mut found = false;

            // Check inflight messages
            for msg in &mut queue.inflight {
                if msg.message_id == msg_id {
                    msg.visible_at = new_visible_at;
                    found = true;
                    break;
                }
            }

            // Also check messages queue (message may have become visible again)
            if !found {
                for msg in &mut queue.messages {
                    if msg.message_id == msg_id {
                        msg.visible_at = new_visible_at;
                        found = true;
                        break;
                    }
                }
            }

            if !found {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ReceiptHandleIsInvalid",
                    "The input receipt handle is invalid.",
                ));
            }
        } else {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ReceiptHandleIsInvalid",
                "The input receipt handle is invalid.",
            ));
        }

        Ok(sqs_response(
            "ChangeMessageVisibility",
            json!({}),
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn change_message_visibility_batch(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let queue_url = body["QueueUrl"]
            .as_str()
            .ok_or_else(|| missing_param("QueueUrl"))?;

        let entries = body["Entries"]
            .as_array()
            .ok_or_else(|| missing_param("Entries"))?
            .clone();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let resolved_url = resolve_queue_url(queue_url, state).ok_or_else(queue_not_found)?;
        let queue = state
            .queues
            .get_mut(&resolved_url)
            .ok_or_else(queue_not_found)?;

        let now = Utc::now();
        let mut successful = Vec::new();
        let mut failed: Vec<Value> = Vec::new();

        for entry in &entries {
            let id = match entry["Id"].as_str() {
                Some(id) => id.to_string(),
                None => continue,
            };
            let receipt_handle = match entry["ReceiptHandle"].as_str() {
                Some(rh) => rh,
                None => {
                    failed.push(json!({
                        "Id": id,
                        "SenderFault": true,
                        "Code": "MissingParameter",
                        "Message": "ReceiptHandle is required",
                    }));
                    continue;
                }
            };
            let visibility_timeout = match val_as_i64(&entry["VisibilityTimeout"]) {
                Some(vt) => vt,
                None => {
                    failed.push(json!({
                        "Id": id,
                        "SenderFault": true,
                        "Code": "MissingParameter",
                        "Message": "VisibilityTimeout is required",
                    }));
                    continue;
                }
            };

            let message_id = find_message_id_for_receipt(queue, receipt_handle);

            if let Some(msg_id) = message_id {
                let new_visible_at = Some(now + chrono::Duration::seconds(visibility_timeout));
                let mut found = false;

                for msg in &mut queue.inflight {
                    if msg.message_id == msg_id {
                        msg.visible_at = new_visible_at;
                        found = true;
                        break;
                    }
                }

                if !found {
                    for msg in &mut queue.messages {
                        if msg.message_id == msg_id {
                            msg.visible_at = new_visible_at;
                            found = true;
                            break;
                        }
                    }
                }

                if found {
                    successful.push(json!({ "Id": id }));
                } else {
                    failed.push(json!({
                        "Id": id,
                        "SenderFault": true,
                        "Code": "ReceiptHandleIsInvalid",
                        "Message": "The input receipt handle is invalid.",
                    }));
                }
            } else {
                failed.push(json!({
                    "Id": id,
                    "SenderFault": true,
                    "Code": "ReceiptHandleIsInvalid",
                    "Message": "The input receipt handle is invalid.",
                }));
            }
        }

        Ok(sqs_response(
            "ChangeMessageVisibilityBatch",
            json!({
                "Successful": successful,
                "Failed": failed,
            }),
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn set_queue_attributes(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let queue_url = body["QueueUrl"]
            .as_str()
            .ok_or_else(|| missing_param("QueueUrl"))?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let resolved_url = resolve_queue_url(queue_url, state).ok_or_else(queue_not_found)?;
        let queue = state
            .queues
            .get_mut(&resolved_url)
            .ok_or_else(queue_not_found)?;

        // Validate DelaySeconds (0–900 inclusive) before applying
        if let Some(attrs) = body["Attributes"].as_object() {
            if let Some(ds) = attrs.get("DelaySeconds").and_then(|v| v.as_str()) {
                if let Ok(d) = ds.parse::<i64>() {
                    if !(0..=900).contains(&d) {
                        return Err(AwsServiceError::aws_error(
                            StatusCode::BAD_REQUEST,
                            "InvalidAttributeValue",
                            "Invalid value for the parameter DelaySeconds.".to_string(),
                        ));
                    }
                }
            }
        }

        if let Some(attrs) = body["Attributes"].as_object() {
            for (k, v) in attrs {
                if let Some(s) = v.as_str() {
                    // Setting an empty value clears an existing value. For
                    // JSON-valued policies and for the KMS master key alias,
                    // "" means "remove" (Terraform's provider sends "" to
                    // switch encryption modes). Other attributes are stored
                    // with their empty string so the round-trip is faithful.
                    let is_clearable = matches!(
                        k.as_str(),
                        "Policy" | "RedrivePolicy" | "RedriveAllowPolicy" | "KmsMasterKeyId"
                    );
                    if s.is_empty() && is_clearable {
                        queue.attributes.remove(k);
                        if k == "RedrivePolicy" {
                            queue.redrive_policy = None;
                        }
                    } else {
                        queue
                            .attributes
                            .insert(k.clone(), canonicalize_json_attr(k, s.to_string()));
                    }
                }
            }

            // Encryption-mode mutual exclusion. Switching *to* SSE-SQS
            // (`SqsManagedSseEnabled=true`) clears the KMS key and resets
            // the reuse period to 300 — real AWS SQS uses a new data key
            // on the managed mode, and the upstream `aws_sqs_queue`
            // provider's refresh expects the default value back.
            // Switching to SSE-KMS (`KmsMasterKeyId` set to non-empty)
            // turns off the managed-SSE flag. A mode switch that doesn't
            // specify `KmsDataKeyReusePeriodSeconds` also resets it to
            // 300, matching real-AWS behaviour.
            let sse_mode_switch =
                attrs.get("SqsManagedSseEnabled").and_then(|v| v.as_str()) == Some("true");
            let kms_key_switch = attrs
                .get("KmsMasterKeyId")
                .and_then(|v| v.as_str())
                .is_some_and(|k| !k.is_empty());
            let reuse_period_explicit = attrs.contains_key("KmsDataKeyReusePeriodSeconds");

            if sse_mode_switch {
                queue.attributes.remove("KmsMasterKeyId");
                if !reuse_period_explicit {
                    queue.attributes.insert(
                        "KmsDataKeyReusePeriodSeconds".to_string(),
                        "300".to_string(),
                    );
                }
            }
            if kms_key_switch {
                queue
                    .attributes
                    .insert("SqsManagedSseEnabled".to_string(), "false".to_string());
            }

            // Update typed redrive_policy used for runtime DLQ routing.
            // The stored attribute string is already canonicalized above.
            if let Some(rp_str) = attrs.get("RedrivePolicy").and_then(|v| v.as_str()) {
                if !rp_str.is_empty() {
                    if let Some(rp) = parse_redrive_policy(rp_str) {
                        queue.redrive_policy = Some(rp);
                    }
                }
            }
        }

        Ok(sqs_response(
            "SetQueueAttributes",
            json!({}),
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn send_message_batch(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let queue_url = body["QueueUrl"]
            .as_str()
            .ok_or_else(|| missing_param("QueueUrl"))?
            .to_string();

        let entries = body["Entries"]
            .as_array()
            .ok_or_else(|| missing_param("Entries"))?
            .clone();

        // Validate batch is not empty
        if entries.is_empty() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "AWS.SimpleQueueService.EmptyBatchRequest",
                "There should be at least one SendMessageBatchRequestEntry in the request.",
            ));
        }

        // Max 10 entries
        if entries.len() > 10 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "AWS.SimpleQueueService.TooManyEntriesInBatchRequest",
                format!(
                    "Maximum number of entries per request are 10. You have sent {}.",
                    entries.len()
                ),
            ));
        }

        // Validate entry IDs and check for duplicates
        let mut seen_ids: Vec<String> = Vec::new();
        for entry in &entries {
            if let Some(id) = entry["Id"].as_str() {
                // Validate ID format
                if !is_valid_batch_id(id) {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "AWS.SimpleQueueService.InvalidBatchEntryId",
                        "A batch entry id can only contain alphanumeric characters, hyphens and underscores. It can be at most 80 letters long.",
                    ));
                }
                if seen_ids.contains(&id.to_string()) {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "AWS.SimpleQueueService.BatchEntryIdsNotDistinct",
                        format!("Id {} repeated.", id),
                    ));
                }
                seen_ids.push(id.to_string());
            }
        }

        // Validate total batch size
        let total_size: usize = entries
            .iter()
            .filter_map(|e| e["MessageBody"].as_str())
            .map(|b| b.len())
            .sum();
        if total_size > 1_048_576 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "AWS.SimpleQueueService.BatchRequestTooLong",
                format!(
                    "Batch requests cannot be longer than 1048576 bytes. You have sent {} bytes.",
                    total_size
                ),
            ));
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let resolved_url = resolve_queue_url(&queue_url, state).ok_or_else(queue_not_found)?;
        let queue = state
            .queues
            .get_mut(&resolved_url)
            .ok_or_else(queue_not_found)?;

        let now = Utc::now();
        let mut successful = Vec::new();
        let mut failed: Vec<Value> = Vec::new();

        let cfg = BatchSendConfig::from_queue(queue, now);

        // SSE-KMS: pre-encrypt every entry's body before handing it to
        // the per-entry helper. Encryption is queue-wide, so a KMS
        // failure here aborts the whole batch (matches AWS behavior:
        // when the queue's CMK is unavailable, no entry can succeed).
        // Skip encryption for entries that won't pass per-entry
        // validation — otherwise an invalid entry would still record a
        // KMS GenerateDataKey call and inflate the audit trail.
        let kms_key_id = queue
            .attributes
            .get("KmsMasterKeyId")
            .cloned()
            .filter(|s| !s.is_empty());
        let queue_arn = queue.arn.clone();
        let mut stored_overrides: Vec<Option<String>> = Vec::with_capacity(entries.len());
        if kms_key_id.is_some() && self.kms_hook.is_some() {
            for entry in &entries {
                let body = entry["MessageBody"].as_str();
                let body_size_ok = body.is_some_and(|b| b.len() <= cfg.max_message_size);
                let id_ok = entry["Id"].as_str().is_some_and(is_valid_batch_id);
                let delay_ok = match val_as_i64(&entry["DelaySeconds"]) {
                    Some(d) => (0..=900).contains(&d),
                    None => true,
                };
                if body_size_ok && id_ok && delay_ok {
                    let stored = self.encrypt_message_body(
                        &req.account_id,
                        &queue_arn,
                        kms_key_id.as_deref(),
                        body.unwrap(),
                    )?;
                    stored_overrides.push(Some(stored));
                } else {
                    stored_overrides.push(None);
                }
            }
        } else {
            stored_overrides.resize(entries.len(), None);
        }

        for (entry, override_body) in entries.iter().zip(stored_overrides) {
            match process_batch_send_entry(queue, entry, &cfg, override_body)? {
                BatchEntryOutcome::Success(v) => successful.push(v),
                BatchEntryOutcome::Failure(v) => failed.push(v),
            }
        }

        Ok(sqs_response(
            "SendMessageBatch",
            json!({
                "Successful": successful,
                "Failed": failed,
            }),
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn delete_message_batch(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let queue_url = body["QueueUrl"]
            .as_str()
            .ok_or_else(|| missing_param("QueueUrl"))?;

        let entries = body["Entries"]
            .as_array()
            .ok_or_else(|| missing_param("Entries"))?
            .clone();

        // Validate batch is not empty
        if entries.is_empty() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "AWS.SimpleQueueService.EmptyBatchRequest",
                "There should be at least one DeleteMessageBatchRequestEntry in the request.",
            ));
        }

        // Check for duplicate IDs
        let mut seen_ids = std::collections::HashSet::new();
        for entry in &entries {
            if let Some(id) = entry["Id"].as_str() {
                if !seen_ids.insert(id.to_string()) {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "AWS.SimpleQueueService.BatchEntryIdsNotDistinct",
                        "Two or more batch entries in the operation have the same Id.",
                    ));
                }
            }
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let resolved_url = resolve_queue_url(queue_url, state).ok_or_else(queue_not_found)?;
        let queue = state
            .queues
            .get_mut(&resolved_url)
            .ok_or_else(queue_not_found)?;

        let mut successful = Vec::new();
        let mut failed: Vec<Value> = Vec::new();

        for entry in &entries {
            let id = match entry["Id"].as_str() {
                Some(id) => id.to_string(),
                None => continue,
            };
            let receipt_handle = match entry["ReceiptHandle"].as_str() {
                Some(rh) => rh,
                None => {
                    failed.push(json!({
                        "Id": id,
                        "SenderFault": true,
                        "Code": "MissingParameter",
                        "Message": "ReceiptHandle is required",
                    }));
                    continue;
                }
            };

            let message_id = find_message_id_for_receipt(queue, receipt_handle);

            if let Some(msg_id) = message_id {
                queue.inflight.retain(|m| m.message_id != msg_id);
                queue.messages.retain(|m| m.message_id != msg_id);
                successful.push(json!({ "Id": id }));
            } else {
                failed.push(json!({
                    "Id": id,
                    "SenderFault": true,
                    "Code": "ReceiptHandleIsInvalid",
                    "Message": format!(
                        "The input receipt handle \"{}\" is not a valid receipt handle.",
                        receipt_handle
                    ),
                }));
            }
        }

        Ok(sqs_response(
            "DeleteMessageBatch",
            json!({
                "Successful": successful,
                "Failed": failed,
            }),
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn list_queue_tags(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let queue_url = body["QueueUrl"]
            .as_str()
            .ok_or_else(|| missing_param("QueueUrl"))?;

        let _accts = self.state.read();
        let _empty = crate::state::SqsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);
        let resolved_url = resolve_queue_url(queue_url, state).ok_or_else(queue_not_found)?;
        let queue = state
            .queues
            .get(&resolved_url)
            .ok_or_else(queue_not_found)?;
        let tags = &queue.tags;

        Ok(sqs_response(
            "ListQueueTags",
            json!({ "Tags": tags }),
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn tag_queue(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let queue_url = body["QueueUrl"]
            .as_str()
            .ok_or_else(|| missing_param("QueueUrl"))?;
        let tags = body["Tags"].as_object();

        // Validate tags are not empty
        if tags.is_none() || tags.map(|t| t.is_empty()) == Some(true) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "The request must contain the parameter Tags.",
            ));
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let resolved_url = resolve_queue_url(queue_url, state).ok_or_else(queue_not_found)?;
        let queue = state
            .queues
            .get_mut(&resolved_url)
            .ok_or_else(queue_not_found)?;

        if let Some(tags_obj) = tags {
            // Check total tag count after adding
            let mut merged = queue.tags.clone();
            for (k, v) in tags_obj {
                if let Some(s) = v.as_str() {
                    merged.insert(k.clone(), s.to_string());
                }
            }
            if merged.len() > 50 {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    format!("Too many tags added for queue {}.", queue.queue_name),
                ));
            }
            queue.tags = merged;
        }

        Ok(sqs_response(
            "TagQueue",
            json!({}),
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn untag_queue(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let queue_url = body["QueueUrl"]
            .as_str()
            .ok_or_else(|| missing_param("QueueUrl"))?;
        let tag_keys = body["TagKeys"].as_array();

        // Validate tag keys are not empty
        if tag_keys.is_none() || tag_keys.map(|t| t.is_empty()) == Some(true) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                "Tag keys must be between 1 and 128 characters in length.",
            ));
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let resolved_url = resolve_queue_url(queue_url, state).ok_or_else(queue_not_found)?;
        let queue = state
            .queues
            .get_mut(&resolved_url)
            .ok_or_else(queue_not_found)?;

        if let Some(keys) = tag_keys {
            for k in keys {
                if let Some(s) = k.as_str() {
                    queue.tags.remove(s);
                }
            }
        }

        Ok(sqs_response(
            "UntagQueue",
            json!({}),
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn add_permission(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let queue_url = body["QueueUrl"]
            .as_str()
            .ok_or_else(|| missing_param("QueueUrl"))?;
        let label = body["Label"]
            .as_str()
            .ok_or_else(|| missing_param("Label"))?;

        // Parse Actions - may come as array or query params
        let actions: Vec<String> = if let Some(arr) = body["Actions"].as_array() {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        } else {
            parse_numbered_params(&body, "ActionName")
        };

        // Parse AWSAccountIds
        let account_ids: Vec<String> = if let Some(arr) = body["AWSAccountIds"].as_array() {
            arr.iter()
                .filter_map(|v| v.as_str().map(String::from))
                .collect()
        } else {
            let mut ids = Vec::new();
            if let Some(obj) = body.as_object() {
                for i in 1..=20 {
                    let key = format!("AWSAccountId.{i}");
                    if let Some(v) = obj.get(&key).and_then(|v| v.as_str()) {
                        ids.push(v.to_string());
                    }
                }
            }
            ids
        };

        // Validate actions not empty
        if actions.is_empty() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "The request must contain the parameter Actions.",
            ));
        }

        // Validate account IDs not empty
        if account_ids.is_empty() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                "Value [] for parameter PrincipalId is invalid. Reason: Unable to verify.",
            ));
        }

        // Validate max 7 actions
        if actions.len() > 7 {
            return Err(AwsServiceError::aws_error(
                StatusCode::FORBIDDEN,
                "OverLimit",
                format!(
                    "{} Actions were found, maximum allowed is 7.",
                    actions.len()
                ),
            ));
        }

        // Validate no owner-only actions
        let owner_only = [
            "AddPermission",
            "RemovePermission",
            "CreateQueue",
            "DeleteQueue",
            "SetQueueAttributes",
            "TagQueue",
            "UntagQueue",
        ];
        for action in &actions {
            if owner_only.contains(&action.as_str()) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    format!(
                        "Value SQS:{action} for parameter ActionName is invalid. Reason: Only the queue owner is allowed to invoke this action."
                    ),
                ));
            }
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let resolved_url = resolve_queue_url(queue_url, state).ok_or_else(queue_not_found)?;
        let queue = state
            .queues
            .get_mut(&resolved_url)
            .ok_or_else(queue_not_found)?;

        // Check for duplicate label
        if queue.permission_labels.contains(&label.to_string()) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                format!("Value {label} for parameter Label is invalid. Reason: Already exists."),
            ));
        }

        queue.permission_labels.push(label.to_string());

        // Build policy
        let mut statements: Vec<Value> = Vec::new();

        // Load existing policy
        if let Some(policy_str) = queue.attributes.get("Policy") {
            if let Ok(policy) = serde_json::from_str::<Value>(policy_str) {
                if let Some(stmts) = policy["Statement"].as_array() {
                    statements = stmts.clone();
                }
            }
        }

        // Add new statement for each account/action pair
        for account_id in &account_ids {
            let action_values: Vec<String> = actions
                .iter()
                .map(|a| {
                    if a == "*" {
                        "SQS:*".to_string()
                    } else {
                        format!("SQS:{a}")
                    }
                })
                .collect();

            let action_value = if action_values.len() == 1 {
                json!(action_values[0])
            } else {
                json!(action_values)
            };

            statements.push(json!({
                "Sid": label,
                "Effect": "Allow",
                "Principal": {
                    "AWS": Arn::global("iam", account_id, "root").to_string()
                },
                "Action": action_value,
                "Resource": queue.arn,
            }));
        }

        let policy = json!({
            "Version": "2012-10-17",
            "Id": format!("{}/SQSDefaultPolicy", queue.arn),
            "Statement": statements,
        });

        queue.attributes.insert(
            "Policy".to_string(),
            serde_json::to_string(&policy).unwrap(),
        );

        Ok(sqs_response(
            "AddPermission",
            json!({}),
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn remove_permission(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let queue_url = body["QueueUrl"]
            .as_str()
            .ok_or_else(|| missing_param("QueueUrl"))?;
        let label = body["Label"]
            .as_str()
            .ok_or_else(|| missing_param("Label"))?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let resolved_url = resolve_queue_url(queue_url, state).ok_or_else(queue_not_found)?;
        let queue = state
            .queues
            .get_mut(&resolved_url)
            .ok_or_else(queue_not_found)?;

        // Check label exists
        if !queue.permission_labels.contains(&label.to_string()) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                format!(
                    "Value {label} for parameter Label is invalid. Reason: can't find label on existing policy."
                ),
            ));
        }

        queue.permission_labels.retain(|l| l != label);

        // Remove from policy
        if let Some(policy_str) = queue.attributes.get("Policy").cloned() {
            if let Ok(mut policy) = serde_json::from_str::<Value>(&policy_str) {
                if let Some(stmts) = policy["Statement"].as_array() {
                    let filtered: Vec<Value> = stmts
                        .iter()
                        .filter(|s| s["Sid"].as_str() != Some(label))
                        .cloned()
                        .collect();
                    policy["Statement"] = json!(filtered);
                    queue.attributes.insert(
                        "Policy".to_string(),
                        serde_json::to_string(&policy).unwrap(),
                    );
                }
            }
        }

        Ok(sqs_response(
            "RemovePermission",
            json!({}),
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn list_dead_letter_source_queues(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let queue_url = body["QueueUrl"]
            .as_str()
            .ok_or_else(|| missing_param("QueueUrl"))?;

        let _accts = self.state.read();
        let _empty = crate::state::SqsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);
        let resolved_url = resolve_queue_url(queue_url, state).ok_or_else(queue_not_found)?;
        let queue = state
            .queues
            .get(&resolved_url)
            .ok_or_else(queue_not_found)?;
        let queue_arn = queue.arn.clone();

        // Find all queues whose redrive policy targets this queue
        let source_urls: Vec<String> = state
            .queues
            .values()
            .filter(|q| {
                q.redrive_policy
                    .as_ref()
                    .map(|rp| rp.dead_letter_target_arn == queue_arn)
                    .unwrap_or(false)
            })
            .map(|q| q.queue_url.clone())
            .collect();

        Ok(sqs_response(
            "ListDeadLetterSourceQueues",
            json!({ "queueUrls": source_urls }),
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn start_message_move_task(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let source_arn = body["SourceArn"]
            .as_str()
            .ok_or_else(|| missing_param("SourceArn"))?
            .to_string();
        let destination_arn = body["DestinationArn"].as_str().map(|s| s.to_string());
        let max_per_sec_i64 = val_as_i64(&body["MaxNumberOfMessagesPerSecond"]);
        if let Some(rate) = max_per_sec_i64 {
            if !(1..=500).contains(&rate) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "MaxNumberOfMessagesPerSecond must be between 1 and 500.",
                ));
            }
        }
        let max_per_sec = max_per_sec_i64.map(|rate| rate as i32);

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);

        let source_url = state
            .queues
            .values()
            .find(|q| q.arn == source_arn)
            .map(|q| q.queue_url.clone())
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ResourceNotFoundException",
                    "The resource that you specified for the SourceArn parameter doesn't exist.",
                )
            })?;

        // Source must be a DLQ (i.e. some other queue references it as redrive target).
        let dlq_sources: Vec<String> = state
            .queues
            .values()
            .filter(|q| {
                q.redrive_policy
                    .as_ref()
                    .map(|rp| rp.dead_letter_target_arn == source_arn)
                    .unwrap_or(false)
            })
            .map(|q| q.queue_url.clone())
            .collect();
        if dlq_sources.is_empty() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "AWS.SimpleQueueService.UnsupportedOperation",
                "Source queue must be configured as a dead-letter queue.",
            ));
        }

        // Validate destination if provided: must exist and be in same account.
        if let Some(ref dest) = destination_arn {
            if !state.queues.values().any(|q| &q.arn == dest) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ResourceNotFoundException",
                    "The resource that you specified for the DestinationArn parameter doesn't exist.",
                ));
            }
        }

        // Reject if there's already a RUNNING task for this source.
        if state
            .message_move_tasks
            .iter()
            .any(|t| t.source_arn == source_arn && t.status == MessageMoveTaskStatus::Running)
        {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "AWS.SimpleQueueService.UnsupportedOperation",
                "There is already an active message movement task for the specified source queue.",
            ));
        }

        let total = state
            .queues
            .get(&source_url)
            .map(|q| q.messages.len() as u64)
            .unwrap_or(0);
        let task_handle = format!("FakeCloudMessageMoveTask-{}", uuid::Uuid::new_v4().simple());

        // Fast path: if no rate was supplied AND there is no work to throttle,
        // drain synchronously and mark the task COMPLETED before returning.
        // The async path below is only useful when the caller wants real
        // backpressure (rate limit) or the ability to observe / cancel mid-flight.
        if max_per_sec.is_none() {
            let source_messages: Vec<SqsMessage> = state
                .queues
                .get_mut(&source_url)
                .map(|q| {
                    let drained: Vec<_> = q.messages.drain(..).collect();
                    q.inflight.clear();
                    drained
                })
                .unwrap_or_default();
            let mut moved: u64 = 0;
            if let Some(ref dest) = destination_arn {
                let dest_url = state
                    .queues
                    .values()
                    .find(|q| &q.arn == dest)
                    .map(|q| q.queue_url.clone());
                if let Some(dest_url) = dest_url {
                    if let Some(dq) = state.queues.get_mut(&dest_url) {
                        for msg in source_messages {
                            let mut new_msg = msg;
                            new_msg.visible_at = None;
                            new_msg.receive_count = 0;
                            dq.messages.push_back(new_msg);
                            moved += 1;
                        }
                    }
                }
            } else {
                let targets = dlq_sources.clone();
                for (idx, msg) in source_messages.into_iter().enumerate() {
                    if targets.is_empty() {
                        break;
                    }
                    let target_url = &targets[idx % targets.len()];
                    if let Some(tq) = state.queues.get_mut(target_url) {
                        let mut new_msg = msg;
                        new_msg.visible_at = None;
                        new_msg.receive_count = 0;
                        tq.messages.push_back(new_msg);
                        moved += 1;
                    }
                }
            }

            state.message_move_tasks.push(MessageMoveTask {
                task_handle: task_handle.clone(),
                source_arn,
                destination_arn,
                max_messages_per_second: max_per_sec,
                status: MessageMoveTaskStatus::Completed,
                messages_moved: moved,
                messages_to_move: total,
                started_timestamp: Utc::now().timestamp_millis(),
                failure_reason: None,
                cancel_flag: Arc::new(AtomicBool::new(false)),
            });
            return Ok(sqs_response(
                "StartMessageMoveTask",
                json!({ "TaskHandle": task_handle }),
                &req.request_id,
                req.is_query_protocol,
            ));
        }

        // Async path: insert a Running task, spawn a background mover that
        // drains one message at a time at the requested rate. Cancellation is
        // signalled through the task's `cancel_flag`.
        let cancel_flag = Arc::new(AtomicBool::new(false));
        state.message_move_tasks.push(MessageMoveTask {
            task_handle: task_handle.clone(),
            source_arn: source_arn.clone(),
            destination_arn: destination_arn.clone(),
            max_messages_per_second: max_per_sec,
            status: MessageMoveTaskStatus::Running,
            messages_moved: 0,
            messages_to_move: total,
            started_timestamp: Utc::now().timestamp_millis(),
            failure_reason: None,
            cancel_flag: cancel_flag.clone(),
        });
        drop(accounts);

        let state_handle = self.state.clone();
        let account_id = req.account_id.clone();
        let region = req.region.clone();
        let handle_for_task = task_handle.clone();
        let dlq_targets = dlq_sources.clone();
        let rate = max_per_sec.unwrap_or(1).max(1) as u64;
        let interval = std::time::Duration::from_nanos(1_000_000_000 / rate);

        tokio::spawn(async move {
            run_message_move_task(
                state_handle,
                account_id,
                region,
                handle_for_task,
                source_url,
                destination_arn,
                dlq_targets,
                interval,
                cancel_flag,
            )
            .await;
        });

        Ok(sqs_response(
            "StartMessageMoveTask",
            json!({ "TaskHandle": task_handle }),
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn cancel_message_move_task(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let task_handle = body["TaskHandle"]
            .as_str()
            .ok_or_else(|| missing_param("TaskHandle"))?
            .to_string();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let task = state
            .message_move_tasks
            .iter_mut()
            .find(|t| t.task_handle == task_handle)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "ResourceNotFoundException",
                    "The specified task handle doesn't exist.",
                )
            })?;
        let moved = task.messages_moved;
        match task.status {
            MessageMoveTaskStatus::Running => {
                // Signal the background mover to stop on its next tick.
                // The mover flips status to Cancelled when it observes the
                // flag and exits its loop; we mark Cancelling here so the
                // request doesn't have to wait for that observation.
                task.cancel_flag.store(true, Ordering::SeqCst);
                task.status = MessageMoveTaskStatus::Cancelling;
            }
            MessageMoveTaskStatus::Completed
            | MessageMoveTaskStatus::Cancelled
            | MessageMoveTaskStatus::Cancelling
            | MessageMoveTaskStatus::Failed => {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "AWS.SimpleQueueService.UnsupportedOperation",
                    "The message movement task isn't in RUNNING status.",
                ));
            }
        }

        Ok(sqs_response(
            "CancelMessageMoveTask",
            json!({ "ApproximateNumberOfMessagesMoved": moved }),
            &req.request_id,
            req.is_query_protocol,
        ))
    }

    fn list_message_move_tasks(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let body = parse_body(req);
        let source_arn = body["SourceArn"]
            .as_str()
            .ok_or_else(|| missing_param("SourceArn"))?
            .to_string();
        let max_results = val_as_i64(&body["MaxResults"])
            .map(|n| n.clamp(1, 10) as usize)
            .unwrap_or(1);

        let accounts = self.state.read();
        let empty = crate::state::SqsState::new(&req.account_id, &req.region, "");
        let state = accounts.get(&req.account_id).unwrap_or(&empty);

        // Source queue must exist.
        if !state.queues.values().any(|q| q.arn == source_arn) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "ResourceNotFoundException",
                "The resource that you specified for the SourceArn parameter doesn't exist.",
            ));
        }

        let mut tasks: Vec<&MessageMoveTask> = state
            .message_move_tasks
            .iter()
            .filter(|t| t.source_arn == source_arn)
            .collect();
        tasks.sort_by_key(|t| std::cmp::Reverse(t.started_timestamp));
        tasks.truncate(max_results);

        let results: Vec<Value> = tasks
            .into_iter()
            .map(|t| {
                let mut entry = serde_json::Map::new();
                if t.status == MessageMoveTaskStatus::Running {
                    entry.insert("TaskHandle".to_string(), json!(t.task_handle));
                }
                entry.insert("Status".to_string(), json!(t.status.as_str()));
                entry.insert("SourceArn".to_string(), json!(t.source_arn));
                if let Some(ref d) = t.destination_arn {
                    entry.insert("DestinationArn".to_string(), json!(d));
                }
                if let Some(m) = t.max_messages_per_second {
                    entry.insert("MaxNumberOfMessagesPerSecond".to_string(), json!(m));
                }
                entry.insert(
                    "ApproximateNumberOfMessagesMoved".to_string(),
                    json!(t.messages_moved),
                );
                entry.insert(
                    "ApproximateNumberOfMessagesToMove".to_string(),
                    json!(t.messages_to_move),
                );
                if let Some(ref reason) = t.failure_reason {
                    entry.insert("FailureReason".to_string(), json!(reason));
                }
                entry.insert("StartedTimestamp".to_string(), json!(t.started_timestamp));
                Value::Object(entry)
            })
            .collect();

        Ok(sqs_response(
            "ListMessageMoveTasks",
            json!({ "Results": results }),
            &req.request_id,
            req.is_query_protocol,
        ))
    }
}

fn format_receive_response(
    received: &[SqsMessage],
    request_id: &str,
    is_query: bool,
    requested_sys_attrs: Option<&[String]>,
    msg_attr_names: Option<&[String]>,
) -> AwsResponse {
    let now_millis = Utc::now().timestamp_millis();

    let messages: Vec<Value> = received
        .iter()
        .map(|m| {
            let mut msg_json = json!({
                "MessageId": m.message_id,
                "ReceiptHandle": m.receipt_handle,
                "MD5OfBody": m.md5_of_body,
                "Body": m.body,
            });

            // Only include system attributes if requested
            if let Some(names) = requested_sys_attrs {
                if !names.is_empty() {
                    let want_all = names.iter().any(|n| n == "All");
                    let mut sys_attrs = serde_json::Map::new();

                    if want_all || names.iter().any(|n| n == "ApproximateReceiveCount") {
                        sys_attrs.insert(
                            "ApproximateReceiveCount".to_string(),
                            json!(m.receive_count.to_string()),
                        );
                    }
                    if want_all || names.iter().any(|n| n == "SentTimestamp") {
                        sys_attrs.insert(
                            "SentTimestamp".to_string(),
                            json!(m.sent_timestamp.to_string()),
                        );
                    }
                    if want_all
                        || names
                            .iter()
                            .any(|n| n == "ApproximateFirstReceiveTimestamp")
                    {
                        sys_attrs.insert(
                            "ApproximateFirstReceiveTimestamp".to_string(),
                            json!(now_millis.to_string()),
                        );
                    }
                    if want_all || names.iter().any(|n| n == "SenderId") {
                        sys_attrs.insert("SenderId".to_string(), json!("AIDAIT2UOQQY3AUEKVGXU"));
                    }
                    if want_all || names.iter().any(|n| n == "MessageGroupId") {
                        if let Some(ref group_id) = m.message_group_id {
                            sys_attrs.insert("MessageGroupId".to_string(), json!(group_id));
                        }
                    }
                    if want_all || names.iter().any(|n| n == "MessageDeduplicationId") {
                        if let Some(ref dedup_id) = m.message_dedup_id {
                            sys_attrs.insert("MessageDeduplicationId".to_string(), json!(dedup_id));
                        }
                    }
                    if want_all || names.iter().any(|n| n == "SequenceNumber") {
                        if let Some(ref seq) = m.sequence_number {
                            sys_attrs.insert("SequenceNumber".to_string(), json!(seq));
                        }
                    }
                    if want_all || names.iter().any(|n| n == "AWSTraceHeader") {
                        // Include AWSTraceHeader if message has it in system attributes
                        if let Some(trace) = m.attributes.get("AWSTraceHeader") {
                            sys_attrs.insert("AWSTraceHeader".to_string(), json!(trace));
                        }
                    }

                    if !sys_attrs.is_empty() {
                        msg_json["Attributes"] = Value::Object(sys_attrs);
                    }
                }
            }

            // Filter message attributes
            let filtered_attrs: HashMap<String, &MessageAttribute> =
                if let Some(names) = msg_attr_names {
                    if names.is_empty() {
                        HashMap::new()
                    } else if names.iter().any(|n| n == "All" || n == ".*") {
                        m.message_attributes
                            .iter()
                            .map(|(k, v)| (k.clone(), v))
                            .collect()
                    } else {
                        m.message_attributes
                            .iter()
                            .filter(|(k, _)| {
                                names.iter().any(|n| {
                                    if n.ends_with(".*") {
                                        k.starts_with(n.trim_end_matches(".*"))
                                    } else {
                                        k.as_str() == n.as_str()
                                    }
                                })
                            })
                            .map(|(k, v)| (k.clone(), v))
                            .collect()
                    }
                } else {
                    HashMap::new()
                };

            if !filtered_attrs.is_empty() {
                let attrs: serde_json::Map<String, Value> = filtered_attrs
                    .iter()
                    .map(|(k, v)| {
                        let mut attr = json!({ "DataType": v.data_type });
                        if let Some(ref sv) = v.string_value {
                            attr["StringValue"] = json!(sv);
                        }
                        if let Some(ref bv) = v.binary_value {
                            use base64::Engine;
                            attr["BinaryValue"] =
                                json!(base64::engine::general_purpose::STANDARD.encode(bv));
                        }
                        (k.clone(), attr)
                    })
                    .collect();
                msg_json["MessageAttributes"] = Value::Object(attrs);
                msg_json["MD5OfMessageAttributes"] =
                    json!(md5_of_message_attributes_from_refs(&filtered_attrs));
            }

            msg_json
        })
        .collect();

    let body = if messages.is_empty() && !is_query {
        // For JSON protocol, omit Messages key when empty
        json!({})
    } else {
        json!({ "Messages": messages })
    };

    sqs_response("ReceiveMessage", body, request_id, is_query)
}

fn parse_message_attributes(body: &Value) -> HashMap<String, MessageAttribute> {
    let mut result = HashMap::new();
    if let Some(attrs) = body["MessageAttributes"].as_object() {
        for (name, val) in attrs {
            let data_type = val["DataType"].as_str().unwrap_or("String").to_string();
            let string_value = val["StringValue"].as_str().map(|s| s.to_string());
            let binary_value = val["BinaryValue"].as_str().and_then(|s| {
                use base64::Engine;
                base64::engine::general_purpose::STANDARD.decode(s).ok()
            });
            result.insert(
                name.clone(),
                MessageAttribute {
                    data_type,
                    string_value,
                    binary_value,
                },
            );
        }
    }

    // Handle Query protocol MessageAttribute.N.Name/Value patterns
    if let Some(body_obj) = body.as_object() {
        for i in 1..=20 {
            let name_key = format!("MessageAttribute.{i}.Name");
            let type_key = format!("MessageAttribute.{i}.Value.DataType");
            let str_key = format!("MessageAttribute.{i}.Value.StringValue");
            let bin_key = format!("MessageAttribute.{i}.Value.BinaryValue");

            if let Some(name) = body_obj.get(&name_key).and_then(|v| v.as_str()) {
                let data_type = body_obj
                    .get(&type_key)
                    .and_then(|v| v.as_str())
                    .unwrap_or("String")
                    .to_string();
                let string_value = body_obj
                    .get(&str_key)
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let binary_value = body_obj
                    .get(&bin_key)
                    .and_then(|v| v.as_str())
                    .and_then(|s| {
                        use base64::Engine;
                        base64::engine::general_purpose::STANDARD.decode(s).ok()
                    });
                result.insert(
                    name.to_string(),
                    MessageAttribute {
                        data_type,
                        string_value,
                        binary_value,
                    },
                );
            }
        }
    }

    result
}

/// Validate message attribute names and data types
fn validate_message_attributes(
    attrs: &HashMap<String, MessageAttribute>,
) -> Result<(), AwsServiceError> {
    for (name, attr) in attrs {
        // Validate attribute name
        if !name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-' || c == '.')
        {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                format!(
                    "The message attribute name '{}' is invalid. Attribute name can contain A-Z, a-z, 0-9, underscore (_), hyphen (-), and period (.) characters.",
                    name
                ),
            ));
        }

        // Validate data type
        let dt = &attr.data_type;
        let base_type = dt.split('.').next().unwrap_or(dt);
        let valid_prefixes = ["String", "Number", "Binary"];
        if !valid_prefixes.contains(&base_type) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                format!(
                    "The message attribute '{name}' has an invalid message attribute type, the set of supported type prefixes is Binary, Number, and String."
                ),
            ));
        }
    }
    Ok(())
}

fn is_valid_queue_name(name: &str) -> bool {
    if name.is_empty() || name.len() > 80 {
        return false;
    }
    name.chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

/// Compute MD5 of message attributes per AWS specification.
/// AWS sorts attributes by name, then for each: encode name length (4 bytes BE),
/// name bytes, data type length (4 bytes BE), data type bytes,
/// then transport type (1=String, 2=Binary) and value length + value bytes.
fn md5_of_message_attributes(attrs: &HashMap<String, MessageAttribute>) -> String {
    use md5::Digest;
    let mut sorted: Vec<(&String, &MessageAttribute)> = attrs.iter().collect();
    sorted.sort_by_key(|(k, _)| k.as_str());

    let mut hasher = Md5::new();
    for (name, attr) in sorted {
        // Name
        hasher.update((name.len() as u32).to_be_bytes());
        hasher.update(name.as_bytes());
        // Data type
        hasher.update((attr.data_type.len() as u32).to_be_bytes());
        hasher.update(attr.data_type.as_bytes());

        // Transport type and value
        if attr.data_type.starts_with("String") || attr.data_type.starts_with("Number") {
            hasher.update([1u8]); // STRING transport type
            if let Some(ref sv) = attr.string_value {
                hasher.update((sv.len() as u32).to_be_bytes());
                hasher.update(sv.as_bytes());
            } else {
                hasher.update(0u32.to_be_bytes());
            }
        } else if attr.data_type.starts_with("Binary") {
            hasher.update([2u8]); // BINARY transport type
            if let Some(ref bv) = attr.binary_value {
                hasher.update((bv.len() as u32).to_be_bytes());
                hasher.update(bv);
            } else {
                hasher.update(0u32.to_be_bytes());
            }
        }
    }
    format!("{:032x}", hasher.finalize())
}

/// Same as md5_of_message_attributes but works with borrowed references
fn md5_of_message_attributes_from_refs(attrs: &HashMap<String, &MessageAttribute>) -> String {
    use md5::Digest;
    let mut sorted: Vec<(&String, &&MessageAttribute)> = attrs.iter().collect();
    sorted.sort_by_key(|(k, _)| k.as_str());

    let mut hasher = Md5::new();
    for (name, attr) in sorted {
        hasher.update((name.len() as u32).to_be_bytes());
        hasher.update(name.as_bytes());
        hasher.update((attr.data_type.len() as u32).to_be_bytes());
        hasher.update(attr.data_type.as_bytes());

        if attr.data_type.starts_with("String") || attr.data_type.starts_with("Number") {
            hasher.update([1u8]);
            if let Some(ref sv) = attr.string_value {
                hasher.update((sv.len() as u32).to_be_bytes());
                hasher.update(sv.as_bytes());
            } else {
                hasher.update(0u32.to_be_bytes());
            }
        } else if attr.data_type.starts_with("Binary") {
            hasher.update([2u8]);
            if let Some(ref bv) = attr.binary_value {
                hasher.update((bv.len() as u32).to_be_bytes());
                hasher.update(bv);
            } else {
                hasher.update(0u32.to_be_bytes());
            }
        }
    }
    format!("{:032x}", hasher.finalize())
}

/// Resolve a QueueUrl that might be a queue name, a path, or a full URL
fn resolve_queue_url(input: &str, state: &crate::state::SqsState) -> Option<String> {
    // Direct match
    if state.queues.contains_key(input) {
        return Some(input.to_string());
    }
    // Try as queue name
    if let Some(url) = state.name_to_url.get(input) {
        return Some(url.clone());
    }
    // Try extracting queue name from URL path (e.g., /123456789012/my-queue)
    let name = input.rsplit('/').next().unwrap_or("");
    if let Some(url) = state.name_to_url.get(name) {
        return Some(url.clone());
    }
    None
}

fn missing_param(name: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "MissingParameter",
        format!("The request must contain the parameter {name}"),
    )
}

fn queue_not_found() -> AwsServiceError {
    AwsServiceError::aws_error_with_headers(
        StatusCode::BAD_REQUEST,
        "QueueDoesNotExist",
        "The specified queue does not exist.",
        vec![(
            "x-amzn-query-error".to_string(),
            "AWS.SimpleQueueService.NonExistentQueue;Sender".to_string(),
        )],
    )
}

pub(crate) fn md5_hex(input: &str) -> String {
    use md5::Digest;
    let mut hasher = Md5::new();
    hasher.update(input.as_bytes());
    format!("{:032x}", hasher.finalize())
}

pub(crate) fn sha256_hex(input: &str) -> String {
    use sha2::Digest;
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    format!("{:064x}", hasher.finalize())
}

/// Find the message_id associated with a receipt handle by checking both the
/// receipt_handle_map (historical handles) and current message receipt handles.
fn find_message_id_for_receipt(
    queue: &crate::state::SqsQueue,
    receipt_handle: &str,
) -> Option<String> {
    // Check the receipt handle map for any historical handle
    for (msg_id, handles) in &queue.receipt_handle_map {
        if handles.iter().any(|h| h == receipt_handle) {
            return Some(msg_id.clone());
        }
    }
    // Also check current messages/inflight directly
    for msg in &queue.inflight {
        if msg.receipt_handle.as_deref() == Some(receipt_handle) {
            return Some(msg.message_id.clone());
        }
    }
    for msg in &queue.messages {
        if msg.receipt_handle.as_deref() == Some(receipt_handle) {
            return Some(msg.message_id.clone());
        }
    }
    None
}

/// Parse MessageSystemAttributes (e.g., AWSTraceHeader) from the request body.
fn parse_message_system_attributes(body: &Value) -> HashMap<String, String> {
    let mut result = HashMap::new();

    // JSON protocol
    if let Some(attrs) = body["MessageSystemAttributes"].as_object() {
        for (name, val) in attrs {
            if let Some(sv) = val["StringValue"].as_str() {
                result.insert(name.clone(), sv.to_string());
            }
        }
    }

    // Query protocol: MessageSystemAttribute.N.Name/Value
    if let Some(body_obj) = body.as_object() {
        for i in 1..=20 {
            let name_key = format!("MessageSystemAttribute.{i}.Name");
            let str_key = format!("MessageSystemAttribute.{i}.Value.StringValue");

            if let Some(name) = body_obj.get(&name_key).and_then(|v| v.as_str()) {
                if let Some(value) = body_obj.get(&str_key).and_then(|v| v.as_str()) {
                    result.insert(name.to_string(), value.to_string());
                }
            }
        }
    }

    result
}

fn is_valid_batch_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 80 {
        return false;
    }
    id.chars()
        .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

fn parse_numbered_params(body: &Value, prefix: &str) -> Vec<String> {
    let mut result = Vec::new();
    if let Some(obj) = body.as_object() {
        for i in 1..=20 {
            let key = format!("{prefix}.{i}");
            if let Some(v) = obj.get(&key).and_then(|v| v.as_str()) {
                result.push(v.to_string());
            }
        }
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::RwLock;
    use serde_json::json;
    use std::collections::HashMap;
    use std::sync::Arc;

    fn expect_err(result: Result<AwsResponse, AwsServiceError>) -> AwsServiceError {
        match result {
            Err(e) => e,
            Ok(_) => panic!("expected error but got Ok"),
        }
    }

    fn make_service() -> SqsService {
        let state: SharedSqsState = Arc::new(RwLock::new(
            fakecloud_core::multi_account::MultiAccountState::new(
                "123456789012",
                "us-east-1",
                "http://localhost:4566",
            ),
        ));
        SqsService::new(state)
    }

    fn make_request(action: &str, body: Value) -> AwsRequest {
        AwsRequest {
            service: "sqs".to_string(),
            action: action.to_string(),
            region: "us-east-1".to_string(),
            account_id: "123456789012".to_string(),
            request_id: "test-id".to_string(),
            headers: http::HeaderMap::new(),
            query_params: HashMap::new(),
            body: serde_json::to_vec(&body).unwrap().into(),
            path_segments: vec![],
            raw_path: "/".to_string(),
            raw_query: String::new(),
            method: http::Method::POST,
            is_query_protocol: false,
            access_key_id: None,
            principal: None,
        }
    }

    #[test]
    fn iam_condition_keys_for_send_message_populates_attributes() {
        let svc = make_service();
        let req = make_request(
            "SendMessage",
            json!({
                "QueueUrl": "http://localhost:4566/123456789012/q",
                "MessageBody": "hi",
                "MessageAttributes": {
                    "Color": {"DataType": "String", "StringValue": "red"},
                    "Priority": {"DataType": "Number", "StringValue": "1"}
                }
            }),
        );
        let action = fakecloud_core::auth::IamAction {
            service: "sqs",
            action: "SendMessage",
            resource: "arn:aws:sqs:us-east-1:123456789012:q".to_string(),
        };
        let keys = svc.iam_condition_keys_for(&req, &action);
        assert_eq!(
            keys.get("sqs:messageattribute.Color"),
            Some(&vec!["red".to_string()])
        );
        assert!(keys.contains_key("sqs:messageattribute.Priority"));
    }

    #[test]
    fn iam_condition_keys_for_send_message_without_attrs_is_empty() {
        let svc = make_service();
        let req = make_request(
            "SendMessage",
            json!({"QueueUrl": "http://localhost:4566/123456789012/q", "MessageBody": "hi"}),
        );
        let action = fakecloud_core::auth::IamAction {
            service: "sqs",
            action: "SendMessage",
            resource: "arn:aws:sqs:us-east-1:123456789012:q".to_string(),
        };
        assert!(svc.iam_condition_keys_for(&req, &action).is_empty());
    }

    #[test]
    fn iam_condition_keys_for_non_send_message_is_empty() {
        let svc = make_service();
        let req = make_request("ReceiveMessage", json!({"QueueUrl": "http://x/q"}));
        let action = fakecloud_core::auth::IamAction {
            service: "sqs",
            action: "ReceiveMessage",
            resource: "arn:aws:sqs:us-east-1:123456789012:q".to_string(),
        };
        assert!(svc.iam_condition_keys_for(&req, &action).is_empty());
    }

    fn create_queue(svc: &SqsService, name: &str) -> String {
        let req = make_request("CreateQueue", json!({ "QueueName": name }));
        let resp = svc.create_queue(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        body["QueueUrl"].as_str().unwrap().to_string()
    }

    fn send_msg(svc: &SqsService, queue_url: &str, body_text: &str) -> String {
        let req = make_request(
            "SendMessage",
            json!({ "QueueUrl": queue_url, "MessageBody": body_text }),
        );
        let resp = svc.send_message(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        body["MessageId"].as_str().unwrap().to_string()
    }

    fn receive_msgs(svc: &SqsService, queue_url: &str, max: u32) -> Vec<Value> {
        let req = make_request(
            "ReceiveMessage",
            json!({
                "QueueUrl": queue_url,
                "MaxNumberOfMessages": max,
                "VisibilityTimeout": 0,
            }),
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let resp = rt.block_on(svc.receive_message(&req)).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        body["Messages"].as_array().cloned().unwrap_or_default()
    }

    // ── CreateQueue / GetQueueUrl / DeleteQueue / ListQueues ─────────

    #[test]
    fn create_queue_returns_url() {
        let svc = make_service();
        let url = create_queue(&svc, "my-queue");
        assert!(url.contains("my-queue"));
    }

    #[test]
    fn create_queue_idempotent_same_attributes() {
        let svc = make_service();
        let url1 = create_queue(&svc, "my-queue");
        let url2 = create_queue(&svc, "my-queue");
        assert_eq!(url1, url2);
    }

    #[test]
    fn create_queue_conflict_different_attributes() {
        let svc = make_service();
        let req1 = make_request(
            "CreateQueue",
            json!({
                "QueueName": "my-queue",
                "Attributes": { "VisibilityTimeout": "60" }
            }),
        );
        svc.create_queue(&req1).unwrap();

        let req2 = make_request(
            "CreateQueue",
            json!({
                "QueueName": "my-queue",
                "Attributes": { "VisibilityTimeout": "120" }
            }),
        );
        let err = expect_err(svc.create_queue(&req2));
        assert!(err.to_string().contains("QueueAlreadyExists"));
    }

    #[test]
    fn get_queue_url_existing() {
        let svc = make_service();
        let url = create_queue(&svc, "lookup-queue");
        let req = make_request("GetQueueUrl", json!({ "QueueName": "lookup-queue" }));
        let resp = svc.get_queue_url(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        assert_eq!(body["QueueUrl"].as_str().unwrap(), url);
    }

    #[test]
    fn get_queue_url_nonexistent() {
        let svc = make_service();
        let req = make_request("GetQueueUrl", json!({ "QueueName": "nope" }));
        let err = expect_err(svc.get_queue_url(&req));
        assert!(err.to_string().contains("QueueDoesNotExist"));
    }

    #[test]
    fn delete_queue_removes_it() {
        let svc = make_service();
        let url = create_queue(&svc, "del-queue");
        let req = make_request("DeleteQueue", json!({ "QueueUrl": url }));
        svc.delete_queue(&req).unwrap();

        let req2 = make_request("GetQueueUrl", json!({ "QueueName": "del-queue" }));
        assert!(svc.get_queue_url(&req2).is_err());
    }

    #[test]
    fn list_queues_all() {
        let svc = make_service();
        create_queue(&svc, "alpha");
        create_queue(&svc, "beta");
        create_queue(&svc, "gamma");

        let req = make_request("ListQueues", json!({}));
        let resp = svc.list_queues(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let urls = body["QueueUrls"].as_array().unwrap();
        assert_eq!(urls.len(), 3);
    }

    #[test]
    fn list_queues_with_prefix() {
        let svc = make_service();
        create_queue(&svc, "prod-orders");
        create_queue(&svc, "prod-events");
        create_queue(&svc, "dev-orders");

        let req = make_request("ListQueues", json!({ "QueueNamePrefix": "prod-" }));
        let resp = svc.list_queues(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let urls = body["QueueUrls"].as_array().unwrap();
        assert_eq!(urls.len(), 2);
        for u in urls {
            assert!(u.as_str().unwrap().contains("prod-"));
        }
    }

    #[test]
    fn list_queues_pagination() {
        let svc = make_service();
        for i in 0..5 {
            create_queue(&svc, &format!("page-queue-{i}"));
        }

        let req = make_request("ListQueues", json!({ "MaxResults": 2 }));
        let resp = svc.list_queues(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let urls = body["QueueUrls"].as_array().unwrap();
        assert_eq!(urls.len(), 2);
        assert!(body["NextToken"].as_str().is_some());

        // Second page
        let token = body["NextToken"].as_str().unwrap();
        let req2 = make_request("ListQueues", json!({ "MaxResults": 2, "NextToken": token }));
        let resp2 = svc.list_queues(&req2).unwrap();
        let body2: Value = serde_json::from_slice(resp2.body.expect_bytes()).unwrap();
        let urls2 = body2["QueueUrls"].as_array().unwrap();
        assert_eq!(urls2.len(), 2);

        // Third page (last 1)
        let token2 = body2["NextToken"].as_str().unwrap();
        let req3 = make_request(
            "ListQueues",
            json!({ "MaxResults": 2, "NextToken": token2 }),
        );
        let resp3 = svc.list_queues(&req3).unwrap();
        let body3: Value = serde_json::from_slice(resp3.body.expect_bytes()).unwrap();
        let urls3 = body3["QueueUrls"].as_array().unwrap();
        assert_eq!(urls3.len(), 1);
        assert!(body3["NextToken"].is_null());
    }

    // ── SendMessage / ReceiveMessage / DeleteMessage ────────────────

    #[test]
    fn send_and_receive_message() {
        let svc = make_service();
        let url = create_queue(&svc, "msg-queue");
        send_msg(&svc, &url, "hello world");

        let msgs = receive_msgs(&svc, &url, 1);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0]["Body"].as_str().unwrap(), "hello world");
        assert!(msgs[0]["MessageId"].as_str().is_some());
        assert!(msgs[0]["ReceiptHandle"].as_str().is_some());
    }

    #[test]
    fn send_message_returns_md5() {
        let svc = make_service();
        let url = create_queue(&svc, "md5-queue");
        let req = make_request(
            "SendMessage",
            json!({ "QueueUrl": url, "MessageBody": "test" }),
        );
        let resp = svc.send_message(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        assert!(body["MD5OfMessageBody"].as_str().is_some());
        assert!(body["MessageId"].as_str().is_some());
    }

    #[test]
    fn receive_empty_queue() {
        let svc = make_service();
        let url = create_queue(&svc, "empty-queue");
        let msgs = receive_msgs(&svc, &url, 10);
        assert!(msgs.is_empty());
    }

    #[test]
    fn receive_respects_max_messages() {
        let svc = make_service();
        let url = create_queue(&svc, "multi-queue");
        for i in 0..5 {
            send_msg(&svc, &url, &format!("msg-{i}"));
        }
        let msgs = receive_msgs(&svc, &url, 3);
        assert_eq!(msgs.len(), 3);
    }

    #[test]
    fn delete_message_removes_from_inflight() {
        let svc = make_service();
        let url = create_queue(&svc, "del-msg-queue");
        send_msg(&svc, &url, "to-delete");

        // Receive with a high visibility timeout so it stays inflight
        let req = make_request(
            "ReceiveMessage",
            json!({
                "QueueUrl": url,
                "MaxNumberOfMessages": 1,
                "VisibilityTimeout": 300,
            }),
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let resp = rt.block_on(svc.receive_message(&req)).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let receipt = body["Messages"][0]["ReceiptHandle"]
            .as_str()
            .unwrap()
            .to_string();

        // Delete it
        let del_req = make_request(
            "DeleteMessage",
            json!({ "QueueUrl": url, "ReceiptHandle": receipt }),
        );
        svc.delete_message(&del_req).unwrap();

        // Receive again with visibility 0 - should be empty
        let msgs = receive_msgs(&svc, &url, 10);
        assert!(msgs.is_empty());
    }

    #[test]
    fn delete_message_invalid_receipt_handle() {
        let svc = make_service();
        let url = create_queue(&svc, "bad-receipt-queue");
        let req = make_request(
            "DeleteMessage",
            json!({ "QueueUrl": url, "ReceiptHandle": "bogus" }),
        );
        let err = expect_err(svc.delete_message(&req));
        assert!(err.to_string().contains("ReceiptHandleIsInvalid"));
    }

    // ── SendMessageBatch ────────────────────────────────────────────

    #[test]
    fn send_message_batch_success() {
        let svc = make_service();
        let url = create_queue(&svc, "batch-queue");
        let req = make_request(
            "SendMessageBatch",
            json!({
                "QueueUrl": url,
                "Entries": [
                    { "Id": "a", "MessageBody": "first" },
                    { "Id": "b", "MessageBody": "second" },
                    { "Id": "c", "MessageBody": "third" },
                ]
            }),
        );
        let resp = svc.send_message_batch(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let successful = body["Successful"].as_array().unwrap();
        assert_eq!(successful.len(), 3);

        let ids: Vec<&str> = successful
            .iter()
            .map(|e| e["Id"].as_str().unwrap())
            .collect();
        assert!(ids.contains(&"a"));
        assert!(ids.contains(&"b"));
        assert!(ids.contains(&"c"));

        // Verify messages are receivable
        let msgs = receive_msgs(&svc, &url, 10);
        assert_eq!(msgs.len(), 3);
    }

    #[test]
    fn send_message_batch_empty_fails() {
        let svc = make_service();
        let url = create_queue(&svc, "batch-empty-queue");
        let req = make_request(
            "SendMessageBatch",
            json!({ "QueueUrl": url, "Entries": [] }),
        );
        let err = expect_err(svc.send_message_batch(&req));
        assert!(err.to_string().contains("EmptyBatchRequest"));
    }

    #[test]
    fn send_message_batch_duplicate_ids_fails() {
        let svc = make_service();
        let url = create_queue(&svc, "batch-dup-queue");
        let req = make_request(
            "SendMessageBatch",
            json!({
                "QueueUrl": url,
                "Entries": [
                    { "Id": "a", "MessageBody": "first" },
                    { "Id": "a", "MessageBody": "second" },
                ]
            }),
        );
        let err = expect_err(svc.send_message_batch(&req));
        assert!(err.to_string().contains("BatchEntryIdsNotDistinct"));
    }

    // ── ChangeMessageVisibility ─────────────────────────────────────

    #[test]
    fn change_message_visibility() {
        let svc = make_service();
        let url = create_queue(&svc, "vis-queue");
        send_msg(&svc, &url, "visibility-test");

        // Receive with high visibility timeout
        let req = make_request(
            "ReceiveMessage",
            json!({
                "QueueUrl": url,
                "MaxNumberOfMessages": 1,
                "VisibilityTimeout": 300,
            }),
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let resp = rt.block_on(svc.receive_message(&req)).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let receipt = body["Messages"][0]["ReceiptHandle"]
            .as_str()
            .unwrap()
            .to_string();

        // Change visibility to 0 (make immediately visible)
        let cmv_req = make_request(
            "ChangeMessageVisibility",
            json!({
                "QueueUrl": url,
                "ReceiptHandle": receipt,
                "VisibilityTimeout": 0,
            }),
        );
        svc.change_message_visibility(&cmv_req).unwrap();

        // Message should be receivable again immediately
        let msgs = receive_msgs(&svc, &url, 1);
        assert_eq!(msgs.len(), 1);
        assert_eq!(msgs[0]["Body"].as_str().unwrap(), "visibility-test");
    }

    #[test]
    fn change_message_visibility_invalid_receipt() {
        let svc = make_service();
        let url = create_queue(&svc, "vis-bad-queue");
        let req = make_request(
            "ChangeMessageVisibility",
            json!({
                "QueueUrl": url,
                "ReceiptHandle": "invalid-handle",
                "VisibilityTimeout": 0,
            }),
        );
        let err = expect_err(svc.change_message_visibility(&req));
        assert!(err.to_string().contains("ReceiptHandleIsInvalid"));
    }

    // ── GetQueueAttributes / SetQueueAttributes ─────────────────────

    #[test]
    fn get_queue_attributes_all() {
        let svc = make_service();
        let url = create_queue(&svc, "attrs-queue");
        let req = make_request(
            "GetQueueAttributes",
            json!({
                "QueueUrl": url,
                "AttributeNames": ["All"],
            }),
        );
        let resp = svc.get_queue_attributes(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let attrs = body["Attributes"].as_object().unwrap();

        assert_eq!(attrs["VisibilityTimeout"].as_str().unwrap(), "30");
        assert_eq!(attrs["DelaySeconds"].as_str().unwrap(), "0");
        assert!(attrs.contains_key("QueueArn"));
        assert!(attrs.contains_key("ApproximateNumberOfMessages"));
    }

    #[test]
    fn get_queue_attributes_specific() {
        let svc = make_service();
        let url = create_queue(&svc, "specific-attrs-queue");
        let req = make_request(
            "GetQueueAttributes",
            json!({
                "QueueUrl": url,
                "AttributeNames": ["VisibilityTimeout", "DelaySeconds"],
            }),
        );
        let resp = svc.get_queue_attributes(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let attrs = body["Attributes"].as_object().unwrap();

        assert!(attrs.contains_key("VisibilityTimeout"));
        assert!(attrs.contains_key("DelaySeconds"));
        assert!(!attrs.contains_key("QueueArn"));
    }

    #[test]
    fn set_queue_attributes_updates_values() {
        let svc = make_service();
        let url = create_queue(&svc, "set-attrs-queue");

        let set_req = make_request(
            "SetQueueAttributes",
            json!({
                "QueueUrl": url,
                "Attributes": { "VisibilityTimeout": "60", "DelaySeconds": "10" },
            }),
        );
        svc.set_queue_attributes(&set_req).unwrap();

        let get_req = make_request(
            "GetQueueAttributes",
            json!({
                "QueueUrl": url,
                "AttributeNames": ["VisibilityTimeout", "DelaySeconds"],
            }),
        );
        let resp = svc.get_queue_attributes(&get_req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let attrs = body["Attributes"].as_object().unwrap();
        assert_eq!(attrs["VisibilityTimeout"].as_str().unwrap(), "60");
        assert_eq!(attrs["DelaySeconds"].as_str().unwrap(), "10");
    }

    #[test]
    fn get_queue_attributes_message_counts() {
        let svc = make_service();
        let url = create_queue(&svc, "count-queue");
        send_msg(&svc, &url, "msg-1");
        send_msg(&svc, &url, "msg-2");

        let req = make_request(
            "GetQueueAttributes",
            json!({
                "QueueUrl": url,
                "AttributeNames": ["ApproximateNumberOfMessages"],
            }),
        );
        let resp = svc.get_queue_attributes(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        assert_eq!(
            body["Attributes"]["ApproximateNumberOfMessages"]
                .as_str()
                .unwrap(),
            "2"
        );
    }

    #[test]
    fn set_queue_attributes_removes_policy() {
        let svc = make_service();
        let url = create_queue(&svc, "policy-queue");

        let set_req = make_request(
            "SetQueueAttributes",
            json!({
                "QueueUrl": url,
                "Attributes": { "Policy": "{\"Version\":\"2012-10-17\"}" },
            }),
        );
        svc.set_queue_attributes(&set_req).unwrap();

        let remove_req = make_request(
            "SetQueueAttributes",
            json!({
                "QueueUrl": url,
                "Attributes": { "Policy": "" },
            }),
        );
        svc.set_queue_attributes(&remove_req).unwrap();

        let get_req = make_request(
            "GetQueueAttributes",
            json!({
                "QueueUrl": url,
                "AttributeNames": ["All"],
            }),
        );
        let resp = svc.get_queue_attributes(&get_req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let attrs = body["Attributes"].as_object().unwrap();
        assert!(!attrs.contains_key("Policy"));
    }

    // ── PurgeQueue ──────────────────────────────────────────────────

    #[test]
    fn purge_queue_removes_all_messages() {
        let svc = make_service();
        let url = create_queue(&svc, "purge-queue");
        send_msg(&svc, &url, "msg-1");
        send_msg(&svc, &url, "msg-2");
        send_msg(&svc, &url, "msg-3");

        let req = make_request("PurgeQueue", json!({ "QueueUrl": url }));
        svc.purge_queue(&req).unwrap();

        let msgs = receive_msgs(&svc, &url, 10);
        assert!(msgs.is_empty());
    }

    #[test]
    fn purge_queue_nonexistent_fails() {
        let svc = make_service();
        let req = make_request(
            "PurgeQueue",
            json!({ "QueueUrl": "http://localhost:4566/123456789012/nope" }),
        );
        assert!(svc.purge_queue(&req).is_err());
    }

    // ── TagQueue / UntagQueue / ListQueueTags ───────────────────────

    #[test]
    fn tag_and_list_queue_tags() {
        let svc = make_service();
        let url = create_queue(&svc, "tag-queue");

        let tag_req = make_request(
            "TagQueue",
            json!({
                "QueueUrl": url,
                "Tags": { "env": "prod", "team": "backend" },
            }),
        );
        svc.tag_queue(&tag_req).unwrap();

        let list_req = make_request("ListQueueTags", json!({ "QueueUrl": url }));
        let resp = svc.list_queue_tags(&list_req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let tags = body["Tags"].as_object().unwrap();
        assert_eq!(tags["env"].as_str().unwrap(), "prod");
        assert_eq!(tags["team"].as_str().unwrap(), "backend");
    }

    #[test]
    fn untag_queue_removes_tags() {
        let svc = make_service();
        let url = create_queue(&svc, "untag-queue");

        let tag_req = make_request(
            "TagQueue",
            json!({
                "QueueUrl": url,
                "Tags": { "env": "prod", "team": "backend", "version": "1" },
            }),
        );
        svc.tag_queue(&tag_req).unwrap();

        let untag_req = make_request(
            "UntagQueue",
            json!({
                "QueueUrl": url,
                "TagKeys": ["env", "version"],
            }),
        );
        svc.untag_queue(&untag_req).unwrap();

        let list_req = make_request("ListQueueTags", json!({ "QueueUrl": url }));
        let resp = svc.list_queue_tags(&list_req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let tags = body["Tags"].as_object().unwrap();
        assert_eq!(tags.len(), 1);
        assert_eq!(tags["team"].as_str().unwrap(), "backend");
    }

    #[test]
    fn tag_queue_merges_with_existing() {
        let svc = make_service();
        let url = create_queue(&svc, "merge-tag-queue");

        let tag1 = make_request("TagQueue", json!({ "QueueUrl": url, "Tags": { "a": "1" } }));
        svc.tag_queue(&tag1).unwrap();

        let tag2 = make_request("TagQueue", json!({ "QueueUrl": url, "Tags": { "b": "2" } }));
        svc.tag_queue(&tag2).unwrap();

        let list_req = make_request("ListQueueTags", json!({ "QueueUrl": url }));
        let resp = svc.list_queue_tags(&list_req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let tags = body["Tags"].as_object().unwrap();
        assert_eq!(tags.len(), 2);
        assert_eq!(tags["a"].as_str().unwrap(), "1");
        assert_eq!(tags["b"].as_str().unwrap(), "2");
    }

    #[test]
    fn tag_queue_empty_tags_fails() {
        let svc = make_service();
        let url = create_queue(&svc, "empty-tag-queue");
        let req = make_request("TagQueue", json!({ "QueueUrl": url, "Tags": {} }));
        assert!(svc.tag_queue(&req).is_err());
    }

    #[test]
    fn list_queue_tags_empty_by_default() {
        let svc = make_service();
        let url = create_queue(&svc, "no-tags-queue");
        let req = make_request("ListQueueTags", json!({ "QueueUrl": url }));
        let resp = svc.list_queue_tags(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let tags = body["Tags"].as_object().unwrap();
        assert!(tags.is_empty());
    }

    // ── CreateQueue with tags and custom attributes ─────────────────

    #[test]
    fn create_queue_with_tags() {
        let svc = make_service();
        let req = make_request(
            "CreateQueue",
            json!({
                "QueueName": "tagged-at-create",
                "Tags": { "env": "test" },
            }),
        );
        let resp = svc.create_queue(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let url = body["QueueUrl"].as_str().unwrap();

        let list_req = make_request("ListQueueTags", json!({ "QueueUrl": url }));
        let resp = svc.list_queue_tags(&list_req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        assert_eq!(body["Tags"]["env"].as_str().unwrap(), "test");
    }

    #[test]
    fn create_queue_with_custom_visibility_timeout() {
        let svc = make_service();
        let req = make_request(
            "CreateQueue",
            json!({
                "QueueName": "custom-vt",
                "Attributes": { "VisibilityTimeout": "45" },
            }),
        );
        let resp = svc.create_queue(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let url = body["QueueUrl"].as_str().unwrap();

        let get_req = make_request(
            "GetQueueAttributes",
            json!({
                "QueueUrl": url,
                "AttributeNames": ["VisibilityTimeout"],
            }),
        );
        let resp = svc.get_queue_attributes(&get_req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        assert_eq!(
            body["Attributes"]["VisibilityTimeout"].as_str().unwrap(),
            "45"
        );
    }

    // ── FIFO queue ──────────────────────────────────────────────────

    #[test]
    fn create_fifo_queue() {
        let svc = make_service();
        let url = create_queue(&svc, "my-queue.fifo");
        assert!(url.contains(".fifo"));

        let req = make_request(
            "GetQueueAttributes",
            json!({
                "QueueUrl": url,
                "AttributeNames": ["FifoQueue"],
            }),
        );
        let resp = svc.get_queue_attributes(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        assert_eq!(body["Attributes"]["FifoQueue"].as_str().unwrap(), "true");
    }

    #[test]
    fn fifo_queue_requires_message_group_id() {
        let svc = make_service();
        let url = create_queue(&svc, "strict.fifo");
        let req = make_request(
            "SendMessage",
            json!({
                "QueueUrl": url,
                "MessageBody": "hello",
                "MessageDeduplicationId": "dedup-1",
            }),
        );
        let err = expect_err(svc.send_message(&req));
        assert!(err.to_string().contains("MessageGroupId"));
    }

    // ── Queue name validation ───────────────────────────────────────

    #[test]
    fn create_queue_invalid_name() {
        let svc = make_service();
        let req = make_request(
            "CreateQueue",
            json!({ "QueueName": "bad name with spaces" }),
        );
        let err = expect_err(svc.create_queue(&req));
        assert!(err.to_string().contains("InvalidParameterValue"));
    }

    // ── Message attributes ──────────────────────────────────────────

    #[test]
    fn send_message_with_attributes() {
        let svc = make_service();
        let url = create_queue(&svc, "msg-attrs-queue");
        let req = make_request(
            "SendMessage",
            json!({
                "QueueUrl": url,
                "MessageBody": "with-attrs",
                "MessageAttributes": {
                    "Color": {
                        "DataType": "String",
                        "StringValue": "blue"
                    }
                }
            }),
        );
        let resp = svc.send_message(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        assert!(body["MD5OfMessageAttributes"].as_str().is_some());
    }

    // ── Inflight tracking ───────────────────────────────────────────

    #[test]
    fn receive_increments_inflight_count() {
        let svc = make_service();
        let url = create_queue(&svc, "inflight-queue");
        send_msg(&svc, &url, "tracked");

        // Receive with high visibility timeout
        let req = make_request(
            "ReceiveMessage",
            json!({
                "QueueUrl": url,
                "MaxNumberOfMessages": 1,
                "VisibilityTimeout": 300,
            }),
        );
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        rt.block_on(svc.receive_message(&req)).unwrap();

        let attr_req = make_request(
            "GetQueueAttributes",
            json!({
                "QueueUrl": url,
                "AttributeNames": [
                    "ApproximateNumberOfMessages",
                    "ApproximateNumberOfMessagesNotVisible"
                ],
            }),
        );
        let resp = svc.get_queue_attributes(&attr_req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let attrs = body["Attributes"].as_object().unwrap();
        assert_eq!(attrs["ApproximateNumberOfMessages"].as_str().unwrap(), "0");
        assert_eq!(
            attrs["ApproximateNumberOfMessagesNotVisible"]
                .as_str()
                .unwrap(),
            "1"
        );
    }

    // ── Batch additions: permission, batch ops, dead letter ─────────

    fn body_json(resp: AwsResponse) -> Value {
        serde_json::from_slice(resp.body.expect_bytes()).unwrap()
    }

    fn create_queue_url(svc: &SqsService, name: &str) -> String {
        let resp = svc
            .create_queue(&make_request("CreateQueue", json!({ "QueueName": name })))
            .unwrap();
        body_json(resp)["QueueUrl"].as_str().unwrap().to_string()
    }

    fn send_msg_simple(svc: &SqsService, url: &str, body: &str) {
        svc.send_message(&make_request(
            "SendMessage",
            json!({ "QueueUrl": url, "MessageBody": body }),
        ))
        .unwrap();
    }

    // ── AddPermission / RemovePermission ─────────────────────────────

    #[test]
    fn add_permission_builds_policy_and_remove_strips_it() {
        let svc = make_service();
        let url = create_queue_url(&svc, "perm-q");

        let add = make_request(
            "AddPermission",
            json!({
                "QueueUrl": url,
                "Label": "AllowSend",
                "Actions": ["SendMessage"],
                "AWSAccountIds": ["111111111111"]
            }),
        );
        svc.add_permission(&add).unwrap();

        let attrs = svc
            .get_queue_attributes(&make_request(
                "GetQueueAttributes",
                json!({ "QueueUrl": url, "AttributeNames": ["Policy"] }),
            ))
            .unwrap();
        let body = body_json(attrs);
        let policy_str = body["Attributes"]["Policy"].as_str().unwrap();
        let policy: Value = serde_json::from_str(policy_str).unwrap();
        let stmts = policy["Statement"].as_array().unwrap();
        assert_eq!(stmts.len(), 1);
        assert_eq!(stmts[0]["Sid"], json!("AllowSend"));

        let rm = make_request(
            "RemovePermission",
            json!({ "QueueUrl": url, "Label": "AllowSend" }),
        );
        svc.remove_permission(&rm).unwrap();
        let attrs2 = svc
            .get_queue_attributes(&make_request(
                "GetQueueAttributes",
                json!({ "QueueUrl": url, "AttributeNames": ["Policy"] }),
            ))
            .unwrap();
        let body2 = body_json(attrs2);
        let policy2: Value =
            serde_json::from_str(body2["Attributes"]["Policy"].as_str().unwrap()).unwrap();
        assert!(policy2["Statement"].as_array().unwrap().is_empty());
    }

    #[test]
    fn add_permission_empty_actions_rejected() {
        let svc = make_service();
        let url = create_queue_url(&svc, "perm-q2");
        let req = make_request(
            "AddPermission",
            json!({
                "QueueUrl": url,
                "Label": "L",
                "Actions": [],
                "AWSAccountIds": ["111111111111"]
            }),
        );
        assert_eq!(
            expect_err(svc.add_permission(&req)).code(),
            "MissingParameter"
        );
    }

    #[test]
    fn add_permission_rejects_owner_only_actions() {
        let svc = make_service();
        let url = create_queue_url(&svc, "perm-q3");
        let req = make_request(
            "AddPermission",
            json!({
                "QueueUrl": url,
                "Label": "L",
                "Actions": ["DeleteQueue"],
                "AWSAccountIds": ["111111111111"]
            }),
        );
        assert_eq!(
            expect_err(svc.add_permission(&req)).code(),
            "InvalidParameterValue"
        );
    }

    #[test]
    fn add_permission_rejects_duplicate_label() {
        let svc = make_service();
        let url = create_queue_url(&svc, "perm-q4");
        let add = make_request(
            "AddPermission",
            json!({
                "QueueUrl": url,
                "Label": "L",
                "Actions": ["SendMessage"],
                "AWSAccountIds": ["111111111111"]
            }),
        );
        svc.add_permission(&add).unwrap();
        assert_eq!(
            expect_err(svc.add_permission(&add)).code(),
            "InvalidParameterValue"
        );
    }

    #[test]
    fn remove_permission_unknown_label_errors() {
        let svc = make_service();
        let url = create_queue_url(&svc, "perm-q5");
        let req = make_request(
            "RemovePermission",
            json!({ "QueueUrl": url, "Label": "ghost" }),
        );
        assert_eq!(
            expect_err(svc.remove_permission(&req)).code(),
            "InvalidParameterValue"
        );
    }

    // ── DeleteMessageBatch ───────────────────────────────────────────

    #[test]
    fn delete_message_batch_removes_listed_messages() {
        let svc = make_service();
        let url = create_queue_url(&svc, "batch-del");
        send_msg_simple(&svc, &url, "a");
        send_msg_simple(&svc, &url, "b");

        let rt = tokio::runtime::Runtime::new().unwrap();
        let recv = rt
            .block_on(svc.receive_message(&make_request(
                "ReceiveMessage",
                json!({ "QueueUrl": url, "MaxNumberOfMessages": 2 }),
            )))
            .unwrap();
        let messages = body_json(recv)["Messages"].as_array().unwrap().clone();
        assert_eq!(messages.len(), 2);

        let entries: Vec<Value> = messages
            .iter()
            .enumerate()
            .map(|(i, m)| {
                json!({
                    "Id": format!("e{i}"),
                    "ReceiptHandle": m["ReceiptHandle"].as_str().unwrap(),
                })
            })
            .collect();

        let del = svc
            .delete_message_batch(&make_request(
                "DeleteMessageBatch",
                json!({ "QueueUrl": url, "Entries": entries }),
            ))
            .unwrap();
        let body = body_json(del);
        assert_eq!(body["Successful"].as_array().unwrap().len(), 2);
    }

    // ── ChangeMessageVisibilityBatch ─────────────────────────────────

    #[test]
    fn change_message_visibility_batch_updates_multiple() {
        let svc = make_service();
        let url = create_queue_url(&svc, "batch-vis");
        send_msg_simple(&svc, &url, "a");
        send_msg_simple(&svc, &url, "b");

        let rt = tokio::runtime::Runtime::new().unwrap();
        let recv = rt
            .block_on(svc.receive_message(&make_request(
                "ReceiveMessage",
                json!({ "QueueUrl": url, "MaxNumberOfMessages": 2 }),
            )))
            .unwrap();
        let messages = body_json(recv)["Messages"].as_array().unwrap().clone();

        let entries: Vec<Value> = messages
            .iter()
            .enumerate()
            .map(|(i, m)| {
                json!({
                    "Id": format!("e{i}"),
                    "ReceiptHandle": m["ReceiptHandle"].as_str().unwrap(),
                    "VisibilityTimeout": 300,
                })
            })
            .collect();

        let resp = svc
            .change_message_visibility_batch(&make_request(
                "ChangeMessageVisibilityBatch",
                json!({ "QueueUrl": url, "Entries": entries }),
            ))
            .unwrap();
        let body = body_json(resp);
        assert_eq!(body["Successful"].as_array().unwrap().len(), 2);
    }

    // ── ListDeadLetterSourceQueues ───────────────────────────────────

    #[test]
    fn list_dead_letter_source_queues_finds_sources() {
        let svc = make_service();
        let dlq_url = create_queue_url(&svc, "dlq");
        let dlq_arn = {
            let resp = svc
                .get_queue_attributes(&make_request(
                    "GetQueueAttributes",
                    json!({ "QueueUrl": dlq_url, "AttributeNames": ["QueueArn"] }),
                ))
                .unwrap();
            body_json(resp)["Attributes"]["QueueArn"]
                .as_str()
                .unwrap()
                .to_string()
        };

        // Create a source queue that points to the DLQ.
        let src_url = create_queue_url(&svc, "src-q");
        let redrive = json!({ "deadLetterTargetArn": dlq_arn, "maxReceiveCount": "3" }).to_string();
        svc.set_queue_attributes(&make_request(
            "SetQueueAttributes",
            json!({
                "QueueUrl": src_url,
                "Attributes": { "RedrivePolicy": redrive }
            }),
        ))
        .unwrap();

        let resp = svc
            .list_dead_letter_source_queues(&make_request(
                "ListDeadLetterSourceQueues",
                json!({ "QueueUrl": dlq_url }),
            ))
            .unwrap();
        let body = body_json(resp);
        let urls = body["queueUrls"].as_array().unwrap();
        assert_eq!(urls.len(), 1);
        assert!(urls[0].as_str().unwrap().contains("src-q"));
    }

    // ── Error branch tests ──

    #[test]
    fn get_queue_url_not_found() {
        let svc = make_service();
        let req = make_request("GetQueueUrl", json!({"QueueName": "ghost"}));
        let err = expect_err(svc.get_queue_url(&req));
        assert_eq!(err.code(), "QueueDoesNotExist");
    }

    #[test]
    fn delete_queue_not_found() {
        let svc = make_service();
        let req = make_request(
            "DeleteQueue",
            json!({"QueueUrl": "http://localhost/123/ghost"}),
        );
        let err = expect_err(svc.delete_queue(&req));
        assert_eq!(err.code(), "QueueDoesNotExist");
    }

    #[test]
    fn send_message_queue_not_found() {
        let svc = make_service();
        let req = make_request(
            "SendMessage",
            json!({"QueueUrl": "http://localhost/123/ghost", "MessageBody": "hi"}),
        );
        let err = expect_err(svc.send_message(&req));
        assert_eq!(err.code(), "QueueDoesNotExist");
    }

    #[tokio::test]
    async fn receive_message_queue_not_found() {
        let svc = make_service();
        let req = make_request(
            "ReceiveMessage",
            json!({"QueueUrl": "http://localhost/123/ghost"}),
        );
        let err = expect_err(svc.receive_message(&req).await);
        assert_eq!(err.code(), "QueueDoesNotExist");
    }

    #[test]
    fn get_queue_attributes_not_found() {
        let svc = make_service();
        let req = make_request(
            "GetQueueAttributes",
            json!({"QueueUrl": "http://localhost/123/ghost", "AttributeNames": ["All"]}),
        );
        let err = expect_err(svc.get_queue_attributes(&req));
        assert_eq!(err.code(), "QueueDoesNotExist");
    }

    #[test]
    fn set_queue_attributes_not_found() {
        let svc = make_service();
        let req = make_request(
            "SetQueueAttributes",
            json!({"QueueUrl": "http://localhost/123/ghost", "Attributes": {"VisibilityTimeout": "30"}}),
        );
        let err = expect_err(svc.set_queue_attributes(&req));
        assert_eq!(err.code(), "QueueDoesNotExist");
    }

    #[test]
    fn purge_queue_not_found() {
        let svc = make_service();
        let req = make_request(
            "PurgeQueue",
            json!({"QueueUrl": "http://localhost/123/ghost"}),
        );
        let err = expect_err(svc.purge_queue(&req));
        assert_eq!(err.code(), "QueueDoesNotExist");
    }

    #[test]
    fn tag_queue_not_found() {
        let svc = make_service();
        let req = make_request(
            "TagQueue",
            json!({"QueueUrl": "http://localhost/123/ghost", "Tags": {"k": "v"}}),
        );
        let err = expect_err(svc.tag_queue(&req));
        assert_eq!(err.code(), "QueueDoesNotExist");
    }

    #[test]
    fn untag_queue_not_found() {
        let svc = make_service();
        let req = make_request(
            "UntagQueue",
            json!({"QueueUrl": "http://localhost/123/ghost", "TagKeys": ["k"]}),
        );
        let err = expect_err(svc.untag_queue(&req));
        assert_eq!(err.code(), "QueueDoesNotExist");
    }

    #[test]
    fn list_queue_tags_not_found() {
        let svc = make_service();
        let req = make_request(
            "ListQueueTags",
            json!({"QueueUrl": "http://localhost/123/ghost"}),
        );
        let err = expect_err(svc.list_queue_tags(&req));
        assert_eq!(err.code(), "QueueDoesNotExist");
    }

    #[test]
    fn change_message_visibility_not_found() {
        let svc = make_service();
        let req = make_request(
            "ChangeMessageVisibility",
            json!({"QueueUrl": "http://localhost/123/ghost", "ReceiptHandle": "rh", "VisibilityTimeout": 30}),
        );
        let err = expect_err(svc.change_message_visibility(&req));
        assert_eq!(err.code(), "QueueDoesNotExist");
    }

    #[test]
    fn delete_message_queue_not_found() {
        let svc = make_service();
        let req = make_request(
            "DeleteMessage",
            json!({"QueueUrl": "http://localhost/123/ghost", "ReceiptHandle": "rh"}),
        );
        let err = expect_err(svc.delete_message(&req));
        assert_eq!(err.code(), "QueueDoesNotExist");
    }

    #[test]
    fn send_message_missing_body() {
        let svc = make_service();
        let url = create_queue(&svc, "mb-q");
        let req = make_request("SendMessage", json!({"QueueUrl": url}));
        let err = expect_err(svc.send_message(&req));
        assert_eq!(err.code(), "MissingParameter");
    }

    // ── FIFO queue lifecycle ──

    #[test]
    fn fifo_queue_create_and_send_with_group_id() {
        let svc = make_service();
        let req = make_request(
            "CreateQueue",
            json!({"QueueName": "test.fifo", "Attributes": {"FifoQueue": "true"}}),
        );
        let resp = svc.create_queue(&req).unwrap();
        let b = body_json(resp);
        let url = b["QueueUrl"].as_str().unwrap().to_string();

        let req = make_request(
            "SendMessage",
            json!({
                "QueueUrl": url,
                "MessageBody": "hi",
                "MessageGroupId": "g1",
                "MessageDeduplicationId": "d1",
            }),
        );
        svc.send_message(&req).unwrap();
    }

    #[test]
    fn fifo_queue_send_without_group_id_fails() {
        let svc = make_service();
        let req = make_request(
            "CreateQueue",
            json!({"QueueName": "fifo2.fifo", "Attributes": {"FifoQueue": "true"}}),
        );
        let resp = svc.create_queue(&req).unwrap();
        let b = body_json(resp);
        let url = b["QueueUrl"].as_str().unwrap().to_string();

        let req = make_request("SendMessage", json!({"QueueUrl": url, "MessageBody": "hi"}));
        assert!(svc.send_message(&req).is_err());
    }

    // ── Send message batch ──

    #[test]
    fn send_message_batch_happy_path() {
        let svc = make_service();
        let url = create_queue(&svc, "batch-q");

        let req = make_request(
            "SendMessageBatch",
            json!({
                "QueueUrl": url,
                "Entries": [
                    {"Id": "1", "MessageBody": "msg1"},
                    {"Id": "2", "MessageBody": "msg2"},
                    {"Id": "3", "MessageBody": "msg3"},
                ]
            }),
        );
        let resp = svc.send_message_batch(&req).unwrap();
        let b = body_json(resp);
        assert_eq!(b["Successful"].as_array().unwrap().len(), 3);
    }

    #[test]
    fn send_message_batch_queue_not_found() {
        let svc = make_service();
        let req = make_request(
            "SendMessageBatch",
            json!({
                "QueueUrl": "http://localhost/123/ghost",
                "Entries": [{"Id": "1", "MessageBody": "msg"}]
            }),
        );
        assert!(svc.send_message_batch(&req).is_err());
    }

    // ── Delete message batch ──

    #[tokio::test]
    async fn delete_message_batch_removes_messages() {
        let svc = make_service();
        let url = create_queue(&svc, "del-batch-q");

        send_msg_simple(&svc, &url, "msg1");
        send_msg_simple(&svc, &url, "msg2");

        let req = make_request(
            "ReceiveMessage",
            json!({"QueueUrl": url, "MaxNumberOfMessages": 10}),
        );
        let resp = svc.receive_message(&req).await.unwrap();
        let b = body_json(resp);
        let messages = b["Messages"].as_array().unwrap();

        let entries: Vec<Value> = messages
            .iter()
            .enumerate()
            .map(|(i, m)| {
                json!({"Id": format!("d{i}"), "ReceiptHandle": m["ReceiptHandle"].clone()})
            })
            .collect();

        let req = make_request(
            "DeleteMessageBatch",
            json!({"QueueUrl": url, "Entries": entries}),
        );
        let resp = svc.delete_message_batch(&req).unwrap();
        let b = body_json(resp);
        assert_eq!(b["Successful"].as_array().unwrap().len(), 2);
    }

    // ── Change message visibility batch ──

    #[tokio::test]
    async fn change_message_visibility_batch_happy() {
        let svc = make_service();
        let url = create_queue(&svc, "cmvb-q");
        send_msg_simple(&svc, &url, "msg1");

        let req = make_request(
            "ReceiveMessage",
            json!({"QueueUrl": url, "MaxNumberOfMessages": 1}),
        );
        let resp = svc.receive_message(&req).await.unwrap();
        let b = body_json(resp);
        let rh = b["Messages"][0]["ReceiptHandle"]
            .as_str()
            .unwrap()
            .to_string();

        let req = make_request(
            "ChangeMessageVisibilityBatch",
            json!({
                "QueueUrl": url,
                "Entries": [{"Id": "1", "ReceiptHandle": rh, "VisibilityTimeout": 60}]
            }),
        );
        let resp = svc.change_message_visibility_batch(&req).unwrap();
        let b = body_json(resp);
        assert_eq!(b["Successful"].as_array().unwrap().len(), 1);
    }

    // ── Permissions ──

    #[test]
    fn add_and_remove_permission() {
        let svc = make_service();
        let url = create_queue(&svc, "perm-q");

        let req = make_request(
            "AddPermission",
            json!({
                "QueueUrl": url,
                "Label": "AllowAll",
                "AWSAccountIds": ["123456789012"],
                "Actions": ["ReceiveMessage"]
            }),
        );
        svc.add_permission(&req).unwrap();

        let req = make_request(
            "RemovePermission",
            json!({"QueueUrl": url, "Label": "AllowAll"}),
        );
        svc.remove_permission(&req).unwrap();
    }

    #[test]
    fn add_permission_empty_actions_list_errors() {
        let svc = make_service();
        let url = create_queue(&svc, "perm-empty-q");

        let req = make_request(
            "AddPermission",
            json!({
                "QueueUrl": url,
                "Label": "L",
                "AWSAccountIds": ["123"],
                "Actions": []
            }),
        );
        assert!(svc.add_permission(&req).is_err());
    }

    // ── Visibility timeout change ──

    #[tokio::test]
    async fn change_message_visibility_updates() {
        let svc = make_service();
        let url = create_queue(&svc, "cmv-q");
        send_msg_simple(&svc, &url, "msg1");

        let req = make_request(
            "ReceiveMessage",
            json!({"QueueUrl": url, "MaxNumberOfMessages": 1}),
        );
        let resp = svc.receive_message(&req).await.unwrap();
        let b = body_json(resp);
        let rh = b["Messages"][0]["ReceiptHandle"]
            .as_str()
            .unwrap()
            .to_string();

        let req = make_request(
            "ChangeMessageVisibility",
            json!({"QueueUrl": url, "ReceiptHandle": rh, "VisibilityTimeout": 120}),
        );
        svc.change_message_visibility(&req).unwrap();
    }

    // ── Message attributes ──

    #[tokio::test]
    async fn send_and_receive_message_with_attributes() {
        let svc = make_service();
        let url = create_queue(&svc, "attr-q");

        let req = make_request(
            "SendMessage",
            json!({
                "QueueUrl": url,
                "MessageBody": "hello",
                "MessageAttributes": {
                    "color": {"DataType": "String", "StringValue": "blue"},
                    "count": {"DataType": "Number", "StringValue": "42"}
                }
            }),
        );
        svc.send_message(&req).unwrap();

        let req = make_request(
            "ReceiveMessage",
            json!({
                "QueueUrl": url,
                "MessageAttributeNames": ["All"],
                "MaxNumberOfMessages": 1
            }),
        );
        let resp = svc.receive_message(&req).await.unwrap();
        let b = body_json(resp);
        let msg = &b["Messages"][0];
        assert!(msg["MessageAttributes"].is_object());
    }

    // ── Delay ──

    #[test]
    fn send_message_with_delay() {
        let svc = make_service();
        let url = create_queue(&svc, "delay-q");

        let req = make_request(
            "SendMessage",
            json!({"QueueUrl": url, "MessageBody": "delayed", "DelaySeconds": 10}),
        );
        svc.send_message(&req).unwrap();
    }

    // ── Redrive policy ──

    #[test]
    fn set_redrive_policy_attribute() {
        let svc = make_service();
        let dlq_url = create_queue(&svc, "dlq");
        let url = create_queue(&svc, "main-q");

        let req = make_request(
            "GetQueueAttributes",
            json!({"QueueUrl": dlq_url, "AttributeNames": ["QueueArn"]}),
        );
        let resp = svc.get_queue_attributes(&req).unwrap();
        let b = body_json(resp);
        let dlq_arn = b["Attributes"]["QueueArn"].as_str().unwrap().to_string();

        let redrive =
            serde_json::json!({"deadLetterTargetArn": dlq_arn, "maxReceiveCount": 3}).to_string();
        let req = make_request(
            "SetQueueAttributes",
            json!({
                "QueueUrl": url,
                "Attributes": {"RedrivePolicy": redrive}
            }),
        );
        svc.set_queue_attributes(&req).unwrap();
    }

    // ── create queue validation branches ──

    #[test]
    fn create_queue_name_too_long() {
        let svc = make_service();
        let name = "x".repeat(81);
        let req = make_request("CreateQueue", json!({"QueueName": name}));
        expect_err(svc.create_queue(&req));
    }

    #[test]
    fn create_queue_name_empty() {
        let svc = make_service();
        let req = make_request("CreateQueue", json!({"QueueName": ""}));
        expect_err(svc.create_queue(&req));
    }

    #[test]
    fn create_queue_invalid_chars() {
        let svc = make_service();
        let req = make_request("CreateQueue", json!({"QueueName": "bad name"}));
        expect_err(svc.create_queue(&req));
    }

    #[test]
    fn create_queue_fifo_without_suffix() {
        let svc = make_service();
        let req = make_request(
            "CreateQueue",
            json!({
                "QueueName": "plain",
                "Attributes": {"FifoQueue": "true"}
            }),
        );
        expect_err(svc.create_queue(&req));
    }

    #[test]
    fn create_queue_invalid_max_message_size() {
        let svc = make_service();
        let req = make_request(
            "CreateQueue",
            json!({
                "QueueName": "mms",
                "Attributes": {"MaximumMessageSize": "100"}
            }),
        );
        expect_err(svc.create_queue(&req));
    }

    #[test]
    fn create_queue_invalid_delay_seconds() {
        let svc = make_service();
        let req = make_request(
            "CreateQueue",
            json!({
                "QueueName": "ds",
                "Attributes": {"DelaySeconds": "10000"}
            }),
        );
        expect_err(svc.create_queue(&req));
    }

    // ── send_message error branches ──

    #[test]
    fn send_message_missing_queue_url() {
        let svc = make_service();
        let req = make_request("SendMessage", json!({"MessageBody": "hi"}));
        expect_err(svc.send_message(&req));
    }

    #[test]
    fn send_message_queue_not_found_detailed() {
        let svc = make_service();
        let req = make_request(
            "SendMessage",
            json!({
                "QueueUrl": "http://localhost:4566/123456789012/ghost",
                "MessageBody": "hi"
            }),
        );
        expect_err(svc.send_message(&req));
    }

    #[test]
    fn send_message_invalid_delay_seconds() {
        let svc = make_service();
        let req = make_request("CreateQueue", json!({"QueueName": "d"}));
        let resp = svc.create_queue(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let url = body["QueueUrl"].as_str().unwrap().to_string();
        let req = make_request(
            "SendMessage",
            json!({
                "QueueUrl": url,
                "MessageBody": "hi",
                "DelaySeconds": 9999
            }),
        );
        expect_err(svc.send_message(&req));
    }

    // ── change_message_visibility error branches ──

    #[test]
    fn change_message_visibility_over_max_errors() {
        let svc = make_service();
        let req = make_request("CreateQueue", json!({"QueueName": "cmv"}));
        let resp = svc.create_queue(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let url = body["QueueUrl"].as_str().unwrap().to_string();
        let req = make_request(
            "ChangeMessageVisibility",
            json!({
                "QueueUrl": url,
                "ReceiptHandle": "bogus",
                "VisibilityTimeout": 99999
            }),
        );
        expect_err(svc.change_message_visibility(&req));
    }

    // ── delete_message ──

    #[test]
    fn delete_message_missing_receipt_errors() {
        let svc = make_service();
        let req = make_request("CreateQueue", json!({"QueueName": "dm"}));
        let resp = svc.create_queue(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        let url = body["QueueUrl"].as_str().unwrap().to_string();
        let req = make_request("DeleteMessage", json!({"QueueUrl": url}));
        expect_err(svc.delete_message(&req));
    }

    // ── get_queue_attributes ──

    #[test]
    fn get_queue_attributes_filtered_by_names() {
        let svc = make_service();
        svc.create_queue(&make_request("CreateQueue", json!({"QueueName": "filt"})))
            .unwrap();
        let req = make_request(
            "GetQueueAttributes",
            json!({
                "QueueUrl": "http://localhost:4566/123456789012/filt",
                "AttributeNames": ["VisibilityTimeout"]
            }),
        );
        let resp = svc.get_queue_attributes(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        assert!(body["Attributes"]["VisibilityTimeout"].is_string());
        assert!(body["Attributes"]["MessageRetentionPeriod"].is_null());
    }

    // ── set_queue_attributes error branches ──

    // ── list_queues pagination/prefix ──

    #[test]
    fn list_queues_by_prefix_pagination() {
        let svc = make_service();
        for i in 0..10 {
            svc.create_queue(&make_request(
                "CreateQueue",
                json!({"QueueName": format!("pfx-{i}")}),
            ))
            .unwrap();
        }
        svc.create_queue(&make_request("CreateQueue", json!({"QueueName": "other"})))
            .unwrap();
        let req = make_request(
            "ListQueues",
            json!({"QueueNamePrefix": "pfx-", "MaxResults": 3}),
        );
        let resp = svc.list_queues(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        assert_eq!(body["QueueUrls"].as_array().unwrap().len(), 3);
        assert!(body["NextToken"].is_string());
    }

    // ── tag_queue errors ──

    #[test]
    fn tag_queue_missing_url_errors() {
        let svc = make_service();
        let req = make_request("TagQueue", json!({"Tags": {"env": "prod"}}));
        expect_err(svc.tag_queue(&req));
    }

    // ── fifo queue specific errors ──

    #[test]
    fn send_to_fifo_without_dedup_id_and_no_content_dedup_errors() {
        let svc = make_service();
        svc.create_queue(&make_request(
            "CreateQueue",
            json!({
                "QueueName": "nd.fifo",
                "Attributes": {"FifoQueue": "true"}
            }),
        ))
        .unwrap();
        let req = make_request(
            "SendMessage",
            json!({
                "QueueUrl": "http://localhost:4566/123456789012/nd.fifo",
                "MessageBody": "m",
                "MessageGroupId": "g1"
            }),
        );
        expect_err(svc.send_message(&req));
    }

    // ── purge queue ──

    #[test]
    fn purge_queue_missing_url_errors() {
        let svc = make_service();
        let req = make_request("PurgeQueue", json!({}));
        expect_err(svc.purge_queue(&req));
    }

    // ── delete_message_batch ──

    #[test]
    fn delete_message_batch_empty_errors() {
        let svc = make_service();
        svc.create_queue(&make_request("CreateQueue", json!({"QueueName": "dmb"})))
            .unwrap();
        let req = make_request(
            "DeleteMessageBatch",
            json!({
                "QueueUrl": "http://localhost:4566/123456789012/dmb",
                "Entries": []
            }),
        );
        expect_err(svc.delete_message_batch(&req));
    }

    // ── list_dead_letter_source_queues nonexistent ──

    #[test]
    fn list_dead_letter_source_queues_nonexistent_ok() {
        let svc = make_service();
        svc.create_queue(&make_request("CreateQueue", json!({"QueueName": "dlq"})))
            .unwrap();
        let req = make_request(
            "ListDeadLetterSourceQueues",
            json!({"QueueUrl": "http://localhost:4566/123456789012/dlq"}),
        );
        let resp = svc.list_dead_letter_source_queues(&req).unwrap();
        let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
        assert!(body["queueUrls"].as_array().unwrap().is_empty());
    }

    #[test]
    fn purge_queue_unknown_queue_errors() {
        let svc = make_service();
        let req = make_request(
            "PurgeQueue",
            json!({"QueueUrl": "http://localhost:4566/123456789012/ghost"}),
        );
        assert!(svc.purge_queue(&req).is_err());
    }

    #[test]
    fn get_queue_url_missing_name_errors() {
        let svc = make_service();
        let req = make_request("GetQueueUrl", json!({}));
        assert!(svc.get_queue_url(&req).is_err());
    }

    #[test]
    fn get_queue_attributes_missing_url_errors() {
        let svc = make_service();
        let req = make_request("GetQueueAttributes", json!({}));
        assert!(svc.get_queue_attributes(&req).is_err());
    }

    #[test]
    fn set_queue_attributes_missing_url_errors() {
        let svc = make_service();
        let req = make_request(
            "SetQueueAttributes",
            json!({"Attributes": {"VisibilityTimeout": "60"}}),
        );
        assert!(svc.set_queue_attributes(&req).is_err());
    }

    #[test]
    fn remove_permission_unknown_queue_errors() {
        let svc = make_service();
        let req = make_request(
            "RemovePermission",
            json!({
                "QueueUrl": "http://localhost:4566/123456789012/ghost",
                "Label": "l"
            }),
        );
        assert!(svc.remove_permission(&req).is_err());
    }

    #[test]
    fn untag_queue_missing_url_errors() {
        let svc = make_service();
        let req = make_request("UntagQueue", json!({"TagKeys": ["k"]}));
        assert!(svc.untag_queue(&req).is_err());
    }

    fn make_query_request(action: &str, params: &[(&str, &str)]) -> AwsRequest {
        let mut qp = HashMap::new();
        for (k, v) in params {
            qp.insert(k.to_string(), v.to_string());
        }
        AwsRequest {
            service: "sqs".to_string(),
            action: action.to_string(),
            region: "us-east-1".to_string(),
            account_id: "123456789012".to_string(),
            request_id: "test-id".to_string(),
            headers: http::HeaderMap::new(),
            query_params: qp,
            body: Vec::<u8>::new().into(),
            path_segments: vec![],
            raw_path: "/".to_string(),
            raw_query: String::new(),
            method: http::Method::POST,
            is_query_protocol: true,
            access_key_id: None,
            principal: None,
        }
    }

    fn create_dlq_with_source(svc: &SqsService, dlq_name: &str, src_name: &str) -> String {
        let dlq_url = create_queue_url(svc, dlq_name);
        let dlq_arn = body_json(
            svc.get_queue_attributes(&make_request(
                "GetQueueAttributes",
                json!({ "QueueUrl": dlq_url, "AttributeNames": ["QueueArn"] }),
            ))
            .unwrap(),
        )["Attributes"]["QueueArn"]
            .as_str()
            .unwrap()
            .to_string();
        let src_url = create_queue_url(svc, src_name);
        let redrive = json!({ "deadLetterTargetArn": dlq_arn, "maxReceiveCount": "1" }).to_string();
        svc.set_queue_attributes(&make_request(
            "SetQueueAttributes",
            json!({
                "QueueUrl": src_url,
                "Attributes": { "RedrivePolicy": redrive }
            }),
        ))
        .unwrap();
        dlq_arn
    }

    #[tokio::test]
    async fn start_message_move_task_query_protocol_parses_string_rate() {
        let svc = make_service();
        let dlq_arn = create_dlq_with_source(&svc, "qp-dlq", "qp-src");
        // Query protocol passes integers as strings; this should parse fine.
        // The rate-bound path spawns a background mover, so this test runs
        // on the tokio runtime.
        let req = make_query_request(
            "StartMessageMoveTask",
            &[
                ("SourceArn", dlq_arn.as_str()),
                ("MaxNumberOfMessagesPerSecond", "100"),
            ],
        );
        let resp = svc.start_message_move_task(&req).unwrap();
        assert!(resp.status.is_success());
    }

    #[test]
    fn start_message_move_task_rejects_out_of_range_rate() {
        let svc = make_service();
        let dlq_arn = create_dlq_with_source(&svc, "oor-dlq", "oor-src");
        let req = make_request(
            "StartMessageMoveTask",
            json!({
                "SourceArn": dlq_arn,
                "MaxNumberOfMessagesPerSecond": 0
            }),
        );
        let err = expect_err(svc.start_message_move_task(&req));
        assert_eq!(err.code(), "InvalidParameterValue");

        let req = make_request(
            "StartMessageMoveTask",
            json!({
                "SourceArn": dlq_arn,
                "MaxNumberOfMessagesPerSecond": 501
            }),
        );
        let err = expect_err(svc.start_message_move_task(&req));
        assert_eq!(err.code(), "InvalidParameterValue");
    }

    #[test]
    fn start_message_move_task_rejects_non_dlq_source() {
        let svc = make_service();
        let q_url = create_queue_url(&svc, "lonely");
        let q_arn = body_json(
            svc.get_queue_attributes(&make_request(
                "GetQueueAttributes",
                json!({ "QueueUrl": q_url, "AttributeNames": ["QueueArn"] }),
            ))
            .unwrap(),
        )["Attributes"]["QueueArn"]
            .as_str()
            .unwrap()
            .to_string();
        let req = make_request("StartMessageMoveTask", json!({ "SourceArn": q_arn }));
        let err = expect_err(svc.start_message_move_task(&req));
        assert_eq!(err.code(), "AWS.SimpleQueueService.UnsupportedOperation");
    }

    #[test]
    fn start_message_move_task_rejects_unknown_source() {
        let svc = make_service();
        let req = make_request(
            "StartMessageMoveTask",
            json!({ "SourceArn": "arn:aws:sqs:us-east-1:123456789012:ghost" }),
        );
        let err = expect_err(svc.start_message_move_task(&req));
        assert_eq!(err.code(), "ResourceNotFoundException");
    }

    #[test]
    fn list_message_move_tasks_query_protocol_caps_max_results() {
        let svc = make_service();
        let dlq_arn = create_dlq_with_source(&svc, "lmmt-dlq2", "lmmt-src2");
        // Start a task so there's something to list.
        svc.start_message_move_task(&make_request(
            "StartMessageMoveTask",
            json!({ "SourceArn": dlq_arn }),
        ))
        .unwrap();
        // Query protocol: MaxResults arrives as string. Helper must parse it.
        let req = make_query_request(
            "ListMessageMoveTasks",
            &[("SourceArn", dlq_arn.as_str()), ("MaxResults", "5")],
        );
        let resp = svc.list_message_move_tasks(&req).unwrap();
        assert!(resp.status.is_success());
    }

    #[test]
    fn list_message_move_tasks_rejects_unknown_source() {
        let svc = make_service();
        let req = make_request(
            "ListMessageMoveTasks",
            json!({ "SourceArn": "arn:aws:sqs:us-east-1:123456789012:nope" }),
        );
        let err = expect_err(svc.list_message_move_tasks(&req));
        assert_eq!(err.code(), "ResourceNotFoundException");
    }

    #[test]
    fn cancel_message_move_task_unknown_handle_errors() {
        let svc = make_service();
        let req = make_request(
            "CancelMessageMoveTask",
            json!({ "TaskHandle": "no-such-task" }),
        );
        let err = expect_err(svc.cancel_message_move_task(&req));
        assert_eq!(err.code(), "ResourceNotFoundException");
    }

    #[test]
    fn cancel_message_move_task_completed_task_errors() {
        let svc = make_service();
        let dlq_arn = create_dlq_with_source(&svc, "cmmt-dlq", "cmmt-src");
        let resp = svc
            .start_message_move_task(&make_request(
                "StartMessageMoveTask",
                json!({ "SourceArn": dlq_arn }),
            ))
            .unwrap();
        let handle = body_json(resp)["TaskHandle"].as_str().unwrap().to_string();
        let req = make_request("CancelMessageMoveTask", json!({ "TaskHandle": handle }));
        let err = expect_err(svc.cancel_message_move_task(&req));
        assert_eq!(err.code(), "AWS.SimpleQueueService.UnsupportedOperation");
    }

    #[test]
    fn val_as_i64_handles_number_and_string() {
        assert_eq!(val_as_i64(&json!(42)), Some(42));
        assert_eq!(val_as_i64(&json!("42")), Some(42));
        assert_eq!(val_as_i64(&json!("not-int")), None);
        assert_eq!(val_as_i64(&json!(null)), None);
    }

    #[test]
    fn start_message_move_task_drains_to_explicit_destination() {
        let svc = make_service();
        let dlq_arn = create_dlq_with_source(&svc, "drain-dlq", "drain-src");
        // Pre-stage a couple of messages on the DLQ.
        let dlq_url = body_json(
            svc.get_queue_url(&make_request(
                "GetQueueUrl",
                json!({ "QueueName": "drain-dlq" }),
            ))
            .unwrap(),
        )["QueueUrl"]
            .as_str()
            .unwrap()
            .to_string();
        for body in ["m1", "m2"] {
            svc.send_message(&make_request(
                "SendMessage",
                json!({ "QueueUrl": &dlq_url, "MessageBody": body }),
            ))
            .unwrap();
        }
        // Make a custom destination queue and grab its ARN.
        let dest_url = create_queue_url(&svc, "drain-dest");
        let dest_arn = body_json(
            svc.get_queue_attributes(&make_request(
                "GetQueueAttributes",
                json!({ "QueueUrl": dest_url, "AttributeNames": ["QueueArn"] }),
            ))
            .unwrap(),
        )["Attributes"]["QueueArn"]
            .as_str()
            .unwrap()
            .to_string();
        let resp = svc
            .start_message_move_task(&make_request(
                "StartMessageMoveTask",
                json!({ "SourceArn": dlq_arn, "DestinationArn": dest_arn }),
            ))
            .unwrap();
        assert!(body_json(resp)["TaskHandle"].as_str().is_some());
        // Verify destination queue received both messages.
        let runtime = tokio::runtime::Runtime::new().unwrap();
        let recv = runtime
            .block_on(svc.receive_message(&make_request(
                "ReceiveMessage",
                json!({ "QueueUrl": dest_url, "MaxNumberOfMessages": 10 }),
            )))
            .unwrap();
        let body = body_json(recv);
        assert_eq!(body["Messages"].as_array().map(|a| a.len()).unwrap_or(0), 2);
    }

    #[test]
    fn start_message_move_task_unknown_destination_errors() {
        let svc = make_service();
        let dlq_arn = create_dlq_with_source(&svc, "ud-dlq", "ud-src");
        let req = make_request(
            "StartMessageMoveTask",
            json!({
                "SourceArn": dlq_arn,
                "DestinationArn": "arn:aws:sqs:us-east-1:123456789012:no-such-dest"
            }),
        );
        let err = expect_err(svc.start_message_move_task(&req));
        assert_eq!(err.code(), "ResourceNotFoundException");
    }

    #[test]
    fn start_message_move_task_blocks_concurrent_running() {
        let svc = make_service();
        let dlq_arn = create_dlq_with_source(&svc, "conc-dlq", "conc-src");
        // First call completes synchronously (Completed). To exercise the
        // "already running" guard, force a Running entry directly.
        {
            let mut accounts = svc.state.write();
            let state = accounts.get_or_create("123456789012");
            state.message_move_tasks.push(MessageMoveTask {
                task_handle: "FakeCloudMessageMoveTask-running".to_string(),
                source_arn: dlq_arn.clone(),
                destination_arn: None,
                max_messages_per_second: None,
                status: MessageMoveTaskStatus::Running,
                messages_moved: 0,
                messages_to_move: 0,
                started_timestamp: 0,
                failure_reason: None,
                cancel_flag: Arc::new(AtomicBool::new(false)),
            });
        }
        let req = make_request("StartMessageMoveTask", json!({ "SourceArn": dlq_arn }));
        let err = expect_err(svc.start_message_move_task(&req));
        assert_eq!(err.code(), "AWS.SimpleQueueService.UnsupportedOperation");
    }

    #[test]
    fn cancel_message_move_task_cancels_running() {
        let svc = make_service();
        // Insert a Running task; cancellation should succeed and report
        // ApproximateNumberOfMessagesMoved.
        {
            let mut accounts = svc.state.write();
            let state = accounts.get_or_create("123456789012");
            state.message_move_tasks.push(MessageMoveTask {
                task_handle: "running-handle".to_string(),
                source_arn: "arn:aws:sqs:us-east-1:123456789012:src".to_string(),
                destination_arn: None,
                max_messages_per_second: None,
                status: MessageMoveTaskStatus::Running,
                messages_moved: 7,
                messages_to_move: 10,
                started_timestamp: 0,
                failure_reason: None,
                cancel_flag: Arc::new(AtomicBool::new(false)),
            });
        }
        let resp = svc
            .cancel_message_move_task(&make_request(
                "CancelMessageMoveTask",
                json!({ "TaskHandle": "running-handle" }),
            ))
            .unwrap();
        let body = body_json(resp);
        assert_eq!(
            body["ApproximateNumberOfMessagesMoved"].as_u64().unwrap(),
            7
        );
    }

    #[test]
    fn list_message_move_tasks_caps_at_max_and_excludes_running_handle() {
        let svc = make_service();
        let dlq_arn = create_dlq_with_source(&svc, "cap-dlq", "cap-src");
        // Insert 12 tasks; ListMessageMoveTasks should cap MaxResults at 10.
        {
            let mut accounts = svc.state.write();
            let state = accounts.get_or_create("123456789012");
            for i in 0..12 {
                state.message_move_tasks.push(MessageMoveTask {
                    task_handle: format!("h{i}"),
                    source_arn: dlq_arn.clone(),
                    destination_arn: None,
                    max_messages_per_second: None,
                    status: MessageMoveTaskStatus::Completed,
                    messages_moved: 0,
                    messages_to_move: 0,
                    started_timestamp: i,
                    failure_reason: None,
                    cancel_flag: Arc::new(AtomicBool::new(false)),
                });
            }
        }
        let req = make_request(
            "ListMessageMoveTasks",
            json!({ "SourceArn": dlq_arn, "MaxResults": 50 }),
        );
        let body = body_json(svc.list_message_move_tasks(&req).unwrap());
        assert_eq!(body["Results"].as_array().unwrap().len(), 10);
        // Completed tasks must not include TaskHandle (per AWS docs).
        for r in body["Results"].as_array().unwrap() {
            assert!(r.get("TaskHandle").is_none());
        }
    }

    #[test]
    fn send_message_batch_over_max_entries_errors() {
        let svc = make_service();
        svc.create_queue(&make_request("CreateQueue", json!({"QueueName": "smbo"})))
            .unwrap();
        let mut entries = Vec::new();
        for i in 0..15 {
            entries.push(json!({"Id": format!("e{i}"), "MessageBody": "x"}));
        }
        let req = make_request(
            "SendMessageBatch",
            json!({
                "QueueUrl": "http://localhost:4566/123456789012/smbo",
                "Entries": entries
            }),
        );
        assert!(svc.send_message_batch(&req).is_err());
    }
}
