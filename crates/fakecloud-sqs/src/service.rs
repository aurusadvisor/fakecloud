use async_trait::async_trait;
use chrono::Utc;
use http::StatusCode;
use md5::Md5;
use serde_json::{json, Value};
use sha2::Sha256;
use std::collections::{BTreeMap, HashMap, VecDeque};
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

/// Names of queue attributes whose stored value is a JSON document.
/// We canonicalize these to compact JSON on write so the round-trip
/// through `GetQueueAttributes` matches what Terraform's `jsonencode`
/// emits — real AWS SQS canonicalizes the same way server-side.
const JSON_VALUED_ATTRS: &[&str] = &["Policy", "RedrivePolicy", "RedriveAllowPolicy"];

/// Per-queue configuration used while processing a SendMessageBatch,
/// read once outside the per-entry loop.
pub(crate) struct BatchSendConfig {
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

pub(crate) enum BatchEntryOutcome {
    Success(Value),
    Failure(Value),
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
        Some(
            queue
                .tags
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        )
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

use fakecloud_aws::xml::xml_escape;
use fakecloud_core::query::{query_metadata_only_xml, query_response_xml};

const SQS_NS: &str = "http://queue.amazonaws.com/doc/2012-11-05/";

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

        let mut new_attributes = BTreeMap::new();
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

        let mut attributes = BTreeMap::new();
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
        let mut tags = BTreeMap::new();
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
            dedup_cache: BTreeMap::new(),
            redrive_policy,
            tags,
            next_sequence_number: 0,
            permission_labels: Vec::new(),
            receipt_handle_map: BTreeMap::new(),
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
        let md5_of_system_attrs = if system_attributes.is_empty() {
            None
        } else {
            Some(md5_of_message_system_attributes(&system_attributes))
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
                        if let Some(ref md5) = md5_of_system_attrs {
                            resp["MD5OfMessageSystemAttributes"] = json!(md5);
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
        if let Some(md5) = &md5_of_system_attrs {
            resp["MD5OfMessageSystemAttributes"] = json!(md5);
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

#[path = "helpers.rs"]
mod helpers;
pub(crate) use helpers::*;

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
