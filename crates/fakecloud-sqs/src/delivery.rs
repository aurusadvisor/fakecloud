use std::collections::{BTreeMap, HashMap};

use base64::Engine;
use chrono::Utc;

use fakecloud_core::delivery::{SqsDelivery, SqsDeliveryError, SqsMessageAttribute};

use crate::state::{MessageAttribute, SharedSqsState, SqsMessage};

/// Implements SqsDelivery so other services can push messages into SQS queues.
pub struct SqsDeliveryImpl {
    state: SharedSqsState,
}

impl SqsDeliveryImpl {
    pub fn new(state: SharedSqsState) -> Self {
        Self { state }
    }
}

impl SqsDelivery for SqsDeliveryImpl {
    fn deliver_to_queue(
        &self,
        queue_arn: &str,
        message_body: &str,
        _attributes: &HashMap<String, String>,
    ) {
        self.deliver_to_queue_with_attrs(queue_arn, message_body, &HashMap::new(), None, None);
    }

    fn deliver_to_queue_with_attrs(
        &self,
        queue_arn: &str,
        message_body: &str,
        message_attributes: &HashMap<String, SqsMessageAttribute>,
        message_group_id: Option<&str>,
        message_dedup_id: Option<&str>,
    ) {
        if let Err(err) = self.try_deliver_to_queue_with_attrs(
            queue_arn,
            message_body,
            message_attributes,
            message_group_id,
            message_dedup_id,
        ) {
            tracing::warn!(%err, queue_arn, "SQS delivery failed");
        }
    }

    fn try_deliver_to_queue_with_attrs(
        &self,
        queue_arn: &str,
        message_body: &str,
        message_attributes: &HashMap<String, SqsMessageAttribute>,
        message_group_id: Option<&str>,
        message_dedup_id: Option<&str>,
    ) -> Result<(), SqsDeliveryError> {
        let mut accounts = self.state.write();

        // Parse account from queue ARN (arn:aws:sqs:region:ACCOUNT:name)
        let default_id = accounts.default_account_id().to_string();
        let target_account = queue_arn
            .split(':')
            .nth(4)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| SqsDeliveryError::InvalidArn(queue_arn.to_string()))?
            .to_string();
        let target_account = if target_account.is_empty() {
            default_id
        } else {
            target_account
        };
        let state = accounts.get_or_create(&target_account);

        // Find queue by ARN
        let queue = state
            .queues
            .values_mut()
            .find(|q| q.arn == queue_arn)
            .ok_or_else(|| SqsDeliveryError::QueueNotFound(queue_arn.to_string()))?;

        // For FIFO queues without content-based dedup, require explicit dedup ID
        if queue.is_fifo && message_dedup_id.is_none() {
            let content_based = queue
                .attributes
                .get("ContentBasedDeduplication")
                .map(|v| v.as_str())
                == Some("true");
            if !content_based {
                tracing::debug!(
                    queue_arn,
                    "skipping delivery: FIFO queue requires dedup ID or content-based dedup"
                );
                return Ok(());
            }
        }

        let now = Utc::now();

        let effective_dedup_id = if message_dedup_id.is_some() {
            message_dedup_id.map(|s| s.to_string())
        } else if queue.is_fifo {
            Some(crate::service::sha256_hex(message_body))
        } else {
            None
        };

        let sqs_attrs: BTreeMap<String, MessageAttribute> = message_attributes
            .iter()
            .map(|(k, v)| {
                (
                    k.clone(),
                    MessageAttribute {
                        data_type: v.data_type.clone(),
                        string_value: v.string_value.clone(),
                        binary_value: v
                            .binary_value
                            .as_ref()
                            .and_then(|s| base64::engine::general_purpose::STANDARD.decode(s).ok()),
                    },
                )
            })
            .collect();

        let msg = SqsMessage {
            message_id: uuid::Uuid::new_v4().to_string(),
            receipt_handle: None,
            md5_of_body: crate::service::md5_hex(message_body),
            body: message_body.to_string(),
            sent_timestamp: now.timestamp_millis(),
            attributes: BTreeMap::new(),
            message_attributes: sqs_attrs,
            visible_at: None,
            receive_count: 0,
            message_group_id: message_group_id.map(|s| s.to_string()),
            message_dedup_id: effective_dedup_id,
            created_at: now,
            sequence_number: None,
        };
        queue.messages.push_back(msg);
        tracing::debug!(queue_arn, "delivered message to SQS queue");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{SharedSqsState, SqsQueue, SqsState};
    use chrono::Utc;
    use fakecloud_core::multi_account::MultiAccountState;
    use parking_lot::RwLock;
    use std::collections::VecDeque;
    use std::sync::Arc;

    const ACCOUNT: &str = "123456789012";
    const REGION: &str = "us-east-1";
    const ENDPOINT: &str = "http://localhost:4566";

    fn make_queue(name: &str, is_fifo: bool, content_based_dedup: bool) -> SqsQueue {
        let mut attributes = BTreeMap::new();
        if content_based_dedup {
            attributes.insert("ContentBasedDeduplication".to_string(), "true".to_string());
        }
        SqsQueue {
            queue_name: name.to_string(),
            queue_url: format!("{ENDPOINT}/{ACCOUNT}/{name}"),
            arn: format!("arn:aws:sqs:{REGION}:{ACCOUNT}:{name}"),
            created_at: Utc::now(),
            messages: VecDeque::new(),
            inflight: Vec::new(),
            attributes,
            is_fifo,
            dedup_cache: BTreeMap::new(),
            redrive_policy: None,
            tags: BTreeMap::new(),
            next_sequence_number: 0,
            permission_labels: Vec::new(),
            receipt_handle_map: BTreeMap::new(),
        }
    }

    fn make_state_with_queue(queue: SqsQueue) -> SharedSqsState {
        let mut multi: MultiAccountState<SqsState> =
            MultiAccountState::new(ACCOUNT, REGION, ENDPOINT);
        let state = multi.default_mut();
        state
            .name_to_url
            .insert(queue.queue_name.clone(), queue.queue_url.clone());
        state.queues.insert(queue.queue_url.clone(), queue);
        Arc::new(RwLock::new(multi))
    }

    #[test]
    fn deliver_to_queue_pushes_message() {
        let queue = make_queue("standard", false, false);
        let arn = queue.arn.clone();
        let url = queue.queue_url.clone();
        let state = make_state_with_queue(queue);
        let delivery = SqsDeliveryImpl::new(state.clone());
        delivery.deliver_to_queue(&arn, "hello", &HashMap::new());
        let guard = state.read();
        let q = guard.default_ref().queues.get(&url).unwrap();
        assert_eq!(q.messages.len(), 1);
        let msg = q.messages.front().unwrap();
        assert_eq!(msg.body, "hello");
        assert!(msg.message_group_id.is_none());
        assert!(msg.message_dedup_id.is_none());
    }

    #[test]
    fn deliver_fifo_without_dedup_id_is_dropped() {
        let queue = make_queue("fifo.fifo", true, false);
        let arn = queue.arn.clone();
        let url = queue.queue_url.clone();
        let state = make_state_with_queue(queue);
        let delivery = SqsDeliveryImpl::new(state.clone());
        delivery.deliver_to_queue_with_attrs(&arn, "body", &HashMap::new(), Some("g1"), None);
        let guard = state.read();
        let q = guard.default_ref().queues.get(&url).unwrap();
        assert!(q.messages.is_empty());
    }

    #[test]
    fn deliver_fifo_content_based_dedup_generates_id() {
        let queue = make_queue("fifo.fifo", true, true);
        let arn = queue.arn.clone();
        let url = queue.queue_url.clone();
        let state = make_state_with_queue(queue);
        let delivery = SqsDeliveryImpl::new(state.clone());
        delivery.deliver_to_queue_with_attrs(&arn, "body", &HashMap::new(), Some("g1"), None);
        let guard = state.read();
        let q = guard.default_ref().queues.get(&url).unwrap();
        assert_eq!(q.messages.len(), 1);
        assert!(q.messages.front().unwrap().message_dedup_id.is_some());
    }

    #[test]
    fn deliver_fifo_with_explicit_dedup_id_preserved() {
        let queue = make_queue("fifo.fifo", true, false);
        let arn = queue.arn.clone();
        let url = queue.queue_url.clone();
        let state = make_state_with_queue(queue);
        let delivery = SqsDeliveryImpl::new(state.clone());
        delivery.deliver_to_queue_with_attrs(
            &arn,
            "body",
            &HashMap::new(),
            Some("g1"),
            Some("dedup-123"),
        );
        let guard = state.read();
        let q = guard.default_ref().queues.get(&url).unwrap();
        assert_eq!(q.messages.len(), 1);
        let msg = q.messages.front().unwrap();
        assert_eq!(msg.message_dedup_id.as_deref(), Some("dedup-123"));
        assert_eq!(msg.message_group_id.as_deref(), Some("g1"));
    }

    #[test]
    fn deliver_includes_string_message_attribute() {
        let queue = make_queue("standard", false, false);
        let arn = queue.arn.clone();
        let url = queue.queue_url.clone();
        let state = make_state_with_queue(queue);
        let delivery = SqsDeliveryImpl::new(state.clone());
        let mut attrs = HashMap::new();
        attrs.insert(
            "TraceId".to_string(),
            SqsMessageAttribute {
                data_type: "String".to_string(),
                string_value: Some("abc".to_string()),
                binary_value: None,
            },
        );
        delivery.deliver_to_queue_with_attrs(&arn, "body", &attrs, None, None);
        let guard = state.read();
        let q = guard.default_ref().queues.get(&url).unwrap();
        let msg = q.messages.front().unwrap();
        let trace = msg.message_attributes.get("TraceId").unwrap();
        assert_eq!(trace.data_type, "String");
        assert_eq!(trace.string_value.as_deref(), Some("abc"));
    }

    #[test]
    fn deliver_decodes_binary_message_attribute() {
        let queue = make_queue("standard", false, false);
        let arn = queue.arn.clone();
        let url = queue.queue_url.clone();
        let state = make_state_with_queue(queue);
        let delivery = SqsDeliveryImpl::new(state.clone());
        let encoded = base64::engine::general_purpose::STANDARD.encode([0x01, 0x02, 0x03]);
        let mut attrs = HashMap::new();
        attrs.insert(
            "Blob".to_string(),
            SqsMessageAttribute {
                data_type: "Binary".to_string(),
                string_value: None,
                binary_value: Some(encoded),
            },
        );
        delivery.deliver_to_queue_with_attrs(&arn, "body", &attrs, None, None);
        let guard = state.read();
        let q = guard.default_ref().queues.get(&url).unwrap();
        let msg = q.messages.front().unwrap();
        let blob = msg.message_attributes.get("Blob").unwrap();
        assert_eq!(
            blob.binary_value.as_deref(),
            Some(&[0x01u8, 0x02, 0x03][..])
        );
    }

    #[test]
    fn deliver_unknown_queue_is_noop() {
        let queue = make_queue("standard", false, false);
        let url = queue.queue_url.clone();
        let state = make_state_with_queue(queue);
        let delivery = SqsDeliveryImpl::new(state.clone());
        delivery.deliver_to_queue(
            &format!("arn:aws:sqs:{REGION}:{ACCOUNT}:missing"),
            "body",
            &HashMap::new(),
        );
        let guard = state.read();
        let q = guard.default_ref().queues.get(&url).unwrap();
        assert!(q.messages.is_empty());
    }
}
