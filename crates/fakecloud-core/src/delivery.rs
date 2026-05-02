use std::collections::HashMap;
use std::sync::Arc;

/// Cross-service message delivery.
///
/// Services use this to deliver messages to other services without
/// direct dependencies between service crates. The server wires up
/// the delivery functions at startup.
pub struct DeliveryBus {
    /// Deliver a message to an SQS queue by ARN.
    sqs_sender: Option<Arc<dyn SqsDelivery>>,
    /// Publish a message to an SNS topic by ARN.
    sns_sender: Option<Arc<dyn SnsDelivery>>,
    /// Put an event onto an EventBridge bus.
    eventbridge_sender: Option<Arc<dyn EventBridgeDelivery>>,
    /// Invoke a Lambda function by ARN.
    lambda_invoker: Option<Arc<dyn LambdaDelivery>>,
    /// Put records to a Kinesis Data Stream by ARN.
    kinesis_sender: Option<Arc<dyn KinesisDelivery>>,
    /// Start Step Functions executions.
    stepfunctions_starter: Option<Arc<dyn StepFunctionsDelivery>>,
}

/// Message attribute for SQS delivery from SNS.
#[derive(Debug, Clone)]
pub struct SqsMessageAttribute {
    pub data_type: String,
    pub string_value: Option<String>,
    pub binary_value: Option<String>,
}

/// Error returned by fallible SQS delivery. Used by Scheduler's DLQ
/// routing, which must distinguish "target queue missing" from
/// "delivered successfully" to decide whether to send to the
/// `DeadLetterConfig.Arn`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SqsDeliveryError {
    /// The target queue ARN did not resolve to any existing queue.
    QueueNotFound(String),
    /// The ARN could not be parsed into a valid SQS queue identifier.
    InvalidArn(String),
    /// The message violated a constraint required by the target queue
    /// (e.g. FIFO send missing MessageDeduplicationId without
    /// content-based dedup enabled). Surfaces as a non-retriable
    /// failure so the upstream service can route to its configured DLQ.
    InvalidParameter(String),
}

impl std::fmt::Display for SqsDeliveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::QueueNotFound(arn) => write!(f, "queue not found: {arn}"),
            Self::InvalidArn(arn) => write!(f, "invalid queue ARN: {arn}"),
            Self::InvalidParameter(msg) => write!(f, "invalid parameter: {msg}"),
        }
    }
}

impl std::error::Error for SqsDeliveryError {}

/// Trait for delivering messages to SQS queues.
pub trait SqsDelivery: Send + Sync {
    fn deliver_to_queue(
        &self,
        queue_arn: &str,
        message_body: &str,
        attributes: &HashMap<String, String>,
    );

    /// Deliver with message attributes and FIFO fields
    fn deliver_to_queue_with_attrs(
        &self,
        queue_arn: &str,
        message_body: &str,
        message_attributes: &HashMap<String, SqsMessageAttribute>,
        message_group_id: Option<&str>,
        message_dedup_id: Option<&str>,
    ) {
        // Default implementation: fall back to simple delivery
        let _ = (message_attributes, message_group_id, message_dedup_id);
        self.deliver_to_queue(queue_arn, message_body, &HashMap::new());
    }

    /// Fallible variant used by Scheduler's DLQ routing. Default
    /// implementation assumes the queue exists (preserving the
    /// fire-and-forget semantics of `deliver_to_queue`); the real SQS
    /// impl overrides this to actually look up the queue and report
    /// `QueueNotFound` so the caller can route to a DLQ.
    fn try_deliver_to_queue_with_attrs(
        &self,
        queue_arn: &str,
        message_body: &str,
        message_attributes: &HashMap<String, SqsMessageAttribute>,
        message_group_id: Option<&str>,
        message_dedup_id: Option<&str>,
    ) -> Result<(), SqsDeliveryError> {
        self.deliver_to_queue_with_attrs(
            queue_arn,
            message_body,
            message_attributes,
            message_group_id,
            message_dedup_id,
        );
        Ok(())
    }
}

/// Trait for publishing messages to SNS topics.
pub trait SnsDelivery: Send + Sync {
    fn publish_to_topic(&self, topic_arn: &str, message: &str, subject: Option<&str>);

    /// Publish to a FIFO SNS topic carrying the message group/dedup IDs
    /// that downstream SQS subscribers need for ordering. Default impl
    /// drops the IDs so non-FIFO callers don't have to override.
    fn publish_to_topic_fifo(
        &self,
        topic_arn: &str,
        message: &str,
        subject: Option<&str>,
        _message_group_id: Option<&str>,
        _message_dedup_id: Option<&str>,
    ) {
        self.publish_to_topic(topic_arn, message, subject);
    }
}

/// Trait for putting events onto an EventBridge bus from cross-service integrations.
pub trait EventBridgeDelivery: Send + Sync {
    /// Put an event onto the specified event bus in the default account.
    /// The implementation should handle rule matching and target delivery.
    fn put_event(&self, source: &str, detail_type: &str, detail: &str, event_bus_name: &str);

    /// Put an event onto the specified event bus owned by `target_account_id`.
    /// Used for cross-account delivery where the source service (e.g. Scheduler)
    /// has a target ARN containing the destination account. The default impl
    /// falls back to the default-account `put_event` for backwards compat —
    /// real implementations should override and route to the target account's
    /// state.
    fn put_event_to_account(
        &self,
        source: &str,
        detail_type: &str,
        detail: &str,
        event_bus_name: &str,
        _target_account_id: &str,
    ) {
        self.put_event(source, detail_type, detail, event_bus_name);
    }
}

/// Trait for invoking Lambda functions from cross-service integrations.
pub trait LambdaDelivery: Send + Sync {
    /// Invoke a Lambda function with the given payload.
    /// The function is identified by ARN. Returns the response bytes on success.
    fn invoke_lambda(
        &self,
        function_arn: &str,
        payload: &str,
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Vec<u8>, String>> + Send>>;
}

/// Trait for putting records to Kinesis Data Streams.
pub trait KinesisDelivery: Send + Sync {
    /// Put a record to a Kinesis stream identified by ARN.
    /// The data should be base64-encoded. partition_key is used for shard distribution.
    fn put_record(&self, stream_arn: &str, data: &str, partition_key: &str);
}

/// Trait for starting Step Functions executions from cross-service integrations.
pub trait StepFunctionsDelivery: Send + Sync {
    /// Start a state machine execution with the given input.
    /// The state machine is identified by ARN.
    fn start_execution(&self, state_machine_arn: &str, input: &str);
}

/// Outbound email dispatch used by services that emulate AWS flows that
/// route through SES (Cognito verification, etc.) without taking a direct
/// dependency on the SES crate.
pub trait EmailDispatcher: Send + Sync {
    fn send_email(
        &self,
        account_id: &str,
        from: &str,
        to: &str,
        subject: &str,
        body_text: &str,
        body_html: Option<&str>,
    );
}

/// Outbound SMS dispatch used by services that emulate AWS flows that route
/// through SNS phone-number publish (Cognito SMS MFA, etc.).
pub trait SmsDispatcher: Send + Sync {
    fn send_sms(&self, account_id: &str, phone_number: &str, message: &str);
}

/// Cross-service KMS hook: services that accept a `KmsKeyId` (Secrets
/// Manager, SSM `SecureString`, S3 SSE-KMS, SQS / SNS / DynamoDB
/// encrypted resources) call this so that real KMS calls happen, the
/// invocation is recorded for introspection, and the returned blob is
/// decryptable by the public KMS API.
///
/// Encryption context is the AWS-defined per-service map (e.g.
/// `{aws:secretsmanager:secretArn: <arn>}` for Secrets Manager) and is
/// recorded with the call so test code can assert it.
pub trait KmsHook: Send + Sync {
    fn encrypt(
        &self,
        account_id: &str,
        region: &str,
        key_id: &str,
        plaintext: &[u8],
        service_principal: &str,
        encryption_context: std::collections::HashMap<String, String>,
    ) -> Result<String, String>;

    fn decrypt(
        &self,
        account_id: &str,
        ciphertext_b64: &str,
        service_principal: &str,
        encryption_context: std::collections::HashMap<String, String>,
    ) -> Result<Vec<u8>, String>;
}

impl DeliveryBus {
    pub fn new() -> Self {
        Self {
            sqs_sender: None,
            sns_sender: None,
            eventbridge_sender: None,
            lambda_invoker: None,
            kinesis_sender: None,
            stepfunctions_starter: None,
        }
    }

    pub fn with_sqs(mut self, sender: Arc<dyn SqsDelivery>) -> Self {
        self.sqs_sender = Some(sender);
        self
    }

    pub fn with_sns(mut self, sender: Arc<dyn SnsDelivery>) -> Self {
        self.sns_sender = Some(sender);
        self
    }

    pub fn with_eventbridge(mut self, sender: Arc<dyn EventBridgeDelivery>) -> Self {
        self.eventbridge_sender = Some(sender);
        self
    }

    pub fn with_lambda(mut self, invoker: Arc<dyn LambdaDelivery>) -> Self {
        self.lambda_invoker = Some(invoker);
        self
    }

    pub fn with_kinesis(mut self, sender: Arc<dyn KinesisDelivery>) -> Self {
        self.kinesis_sender = Some(sender);
        self
    }

    pub fn with_stepfunctions(mut self, starter: Arc<dyn StepFunctionsDelivery>) -> Self {
        self.stepfunctions_starter = Some(starter);
        self
    }

    /// Send a message to an SQS queue identified by ARN.
    pub fn send_to_sqs(
        &self,
        queue_arn: &str,
        message_body: &str,
        attributes: &HashMap<String, String>,
    ) {
        if let Some(ref sender) = self.sqs_sender {
            sender.deliver_to_queue(queue_arn, message_body, attributes);
        }
    }

    /// Send a message to an SQS queue with message attributes and FIFO fields.
    pub fn send_to_sqs_with_attrs(
        &self,
        queue_arn: &str,
        message_body: &str,
        message_attributes: &HashMap<String, SqsMessageAttribute>,
        message_group_id: Option<&str>,
        message_dedup_id: Option<&str>,
    ) {
        if let Some(ref sender) = self.sqs_sender {
            sender.deliver_to_queue_with_attrs(
                queue_arn,
                message_body,
                message_attributes,
                message_group_id,
                message_dedup_id,
            );
        }
    }

    /// Fallible SQS send — returns `Err` when the target queue does not
    /// exist, so callers (Scheduler) can route to a DLQ. Returns
    /// `Err(QueueNotFound)` when no SQS sender is wired up at all,
    /// matching the "target unreachable" semantics Scheduler relies on.
    pub fn try_send_to_sqs_with_attrs(
        &self,
        queue_arn: &str,
        message_body: &str,
        message_attributes: &HashMap<String, SqsMessageAttribute>,
        message_group_id: Option<&str>,
        message_dedup_id: Option<&str>,
    ) -> Result<(), SqsDeliveryError> {
        match self.sqs_sender {
            Some(ref sender) => sender.try_deliver_to_queue_with_attrs(
                queue_arn,
                message_body,
                message_attributes,
                message_group_id,
                message_dedup_id,
            ),
            None => Err(SqsDeliveryError::QueueNotFound(queue_arn.to_string())),
        }
    }

    /// Publish a message to an SNS topic identified by ARN.
    pub fn publish_to_sns(&self, topic_arn: &str, message: &str, subject: Option<&str>) {
        if let Some(ref sender) = self.sns_sender {
            sender.publish_to_topic(topic_arn, message, subject);
        }
    }

    /// Put an event onto an EventBridge bus in the default account.
    pub fn put_event_to_eventbridge(
        &self,
        source: &str,
        detail_type: &str,
        detail: &str,
        event_bus_name: &str,
    ) {
        if let Some(ref sender) = self.eventbridge_sender {
            sender.put_event(source, detail_type, detail, event_bus_name);
        }
    }

    /// Put an event onto an EventBridge bus in a specific account. Used by
    /// Scheduler to deliver to cross-account event buses.
    pub fn put_event_to_eventbridge_for_account(
        &self,
        source: &str,
        detail_type: &str,
        detail: &str,
        event_bus_name: &str,
        target_account_id: &str,
    ) {
        if let Some(ref sender) = self.eventbridge_sender {
            sender.put_event_to_account(
                source,
                detail_type,
                detail,
                event_bus_name,
                target_account_id,
            );
        }
    }

    /// Invoke a Lambda function identified by ARN.
    pub async fn invoke_lambda(
        &self,
        function_arn: &str,
        payload: &str,
    ) -> Option<Result<Vec<u8>, String>> {
        if let Some(ref invoker) = self.lambda_invoker {
            Some(invoker.invoke_lambda(function_arn, payload).await)
        } else {
            None
        }
    }

    /// Put a record to a Kinesis stream identified by ARN.
    pub fn send_to_kinesis(&self, stream_arn: &str, data: &str, partition_key: &str) {
        if let Some(ref sender) = self.kinesis_sender {
            sender.put_record(stream_arn, data, partition_key);
        }
    }

    /// Start a Step Functions execution identified by state machine ARN.
    pub fn start_stepfunctions_execution(&self, state_machine_arn: &str, input: &str) {
        if let Some(ref starter) = self.stepfunctions_starter {
            starter.start_execution(state_machine_arn, input);
        }
    }
}

impl Default for DeliveryBus {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::Arc;

    // Mock implementations
    struct MockSqs {
        call_count: AtomicUsize,
    }
    impl SqsDelivery for MockSqs {
        fn deliver_to_queue(
            &self,
            _queue_arn: &str,
            _message_body: &str,
            _attributes: &HashMap<String, String>,
        ) {
            self.call_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct MockSns {
        call_count: AtomicUsize,
    }
    impl SnsDelivery for MockSns {
        fn publish_to_topic(&self, _topic_arn: &str, _message: &str, _subject: Option<&str>) {
            self.call_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct MockEventBridge {
        call_count: AtomicUsize,
    }
    impl EventBridgeDelivery for MockEventBridge {
        fn put_event(
            &self,
            _source: &str,
            _detail_type: &str,
            _detail: &str,
            _event_bus_name: &str,
        ) {
            self.call_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct MockKinesis {
        call_count: AtomicUsize,
    }
    impl KinesisDelivery for MockKinesis {
        fn put_record(&self, _stream_arn: &str, _data: &str, _partition_key: &str) {
            self.call_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    struct MockStepFunctions {
        call_count: AtomicUsize,
    }
    impl StepFunctionsDelivery for MockStepFunctions {
        fn start_execution(&self, _state_machine_arn: &str, _input: &str) {
            self.call_count.fetch_add(1, Ordering::SeqCst);
        }
    }

    #[test]
    fn delivery_bus_new_has_no_senders() {
        let bus = DeliveryBus::new();
        // Calling methods without senders should be no-ops
        bus.send_to_sqs("arn:queue", "body", &HashMap::new());
        bus.publish_to_sns("arn:topic", "msg", None);
        bus.put_event_to_eventbridge("src", "type", "{}", "default");
        bus.send_to_kinesis("arn:stream", "data", "pk");
        bus.start_stepfunctions_execution("arn:sfn", "{}");
        // No panics = success
    }

    #[test]
    fn delivery_bus_default_is_same_as_new() {
        let bus = DeliveryBus::default();
        bus.send_to_sqs("arn:q", "b", &HashMap::new());
    }

    #[test]
    fn send_to_sqs_calls_sender() {
        let mock = Arc::new(MockSqs {
            call_count: AtomicUsize::new(0),
        });
        let bus = DeliveryBus::new().with_sqs(mock.clone());

        bus.send_to_sqs("arn:queue", "msg", &HashMap::new());
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);

        bus.send_to_sqs("arn:queue2", "msg2", &HashMap::new());
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn send_to_sqs_with_attrs_calls_sender() {
        let mock = Arc::new(MockSqs {
            call_count: AtomicUsize::new(0),
        });
        let bus = DeliveryBus::new().with_sqs(mock.clone());

        let mut attrs = HashMap::new();
        attrs.insert(
            "key".to_string(),
            SqsMessageAttribute {
                data_type: "String".to_string(),
                string_value: Some("val".to_string()),
                binary_value: None,
            },
        );
        bus.send_to_sqs_with_attrs("arn:q", "body", &attrs, Some("group"), Some("dedup"));
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn publish_to_sns_calls_sender() {
        let mock = Arc::new(MockSns {
            call_count: AtomicUsize::new(0),
        });
        let bus = DeliveryBus::new().with_sns(mock.clone());

        bus.publish_to_sns("arn:topic", "message", Some("subject"));
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn put_event_to_eventbridge_calls_sender() {
        let mock = Arc::new(MockEventBridge {
            call_count: AtomicUsize::new(0),
        });
        let bus = DeliveryBus::new().with_eventbridge(mock.clone());

        bus.put_event_to_eventbridge("aws.s3", "Object Created", "{}", "default");
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn send_to_kinesis_calls_sender() {
        let mock = Arc::new(MockKinesis {
            call_count: AtomicUsize::new(0),
        });
        let bus = DeliveryBus::new().with_kinesis(mock.clone());

        bus.send_to_kinesis("arn:stream", "data", "partition-key");
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn start_stepfunctions_calls_sender() {
        let mock = Arc::new(MockStepFunctions {
            call_count: AtomicUsize::new(0),
        });
        let bus = DeliveryBus::new().with_stepfunctions(mock.clone());

        bus.start_stepfunctions_execution("arn:sfn:machine", r#"{"key":"val"}"#);
        assert_eq!(mock.call_count.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn builder_chaining_works() {
        let sqs = Arc::new(MockSqs {
            call_count: AtomicUsize::new(0),
        });
        let sns = Arc::new(MockSns {
            call_count: AtomicUsize::new(0),
        });
        let eb = Arc::new(MockEventBridge {
            call_count: AtomicUsize::new(0),
        });
        let kin = Arc::new(MockKinesis {
            call_count: AtomicUsize::new(0),
        });
        let sfn = Arc::new(MockStepFunctions {
            call_count: AtomicUsize::new(0),
        });

        let bus = DeliveryBus::new()
            .with_sqs(sqs.clone())
            .with_sns(sns.clone())
            .with_eventbridge(eb.clone())
            .with_kinesis(kin.clone())
            .with_stepfunctions(sfn.clone());

        bus.send_to_sqs("q", "m", &HashMap::new());
        bus.publish_to_sns("t", "m", None);
        bus.put_event_to_eventbridge("s", "d", "{}", "b");
        bus.send_to_kinesis("s", "d", "k");
        bus.start_stepfunctions_execution("sm", "{}");

        assert_eq!(sqs.call_count.load(Ordering::SeqCst), 1);
        assert_eq!(sns.call_count.load(Ordering::SeqCst), 1);
        assert_eq!(eb.call_count.load(Ordering::SeqCst), 1);
        assert_eq!(kin.call_count.load(Ordering::SeqCst), 1);
        assert_eq!(sfn.call_count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn invoke_lambda_returns_none_without_invoker() {
        let bus = DeliveryBus::new();
        let result = bus.invoke_lambda("arn:lambda", "{}").await;
        assert!(result.is_none());
    }
}
