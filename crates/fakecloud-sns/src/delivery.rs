use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;

use fakecloud_core::delivery::{DeliveryBus, SnsDelivery};

use crate::state::{PublishedMessage, SharedSnsState};

/// Implements SnsDelivery so other services (EventBridge) can publish to SNS topics.
pub struct SnsDeliveryImpl {
    state: SharedSnsState,
    delivery: Arc<DeliveryBus>,
}

impl SnsDeliveryImpl {
    pub fn new(state: SharedSnsState, delivery: Arc<DeliveryBus>) -> Self {
        Self { state, delivery }
    }
}

impl SnsDelivery for SnsDeliveryImpl {
    fn publish_to_topic(&self, topic_arn: &str, message: &str, subject: Option<&str>) {
        let mut accounts = self.state.write();

        // Parse account from topic ARN (arn:aws:sns:region:ACCOUNT:name)
        let default_id = accounts.default_account_id().to_string();
        let target_account = topic_arn.split(':').nth(4).unwrap_or(&default_id);
        let state = accounts.get_or_create(target_account);

        if !state.topics.contains_key(topic_arn) {
            tracing::warn!(topic_arn, "SNS delivery target topic not found");
            return;
        }

        let msg_id = uuid::Uuid::new_v4().to_string();
        state.published.push(PublishedMessage {
            message_id: msg_id.clone(),
            topic_arn: topic_arn.to_string(),
            message: message.to_string(),
            subject: subject.map(|s| s.to_string()),
            message_attributes: HashMap::new(),
            message_group_id: None,
            message_dedup_id: None,
            timestamp: Utc::now(),
        });

        // Fan out to SQS subscribers
        let sqs_subscribers: Vec<String> = state
            .subscriptions
            .values()
            .filter(|s| s.topic_arn == topic_arn && s.protocol == "sqs" && s.confirmed)
            .map(|s| s.endpoint.clone())
            .collect();

        // Collect Lambda, email, and SMS subscribers
        let lambda_subscribers: Vec<(String, String)> = state
            .subscriptions
            .values()
            .filter(|s| s.topic_arn == topic_arn && s.protocol == "lambda" && s.confirmed)
            .map(|s| (s.endpoint.clone(), s.subscription_arn.clone()))
            .collect();

        let email_subscribers: Vec<String> = state
            .subscriptions
            .values()
            .filter(|s| {
                s.topic_arn == topic_arn
                    && (s.protocol == "email" || s.protocol == "email-json")
                    && s.confirmed
            })
            .map(|s| s.endpoint.clone())
            .collect();

        let sms_subscribers: Vec<String> = state
            .subscriptions
            .values()
            .filter(|s| s.topic_arn == topic_arn && s.protocol == "sms" && s.confirmed)
            .map(|s| s.endpoint.clone())
            .collect();

        let endpoint = state.endpoint.clone();

        // Build SNS Lambda event payload (matches real AWS format)
        let now = Utc::now();
        let empty_attrs = serde_json::Map::new();
        let lambda_payloads: Vec<(String, String)> = lambda_subscribers
            .iter()
            .map(|(function_arn, subscription_arn)| {
                let payload =
                    crate::service::build_sns_lambda_event(&crate::service::SnsLambdaEventInput {
                        message_id: &msg_id,
                        topic_arn,
                        subscription_arn,
                        message,
                        subject,
                        message_attributes: &empty_attrs,
                        timestamp: &now,
                        endpoint: &endpoint,
                    });
                (function_arn.clone(), payload)
            })
            .collect();

        // Record invocations in state
        for (function_arn, _) in &lambda_payloads {
            state
                .lambda_invocations
                .push(crate::state::LambdaInvocation {
                    function_arn: function_arn.clone(),
                    message: message.to_string(),
                    subject: subject.map(|s| s.to_string()),
                    timestamp: now,
                });
        }

        // Store email deliveries
        for email_address in &email_subscribers {
            tracing::info!(
                email = %email_address,
                topic_arn = %topic_arn,
                "SNS cross-service delivering to email (stub)"
            );
            state.sent_emails.push(crate::state::SentEmail {
                email_address: email_address.clone(),
                message: message.to_string(),
                subject: subject.map(|s| s.to_string()),
                topic_arn: topic_arn.to_string(),
                timestamp: now,
            });
        }

        // Store SMS deliveries
        for phone_number in &sms_subscribers {
            tracing::info!(
                phone_number = %phone_number,
                topic_arn = %topic_arn,
                "SNS cross-service delivering to SMS (stub)"
            );
            state
                .sms_messages
                .push((phone_number.clone(), message.to_string()));
        }

        // Drop the lock before calling into SQS delivery
        drop(accounts);

        // Wrap the message in SNS notification envelope (matches real AWS format)
        let timestamp = Utc::now().to_rfc3339();
        let canonical = crate::signing::canonical_notification(
            message, &msg_id, subject, &timestamp, topic_arn,
        );
        let signature = crate::signing::sign(&canonical);
        let sns_envelope = serde_json::json!({
            "Type": "Notification",
            "MessageId": msg_id,
            "TopicArn": topic_arn,
            "Subject": subject.unwrap_or(""),
            "Message": message,
            "Timestamp": timestamp,
            "SignatureVersion": "1",
            "Signature": signature,
            "SigningCertURL": crate::signing::cert_url(&endpoint),
            "UnsubscribeURL": format!("{}/?Action=Unsubscribe&SubscriptionArn={}", endpoint, topic_arn),
        });
        let envelope_str = sns_envelope.to_string();

        for queue_arn in sqs_subscribers {
            self.delivery
                .send_to_sqs(&queue_arn, &envelope_str, &HashMap::new());
        }

        // Invoke Lambda subscribers via container runtime
        if !lambda_payloads.is_empty() {
            let delivery = self.delivery.clone();
            tokio::spawn(async move {
                for (function_arn, payload) in lambda_payloads {
                    tracing::info!(
                        function_arn = %function_arn,
                        "SNS invoking Lambda function"
                    );
                    match delivery.invoke_lambda(&function_arn, &payload).await {
                        Some(Ok(_)) => {
                            tracing::info!(
                                function_arn = %function_arn,
                                "SNS->Lambda invocation succeeded"
                            );
                        }
                        Some(Err(e)) => {
                            tracing::error!(
                                function_arn = %function_arn,
                                error = %e,
                                "SNS->Lambda invocation failed"
                            );
                        }
                        None => {
                            tracing::info!(
                                function_arn = %function_arn,
                                "SNS->Lambda: no container runtime available, skipping real execution"
                            );
                        }
                    }
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{SharedSnsState, SnsState, SnsSubscription, SnsTopic};
    use chrono::Utc;
    use fakecloud_core::multi_account::MultiAccountState;
    use parking_lot::RwLock;
    use std::collections::{BTreeMap, HashMap};

    const ACCOUNT: &str = "123456789012";
    const REGION: &str = "us-east-1";
    const ENDPOINT: &str = "http://localhost:4566";

    fn make_topic(name: &str) -> (SnsTopic, String) {
        let arn = format!("arn:aws:sns:{REGION}:{ACCOUNT}:{name}");
        let topic = SnsTopic {
            topic_arn: arn.clone(),
            name: name.to_string(),
            attributes: HashMap::new(),
            tags: Vec::new(),
            is_fifo: false,
            created_at: Utc::now(),
        };
        (topic, arn)
    }

    fn make_subscription(
        topic_arn: &str,
        protocol: &str,
        endpoint: &str,
        confirmed: bool,
    ) -> SnsSubscription {
        let sub_arn = format!("{topic_arn}:{}", uuid::Uuid::new_v4());
        SnsSubscription {
            subscription_arn: sub_arn,
            topic_arn: topic_arn.to_string(),
            protocol: protocol.to_string(),
            endpoint: endpoint.to_string(),
            owner: ACCOUNT.to_string(),
            attributes: HashMap::new(),
            confirmed,
            confirmation_token: None,
        }
    }

    fn make_state(topics: Vec<SnsTopic>, subs: Vec<SnsSubscription>) -> SharedSnsState {
        let mut multi: MultiAccountState<SnsState> =
            MultiAccountState::new(ACCOUNT, REGION, ENDPOINT);
        let state = multi.default_mut();
        for t in topics {
            state.topics.insert(t.topic_arn.clone(), t);
        }
        let mut sub_map: BTreeMap<String, SnsSubscription> = BTreeMap::new();
        for s in subs {
            sub_map.insert(s.subscription_arn.clone(), s);
        }
        state.subscriptions = sub_map;
        Arc::new(RwLock::new(multi))
    }

    #[test]
    fn publish_records_message_in_topic() {
        let (topic, arn) = make_topic("t1");
        let state = make_state(vec![topic], vec![]);
        let bus = Arc::new(DeliveryBus::new());
        let delivery = SnsDeliveryImpl::new(state.clone(), bus);
        delivery.publish_to_topic(&arn, "hello", Some("hi"));
        let guard = state.read();
        let s = guard.default_ref();
        assert_eq!(s.published.len(), 1);
        let msg = &s.published[0];
        assert_eq!(msg.message, "hello");
        assert_eq!(msg.subject.as_deref(), Some("hi"));
        assert_eq!(msg.topic_arn, arn);
    }

    #[test]
    fn publish_unknown_topic_noop() {
        let (topic, _arn) = make_topic("t1");
        let state = make_state(vec![topic], vec![]);
        let bus = Arc::new(DeliveryBus::new());
        let delivery = SnsDeliveryImpl::new(state.clone(), bus);
        delivery.publish_to_topic(
            &format!("arn:aws:sns:{REGION}:{ACCOUNT}:unknown"),
            "body",
            None,
        );
        let guard = state.read();
        assert!(guard.default_ref().published.is_empty());
    }

    #[test]
    fn publish_records_email_delivery() {
        let (topic, arn) = make_topic("t1");
        let sub = make_subscription(&arn, "email", "user@example.com", true);
        let state = make_state(vec![topic], vec![sub]);
        let bus = Arc::new(DeliveryBus::new());
        let delivery = SnsDeliveryImpl::new(state.clone(), bus);
        delivery.publish_to_topic(&arn, "greetings", Some("subj"));
        let guard = state.read();
        let s = guard.default_ref();
        assert_eq!(s.sent_emails.len(), 1);
        assert_eq!(s.sent_emails[0].email_address, "user@example.com");
        assert_eq!(s.sent_emails[0].message, "greetings");
        assert_eq!(s.sent_emails[0].subject.as_deref(), Some("subj"));
    }

    #[test]
    fn publish_records_sms_delivery() {
        let (topic, arn) = make_topic("t1");
        let sub = make_subscription(&arn, "sms", "+14155550199", true);
        let state = make_state(vec![topic], vec![sub]);
        let bus = Arc::new(DeliveryBus::new());
        let delivery = SnsDeliveryImpl::new(state.clone(), bus);
        delivery.publish_to_topic(&arn, "text-body", None);
        let guard = state.read();
        let s = guard.default_ref();
        assert_eq!(s.sms_messages.len(), 1);
        assert_eq!(s.sms_messages[0].0, "+14155550199");
        assert_eq!(s.sms_messages[0].1, "text-body");
    }

    #[test]
    fn publish_unconfirmed_subscription_skipped() {
        let (topic, arn) = make_topic("t1");
        let sub = make_subscription(&arn, "email", "user@example.com", false);
        let state = make_state(vec![topic], vec![sub]);
        let bus = Arc::new(DeliveryBus::new());
        let delivery = SnsDeliveryImpl::new(state.clone(), bus);
        delivery.publish_to_topic(&arn, "msg", None);
        let guard = state.read();
        let s = guard.default_ref();
        assert!(s.sent_emails.is_empty());
        assert_eq!(s.published.len(), 1);
    }

    #[tokio::test]
    async fn publish_records_lambda_invocation() {
        let (topic, arn) = make_topic("t1");
        let fn_arn = format!("arn:aws:lambda:{REGION}:{ACCOUNT}:function:myFn");
        let sub = make_subscription(&arn, "lambda", &fn_arn, true);
        let state = make_state(vec![topic], vec![sub]);
        let bus = Arc::new(DeliveryBus::new());
        let delivery = SnsDeliveryImpl::new(state.clone(), bus);
        delivery.publish_to_topic(&arn, "payload", Some("s"));
        let guard = state.read();
        let s = guard.default_ref();
        assert_eq!(s.lambda_invocations.len(), 1);
        assert_eq!(s.lambda_invocations[0].function_arn, fn_arn);
        assert_eq!(s.lambda_invocations[0].message, "payload");
    }

    #[tokio::test]
    async fn publish_with_sqs_subscriber_calls_delivery_bus() {
        use fakecloud_core::delivery::SqsDelivery;
        use std::sync::Mutex;

        #[derive(Default)]
        struct Recorder {
            calls: Mutex<Vec<(String, String)>>,
        }

        impl SqsDelivery for Recorder {
            fn deliver_to_queue(
                &self,
                queue_arn: &str,
                message_body: &str,
                _attrs: &HashMap<String, String>,
            ) {
                self.calls
                    .lock()
                    .unwrap()
                    .push((queue_arn.to_string(), message_body.to_string()));
            }

            fn deliver_to_queue_with_attrs(
                &self,
                queue_arn: &str,
                message_body: &str,
                _attrs: &HashMap<String, fakecloud_core::delivery::SqsMessageAttribute>,
                _group: Option<&str>,
                _dedup: Option<&str>,
            ) {
                self.calls
                    .lock()
                    .unwrap()
                    .push((queue_arn.to_string(), message_body.to_string()));
            }
        }

        let recorder = Arc::new(Recorder::default());
        let (topic, arn) = make_topic("t1");
        let q_arn = format!("arn:aws:sqs:{REGION}:{ACCOUNT}:q1");
        let sub = make_subscription(&arn, "sqs", &q_arn, true);
        let state = make_state(vec![topic], vec![sub]);
        let bus = Arc::new(DeliveryBus::new().with_sqs(recorder.clone()));
        let delivery = SnsDeliveryImpl::new(state.clone(), bus);
        delivery.publish_to_topic(&arn, "hello-sqs", Some("s"));
        let calls = recorder.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].0, q_arn);
        let envelope: serde_json::Value = serde_json::from_str(&calls[0].1).unwrap();
        assert_eq!(envelope["Type"], "Notification");
        assert_eq!(envelope["Message"], "hello-sqs");
        assert_eq!(envelope["Subject"], "s");
        assert_eq!(envelope["TopicArn"], arn);
    }
}
