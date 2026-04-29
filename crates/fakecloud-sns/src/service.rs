use async_trait::async_trait;
use base64::Engine;
use chrono::Utc;
use http::StatusCode;
use serde_json::Value;
use std::collections::{BTreeMap, HashMap};
use std::sync::Arc;
use tokio::sync::Mutex as AsyncMutex;

use fakecloud_aws::arn::Arn;
use fakecloud_core::delivery::DeliveryBus;
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
use fakecloud_persistence::SnapshotStore;

use crate::state::{
    MessageAttribute, PlatformApplication, PlatformEndpoint, PublishedMessage, SharedSnsState,
    SnsSnapshot, SnsSubscription, SnsTopic, SNS_SNAPSHOT_SCHEMA_VERSION,
};

pub struct SnsService {
    state: SharedSnsState,
    delivery: Arc<DeliveryBus>,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    snapshot_lock: Arc<AsyncMutex<()>>,
    pub(crate) kms_hook: Option<Arc<dyn fakecloud_core::delivery::KmsHook>>,
    pub(crate) region: String,
}

impl SnsService {
    pub fn new(state: SharedSnsState, delivery: Arc<DeliveryBus>) -> Self {
        Self {
            state,
            delivery,
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

    /// Record `GenerateDataKey` + `Decrypt` for an encrypted SNS topic.
    /// SNS encrypts each message at rest with the topic's KMS key, then
    /// decrypts to fan-out to subscribers. fakecloud's fan-out happens
    /// in-process so we don't actually round-trip ciphertext through the
    /// envelope; we just emit the audit-trail records the AWS API would
    /// produce, so callers can assert KMS usage via
    /// `/_fakecloud/kms/usage`.
    fn record_topic_kms_usage(
        &self,
        account_id: &str,
        topic_arn: &str,
        kms_key_id: Option<&str>,
        message: &str,
    ) -> Result<(), AwsServiceError> {
        let Some(hook) = &self.kms_hook else {
            return Ok(());
        };
        let Some(key) = kms_key_id.filter(|k| !k.is_empty()) else {
            return Ok(());
        };
        let mut ctx = std::collections::HashMap::new();
        ctx.insert("aws:sns:arn".to_string(), topic_arn.to_string());
        let envelope = match hook.encrypt(
            account_id,
            &self.region,
            key,
            message.as_bytes(),
            "sns.amazonaws.com",
            ctx.clone(),
        ) {
            Ok(env) => env,
            Err(err) => {
                tracing::warn!(topic = %topic_arn, error = %err, "SNS SSE-KMS encrypt failed");
                return Err(AwsServiceError::aws_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "KMS.InternalFailureException",
                    format!("Failed to encrypt SNS message via KMS: {err}"),
                ));
            }
        };
        // Mirror the GenerateDataKey with the matching Decrypt the
        // service would emit at fan-out time. A decrypt failure here
        // means the topic's CMK is unusable for delivery — also
        // fail-closed so callers don't silently lose audit records.
        if let Err(err) = hook.decrypt(account_id, &envelope, "sns.amazonaws.com", ctx) {
            tracing::warn!(topic = %topic_arn, error = %err, "SNS SSE-KMS decrypt failed");
            return Err(AwsServiceError::aws_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "KMS.InternalFailureException",
                format!("Failed to decrypt SNS message via KMS: {err}"),
            ));
        }
        Ok(())
    }

    /// Persist current state as a snapshot. Held across the
    /// clone-serialize-write sequence to prevent stale-last writes,
    /// with serde + file I/O offloaded to the blocking pool.
    async fn save_snapshot(&self) {
        let Some(store) = self.snapshot_store.clone() else {
            return;
        };
        let _guard = self.snapshot_lock.lock().await;
        let snapshot = SnsSnapshot {
            schema_version: SNS_SNAPSHOT_SCHEMA_VERSION,
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
            Ok(Err(err)) => tracing::error!(%err, "failed to write sns snapshot"),
            Err(err) => tracing::error!(%err, "sns snapshot task panicked"),
        }
    }
}

use fakecloud_aws::xml::xml_escape;

const DEFAULT_PAGE_SIZE: usize = 100;

const DEFAULT_EFFECTIVE_DELIVERY_POLICY: &str = r#"{"defaultHealthyRetryPolicy":{"numNoDelayRetries":0,"numMinDelayRetries":0,"minDelayTarget":20,"maxDelayTarget":20,"numMaxDelayRetries":0,"numRetries":3,"backoffFunction":"linear"},"sicklyRetryPolicy":null,"throttlePolicy":null,"guaranteed":false}"#;

const VALID_SNS_ACTIONS: &[&str] = &[
    "GetTopicAttributes",
    "SetTopicAttributes",
    "AddPermission",
    "RemovePermission",
    "DeleteTopic",
    "Subscribe",
    "ListSubscriptionsByTopic",
    "Publish",
    "Receive",
];

const VALID_SUBSCRIPTION_ATTRS: &[&str] = &[
    "RawMessageDelivery",
    "DeliveryPolicy",
    "FilterPolicy",
    "FilterPolicyScope",
    "RedrivePolicy",
    "SubscriptionRoleArn",
];

#[async_trait]
impl AwsService for SnsService {
    fn service_name(&self) -> &str {
        "sns"
    }

    async fn handle(&self, req: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mutates = is_mutating_action(req.action.as_str());
        let result = match req.action.as_str() {
            "CreateTopic" => self.create_topic(&req),
            "DeleteTopic" => self.delete_topic(&req),
            "ListTopics" => self.list_topics(&req),
            "GetTopicAttributes" => self.get_topic_attributes(&req),
            "SetTopicAttributes" => self.set_topic_attributes(&req),
            "Subscribe" => self.subscribe(&req),
            "ConfirmSubscription" => self.confirm_subscription(&req),
            "Unsubscribe" => self.unsubscribe(&req),
            "Publish" => self.publish(&req),
            "PublishBatch" => self.publish_batch(&req),
            "ListSubscriptions" => self.list_subscriptions(&req),
            "ListSubscriptionsByTopic" => self.list_subscriptions_by_topic(&req),
            "GetSubscriptionAttributes" => self.get_subscription_attributes(&req),
            "SetSubscriptionAttributes" => self.set_subscription_attributes(&req),
            "TagResource" => self.tag_resource(&req),
            "UntagResource" => self.untag_resource(&req),
            "ListTagsForResource" => self.list_tags_for_resource(&req),
            "AddPermission" => self.add_permission(&req),
            "RemovePermission" => self.remove_permission(&req),
            // Platform application actions
            "CreatePlatformApplication" => self.create_platform_application(&req),
            "DeletePlatformApplication" => self.delete_platform_application(&req),
            "GetPlatformApplicationAttributes" => self.get_platform_application_attributes(&req),
            "SetPlatformApplicationAttributes" => self.set_platform_application_attributes(&req),
            "ListPlatformApplications" => self.list_platform_applications(&req),
            "CreatePlatformEndpoint" => self.create_platform_endpoint(&req),
            "DeleteEndpoint" => self.delete_endpoint(&req),
            "GetEndpointAttributes" => self.get_endpoint_attributes(&req),
            "SetEndpointAttributes" => self.set_endpoint_attributes(&req),
            "ListEndpointsByPlatformApplication" => {
                self.list_endpoints_by_platform_application(&req)
            }
            // SMS actions
            "SetSMSAttributes" => self.set_sms_attributes(&req),
            "GetSMSAttributes" => self.get_sms_attributes(&req),
            "CheckIfPhoneNumberIsOptedOut" => self.check_if_phone_number_is_opted_out(&req),
            "ListPhoneNumbersOptedOut" => self.list_phone_numbers_opted_out(&req),
            "OptInPhoneNumber" => self.opt_in_phone_number(&req),
            "CreateSMSSandboxPhoneNumber" => self.create_sms_sandbox_phone_number(&req),
            "DeleteSMSSandboxPhoneNumber" => self.delete_sms_sandbox_phone_number(&req),
            "VerifySMSSandboxPhoneNumber" => self.verify_sms_sandbox_phone_number(&req),
            "ListSMSSandboxPhoneNumbers" => self.list_sms_sandbox_phone_numbers(&req),
            "GetSMSSandboxAccountStatus" => self.get_sms_sandbox_account_status(&req),
            "ListOriginationNumbers" => self.list_origination_numbers(&req),
            "GetDataProtectionPolicy" => self.get_data_protection_policy(&req),
            "PutDataProtectionPolicy" => self.put_data_protection_policy(&req),
            _ => Err(AwsServiceError::action_not_implemented("sns", &req.action)),
        };
        if mutates && matches!(result.as_ref(), Ok(resp) if resp.status.is_success()) {
            self.save_snapshot().await;
        }
        result
    }

    fn supported_actions(&self) -> &[&str] {
        SNS_SUPPORTED_ACTIONS
    }

    fn iam_enforceable(&self) -> bool {
        true
    }

    /// SNS resources are topic / subscription / platform-app / endpoint
    /// ARNs. Topic-targeted actions carry a `TopicArn`; subscription
    /// actions carry a `SubscriptionArn`; platform-app actions carry
    /// `PlatformApplicationArn`; endpoint actions carry `EndpointArn`.
    /// Listing and account-scoped actions target `*`.
    fn iam_action_for(&self, request: &AwsRequest) -> Option<fakecloud_core::auth::IamAction> {
        let action = SNS_SUPPORTED_ACTIONS
            .iter()
            .copied()
            .find(|a| *a == request.action)?;
        let resource = match action {
            "CreateTopic" => {
                // The to-be-created topic ARN is built from the same
                // account id the handler uses (state.account_id via
                // `Arn::new`), not `principal.account_id`, so policy
                // evaluation and the actual ARN can't diverge even if
                // the two sources ever drift (identified by cubic on
                // PR #399).
                let _accts = self.state.read(); let _empty = crate::state::SnsState::new(&request.account_id, &request.region, ""); let state = _accts.get(&request.account_id).unwrap_or(&_empty);
                let partition = if request.region.starts_with("cn-") {
                    "aws-cn"
                } else if request.region.starts_with("us-gov-") {
                    "aws-us-gov"
                } else {
                    "aws"
                };
                param(request, "Name")
                    .map(|n| {
                        format!(
                            "arn:{}:sns:{}:{}:{}",
                            partition, request.region, state.account_id, n
                        )
                    })
                    .unwrap_or_else(|| "*".to_string())
            }
            "DeleteTopic"
            | "GetTopicAttributes"
            | "SetTopicAttributes"
            | "Subscribe"
            | "Publish"
            | "PublishBatch"
            | "ListSubscriptionsByTopic"
            | "AddPermission"
            | "RemovePermission"
            // ConfirmSubscription is keyed by TopicArn (identified by
            // cubic on PR #399) — the Token in the request confirms a
            // subscription to that topic; SubscriptionArn only exists
            // after confirmation.
            | "ConfirmSubscription" => {
                param(request, "TopicArn").unwrap_or_else(|| "*".to_string())
            }
            "Unsubscribe" | "GetSubscriptionAttributes" | "SetSubscriptionAttributes" => {
                param(request, "SubscriptionArn").unwrap_or_else(|| "*".to_string())
            }
            "TagResource" | "UntagResource" | "ListTagsForResource" => {
                param(request, "ResourceArn").unwrap_or_else(|| "*".to_string())
            }
            "DeletePlatformApplication"
            | "GetPlatformApplicationAttributes"
            | "SetPlatformApplicationAttributes"
            | "CreatePlatformEndpoint"
            | "ListEndpointsByPlatformApplication" => {
                param(request, "PlatformApplicationArn").unwrap_or_else(|| "*".to_string())
            }
            "DeleteEndpoint" | "GetEndpointAttributes" | "SetEndpointAttributes" => {
                param(request, "EndpointArn").unwrap_or_else(|| "*".to_string())
            }
            "GetDataProtectionPolicy" | "PutDataProtectionPolicy" => {
                param(request, "ResourceArn").unwrap_or_else(|| "*".to_string())
            }
            _ => "*".to_string(),
        };
        Some(fakecloud_core::auth::IamAction {
            service: "sns",
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
        if action.action == "Subscribe" {
            if let Some(protocol) = param(request, "Protocol") {
                out.insert("sns:protocol".to_string(), vec![protocol]);
            }
            if let Some(endpoint) = param(request, "Endpoint") {
                out.insert("sns:endpoint".to_string(), vec![endpoint]);
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
        let account_id = resource_arn.split(':').nth(4).unwrap_or("");
        let _accts = self.state.read();
        let state = _accts.get(account_id)?;
        let topic = state.topics.get(resource_arn)?;
        Some(topic.tags.iter().cloned().collect())
    }

    fn request_tags_from(
        &self,
        request: &AwsRequest,
        action: &str,
    ) -> Option<std::collections::HashMap<String, String>> {
        match action {
            "CreateTopic" | "TagResource" => {
                let tags = parse_tags(request);
                Some(tags.into_iter().collect())
            }
            _ => Some(std::collections::HashMap::new()),
        }
    }
}

const SNS_SUPPORTED_ACTIONS: &[&str] = &[
    "CreateTopic",
    "DeleteTopic",
    "ListTopics",
    "GetTopicAttributes",
    "SetTopicAttributes",
    "Subscribe",
    "ConfirmSubscription",
    "Unsubscribe",
    "Publish",
    "PublishBatch",
    "ListSubscriptions",
    "ListSubscriptionsByTopic",
    "GetSubscriptionAttributes",
    "SetSubscriptionAttributes",
    "TagResource",
    "UntagResource",
    "ListTagsForResource",
    "AddPermission",
    "RemovePermission",
    "CreatePlatformApplication",
    "DeletePlatformApplication",
    "GetPlatformApplicationAttributes",
    "SetPlatformApplicationAttributes",
    "ListPlatformApplications",
    "CreatePlatformEndpoint",
    "DeleteEndpoint",
    "GetEndpointAttributes",
    "SetEndpointAttributes",
    "ListEndpointsByPlatformApplication",
    "SetSMSAttributes",
    "GetSMSAttributes",
    "CheckIfPhoneNumberIsOptedOut",
    "ListPhoneNumbersOptedOut",
    "OptInPhoneNumber",
    "CreateSMSSandboxPhoneNumber",
    "DeleteSMSSandboxPhoneNumber",
    "VerifySMSSandboxPhoneNumber",
    "ListSMSSandboxPhoneNumbers",
    "GetSMSSandboxAccountStatus",
    "ListOriginationNumbers",
    "GetDataProtectionPolicy",
    "PutDataProtectionPolicy",
];

const FIFO_NAME_ERROR: &str = "Fifo Topic names must end with .fifo and must be made up of only uppercase and lowercase ASCII letters, numbers, underscores, and hyphens, and must be between 1 and 256 characters long.";
const STANDARD_NAME_ERROR: &str = "Topic names must be made up of only uppercase and lowercase ASCII letters, numbers, underscores, and hyphens, and must be between 1 and 256 characters long.";

impl SnsService {
    fn create_topic(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let name = required(req, "Name")?;

        // Parse attributes from Attributes.entry.N.key / Attributes.entry.N.value
        let topic_attrs = parse_entries(req, "Attributes");
        let is_fifo_attr = topic_attrs
            .get("FifoTopic")
            .map(|v| v.eq_ignore_ascii_case("true"))
            .unwrap_or(false);
        let is_fifo = name.ends_with(".fifo");

        validate_topic_name(&name, is_fifo_attr)?;

        // Parse tags from request
        let tags = parse_tags(req);

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let topic_arn = Arn::new("sns", &req.region, &state.account_id, &name).to_string();

        if !state.topics.contains_key(&topic_arn) {
            let mut attributes = BTreeMap::new();
            // Set default policy
            attributes.insert(
                "Policy".to_string(),
                default_policy(&topic_arn, &state.account_id),
            );
            attributes.insert("DisplayName".to_string(), String::new());
            attributes.insert("DeliveryPolicy".to_string(), String::new());

            if is_fifo {
                attributes.insert("FifoTopic".to_string(), "true".to_string());
                attributes.insert("ContentBasedDeduplication".to_string(), "false".to_string());
            }

            // Apply topic attributes from the request
            for (k, v) in &topic_attrs {
                // Normalize boolean-like values for FifoTopic and ContentBasedDeduplication
                if k == "FifoTopic" || k == "ContentBasedDeduplication" {
                    let normalized = if v.eq_ignore_ascii_case("true") {
                        "true"
                    } else {
                        "false"
                    };
                    if k == "FifoTopic" && normalized == "false" {
                        attributes.remove("FifoTopic");
                        attributes.remove("ContentBasedDeduplication");
                        continue;
                    }
                    attributes.insert(k.clone(), normalized.to_string());
                    continue;
                }
                attributes.insert(k.clone(), v.clone());
            }

            let topic = SnsTopic {
                topic_arn: topic_arn.clone(),
                name,
                attributes,
                tags,
                is_fifo,
                created_at: Utc::now(),
            };
            state.topics.insert(topic_arn.clone(), topic);
        }

        Ok(xml_resp(
            &format!(
                r#"<CreateTopicResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <CreateTopicResult>
    <TopicArn>{topic_arn}</TopicArn>
  </CreateTopicResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</CreateTopicResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn delete_topic(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let topic_arn = required(req, "TopicArn")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state.topics.remove(&topic_arn);
        state
            .subscriptions
            .retain(|_, sub| sub.topic_arn != topic_arn);

        Ok(xml_resp(
            &format!(
                r#"<DeleteTopicResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</DeleteTopicResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn list_topics(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let _accts = self.state.read();
        let _empty = crate::state::SnsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);

        // Filter topics by region
        let all_topics: Vec<&SnsTopic> = state
            .topics
            .values()
            .filter(|t| {
                // Extract region from ARN
                let parts: Vec<&str> = t.topic_arn.split(':').collect();
                parts.len() >= 4 && parts[3] == req.region
            })
            .collect();

        let next_token = param(req, "NextToken")
            .and_then(|t| t.parse::<usize>().ok())
            .unwrap_or(0);
        let next_token = next_token.min(all_topics.len());

        let page = &all_topics[next_token..];
        let has_more = page.len() > DEFAULT_PAGE_SIZE;
        let page = if has_more {
            &page[..DEFAULT_PAGE_SIZE]
        } else {
            page
        };

        let members: String = page
            .iter()
            .map(|t| {
                format!(
                    "      <member><TopicArn>{}</TopicArn></member>",
                    t.topic_arn
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        let next_token_xml = if has_more {
            format!(
                "\n    <NextToken>{}</NextToken>",
                next_token + DEFAULT_PAGE_SIZE
            )
        } else {
            String::new()
        };

        Ok(xml_resp(
            &format!(
                r#"<ListTopicsResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ListTopicsResult>
    <Topics>
{members}
    </Topics>{next_token_xml}
  </ListTopicsResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</ListTopicsResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn get_topic_attributes(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let topic_arn = required(req, "TopicArn")?;

        // Check region: topic must belong to the request's region
        if let Some(topic_region) = arn_region(&topic_arn) {
            if topic_region != req.region {
                return Err(not_found("Topic"));
            }
        }

        let _accts = self.state.read();
        let _empty = crate::state::SnsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);
        let topic = state
            .topics
            .get(&topic_arn)
            .ok_or_else(|| not_found("Topic"))?;

        let subs_confirmed = state
            .subscriptions
            .values()
            .filter(|s| s.topic_arn == topic_arn && s.confirmed)
            .count();
        let subs_pending = state
            .subscriptions
            .values()
            .filter(|s| s.topic_arn == topic_arn && !s.confirmed)
            .count();

        let mut entries = vec![
            format_attr("TopicArn", &topic.topic_arn),
            format_attr("Owner", &state.account_id),
            format_attr("SubscriptionsConfirmed", &subs_confirmed.to_string()),
            format_attr("SubscriptionsPending", &subs_pending.to_string()),
            format_attr("SubscriptionsDeleted", "0"),
        ];

        // Add EffectiveDeliveryPolicy
        entries.push(format_attr(
            "EffectiveDeliveryPolicy",
            DEFAULT_EFFECTIVE_DELIVERY_POLICY,
        ));

        // Add all stored attributes
        for (k, v) in &topic.attributes {
            entries.push(format_attr(k, v));
        }

        let attrs = entries.join("\n");
        Ok(xml_resp(
            &format!(
                r#"<GetTopicAttributesResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <GetTopicAttributesResult>
    <Attributes>
{attrs}
    </Attributes>
  </GetTopicAttributesResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</GetTopicAttributesResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn set_topic_attributes(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let topic_arn = required(req, "TopicArn")?;
        let attr_name = required(req, "AttributeName")?;
        let attr_value = param(req, "AttributeValue").unwrap_or_default();

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let topic = state
            .topics
            .get_mut(&topic_arn)
            .ok_or_else(|| not_found("Topic"))?;

        // If setting Policy, compact the JSON
        if attr_name == "Policy" {
            if let Ok(parsed) = serde_json::from_str::<Value>(&attr_value) {
                if let Ok(compact) = serde_json::to_string(&parsed) {
                    topic.attributes.insert(attr_name, compact);
                } else {
                    topic.attributes.insert(attr_name, attr_value);
                }
            } else {
                topic.attributes.insert(attr_name, attr_value);
            }
        } else {
            topic.attributes.insert(attr_name, attr_value);
        }

        Ok(xml_resp(
            &format!(
                r#"<SetTopicAttributesResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</SetTopicAttributesResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn subscribe(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let topic_arn = required(req, "TopicArn")?;
        let protocol = required(req, "Protocol")?;
        let endpoint = param(req, "Endpoint").unwrap_or_default();

        let accts = self.state.read();
        let state_r = match accts.get(&req.account_id) {
            Some(s) => s,
            None => return Err(not_found("Topic")),
        };
        let topic = state_r
            .topics
            .get(&topic_arn)
            .ok_or_else(|| not_found("Topic"))?;
        let is_fifo_topic = topic.is_fifo;
        let account_id = req.account_id.clone();

        // Validate application endpoint exists
        if protocol == "application" {
            let endpoint_exists = state_r
                .platform_applications
                .values()
                .any(|app| app.endpoints.contains_key(&endpoint));
            if !endpoint_exists {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameter",
                    format!(
                        "Invalid parameter: Endpoint Reason: Endpoint does not exist for endpoint {endpoint}"
                    ),
                ));
            }
        }
        drop(accts);

        // Validate SMS endpoint
        if protocol == "sms" {
            validate_sms_endpoint(&endpoint)?;
        }

        // Validate SQS endpoint (must be an ARN)
        if protocol == "sqs" && !endpoint.starts_with("arn:aws:sqs:") {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                "Invalid parameter: SQS endpoint ARN",
            ));
        }

        // Validate: FIFO SQS queues can only be subscribed to FIFO topics
        if protocol == "sqs" && endpoint.ends_with(".fifo") && !is_fifo_topic {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                "Invalid parameter: Invalid parameter: Endpoint Reason: FIFO SQS Queues can not be subscribed to standard SNS topics",
            ));
        }

        // Parse subscription attributes
        let sub_attrs = parse_entries(req, "Attributes");

        // Validate subscription attribute names
        for key in sub_attrs.keys() {
            if !VALID_SUBSCRIPTION_ATTRS.contains(&key.as_str()) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameter",
                    format!("Invalid parameter: Attributes Reason: Unknown attribute: {key}"),
                ));
            }
        }

        // Validate and auto-set FilterPolicy
        let mut attributes = sub_attrs;
        if let Some(fp) = attributes.get("FilterPolicy") {
            if !fp.is_empty() {
                validate_filter_policy(fp)?;
            }
            if !attributes.contains_key("FilterPolicyScope") {
                attributes.insert(
                    "FilterPolicyScope".to_string(),
                    "MessageAttributes".to_string(),
                );
            }
        }

        // Check for duplicate subscription (same topic, protocol, endpoint)
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        for sub in state.subscriptions.values() {
            if sub.topic_arn == topic_arn && sub.protocol == protocol && sub.endpoint == endpoint {
                return Ok(xml_resp(
                    &format!(
                        r#"<SubscribeResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <SubscribeResult>
    <SubscriptionArn>{}</SubscriptionArn>
  </SubscribeResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</SubscribeResponse>"#,
                        sub.subscription_arn, req.request_id
                    ),
                    &req.request_id,
                ));
            }
        }

        let sub_arn = format!("{}:{}", topic_arn, uuid::Uuid::new_v4());

        // HTTP/HTTPS subscriptions start as pending (require confirmation)
        let confirmed = protocol != "http" && protocol != "https";
        let response_arn = if confirmed {
            sub_arn.clone()
        } else {
            "pending confirmation".to_string()
        };

        // Generate a confirmation token for pending subscriptions
        let confirmation_token = if !confirmed {
            Some(uuid::Uuid::new_v4().to_string())
        } else {
            None
        };

        let sub = SnsSubscription {
            subscription_arn: sub_arn.clone(),
            topic_arn,
            protocol,
            endpoint,
            owner: account_id,
            attributes,
            confirmed,
            confirmation_token,
        };

        state.subscriptions.insert(sub_arn.clone(), sub);

        Ok(xml_resp(
            &format!(
                r#"<SubscribeResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <SubscribeResult>
    <SubscriptionArn>{response_arn}</SubscriptionArn>
  </SubscribeResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</SubscribeResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn confirm_subscription(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let topic_arn = required(req, "TopicArn")?;
        let token = required(req, "Token")?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        // AWS accepts both the confirmation token and the subscription ARN as the Token parameter.
        // Confirming an already-confirmed subscription is a no-op (idempotent).
        let sub_arn = state
            .subscriptions
            .values()
            .find(|s| {
                s.topic_arn == topic_arn
                    && (s.confirmation_token.as_deref() == Some(&token)
                        || s.subscription_arn == token)
            })
            .map(|s| s.subscription_arn.clone())
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "NotFound",
                    format!("No pending subscription found for token: {token}"),
                )
            })?;

        // Mark the subscription as confirmed
        if let Some(sub) = state.subscriptions.get_mut(&sub_arn) {
            sub.confirmed = true;
        }

        Ok(xml_resp(
            &format!(
                r#"<ConfirmSubscriptionResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ConfirmSubscriptionResult>
    <SubscriptionArn>{sub_arn}</SubscriptionArn>
  </ConfirmSubscriptionResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</ConfirmSubscriptionResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn unsubscribe(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let sub_arn = required(req, "SubscriptionArn")?;
        self.state
            .write()
            .get_or_create(&req.account_id)
            .subscriptions
            .remove(&sub_arn);

        Ok(xml_resp(
            &format!(
                r#"<UnsubscribeResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</UnsubscribeResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn publish(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        // Either TopicArn or TargetArn is required; also allow PhoneNumber for SMS
        let topic_arn = param(req, "TopicArn").or_else(|| param(req, "TargetArn"));
        let phone_number = param(req, "PhoneNumber");

        if topic_arn.is_none() && phone_number.is_none() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                "The request must contain the parameter TopicArn or TargetArn or PhoneNumber",
            ));
        }

        let message = required(req, "Message")?;
        let subject = param(req, "Subject");
        let message_group_id = param(req, "MessageGroupId");
        let message_dedup_id = param(req, "MessageDeduplicationId");
        let message_structure = param(req, "MessageStructure");

        // Validate subject length
        if let Some(ref subj) = subject {
            if subj.len() > 100 {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameter",
                    "Subject must be less than 100 characters",
                ));
            }
        }

        // Validate message length (256KB)
        if message.len() > 262144 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                "Invalid parameter: Message too long",
            ));
        }

        // Validate MessageStructure=json
        if message_structure.as_deref() == Some("json") {
            validate_message_structure_json(&message)?;
        }

        // Parse MessageAttributes from query params
        let message_attributes = parse_message_attributes(req);

        if let Some(ref phone) = phone_number {
            return self.publish_to_phone_number(
                req,
                phone,
                message,
                subject,
                message_attributes,
                message_group_id,
                message_dedup_id,
            );
        }

        let topic_arn = topic_arn.ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                "TopicArn or TargetArn is required",
            )
        })?;

        // Check if it's a platform endpoint ARN
        if topic_arn.contains(":endpoint/") {
            return self.publish_to_platform_endpoint(
                &topic_arn,
                &message,
                &message_attributes,
                &req.request_id,
            );
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let topic = state
            .topics
            .get(&topic_arn)
            .ok_or_else(|| not_found("Topic"))?;

        // FIFO topic enforcement
        if topic.is_fifo {
            if message_group_id.is_none() {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameter",
                    "Invalid parameter: The request must contain the parameter MessageGroupId.",
                ));
            }
            // FIFO topics require deduplication: either ContentBasedDeduplication or explicit ID
            let content_dedup = topic
                .attributes
                .get("ContentBasedDeduplication")
                .map(|v| v == "true")
                .unwrap_or(false);
            if !content_dedup && message_dedup_id.is_none() {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameter",
                    "Invalid parameter: The topic should either have ContentBasedDeduplication enabled or MessageDeduplicationId provided explicitly",
                ));
            }
        } else {
            // Non-FIFO: MessageGroupId is allowed (forwarded to SQS for fair queuing)
            // But DeduplicationId is NOT allowed on non-FIFO topics
            if message_dedup_id.is_some() {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameter",
                    "Invalid parameter: The request includes MessageDeduplicationId parameter that is not valid for this topic type",
                ));
            }
        }

        let kms_key_id = topic
            .attributes
            .get("KmsMasterKeyId")
            .cloned()
            .filter(|s| !s.is_empty());
        self.record_topic_kms_usage(&req.account_id, &topic_arn, kms_key_id.as_deref(), &message)?;

        let msg_id = uuid::Uuid::new_v4().to_string();
        state.published.push(PublishedMessage {
            message_id: msg_id.clone(),
            topic_arn: topic_arn.clone(),
            message: message.clone(),
            subject: subject.clone(),
            message_attributes: message_attributes.clone(),
            message_group_id: message_group_id.clone(),
            message_dedup_id: message_dedup_id.clone(),
            timestamp: Utc::now(),
        });

        // Resolve the actual message per protocol for MessageStructure=json
        let parsed_structure: Option<Value> = if message_structure.as_deref() == Some("json") {
            Some(serde_json::from_str(&message).map_err(|_| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameter",
                    "Invalid parameter: Message Structure - No JSON message body is parseable",
                )
            })?)
        } else {
            None
        };

        let subscribers =
            collect_topic_subscribers(state, &topic_arn, &message_attributes, &message);
        let endpoint = state.endpoint.clone();
        drop(accounts);

        // Determine actual message content per protocol
        let sqs_message = if let Some(ref structure) = parsed_structure {
            structure
                .get("sqs")
                .or_else(|| structure.get("default"))
                .and_then(|v| v.as_str())
                .unwrap_or(&message)
                .to_string()
        } else {
            message.clone()
        };

        let default_message = if let Some(ref structure) = parsed_structure {
            structure
                .get("default")
                .and_then(|v| v.as_str())
                .unwrap_or(&message)
                .to_string()
        } else {
            message.clone()
        };

        let envelope_attrs = build_envelope_attrs(&message_attributes);

        let ctx = TopicFanoutContext {
            msg_id: &msg_id,
            topic_arn: &topic_arn,
            subject: subject.as_deref(),
            endpoint: &endpoint,
            sqs_message: &sqs_message,
            default_message: &default_message,
            envelope_attrs: &envelope_attrs,
            message_attributes: &message_attributes,
            message_group_id: message_group_id.as_deref(),
            message_dedup_id: message_dedup_id.as_deref(),
        };

        self.deliver_to_sqs_subscribers(&subscribers.sqs, &ctx);
        self.deliver_to_http_subscribers(&subscribers.http, &ctx);
        self.deliver_to_lambda_subscribers(&subscribers.lambda, &ctx);
        self.deliver_to_email_subscribers(&subscribers.email, &ctx);
        self.deliver_to_sms_subscribers(&subscribers.sms, &ctx);

        Ok(xml_resp(
            &format!(
                r#"<PublishResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <PublishResult>
    <MessageId>{msg_id}</MessageId>
  </PublishResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</PublishResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn deliver_to_sqs_subscribers(&self, subs: &[(String, bool)], ctx: &TopicFanoutContext<'_>) {
        for (queue_arn, raw) in subs {
            if *raw {
                let mut sqs_msg_attrs = HashMap::new();
                for (k, v) in ctx.message_attributes {
                    let mut attr = fakecloud_core::delivery::SqsMessageAttribute {
                        data_type: v.data_type.clone(),
                        string_value: v.string_value.clone(),
                        binary_value: None,
                    };
                    if let Some(ref bv) = v.binary_value {
                        attr.binary_value =
                            Some(base64::engine::general_purpose::STANDARD.encode(bv));
                    }
                    sqs_msg_attrs.insert(k.clone(), attr);
                }
                self.delivery.send_to_sqs_with_attrs(
                    queue_arn,
                    ctx.sqs_message,
                    &sqs_msg_attrs,
                    ctx.message_group_id,
                    ctx.message_dedup_id,
                );
            } else {
                let envelope_str = build_sns_envelope(
                    ctx.msg_id,
                    ctx.topic_arn,
                    &ctx.subject.map(|s| s.to_string()),
                    ctx.sqs_message,
                    ctx.envelope_attrs,
                    ctx.endpoint,
                );
                self.delivery
                    .send_to_sqs(queue_arn, &envelope_str, &HashMap::new());
            }
        }
    }

    fn deliver_to_http_subscribers(&self, subs: &[String], ctx: &TopicFanoutContext<'_>) {
        for endpoint_url in subs {
            let body = build_sns_envelope(
                ctx.msg_id,
                ctx.topic_arn,
                &ctx.subject.map(|s| s.to_string()),
                ctx.default_message,
                ctx.envelope_attrs,
                ctx.endpoint,
            );
            let endpoint_url = endpoint_url.clone();
            let topic = ctx.topic_arn.to_string();
            tokio::spawn(async move {
                let client = reqwest::Client::new();
                let result = client
                    .post(&endpoint_url)
                    .header("Content-Type", "application/json")
                    .header("x-amz-sns-message-type", "Notification")
                    .header("x-amz-sns-topic-arn", &topic)
                    .body(body)
                    .send()
                    .await;
                if let Err(e) = result {
                    tracing::warn!(endpoint = %endpoint_url, error = %e, "SNS HTTP delivery failed");
                }
            });
        }
    }

    fn deliver_to_lambda_subscribers(
        &self,
        subs: &[(String, String)],
        ctx: &TopicFanoutContext<'_>,
    ) {
        if subs.is_empty() {
            return;
        }
        let now = Utc::now();
        let subject_owned = ctx.subject.map(|s| s.to_string());

        let lambda_payloads: Vec<(String, String)> = subs
            .iter()
            .map(|(function_arn, subscription_arn)| {
                let payload = build_sns_lambda_event(&SnsLambdaEventInput {
                    message_id: ctx.msg_id,
                    topic_arn: ctx.topic_arn,
                    subscription_arn,
                    message: ctx.default_message,
                    subject: ctx.subject,
                    message_attributes: ctx.envelope_attrs,
                    timestamp: &now,
                    endpoint: ctx.endpoint,
                });
                (function_arn.clone(), payload)
            })
            .collect();

        {
            let acct = ctx.topic_arn.split(':').nth(4).unwrap_or("");
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(acct);
            for (function_arn, _) in &lambda_payloads {
                state
                    .lambda_invocations
                    .push(crate::state::LambdaInvocation {
                        function_arn: function_arn.clone(),
                        message: ctx.default_message.to_string(),
                        subject: subject_owned.clone(),
                        timestamp: now,
                    });
            }
        }

        let delivery = self.delivery.clone();
        tokio::spawn(async move {
            for (function_arn, payload) in lambda_payloads {
                tracing::info!(function_arn = %function_arn, "SNS invoking Lambda function");
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
                        tracing::debug!(
                            function_arn = %function_arn,
                            "SNS->Lambda: no container runtime, skipping real execution"
                        );
                    }
                }
            }
        });
    }

    fn deliver_to_email_subscribers(&self, subs: &[String], ctx: &TopicFanoutContext<'_>) {
        if subs.is_empty() {
            return;
        }
        let now = Utc::now();
        let subject_owned = ctx.subject.map(|s| s.to_string());
        let acct = ctx.topic_arn.split(':').nth(4).unwrap_or("");
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(acct);
        for email_address in subs {
            tracing::info!(
                email = %email_address,
                topic_arn = %ctx.topic_arn,
                "SNS delivering to email (stub)"
            );
            state.sent_emails.push(crate::state::SentEmail {
                email_address: email_address.clone(),
                message: ctx.default_message.to_string(),
                subject: subject_owned.clone(),
                topic_arn: ctx.topic_arn.to_string(),
                timestamp: now,
            });
        }
    }

    fn deliver_to_sms_subscribers(&self, subs: &[String], ctx: &TopicFanoutContext<'_>) {
        if subs.is_empty() {
            return;
        }
        let acct = ctx.topic_arn.split(':').nth(4).unwrap_or("");
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(acct);
        for phone_number in subs {
            tracing::info!(
                phone_number = %phone_number,
                topic_arn = %ctx.topic_arn,
                "SNS delivering to SMS (stub)"
            );
            state
                .sms_messages
                .push((phone_number.clone(), ctx.default_message.to_string()));
        }
    }

    fn publish_batch(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let topic_arn = required(req, "TopicArn")?;

        let _accts = self.state.read();
        let _empty = crate::state::SnsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);
        let topic = state
            .topics
            .get(&topic_arn)
            .ok_or_else(|| not_found("Topic"))?;
        let is_fifo = topic.is_fifo;
        let endpoint = state.endpoint.clone();
        drop(_accts);

        // Parse batch entries: PublishBatchRequestEntries.member.N.*
        let mut entries = Vec::new();
        for n in 1..=100 {
            let id_key = format!("PublishBatchRequestEntries.member.{n}.Id");
            if let Some(id) = req.query_params.get(&id_key) {
                let msg_key = format!("PublishBatchRequestEntries.member.{n}.Message");
                let message = req.query_params.get(&msg_key).cloned().unwrap_or_default();
                let subject_key = format!("PublishBatchRequestEntries.member.{n}.Subject");
                let subject = req.query_params.get(&subject_key).cloned();
                let group_key = format!("PublishBatchRequestEntries.member.{n}.MessageGroupId");
                let group_id = req.query_params.get(&group_key).cloned();
                let dedup_key =
                    format!("PublishBatchRequestEntries.member.{n}.MessageDeduplicationId");
                let dedup_id = req.query_params.get(&dedup_key).cloned();
                let structure_key =
                    format!("PublishBatchRequestEntries.member.{n}.MessageStructure");
                let message_structure = req.query_params.get(&structure_key).cloned();
                entries.push((
                    id.clone(),
                    message,
                    subject,
                    group_id,
                    dedup_id,
                    message_structure,
                ));
            } else {
                break;
            }
        }

        // Validate: max 10 entries
        if entries.len() > 10 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "TooManyEntriesInBatchRequest",
                "The batch request contains more entries than permissible.",
            ));
        }

        // Validate: unique IDs
        let ids: Vec<&str> = entries.iter().map(|e| e.0.as_str()).collect();
        let unique_ids: std::collections::HashSet<&str> = ids.iter().copied().collect();
        if unique_ids.len() != ids.len() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "BatchEntryIdsNotDistinct",
                "Two or more batch entries in the request have the same Id.",
            ));
        }

        // FIFO: all entries must have MessageGroupId — this is a top-level error
        if is_fifo && entries.iter().any(|e| e.3.is_none()) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                "Invalid parameter: The MessageGroupId parameter is required for FIFO topics",
            ));
        }

        let mut successful = Vec::new();
        let failed: Vec<String> = Vec::new();

        for (idx, (id, message, subject, group_id, dedup_id, structure)) in
            entries.iter().enumerate()
        {
            // Parse per-entry message attributes
            let batch_attrs = parse_batch_message_attributes(req, idx + 1);

            // Validate MessageStructure=json
            if structure.as_deref() == Some("json") {
                validate_message_structure_json(message)?;
            }

            let msg_id = uuid::Uuid::new_v4().to_string();
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&req.account_id);
            state.published.push(PublishedMessage {
                message_id: msg_id.clone(),
                topic_arn: topic_arn.clone(),
                message: message.clone(),
                subject: subject.clone(),
                message_attributes: batch_attrs.clone(),
                message_group_id: group_id.clone(),
                message_dedup_id: dedup_id.clone(),
                timestamp: Utc::now(),
            });

            // Resolve message for SQS via MessageStructure=json
            let parsed_structure: Option<Value> = if structure.as_deref() == Some("json") {
                Some(serde_json::from_str(message).map_err(|_| {
                    AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameter",
                        "Invalid parameter: Message Structure - No JSON message body is parseable",
                    )
                })?)
            } else {
                None
            };
            let sqs_message = if let Some(ref s) = parsed_structure {
                s.get("sqs")
                    .or_else(|| s.get("default"))
                    .and_then(|v| v.as_str())
                    .unwrap_or(message)
                    .to_string()
            } else {
                message.clone()
            };

            // Deliver to SQS subscribers
            let sqs_subscribers: Vec<(String, bool)> = state
                .subscriptions
                .values()
                .filter(|s| s.topic_arn == topic_arn && s.protocol == "sqs" && s.confirmed)
                .map(|s| {
                    let raw = s
                        .attributes
                        .get("RawMessageDelivery")
                        .map(|v| v == "true")
                        .unwrap_or(false);
                    (s.endpoint.clone(), raw)
                })
                .collect();
            drop(accounts);

            // Build envelope attributes
            let mut envelope_attrs = serde_json::Map::new();
            for (key, attr) in &batch_attrs {
                let mut attr_obj = serde_json::Map::new();
                attr_obj.insert("Type".to_string(), Value::String(attr.data_type.clone()));
                if let Some(ref sv) = attr.string_value {
                    attr_obj.insert("Value".to_string(), Value::String(sv.clone()));
                }
                if let Some(ref bv) = attr.binary_value {
                    attr_obj.insert(
                        "Value".to_string(),
                        Value::String(base64::engine::general_purpose::STANDARD.encode(bv)),
                    );
                }
                envelope_attrs.insert(key.clone(), Value::Object(attr_obj));
            }

            for (queue_arn, raw) in &sqs_subscribers {
                if *raw {
                    let mut sqs_msg_attrs = HashMap::new();
                    for (k, v) in &batch_attrs {
                        let mut attr = fakecloud_core::delivery::SqsMessageAttribute {
                            data_type: v.data_type.clone(),
                            string_value: v.string_value.clone(),
                            binary_value: None,
                        };
                        if let Some(ref bv) = v.binary_value {
                            attr.binary_value =
                                Some(base64::engine::general_purpose::STANDARD.encode(bv));
                        }
                        sqs_msg_attrs.insert(k.clone(), attr);
                    }
                    self.delivery.send_to_sqs_with_attrs(
                        queue_arn,
                        &sqs_message,
                        &sqs_msg_attrs,
                        if is_fifo { group_id.as_deref() } else { None },
                        if is_fifo { dedup_id.as_deref() } else { None },
                    );
                } else {
                    let envelope_str = build_sns_envelope(
                        &msg_id,
                        &topic_arn,
                        subject,
                        &sqs_message,
                        &envelope_attrs,
                        &endpoint,
                    );
                    self.delivery
                        .send_to_sqs(queue_arn, &envelope_str, &HashMap::new());
                }
            }

            successful.push(format!(
                r#"    <member>
      <Id>{id}</Id>
      <MessageId>{msg_id}</MessageId>
    </member>"#
            ));
        }

        let successful_xml = successful.join("\n");
        let failed_xml = failed.join("\n");

        Ok(xml_resp(
            &format!(
                r#"<PublishBatchResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <PublishBatchResult>
    <Successful>
{successful_xml}
    </Successful>
    <Failed>
{failed_xml}
    </Failed>
  </PublishBatchResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</PublishBatchResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    /// Publish directly to an SMS destination (`Publish` called with
    /// `PhoneNumber` instead of `TopicArn` / `TargetArn`). This path
    /// does its own length and E.164 validation since AWS reports
    /// distinct error messages for SMS.
    #[allow(clippy::too_many_arguments)]
    fn publish_to_phone_number(
        &self,
        req: &AwsRequest,
        phone: &str,
        message: String,
        subject: Option<String>,
        message_attributes: BTreeMap<String, MessageAttribute>,
        message_group_id: Option<String>,
        message_dedup_id: Option<String>,
    ) -> Result<AwsResponse, AwsServiceError> {
        let is_valid_e164 = phone.starts_with('+')
            && phone.len() >= 2
            && phone[1..].chars().all(|c| c.is_ascii_digit());
        if !is_valid_e164 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                format!(
                    "Invalid parameter: PhoneNumber Reason: {phone} does not meet the E164 format"
                ),
            ));
        }

        if message.len() > 1600 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                "Invalid parameter: Message Reason: Message must be less than 1600 characters long",
            ));
        }

        let msg_id = uuid::Uuid::new_v4().to_string();
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state
            .sms_messages
            .push((phone.to_string(), message.clone()));
        state.published.push(PublishedMessage {
            message_id: msg_id.clone(),
            topic_arn: String::new(),
            message,
            subject,
            message_attributes,
            message_group_id,
            message_dedup_id,
            timestamp: Utc::now(),
        });

        Ok(xml_resp(
            &format!(
                r#"<PublishResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <PublishResult>
    <MessageId>{msg_id}</MessageId>
  </PublishResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</PublishResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn publish_to_platform_endpoint(
        &self,
        endpoint_arn: &str,
        message: &str,
        message_attributes: &BTreeMap<String, MessageAttribute>,
        request_id: &str,
    ) -> Result<AwsResponse, AwsServiceError> {
        let acct = endpoint_arn.split(':').nth(4).unwrap_or("");
        let _accts = self.state.read();
        let state = _accts.get(acct).unwrap_or_else(|| _accts.default_ref());

        // Find the platform endpoint
        let mut found_endpoint: Option<&PlatformEndpoint> = None;
        for app in state.platform_applications.values() {
            if let Some(ep) = app.endpoints.get(endpoint_arn) {
                found_endpoint = Some(ep);
                break;
            }
        }

        let ep = found_endpoint.ok_or_else(|| {
            AwsServiceError::aws_error(StatusCode::NOT_FOUND, "NotFound", "Endpoint does not exist")
        })?;

        if !ep.enabled {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "EndpointDisabled",
                "Endpoint is disabled",
            ));
        }
        drop(_accts);

        let msg_id = uuid::Uuid::new_v4().to_string();
        let acct = endpoint_arn.split(':').nth(4).unwrap_or("");
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(acct);
        // Store message on the endpoint
        for app in state.platform_applications.values_mut() {
            if let Some(ep) = app.endpoints.get_mut(endpoint_arn) {
                ep.messages.push(PublishedMessage {
                    message_id: msg_id.clone(),
                    topic_arn: endpoint_arn.to_string(),
                    message: message.to_string(),
                    subject: None,
                    message_attributes: message_attributes.clone(),
                    message_group_id: None,
                    message_dedup_id: None,
                    timestamp: Utc::now(),
                });
                break;
            }
        }

        Ok(xml_resp(
            &format!(
                r#"<PublishResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <PublishResult>
    <MessageId>{msg_id}</MessageId>
  </PublishResult>
  <ResponseMetadata>
    <RequestId>{request_id}</RequestId>
  </ResponseMetadata>
</PublishResponse>"#,
            ),
            request_id,
        ))
    }

    fn list_subscriptions(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let _accts = self.state.read();
        let _empty = crate::state::SnsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);

        let all_subs: Vec<&SnsSubscription> = state.subscriptions.values().collect();
        let next_token = param(req, "NextToken")
            .and_then(|t| t.parse::<usize>().ok())
            .unwrap_or(0);
        let next_token = next_token.min(all_subs.len());

        let page = &all_subs[next_token..];
        let has_more = page.len() > DEFAULT_PAGE_SIZE;
        let page = if has_more {
            &page[..DEFAULT_PAGE_SIZE]
        } else {
            page
        };

        let members: String = page
            .iter()
            .map(|s| format_sub_member(s))
            .collect::<Vec<_>>()
            .join("\n");

        let next_token_xml = if has_more {
            format!(
                "\n    <NextToken>{}</NextToken>",
                next_token + DEFAULT_PAGE_SIZE
            )
        } else {
            String::new()
        };

        Ok(xml_resp(
            &format!(
                r#"<ListSubscriptionsResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ListSubscriptionsResult>
    <Subscriptions>
{members}
    </Subscriptions>{next_token_xml}
  </ListSubscriptionsResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</ListSubscriptionsResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn list_subscriptions_by_topic(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let topic_arn = required(req, "TopicArn")?;
        let _accts = self.state.read();
        let _empty = crate::state::SnsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);

        let all_subs: Vec<&SnsSubscription> = state
            .subscriptions
            .values()
            .filter(|s| s.topic_arn == topic_arn)
            .collect();

        let next_token = param(req, "NextToken")
            .and_then(|t| t.parse::<usize>().ok())
            .unwrap_or(0);
        let next_token = next_token.min(all_subs.len());

        let page = &all_subs[next_token..];
        let has_more = page.len() > DEFAULT_PAGE_SIZE;
        let page = if has_more {
            &page[..DEFAULT_PAGE_SIZE]
        } else {
            page
        };

        let members: String = page
            .iter()
            .map(|s| format_sub_member(s))
            .collect::<Vec<_>>()
            .join("\n");

        let next_token_xml = if has_more {
            format!(
                "\n    <NextToken>{}</NextToken>",
                next_token + DEFAULT_PAGE_SIZE
            )
        } else {
            String::new()
        };

        Ok(xml_resp(
            &format!(
                r#"<ListSubscriptionsByTopicResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ListSubscriptionsByTopicResult>
    <Subscriptions>
{members}
    </Subscriptions>{next_token_xml}
  </ListSubscriptionsByTopicResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</ListSubscriptionsByTopicResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn get_subscription_attributes(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let sub_arn = required(req, "SubscriptionArn")?;
        let _accts = self.state.read();
        let _empty = crate::state::SnsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);
        let sub = state
            .subscriptions
            .get(&sub_arn)
            .ok_or_else(|| not_found("Subscription"))?;

        let mut entries = vec![
            format_attr("SubscriptionArn", &sub.subscription_arn),
            format_attr("TopicArn", &sub.topic_arn),
            format_attr("Protocol", &sub.protocol),
            format_attr("Endpoint", &sub.endpoint),
            format_attr("Owner", &sub.owner),
            format_attr("ConfirmationWasAuthenticated", "true"),
            format_attr("PendingConfirmation", "false"),
        ];

        // Add RawMessageDelivery from attributes or default
        if !sub.attributes.contains_key("RawMessageDelivery") {
            entries.push(format_attr("RawMessageDelivery", "false"));
        }

        // Add EffectiveDeliveryPolicy
        entries.push(format_attr(
            "EffectiveDeliveryPolicy",
            DEFAULT_EFFECTIVE_DELIVERY_POLICY,
        ));

        for (k, v) in &sub.attributes {
            // Skip empty FilterPolicy (unsetting it removes it)
            if k == "FilterPolicy" && v.is_empty() {
                continue;
            }
            // If FilterPolicy is unset, also skip FilterPolicyScope
            if k == "FilterPolicyScope" {
                let has_filter = sub
                    .attributes
                    .get("FilterPolicy")
                    .map(|v| !v.is_empty())
                    .unwrap_or(false);
                if !has_filter {
                    continue;
                }
            }
            entries.push(format_attr(k, v));
        }
        let attrs = entries.join("\n");

        Ok(xml_resp(
            &format!(
                r#"<GetSubscriptionAttributesResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <GetSubscriptionAttributesResult>
    <Attributes>
{attrs}
    </Attributes>
  </GetSubscriptionAttributesResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</GetSubscriptionAttributesResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn set_subscription_attributes(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let sub_arn = required(req, "SubscriptionArn")?;
        let attr_name = required(req, "AttributeName")?;
        let attr_value = param(req, "AttributeValue").unwrap_or_default();

        // Validate attribute name
        if !VALID_SUBSCRIPTION_ATTRS.contains(&attr_name.as_str()) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                "Invalid parameter: AttributeName".to_string(),
            ));
        }

        // Validate filter policy
        if attr_name == "FilterPolicy" && !attr_value.is_empty() {
            validate_filter_policy(&attr_value)?;
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let sub = state
            .subscriptions
            .get_mut(&sub_arn)
            .ok_or_else(|| not_found("Subscription"))?;

        sub.attributes.insert(attr_name.clone(), attr_value.clone());

        // Setting FilterPolicy auto-sets FilterPolicyScope
        if attr_name == "FilterPolicy" && !attr_value.is_empty() {
            sub.attributes
                .entry("FilterPolicyScope".to_string())
                .or_insert_with(|| "MessageAttributes".to_string());
        }

        Ok(xml_resp(
            &format!(
                r#"<SetSubscriptionAttributesResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</SetSubscriptionAttributesResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn tag_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let resource_arn = required(req, "ResourceArn")?;
        let new_tags = parse_tags(req);

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let topic = state.topics.get_mut(&resource_arn).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFound",
                "Resource does not exist",
            )
        })?;

        // Check tag quota: existing + new (after dedup) must not exceed 50
        let mut merged = topic.tags.clone();
        for (k, v) in &new_tags {
            // Update existing or add
            if let Some(pos) = merged.iter().position(|(ek, _)| ek == k) {
                merged[pos] = (k.clone(), v.clone());
            } else {
                merged.push((k.clone(), v.clone()));
            }
        }
        if merged.len() > 50 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "TagLimitExceeded",
                "Could not complete request: tag quota of per resource exceeded",
            ));
        }

        topic.tags = merged;

        Ok(xml_resp(
            &format!(
                r#"<TagResourceResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <TagResourceResult/>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</TagResourceResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn untag_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let resource_arn = required(req, "ResourceArn")?;
        let tag_keys = parse_tag_keys(req);

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let topic = state.topics.get_mut(&resource_arn).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFound",
                "Resource does not exist",
            )
        })?;
        topic.tags.retain(|(k, _)| !tag_keys.contains(k));

        Ok(xml_resp(
            &format!(
                r#"<UntagResourceResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <UntagResourceResult/>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</UntagResourceResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn list_tags_for_resource(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let resource_arn = required(req, "ResourceArn")?;
        let _accts = self.state.read();
        let _empty = crate::state::SnsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);
        let topic = state.topics.get(&resource_arn).ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFound",
                "Resource does not exist",
            )
        })?;

        let members: String = topic
            .tags
            .iter()
            .map(|(k, v)| format!("      <member><Key>{k}</Key><Value>{v}</Value></member>"))
            .collect::<Vec<_>>()
            .join("\n");

        Ok(xml_resp(
            &format!(
                r#"<ListTagsForResourceResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ListTagsForResourceResult>
    <Tags>
{members}
    </Tags>
  </ListTagsForResourceResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</ListTagsForResourceResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn add_permission(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let topic_arn = required(req, "TopicArn")?;
        let label = required(req, "Label")?;

        // Parse AWSAccountId.member.N and ActionName.member.N
        let mut account_ids = Vec::new();
        for n in 1..=20 {
            let key = format!("AWSAccountId.member.{n}");
            if let Some(v) = req.query_params.get(&key) {
                account_ids.push(v.clone());
            } else {
                break;
            }
        }

        let mut action_names = Vec::new();
        for n in 1..=20 {
            let key = format!("ActionName.member.{n}");
            if let Some(v) = req.query_params.get(&key) {
                action_names.push(v.clone());
            } else {
                break;
            }
        }

        // Validate action names
        for action in &action_names {
            if !VALID_SNS_ACTIONS.contains(&action.as_str()) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameter",
                    "Policy statement action out of service scope!",
                ));
            }
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let account_id = state.account_id.clone();
        let topic = state
            .topics
            .get_mut(&topic_arn)
            .ok_or_else(|| not_found("Topic"))?;

        // Get or create policy
        let policy_str = topic
            .attributes
            .get("Policy")
            .cloned()
            .unwrap_or_else(|| default_policy(&topic_arn, &account_id));

        let mut policy: Value = serde_json::from_str(&policy_str)
            .or_else(|_| serde_json::from_str(&default_policy(&topic_arn, &account_id)))
            .map_err(|_| {
                AwsServiceError::aws_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "Failed to parse topic policy",
                )
            })?;

        // Check if statement with this label already exists
        if let Some(statements) = policy["Statement"].as_array() {
            for stmt in statements {
                if stmt["Sid"].as_str() == Some(&label) {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameter",
                        "Statement already exists",
                    ));
                }
            }
        }

        // Build principal
        let principal = if account_ids.len() == 1 {
            Value::String(Arn::global("iam", &account_ids[0], "root").to_string())
        } else {
            Value::Array(
                account_ids
                    .iter()
                    .map(|id| Value::String(Arn::global("iam", id, "root").to_string()))
                    .collect(),
            )
        };

        // Build action
        let action = if action_names.len() == 1 {
            Value::String(format!("SNS:{}", action_names[0]))
        } else {
            Value::Array(
                action_names
                    .iter()
                    .map(|a| Value::String(format!("SNS:{}", a)))
                    .collect(),
            )
        };

        let new_statement = serde_json::json!({
            "Sid": label,
            "Effect": "Allow",
            "Principal": {"AWS": principal},
            "Action": action,
            "Resource": topic_arn,
        });

        if let Some(statements) = policy["Statement"].as_array_mut() {
            statements.push(new_statement);
        }

        topic
            .attributes
            .insert("Policy".to_string(), policy.to_string());

        Ok(xml_resp(
            &format!(
                r#"<AddPermissionResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</AddPermissionResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn remove_permission(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let topic_arn = required(req, "TopicArn")?;
        let label = required(req, "Label")?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let topic = state
            .topics
            .get_mut(&topic_arn)
            .ok_or_else(|| not_found("Topic"))?;

        if let Some(policy_str) = topic.attributes.get("Policy").cloned() {
            if let Ok(mut policy) = serde_json::from_str::<Value>(&policy_str) {
                if let Some(statements) = policy["Statement"].as_array_mut() {
                    statements.retain(|s| s["Sid"].as_str() != Some(&label));
                }
                topic
                    .attributes
                    .insert("Policy".to_string(), policy.to_string());
            }
        }

        Ok(xml_resp(
            &format!(
                r#"<RemovePermissionResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</RemovePermissionResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    // ===== Platform Application actions =====

    fn create_platform_application(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let name = required(req, "Name")?;
        let platform = required(req, "Platform")?;
        let attributes = parse_entries(req, "Attributes");

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let arn = format!(
            "arn:aws:sns:{}:{}:app/{}/{}",
            req.region, state.account_id, platform, name
        );

        state.platform_applications.insert(
            arn.clone(),
            PlatformApplication {
                arn: arn.clone(),
                name,
                platform,
                attributes,
                endpoints: BTreeMap::new(),
            },
        );

        Ok(xml_resp(
            &format!(
                r#"<CreatePlatformApplicationResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <CreatePlatformApplicationResult>
    <PlatformApplicationArn>{arn}</PlatformApplicationArn>
  </CreatePlatformApplicationResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</CreatePlatformApplicationResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn delete_platform_application(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required(req, "PlatformApplicationArn")?;
        self.state
            .write()
            .get_or_create(&req.account_id)
            .platform_applications
            .remove(&arn);

        Ok(xml_resp(
            &format!(
                r#"<DeletePlatformApplicationResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</DeletePlatformApplicationResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn get_platform_application_attributes(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required(req, "PlatformApplicationArn")?;
        let _accts = self.state.read();
        let _empty = crate::state::SnsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);
        let app = state
            .platform_applications
            .get(&arn)
            .ok_or_else(|| not_found("PlatformApplication"))?;

        let attrs: String = app
            .attributes
            .iter()
            .map(|(k, v)| format_attr(k, v))
            .collect::<Vec<_>>()
            .join("\n");

        Ok(xml_resp(
            &format!(
                r#"<GetPlatformApplicationAttributesResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <GetPlatformApplicationAttributesResult>
    <Attributes>
{attrs}
    </Attributes>
  </GetPlatformApplicationAttributesResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</GetPlatformApplicationAttributesResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn set_platform_application_attributes(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let arn = required(req, "PlatformApplicationArn")?;
        let new_attrs = parse_entries(req, "Attributes");

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let app = state
            .platform_applications
            .get_mut(&arn)
            .ok_or_else(|| not_found("PlatformApplication"))?;

        for (k, v) in new_attrs {
            app.attributes.insert(k, v);
        }

        Ok(xml_resp(
            &format!(
                r#"<SetPlatformApplicationAttributesResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</SetPlatformApplicationAttributesResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn list_platform_applications(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let _accts = self.state.read();
        let _empty = crate::state::SnsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);

        let members: String = state
            .platform_applications
            .values()
            .map(|app| {
                let attrs: String = app
                    .attributes
                    .iter()
                    .map(|(k, v)| format_attr(k, v))
                    .collect::<Vec<_>>()
                    .join("\n");
                format!(
                    r#"      <member>
        <PlatformApplicationArn>{}</PlatformApplicationArn>
        <Attributes>
{attrs}
        </Attributes>
      </member>"#,
                    app.arn
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        Ok(xml_resp(
            &format!(
                r#"<ListPlatformApplicationsResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ListPlatformApplicationsResult>
    <PlatformApplications>
{members}
    </PlatformApplications>
  </ListPlatformApplicationsResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</ListPlatformApplicationsResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn create_platform_endpoint(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let app_arn = required(req, "PlatformApplicationArn")?;
        let token = required(req, "Token")?;
        let custom_user_data = param(req, "CustomUserData");
        let attrs = parse_entries(req, "Attributes");

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let account_id = state.account_id.clone();
        let app = state
            .platform_applications
            .get_mut(&app_arn)
            .ok_or_else(|| not_found("PlatformApplication"))?;

        // Check for existing endpoint with same token
        for (arn, ep) in &app.endpoints {
            if ep.token == token {
                // If attributes are different, check Enabled attribute
                let existing_enabled = ep
                    .attributes
                    .get("Enabled")
                    .cloned()
                    .unwrap_or_else(|| "true".to_string());
                let new_enabled = attrs
                    .get("Enabled")
                    .cloned()
                    .unwrap_or_else(|| "true".to_string());
                let custom_matches = match (&custom_user_data, ep.attributes.get("CustomUserData"))
                {
                    (Some(new), Some(old)) => new == old,
                    (None, None) => true,
                    (None, Some(_)) => true,
                    _ => false,
                };

                if existing_enabled == new_enabled && custom_matches {
                    // Return existing endpoint
                    return Ok(xml_resp(
                        &format!(
                            r#"<CreatePlatformEndpointResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <CreatePlatformEndpointResult>
    <EndpointArn>{arn}</EndpointArn>
  </CreatePlatformEndpointResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</CreatePlatformEndpointResponse>"#,
                            req.request_id
                        ),
                        &req.request_id,
                    ));
                } else {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameter",
                        format!("Invalid parameter: Token Reason: Endpoint {} already exists with the same Token, but different attributes.", arn),
                    ));
                }
            }
        }

        let endpoint_id = uuid::Uuid::new_v4().to_string().replace('-', "");
        let endpoint_arn = format!(
            "arn:aws:sns:{}:{}:endpoint/{}/{}/{}",
            req.region, account_id, app.platform, app.name, endpoint_id
        );

        let mut endpoint_attrs = attrs;
        endpoint_attrs
            .entry("Enabled".to_string())
            .or_insert_with(|| "true".to_string());
        endpoint_attrs.insert("Token".to_string(), token.clone());
        if let Some(ref ud) = custom_user_data {
            endpoint_attrs
                .entry("CustomUserData".to_string())
                .or_insert_with(|| ud.clone());
        }

        let enabled = endpoint_attrs
            .get("Enabled")
            .map(|v| v == "true")
            .unwrap_or(true);

        app.endpoints.insert(
            endpoint_arn.clone(),
            PlatformEndpoint {
                arn: endpoint_arn.clone(),
                token,
                attributes: endpoint_attrs,
                enabled,
                messages: Vec::new(),
            },
        );

        Ok(xml_resp(
            &format!(
                r#"<CreatePlatformEndpointResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <CreatePlatformEndpointResult>
    <EndpointArn>{endpoint_arn}</EndpointArn>
  </CreatePlatformEndpointResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</CreatePlatformEndpointResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn delete_endpoint(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let endpoint_arn = required(req, "EndpointArn")?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        for app in state.platform_applications.values_mut() {
            app.endpoints.remove(&endpoint_arn);
        }

        Ok(xml_resp(
            &format!(
                r#"<DeleteEndpointResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</DeleteEndpointResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn get_endpoint_attributes(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let endpoint_arn = required(req, "EndpointArn")?;

        let _accts = self.state.read();
        let _empty = crate::state::SnsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);
        for app in state.platform_applications.values() {
            if let Some(ep) = app.endpoints.get(&endpoint_arn) {
                let attrs: String = ep
                    .attributes
                    .iter()
                    .map(|(k, v)| format_attr(k, v))
                    .collect::<Vec<_>>()
                    .join("\n");

                return Ok(xml_resp(
                    &format!(
                        r#"<GetEndpointAttributesResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <GetEndpointAttributesResult>
    <Attributes>
{attrs}
    </Attributes>
  </GetEndpointAttributesResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</GetEndpointAttributesResponse>"#,
                        req.request_id
                    ),
                    &req.request_id,
                ));
            }
        }

        Err(not_found("Endpoint"))
    }

    fn set_endpoint_attributes(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let endpoint_arn = required(req, "EndpointArn")?;
        let new_attrs = parse_entries(req, "Attributes");

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        for app in state.platform_applications.values_mut() {
            if let Some(ep) = app.endpoints.get_mut(&endpoint_arn) {
                for (k, v) in new_attrs {
                    if k == "Enabled" {
                        ep.enabled = v == "true";
                    }
                    ep.attributes.insert(k, v);
                }

                return Ok(xml_resp(
                    &format!(
                        r#"<SetEndpointAttributesResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</SetEndpointAttributesResponse>"#,
                        req.request_id
                    ),
                    &req.request_id,
                ));
            }
        }

        Err(not_found("Endpoint"))
    }

    fn list_endpoints_by_platform_application(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let app_arn = required(req, "PlatformApplicationArn")?;

        let _accts = self.state.read();
        let _empty = crate::state::SnsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);
        let app = state
            .platform_applications
            .get(&app_arn)
            .ok_or_else(|| not_found("PlatformApplication"))?;

        let members: String = app
            .endpoints
            .values()
            .map(|ep| {
                let attrs: String = ep
                    .attributes
                    .iter()
                    .map(|(k, v)| format_attr(k, v))
                    .collect::<Vec<_>>()
                    .join("\n");
                format!(
                    r#"      <member>
        <EndpointArn>{}</EndpointArn>
        <Attributes>
{attrs}
        </Attributes>
      </member>"#,
                    ep.arn
                )
            })
            .collect::<Vec<_>>()
            .join("\n");

        Ok(xml_resp(
            &format!(
                r#"<ListEndpointsByPlatformApplicationResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ListEndpointsByPlatformApplicationResult>
    <Endpoints>
{members}
    </Endpoints>
  </ListEndpointsByPlatformApplicationResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</ListEndpointsByPlatformApplicationResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    // ===== SMS actions =====

    fn set_sms_attributes(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let attrs = parse_entries(req, "attributes");

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        for (k, v) in attrs {
            state.sms_attributes.insert(k, v);
        }

        Ok(xml_resp(
            &format!(
                r#"<SetSMSAttributesResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <SetSMSAttributesResult/>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</SetSMSAttributesResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn get_sms_attributes(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        // Parse optional attribute name filter: attributes.member.N
        let mut filter_names = Vec::new();
        for n in 1..=50 {
            let key = format!("attributes.member.{n}");
            if let Some(name) = req.query_params.get(&key) {
                filter_names.push(name.clone());
            } else {
                break;
            }
        }

        let _accts = self.state.read();
        let _empty = crate::state::SnsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);

        let attrs: String = state
            .sms_attributes
            .iter()
            .filter(|(k, _)| filter_names.is_empty() || filter_names.contains(k))
            .map(|(k, v)| format_attr(k, v))
            .collect::<Vec<_>>()
            .join("\n");

        Ok(xml_resp(
            &format!(
                r#"<GetSMSAttributesResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <GetSMSAttributesResult>
    <attributes>
{attrs}
    </attributes>
  </GetSMSAttributesResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</GetSMSAttributesResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn check_if_phone_number_is_opted_out(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let phone_number = required(req, "phoneNumber")?;

        // Validate phone number format (E.164)
        let valid = phone_number.starts_with('+')
            && phone_number.len() >= 2
            && phone_number[1..].chars().all(|c| c.is_ascii_digit());
        if !valid {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                format!(
                    "Invalid parameter: PhoneNumber Reason: {phone_number} does not meet the E164 format"
                ),
            ));
        }

        let _accts = self.state.read();
        let _empty = crate::state::SnsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);
        // Numbers ending in 99 are considered opted out by convention
        let is_opted_out =
            state.opted_out_numbers.contains(&phone_number) || phone_number.ends_with("99");

        Ok(xml_resp(
            &format!(
                r#"<CheckIfPhoneNumberIsOptedOutResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <CheckIfPhoneNumberIsOptedOutResult>
    <isOptedOut>{is_opted_out}</isOptedOut>
  </CheckIfPhoneNumberIsOptedOutResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</CheckIfPhoneNumberIsOptedOutResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn list_phone_numbers_opted_out(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let _accts = self.state.read();
        let _empty = crate::state::SnsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);
        let members: String = state
            .opted_out_numbers
            .iter()
            .map(|n| format!("      <member>{n}</member>"))
            .collect::<Vec<_>>()
            .join("\n");

        Ok(xml_resp(
            &format!(
                r#"<ListPhoneNumbersOptedOutResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ListPhoneNumbersOptedOutResult>
    <phoneNumbers>
{members}
    </phoneNumbers>
  </ListPhoneNumbersOptedOutResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</ListPhoneNumbersOptedOutResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn opt_in_phone_number(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let phone_number = required(req, "phoneNumber")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state.opted_out_numbers.retain(|n| n != &phone_number);

        Ok(xml_resp(
            &format!(
                r#"<OptInPhoneNumberResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <OptInPhoneNumberResult/>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</OptInPhoneNumberResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn create_sms_sandbox_phone_number(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let phone_number = required(req, "PhoneNumber")?;
        validate_e164(&phone_number)?;
        let language_code = param(req, "LanguageCode").unwrap_or_else(|| "en-US".to_string());
        if !is_valid_sandbox_language(&language_code) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                format!("Invalid parameter: LanguageCode {language_code} is not supported"),
            ));
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if state.sms_sandbox_phone_numbers.contains_key(&phone_number) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "OptedOutException",
                format!(
                    "Phone number {phone_number} is already registered as a sandbox destination."
                ),
            ));
        }
        let otp = format!("{:06}", rand_u32() % 1_000_000);
        state.sms_sandbox_phone_numbers.insert(
            phone_number.clone(),
            crate::state::SmsSandboxPhoneNumber {
                phone_number: phone_number.clone(),
                language_code,
                status: crate::state::SmsSandboxPhoneStatus::Pending,
                one_time_password: otp,
            },
        );
        Ok(xml_resp(
            &format!(
                r#"<CreateSMSSandboxPhoneNumberResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <CreateSMSSandboxPhoneNumberResult/>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</CreateSMSSandboxPhoneNumberResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn delete_sms_sandbox_phone_number(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let phone_number = required(req, "PhoneNumber")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if state
            .sms_sandbox_phone_numbers
            .remove(&phone_number)
            .is_none()
        {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "ResourceNotFound",
                format!("Sandbox phone number {phone_number} not found."),
            ));
        }
        Ok(xml_resp(
            &format!(
                r#"<DeleteSMSSandboxPhoneNumberResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <DeleteSMSSandboxPhoneNumberResult/>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</DeleteSMSSandboxPhoneNumberResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn verify_sms_sandbox_phone_number(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let phone_number = required(req, "PhoneNumber")?;
        let one_time_password = required(req, "OneTimePassword")?;
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        let entry = state
            .sms_sandbox_phone_numbers
            .get_mut(&phone_number)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "ResourceNotFound",
                    format!("Sandbox phone number {phone_number} not found."),
                )
            })?;
        if entry.one_time_password != one_time_password {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "VerificationException",
                "The verification code provided is incorrect.",
            ));
        }
        entry.status = crate::state::SmsSandboxPhoneStatus::Verified;
        Ok(xml_resp(
            &format!(
                r#"<VerifySMSSandboxPhoneNumberResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <VerifySMSSandboxPhoneNumberResult/>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</VerifySMSSandboxPhoneNumberResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn list_sms_sandbox_phone_numbers(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let _accts = self.state.read();
        let _empty = crate::state::SnsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);
        let members: String = state
            .sms_sandbox_phone_numbers
            .values()
            .map(|p| {
                format!(
                    "      <member>\n        <PhoneNumber>{}</PhoneNumber>\n        <Status>{}</Status>\n      </member>",
                    xml_escape(&p.phone_number),
                    p.status.as_str()
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        Ok(xml_resp(
            &format!(
                r#"<ListSMSSandboxPhoneNumbersResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ListSMSSandboxPhoneNumbersResult>
    <PhoneNumbers>
{members}
    </PhoneNumbers>
  </ListSMSSandboxPhoneNumbersResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</ListSMSSandboxPhoneNumbersResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn get_sms_sandbox_account_status(
        &self,
        req: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let _accts = self.state.read();
        let _empty = crate::state::SnsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);
        let in_sandbox = state.is_sms_sandboxed();
        Ok(xml_resp(
            &format!(
                r#"<GetSMSSandboxAccountStatusResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <GetSMSSandboxAccountStatusResult>
    <IsInSandbox>{in_sandbox}</IsInSandbox>
  </GetSMSSandboxAccountStatusResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</GetSMSSandboxAccountStatusResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn list_origination_numbers(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        state.seed_default_origination_numbers();
        let members: String = state
            .origination_numbers
            .iter()
            .map(|n| {
                let caps: String = n
                    .number_capabilities
                    .iter()
                    .map(|c| format!("          <member>{}</member>", xml_escape(c)))
                    .collect::<Vec<_>>()
                    .join("\n");
                format!(
                    r#"      <member>
        <PhoneNumber>{phone}</PhoneNumber>
        <IsoCountryCode>{iso}</IsoCountryCode>
        <Status>{status}</Status>
        <RouteType>{rt}</RouteType>
        <NumberCapabilities>
{caps}
        </NumberCapabilities>
        <CreatedAt>{created}</CreatedAt>
      </member>"#,
                    phone = xml_escape(&n.phone_number),
                    iso = xml_escape(&n.iso_country_code),
                    status = xml_escape(&n.status),
                    rt = xml_escape(&n.route_type),
                    caps = caps,
                    created = n.created_at.format("%Y-%m-%dT%H:%M:%SZ"),
                )
            })
            .collect::<Vec<_>>()
            .join("\n");
        Ok(xml_resp(
            &format!(
                r#"<ListOriginationNumbersResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <ListOriginationNumbersResult>
    <PhoneNumbers>
{members}
    </PhoneNumbers>
  </ListOriginationNumbersResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</ListOriginationNumbersResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn get_data_protection_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let resource_arn = required(req, "ResourceArn")?;
        let _accts = self.state.read();
        let _empty = crate::state::SnsState::new(&req.account_id, &req.region, "");
        let state = _accts.get(&req.account_id).unwrap_or(&_empty);
        if !state.topics.contains_key(&resource_arn) {
            return Err(not_found("Topic"));
        }
        let policy = state
            .data_protection_policies
            .get(&resource_arn)
            .cloned()
            .unwrap_or_default();
        Ok(xml_resp(
            &format!(
                r#"<GetDataProtectionPolicyResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <GetDataProtectionPolicyResult>
    <DataProtectionPolicy>{}</DataProtectionPolicy>
  </GetDataProtectionPolicyResult>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</GetDataProtectionPolicyResponse>"#,
                xml_escape(&policy),
                req.request_id
            ),
            &req.request_id,
        ))
    }

    fn put_data_protection_policy(&self, req: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let resource_arn = required(req, "ResourceArn")?;
        let policy = required(req, "DataProtectionPolicy")?;
        // Validate JSON.
        if serde_json::from_str::<Value>(&policy).is_err() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                "DataProtectionPolicy must be valid JSON.",
            ));
        }
        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&req.account_id);
        if !state.topics.contains_key(&resource_arn) {
            return Err(not_found("Topic"));
        }
        state.data_protection_policies.insert(resource_arn, policy);
        Ok(xml_resp(
            &format!(
                r#"<PutDataProtectionPolicyResponse xmlns="http://sns.amazonaws.com/doc/2010-03-31/">
  <PutDataProtectionPolicyResult/>
  <ResponseMetadata>
    <RequestId>{}</RequestId>
  </ResponseMetadata>
</PutDataProtectionPolicyResponse>"#,
                req.request_id
            ),
            &req.request_id,
        ))
    }
}

/// Sandbox languages SNS will send the verification code in. Mirrors the
/// `LanguageCodeString` enum in `aws-models/sns.json` — keep these two
/// lists in lockstep.
const SUPPORTED_SANDBOX_LANGUAGES: &[&str] = &[
    "en-US", "en-GB", "es-419", "es-ES", "de-DE", "fr-CA", "fr-FR", "it-IT", "ja-JP", "pt-BR",
    "kr-KR", "zh-CN", "zh-TW",
];

/// Inputs to `build_sns_lambda_event` — one SNS message delivered to one Lambda subscription.
pub(crate) struct SnsLambdaEventInput<'a> {
    pub message_id: &'a str,
    pub topic_arn: &'a str,
    pub subscription_arn: &'a str,
    pub message: &'a str,
    pub subject: Option<&'a str>,
    pub message_attributes: &'a serde_json::Map<String, Value>,
    pub timestamp: &'a chrono::DateTime<Utc>,
    pub endpoint: &'a str,
}

/// Parse MessageAttributes from query params.
/// Format: MessageAttributes.entry.N.Name, MessageAttributes.entry.N.Value.DataType,
///         MessageAttributes.entry.N.Value.StringValue
/// Subscribers of a topic, grouped by protocol. Returned by
/// `collect_topic_subscribers` so the fan-out loop doesn't have to
/// re-filter the subscriptions map five times inline.
pub(crate) struct TopicSubscribers {
    /// (queue_arn, raw_message_delivery)
    sqs: Vec<(String, bool)>,
    http: Vec<String>,
    /// (function_arn, subscription_arn)
    lambda: Vec<(String, String)>,
    email: Vec<String>,
    sms: Vec<String>,
}

/// Read-only state passed down the fan-out helpers so each helper has
/// the same data the monolithic publish() used to reference inline.
struct TopicFanoutContext<'a> {
    msg_id: &'a str,
    topic_arn: &'a str,
    subject: Option<&'a str>,
    endpoint: &'a str,
    sqs_message: &'a str,
    default_message: &'a str,
    envelope_attrs: &'a serde_json::Map<String, Value>,
    message_attributes: &'a BTreeMap<String, MessageAttribute>,
    message_group_id: Option<&'a str>,
    message_dedup_id: Option<&'a str>,
}

/// Known match type keys for filter policy objects.
const VALID_FILTER_MATCH_TYPES: &[&str] = &[
    "exists",
    "prefix",
    "suffix",
    "anything-but",
    "numeric",
    "equals-ignore-case",
];

const VALID_NUMERIC_OPS: &[&str] = &["=", "<", "<=", ">", ">="];
const LOWER_OPS: &[&str] = &[">", ">="];
const UPPER_OPS: &[&str] = &["<", "<="];

#[path = "helpers.rs"]
mod helpers;
pub(crate) use helpers::*;

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
