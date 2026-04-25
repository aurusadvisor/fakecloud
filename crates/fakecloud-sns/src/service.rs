use async_trait::async_trait;
use base64::Engine;
use chrono::Utc;
use http::StatusCode;
use serde_json::Value;
use std::collections::HashMap;
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

/// Actions that mutate SNS state.
fn is_mutating_action(action: &str) -> bool {
    matches!(
        action,
        "CreateTopic"
            | "DeleteTopic"
            | "SetTopicAttributes"
            | "Subscribe"
            | "ConfirmSubscription"
            | "Unsubscribe"
            | "Publish"
            | "PublishBatch"
            | "SetSubscriptionAttributes"
            | "TagResource"
            | "UntagResource"
            | "AddPermission"
            | "RemovePermission"
            | "CreatePlatformApplication"
            | "DeletePlatformApplication"
            | "SetPlatformApplicationAttributes"
            | "CreatePlatformEndpoint"
            | "DeleteEndpoint"
            | "SetEndpointAttributes"
            | "SetSMSAttributes"
            | "OptInPhoneNumber"
            | "CreateSMSSandboxPhoneNumber"
            | "DeleteSMSSandboxPhoneNumber"
            | "VerifySMSSandboxPhoneNumber"
            | "PutDataProtectionPolicy"
            // ListOriginationNumbers lazy-seeds a default origination number
            // on first read; treat it as mutating so the snapshot stays
            // consistent across restarts.
            | "ListOriginationNumbers"
    )
}

const DEFAULT_PAGE_SIZE: usize = 100;

const DEFAULT_EFFECTIVE_DELIVERY_POLICY: &str = r#"{"defaultHealthyRetryPolicy":{"numNoDelayRetries":0,"numMinDelayRetries":0,"minDelayTarget":20,"maxDelayTarget":20,"numMaxDelayRetries":0,"numRetries":3,"backoffFunction":"linear"},"sicklyRetryPolicy":null,"throttlePolicy":null,"guaranteed":false}"#;

fn default_policy(topic_arn: &str, account_id: &str) -> String {
    serde_json::json!({
        "Version": "2008-10-17",
        "Id": "__default_policy_ID",
        "Statement": [{
            "Effect": "Allow",
            "Sid": "__default_statement_ID",
            "Principal": {"AWS": "*"},
            "Action": [
                "SNS:GetTopicAttributes",
                "SNS:SetTopicAttributes",
                "SNS:AddPermission",
                "SNS:RemovePermission",
                "SNS:DeleteTopic",
                "SNS:Subscribe",
                "SNS:ListSubscriptionsByTopic",
                "SNS:Publish",
            ],
            "Resource": topic_arn,
            "Condition": {"StringEquals": {"AWS:SourceOwner": account_id}},
        }]
    })
    .to_string()
}

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

/// SNS uses Query protocol — params come from query_params (which includes form body).
fn param(req: &AwsRequest, name: &str) -> Option<String> {
    // Try query params first (Query protocol)
    if let Some(v) = req.query_params.get(name) {
        return Some(v.clone());
    }
    // Try JSON body (JSON protocol)
    if let Ok(body) = serde_json::from_slice::<Value>(&req.body) {
        if let Some(s) = body[name].as_str() {
            return Some(s.to_string());
        }
    }
    None
}

fn required(req: &AwsRequest, name: &str) -> Result<String, AwsServiceError> {
    param(req, name).ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            format!("The request must contain the parameter {name}"),
        )
    })
}

fn validate_message_structure_json(message: &str) -> Result<(), AwsServiceError> {
    let parsed: Value = serde_json::from_str(message).map_err(|_| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            "Invalid parameter: Message Structure - No JSON message body is parseable",
        )
    })?;
    if parsed.get("default").is_none() {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            "Invalid parameter: Message Structure - No default entry in JSON message body",
        ));
    }
    Ok(())
}

fn not_found(entity: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::NOT_FOUND,
        "NotFound",
        format!("{entity} does not exist"),
    )
}

/// Check if a topic ARN belongs to the given region
fn arn_region(arn: &str) -> Option<&str> {
    let parts: Vec<&str> = arn.split(':').collect();
    if parts.len() >= 4 {
        Some(parts[3])
    } else {
        None
    }
}

/// SNS uses XML responses for Query protocol.
fn xml_resp(inner: &str, _request_id: &str) -> AwsResponse {
    let xml = format!("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n{inner}\n");
    AwsResponse::xml(StatusCode::OK, xml)
}

const FIFO_NAME_ERROR: &str = "Fifo Topic names must end with .fifo and must be made up of only uppercase and lowercase ASCII letters, numbers, underscores, and hyphens, and must be between 1 and 256 characters long.";
const STANDARD_NAME_ERROR: &str = "Topic names must be made up of only uppercase and lowercase ASCII letters, numbers, underscores, and hyphens, and must be between 1 and 256 characters long.";

/// Validate a topic name according to AWS rules
fn validate_topic_name(name: &str, is_fifo_attr: bool) -> Result<(), AwsServiceError> {
    if name.is_empty() || name.len() > 256 {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            STANDARD_NAME_ERROR,
        ));
    }

    let base_name = name.strip_suffix(".fifo").unwrap_or(name);
    let valid_chars = base_name
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_');

    if !valid_chars {
        let msg = if name.ends_with(".fifo") || is_fifo_attr {
            FIFO_NAME_ERROR
        } else {
            STANDARD_NAME_ERROR
        };
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            msg,
        ));
    }

    // FIFO validation
    if is_fifo_attr && !name.ends_with(".fifo") {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            FIFO_NAME_ERROR,
        ));
    }

    if name.ends_with(".fifo") && !is_fifo_attr {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            STANDARD_NAME_ERROR,
        ));
    }

    Ok(())
}

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
            let mut attributes = HashMap::new();
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
        message_attributes: HashMap<String, MessageAttribute>,
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
        message_attributes: &HashMap<String, MessageAttribute>,
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
                endpoints: HashMap::new(),
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

fn is_valid_sandbox_language(code: &str) -> bool {
    SUPPORTED_SANDBOX_LANGUAGES.contains(&code)
}

fn validate_e164(phone: &str) -> Result<(), AwsServiceError> {
    // E.164: leading '+' followed by country code + subscriber digits.
    // Real range is up to 15 digits with at least 4 (smallest standard
    // country plus subscriber). AWS rejects shorter numbers like "+1".
    let digits = phone.strip_prefix('+').unwrap_or("");
    let digit_only = digits.chars().all(|c| c.is_ascii_digit());
    let valid = phone.starts_with('+') && digit_only && (4..=15).contains(&digits.len());
    if !valid {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            format!("Invalid parameter: PhoneNumber Reason: {phone} does not meet the E164 format"),
        ));
    }
    Ok(())
}

fn rand_u32() -> u32 {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    nanos.wrapping_mul(2654435761)
}

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

/// Build an SNS Lambda event payload (matches real AWS format).
/// Used by both direct Publish and cross-service delivery.
pub(crate) fn build_sns_lambda_event(input: &SnsLambdaEventInput<'_>) -> String {
    let sns_event = serde_json::json!({
        "Records": [{
            "EventVersion": "1.0",
            "EventSubscriptionArn": input.subscription_arn,
            "EventSource": "aws:sns",
            "Sns": {
                "SignatureVersion": "1",
                "Timestamp": input.timestamp.to_rfc3339(),
                "Signature": "FAKE_SIGNATURE",
                "SigningCertUrl": "https://sns.us-east-1.amazonaws.com/SimpleNotificationService-0000000000000000000000.pem",
                "MessageId": input.message_id,
                "Message": input.message,
                "MessageAttributes": input.message_attributes,
                "Type": "Notification",
                "UnsubscribeUrl": format!("{}/?Action=Unsubscribe&SubscriptionArn={}", input.endpoint, input.subscription_arn),
                "TopicArn": input.topic_arn,
                "Subject": input.subject.unwrap_or(""),
            }
        }]
    });
    sns_event.to_string()
}

/// Build an SNS notification envelope as JSON string.
/// Subject and MessageAttributes are only included when present.
fn build_sns_envelope(
    message_id: &str,
    topic_arn: &str,
    subject: &Option<String>,
    message: &str,
    message_attributes: &serde_json::Map<String, Value>,
    endpoint: &str,
) -> String {
    let mut map = serde_json::Map::new();
    map.insert(
        "Type".to_string(),
        Value::String("Notification".to_string()),
    );
    map.insert(
        "MessageId".to_string(),
        Value::String(message_id.to_string()),
    );
    map.insert("TopicArn".to_string(), Value::String(topic_arn.to_string()));
    if let Some(ref subj) = subject {
        map.insert("Subject".to_string(), Value::String(subj.clone()));
    }
    map.insert("Message".to_string(), Value::String(message.to_string()));
    map.insert(
        "Timestamp".to_string(),
        Value::String(Utc::now().to_rfc3339()),
    );
    map.insert(
        "SignatureVersion".to_string(),
        Value::String("1".to_string()),
    );
    map.insert(
        "Signature".to_string(),
        Value::String("FAKE_SIGNATURE".to_string()),
    );
    map.insert(
        "SigningCertURL".to_string(),
        Value::String("https://sns.us-east-1.amazonaws.com/SimpleNotificationService-0000000000000000000000.pem".to_string()),
    );
    map.insert(
        "UnsubscribeURL".to_string(),
        Value::String(format!(
            "{}/?Action=Unsubscribe&SubscriptionArn={}",
            endpoint, topic_arn
        )),
    );
    if !message_attributes.is_empty() {
        map.insert(
            "MessageAttributes".to_string(),
            Value::Object(message_attributes.clone()),
        );
    }
    Value::Object(map).to_string()
}

fn format_attr(name: &str, value: &str) -> String {
    format!("      <entry><key>{name}</key><value>{value}</value></entry>")
}

fn format_sub_member(sub: &SnsSubscription) -> String {
    let display_arn = if sub.confirmed {
        &sub.subscription_arn
    } else {
        "PendingConfirmation"
    };
    format!(
        r#"      <member>
        <SubscriptionArn>{}</SubscriptionArn>
        <TopicArn>{}</TopicArn>
        <Protocol>{}</Protocol>
        <Endpoint>{}</Endpoint>
        <Owner>{}</Owner>
      </member>"#,
        display_arn, sub.topic_arn, sub.protocol, sub.endpoint, sub.owner,
    )
}

/// Parse MessageAttributes from query params.
/// Format: MessageAttributes.entry.N.Name, MessageAttributes.entry.N.Value.DataType,
///         MessageAttributes.entry.N.Value.StringValue
/// Subscribers of a topic, grouped by protocol. Returned by
/// `collect_topic_subscribers` so the fan-out loop doesn't have to
/// re-filter the subscriptions map five times inline.
struct TopicSubscribers {
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
    message_attributes: &'a HashMap<String, MessageAttribute>,
    message_group_id: Option<&'a str>,
    message_dedup_id: Option<&'a str>,
}

fn collect_topic_subscribers(
    state: &crate::state::SnsState,
    topic_arn: &str,
    message_attributes: &HashMap<String, MessageAttribute>,
    message: &str,
) -> TopicSubscribers {
    let confirmed_for_topic = |s: &&SnsSubscription| {
        s.topic_arn == topic_arn
            && s.confirmed
            && matches_filter_policy(s, message_attributes, message)
    };

    let sqs = state
        .subscriptions
        .values()
        .filter(|s| s.protocol == "sqs")
        .filter(confirmed_for_topic)
        .map(|s| {
            let raw = s
                .attributes
                .get("RawMessageDelivery")
                .map(|v| v == "true")
                .unwrap_or(false);
            (s.endpoint.clone(), raw)
        })
        .collect();

    let http = state
        .subscriptions
        .values()
        .filter(|s| s.protocol == "http" || s.protocol == "https")
        .filter(confirmed_for_topic)
        .map(|s| s.endpoint.clone())
        .collect();

    let lambda = state
        .subscriptions
        .values()
        .filter(|s| s.protocol == "lambda")
        .filter(confirmed_for_topic)
        .map(|s| (s.endpoint.clone(), s.subscription_arn.clone()))
        .collect();

    let email = state
        .subscriptions
        .values()
        .filter(|s| s.protocol == "email" || s.protocol == "email-json")
        .filter(confirmed_for_topic)
        .map(|s| s.endpoint.clone())
        .collect();

    let sms = state
        .subscriptions
        .values()
        .filter(|s| s.protocol == "sms")
        .filter(confirmed_for_topic)
        .map(|s| s.endpoint.clone())
        .collect();

    TopicSubscribers {
        sqs,
        http,
        lambda,
        email,
        sms,
    }
}

/// Build the `MessageAttributes` object used inside an SNS notification
/// envelope from the typed SNS message attributes.
fn build_envelope_attrs(
    message_attributes: &HashMap<String, MessageAttribute>,
) -> serde_json::Map<String, Value> {
    let mut envelope_attrs = serde_json::Map::new();
    for (key, attr) in message_attributes {
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
    envelope_attrs
}

fn parse_message_attributes(req: &AwsRequest) -> HashMap<String, MessageAttribute> {
    let mut attrs = HashMap::new();
    for n in 1..=10 {
        let name_key = format!("MessageAttributes.entry.{n}.Name");
        let data_type_key = format!("MessageAttributes.entry.{n}.Value.DataType");
        if let (Some(name), Some(data_type)) = (
            req.query_params.get(&name_key),
            req.query_params.get(&data_type_key),
        ) {
            let string_value_key = format!("MessageAttributes.entry.{n}.Value.StringValue");
            let string_value = req.query_params.get(&string_value_key).cloned();
            let binary_value_key = format!("MessageAttributes.entry.{n}.Value.BinaryValue");
            let binary_value = req
                .query_params
                .get(&binary_value_key)
                .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok());
            attrs.insert(
                name.clone(),
                MessageAttribute {
                    data_type: data_type.clone(),
                    string_value,
                    binary_value,
                },
            );
        } else {
            break;
        }
    }
    attrs
}

/// Parse MessageAttributes for a specific PublishBatch entry.
/// Format: PublishBatchRequestEntries.member.M.MessageAttributes.entry.N.Name/...
fn parse_batch_message_attributes(
    req: &AwsRequest,
    member_idx: usize,
) -> HashMap<String, MessageAttribute> {
    let mut attrs = HashMap::new();
    for n in 1..=10 {
        let prefix =
            format!("PublishBatchRequestEntries.member.{member_idx}.MessageAttributes.entry.{n}");
        let name_key = format!("{prefix}.Name");
        let data_type_key = format!("{prefix}.Value.DataType");
        if let (Some(name), Some(data_type)) = (
            req.query_params.get(&name_key),
            req.query_params.get(&data_type_key),
        ) {
            let sv_key = format!("{prefix}.Value.StringValue");
            let string_value = req.query_params.get(&sv_key).cloned();
            let bv_key = format!("{prefix}.Value.BinaryValue");
            let binary_value = req
                .query_params
                .get(&bv_key)
                .and_then(|b| base64::engine::general_purpose::STANDARD.decode(b).ok());
            attrs.insert(
                name.clone(),
                MessageAttribute {
                    data_type: data_type.clone(),
                    string_value,
                    binary_value,
                },
            );
        } else {
            break;
        }
    }
    attrs
}

/// Parse tags from query params.
/// Format: Tags.member.N.Key / Tags.member.N.Value
fn parse_tags(req: &AwsRequest) -> Vec<(String, String)> {
    let mut tags = Vec::new();
    for n in 1..=100 {
        let key_param = format!("Tags.member.{n}.Key");
        let val_param = format!("Tags.member.{n}.Value");
        if let Some(key) = req.query_params.get(&key_param) {
            let value = req
                .query_params
                .get(&val_param)
                .cloned()
                .unwrap_or_default();
            tags.push((key.clone(), value));
        } else {
            break;
        }
    }
    tags
}

/// Parse tag keys for UntagResource.
/// Format: TagKeys.member.N
fn parse_tag_keys(req: &AwsRequest) -> Vec<String> {
    let mut keys = Vec::new();
    for n in 1..=50 {
        let key_param = format!("TagKeys.member.{n}");
        if let Some(key) = req.query_params.get(&key_param) {
            keys.push(key.clone());
        } else {
            break;
        }
    }
    keys
}

/// Parse Attributes.entry.N.key/value pairs (used by CreateTopic, Subscribe, etc.)
fn parse_entries(req: &AwsRequest, prefix: &str) -> HashMap<String, String> {
    let mut attrs = HashMap::new();
    for n in 1..=50 {
        let key_param = format!("{prefix}.entry.{n}.key");
        let val_param = format!("{prefix}.entry.{n}.value");
        if let Some(key) = req.query_params.get(&key_param) {
            let value = req
                .query_params
                .get(&val_param)
                .cloned()
                .unwrap_or_default();
            attrs.insert(key.clone(), value);
        } else {
            break;
        }
    }
    attrs
}

/// Validate SMS phone number
fn validate_sms_endpoint(endpoint: &str) -> Result<(), AwsServiceError> {
    // Allow formats like +15551234567 and +15/55-123.4567
    if endpoint.is_empty() {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            "Invalid parameter: Endpoint",
        ));
    }

    // Must start with optional + and contain only digits, -, /, .
    let stripped = endpoint.strip_prefix('+').unwrap_or(endpoint);
    if stripped.is_empty() {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            format!("Invalid SMS endpoint: {endpoint}"),
        ));
    }

    // Check for invalid patterns: consecutive special chars, must start with + or digit
    if !endpoint.starts_with('+') && !endpoint.starts_with(|c: char| c.is_ascii_digit()) {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            format!("Invalid SMS endpoint: {endpoint}"),
        ));
    }

    // Must not end with a special char
    if endpoint.ends_with('.') || endpoint.ends_with('-') || endpoint.ends_with('/') {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            format!("Invalid SMS endpoint: {endpoint}"),
        ));
    }

    // Must not have consecutive special chars like --
    let chars: Vec<char> = endpoint.chars().collect();
    for i in 0..chars.len() - 1 {
        let c = chars[i];
        let next = chars[i + 1];
        if (c == '-' || c == '/' || c == '.') && (next == '-' || next == '/' || next == '.') {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                format!("Invalid SMS endpoint: {endpoint}"),
            ));
        }
    }

    // Check all chars are valid
    for c in stripped.chars() {
        if !c.is_ascii_digit() && c != '-' && c != '/' && c != '.' {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                format!("Invalid SMS endpoint: {endpoint}"),
            ));
        }
    }

    Ok(())
}

/// Check if a message's attributes match the subscription's FilterPolicy.
fn matches_filter_policy(
    sub: &SnsSubscription,
    message_attributes: &HashMap<String, MessageAttribute>,
    message_body: &str,
) -> bool {
    let filter_json = match sub.attributes.get("FilterPolicy") {
        Some(fp) if !fp.is_empty() => fp,
        _ => return true,
    };

    let filter: HashMap<String, Value> = match serde_json::from_str(filter_json) {
        Ok(f) => f,
        Err(_) => return false,
    };

    let scope = sub
        .attributes
        .get("FilterPolicyScope")
        .map(|s| s.as_str())
        .unwrap_or("MessageAttributes");

    if scope == "MessageBody" {
        return matches_filter_policy_body(&filter, message_body);
    }

    // MessageAttributes scope
    for (attr_name, allowed_values) in &filter {
        // Handle $or operator
        if attr_name == "$or" {
            if let Some(or_conditions) = allowed_values.as_array() {
                let any_match = or_conditions.iter().any(|condition| {
                    if let Some(cond_obj) = condition.as_object() {
                        let cond_map: HashMap<String, Value> = cond_obj
                            .iter()
                            .map(|(k, v)| (k.clone(), v.clone()))
                            .collect();
                        // Each condition in $or is a mini filter policy
                        cond_map.iter().all(|(key, vals)| {
                            if let Some(arr) = vals.as_array() {
                                if let Some(msg_attr) = message_attributes.get(key) {
                                    let val = msg_attr.string_value.as_deref().unwrap_or("");
                                    check_filter_values(arr, val)
                                } else {
                                    false
                                }
                            } else {
                                false
                            }
                        })
                    } else {
                        false
                    }
                });
                if !any_match {
                    return false;
                }
                continue;
            }
        }

        let allowed = match allowed_values.as_array() {
            Some(arr) => arr,
            None => continue,
        };

        let msg_attr = match message_attributes.get(attr_name) {
            Some(a) => a,
            None => {
                let has_exists_false = allowed.iter().any(|v| {
                    v.as_object()
                        .and_then(|o| o.get("exists"))
                        .and_then(|e| e.as_bool())
                        == Some(false)
                });
                if has_exists_false {
                    continue;
                }
                return false;
            }
        };

        let attr_value = msg_attr.string_value.as_deref().unwrap_or("");
        let is_numeric_type = msg_attr.data_type == "Number";

        // Handle String.Array data type: parse the JSON array and check each element
        if msg_attr.data_type.starts_with("String.Array") || msg_attr.data_type == "String.Array" {
            if let Ok(arr) = serde_json::from_str::<Vec<Value>>(attr_value) {
                let any_match = arr.iter().any(|elem| {
                    let elem_str = match elem {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        _ => elem.to_string(),
                    };
                    check_filter_values(allowed, &elem_str)
                });
                if !any_match {
                    return false;
                }
                continue;
            }
        }

        let matched = check_filter_values_typed(allowed, attr_value, Some(is_numeric_type));
        if !matched {
            return false;
        }
    }

    true
}

/// Match filter policy against message body (JSON)
fn matches_filter_policy_body(filter: &HashMap<String, Value>, message_body: &str) -> bool {
    let body: Value = match serde_json::from_str(message_body) {
        Ok(v) => v,
        Err(_) => return false,
    };

    matches_filter_policy_nested(filter, &body)
}

fn matches_filter_policy_nested(filter: &HashMap<String, Value>, body: &Value) -> bool {
    let body_obj = match body.as_object() {
        Some(o) => o,
        None => return false,
    };

    for (key, filter_value) in filter {
        let body_value = match body_obj.get(key) {
            Some(v) => v,
            None => {
                // Check for exists: false
                if let Some(arr) = filter_value.as_array() {
                    let has_exists_false = arr.iter().any(|v| {
                        v.as_object()
                            .and_then(|o| o.get("exists"))
                            .and_then(|e| e.as_bool())
                            == Some(false)
                    });
                    if has_exists_false {
                        continue;
                    }
                }
                return false;
            }
        };

        if let Some(arr) = filter_value.as_array() {
            // This is a leaf filter: check the value
            // If the body value is an array, check if ANY element matches
            if let Some(body_arr) = body_value.as_array() {
                let any_match = body_arr.iter().any(|elem| {
                    let is_elem_numeric = elem.is_number();
                    let elem_str = match elem {
                        Value::String(s) => s.clone(),
                        Value::Number(n) => n.to_string(),
                        Value::Bool(b) => b.to_string(),
                        Value::Null => "null".to_string(),
                        _ => elem.to_string(),
                    };
                    check_filter_values_typed(arr, &elem_str, Some(is_elem_numeric))
                });
                if !any_match {
                    return false;
                }
            } else {
                let is_body_numeric = body_value.is_number();
                let value_str = match body_value {
                    Value::String(s) => s.clone(),
                    Value::Number(n) => n.to_string(),
                    Value::Bool(b) => b.to_string(),
                    Value::Null => "null".to_string(),
                    _ => body_value.to_string(),
                };
                if !check_filter_values_typed(arr, &value_str, Some(is_body_numeric)) {
                    return false;
                }
            }
        } else if let Some(nested_filter) = filter_value.as_object() {
            // Nested filter: recurse
            let nested_map: HashMap<String, Value> = nested_filter
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect();
            // If body_value is an array, check if ANY element matches
            if let Some(body_arr) = body_value.as_array() {
                let any_match = body_arr
                    .iter()
                    .any(|elem| matches_filter_policy_nested(&nested_map, elem));
                if !any_match {
                    return false;
                }
            } else if !matches_filter_policy_nested(&nested_map, body_value) {
                return false;
            }
        }
    }

    true
}

/// Untyped filter check - used for String.Array elements, $or, and body array elements
/// where both string and numeric comparisons are allowed.
fn check_filter_values(allowed: &[Value], attr_value: &str) -> bool {
    check_filter_values_typed(allowed, attr_value, None)
}

/// Type-aware filter check. When `is_numeric` is Some(true), only Number filters match.
/// When Some(false), only String filters match. When None, both match (original behavior).
fn check_filter_values_typed(
    allowed: &[Value],
    attr_value: &str,
    is_numeric: Option<bool>,
) -> bool {
    allowed.iter().any(|v| match v {
        Value::String(s) => {
            // If we know the attribute is numeric, string filters don't match
            if is_numeric == Some(true) {
                false
            } else {
                s == attr_value
            }
        }
        Value::Number(n) => {
            // If we know the attribute is a string, number filters don't match
            if is_numeric == Some(false) {
                return false;
            }
            if let Ok(attr_num) = attr_value.parse::<f64>() {
                if let Some(filter_num) = n.as_f64() {
                    numbers_equal(attr_num, filter_num)
                } else {
                    false
                }
            } else {
                false
            }
        }
        Value::Bool(_) | Value::Null => false,
        Value::Object(obj) => {
            if let Some(prefix) = obj.get("prefix").and_then(|v| v.as_str()) {
                attr_value.starts_with(prefix)
            } else if let Some(suffix) = obj.get("suffix").and_then(|v| v.as_str()) {
                attr_value.ends_with(suffix)
            } else if let Some(anything_but) = obj.get("anything-but") {
                match anything_but {
                    Value::String(s) => {
                        // String anything-but only excludes string-type attrs
                        if is_numeric == Some(true) {
                            true
                        } else {
                            attr_value != s
                        }
                    }
                    Value::Number(n) => {
                        // Number anything-but only excludes number-type attrs
                        if is_numeric == Some(false) {
                            return true;
                        }
                        if let Ok(attr_num) = attr_value.parse::<f64>() {
                            if let Some(filter_num) = n.as_f64() {
                                (attr_num - filter_num).abs() >= f64::EPSILON
                            } else {
                                true
                            }
                        } else {
                            true
                        }
                    }
                    Value::Array(arr) => {
                        // anything-but with array: type must match for exclusion
                        !arr.iter().any(|av| match av {
                            Value::String(s) => {
                                if is_numeric == Some(true) {
                                    false
                                } else {
                                    s == attr_value
                                }
                            }
                            Value::Number(n) => {
                                if is_numeric == Some(false) {
                                    return false;
                                }
                                if let Ok(attr_num) = attr_value.parse::<f64>() {
                                    if let Some(filter_num) = n.as_f64() {
                                        numbers_equal(attr_num, filter_num)
                                    } else {
                                        false
                                    }
                                } else {
                                    false
                                }
                            }
                            _ => false,
                        })
                    }
                    Value::Object(inner) => {
                        // anything-but with prefix
                        if let Some(prefix) = inner.get("prefix").and_then(|v| v.as_str()) {
                            !attr_value.starts_with(prefix)
                        } else if let Some(suffix) = inner.get("suffix").and_then(|v| v.as_str()) {
                            !attr_value.ends_with(suffix)
                        } else {
                            false
                        }
                    }
                    _ => false,
                }
            } else if let Some(numeric_arr) = obj.get("numeric").and_then(|v| v.as_array()) {
                let attr_num: f64 = match attr_value.parse() {
                    Ok(n) => n,
                    Err(_) => return false,
                };
                matches_numeric_filter(attr_num, numeric_arr)
            } else if let Some(eq_ignore_case) =
                obj.get("equals-ignore-case").and_then(|v| v.as_str())
            {
                attr_value.eq_ignore_ascii_case(eq_ignore_case)
            } else {
                // {"exists": true/false}
                obj.get("exists")
                    .and_then(|v| v.as_bool())
                    .unwrap_or_default()
            }
        }
        _ => false,
    })
}

/// Compare two f64 values with limited precision (5 decimal places).
/// AWS SNS uses limited precision for number comparisons.
fn numbers_equal(a: f64, b: f64) -> bool {
    // Compare with ~5 decimal digit precision
    (a - b).abs() < 1e-5
}

/// Evaluate a numeric filter
fn matches_numeric_filter(value: f64, conditions: &[Value]) -> bool {
    let mut i = 0;
    while i + 1 < conditions.len() {
        let op = match conditions[i].as_str() {
            Some(s) => s,
            None => return false,
        };
        let threshold = match conditions[i + 1].as_f64() {
            Some(n) => n,
            None => return false,
        };
        let passes = match op {
            "=" => numbers_equal(value, threshold),
            ">" => value > threshold,
            ">=" => value >= threshold,
            "<" => value < threshold,
            "<=" => value <= threshold,
            _ => return false,
        };
        if !passes {
            return false;
        }
        i += 2;
    }
    true
}

/// Validate a filter policy JSON string.
fn validate_filter_policy(policy_str: &str) -> Result<(), AwsServiceError> {
    let policy: HashMap<String, Value> = serde_json::from_str(policy_str).map_err(|_| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            "Invalid parameter: FilterPolicy: failed to parse JSON.",
        )
    })?;

    // Count total filter values across all keys (max 150)
    let mut total_values = 0;
    for (key, value) in &policy {
        // Skip special operators like $or
        if key.starts_with('$') {
            continue;
        }
        if let Some(arr) = value.as_array() {
            total_values += arr.len();
            for item in arr {
                validate_filter_policy_value(item)?;
            }
        }
    }
    if total_values > 150 {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            "Invalid parameter: FilterPolicy: Filter policy is too complex",
        ));
    }

    Ok(())
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

/// Validate a single filter policy value.
fn validate_filter_policy_value(value: &Value) -> Result<(), AwsServiceError> {
    match value {
        Value::String(_) | Value::Bool(_) | Value::Null => Ok(()),
        Value::Number(n) => {
            // Number values must be within range
            if let Some(f) = n.as_f64() {
                if f.abs() >= 1_000_000_000.0 {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        format!(
                            "Invalid parameter: FilterPolicy: Match value {} must be smaller than 1E9",
                            n
                        ),
                    ));
                }
            }
            Ok(())
        }
        Value::Array(_) => Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            "Invalid parameter: FilterPolicy: Match value must be String, number, true, false, or null",
        )),
        Value::Object(obj) => {
            if let Some(exists_val) = obj.get("exists") {
                if !exists_val.is_boolean() {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameter",
                        "Invalid parameter: FilterPolicy: exists match pattern must be either true or false.",
                    ));
                }
            }
            // Validate that object keys are recognized match types
            for key in obj.keys() {
                if !VALID_FILTER_MATCH_TYPES.contains(&key.as_str()) {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidParameter",
                        format!(
                            "Invalid parameter: FilterPolicy: Unrecognized match type {key}"
                        ),
                    ));
                }
            }
            // Validate numeric filter operands
            if let Some(numeric_val) = obj.get("numeric") {
                if let Some(arr) = numeric_val.as_array() {
                    validate_numeric_filter(arr)?;
                }
            }
            Ok(())
        }
    }
}

const VALID_NUMERIC_OPS: &[&str] = &["=", "<", "<=", ">", ">="];
const LOWER_OPS: &[&str] = &[">", ">="];
const UPPER_OPS: &[&str] = &["<", "<="];

fn validate_numeric_filter(arr: &[Value]) -> Result<(), AwsServiceError> {
    // Empty array
    if arr.is_empty() {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            "Invalid parameter: Attributes Reason: FilterPolicy: Invalid member in numeric match: ]\n at ...",
        ));
    }

    // First element must be a string operator
    let first_op = match arr[0].as_str() {
        Some(s) => s,
        None => {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                format!(
                    "Invalid parameter: Attributes Reason: FilterPolicy: Invalid member in numeric match: {}\n at ...",
                    arr[0]
                ),
            ));
        }
    };

    // Must be a recognized operator
    if !VALID_NUMERIC_OPS.contains(&first_op) {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            format!(
                "Invalid parameter: Attributes Reason: FilterPolicy: Unrecognized numeric range operator: {first_op}\n at ..."
            ),
        ));
    }

    // Must have a value after the operator
    if arr.len() < 2 {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            format!(
                "Invalid parameter: Attributes Reason: FilterPolicy: Value of {first_op} must be numeric\n at ..."
            ),
        ));
    }

    // Value must be numeric
    if !arr[1].is_number() {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            format!(
                "Invalid parameter: Attributes Reason: FilterPolicy: Value of {first_op} must be numeric\n at ..."
            ),
        ));
    }

    // Numeric operand must be smaller than 1E9
    if let Some(f) = arr[1].as_f64() {
        if f.abs() >= 1_000_000_000.0 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                format!(
                    "Invalid parameter: FilterPolicy: Numeric match value must be smaller than 1E9, got {}",
                    arr[1]
                ),
            ));
        }
    }

    // Single comparison (2 elements): valid
    if arr.len() == 2 {
        return Ok(());
    }

    // Range expression: must have exactly 4 elements
    if arr.len() > 4 {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            "Invalid parameter: Attributes Reason: FilterPolicy: Too many elements in numeric expression\n at ...",
        ));
    }

    if arr.len() < 4 {
        // 3 elements: op, val, op_missing_value
        if let Some(op2) = arr[2].as_str() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                format!(
                    "Invalid parameter: Attributes Reason: FilterPolicy: Value of {op2} must be numeric\n at ..."
                ),
            ));
        }
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            "Invalid parameter: Attributes Reason: FilterPolicy: Too many elements in numeric expression\n at ...",
        ));
    }

    // Exactly 4 elements: range expression
    let second_op = match arr[2].as_str() {
        Some(s) => s,
        None => {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                format!(
                    "Invalid parameter: Attributes Reason: FilterPolicy: Invalid member in numeric match: {}\n at ...",
                    arr[2]
                ),
            ));
        }
    };

    if !arr[3].is_number() {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            format!(
                "Invalid parameter: Attributes Reason: FilterPolicy: Value of {second_op} must be numeric\n at ..."
            ),
        ));
    }

    // Numeric operand must be smaller than 1E9
    if let Some(f) = arr[3].as_f64() {
        if f.abs() >= 1_000_000_000.0 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameter",
                format!(
                    "Invalid parameter: FilterPolicy: Numeric match value must be smaller than 1E9, got {}",
                    arr[3]
                ),
            ));
        }
    }

    // For a range, first op must be lower bound (> or >=) and second op must be upper bound (< or <=)
    let first_is_lower = LOWER_OPS.contains(&first_op);
    let second_is_upper = UPPER_OPS.contains(&second_op);

    if first_is_lower && !second_is_upper {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            format!(
                "Invalid parameter: Attributes Reason: FilterPolicy: Bad numeric range operator: {second_op}\n at ..."
            ),
        ));
    }

    if !first_is_lower {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            "Invalid parameter: Attributes Reason: FilterPolicy: Too many elements in numeric expression\n at ...",
        ));
    }

    // Bottom must be less than top
    let bottom = arr[1].as_f64().unwrap_or(0.0);
    let top = arr[3].as_f64().unwrap_or(0.0);
    if bottom >= top {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameter",
            "Invalid parameter: Attributes Reason: FilterPolicy: Bottom must be less than top\n at ...",
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validate_message_structure_json_rejects_invalid_json() {
        let result = validate_message_structure_json("not valid json");
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(msg.contains("No JSON message body is parseable"), "{msg}");
    }

    #[test]
    fn validate_message_structure_json_rejects_missing_default_key() {
        let result = validate_message_structure_json(r#"{"sqs": "hello"}"#);
        assert!(result.is_err());
        let err = result.unwrap_err();
        let msg = format!("{err}");
        assert!(
            msg.contains("No default entry in JSON message body"),
            "{msg}"
        );
    }

    #[test]
    fn validate_message_structure_json_accepts_valid() {
        let result =
            validate_message_structure_json(r#"{"default": "hello", "sqs": "hello from sqs"}"#);
        assert!(result.is_ok());
    }

    #[test]
    fn build_sns_lambda_event_uses_real_subscription_arn() {
        let now = Utc::now();
        let sub_arn = "arn:aws:sns:us-east-1:123456789012:my-topic:abc-def-123";
        let topic_arn = "arn:aws:sns:us-east-1:123456789012:my-topic";
        let attrs = serde_json::Map::new();

        let payload = build_sns_lambda_event(&SnsLambdaEventInput {
            message_id: "msg-001",
            topic_arn,
            subscription_arn: sub_arn,
            message: "hello",
            subject: Some("test subject"),
            message_attributes: &attrs,
            timestamp: &now,
            endpoint: "http://localhost:4566",
        });

        let parsed: Value = serde_json::from_str(&payload).unwrap();
        let record = &parsed["Records"][0];
        assert_eq!(record["EventSubscriptionArn"], sub_arn);
        assert_eq!(record["EventSource"], "aws:sns");
        assert_eq!(record["Sns"]["TopicArn"], topic_arn);
        assert_eq!(record["Sns"]["Message"], "hello");
        assert_eq!(record["Sns"]["Subject"], "test subject");
        assert_eq!(record["Sns"]["MessageId"], "msg-001");
        // UnsubscribeUrl should use subscription ARN, not topic ARN
        let unsub_url = record["Sns"]["UnsubscribeUrl"].as_str().unwrap();
        assert!(
            unsub_url.contains(sub_arn),
            "UnsubscribeUrl should contain subscription ARN"
        );
    }

    #[test]
    fn build_sns_envelope_uses_configured_endpoint() {
        let endpoint = "http://myhost:5555";
        let topic_arn = "arn:aws:sns:us-east-1:123456789012:my-topic";
        let attrs = serde_json::Map::new();

        let envelope = build_sns_envelope(
            "msg-002",
            topic_arn,
            &None,
            "test message",
            &attrs,
            endpoint,
        );

        let parsed: Value = serde_json::from_str(&envelope).unwrap();
        let unsub_url = parsed["UnsubscribeURL"].as_str().unwrap();
        assert!(
            unsub_url.starts_with("http://myhost:5555/"),
            "UnsubscribeURL should use the configured endpoint, got: {unsub_url}"
        );
        assert!(
            unsub_url.contains(topic_arn),
            "UnsubscribeURL should contain topic ARN"
        );
    }

    #[test]
    fn build_sns_lambda_event_uses_configured_endpoint() {
        let now = Utc::now();
        let sub_arn = "arn:aws:sns:us-east-1:123456789012:my-topic:abc-def-123";
        let attrs = serde_json::Map::new();
        let endpoint = "http://custom:9999";

        let payload = build_sns_lambda_event(&SnsLambdaEventInput {
            message_id: "msg-003",
            topic_arn: "arn:aws:sns:us-east-1:123456789012:my-topic",
            subscription_arn: sub_arn,
            message: "hello",
            subject: None,
            message_attributes: &attrs,
            timestamp: &now,
            endpoint,
        });

        let parsed: Value = serde_json::from_str(&payload).unwrap();
        let unsub_url = parsed["Records"][0]["Sns"]["UnsubscribeUrl"]
            .as_str()
            .unwrap();
        assert!(
            unsub_url.starts_with("http://custom:9999/"),
            "UnsubscribeUrl should use configured endpoint, got: {unsub_url}"
        );
    }

    #[test]
    fn add_permission_with_invalid_policy_returns_error_not_panic() {
        use fakecloud_core::delivery::DeliveryBus;
        use fakecloud_core::multi_account::MultiAccountState;
        use parking_lot::RwLock;
        use std::sync::Arc;

        let state = Arc::new(RwLock::new(
            MultiAccountState::<crate::state::SnsState>::new(
                "123456789012",
                "us-east-1",
                "http://localhost:4566",
            ),
        ));
        let delivery = Arc::new(DeliveryBus::new());
        let svc = SnsService::new(state.clone(), delivery);

        // Create a topic first
        let topic_arn = "arn:aws:sns:us-east-1:123456789012:test-topic";
        {
            let mut s = state.write();
            s.default_mut().topics.insert(
                topic_arn.to_string(),
                crate::state::SnsTopic {
                    topic_arn: topic_arn.to_string(),
                    name: "test-topic".to_string(),
                    attributes: {
                        let mut m = std::collections::HashMap::new();
                        // Set an intentionally broken JSON policy
                        m.insert("Policy".to_string(), "not valid json {{{".to_string());
                        m
                    },
                    is_fifo: false,
                    tags: vec![],
                    created_at: Utc::now(),
                },
            );
        }

        // Build an AddPermission request
        let body = format!(
            "Action=AddPermission&TopicArn={}&Label=TestLabel&ActionName.member.1=Publish&AWSAccountId.member.1=111111111111",
            topic_arn
        );
        let req = fakecloud_core::service::AwsRequest {
            service: "sns".to_string(),
            action: "AddPermission".to_string(),
            region: "us-east-1".to_string(),
            account_id: "123456789012".to_string(),
            request_id: "test-req".to_string(),
            headers: http::HeaderMap::new(),
            query_params: std::collections::HashMap::new(),
            body: body.into(),
            path_segments: vec![],
            raw_path: "/".to_string(),
            raw_query: String::new(),
            method: http::Method::POST,
            is_query_protocol: true,
            access_key_id: None,
            principal: None,
        };

        // This should return an error, not panic
        let result = svc.add_permission(&req);
        assert!(
            result.is_err(),
            "Invalid policy JSON should return error, not panic"
        );
    }

    // --- Helper to build SNS service + state for integration-style unit tests ---

    fn make_sns() -> (SnsService, crate::state::SharedSnsState) {
        use fakecloud_core::delivery::DeliveryBus;
        use fakecloud_core::multi_account::MultiAccountState;
        use parking_lot::RwLock;
        use std::sync::Arc;

        let state = Arc::new(RwLock::new(
            MultiAccountState::<crate::state::SnsState>::new(
                "123456789012",
                "us-east-1",
                "http://localhost:4566",
            ),
        ));
        let delivery = Arc::new(DeliveryBus::new());
        let svc = SnsService::new(state.clone(), delivery);
        (svc, state)
    }

    fn sns_request(action: &str, params: Vec<(&str, &str)>) -> fakecloud_core::service::AwsRequest {
        let mut query_params = std::collections::HashMap::new();
        query_params.insert("Action".to_string(), action.to_string());
        for (k, v) in params {
            query_params.insert(k.to_string(), v.to_string());
        }
        fakecloud_core::service::AwsRequest {
            service: "sns".to_string(),
            action: action.to_string(),
            region: "us-east-1".to_string(),
            account_id: "123456789012".to_string(),
            request_id: "test-req".to_string(),
            headers: http::HeaderMap::new(),
            query_params,
            body: Default::default(),
            path_segments: vec![],
            raw_path: "/".to_string(),
            raw_query: String::new(),
            method: http::Method::POST,
            is_query_protocol: true,
            access_key_id: None,
            principal: None,
        }
    }

    fn assert_ok(result: &Result<AwsResponse, AwsServiceError>) {
        assert!(
            result.is_ok(),
            "Expected Ok, got: {:?}",
            result.as_ref().err()
        );
    }

    fn response_body(result: &Result<AwsResponse, AwsServiceError>) -> String {
        String::from_utf8(result.as_ref().unwrap().body.expect_bytes().to_vec()).unwrap()
    }

    // --- Subscribe / Unsubscribe / ListSubscriptions / ListSubscriptionsByTopic ---

    #[test]
    fn iam_condition_keys_for_subscribe_populates_protocol_and_endpoint() {
        let (svc, _state) = make_sns();
        let req = sns_request(
            "Subscribe",
            vec![
                ("TopicArn", "arn:aws:sns:us-east-1:123456789012:t"),
                ("Protocol", "https"),
                ("Endpoint", "https://example.com/hook"),
            ],
        );
        let action = fakecloud_core::auth::IamAction {
            service: "sns",
            action: "Subscribe",
            resource: "arn:aws:sns:us-east-1:123456789012:t".to_string(),
        };
        let keys = svc.iam_condition_keys_for(&req, &action);
        assert_eq!(keys.get("sns:protocol"), Some(&vec!["https".to_string()]));
        assert_eq!(
            keys.get("sns:endpoint"),
            Some(&vec!["https://example.com/hook".to_string()])
        );
    }

    #[test]
    fn iam_condition_keys_for_subscribe_omits_missing_fields() {
        let (svc, _state) = make_sns();
        let req = sns_request(
            "Subscribe",
            vec![("TopicArn", "arn:aws:sns:us-east-1:123456789012:t")],
        );
        let action = fakecloud_core::auth::IamAction {
            service: "sns",
            action: "Subscribe",
            resource: "arn:aws:sns:us-east-1:123456789012:t".to_string(),
        };
        assert!(svc.iam_condition_keys_for(&req, &action).is_empty());
    }

    #[test]
    fn iam_condition_keys_for_non_subscribe_is_empty() {
        let (svc, _state) = make_sns();
        let req = sns_request(
            "Publish",
            vec![
                ("TopicArn", "arn:aws:sns:us-east-1:123456789012:t"),
                ("Protocol", "https"),
            ],
        );
        let action = fakecloud_core::auth::IamAction {
            service: "sns",
            action: "Publish",
            resource: "arn:aws:sns:us-east-1:123456789012:t".to_string(),
        };
        assert!(svc.iam_condition_keys_for(&req, &action).is_empty());
    }

    #[test]
    fn subscribe_creates_subscription() {
        let (svc, _state) = make_sns();
        // Create topic first
        let req = sns_request("CreateTopic", vec![("Name", "my-topic")]);
        assert_ok(&svc.create_topic(&req));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:my-topic";
        let req = sns_request(
            "Subscribe",
            vec![
                ("TopicArn", topic_arn),
                ("Protocol", "email"),
                ("Endpoint", "user@example.com"),
            ],
        );
        let result = svc.subscribe(&req);
        assert_ok(&result);
        let body = response_body(&result);
        assert!(
            body.contains("<SubscriptionArn>"),
            "Response should contain SubscriptionArn"
        );
        assert!(
            body.contains(topic_arn),
            "SubscriptionArn should contain topic ARN"
        );
    }

    #[test]
    fn subscribe_duplicate_returns_existing_arn() {
        let (svc, _state) = make_sns();
        let req = sns_request("CreateTopic", vec![("Name", "dup-topic")]);
        assert_ok(&svc.create_topic(&req));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:dup-topic";
        let params = vec![
            ("TopicArn", topic_arn),
            ("Protocol", "email"),
            ("Endpoint", "user@example.com"),
        ];
        let r1 = svc.subscribe(&sns_request("Subscribe", params.clone()));
        assert_ok(&r1);
        let body1 = response_body(&r1);

        let r2 = svc.subscribe(&sns_request("Subscribe", params));
        assert_ok(&r2);
        let body2 = response_body(&r2);

        // Both should return same subscription ARN
        assert_eq!(body1, body2, "Duplicate subscribe should return same ARN");
    }

    #[test]
    fn unsubscribe_removes_subscription() {
        let (svc, state) = make_sns();
        let req = sns_request("CreateTopic", vec![("Name", "unsub-topic")]);
        assert_ok(&svc.create_topic(&req));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:unsub-topic";
        let req = sns_request(
            "Subscribe",
            vec![
                ("TopicArn", topic_arn),
                ("Protocol", "email"),
                ("Endpoint", "user@example.com"),
            ],
        );
        assert_ok(&svc.subscribe(&req));

        // Get subscription ARN from state
        let sub_arn = {
            let s = state.read();
            s.default_ref().subscriptions.keys().next().unwrap().clone()
        };

        let req = sns_request("Unsubscribe", vec![("SubscriptionArn", &sub_arn)]);
        assert_ok(&svc.unsubscribe(&req));

        let s = state.read();
        assert!(
            s.default_ref().subscriptions.is_empty(),
            "Subscription should be removed"
        );
    }

    #[test]
    fn list_subscriptions_returns_all() {
        let (svc, _state) = make_sns();
        let req = sns_request("CreateTopic", vec![("Name", "list-topic")]);
        assert_ok(&svc.create_topic(&req));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:list-topic";
        for i in 0..3 {
            let email = format!("user{}@example.com", i);
            let req = sns_request(
                "Subscribe",
                vec![
                    ("TopicArn", topic_arn),
                    ("Protocol", "email"),
                    ("Endpoint", &email),
                ],
            );
            assert_ok(&svc.subscribe(&req));
        }

        let req = sns_request("ListSubscriptions", vec![]);
        let result = svc.list_subscriptions(&req);
        assert_ok(&result);
        let body = response_body(&result);
        // Should contain all 3 subscriptions
        let count = body.matches("<member>").count();
        assert_eq!(count, 3, "Should list 3 subscriptions, found {}", count);
    }

    #[test]
    fn list_subscriptions_by_topic_filters_correctly() {
        let (svc, _state) = make_sns();
        // Create two topics
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "topicA")])));
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "topicB")])));

        let arn_a = "arn:aws:sns:us-east-1:123456789012:topicA";
        let arn_b = "arn:aws:sns:us-east-1:123456789012:topicB";

        // Subscribe 2 to A, 1 to B
        assert_ok(&svc.subscribe(&sns_request(
            "Subscribe",
            vec![
                ("TopicArn", arn_a),
                ("Protocol", "email"),
                ("Endpoint", "a1@example.com"),
            ],
        )));
        assert_ok(&svc.subscribe(&sns_request(
            "Subscribe",
            vec![
                ("TopicArn", arn_a),
                ("Protocol", "email"),
                ("Endpoint", "a2@example.com"),
            ],
        )));
        assert_ok(&svc.subscribe(&sns_request(
            "Subscribe",
            vec![
                ("TopicArn", arn_b),
                ("Protocol", "email"),
                ("Endpoint", "b1@example.com"),
            ],
        )));

        let req = sns_request("ListSubscriptionsByTopic", vec![("TopicArn", arn_a)]);
        let result = svc.list_subscriptions_by_topic(&req);
        assert_ok(&result);
        let body = response_body(&result);
        let count = body.matches("<member>").count();
        assert_eq!(
            count, 2,
            "Topic A should have 2 subscriptions, found {}",
            count
        );
    }

    // --- Publish / PublishBatch ---

    #[test]
    fn publish_to_topic_stores_message() {
        let (svc, state) = make_sns();
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "pub-topic")])));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:pub-topic";
        let req = sns_request(
            "Publish",
            vec![
                ("TopicArn", topic_arn),
                ("Message", "Hello world"),
                ("Subject", "Test subject"),
            ],
        );
        let result = svc.publish(&req);
        assert_ok(&result);
        let body = response_body(&result);
        assert!(
            body.contains("<MessageId>"),
            "Response should contain MessageId"
        );

        let s = state.read();
        assert_eq!(s.default_ref().published.len(), 1);
        assert_eq!(s.default_ref().published[0].message, "Hello world");
        assert_eq!(
            s.default_ref().published[0].subject.as_deref(),
            Some("Test subject")
        );
    }

    #[test]
    fn publish_to_nonexistent_topic_returns_error() {
        let (svc, _state) = make_sns();
        let req = sns_request(
            "Publish",
            vec![
                ("TopicArn", "arn:aws:sns:us-east-1:123456789012:nope"),
                ("Message", "Hello"),
            ],
        );
        let result = svc.publish(&req);
        assert!(result.is_err(), "Publish to nonexistent topic should error");
    }

    #[test]
    fn publish_without_topic_or_phone_returns_error() {
        let (svc, _state) = make_sns();
        let req = sns_request("Publish", vec![("Message", "Hello")]);
        let result = svc.publish(&req);
        assert!(result.is_err(), "Publish without target should error");
    }

    #[test]
    fn publish_validates_subject_length() {
        let (svc, _state) = make_sns();
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "subj-topic")])));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:subj-topic";
        let long_subject = "x".repeat(101);
        let req = sns_request(
            "Publish",
            vec![
                ("TopicArn", topic_arn),
                ("Message", "Hello"),
                ("Subject", &long_subject),
            ],
        );
        let result = svc.publish(&req);
        assert!(result.is_err(), "Subject > 100 chars should error");
    }

    #[test]
    fn publish_to_sms_phone_number() {
        let (svc, state) = make_sns();
        let req = sns_request(
            "Publish",
            vec![("PhoneNumber", "+15551234567"), ("Message", "SMS test")],
        );
        let result = svc.publish(&req);
        assert_ok(&result);

        let s = state.read();
        assert_eq!(s.default_ref().sms_messages.len(), 1);
        assert_eq!(s.default_ref().sms_messages[0].0, "+15551234567");
        assert_eq!(s.default_ref().sms_messages[0].1, "SMS test");
    }

    #[test]
    fn publish_to_invalid_phone_returns_error() {
        let (svc, _state) = make_sns();
        let req = sns_request(
            "Publish",
            vec![("PhoneNumber", "not-a-phone"), ("Message", "SMS test")],
        );
        let result = svc.publish(&req);
        assert!(result.is_err(), "Invalid phone should error");
    }

    #[test]
    fn publish_batch_stores_multiple_messages() {
        let (svc, state) = make_sns();
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "batch-topic")])));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:batch-topic";
        let req = sns_request(
            "PublishBatch",
            vec![
                ("TopicArn", topic_arn),
                ("PublishBatchRequestEntries.member.1.Id", "msg1"),
                ("PublishBatchRequestEntries.member.1.Message", "Hello 1"),
                ("PublishBatchRequestEntries.member.2.Id", "msg2"),
                ("PublishBatchRequestEntries.member.2.Message", "Hello 2"),
            ],
        );
        let result = svc.publish_batch(&req);
        assert_ok(&result);
        let body = response_body(&result);
        assert!(
            body.contains("<Successful>"),
            "Response should contain Successful element"
        );

        let s = state.read();
        assert_eq!(s.default_ref().published.len(), 2);
    }

    #[test]
    fn publish_batch_rejects_duplicate_ids() {
        let (svc, _state) = make_sns();
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "batch-dup")])));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:batch-dup";
        let req = sns_request(
            "PublishBatch",
            vec![
                ("TopicArn", topic_arn),
                ("PublishBatchRequestEntries.member.1.Id", "same"),
                ("PublishBatchRequestEntries.member.1.Message", "Hello 1"),
                ("PublishBatchRequestEntries.member.2.Id", "same"),
                ("PublishBatchRequestEntries.member.2.Message", "Hello 2"),
            ],
        );
        let result = svc.publish_batch(&req);
        assert!(result.is_err(), "Duplicate batch IDs should error");
    }

    // --- SetSubscriptionAttributes / GetSubscriptionAttributes ---

    #[test]
    fn get_subscription_attributes_returns_defaults() {
        let (svc, state) = make_sns();
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "attr-topic")])));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:attr-topic";
        assert_ok(&svc.subscribe(&sns_request(
            "Subscribe",
            vec![
                ("TopicArn", topic_arn),
                ("Protocol", "email"),
                ("Endpoint", "u@example.com"),
            ],
        )));

        let sub_arn = {
            let s = state.read();
            s.default_ref().subscriptions.keys().next().unwrap().clone()
        };

        let req = sns_request(
            "GetSubscriptionAttributes",
            vec![("SubscriptionArn", &sub_arn)],
        );
        let result = svc.get_subscription_attributes(&req);
        assert_ok(&result);
        let body = response_body(&result);
        assert!(
            body.contains("<key>Protocol</key>"),
            "Should contain Protocol attribute"
        );
        assert!(
            body.contains("<value>email</value>"),
            "Protocol should be email"
        );
        assert!(
            body.contains("<key>Endpoint</key>"),
            "Should contain Endpoint attribute"
        );
        assert!(
            body.contains("<key>RawMessageDelivery</key>"),
            "Should contain RawMessageDelivery"
        );
    }

    #[test]
    fn set_subscription_attributes_updates_value() {
        let (svc, state) = make_sns();
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "setattr-topic")])));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:setattr-topic";
        assert_ok(&svc.subscribe(&sns_request(
            "Subscribe",
            vec![
                ("TopicArn", topic_arn),
                ("Protocol", "email"),
                ("Endpoint", "u@example.com"),
            ],
        )));

        let sub_arn = {
            let s = state.read();
            s.default_ref().subscriptions.keys().next().unwrap().clone()
        };

        // Set RawMessageDelivery to true
        let req = sns_request(
            "SetSubscriptionAttributes",
            vec![
                ("SubscriptionArn", &sub_arn),
                ("AttributeName", "RawMessageDelivery"),
                ("AttributeValue", "true"),
            ],
        );
        assert_ok(&svc.set_subscription_attributes(&req));

        // Verify in state
        let s = state.read();
        let sub = s.default_ref().subscriptions.get(&sub_arn).unwrap();
        assert_eq!(sub.attributes.get("RawMessageDelivery").unwrap(), "true");
    }

    #[test]
    fn set_subscription_attributes_rejects_invalid_attr() {
        let (svc, state) = make_sns();
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "inv-attr")])));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:inv-attr";
        assert_ok(&svc.subscribe(&sns_request(
            "Subscribe",
            vec![
                ("TopicArn", topic_arn),
                ("Protocol", "email"),
                ("Endpoint", "u@example.com"),
            ],
        )));

        let sub_arn = {
            let s = state.read();
            s.default_ref().subscriptions.keys().next().unwrap().clone()
        };

        let req = sns_request(
            "SetSubscriptionAttributes",
            vec![
                ("SubscriptionArn", &sub_arn),
                ("AttributeName", "BogusAttribute"),
                ("AttributeValue", "whatever"),
            ],
        );
        let result = svc.set_subscription_attributes(&req);
        assert!(result.is_err(), "Invalid attribute name should error");
    }

    #[test]
    fn get_subscription_attributes_nonexistent_returns_error() {
        let (svc, _state) = make_sns();
        let req = sns_request(
            "GetSubscriptionAttributes",
            vec![(
                "SubscriptionArn",
                "arn:aws:sns:us-east-1:123456789012:nope:fake",
            )],
        );
        let result = svc.get_subscription_attributes(&req);
        assert!(result.is_err(), "Nonexistent subscription should error");
    }

    // --- TagResource / UntagResource / ListTagsForResource ---

    #[test]
    fn tag_untag_list_tags_lifecycle() {
        let (svc, _state) = make_sns();
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "tag-topic")])));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:tag-topic";

        // Tag the resource
        let req = sns_request(
            "TagResource",
            vec![
                ("ResourceArn", topic_arn),
                ("Tags.member.1.Key", "env"),
                ("Tags.member.1.Value", "prod"),
                ("Tags.member.2.Key", "team"),
                ("Tags.member.2.Value", "platform"),
            ],
        );
        assert_ok(&svc.tag_resource(&req));

        // List tags
        let req = sns_request("ListTagsForResource", vec![("ResourceArn", topic_arn)]);
        let result = svc.list_tags_for_resource(&req);
        assert_ok(&result);
        let body = response_body(&result);
        assert!(
            body.contains("<Key>env</Key>"),
            "Should contain env tag key"
        );
        assert!(
            body.contains("<Value>prod</Value>"),
            "Should contain prod tag value"
        );
        assert!(
            body.contains("<Key>team</Key>"),
            "Should contain team tag key"
        );

        // Untag one key
        let req = sns_request(
            "UntagResource",
            vec![("ResourceArn", topic_arn), ("TagKeys.member.1", "env")],
        );
        assert_ok(&svc.untag_resource(&req));

        // Verify only team remains
        let req = sns_request("ListTagsForResource", vec![("ResourceArn", topic_arn)]);
        let result = svc.list_tags_for_resource(&req);
        assert_ok(&result);
        let body = response_body(&result);
        assert!(
            !body.contains("<Key>env</Key>"),
            "env tag should be removed"
        );
        assert!(body.contains("<Key>team</Key>"), "team tag should remain");
    }

    #[test]
    fn tag_resource_nonexistent_returns_error() {
        let (svc, _state) = make_sns();
        let req = sns_request(
            "TagResource",
            vec![
                ("ResourceArn", "arn:aws:sns:us-east-1:123456789012:nope"),
                ("Tags.member.1.Key", "k"),
                ("Tags.member.1.Value", "v"),
            ],
        );
        let result = svc.tag_resource(&req);
        assert!(result.is_err(), "Tagging nonexistent resource should error");
    }

    #[test]
    fn tag_resource_overwrites_existing_key() {
        let (svc, _state) = make_sns();
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "tag-overwrite")])));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:tag-overwrite";

        // Add tag
        let req = sns_request(
            "TagResource",
            vec![
                ("ResourceArn", topic_arn),
                ("Tags.member.1.Key", "env"),
                ("Tags.member.1.Value", "dev"),
            ],
        );
        assert_ok(&svc.tag_resource(&req));

        // Overwrite tag
        let req = sns_request(
            "TagResource",
            vec![
                ("ResourceArn", topic_arn),
                ("Tags.member.1.Key", "env"),
                ("Tags.member.1.Value", "prod"),
            ],
        );
        assert_ok(&svc.tag_resource(&req));

        // Verify overwritten
        let req = sns_request("ListTagsForResource", vec![("ResourceArn", topic_arn)]);
        let body = response_body(&svc.list_tags_for_resource(&req));
        assert!(
            body.contains("<Value>prod</Value>"),
            "Tag value should be overwritten to prod"
        );
        // Should only have 1 member
        assert_eq!(
            body.matches("<member>").count(),
            1,
            "Should have exactly 1 tag"
        );
    }

    // --- SetTopicAttributes / GetTopicAttributes ---

    #[test]
    fn set_and_get_topic_attributes() {
        let (svc, _state) = make_sns();
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "attr-topic2")])));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:attr-topic2";

        // Set DisplayName
        let req = sns_request(
            "SetTopicAttributes",
            vec![
                ("TopicArn", topic_arn),
                ("AttributeName", "DisplayName"),
                ("AttributeValue", "My Nice Topic"),
            ],
        );
        assert_ok(&svc.set_topic_attributes(&req));

        // Get attributes
        let req = sns_request("GetTopicAttributes", vec![("TopicArn", topic_arn)]);
        let result = svc.get_topic_attributes(&req);
        assert_ok(&result);
        let body = response_body(&result);
        assert!(
            body.contains("<value>My Nice Topic</value>"),
            "DisplayName should be set"
        );
        assert!(
            body.contains("<key>TopicArn</key>"),
            "Should contain TopicArn"
        );
        assert!(body.contains("<key>Owner</key>"), "Should contain Owner");
    }

    #[test]
    fn get_topic_attributes_nonexistent_returns_error() {
        let (svc, _state) = make_sns();
        let req = sns_request(
            "GetTopicAttributes",
            vec![("TopicArn", "arn:aws:sns:us-east-1:123456789012:nope")],
        );
        let result = svc.get_topic_attributes(&req);
        assert!(result.is_err(), "Nonexistent topic should error");
    }

    #[test]
    fn get_topic_attributes_wrong_region_returns_error() {
        let (svc, _state) = make_sns();
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "region-topic")])));

        // The topic was created in us-east-1, but try to get it with a different region in the ARN
        let req = sns_request(
            "GetTopicAttributes",
            vec![(
                "TopicArn",
                "arn:aws:sns:eu-west-1:123456789012:region-topic",
            )],
        );
        let result = svc.get_topic_attributes(&req);
        assert!(result.is_err(), "Topic in wrong region should error");
    }

    // --- ConfirmSubscription ---

    #[test]
    fn confirm_subscription_returns_arn() {
        let (svc, state) = make_sns();
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "confirm-topic")])));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:confirm-topic";

        // Subscribe an HTTP endpoint (starts as pending)
        assert_ok(&svc.subscribe(&sns_request(
            "Subscribe",
            vec![
                ("TopicArn", topic_arn),
                ("Protocol", "http"),
                ("Endpoint", "http://example.com/hook"),
            ],
        )));

        // Get the token from the pending subscription
        let token = {
            let s = state.read();
            s.default_ref()
                .subscriptions
                .values()
                .find(|sub| sub.topic_arn == topic_arn && !sub.confirmed)
                .expect("should have a pending subscription")
                .confirmation_token
                .clone()
                .expect("pending subscription should have a token")
        };

        let req = sns_request(
            "ConfirmSubscription",
            vec![("TopicArn", topic_arn), ("Token", &token)],
        );
        let result = svc.confirm_subscription(&req);
        assert_ok(&result);
        let body = response_body(&result);
        assert!(
            body.contains("<SubscriptionArn>"),
            "Should return a SubscriptionArn"
        );

        // Verify the subscription is now confirmed
        let s = state.read();
        let sub = s
            .default_ref()
            .subscriptions
            .values()
            .find(|sub| sub.topic_arn == topic_arn)
            .expect("subscription should exist");
        assert!(sub.confirmed, "subscription should be confirmed");
    }

    #[test]
    fn confirm_subscription_rejects_invalid_token() {
        let (svc, _state) = make_sns();
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "confirm-topic")])));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:confirm-topic";

        // Subscribe an HTTP endpoint (starts as pending)
        assert_ok(&svc.subscribe(&sns_request(
            "Subscribe",
            vec![
                ("TopicArn", topic_arn),
                ("Protocol", "http"),
                ("Endpoint", "http://example.com/hook"),
            ],
        )));

        // Try to confirm with wrong token
        let req = sns_request(
            "ConfirmSubscription",
            vec![("TopicArn", topic_arn), ("Token", "wrong-token")],
        );
        let result = svc.confirm_subscription(&req);
        assert!(result.is_err(), "Should reject invalid token");
    }

    #[test]
    fn confirm_subscription_matches_correct_pending_sub() {
        let (svc, state) = make_sns();
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "multi-topic")])));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:multi-topic";

        // Subscribe two HTTP endpoints (both start as pending)
        assert_ok(&svc.subscribe(&sns_request(
            "Subscribe",
            vec![
                ("TopicArn", topic_arn),
                ("Protocol", "http"),
                ("Endpoint", "http://first.example.com/hook"),
            ],
        )));
        assert_ok(&svc.subscribe(&sns_request(
            "Subscribe",
            vec![
                ("TopicArn", topic_arn),
                ("Protocol", "http"),
                ("Endpoint", "http://second.example.com/hook"),
            ],
        )));

        // Get the token for the second subscription
        let (second_arn, second_token) = {
            let s = state.read();
            let sub = s
                .default_ref()
                .subscriptions
                .values()
                .find(|sub| sub.endpoint == "http://second.example.com/hook")
                .expect("should have second subscription");
            (
                sub.subscription_arn.clone(),
                sub.confirmation_token.clone().unwrap(),
            )
        };

        // Confirm using the second subscription's token
        let req = sns_request(
            "ConfirmSubscription",
            vec![("TopicArn", topic_arn), ("Token", &second_token)],
        );
        let result = svc.confirm_subscription(&req);
        assert_ok(&result);
        let body = response_body(&result);
        assert!(
            body.contains(&second_arn),
            "Should return the second subscription's ARN"
        );

        // Verify only the second subscription is confirmed
        let s = state.read();
        for sub in s.default_ref().subscriptions.values() {
            if sub.endpoint == "http://second.example.com/hook" {
                assert!(sub.confirmed, "second subscription should be confirmed");
            } else {
                assert!(!sub.confirmed, "first subscription should still be pending");
            }
        }
    }

    #[test]
    fn confirm_subscription_accepts_sub_arn_as_token() {
        let (svc, state) = make_sns();
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "arn-token")])));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:arn-token";

        // Subscribe an HTTP endpoint (starts as pending)
        assert_ok(&svc.subscribe(&sns_request(
            "Subscribe",
            vec![
                ("TopicArn", topic_arn),
                ("Protocol", "http"),
                ("Endpoint", "http://example.com/hook"),
            ],
        )));

        // Get the subscription ARN
        let sub_arn = {
            let s = state.read();
            s.default_ref()
                .subscriptions
                .values()
                .find(|sub| sub.topic_arn == topic_arn)
                .expect("should have a subscription")
                .subscription_arn
                .clone()
        };

        // Confirm using the subscription ARN as the token (AWS-compatible behavior)
        let req = sns_request(
            "ConfirmSubscription",
            vec![("TopicArn", topic_arn), ("Token", &sub_arn)],
        );
        let result = svc.confirm_subscription(&req);
        assert_ok(&result);

        // Verify the subscription is now confirmed
        let s = state.read();
        let sub = s
            .default_ref()
            .subscriptions
            .values()
            .find(|sub| sub.topic_arn == topic_arn)
            .expect("subscription should exist");
        assert!(sub.confirmed, "subscription should be confirmed");
    }

    // --- CreateTopic / DeleteTopic / ListTopics ---

    #[test]
    fn create_delete_list_topics_lifecycle() {
        let (svc, _state) = make_sns();
        // Create two topics
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "topic1")])));
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "topic2")])));

        // List
        let req = sns_request("ListTopics", vec![]);
        let body = response_body(&svc.list_topics(&req));
        assert_eq!(body.matches("<TopicArn>").count(), 2);

        // Delete one
        let req = sns_request(
            "DeleteTopic",
            vec![("TopicArn", "arn:aws:sns:us-east-1:123456789012:topic1")],
        );
        assert_ok(&svc.delete_topic(&req));

        // List again
        let req = sns_request("ListTopics", vec![]);
        let body = response_body(&svc.list_topics(&req));
        assert_eq!(body.matches("<TopicArn>").count(), 1);
        assert!(body.contains("topic2"), "topic2 should remain");
    }

    #[test]
    fn create_topic_idempotent() {
        let (svc, _state) = make_sns();
        let r1 = svc.create_topic(&sns_request("CreateTopic", vec![("Name", "idem-topic")]));
        assert_ok(&r1);
        let r2 = svc.create_topic(&sns_request("CreateTopic", vec![("Name", "idem-topic")]));
        assert_ok(&r2);
        let body1 = response_body(&r1);
        let body2 = response_body(&r2);
        assert_eq!(
            body1, body2,
            "Creating same topic twice should be idempotent"
        );
    }

    // --- AddPermission / RemovePermission ---

    #[test]
    fn add_and_remove_permission() {
        let (svc, state) = make_sns();
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "perm-topic")])));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:perm-topic";
        let req = sns_request(
            "AddPermission",
            vec![
                ("TopicArn", topic_arn),
                ("Label", "MyPermission"),
                ("AWSAccountId.member.1", "111111111111"),
                ("ActionName.member.1", "Publish"),
            ],
        );
        assert_ok(&svc.add_permission(&req));

        // Verify policy has the new statement
        {
            let s = state.read();
            let policy_str = s
                .default_ref()
                .topics
                .get(topic_arn)
                .unwrap()
                .attributes
                .get("Policy")
                .unwrap();
            let policy: Value = serde_json::from_str(policy_str).unwrap();
            let stmts = policy["Statement"].as_array().unwrap();
            assert!(
                stmts
                    .iter()
                    .any(|s| s["Sid"].as_str() == Some("MyPermission")),
                "Policy should contain MyPermission statement"
            );
        }

        // Remove permission
        let req = sns_request(
            "RemovePermission",
            vec![("TopicArn", topic_arn), ("Label", "MyPermission")],
        );
        assert_ok(&svc.remove_permission(&req));

        // Verify removed
        {
            let s = state.read();
            let policy_str = s
                .default_ref()
                .topics
                .get(topic_arn)
                .unwrap()
                .attributes
                .get("Policy")
                .unwrap();
            let policy: Value = serde_json::from_str(policy_str).unwrap();
            let stmts = policy["Statement"].as_array().unwrap();
            assert!(
                !stmts
                    .iter()
                    .any(|s| s["Sid"].as_str() == Some("MyPermission")),
                "MyPermission should be removed"
            );
        }
    }

    // --- FIFO topic ---

    #[test]
    fn publish_to_fifo_topic_requires_group_id() {
        let (svc, _state) = make_sns();
        let mut req = sns_request("CreateTopic", vec![("Name", "fifo-topic.fifo")]);
        req.query_params.insert(
            "Attributes.entry.1.key".to_string(),
            "FifoTopic".to_string(),
        );
        req.query_params
            .insert("Attributes.entry.1.value".to_string(), "true".to_string());
        assert_ok(&svc.create_topic(&req));

        let topic_arn = "arn:aws:sns:us-east-1:123456789012:fifo-topic.fifo";
        // Publish without MessageGroupId — should fail
        let req = sns_request(
            "Publish",
            vec![("TopicArn", topic_arn), ("Message", "Hello")],
        );
        let result = svc.publish(&req);
        assert!(
            result.is_err(),
            "FIFO publish without MessageGroupId should error"
        );
    }

    // --- SMS attributes ---

    #[test]
    fn set_and_get_sms_attributes() {
        let (svc, _state) = make_sns();

        let mut req = sns_request("SetSMSAttributes", vec![]);
        req.query_params.insert(
            "attributes.entry.1.key".to_string(),
            "DefaultSMSType".to_string(),
        );
        req.query_params.insert(
            "attributes.entry.1.value".to_string(),
            "Transactional".to_string(),
        );
        assert_ok(&svc.set_sms_attributes(&req));

        let req = sns_request("GetSMSAttributes", vec![]);
        let result = svc.get_sms_attributes(&req);
        assert_ok(&result);
        let body = response_body(&result);
        assert!(
            body.contains("DefaultSMSType"),
            "Should contain set SMS attribute"
        );
    }

    // --- Phone opt-out ---

    #[test]
    fn check_phone_opted_out() {
        let (svc, state) = make_sns();
        state.write().default_mut().seed_default_opted_out();

        let req = sns_request(
            "CheckIfPhoneNumberIsOptedOut",
            vec![("phoneNumber", "+15005550099")],
        );
        let result = svc.check_if_phone_number_is_opted_out(&req);
        assert_ok(&result);
        let body = response_body(&result);
        assert!(
            body.contains("<isOptedOut>true</isOptedOut>"),
            "Seeded number should be opted out"
        );
    }

    #[test]
    fn list_phone_numbers_opted_out() {
        let (svc, state) = make_sns();
        state.write().default_mut().seed_default_opted_out();

        let req = sns_request("ListPhoneNumbersOptedOut", vec![]);
        let result = svc.list_phone_numbers_opted_out(&req);
        assert_ok(&result);
        let body = response_body(&result);
        assert!(
            body.contains("+15005550099"),
            "Should list seeded opted-out number"
        );
    }

    #[test]
    fn opt_in_phone_number() {
        let (svc, state) = make_sns();
        state.write().default_mut().seed_default_opted_out();

        let req = sns_request("OptInPhoneNumber", vec![("phoneNumber", "+15005550099")]);
        assert_ok(&svc.opt_in_phone_number(&req));

        // Verify removed from opted-out list
        let s = state.read();
        assert!(
            !s.default_ref()
                .opted_out_numbers
                .contains(&"+15005550099".to_string()),
            "Phone should no longer be opted out"
        );
    }

    // --- Delete topic also removes subscriptions ---

    #[test]
    fn delete_topic_removes_subscriptions() {
        let (svc, state) = make_sns();
        assert_ok(&svc.create_topic(&sns_request("CreateTopic", vec![("Name", "del-sub-topic")])));
        let topic_arn = "arn:aws:sns:us-east-1:123456789012:del-sub-topic";
        assert_ok(&svc.subscribe(&sns_request(
            "Subscribe",
            vec![
                ("TopicArn", topic_arn),
                ("Protocol", "email"),
                ("Endpoint", "u@example.com"),
            ],
        )));

        assert_eq!(state.read().default_ref().subscriptions.len(), 1);

        assert_ok(&svc.delete_topic(&sns_request("DeleteTopic", vec![("TopicArn", topic_arn)])));
        assert_eq!(
            state.read().default_ref().subscriptions.len(),
            0,
            "Subscriptions should be removed with topic"
        );
    }

    #[test]
    fn malformed_filter_policy_does_not_match() {
        let sub = SnsSubscription {
            subscription_arn: "arn:aws:sns:us-east-1:123456789012:t:sub-1".to_string(),
            topic_arn: "arn:aws:sns:us-east-1:123456789012:t".to_string(),
            protocol: "sqs".to_string(),
            endpoint: "arn:aws:sqs:us-east-1:123456789012:q".to_string(),
            owner: "123456789012".to_string(),
            attributes: HashMap::from([(
                "FilterPolicy".to_string(),
                "not valid json {{[".to_string(),
            )]),
            confirmed: true,
            confirmation_token: None,
        };
        let attrs = HashMap::new();
        assert!(
            !matches_filter_policy(&sub, &attrs, "hello"),
            "malformed FilterPolicy JSON must not match (fail closed)"
        );
    }

    // ── Platform applications and endpoints ─────────────────────────

    fn create_app(svc: &SnsService, name: &str, platform: &str) -> String {
        let req = sns_request(
            "CreatePlatformApplication",
            vec![
                ("Name", name),
                ("Platform", platform),
                ("Attributes.entry.1.key", "PlatformPrincipal"),
                ("Attributes.entry.1.value", "principal"),
                ("Attributes.entry.2.key", "PlatformCredential"),
                ("Attributes.entry.2.value", "secret"),
            ],
        );
        let resp = svc.create_platform_application(&req).unwrap();
        let body = String::from_utf8(resp.body.expect_bytes().to_vec()).unwrap();
        let start =
            body.find("<PlatformApplicationArn>").unwrap() + "<PlatformApplicationArn>".len();
        let end = body.find("</PlatformApplicationArn>").unwrap();
        body[start..end].to_string()
    }

    #[test]
    fn create_platform_application_persists_arn_and_attrs() {
        let (svc, state) = make_sns();
        let arn = create_app(&svc, "MyApp", "GCM");
        let s = state.read();
        let app = s.default_ref().platform_applications.get(&arn).unwrap();
        assert_eq!(app.name, "MyApp");
        assert_eq!(app.platform, "GCM");
        assert_eq!(
            app.attributes.get("PlatformPrincipal").map(String::as_str),
            Some("principal")
        );
    }

    #[test]
    fn list_platform_applications_returns_created_app() {
        let (svc, _) = make_sns();
        let arn = create_app(&svc, "MyApp", "APNS");
        let req = sns_request("ListPlatformApplications", vec![]);
        let resp = svc.list_platform_applications(&req).unwrap();
        let body = String::from_utf8(resp.body.expect_bytes().to_vec()).unwrap();
        assert!(body.contains(&arn));
    }

    #[test]
    fn get_platform_application_attributes_unknown_errors() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "GetPlatformApplicationAttributes",
            vec![(
                "PlatformApplicationArn",
                "arn:aws:sns:us-east-1:123456789012:app/GCM/Ghost",
            )],
        );
        let result = svc.get_platform_application_attributes(&req);
        assert!(result.is_err());
    }

    #[test]
    fn set_platform_application_attributes_updates_attrs() {
        let (svc, state) = make_sns();
        let arn = create_app(&svc, "MyApp", "GCM");
        let req = sns_request(
            "SetPlatformApplicationAttributes",
            vec![
                ("PlatformApplicationArn", arn.as_str()),
                ("Attributes.entry.1.key", "Enabled"),
                ("Attributes.entry.1.value", "false"),
            ],
        );
        svc.set_platform_application_attributes(&req).unwrap();
        let s = state.read();
        assert_eq!(
            s.default_ref()
                .platform_applications
                .get(&arn)
                .unwrap()
                .attributes
                .get("Enabled")
                .map(String::as_str),
            Some("false")
        );
    }

    #[test]
    fn delete_platform_application_removes_entry() {
        let (svc, state) = make_sns();
        let arn = create_app(&svc, "MyApp", "GCM");
        let req = sns_request(
            "DeletePlatformApplication",
            vec![("PlatformApplicationArn", arn.as_str())],
        );
        svc.delete_platform_application(&req).unwrap();
        assert!(state.read().default_ref().platform_applications.is_empty());
    }

    fn create_endpoint(svc: &SnsService, app_arn: &str, token: &str) -> String {
        let req = sns_request(
            "CreatePlatformEndpoint",
            vec![("PlatformApplicationArn", app_arn), ("Token", token)],
        );
        let resp = svc.create_platform_endpoint(&req).unwrap();
        let body = String::from_utf8(resp.body.expect_bytes().to_vec()).unwrap();
        let start = body.find("<EndpointArn>").unwrap() + "<EndpointArn>".len();
        let end = body.find("</EndpointArn>").unwrap();
        body[start..end].to_string()
    }

    #[test]
    fn create_platform_endpoint_unknown_app_errors() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "CreatePlatformEndpoint",
            vec![
                (
                    "PlatformApplicationArn",
                    "arn:aws:sns:us-east-1:123456789012:app/GCM/Ghost",
                ),
                ("Token", "token-1"),
            ],
        );
        assert!(svc.create_platform_endpoint(&req).is_err());
    }

    #[test]
    fn create_platform_endpoint_idempotent_on_same_token() {
        let (svc, _) = make_sns();
        let app_arn = create_app(&svc, "MyApp", "GCM");
        let arn1 = create_endpoint(&svc, &app_arn, "token-1");
        let arn2 = create_endpoint(&svc, &app_arn, "token-1");
        assert_eq!(arn1, arn2, "duplicate Token should return same EndpointArn");
    }

    #[test]
    fn create_platform_endpoint_same_token_different_attrs_errors() {
        let (svc, _) = make_sns();
        let app_arn = create_app(&svc, "MyApp", "GCM");
        let _ = create_endpoint(&svc, &app_arn, "token-1");
        let req = sns_request(
            "CreatePlatformEndpoint",
            vec![
                ("PlatformApplicationArn", app_arn.as_str()),
                ("Token", "token-1"),
                ("Attributes.entry.1.key", "Enabled"),
                ("Attributes.entry.1.value", "false"),
            ],
        );
        let result = svc.create_platform_endpoint(&req);
        assert!(result.is_err());
    }

    #[test]
    fn get_set_endpoint_attributes_round_trip() {
        let (svc, _) = make_sns();
        let app_arn = create_app(&svc, "MyApp", "GCM");
        let endpoint_arn = create_endpoint(&svc, &app_arn, "token-1");

        let set_req = sns_request(
            "SetEndpointAttributes",
            vec![
                ("EndpointArn", endpoint_arn.as_str()),
                ("Attributes.entry.1.key", "CustomUserData"),
                ("Attributes.entry.1.value", "user-1"),
            ],
        );
        svc.set_endpoint_attributes(&set_req).unwrap();

        let get_req = sns_request(
            "GetEndpointAttributes",
            vec![("EndpointArn", endpoint_arn.as_str())],
        );
        let resp = svc.get_endpoint_attributes(&get_req).unwrap();
        let body = String::from_utf8(resp.body.expect_bytes().to_vec()).unwrap();
        assert!(body.contains("<key>CustomUserData</key>"));
        assert!(body.contains("<value>user-1</value>"));
    }

    #[test]
    fn delete_endpoint_removes_endpoint() {
        let (svc, state) = make_sns();
        let app_arn = create_app(&svc, "MyApp", "GCM");
        let endpoint_arn = create_endpoint(&svc, &app_arn, "token-1");
        let del = sns_request(
            "DeleteEndpoint",
            vec![("EndpointArn", endpoint_arn.as_str())],
        );
        svc.delete_endpoint(&del).unwrap();
        let s = state.read();
        let app = s.default_ref().platform_applications.get(&app_arn).unwrap();
        assert!(app.endpoints.is_empty());
    }

    #[test]
    fn get_endpoint_attributes_unknown_errors() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "GetEndpointAttributes",
            vec![(
                "EndpointArn",
                "arn:aws:sns:us-east-1:123456789012:endpoint/GCM/MyApp/ghost",
            )],
        );
        assert!(svc.get_endpoint_attributes(&req).is_err());
    }

    // ── Error branch tests ──

    #[test]
    fn get_topic_attributes_not_found() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "GetTopicAttributes",
            vec![("TopicArn", "arn:aws:sns:us-east-1:123456789012:nonexistent")],
        );
        assert!(svc.get_topic_attributes(&req).is_err());
    }

    #[test]
    fn delete_topic_not_found() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "DeleteTopic",
            vec![("TopicArn", "arn:aws:sns:us-east-1:123456789012:nonexistent")],
        );
        // DeleteTopic returns success even for nonexistent topics (AWS behavior)
        assert!(svc.delete_topic(&req).is_ok());
    }

    #[test]
    fn subscribe_to_nonexistent_topic() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "Subscribe",
            vec![
                ("TopicArn", "arn:aws:sns:us-east-1:123456789012:nope"),
                ("Protocol", "email"),
                ("Endpoint", "test@example.com"),
            ],
        );
        assert!(svc.subscribe(&req).is_err());
    }

    #[test]
    fn unsubscribe_nonexistent_is_noop() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "Unsubscribe",
            vec![(
                "SubscriptionArn",
                "arn:aws:sns:us-east-1:123456789012:topic:nonexistent-sub",
            )],
        );
        // AWS returns success for nonexistent subscriptions
        assert!(svc.unsubscribe(&req).is_ok());
    }

    #[test]
    fn set_topic_attributes_not_found() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "SetTopicAttributes",
            vec![
                ("TopicArn", "arn:aws:sns:us-east-1:123456789012:nope"),
                ("AttributeName", "DisplayName"),
                ("AttributeValue", "My Topic"),
            ],
        );
        assert!(svc.set_topic_attributes(&req).is_err());
    }

    #[test]
    fn publish_to_nonexistent_topic() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "Publish",
            vec![
                ("TopicArn", "arn:aws:sns:us-east-1:123456789012:nope"),
                ("Message", "hello"),
            ],
        );
        assert!(svc.publish(&req).is_err());
    }

    #[test]
    fn get_subscription_attributes_not_found() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "GetSubscriptionAttributes",
            vec![(
                "SubscriptionArn",
                "arn:aws:sns:us-east-1:123456789012:topic:bad-sub",
            )],
        );
        assert!(svc.get_subscription_attributes(&req).is_err());
    }

    #[test]
    fn set_subscription_attributes_not_found() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "SetSubscriptionAttributes",
            vec![
                (
                    "SubscriptionArn",
                    "arn:aws:sns:us-east-1:123456789012:topic:bad-sub",
                ),
                ("AttributeName", "FilterPolicy"),
                ("AttributeValue", "{}"),
            ],
        );
        assert!(svc.set_subscription_attributes(&req).is_err());
    }

    #[test]
    fn tag_resource_nonexistent_topic() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "TagResource",
            vec![
                ("ResourceArn", "arn:aws:sns:us-east-1:123456789012:nope"),
                ("Tags.member.1.Key", "env"),
                ("Tags.member.1.Value", "prod"),
            ],
        );
        assert!(svc.tag_resource(&req).is_err());
    }

    #[test]
    fn untag_resource_nonexistent_topic() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "UntagResource",
            vec![
                ("ResourceArn", "arn:aws:sns:us-east-1:123456789012:nope"),
                ("TagKeys.member.1", "env"),
            ],
        );
        assert!(svc.untag_resource(&req).is_err());
    }

    #[test]
    fn list_tags_nonexistent_topic() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "ListTagsForResource",
            vec![("ResourceArn", "arn:aws:sns:us-east-1:123456789012:nope")],
        );
        assert!(svc.list_tags_for_resource(&req).is_err());
    }

    #[test]
    fn create_topic_duplicate_returns_existing_arn() {
        let (svc, _) = make_sns();
        let req = sns_request("CreateTopic", vec![("Name", "dup-topic")]);
        let resp1 = svc.create_topic(&req).unwrap();

        let req = sns_request("CreateTopic", vec![("Name", "dup-topic")]);
        let resp2 = svc.create_topic(&req).unwrap();

        // Should return same ARN (idempotent)
        let body1 = std::str::from_utf8(resp1.body.expect_bytes()).unwrap();
        let body2 = std::str::from_utf8(resp2.body.expect_bytes()).unwrap();
        assert_eq!(body1, body2);
    }

    #[test]
    fn confirm_subscription_not_found() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "ConfirmSubscription",
            vec![
                ("TopicArn", "arn:aws:sns:us-east-1:123456789012:nope"),
                ("Token", "fake-token"),
            ],
        );
        assert!(svc.confirm_subscription(&req).is_err());
    }

    #[test]
    fn get_platform_application_attributes_not_found() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "GetPlatformApplicationAttributes",
            vec![(
                "PlatformApplicationArn",
                "arn:aws:sns:us-east-1:123456789012:app/GCM/ghost",
            )],
        );
        assert!(svc.get_platform_application_attributes(&req).is_err());
    }

    #[test]
    fn create_platform_endpoint_app_not_found() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "CreatePlatformEndpoint",
            vec![
                (
                    "PlatformApplicationArn",
                    "arn:aws:sns:us-east-1:123456789012:app/GCM/ghost",
                ),
                ("Token", "device-token"),
            ],
        );
        assert!(svc.create_platform_endpoint(&req).is_err());
    }

    // ── Phone number opt-out check ──

    #[test]
    fn check_if_phone_number_is_opted_out() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "CheckIfPhoneNumberIsOptedOut",
            vec![("phoneNumber", "+15551234567")],
        );
        let resp = svc.check_if_phone_number_is_opted_out(&req).unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("isOptedOut"));
    }

    // ── Publish batch ──

    #[test]
    fn publish_batch() {
        let (svc, _) = make_sns();
        let req = sns_request("CreateTopic", vec![("Name", "batch-topic")]);
        let resp = svc.create_topic(&req).unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        let arn_start = body.find("<TopicArn>").unwrap() + 10;
        let arn_end = body.find("</TopicArn>").unwrap();
        let arn = body[arn_start..arn_end].to_string();

        let req = sns_request(
            "PublishBatch",
            vec![
                ("TopicArn", &arn),
                ("PublishBatchRequestEntries.member.1.Id", "1"),
                ("PublishBatchRequestEntries.member.1.Message", "msg1"),
                ("PublishBatchRequestEntries.member.2.Id", "2"),
                ("PublishBatchRequestEntries.member.2.Message", "msg2"),
            ],
        );
        let resp = svc.publish_batch(&req).unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("Successful"));
    }

    #[test]
    fn publish_batch_to_nonexistent_topic() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "PublishBatch",
            vec![
                ("TopicArn", "arn:aws:sns:us-east-1:123456789012:ghost"),
                ("PublishBatchRequestEntries.member.1.Id", "1"),
                ("PublishBatchRequestEntries.member.1.Message", "msg"),
            ],
        );
        assert!(svc.publish_batch(&req).is_err());
    }

    // ── Subscriptions list ──

    #[test]
    fn list_subscriptions_by_topic() {
        let (svc, _) = make_sns();
        let req = sns_request("CreateTopic", vec![("Name", "sub-topic")]);
        let resp = svc.create_topic(&req).unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        let arn_start = body.find("<TopicArn>").unwrap() + 10;
        let arn_end = body.find("</TopicArn>").unwrap();
        let arn = body[arn_start..arn_end].to_string();

        let req = sns_request(
            "Subscribe",
            vec![
                ("TopicArn", &arn),
                ("Protocol", "email"),
                ("Endpoint", "test@example.com"),
                ("ReturnSubscriptionArn", "true"),
            ],
        );
        svc.subscribe(&req).unwrap();

        let req = sns_request("ListSubscriptionsByTopic", vec![("TopicArn", &arn)]);
        let resp = svc.list_subscriptions_by_topic(&req).unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("Subscriptions"));
    }

    #[test]
    fn list_subscriptions() {
        let (svc, _) = make_sns();
        let req = sns_request("ListSubscriptions", vec![]);
        svc.list_subscriptions(&req).unwrap();
    }

    // ── Topic policy attribute ──

    #[test]
    fn set_topic_policy_attribute() {
        let (svc, _) = make_sns();
        let req = sns_request("CreateTopic", vec![("Name", "policy-t")]);
        let resp = svc.create_topic(&req).unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        let arn_start = body.find("<TopicArn>").unwrap() + 10;
        let arn_end = body.find("</TopicArn>").unwrap();
        let arn = body[arn_start..arn_end].to_string();

        let policy = r#"{"Version":"2012-10-17","Statement":[]}"#;
        let req = sns_request(
            "SetTopicAttributes",
            vec![
                ("TopicArn", &arn),
                ("AttributeName", "Policy"),
                ("AttributeValue", policy),
            ],
        );
        svc.set_topic_attributes(&req).unwrap();
    }

    // ── Platform application full lifecycle ──

    #[test]
    fn platform_application_create_list_delete() {
        let (svc, _) = make_sns();

        let req = sns_request(
            "CreatePlatformApplication",
            vec![
                ("Name", "MyApp"),
                ("Platform", "GCM"),
                ("Attributes.entry.1.key", "PlatformCredential"),
                ("Attributes.entry.1.value", "api-key-value"),
            ],
        );
        let resp = svc.create_platform_application(&req).unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        let arn_start = body.find("<PlatformApplicationArn>").unwrap() + 24;
        let arn_end = body.find("</PlatformApplicationArn>").unwrap();
        let arn = body[arn_start..arn_end].to_string();

        // List
        let req = sns_request("ListPlatformApplications", vec![]);
        let resp = svc.list_platform_applications(&req).unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        assert!(body.contains("MyApp"));

        // GetPlatformApplicationAttributes
        let req = sns_request(
            "GetPlatformApplicationAttributes",
            vec![("PlatformApplicationArn", &arn)],
        );
        svc.get_platform_application_attributes(&req).unwrap();

        // Delete
        let req = sns_request(
            "DeletePlatformApplication",
            vec![("PlatformApplicationArn", &arn)],
        );
        svc.delete_platform_application(&req).unwrap();
    }

    // ── Subscription filter policy ──

    #[test]
    fn set_subscription_filter_policy() {
        let (svc, _) = make_sns();
        let req = sns_request("CreateTopic", vec![("Name", "filter-t")]);
        let resp = svc.create_topic(&req).unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        let arn_start = body.find("<TopicArn>").unwrap() + 10;
        let arn_end = body.find("</TopicArn>").unwrap();
        let arn = body[arn_start..arn_end].to_string();

        let req = sns_request(
            "Subscribe",
            vec![
                ("TopicArn", &arn),
                ("Protocol", "sqs"),
                ("Endpoint", "arn:aws:sqs:us-east-1:123456789012:q"),
                ("ReturnSubscriptionArn", "true"),
            ],
        );
        let resp = svc.subscribe(&req).unwrap();
        let body = std::str::from_utf8(resp.body.expect_bytes()).unwrap();
        let sub_arn_start = body.find("<SubscriptionArn>").unwrap() + 17;
        let sub_arn_end = body.find("</SubscriptionArn>").unwrap();
        let sub_arn = body[sub_arn_start..sub_arn_end].to_string();

        let req = sns_request(
            "SetSubscriptionAttributes",
            vec![
                ("SubscriptionArn", &sub_arn),
                ("AttributeName", "FilterPolicy"),
                ("AttributeValue", r#"{"color":["blue"]}"#),
            ],
        );
        svc.set_subscription_attributes(&req).unwrap();
    }

    // ── publish error branches ──

    #[test]
    fn publish_missing_message_errors() {
        let (svc, _) = make_sns();
        svc.create_topic(&sns_request("CreateTopic", vec![("Name", "t")]))
            .unwrap();
        let req = sns_request(
            "Publish",
            vec![("TopicArn", "arn:aws:sns:us-east-1:123456789012:t")],
        );
        assert!(svc.publish(&req).is_err());
    }

    #[test]
    fn publish_message_too_long_errors() {
        let (svc, _) = make_sns();
        svc.create_topic(&sns_request("CreateTopic", vec![("Name", "t")]))
            .unwrap();
        let big = "x".repeat(262145);
        let req = sns_request(
            "Publish",
            vec![
                ("TopicArn", "arn:aws:sns:us-east-1:123456789012:t"),
                ("Message", &big),
            ],
        );
        assert!(svc.publish(&req).is_err());
    }

    #[test]
    fn publish_message_structure_invalid_json_errors() {
        let (svc, _) = make_sns();
        svc.create_topic(&sns_request("CreateTopic", vec![("Name", "t")]))
            .unwrap();
        let req = sns_request(
            "Publish",
            vec![
                ("TopicArn", "arn:aws:sns:us-east-1:123456789012:t"),
                ("Message", "not json"),
                ("MessageStructure", "json"),
            ],
        );
        assert!(svc.publish(&req).is_err());
    }

    #[test]
    fn publish_message_structure_json_missing_default_errors() {
        let (svc, _) = make_sns();
        svc.create_topic(&sns_request("CreateTopic", vec![("Name", "t")]))
            .unwrap();
        let req = sns_request(
            "Publish",
            vec![
                ("TopicArn", "arn:aws:sns:us-east-1:123456789012:t"),
                ("Message", r#"{"email":"only"}"#),
                ("MessageStructure", "json"),
            ],
        );
        assert!(svc.publish(&req).is_err());
    }

    #[test]
    fn publish_message_structure_json_uses_protocol_specific() {
        let (svc, _) = make_sns();
        let r = svc
            .create_topic(&sns_request("CreateTopic", vec![("Name", "struc")]))
            .unwrap();
        let body = String::from_utf8(r.body.expect_bytes().to_vec()).unwrap();
        let arn_start = body.find("<TopicArn>").unwrap() + 10;
        let arn_end = body.find("</TopicArn>").unwrap();
        let arn = body[arn_start..arn_end].to_string();

        let req = sns_request(
            "Publish",
            vec![
                ("TopicArn", &arn),
                ("Message", r#"{"default":"hi","sqs":"for sqs"}"#),
                ("MessageStructure", "json"),
            ],
        );
        svc.publish(&req).unwrap();
    }

    #[test]
    fn publish_non_fifo_with_dedup_id_errors() {
        let (svc, _) = make_sns();
        svc.create_topic(&sns_request("CreateTopic", vec![("Name", "s")]))
            .unwrap();
        let req = sns_request(
            "Publish",
            vec![
                ("TopicArn", "arn:aws:sns:us-east-1:123456789012:s"),
                ("Message", "hi"),
                ("MessageDeduplicationId", "d1"),
            ],
        );
        assert!(svc.publish(&req).is_err());
    }

    #[test]
    fn publish_fifo_without_dedup_errors() {
        let (svc, _) = make_sns();
        svc.create_topic(&sns_request(
            "CreateTopic",
            vec![
                ("Name", "ff.fifo"),
                ("Attributes.entry.1.key", "FifoTopic"),
                ("Attributes.entry.1.value", "true"),
            ],
        ))
        .unwrap();
        let req = sns_request(
            "Publish",
            vec![
                ("TopicArn", "arn:aws:sns:us-east-1:123456789012:ff.fifo"),
                ("Message", "m"),
                ("MessageGroupId", "g1"),
            ],
        );
        assert!(svc.publish(&req).is_err());
    }

    #[test]
    fn publish_fifo_with_content_based_dedup_works() {
        let (svc, _) = make_sns();
        svc.create_topic(&sns_request(
            "CreateTopic",
            vec![
                ("Name", "cb.fifo"),
                ("Attributes.entry.1.key", "FifoTopic"),
                ("Attributes.entry.1.value", "true"),
                ("Attributes.entry.2.key", "ContentBasedDeduplication"),
                ("Attributes.entry.2.value", "true"),
            ],
        ))
        .unwrap();
        let req = sns_request(
            "Publish",
            vec![
                ("TopicArn", "arn:aws:sns:us-east-1:123456789012:cb.fifo"),
                ("Message", "m"),
                ("MessageGroupId", "g1"),
            ],
        );
        svc.publish(&req).unwrap();
    }

    // ── platform endpoint publish/delete ──

    #[test]
    fn publish_to_unknown_platform_endpoint_errors() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "Publish",
            vec![
                (
                    "TargetArn",
                    "arn:aws:sns:us-east-1:123456789012:endpoint/GCM/app/abc",
                ),
                ("Message", "hi"),
            ],
        );
        assert!(svc.publish(&req).is_err());
    }

    #[test]
    fn delete_endpoint_unknown_is_idempotent() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "DeleteEndpoint",
            vec![(
                "EndpointArn",
                "arn:aws:sns:us-east-1:123456789012:endpoint/GCM/app/ghost",
            )],
        );
        svc.delete_endpoint(&req).unwrap();
    }

    #[test]
    fn delete_platform_application_unknown_is_ok() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "DeletePlatformApplication",
            vec![(
                "PlatformApplicationArn",
                "arn:aws:sns:us-east-1:123456789012:app/GCM/ghost",
            )],
        );
        svc.delete_platform_application(&req).unwrap();
    }

    #[test]
    fn set_endpoint_attributes_unknown_errors() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "SetEndpointAttributes",
            vec![
                (
                    "EndpointArn",
                    "arn:aws:sns:us-east-1:123456789012:endpoint/GCM/app/missing",
                ),
                ("Attributes.entry.1.key", "Enabled"),
                ("Attributes.entry.1.value", "false"),
            ],
        );
        assert!(svc.set_endpoint_attributes(&req).is_err());
    }

    // ── SMS attributes ──

    #[test]
    fn set_sms_attributes_stores_value() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "SetSMSAttributes",
            vec![
                ("attributes.entry.1.key", "DefaultSenderID"),
                ("attributes.entry.1.value", "MyCorp"),
            ],
        );
        svc.set_sms_attributes(&req).unwrap();
        let req = sns_request("GetSMSAttributes", vec![]);
        let resp = svc.get_sms_attributes(&req).unwrap();
        let body = String::from_utf8(resp.body.expect_bytes().to_vec()).unwrap();
        assert!(body.contains("MyCorp"));
    }

    #[test]
    fn opt_in_phone_number_and_check() {
        let (svc, _) = make_sns();
        let _ = svc.check_if_phone_number_is_opted_out(&sns_request(
            "CheckIfPhoneNumberIsOptedOut",
            vec![("phoneNumber", "+15555555555")],
        ));
        let _ = svc.opt_in_phone_number(&sns_request(
            "OptInPhoneNumber",
            vec![("phoneNumber", "+15555555555")],
        ));
        svc.list_phone_numbers_opted_out(&sns_request("ListPhoneNumbersOptedOut", vec![]))
            .unwrap();
    }

    // ── subscription attribute filter policy validation ──

    #[test]
    fn set_subscription_attributes_raw_message_delivery() {
        let (svc, _) = make_sns();
        let r = svc
            .create_topic(&sns_request("CreateTopic", vec![("Name", "rmd")]))
            .unwrap();
        let body = String::from_utf8(r.body.expect_bytes().to_vec()).unwrap();
        let arn_start = body.find("<TopicArn>").unwrap() + 10;
        let arn_end = body.find("</TopicArn>").unwrap();
        let arn = body[arn_start..arn_end].to_string();

        let req = sns_request(
            "Subscribe",
            vec![
                ("TopicArn", &arn),
                ("Protocol", "sqs"),
                ("Endpoint", "arn:aws:sqs:us-east-1:123456789012:q"),
                ("ReturnSubscriptionArn", "true"),
            ],
        );
        let r = svc.subscribe(&req).unwrap();
        let body = String::from_utf8(r.body.expect_bytes().to_vec()).unwrap();
        let sub_arn = body[body.find("<SubscriptionArn>").unwrap() + 17
            ..body.find("</SubscriptionArn>").unwrap()]
            .to_string();

        let req = sns_request(
            "SetSubscriptionAttributes",
            vec![
                ("SubscriptionArn", &sub_arn),
                ("AttributeName", "RawMessageDelivery"),
                ("AttributeValue", "true"),
            ],
        );
        svc.set_subscription_attributes(&req).unwrap();
    }

    // ── list topics pagination ──

    #[test]
    fn list_topics_pagination_token() {
        let (svc, _) = make_sns();
        for i in 0..120 {
            let name = format!("t{i}");
            svc.create_topic(&sns_request("CreateTopic", vec![("Name", &name)]))
                .unwrap();
        }
        let req = sns_request("ListTopics", vec![]);
        let resp = svc.list_topics(&req).unwrap();
        let body = String::from_utf8(resp.body.expect_bytes().to_vec()).unwrap();
        assert!(body.contains("<NextToken>"));
    }

    // ── invalid topic name branches ──

    #[test]
    fn create_topic_empty_name_errors() {
        let (svc, _) = make_sns();
        assert!(svc
            .create_topic(&sns_request("CreateTopic", vec![("Name", "")]))
            .is_err());
    }

    #[test]
    fn create_topic_too_long_name_errors() {
        let (svc, _) = make_sns();
        let name = "x".repeat(257);
        assert!(svc
            .create_topic(&sns_request("CreateTopic", vec![("Name", &name)]))
            .is_err());
    }

    #[test]
    fn create_topic_fifo_without_suffix_errors() {
        let (svc, _) = make_sns();
        assert!(svc
            .create_topic(&sns_request(
                "CreateTopic",
                vec![
                    ("Name", "plain"),
                    ("Attributes.entry.1.key", "FifoTopic"),
                    ("Attributes.entry.1.value", "true"),
                ]
            ))
            .is_err());
    }

    #[test]
    fn create_topic_non_fifo_with_fifo_suffix_errors() {
        let (svc, _) = make_sns();
        assert!(svc
            .create_topic(&sns_request("CreateTopic", vec![("Name", "bad.fifo")]))
            .is_err());
    }

    // ── subscribe protocol validation ──

    #[test]
    fn subscribe_missing_protocol_errors() {
        let (svc, _) = make_sns();
        svc.create_topic(&sns_request("CreateTopic", vec![("Name", "t")]))
            .unwrap();
        let req = sns_request(
            "Subscribe",
            vec![("TopicArn", "arn:aws:sns:us-east-1:123456789012:t")],
        );
        assert!(svc.subscribe(&req).is_err());
    }

    // ── get_topic_attributes wrong region ──

    #[test]
    fn get_topic_attributes_returns_policy() {
        let (svc, _) = make_sns();
        svc.create_topic(&sns_request("CreateTopic", vec![("Name", "pol")]))
            .unwrap();
        let req = sns_request(
            "GetTopicAttributes",
            vec![("TopicArn", "arn:aws:sns:us-east-1:123456789012:pol")],
        );
        let resp = svc.get_topic_attributes(&req).unwrap();
        let body = String::from_utf8(resp.body.expect_bytes().to_vec()).unwrap();
        assert!(body.contains("Policy"));
    }

    // ── PublishBatch error paths ──

    #[test]
    fn publish_batch_missing_topic_errors() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "PublishBatch",
            vec![
                ("PublishBatchRequestEntries.member.1.Id", "e1"),
                ("PublishBatchRequestEntries.member.1.Message", "hi"),
            ],
        );
        assert!(svc.publish_batch(&req).is_err());
    }

    #[test]
    fn subscribe_missing_topic_arn_errors() {
        let (svc, _) = make_sns();
        let req = sns_request("Subscribe", vec![("Protocol", "sqs")]);
        assert!(svc.subscribe(&req).is_err());
    }

    #[test]
    fn unsubscribe_missing_arn_errors() {
        let (svc, _) = make_sns();
        let req = sns_request("Unsubscribe", vec![]);
        assert!(svc.unsubscribe(&req).is_err());
    }

    #[test]
    fn get_subscription_attributes_missing_arn_errors() {
        let (svc, _) = make_sns();
        let req = sns_request("GetSubscriptionAttributes", vec![]);
        assert!(svc.get_subscription_attributes(&req).is_err());
    }

    #[test]
    fn set_subscription_attributes_missing_arn_errors() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "SetSubscriptionAttributes",
            vec![("AttributeName", "x"), ("AttributeValue", "y")],
        );
        assert!(svc.set_subscription_attributes(&req).is_err());
    }

    #[test]
    fn set_topic_attributes_missing_arn_errors() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "SetTopicAttributes",
            vec![("AttributeName", "DisplayName"), ("AttributeValue", "x")],
        );
        assert!(svc.set_topic_attributes(&req).is_err());
    }

    #[test]
    fn list_tags_missing_resource_arn_errors() {
        let (svc, _) = make_sns();
        let req = sns_request("ListTagsForResource", vec![]);
        assert!(svc.list_tags_for_resource(&req).is_err());
    }

    #[test]
    fn tag_resource_missing_arn_errors() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "TagResource",
            vec![("Tags.member.1.Key", "k"), ("Tags.member.1.Value", "v")],
        );
        assert!(svc.tag_resource(&req).is_err());
    }

    #[test]
    fn untag_resource_missing_arn_errors() {
        let (svc, _) = make_sns();
        let req = sns_request("UntagResource", vec![("TagKeys.member.1", "k")]);
        assert!(svc.untag_resource(&req).is_err());
    }

    #[test]
    fn add_permission_missing_topic_arn_errors() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "AddPermission",
            vec![("Label", "l"), ("AWSAccountId.member.1", "123")],
        );
        assert!(svc.add_permission(&req).is_err());
    }

    #[test]
    fn remove_permission_missing_topic_errors() {
        let (svc, _) = make_sns();
        let req = sns_request("RemovePermission", vec![("Label", "l")]);
        assert!(svc.remove_permission(&req).is_err());
    }

    #[test]
    fn create_platform_endpoint_missing_app_arn_errors() {
        let (svc, _) = make_sns();
        let req = sns_request("CreatePlatformEndpoint", vec![("Token", "t")]);
        assert!(svc.create_platform_endpoint(&req).is_err());
    }

    #[test]
    fn set_platform_application_attributes_unknown_app_errors() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "SetPlatformApplicationAttributes",
            vec![
                (
                    "PlatformApplicationArn",
                    "arn:aws:sns:us-east-1:123456789012:app/GCM/ghost",
                ),
                ("Attributes.entry.1.key", "PlatformCredential"),
                ("Attributes.entry.1.value", "x"),
            ],
        );
        assert!(svc.set_platform_application_attributes(&req).is_err());
    }

    #[test]
    fn delete_topic_missing_arn_errors() {
        let (svc, _) = make_sns();
        let req = sns_request("DeleteTopic", vec![]);
        assert!(svc.delete_topic(&req).is_err());
    }

    #[test]
    fn get_topic_attributes_missing_arn_errors() {
        let (svc, _) = make_sns();
        let req = sns_request("GetTopicAttributes", vec![]);
        assert!(svc.get_topic_attributes(&req).is_err());
    }

    #[test]
    fn publish_message_with_subject() {
        let (svc, _) = make_sns();
        svc.create_topic(&sns_request("CreateTopic", vec![("Name", "subj")]))
            .unwrap();
        let req = sns_request(
            "Publish",
            vec![
                ("TopicArn", "arn:aws:sns:us-east-1:123456789012:subj"),
                ("Message", "hello"),
                ("Subject", "Greeting"),
            ],
        );
        svc.publish(&req).unwrap();
    }

    #[test]
    fn confirm_subscription_missing_token_errors() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "ConfirmSubscription",
            vec![("TopicArn", "arn:aws:sns:us-east-1:123456789012:t")],
        );
        assert!(svc.confirm_subscription(&req).is_err());
    }

    #[test]
    fn confirm_subscription_missing_topic_errors() {
        let (svc, _) = make_sns();
        let req = sns_request("ConfirmSubscription", vec![("Token", "tok")]);
        assert!(svc.confirm_subscription(&req).is_err());
    }

    #[test]
    fn list_subscriptions_by_topic_missing_arn_errors() {
        let (svc, _) = make_sns();
        let req = sns_request("ListSubscriptionsByTopic", vec![]);
        assert!(svc.list_subscriptions_by_topic(&req).is_err());
    }

    #[test]
    fn create_platform_application_missing_name_errors() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "CreatePlatformApplication",
            vec![
                ("Platform", "GCM"),
                ("Attributes.entry.1.key", "PlatformCredential"),
                ("Attributes.entry.1.value", "creds"),
            ],
        );
        assert!(svc.create_platform_application(&req).is_err());
    }

    #[test]
    fn create_platform_application_missing_platform_errors() {
        let (svc, _) = make_sns();
        let req = sns_request("CreatePlatformApplication", vec![("Name", "a")]);
        assert!(svc.create_platform_application(&req).is_err());
    }

    #[test]
    fn delete_endpoint_missing_arn_errors() {
        let (svc, _) = make_sns();
        let req = sns_request("DeleteEndpoint", vec![]);
        assert!(svc.delete_endpoint(&req).is_err());
    }

    #[test]
    fn get_endpoint_attributes_missing_arn_errors() {
        let (svc, _) = make_sns();
        let req = sns_request("GetEndpointAttributes", vec![]);
        assert!(svc.get_endpoint_attributes(&req).is_err());
    }

    #[test]
    fn list_endpoints_by_app_missing_arn_errors() {
        let (svc, _) = make_sns();
        let req = sns_request("ListEndpointsByPlatformApplication", vec![]);
        assert!(svc.list_endpoints_by_platform_application(&req).is_err());
    }

    #[test]
    fn check_phone_opted_out_missing_number_errors() {
        let (svc, _) = make_sns();
        let req = sns_request("CheckIfPhoneNumberIsOptedOut", vec![]);
        assert!(svc.check_if_phone_number_is_opted_out(&req).is_err());
    }

    #[test]
    fn opt_in_phone_missing_number_errors() {
        let (svc, _) = make_sns();
        let req = sns_request("OptInPhoneNumber", vec![]);
        assert!(svc.opt_in_phone_number(&req).is_err());
    }

    // ── SMS sandbox / data protection coverage ──

    #[test]
    fn validate_e164_rejects_short_numbers() {
        assert!(validate_e164("+1").is_err());
        assert!(validate_e164("+12").is_err());
        assert!(validate_e164("+123").is_err());
        assert!(validate_e164("+1234").is_ok());
    }

    #[test]
    fn validate_e164_rejects_too_long_or_non_digit() {
        assert!(validate_e164("+1234567890123456").is_err()); // 16 digits
        assert!(validate_e164("+1abc4567").is_err());
        assert!(validate_e164("12345").is_err()); // missing +
    }

    #[test]
    fn is_valid_sandbox_language_round_trip() {
        for code in SUPPORTED_SANDBOX_LANGUAGES {
            assert!(is_valid_sandbox_language(code), "{code}");
        }
        assert!(!is_valid_sandbox_language("xx-XX"));
        assert!(!is_valid_sandbox_language(""));
    }

    #[test]
    fn create_sms_sandbox_phone_number_rejects_invalid_phone() {
        let (svc, _) = make_sns();
        let req = sns_request("CreateSMSSandboxPhoneNumber", vec![("PhoneNumber", "+1")]);
        let err = match svc.create_sms_sandbox_phone_number(&req) {
            Err(e) => e,
            Ok(_) => panic!("expected err"),
        };
        assert_eq!(err.code(), "InvalidParameter");
    }

    #[test]
    fn create_sms_sandbox_phone_number_rejects_invalid_language() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "CreateSMSSandboxPhoneNumber",
            vec![("PhoneNumber", "+15551234567"), ("LanguageCode", "xx-YY")],
        );
        let err = match svc.create_sms_sandbox_phone_number(&req) {
            Err(e) => e,
            Ok(_) => panic!("expected err"),
        };
        assert_eq!(err.code(), "InvalidParameter");
    }

    #[test]
    fn create_sms_sandbox_phone_number_rejects_duplicate() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "CreateSMSSandboxPhoneNumber",
            vec![("PhoneNumber", "+15551234500")],
        );
        svc.create_sms_sandbox_phone_number(&req).unwrap();
        let err = match svc.create_sms_sandbox_phone_number(&req) {
            Err(e) => e,
            Ok(_) => panic!("expected err"),
        };
        assert_eq!(err.code(), "OptedOutException");
    }

    #[test]
    fn delete_sms_sandbox_phone_number_unknown_errors() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "DeleteSMSSandboxPhoneNumber",
            vec![("PhoneNumber", "+15551234599")],
        );
        let err = match svc.delete_sms_sandbox_phone_number(&req) {
            Err(e) => e,
            Ok(_) => panic!("expected err"),
        };
        assert_eq!(err.code(), "ResourceNotFound");
    }

    #[test]
    fn verify_sms_sandbox_phone_number_wrong_otp_errors() {
        let (svc, _) = make_sns();
        let create = sns_request(
            "CreateSMSSandboxPhoneNumber",
            vec![("PhoneNumber", "+15551234511")],
        );
        svc.create_sms_sandbox_phone_number(&create).unwrap();
        let verify = sns_request(
            "VerifySMSSandboxPhoneNumber",
            vec![
                ("PhoneNumber", "+15551234511"),
                ("OneTimePassword", "999999"),
            ],
        );
        let err = match svc.verify_sms_sandbox_phone_number(&verify) {
            Err(e) => e,
            Ok(_) => panic!("expected err"),
        };
        assert_eq!(err.code(), "VerificationException");
    }

    #[test]
    fn verify_sms_sandbox_phone_number_unknown_errors() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "VerifySMSSandboxPhoneNumber",
            vec![
                ("PhoneNumber", "+15550009999"),
                ("OneTimePassword", "000000"),
            ],
        );
        let err = match svc.verify_sms_sandbox_phone_number(&req) {
            Err(e) => e,
            Ok(_) => panic!("expected err"),
        };
        assert_eq!(err.code(), "ResourceNotFound");
    }

    #[test]
    fn list_sms_sandbox_phone_numbers_returns_entries() {
        let (svc, _) = make_sns();
        let create = sns_request(
            "CreateSMSSandboxPhoneNumber",
            vec![("PhoneNumber", "+15551239876")],
        );
        svc.create_sms_sandbox_phone_number(&create).unwrap();
        let list = sns_request("ListSMSSandboxPhoneNumbers", vec![]);
        let resp = svc.list_sms_sandbox_phone_numbers(&list).unwrap();
        assert!(resp.status.is_success());
    }

    #[test]
    fn get_sms_sandbox_account_status_starts_in_sandbox() {
        let (svc, _) = make_sns();
        let req = sns_request("GetSMSSandboxAccountStatus", vec![]);
        let resp = svc.get_sms_sandbox_account_status(&req).unwrap();
        // raw XML body — eyeball IsInSandbox=true.
        let body = String::from_utf8(resp.body.expect_bytes().to_vec()).unwrap();
        assert!(body.contains("<IsInSandbox>true</IsInSandbox>"), "{body}");
    }

    #[test]
    fn list_origination_numbers_seeds_default() {
        let (svc, _) = make_sns();
        let req = sns_request("ListOriginationNumbers", vec![]);
        let resp = svc.list_origination_numbers(&req).unwrap();
        let body = String::from_utf8(resp.body.expect_bytes().to_vec()).unwrap();
        assert!(body.contains("+18005550100"), "{body}");
    }

    #[test]
    fn put_data_protection_policy_requires_topic() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "PutDataProtectionPolicy",
            vec![
                ("ResourceArn", "arn:aws:sns:us-east-1:123456789012:no-topic"),
                ("DataProtectionPolicy", "{}"),
            ],
        );
        let err = match svc.put_data_protection_policy(&req) {
            Err(e) => e,
            Ok(_) => panic!("expected err"),
        };
        assert_eq!(err.code(), "NotFound");
    }

    #[test]
    fn put_data_protection_policy_rejects_invalid_json() {
        let (svc, _) = make_sns();
        // First create a topic.
        let create = sns_request("CreateTopic", vec![("Name", "dpp-topic")]);
        svc.create_topic(&create).unwrap();
        let arn = "arn:aws:sns:us-east-1:123456789012:dpp-topic";
        let req = sns_request(
            "PutDataProtectionPolicy",
            vec![("ResourceArn", arn), ("DataProtectionPolicy", "not-json")],
        );
        let err = match svc.put_data_protection_policy(&req) {
            Err(e) => e,
            Ok(_) => panic!("expected err"),
        };
        assert_eq!(err.code(), "InvalidParameter");
    }

    #[test]
    fn put_then_get_data_protection_policy_round_trips() {
        let (svc, _) = make_sns();
        let create = sns_request("CreateTopic", vec![("Name", "dpp-topic2")]);
        svc.create_topic(&create).unwrap();
        let arn = "arn:aws:sns:us-east-1:123456789012:dpp-topic2";
        let req = sns_request(
            "PutDataProtectionPolicy",
            vec![
                ("ResourceArn", arn),
                ("DataProtectionPolicy", r#"{"Name":"p"}"#),
            ],
        );
        svc.put_data_protection_policy(&req).unwrap();
        let get = sns_request("GetDataProtectionPolicy", vec![("ResourceArn", arn)]);
        let resp = svc.get_data_protection_policy(&get).unwrap();
        let body = String::from_utf8(resp.body.expect_bytes().to_vec()).unwrap();
        assert!(body.contains("&quot;Name&quot;:&quot;p&quot;"), "{body}");
    }

    #[test]
    fn get_data_protection_policy_unknown_topic_errors() {
        let (svc, _) = make_sns();
        let req = sns_request(
            "GetDataProtectionPolicy",
            vec![("ResourceArn", "arn:aws:sns:us-east-1:123456789012:nope")],
        );
        let err = match svc.get_data_protection_policy(&req) {
            Err(e) => e,
            Ok(_) => panic!("expected err"),
        };
        assert_eq!(err.code(), "NotFound");
    }
}
