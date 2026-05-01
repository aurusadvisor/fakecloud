use chrono::Utc;
use parking_lot::RwLock;
use std::collections::BTreeMap;
use std::sync::Arc;
use uuid::Uuid;

use fakecloud_cloudwatch::{AlarmState, MetricAlarm, SharedCloudWatchState};
use fakecloud_core::delivery::DeliveryBus;
use fakecloud_dynamodb::{
    AttributeDefinition, DynamoTable, KeySchemaElement, OnDemandThroughput, ProvisionedThroughput,
    SharedDynamoDbState,
};
use fakecloud_ecr::{Repository, SharedEcrState};
use fakecloud_eventbridge::{EventRule, SharedEventBridgeState};
use fakecloud_iam::{IamPolicy, IamRole, PolicyVersion, SharedIamState};
use fakecloud_kinesis::{build_stream_shards, KinesisConsumer, KinesisStream, SharedKinesisState};
use fakecloud_kms::{KmsAlias, KmsKey, SharedKmsState};
use fakecloud_lambda::SharedLambdaState;
use fakecloud_logs::{
    LogStream, MetricFilter, MetricTransformation, SharedLogsState, SubscriptionFilter,
};
use fakecloud_s3::{S3Bucket, SharedS3State};
use fakecloud_secretsmanager::{Secret, SecretVersion, SharedSecretsManagerState};
use fakecloud_sns::{SharedSnsState, SnsSubscription, SnsTopic};
use fakecloud_sqs::{SharedSqsState, SqsQueue};
use fakecloud_ssm::{SharedSsmState, SsmParameter};

use crate::state::StackResource;
use crate::template::ResourceDefinition;

/// `LogGroupName` properties on Logs CFN resources may carry either a
/// log-group ARN (when they come from `{Ref: SomeLogGroup}` in the same
/// template) or a plain name. Extract the name in either case.
fn parse_log_group_name(input: &str) -> String {
    if let Some(rest) = input.strip_prefix("arn:aws:logs:") {
        if let Some(after) = rest.split(":log-group:").nth(1) {
            // ARN ends with `:*`; trim it if present.
            return after.trim_end_matches(":*").to_string();
        }
    }
    input.to_string()
}

/// What a resource provisioner returns. The physical id is what `Ref` resolves
/// to; `attributes` is what `Fn::GetAtt` resolves to (per-resource-type).
pub struct ProvisionResult {
    pub physical_id: String,
    pub attributes: BTreeMap<String, String>,
}

impl ProvisionResult {
    pub fn new(physical_id: impl Into<String>) -> Self {
        Self {
            physical_id: physical_id.into(),
            attributes: BTreeMap::new(),
        }
    }

    pub fn with(mut self, key: &str, value: impl Into<String>) -> Self {
        self.attributes.insert(key.to_string(), value.into());
        self
    }
}

/// Holds references to all service states so CloudFormation can provision resources.
pub struct ResourceProvisioner {
    pub sqs_state: SharedSqsState,
    pub sns_state: SharedSnsState,
    pub ssm_state: SharedSsmState,
    pub iam_state: SharedIamState,
    pub s3_state: SharedS3State,
    pub eventbridge_state: SharedEventBridgeState,
    pub dynamodb_state: SharedDynamoDbState,
    pub logs_state: SharedLogsState,
    pub lambda_state: SharedLambdaState,
    pub secretsmanager_state: SharedSecretsManagerState,
    pub kinesis_state: SharedKinesisState,
    pub kms_state: SharedKmsState,
    pub ecr_state: SharedEcrState,
    pub cloudwatch_state: SharedCloudWatchState,
    pub delivery: Arc<DeliveryBus>,
    pub account_id: String,
    pub region: String,
    pub stack_id: String,
}

impl ResourceProvisioner {
    /// Create a resource and return the StackResource with physical ID.
    pub fn create_resource(&self, resource: &ResourceDefinition) -> Result<StackResource, String> {
        let result = match resource.resource_type.as_str() {
            "AWS::SQS::Queue" => self.create_sqs_queue(resource),
            "AWS::SNS::Topic" => self.create_sns_topic(resource),
            "AWS::SNS::Subscription" => self.create_sns_subscription(resource),
            "AWS::SSM::Parameter" => self.create_ssm_parameter(resource),
            "AWS::IAM::Role" => self.create_iam_role(resource),
            "AWS::IAM::Policy" => self.create_iam_policy(resource),
            "AWS::S3::Bucket" => self.create_s3_bucket(resource),
            "AWS::Events::Rule" => self.create_eventbridge_rule(resource),
            "AWS::DynamoDB::Table" => self.create_dynamodb_table(resource),
            "AWS::Logs::LogGroup" => self.create_log_group(resource),
            "AWS::Logs::LogStream" => self.create_log_stream(resource),
            "AWS::Logs::MetricFilter" => self.create_metric_filter(resource),
            "AWS::Logs::SubscriptionFilter" => self.create_subscription_filter(resource),
            "AWS::Lambda::Function" => self.create_lambda_function(resource),
            "AWS::SecretsManager::Secret" => self.create_secrets_manager_secret(resource),
            "AWS::Kinesis::Stream" => self.create_kinesis_stream(resource),
            "AWS::Kinesis::StreamConsumer" => self.create_kinesis_stream_consumer(resource),
            "AWS::KMS::Key" => self.create_kms_key(resource),
            "AWS::KMS::Alias" => self.create_kms_alias(resource),
            "AWS::ECR::Repository" => self.create_ecr_repository(resource),
            "AWS::CloudWatch::Alarm" => self.create_cloudwatch_alarm(resource),
            t if t.starts_with("Custom::") || t == "AWS::CloudFormation::CustomResource" => self
                .create_custom_resource(resource)
                .map(ProvisionResult::new),
            other => Err(format!("Unsupported resource type: {other}")),
        };

        let is_custom = resource.resource_type.starts_with("Custom::")
            || resource.resource_type == "AWS::CloudFormation::CustomResource";
        let service_token = if is_custom {
            resource
                .properties
                .get("ServiceToken")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
        } else {
            None
        };

        result.map(|res| StackResource {
            logical_id: resource.logical_id.clone(),
            physical_id: res.physical_id,
            resource_type: resource.resource_type.clone(),
            status: "CREATE_COMPLETE".to_string(),
            service_token,
            attributes: res.attributes,
        })
    }

    /// Delete a previously created resource.
    pub fn delete_resource(&self, resource: &StackResource) -> Result<(), String> {
        match resource.resource_type.as_str() {
            "AWS::SQS::Queue" => self.delete_sqs_queue(&resource.physical_id),
            "AWS::SNS::Topic" => self.delete_sns_topic(&resource.physical_id),
            "AWS::SNS::Subscription" => self.delete_sns_subscription(&resource.physical_id),
            "AWS::SSM::Parameter" => self.delete_ssm_parameter(&resource.physical_id),
            "AWS::IAM::Role" => self.delete_iam_role(&resource.physical_id),
            "AWS::IAM::Policy" => self.delete_iam_policy(&resource.physical_id),
            "AWS::S3::Bucket" => self.delete_s3_bucket(&resource.physical_id),
            "AWS::Events::Rule" => self.delete_eventbridge_rule(&resource.physical_id),
            "AWS::DynamoDB::Table" => self.delete_dynamodb_table(&resource.physical_id),
            "AWS::Logs::LogGroup" => self.delete_log_group(&resource.physical_id),
            "AWS::Logs::LogStream" => self.delete_log_stream(&resource.physical_id),
            "AWS::Logs::MetricFilter" => self.delete_metric_filter(&resource.physical_id),
            "AWS::Logs::SubscriptionFilter" => {
                self.delete_subscription_filter(&resource.physical_id)
            }
            "AWS::Lambda::Function" => self.delete_lambda_function(&resource.physical_id),
            "AWS::SecretsManager::Secret" => {
                self.delete_secrets_manager_secret(&resource.physical_id)
            }
            "AWS::Kinesis::Stream" => self.delete_kinesis_stream(&resource.physical_id),
            "AWS::Kinesis::StreamConsumer" => {
                self.delete_kinesis_stream_consumer(&resource.physical_id)
            }
            "AWS::KMS::Key" => self.delete_kms_key(&resource.physical_id),
            "AWS::KMS::Alias" => self.delete_kms_alias(&resource.physical_id),
            "AWS::ECR::Repository" => self.delete_ecr_repository(&resource.physical_id),
            "AWS::CloudWatch::Alarm" => self.delete_cloudwatch_alarm(&resource.physical_id),
            t if t.starts_with("Custom::") || t == "AWS::CloudFormation::CustomResource" => {
                self.delete_custom_resource(resource)
            }
            other => Err(format!("Unsupported resource type: {other}")),
        }
    }

    // --- SQS ---

    fn create_sqs_queue(&self, resource: &ResourceDefinition) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let queue_name = props
            .get("QueueName")
            .and_then(|v| v.as_str())
            .unwrap_or(&resource.logical_id);

        let mut __sqs_mas = self.sqs_state.write();
        let state = __sqs_mas.get_or_create(&self.account_id);
        let queue_url = format!("{}/{}/{}", state.endpoint, state.account_id, queue_name);
        let arn = format!(
            "arn:aws:sqs:{}:{}:{}",
            state.region, state.account_id, queue_name
        );

        let is_fifo = queue_name.ends_with(".fifo");
        let mut attributes = std::collections::BTreeMap::new();
        if let Some(obj) = props.as_object() {
            for (k, v) in obj {
                if k != "QueueName" {
                    if let Some(s) = v.as_str() {
                        attributes.insert(k.clone(), s.to_string());
                    } else if let Some(n) = v.as_i64() {
                        attributes.insert(k.clone(), n.to_string());
                    }
                }
            }
        }

        let queue = SqsQueue {
            queue_name: queue_name.to_string(),
            queue_url: queue_url.clone(),
            arn: arn.clone(),
            created_at: Utc::now(),
            messages: std::collections::VecDeque::new(),
            inflight: Vec::new(),
            attributes,
            is_fifo,
            dedup_cache: std::collections::BTreeMap::new(),
            redrive_policy: None,
            tags: std::collections::BTreeMap::new(),
            next_sequence_number: 0,
            permission_labels: Vec::new(),
            receipt_handle_map: std::collections::BTreeMap::new(),
        };

        state
            .name_to_url
            .insert(queue_name.to_string(), queue_url.clone());
        state.queues.insert(queue_url.clone(), queue);

        Ok(ProvisionResult::new(queue_url.clone())
            .with("Arn", arn)
            .with("QueueName", queue_name)
            .with("QueueUrl", queue_url))
    }

    fn delete_sqs_queue(&self, physical_id: &str) -> Result<(), String> {
        let mut __sqs_mas = self.sqs_state.write();
        let state = __sqs_mas.get_or_create(&self.account_id);
        if let Some(queue) = state.queues.remove(physical_id) {
            state.name_to_url.remove(&queue.queue_name);
        }
        Ok(())
    }

    // --- SNS ---

    fn create_sns_topic(&self, resource: &ResourceDefinition) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let topic_name = props
            .get("TopicName")
            .and_then(|v| v.as_str())
            .unwrap_or(&resource.logical_id);

        let mut __sns_mas = self.sns_state.write();
        let state = __sns_mas.get_or_create(&self.account_id);
        let topic_arn = format!(
            "arn:aws:sns:{}:{}:{}",
            state.region, state.account_id, topic_name
        );

        let topic = SnsTopic {
            topic_arn: topic_arn.clone(),
            name: topic_name.to_string(),
            attributes: BTreeMap::new(),
            tags: Vec::new(),
            is_fifo: topic_name.ends_with(".fifo"),
            created_at: Utc::now(),
            subscriptions_deleted: 0,
        };

        state.topics.insert(topic_arn.clone(), topic);
        Ok(ProvisionResult::new(topic_arn.clone())
            .with("TopicArn", topic_arn)
            .with("TopicName", topic_name))
    }

    fn delete_sns_topic(&self, physical_id: &str) -> Result<(), String> {
        let mut __sns_mas = self.sns_state.write();
        let state = __sns_mas.get_or_create(&self.account_id);
        state.topics.remove(physical_id);
        // Also remove subscriptions for this topic
        state
            .subscriptions
            .retain(|_, sub| sub.topic_arn != physical_id);
        Ok(())
    }

    // --- SNS Subscription ---

    fn create_sns_subscription(
        &self,
        resource: &ResourceDefinition,
    ) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let topic_arn = props
            .get("TopicArn")
            .and_then(|v| v.as_str())
            .ok_or("SNS Subscription requires TopicArn")?;
        let protocol = props
            .get("Protocol")
            .and_then(|v| v.as_str())
            .ok_or("SNS Subscription requires Protocol")?;
        let endpoint = props
            .get("Endpoint")
            .and_then(|v| v.as_str())
            .ok_or("SNS Subscription requires Endpoint")?;

        let mut __sns_mas = self.sns_state.write();
        let state = __sns_mas.get_or_create(&self.account_id);

        // Validate that the topic exists
        if !state.topics.contains_key(topic_arn) {
            return Err(format!("Topic ARN does not exist: {topic_arn}"));
        }

        let sub_arn = format!("{}:{}", topic_arn, Uuid::new_v4());

        let subscription = SnsSubscription {
            subscription_arn: sub_arn.clone(),
            topic_arn: topic_arn.to_string(),
            protocol: protocol.to_string(),
            endpoint: endpoint.to_string(),
            owner: state.account_id.clone(),
            attributes: BTreeMap::new(),
            confirmed: true,
            confirmation_token: None,
        };

        state.subscriptions.insert(sub_arn.clone(), subscription);
        Ok(ProvisionResult::new(sub_arn.clone()).with("Arn", sub_arn))
    }

    fn delete_sns_subscription(&self, physical_id: &str) -> Result<(), String> {
        let mut __sns_mas = self.sns_state.write();
        let state = __sns_mas.get_or_create(&self.account_id);
        state.subscriptions.remove(physical_id);
        Ok(())
    }

    // --- SSM ---

    fn create_ssm_parameter(
        &self,
        resource: &ResourceDefinition,
    ) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let name = props
            .get("Name")
            .and_then(|v| v.as_str())
            .ok_or("SSM Parameter requires Name")?;
        let value = props
            .get("Value")
            .and_then(|v| v.as_str())
            .ok_or("SSM Parameter requires Value")?;
        let param_type = props
            .get("Type")
            .and_then(|v| v.as_str())
            .unwrap_or("String");

        let mut accounts = self.ssm_state.write();
        let state = accounts.get_or_create(&self.account_id);
        let arn = format!(
            "arn:aws:ssm:{}:{}:parameter{}",
            self.region,
            self.account_id,
            if name.starts_with('/') {
                name.to_string()
            } else {
                format!("/{name}")
            }
        );

        let parameter = SsmParameter {
            name: name.to_string(),
            value: value.to_string(),
            param_type: param_type.to_string(),
            version: 1,
            arn: arn.clone(),
            last_modified: Utc::now(),
            history: Vec::new(),
            tags: BTreeMap::new(),
            labels: BTreeMap::new(),
            description: props
                .get("Description")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            allowed_pattern: None,
            key_id: None,
            data_type: "text".to_string(),
            tier: "Standard".to_string(),
            policies: None,
        };

        state.parameters.insert(name.to_string(), parameter);
        Ok(ProvisionResult::new(name)
            .with("Type", param_type)
            .with("Value", value))
    }

    fn delete_ssm_parameter(&self, physical_id: &str) -> Result<(), String> {
        let mut accounts = self.ssm_state.write();
        let state = accounts.get_or_create(&self.account_id);
        state.parameters.remove(physical_id);
        Ok(())
    }

    // --- IAM Role ---

    fn create_iam_role(&self, resource: &ResourceDefinition) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let role_name = props
            .get("RoleName")
            .and_then(|v| v.as_str())
            .unwrap_or(&resource.logical_id);

        let assume_role_policy = props
            .get("AssumeRolePolicyDocument")
            .map(|v| {
                if v.is_string() {
                    v.as_str().unwrap().to_string()
                } else {
                    serde_json::to_string(v).unwrap_or_default()
                }
            })
            .unwrap_or_default();

        let path = props.get("Path").and_then(|v| v.as_str()).unwrap_or("/");

        let mut accounts = self.iam_state.write();
        let state = accounts.get_or_create(&self.account_id);
        let role_id = format!(
            "FKIA{}",
            &Uuid::new_v4().to_string().replace('-', "").to_uppercase()[..16]
        );
        let arn = format!(
            "arn:aws:iam::{}:role{}{}",
            state.account_id,
            if path == "/" { "/" } else { path },
            role_name
        );

        let role = IamRole {
            role_name: role_name.to_string(),
            role_id: role_id.clone(),
            arn: arn.clone(),
            path: path.to_string(),
            assume_role_policy_document: assume_role_policy,
            created_at: Utc::now(),
            description: props
                .get("Description")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            max_session_duration: 3600,
            tags: Vec::new(),
            permissions_boundary: None,
        };

        state.roles.insert(role_name.to_string(), role);
        Ok(ProvisionResult::new(arn.clone())
            .with("Arn", arn)
            .with("RoleId", role_id))
    }

    fn delete_iam_role(&self, physical_id: &str) -> Result<(), String> {
        let mut accounts = self.iam_state.write();
        let state = accounts.get_or_create(&self.account_id);
        // physical_id is the ARN; find the role name
        let role_name = state
            .roles
            .iter()
            .find(|(_, r)| r.arn == physical_id)
            .map(|(name, _)| name.clone());
        if let Some(name) = role_name {
            state.roles.remove(&name);
            state.role_policies.remove(&name);
            state.role_inline_policies.remove(&name);
        }
        Ok(())
    }

    // --- IAM Policy ---

    fn create_iam_policy(&self, resource: &ResourceDefinition) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let policy_name = props
            .get("PolicyName")
            .and_then(|v| v.as_str())
            .unwrap_or(&resource.logical_id);

        let policy_document = props
            .get("PolicyDocument")
            .map(|v| {
                if v.is_string() {
                    v.as_str().unwrap().to_string()
                } else {
                    serde_json::to_string(v).unwrap_or_default()
                }
            })
            .unwrap_or_default();

        let path = props.get("Path").and_then(|v| v.as_str()).unwrap_or("/");

        let mut accounts = self.iam_state.write();
        let state = accounts.get_or_create(&self.account_id);
        let policy_id = format!(
            "FSIA{}",
            &Uuid::new_v4().to_string().replace('-', "").to_uppercase()[..16]
        );
        let arn = format!(
            "arn:aws:iam::{}:policy{}{}",
            state.account_id,
            if path == "/" { "/" } else { path },
            policy_name
        );

        let now = Utc::now();
        let policy = IamPolicy {
            policy_name: policy_name.to_string(),
            policy_id,
            arn: arn.clone(),
            path: path.to_string(),
            description: props
                .get("Description")
                .and_then(|v| v.as_str())
                .unwrap_or("")
                .to_string(),
            created_at: now,
            tags: Vec::new(),
            default_version_id: "v1".to_string(),
            versions: vec![PolicyVersion {
                version_id: "v1".to_string(),
                document: policy_document,
                is_default: true,
                created_at: now,
            }],
            next_version_num: 2,
            attachment_count: 0,
        };

        state.policies.insert(arn.clone(), policy);
        Ok(ProvisionResult::new(arn.clone()).with("Arn", arn))
    }

    fn delete_iam_policy(&self, physical_id: &str) -> Result<(), String> {
        let mut accounts = self.iam_state.write();
        let state = accounts.get_or_create(&self.account_id);
        state.policies.remove(physical_id);
        Ok(())
    }

    // --- S3 ---

    fn create_s3_bucket(&self, resource: &ResourceDefinition) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let bucket_name = props
            .get("BucketName")
            .and_then(|v| v.as_str())
            .unwrap_or(&resource.logical_id);

        let mut __s3_mas = self.s3_state.write();
        let state = __s3_mas.get_or_create(&self.account_id);
        let region = state.region.clone();
        let bucket = S3Bucket::new(bucket_name, &state.region, &state.account_id);
        state.buckets.insert(bucket_name.to_string(), bucket);

        let arn = format!("arn:aws:s3:::{bucket_name}");
        let domain_name = format!("{bucket_name}.s3.amazonaws.com");
        let regional_domain_name = format!("{bucket_name}.s3.{region}.amazonaws.com");
        let dual_stack_domain_name = format!("{bucket_name}.s3.dualstack.{region}.amazonaws.com");
        let website_url = format!("http://{bucket_name}.s3-website-{region}.amazonaws.com");
        Ok(ProvisionResult::new(bucket_name)
            .with("Arn", arn)
            .with("DomainName", domain_name)
            .with("RegionalDomainName", regional_domain_name)
            .with("DualStackDomainName", dual_stack_domain_name)
            .with("WebsiteURL", website_url))
    }

    fn delete_s3_bucket(&self, physical_id: &str) -> Result<(), String> {
        let mut __s3_mas = self.s3_state.write();
        let state = __s3_mas.get_or_create(&self.account_id);
        state.buckets.remove(physical_id);
        Ok(())
    }

    // --- EventBridge ---

    fn create_eventbridge_rule(
        &self,
        resource: &ResourceDefinition,
    ) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let rule_name = props
            .get("Name")
            .and_then(|v| v.as_str())
            .unwrap_or(&resource.logical_id);
        let event_bus_name = props
            .get("EventBusName")
            .and_then(|v| v.as_str())
            .unwrap_or("default");

        let mut eb_accounts = self.eventbridge_state.write();
        let state = eb_accounts.get_or_create(&self.account_id);

        // Validate that the event bus exists
        if !state.buses.contains_key(event_bus_name) {
            return Err(format!("Event bus does not exist: {event_bus_name}"));
        }

        let arn = if event_bus_name == "default" {
            format!(
                "arn:aws:events:{}:{}:rule/{}",
                state.region, state.account_id, rule_name
            )
        } else {
            format!(
                "arn:aws:events:{}:{}:rule/{}/{}",
                state.region, state.account_id, event_bus_name, rule_name
            )
        };

        let rule = EventRule {
            name: rule_name.to_string(),
            arn: arn.clone(),
            event_bus_name: event_bus_name.to_string(),
            event_pattern: props.get("EventPattern").map(|v| {
                if v.is_string() {
                    v.as_str().unwrap().to_string()
                } else {
                    serde_json::to_string(v).unwrap_or_default()
                }
            }),
            schedule_expression: props
                .get("ScheduleExpression")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            state: props
                .get("State")
                .and_then(|v| v.as_str())
                .unwrap_or("ENABLED")
                .to_string(),
            description: props
                .get("Description")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            role_arn: props
                .get("RoleArn")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string()),
            managed_by: None,
            created_by: None,
            targets: Vec::new(),
            tags: std::collections::BTreeMap::new(),
            last_fired: None,
        };

        state
            .rules
            .insert((event_bus_name.to_string(), rule_name.to_string()), rule);
        Ok(ProvisionResult::new(arn.clone()).with("Arn", arn))
    }

    fn delete_eventbridge_rule(&self, physical_id: &str) -> Result<(), String> {
        let mut eb_accounts = self.eventbridge_state.write();
        let state = eb_accounts.default_mut();
        // physical_id is the ARN; find the rule key
        let key = state
            .rules
            .iter()
            .find(|(_, r)| r.arn == physical_id)
            .map(|(k, _)| k.clone());
        if let Some(k) = key {
            state.rules.remove(&k);
        }
        Ok(())
    }

    // --- DynamoDB ---

    fn create_dynamodb_table(
        &self,
        resource: &ResourceDefinition,
    ) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let table_name = props
            .get("TableName")
            .and_then(|v| v.as_str())
            .unwrap_or(&resource.logical_id);

        let mut key_schema = Vec::new();
        if let Some(ks) = props.get("KeySchema").and_then(|v| v.as_array()) {
            for item in ks {
                let attr_name = item
                    .get("AttributeName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let key_type = item
                    .get("KeyType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("HASH")
                    .to_string();
                key_schema.push(KeySchemaElement {
                    attribute_name: attr_name,
                    key_type,
                });
            }
        }

        let mut attribute_definitions = Vec::new();
        if let Some(defs) = props.get("AttributeDefinitions").and_then(|v| v.as_array()) {
            for item in defs {
                let attr_name = item
                    .get("AttributeName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let attr_type = item
                    .get("AttributeType")
                    .and_then(|v| v.as_str())
                    .unwrap_or("S")
                    .to_string();
                attribute_definitions.push(AttributeDefinition {
                    attribute_name: attr_name,
                    attribute_type: attr_type,
                });
            }
        }

        let billing_mode = props
            .get("BillingMode")
            .and_then(|v| v.as_str())
            .unwrap_or("PAY_PER_REQUEST")
            .to_string();

        let provisioned_throughput = if billing_mode == "PROVISIONED" {
            if let Some(pt) = props.get("ProvisionedThroughput") {
                ProvisionedThroughput {
                    read_capacity_units: pt
                        .get("ReadCapacityUnits")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(5),
                    write_capacity_units: pt
                        .get("WriteCapacityUnits")
                        .and_then(|v| v.as_i64())
                        .unwrap_or(5),
                }
            } else {
                ProvisionedThroughput {
                    read_capacity_units: 5,
                    write_capacity_units: 5,
                }
            }
        } else {
            ProvisionedThroughput {
                read_capacity_units: 0,
                write_capacity_units: 0,
            }
        };

        // Parse StreamSpecification from CloudFormation properties
        let (stream_enabled, stream_view_type) =
            if let Some(stream_spec) = props.get("StreamSpecification") {
                let view_type = stream_spec
                    .get("StreamViewType")
                    .and_then(|v| v.as_str())
                    .map(|s| s.to_string());
                let enabled = stream_spec
                    .get("StreamEnabled")
                    .and_then(|v| v.as_bool().or_else(|| v.as_str().map(|s| s == "true")))
                    // If StreamViewType is set, treat streams as enabled even if StreamEnabled is missing
                    .unwrap_or(view_type.is_some());
                (enabled, view_type)
            } else {
                (false, None)
            };

        let deletion_protection_enabled = props
            .get("DeletionProtectionEnabled")
            .and_then(|v| v.as_bool().or_else(|| v.as_str().map(|s| s == "true")))
            .unwrap_or(false);

        let on_demand_throughput = props
            .get("OnDemandThroughput")
            .map(|odt| OnDemandThroughput {
                max_read_request_units: odt
                    .get("MaxReadRequestUnits")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(-1),
                max_write_request_units: odt
                    .get("MaxWriteRequestUnits")
                    .and_then(|v| v.as_i64())
                    .unwrap_or(-1),
            });

        let mut __ddb_mas = self.dynamodb_state.write();
        let state = __ddb_mas.get_or_create(&self.account_id);
        let arn = format!(
            "arn:aws:dynamodb:{}:{}:table/{}",
            state.region, state.account_id, table_name
        );

        let stream_arn = if stream_enabled {
            Some(format!(
                "{}/stream/{}",
                arn,
                Utc::now().format("%Y-%m-%dT%H:%M:%S.%3f")
            ))
        } else {
            None
        };
        let stream_arn_attr = stream_arn.clone();

        let table = DynamoTable {
            name: table_name.to_string(),
            arn: arn.clone(),
            table_id: Uuid::new_v4().to_string().replace('-', ""),
            key_schema,
            attribute_definitions,
            provisioned_throughput,
            items: Vec::new(),
            gsi: Vec::new(),
            lsi: Vec::new(),
            tags: BTreeMap::new(),
            created_at: Utc::now(),
            status: "ACTIVE".to_string(),
            item_count: 0,
            size_bytes: 0,
            billing_mode,
            ttl_attribute: None,
            ttl_enabled: false,
            resource_policy: None,
            pitr_enabled: false,
            kinesis_destinations: Vec::new(),
            contributor_insights_status: "DISABLED".to_string(),
            contributor_insights_counters: BTreeMap::new(),
            stream_enabled,
            stream_view_type,
            stream_arn,
            stream_records: Arc::new(RwLock::new(Vec::new())),
            sse_type: None,
            sse_kms_key_arn: None,
            deletion_protection_enabled,
            on_demand_throughput,
        };

        state.tables.insert(table_name.to_string(), table);
        let mut result = ProvisionResult::new(arn.clone()).with("Arn", arn);
        if let Some(stream_arn_value) = stream_arn_attr {
            result = result.with("StreamArn", stream_arn_value);
        }
        Ok(result)
    }

    fn delete_dynamodb_table(&self, physical_id: &str) -> Result<(), String> {
        let mut __ddb_mas = self.dynamodb_state.write();
        let state = __ddb_mas.get_or_create(&self.account_id);
        // physical_id is the ARN; find the table name
        let table_name = state
            .tables
            .iter()
            .find(|(_, t)| t.arn == physical_id)
            .map(|(name, _)| name.clone());
        if let Some(name) = table_name {
            state.tables.remove(&name);
        }
        Ok(())
    }

    // --- CloudWatch Logs ---

    fn create_log_group(&self, resource: &ResourceDefinition) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let log_group_name = props
            .get("LogGroupName")
            .and_then(|v| v.as_str())
            .unwrap_or(&resource.logical_id);

        let retention_in_days = props
            .get("RetentionInDays")
            .and_then(|v| v.as_i64())
            .map(|v| v as i32);

        let mut logs_accounts = self.logs_state.write();
        let state = logs_accounts.get_or_create(&self.account_id);
        let arn = format!(
            "arn:aws:logs:{}:{}:log-group:{}:*",
            state.region, state.account_id, log_group_name
        );

        let log_group = fakecloud_logs::LogGroup {
            name: log_group_name.to_string(),
            arn: arn.clone(),
            creation_time: Utc::now().timestamp_millis(),
            retention_in_days,
            kms_key_id: None,
            stored_bytes: 0,
            log_streams: std::collections::BTreeMap::new(),
            tags: std::collections::BTreeMap::new(),
            subscription_filters: Vec::new(),
            data_protection_policy: None,
            index_policies: Vec::new(),
            transformer: None,
            deletion_protection: false,
            log_group_class: Some("STANDARD".to_string()),
        };

        state
            .log_groups
            .insert(log_group_name.to_string(), log_group);
        Ok(ProvisionResult::new(arn.clone()).with("Arn", arn))
    }

    fn create_lambda_function(
        &self,
        resource: &ResourceDefinition,
    ) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let function_name = props
            .get("FunctionName")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string())
            .unwrap_or_else(|| {
                format!(
                    "{}-{}-{}",
                    self.stack_id
                        .rsplit('/')
                        .nth(1)
                        .unwrap_or(&resource.logical_id),
                    resource.logical_id,
                    Uuid::new_v4()
                        .to_string()
                        .split('-')
                        .next()
                        .unwrap_or("rand")
                )
            });

        let runtime = props
            .get("Runtime")
            .and_then(|v| v.as_str())
            .unwrap_or("provided.al2023")
            .to_string();
        let role = props
            .get("Role")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let handler = props
            .get("Handler")
            .and_then(|v| v.as_str())
            .unwrap_or("index.handler")
            .to_string();
        let description = props
            .get("Description")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string();
        let timeout = props.get("Timeout").and_then(|v| v.as_i64()).unwrap_or(3);
        let memory_size = props
            .get("MemorySize")
            .and_then(|v| v.as_i64())
            .unwrap_or(128);
        let architectures = props
            .get("Architectures")
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_string()))
                    .collect::<Vec<_>>()
            })
            .unwrap_or_else(|| vec!["x86_64".to_string()]);
        let package_type = props
            .get("PackageType")
            .and_then(|v| v.as_str())
            .unwrap_or("Zip")
            .to_string();
        let environment = props
            .get("Environment")
            .and_then(|v| v.get("Variables"))
            .and_then(|v| v.as_object())
            .map(|o| {
                o.iter()
                    .filter_map(|(k, v)| v.as_str().map(|s| (k.clone(), s.to_string())))
                    .collect::<BTreeMap<String, String>>()
            })
            .unwrap_or_default();

        let function_arn = format!(
            "arn:aws:lambda:{}:{}:function:{}",
            self.region, self.account_id, function_name
        );

        let func = fakecloud_lambda::LambdaFunction {
            function_name: function_name.clone(),
            function_arn: function_arn.clone(),
            runtime,
            role,
            handler,
            description,
            timeout,
            memory_size,
            code_sha256: String::new(),
            code_size: 0,
            version: "$LATEST".to_string(),
            last_modified: Utc::now(),
            tags: BTreeMap::new(),
            environment,
            architectures,
            package_type,
            code_zip: None,
            image_uri: None,
            policy: None,
            layers: Vec::new(),
            revision_id: Uuid::new_v4().to_string(),
            tracing_mode: None,
            kms_key_arn: None,
            ephemeral_storage_size: None,
            vpc_config: None,
            snap_start: None,
            dead_letter_config_arn: None,
            file_system_configs: Vec::new(),
            logging_config: None,
            image_config: None,
            signing_profile_version_arn: None,
            signing_job_arn: None,
            runtime_version_config: None,
            master_arn: None,
        };

        let mut accounts = self.lambda_state.write();
        let state = accounts.get_or_create(&self.account_id);
        state.functions.insert(function_name.clone(), func);

        Ok(ProvisionResult::new(function_name.clone())
            .with("Arn", function_arn)
            .with("FunctionName", function_name))
    }

    fn delete_lambda_function(&self, physical_id: &str) -> Result<(), String> {
        let mut accounts = self.lambda_state.write();
        let state = accounts.default_mut();
        state.functions.remove(physical_id);
        Ok(())
    }

    // --- SecretsManager ---

    fn create_secrets_manager_secret(
        &self,
        resource: &ResourceDefinition,
    ) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let name = props
            .get("Name")
            .and_then(|v| v.as_str())
            .unwrap_or(&resource.logical_id)
            .to_string();
        let description = props
            .get("Description")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let kms_key_id = props
            .get("KmsKeyId")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let mut accounts = self.secretsmanager_state.write();
        let state = accounts.get_or_create(&self.account_id);
        let arn = format!(
            "arn:aws:secretsmanager:{}:{}:secret:{}",
            state.region, state.account_id, name
        );

        if state.secrets.contains_key(&arn) {
            return Err(format!("Secret {name} already exists"));
        }

        let now = Utc::now();
        let mut versions = BTreeMap::new();
        let mut current_version_id: Option<String> = None;
        if let Some(secret_string) = props.get("SecretString").and_then(|v| v.as_str()) {
            let version_id = Uuid::new_v4().to_string();
            versions.insert(
                version_id.clone(),
                SecretVersion {
                    version_id: version_id.clone(),
                    secret_string: Some(secret_string.to_string()),
                    secret_binary: None,
                    stages: vec!["AWSCURRENT".to_string()],
                    created_at: now,
                },
            );
            current_version_id = Some(version_id);
        }

        let mut tags: Vec<(String, String)> = Vec::new();
        if let Some(arr) = props.get("Tags").and_then(|v| v.as_array()) {
            for t in arr {
                if let (Some(k), Some(v)) = (
                    t.get("Key").and_then(|x| x.as_str()),
                    t.get("Value").and_then(|x| x.as_str()),
                ) {
                    tags.push((k.to_string(), v.to_string()));
                }
            }
        }
        let tags_set = !tags.is_empty();

        let secret = Secret {
            name: name.clone(),
            arn: arn.clone(),
            description,
            kms_key_id,
            versions,
            current_version_id,
            tags,
            tags_ever_set: tags_set,
            deleted: false,
            deletion_date: None,
            created_at: now,
            last_changed_at: now,
            last_accessed_at: None,
            rotation_enabled: None,
            rotation_lambda_arn: None,
            rotation_rules: None,
            last_rotated_at: None,
            resource_policy: None,
        };
        state.secrets.insert(arn.clone(), secret);

        Ok(ProvisionResult::new(arn.clone())
            .with("Id", arn.clone())
            .with("Name", name))
    }

    fn delete_secrets_manager_secret(&self, physical_id: &str) -> Result<(), String> {
        let mut accounts = self.secretsmanager_state.write();
        let state = accounts.get_or_create(&self.account_id);
        state.secrets.remove(physical_id);
        Ok(())
    }

    // --- Kinesis ---

    fn create_kinesis_stream(
        &self,
        resource: &ResourceDefinition,
    ) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let stream_name = props
            .get("Name")
            .and_then(|v| v.as_str())
            .unwrap_or(&resource.logical_id)
            .to_string();
        let shard_count = props
            .get("ShardCount")
            .and_then(|v| v.as_i64())
            .unwrap_or(1) as i32;
        if shard_count <= 0 {
            return Err("ShardCount must be greater than zero".to_string());
        }
        let stream_mode = props
            .get("StreamModeDetails")
            .and_then(|v| v.get("StreamMode"))
            .and_then(|v| v.as_str())
            .unwrap_or("PROVISIONED")
            .to_string();
        let retention_period_hours = props
            .get("RetentionPeriodHours")
            .and_then(|v| v.as_i64())
            .unwrap_or(24) as i32;

        let mut accounts = self.kinesis_state.write();
        let state = accounts.get_or_create(&self.account_id);
        if state.streams.contains_key(&stream_name) {
            return Err(format!("Stream {stream_name} already exists"));
        }
        let stream_arn = format!(
            "arn:aws:kinesis:{}:{}:stream/{}",
            state.region, state.account_id, stream_name
        );
        let stream = KinesisStream {
            stream_name: stream_name.clone(),
            stream_arn: stream_arn.clone(),
            stream_status: "ACTIVE".to_string(),
            stream_creation_timestamp: Utc::now(),
            retention_period_hours,
            stream_mode,
            encryption_type: "NONE".to_string(),
            key_id: None,
            shard_count,
            open_shard_count: shard_count,
            tags: BTreeMap::new(),
            shards: build_stream_shards(shard_count),
            next_shard_index: shard_count,
            enhanced_metrics: Vec::new(),
            warm_throughput_mibps: None,
            max_record_size_kib: None,
        };
        state.streams.insert(stream_name.clone(), stream);

        Ok(ProvisionResult::new(stream_name).with("Arn", stream_arn))
    }

    fn delete_kinesis_stream(&self, physical_id: &str) -> Result<(), String> {
        let mut accounts = self.kinesis_state.write();
        let state = accounts.get_or_create(&self.account_id);
        state.streams.remove(physical_id);
        Ok(())
    }

    fn create_kinesis_stream_consumer(
        &self,
        resource: &ResourceDefinition,
    ) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let stream_arn = props
            .get("StreamARN")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "StreamARN is required".to_string())?
            .to_string();
        let consumer_name = props
            .get("ConsumerName")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "ConsumerName is required".to_string())?
            .to_string();

        let mut accounts = self.kinesis_state.write();
        let state = accounts.get_or_create(&self.account_id);
        if state
            .consumers
            .values()
            .any(|c| c.stream_arn == stream_arn && c.consumer_name == consumer_name)
        {
            return Err(format!(
                "Consumer {consumer_name} already exists on stream {stream_arn}"
            ));
        }
        let now = Utc::now();
        let consumer_arn = format!(
            "{}/consumer/{}:{}",
            stream_arn,
            consumer_name,
            now.timestamp()
        );
        let consumer = KinesisConsumer {
            consumer_name: consumer_name.clone(),
            consumer_arn: consumer_arn.clone(),
            consumer_status: "ACTIVE".to_string(),
            consumer_creation_timestamp: now,
            stream_arn: stream_arn.clone(),
        };
        state.consumers.insert(consumer_arn.clone(), consumer);

        Ok(ProvisionResult::new(consumer_arn.clone())
            .with("ConsumerARN", consumer_arn)
            .with("ConsumerName", consumer_name)
            .with("ConsumerStatus", "ACTIVE")
            .with("ConsumerCreationTimestamp", now.timestamp().to_string())
            .with("StreamARN", stream_arn))
    }

    fn delete_kinesis_stream_consumer(&self, physical_id: &str) -> Result<(), String> {
        let mut accounts = self.kinesis_state.write();
        let state = accounts.get_or_create(&self.account_id);
        state.consumers.remove(physical_id);
        Ok(())
    }

    // --- KMS ---

    fn create_kms_key(&self, resource: &ResourceDefinition) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let description = props
            .get("Description")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let enabled = props
            .get("Enabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let key_rotation_enabled = props
            .get("EnableKeyRotation")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let key_usage = props
            .get("KeyUsage")
            .and_then(|v| v.as_str())
            .unwrap_or("ENCRYPT_DECRYPT")
            .to_string();
        let key_spec = props
            .get("KeySpec")
            .and_then(|v| v.as_str())
            .unwrap_or("SYMMETRIC_DEFAULT")
            .to_string();
        let multi_region = props
            .get("MultiRegion")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let origin = props
            .get("Origin")
            .and_then(|v| v.as_str())
            .unwrap_or("AWS_KMS")
            .to_string();
        let policy = match props.get("KeyPolicy") {
            Some(v) if v.is_string() => v.as_str().unwrap_or("").to_string(),
            Some(v) => serde_json::to_string(v).unwrap_or_default(),
            None => String::new(),
        };
        if !key_spec.starts_with("SYMMETRIC") && !key_spec.starts_with("HMAC") {
            return Err(format!(
                "AWS::KMS::Key with KeySpec '{key_spec}' is not yet supported in CloudFormation; only symmetric and HMAC specs are provisioned"
            ));
        }

        let mut tags: BTreeMap<String, String> = BTreeMap::new();
        if let Some(arr) = props.get("Tags").and_then(|v| v.as_array()) {
            for t in arr {
                if let (Some(k), Some(v)) = (
                    t.get("Key").and_then(|x| x.as_str()),
                    t.get("Value").and_then(|x| x.as_str()),
                ) {
                    tags.insert(k.to_string(), v.to_string());
                }
            }
        }

        let key_id = if multi_region {
            format!("mrk-{}", Uuid::new_v4().as_simple())
        } else {
            Uuid::new_v4().to_string()
        };

        let mut accounts = self.kms_state.write();
        let state = accounts.get_or_create(&self.account_id);
        let arn = format!(
            "arn:aws:kms:{}:{}:key/{}",
            state.region, state.account_id, key_id
        );
        let now = Utc::now().timestamp() as f64;

        // private_key_seed is only consulted for asymmetric KEY_AGREEMENT
        // specs (ECC DeriveSharedSecret); symmetric and HMAC keys never read
        // it, so a zero seed is fine for the specs this provisioner accepts.
        let seed = vec![0u8; 32];

        let encryption_algorithms = if key_usage == "ENCRYPT_DECRYPT" {
            Some(vec!["SYMMETRIC_DEFAULT".to_string()])
        } else {
            None
        };
        let mac_algorithms = if key_usage == "GENERATE_VERIFY_MAC" {
            let alg = match key_spec.as_str() {
                "HMAC_224" => "HMAC_SHA_224",
                "HMAC_256" => "HMAC_SHA_256",
                "HMAC_384" => "HMAC_SHA_384",
                "HMAC_512" => "HMAC_SHA_512",
                _ => "HMAC_SHA_256",
            };
            Some(vec![alg.to_string()])
        } else {
            None
        };

        let key = KmsKey {
            key_id: key_id.clone(),
            arn: arn.clone(),
            creation_date: now,
            description,
            enabled,
            key_usage,
            key_spec,
            key_manager: "CUSTOMER".to_string(),
            key_state: if enabled { "Enabled" } else { "Disabled" }.to_string(),
            deletion_date: None,
            tags,
            policy,
            key_rotation_enabled,
            origin,
            multi_region,
            rotations: Vec::new(),
            signing_algorithms: None,
            encryption_algorithms,
            mac_algorithms,
            custom_key_store_id: None,
            imported_key_material: false,
            imported_material_bytes: None,
            private_key_seed: seed,
            primary_region: None,
            asymmetric_private_key_der: None,
            asymmetric_public_key_der: None,
        };

        state.keys.insert(key_id.clone(), key);

        Ok(ProvisionResult::new(key_id.clone())
            .with("Arn", arn)
            .with("KeyId", key_id))
    }

    fn delete_kms_key(&self, physical_id: &str) -> Result<(), String> {
        let mut accounts = self.kms_state.write();
        let state = accounts.get_or_create(&self.account_id);
        state.keys.remove(physical_id);
        state.aliases.retain(|_, a| a.target_key_id != physical_id);
        Ok(())
    }

    fn create_kms_alias(&self, resource: &ResourceDefinition) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let alias_name = props
            .get("AliasName")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "AliasName is required".to_string())?
            .to_string();
        if !alias_name.starts_with("alias/") {
            return Err(format!(
                "AliasName must start with 'alias/'; got '{alias_name}'"
            ));
        }
        let target_input = props
            .get("TargetKeyId")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "TargetKeyId is required".to_string())?
            .to_string();

        let mut accounts = self.kms_state.write();
        let state = accounts.get_or_create(&self.account_id);

        let target_key_id = if state.keys.contains_key(&target_input) {
            target_input.clone()
        } else if let Some(id) = target_input
            .strip_prefix("arn:aws:kms:")
            .and_then(|rest| rest.split(":key/").nth(1))
        {
            if state.keys.contains_key(id) {
                id.to_string()
            } else {
                return Err(format!("KMS key '{target_input}' does not exist"));
            }
        } else {
            return Err(format!("KMS key '{target_input}' does not exist"));
        };

        let alias_arn = format!(
            "arn:aws:kms:{}:{}:{}",
            state.region, state.account_id, alias_name
        );
        let alias = KmsAlias {
            alias_name: alias_name.clone(),
            alias_arn,
            target_key_id,
            creation_date: Utc::now().timestamp() as f64,
        };
        state.aliases.insert(alias_name.clone(), alias);

        Ok(ProvisionResult::new(alias_name))
    }

    fn delete_kms_alias(&self, physical_id: &str) -> Result<(), String> {
        let mut accounts = self.kms_state.write();
        let state = accounts.get_or_create(&self.account_id);
        state.aliases.remove(physical_id);
        Ok(())
    }

    // --- ECR ---

    fn create_ecr_repository(
        &self,
        resource: &ResourceDefinition,
    ) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let repository_name = props
            .get("RepositoryName")
            .and_then(|v| v.as_str())
            .unwrap_or(&resource.logical_id)
            .to_string();
        let image_tag_mutability = props
            .get("ImageTagMutability")
            .and_then(|v| v.as_str())
            .unwrap_or("MUTABLE")
            .to_string();
        let scan_on_push = props
            .get("ImageScanningConfiguration")
            .and_then(|v| v.get("ScanOnPush"))
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        let encryption_type = props
            .get("EncryptionConfiguration")
            .and_then(|v| v.get("EncryptionType"))
            .and_then(|v| v.as_str())
            .unwrap_or("AES256")
            .to_string();
        let kms_key = props
            .get("EncryptionConfiguration")
            .and_then(|v| v.get("KmsKey"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let policy_text = props
            .get("RepositoryPolicyText")
            .map(|v| {
                if v.is_string() {
                    v.as_str().unwrap_or("").to_string()
                } else {
                    serde_json::to_string(v).unwrap_or_default()
                }
            })
            .filter(|s| !s.is_empty());
        let lifecycle_policy = props
            .get("LifecyclePolicy")
            .and_then(|v| v.get("LifecyclePolicyText"))
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let mut tags: BTreeMap<String, String> = BTreeMap::new();
        if let Some(arr) = props.get("Tags").and_then(|v| v.as_array()) {
            for t in arr {
                if let (Some(k), Some(v)) = (
                    t.get("Key").and_then(|x| x.as_str()),
                    t.get("Value").and_then(|x| x.as_str()),
                ) {
                    tags.insert(k.to_string(), v.to_string());
                }
            }
        }

        let mut accounts = self.ecr_state.write();
        let state = accounts.get_or_create(&self.account_id);
        if state.repositories.contains_key(&repository_name) {
            return Err(format!("Repository {repository_name} already exists"));
        }
        let arn = state.repository_arn(&repository_name);
        let registry_id = state.account_id.clone();
        let endpoint = format!(
            "{}.dkr.ecr.{}.amazonaws.com",
            state.account_id, state.region
        );
        let mut repo = Repository::new(&repository_name, arn.clone(), &registry_id, &endpoint);
        repo.image_tag_mutability = image_tag_mutability;
        repo.image_scanning_configuration.scan_on_push = scan_on_push;
        repo.encryption_configuration.encryption_type = encryption_type;
        repo.encryption_configuration.kms_key = kms_key;
        repo.policy = policy_text;
        repo.lifecycle_policy = lifecycle_policy;
        repo.tags = tags;
        let uri = repo.repository_uri.clone();
        state.repositories.insert(repository_name.clone(), repo);

        Ok(ProvisionResult::new(repository_name)
            .with("Arn", arn)
            .with("RepositoryUri", uri))
    }

    fn delete_ecr_repository(&self, physical_id: &str) -> Result<(), String> {
        let mut accounts = self.ecr_state.write();
        let state = accounts.get_or_create(&self.account_id);
        state.repositories.remove(physical_id);
        Ok(())
    }

    // --- CloudWatch ---

    fn create_cloudwatch_alarm(
        &self,
        resource: &ResourceDefinition,
    ) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let alarm_name = props
            .get("AlarmName")
            .and_then(|v| v.as_str())
            .unwrap_or(&resource.logical_id)
            .to_string();
        let alarm_description = props
            .get("AlarmDescription")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let actions_enabled = props
            .get("ActionsEnabled")
            .and_then(|v| v.as_bool())
            .unwrap_or(true);
        let str_array = |key: &str| -> Vec<String> {
            props
                .get(key)
                .and_then(|v| v.as_array())
                .map(|arr| {
                    arr.iter()
                        .filter_map(|x| x.as_str().map(|s| s.to_string()))
                        .collect()
                })
                .unwrap_or_default()
        };
        let alarm_actions = str_array("AlarmActions");
        let ok_actions = str_array("OKActions");
        let insufficient_data_actions = str_array("InsufficientDataActions");

        let metric_name = props
            .get("MetricName")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let namespace = props
            .get("Namespace")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let statistic = props
            .get("Statistic")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let extended_statistic = props
            .get("ExtendedStatistic")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let unit = props
            .get("Unit")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let period = props.get("Period").and_then(|v| v.as_i64());
        let evaluation_periods = props
            .get("EvaluationPeriods")
            .and_then(|v| v.as_i64())
            .unwrap_or(1);
        let datapoints_to_alarm = props.get("DatapointsToAlarm").and_then(|v| v.as_i64());
        let threshold = props.get("Threshold").and_then(|v| v.as_f64());
        let comparison_operator = props
            .get("ComparisonOperator")
            .and_then(|v| v.as_str())
            .unwrap_or("GreaterThanThreshold")
            .to_string();
        let treat_missing_data = props
            .get("TreatMissingData")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let evaluate_low_sample_count_percentile = props
            .get("EvaluateLowSampleCountPercentile")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());

        let mut dimensions: BTreeMap<String, String> = BTreeMap::new();
        if let Some(arr) = props.get("Dimensions").and_then(|v| v.as_array()) {
            for d in arr {
                if let (Some(k), Some(v)) = (
                    d.get("Name").and_then(|x| x.as_str()),
                    d.get("Value").and_then(|x| x.as_str()),
                ) {
                    dimensions.insert(k.to_string(), v.to_string());
                }
            }
        }

        let mut accounts = self.cloudwatch_state.write();
        let state = accounts.get_or_create(&self.account_id);
        let alarm_arn = format!(
            "arn:aws:cloudwatch:{}:{}:alarm:{}",
            self.region, self.account_id, alarm_name
        );
        let now = Utc::now();
        let alarm = MetricAlarm {
            alarm_name: alarm_name.clone(),
            alarm_arn: alarm_arn.clone(),
            alarm_description,
            actions_enabled,
            ok_actions,
            alarm_actions,
            insufficient_data_actions,
            state_value: AlarmState::InsufficientData,
            state_reason: "Unchecked: Initial alarm creation".to_string(),
            state_updated_timestamp: now,
            metric_name,
            namespace,
            statistic,
            extended_statistic,
            dimensions,
            period,
            unit,
            evaluation_periods,
            datapoints_to_alarm,
            threshold,
            comparison_operator,
            treat_missing_data,
            evaluate_low_sample_count_percentile,
            configuration_updated_timestamp: now,
            alarm_configuration_updated_timestamp: now,
        };
        let region_alarms = state.alarms_in_mut(&self.region);
        if region_alarms.contains_key(&alarm_name) {
            return Err(format!("Alarm {alarm_name} already exists"));
        }
        region_alarms.insert(alarm_name.clone(), alarm);

        Ok(ProvisionResult::new(alarm_name).with("Arn", alarm_arn))
    }

    fn delete_cloudwatch_alarm(&self, physical_id: &str) -> Result<(), String> {
        let mut accounts = self.cloudwatch_state.write();
        let state = accounts.get_or_create(&self.account_id);
        state.alarms_in_mut(&self.region).remove(physical_id);
        Ok(())
    }

    fn delete_log_group(&self, physical_id: &str) -> Result<(), String> {
        let mut logs_accounts = self.logs_state.write();
        let state = logs_accounts.default_mut();
        // physical_id is the ARN; find the log group name
        let name = state
            .log_groups
            .iter()
            .find(|(_, g)| g.arn == physical_id)
            .map(|(name, _)| name.clone());
        if let Some(name) = name {
            state.log_groups.remove(&name);
        }
        Ok(())
    }

    fn create_log_stream(&self, resource: &ResourceDefinition) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let log_group_name = props
            .get("LogGroupName")
            .and_then(|v| v.as_str())
            .map(parse_log_group_name)
            .ok_or_else(|| "LogGroupName is required".to_string())?;
        let log_stream_name = props
            .get("LogStreamName")
            .and_then(|v| v.as_str())
            .unwrap_or(&resource.logical_id)
            .to_string();

        let mut logs_accounts = self.logs_state.write();
        let state = logs_accounts.get_or_create(&self.account_id);
        let group = state
            .log_groups
            .get_mut(&log_group_name)
            .ok_or_else(|| format!("Log group {log_group_name} does not exist"))?;
        let arn = format!(
            "arn:aws:logs:{}:{}:log-group:{}:log-stream:{}",
            self.region, self.account_id, log_group_name, log_stream_name
        );
        if group.log_streams.contains_key(&log_stream_name) {
            return Err(format!(
                "Log stream {log_stream_name} already exists in {log_group_name}"
            ));
        }
        group.log_streams.insert(
            log_stream_name.clone(),
            LogStream {
                name: log_stream_name.clone(),
                arn,
                creation_time: Utc::now().timestamp_millis(),
                first_event_timestamp: None,
                last_event_timestamp: None,
                last_ingestion_time: None,
                upload_sequence_token: String::new(),
                events: Vec::new(),
            },
        );

        // Encode group + stream into the physical id so deletion can target both.
        let physical_id = format!("{log_group_name}|{log_stream_name}");
        Ok(ProvisionResult::new(physical_id))
    }

    fn delete_log_stream(&self, physical_id: &str) -> Result<(), String> {
        let mut logs_accounts = self.logs_state.write();
        let state = logs_accounts.get_or_create(&self.account_id);
        if let Some((group_name, stream_name)) = physical_id.split_once('|') {
            if let Some(group) = state.log_groups.get_mut(group_name) {
                group.log_streams.remove(stream_name);
            }
        }
        Ok(())
    }

    fn create_metric_filter(
        &self,
        resource: &ResourceDefinition,
    ) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let log_group_name = props
            .get("LogGroupName")
            .and_then(|v| v.as_str())
            .map(parse_log_group_name)
            .ok_or_else(|| "LogGroupName is required".to_string())?;
        let filter_name = props
            .get("FilterName")
            .and_then(|v| v.as_str())
            .unwrap_or(&resource.logical_id)
            .to_string();
        let filter_pattern = props
            .get("FilterPattern")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();

        let mut transformations: Vec<MetricTransformation> = Vec::new();
        if let Some(arr) = props
            .get("MetricTransformations")
            .and_then(|v| v.as_array())
        {
            for t in arr {
                let metric_name = t
                    .get("MetricName")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let metric_namespace = t
                    .get("MetricNamespace")
                    .and_then(|v| v.as_str())
                    .unwrap_or("")
                    .to_string();
                let metric_value = t
                    .get("MetricValue")
                    .and_then(|v| v.as_str())
                    .unwrap_or("1")
                    .to_string();
                let default_value = t.get("DefaultValue").and_then(|v| v.as_f64());
                transformations.push(MetricTransformation {
                    metric_name,
                    metric_namespace,
                    metric_value,
                    default_value,
                });
            }
        }

        let mut logs_accounts = self.logs_state.write();
        let state = logs_accounts.get_or_create(&self.account_id);
        if !state.log_groups.contains_key(&log_group_name) {
            return Err(format!("Log group {log_group_name} does not exist"));
        }
        state
            .metric_filters
            .retain(|f| !(f.log_group_name == log_group_name && f.filter_name == filter_name));
        state.metric_filters.push(MetricFilter {
            filter_name: filter_name.clone(),
            filter_pattern,
            log_group_name: log_group_name.clone(),
            metric_transformations: transformations,
            creation_time: Utc::now().timestamp_millis(),
        });

        Ok(ProvisionResult::new(format!(
            "{log_group_name}|{filter_name}"
        )))
    }

    fn delete_metric_filter(&self, physical_id: &str) -> Result<(), String> {
        let mut logs_accounts = self.logs_state.write();
        let state = logs_accounts.get_or_create(&self.account_id);
        if let Some((group_name, filter_name)) = physical_id.split_once('|') {
            state
                .metric_filters
                .retain(|f| !(f.log_group_name == group_name && f.filter_name == filter_name));
        }
        Ok(())
    }

    fn create_subscription_filter(
        &self,
        resource: &ResourceDefinition,
    ) -> Result<ProvisionResult, String> {
        let props = &resource.properties;
        let log_group_name = props
            .get("LogGroupName")
            .and_then(|v| v.as_str())
            .map(parse_log_group_name)
            .ok_or_else(|| "LogGroupName is required".to_string())?;
        let filter_name = props
            .get("FilterName")
            .and_then(|v| v.as_str())
            .unwrap_or(&resource.logical_id)
            .to_string();
        let filter_pattern = props
            .get("FilterPattern")
            .and_then(|v| v.as_str())
            .unwrap_or("")
            .to_string();
        let destination_arn = props
            .get("DestinationArn")
            .and_then(|v| v.as_str())
            .ok_or_else(|| "DestinationArn is required".to_string())?
            .to_string();
        let role_arn = props
            .get("RoleArn")
            .and_then(|v| v.as_str())
            .map(|s| s.to_string());
        let distribution = props
            .get("Distribution")
            .and_then(|v| v.as_str())
            .unwrap_or("ByLogStream")
            .to_string();

        let mut logs_accounts = self.logs_state.write();
        let state = logs_accounts.get_or_create(&self.account_id);
        let group = state
            .log_groups
            .get_mut(&log_group_name)
            .ok_or_else(|| format!("Log group {log_group_name} does not exist"))?;
        group
            .subscription_filters
            .retain(|f| f.filter_name != filter_name);
        group.subscription_filters.push(SubscriptionFilter {
            filter_name: filter_name.clone(),
            log_group_name: log_group_name.clone(),
            filter_pattern,
            destination_arn,
            role_arn,
            distribution,
            creation_time: Utc::now().timestamp_millis(),
        });

        Ok(ProvisionResult::new(format!(
            "{log_group_name}|{filter_name}"
        )))
    }

    fn delete_subscription_filter(&self, physical_id: &str) -> Result<(), String> {
        let mut logs_accounts = self.logs_state.write();
        let state = logs_accounts.get_or_create(&self.account_id);
        if let Some((group_name, filter_name)) = physical_id.split_once('|') {
            if let Some(group) = state.log_groups.get_mut(group_name) {
                group
                    .subscription_filters
                    .retain(|f| f.filter_name != filter_name);
            }
        }
        Ok(())
    }

    // --- Custom Resources ---

    /// Invoke a Lambda function synchronously via the delivery bus.
    fn invoke_lambda_sync(&self, function_arn: &str, payload: &str) -> Result<(), String> {
        let delivery = self.delivery.clone();
        let function_arn = function_arn.to_string();
        let payload = payload.to_string();
        std::thread::scope(|s| {
            s.spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .map_err(|e| format!("Failed to create runtime: {e}"))?;
                rt.block_on(async {
                    match delivery.invoke_lambda(&function_arn, &payload).await {
                        Some(Ok(_)) => {
                            tracing::info!(
                                "Custom resource Lambda {} invoked successfully",
                                function_arn
                            );
                            Ok(())
                        }
                        Some(Err(e)) => {
                            tracing::warn!(
                                "Custom resource Lambda {} invocation failed: {e}",
                                function_arn
                            );
                            Err(format!("Lambda invocation failed: {e}"))
                        }
                        None => {
                            tracing::warn!(
                                "No Lambda delivery configured; skipping custom resource invocation for {}",
                                function_arn
                            );
                            Ok(())
                        }
                    }
                })
            })
            .join()
            .map_err(|_| "Lambda invocation thread panicked".to_string())?
        })
    }

    fn create_custom_resource(&self, resource: &ResourceDefinition) -> Result<String, String> {
        let props = &resource.properties;
        let service_token = props
            .get("ServiceToken")
            .and_then(|v| v.as_str())
            .ok_or("Custom resource requires ServiceToken property")?;

        let request_id = Uuid::new_v4().to_string();

        // Build the CloudFormation custom resource event
        let event = serde_json::json!({
            "RequestType": "Create",
            "ServiceToken": service_token,
            "StackId": self.stack_id,
            "RequestId": request_id,
            "ResourceType": resource.resource_type,
            "LogicalResourceId": resource.logical_id,
            "ResourceProperties": props,
        });

        let payload = serde_json::to_string(&event).map_err(|e| e.to_string())?;
        self.invoke_lambda_sync(service_token, &payload)?;

        // Physical resource ID: use a generated ID (the Lambda could return one,
        // but for simplicity we generate one here).
        let physical_id = format!("{}-{}", resource.logical_id, &request_id[..8]);
        Ok(physical_id)
    }

    fn delete_custom_resource(&self, resource: &StackResource) -> Result<(), String> {
        let service_token = match &resource.service_token {
            Some(token) => token.clone(),
            None => {
                // No ServiceToken stored — nothing to invoke
                return Ok(());
            }
        };

        let request_id = Uuid::new_v4().to_string();

        let event = serde_json::json!({
            "RequestType": "Delete",
            "ServiceToken": service_token,
            "StackId": self.stack_id,
            "RequestId": request_id,
            "ResourceType": resource.resource_type,
            "LogicalResourceId": resource.logical_id,
            "PhysicalResourceId": resource.physical_id,
        });

        let payload = serde_json::to_string(&event).map_err(|e| e.to_string())?;

        // Best-effort: don't fail stack deletion if Lambda invocation fails
        if let Err(e) = self.invoke_lambda_sync(&service_token, &payload) {
            tracing::warn!(
                "Custom resource delete Lambda invocation failed for {}: {e}",
                resource.logical_id
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use parking_lot::RwLock;

    fn make_provisioner() -> ResourceProvisioner {
        ResourceProvisioner {
            sqs_state: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "http://localhost:4566",
                ),
            )),
            sns_state: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "http://localhost:4566",
                ),
            )),
            ssm_state: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new(
                    "123456789012",
                    "us-east-1",
                    "http://localhost:4566",
                ),
            )),
            iam_state: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", "http://localhost:4566"),
            )),
            s3_state: Arc::new(RwLock::new(fakecloud_core::multi_account::MultiAccountState::new(
                "123456789012",
                "us-east-1", "",
            ))),
            eventbridge_state: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", ""),
            )),
            dynamodb_state: Arc::new(RwLock::new(fakecloud_core::multi_account::MultiAccountState::new(
                "123456789012",
                "us-east-1", "",
            ))),
            logs_state: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", ""),
            )),
            lambda_state: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", ""),
            )),
            secretsmanager_state: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", ""),
            )),
            kinesis_state: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", ""),
            )),
            kms_state: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", ""),
            )),
            ecr_state: Arc::new(RwLock::new(
                fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", ""),
            )),
            cloudwatch_state: Arc::new(RwLock::new(fakecloud_cloudwatch::CloudWatchAccounts::new())),
            delivery: Arc::new(DeliveryBus::new()),
            account_id: "123456789012".to_string(),
            region: "us-east-1".to_string(),
            stack_id: "arn:aws:cloudformation:us-east-1:123456789012:stack/test/00000000-0000-0000-0000-000000000000".to_string(),
        }
    }

    fn make_resource(
        resource_type: &str,
        logical_id: &str,
        props: serde_json::Value,
    ) -> ResourceDefinition {
        ResourceDefinition {
            logical_id: logical_id.to_string(),
            resource_type: resource_type.to_string(),
            properties: props,
        }
    }

    #[test]
    fn sns_subscription_rejects_nonexistent_topic() {
        let prov = make_provisioner();
        let resource = make_resource(
            "AWS::SNS::Subscription",
            "MySub",
            serde_json::json!({
                "TopicArn": "arn:aws:sns:us-east-1:123456789012:NonExistent",
                "Protocol": "sqs",
                "Endpoint": "arn:aws:sqs:us-east-1:123456789012:my-queue"
            }),
        );
        let result = prov.create_resource(&resource);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not exist"));
    }

    #[test]
    fn sns_subscription_succeeds_when_topic_exists() {
        let prov = make_provisioner();
        // First create the topic
        let topic = make_resource(
            "AWS::SNS::Topic",
            "MyTopic",
            serde_json::json!({ "TopicName": "my-topic" }),
        );
        let topic_result = prov.create_resource(&topic);
        assert!(topic_result.is_ok());
        let topic_arn = topic_result.unwrap().physical_id;

        // Now create subscription referencing that topic
        let sub = make_resource(
            "AWS::SNS::Subscription",
            "MySub",
            serde_json::json!({
                "TopicArn": topic_arn,
                "Protocol": "sqs",
                "Endpoint": "arn:aws:sqs:us-east-1:123456789012:my-queue"
            }),
        );
        let result = prov.create_resource(&sub);
        assert!(result.is_ok());
    }

    #[test]
    fn eventbridge_rule_arn_default_bus_omits_bus_name() {
        let prov = make_provisioner();
        let resource = make_resource(
            "AWS::Events::Rule",
            "MyRule",
            serde_json::json!({
                "Name": "my-rule",
                "ScheduleExpression": "rate(1 hour)"
            }),
        );
        let result = prov.create_resource(&resource).unwrap();
        // For default bus, ARN should be rule/<name> without /default/
        assert_eq!(
            result.physical_id,
            "arn:aws:events:us-east-1:123456789012:rule/my-rule"
        );
        assert!(!result.physical_id.contains("rule/default/"));
    }

    #[test]
    fn eventbridge_rule_arn_custom_bus_includes_bus_name() {
        let prov = make_provisioner();
        // Create a custom bus first
        {
            let mut eb_accounts = prov.eventbridge_state.write();
            let state = eb_accounts.default_mut();
            state.buses.insert(
                "custom-bus".to_string(),
                fakecloud_eventbridge::EventBus {
                    name: "custom-bus".to_string(),
                    arn: "arn:aws:events:us-east-1:123456789012:event-bus/custom-bus".to_string(),
                    policy: None,
                    creation_time: Utc::now(),
                    last_modified_time: Utc::now(),
                    description: None,
                    kms_key_identifier: None,
                    dead_letter_config: None,
                    tags: std::collections::BTreeMap::new(),
                },
            );
        }
        let resource = make_resource(
            "AWS::Events::Rule",
            "MyRule",
            serde_json::json!({
                "Name": "my-rule",
                "EventBusName": "custom-bus",
                "ScheduleExpression": "rate(1 hour)"
            }),
        );
        let result = prov.create_resource(&resource).unwrap();
        assert_eq!(
            result.physical_id,
            "arn:aws:events:us-east-1:123456789012:rule/custom-bus/my-rule"
        );
    }

    #[test]
    fn eventbridge_rule_rejects_nonexistent_bus() {
        let prov = make_provisioner();
        let resource = make_resource(
            "AWS::Events::Rule",
            "MyRule",
            serde_json::json!({
                "Name": "my-rule",
                "EventBusName": "nonexistent-bus",
                "ScheduleExpression": "rate(1 hour)"
            }),
        );
        let result = prov.create_resource(&resource);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("does not exist"));
    }

    #[test]
    fn custom_resource_requires_service_token() {
        let prov = make_provisioner();
        let resource = make_resource(
            "Custom::MyResource",
            "MyCustom",
            serde_json::json!({
                "Foo": "bar"
            }),
        );
        let result = prov.create_resource(&resource);
        assert!(result.is_err());
        assert!(
            result.unwrap_err().contains("ServiceToken"),
            "Should require ServiceToken property"
        );
    }

    #[test]
    fn custom_resource_succeeds_without_lambda_delivery() {
        // When no Lambda delivery is configured, custom resource creation
        // should still succeed (the invocation is silently skipped).
        let prov = make_provisioner();
        let resource = make_resource(
            "Custom::MyResource",
            "MyCustom",
            serde_json::json!({
                "ServiceToken": "arn:aws:lambda:us-east-1:123456789012:function:my-func",
                "Foo": "bar"
            }),
        );
        let result = prov.create_resource(&resource);
        assert!(result.is_ok());
        let sr = result.unwrap();
        assert_eq!(sr.logical_id, "MyCustom");
        assert_eq!(sr.resource_type, "Custom::MyResource");
        assert!(sr.physical_id.starts_with("MyCustom-"));
    }

    #[test]
    fn cloudformation_custom_resource_type_succeeds() {
        let prov = make_provisioner();
        let resource = make_resource(
            "AWS::CloudFormation::CustomResource",
            "MyCustom2",
            serde_json::json!({
                "ServiceToken": "arn:aws:lambda:us-east-1:123456789012:function:my-func",
                "Key": "value"
            }),
        );
        let result = prov.create_resource(&resource);
        assert!(result.is_ok());
        let sr = result.unwrap();
        assert_eq!(sr.resource_type, "AWS::CloudFormation::CustomResource");
    }

    // ── Resource create/delete lifecycle tests ──

    #[test]
    fn sqs_queue_create_and_delete() {
        let prov = make_provisioner();
        let res = make_resource(
            "AWS::SQS::Queue",
            "MyQ",
            serde_json::json!({"QueueName": "my-q"}),
        );
        let sr = prov.create_resource(&res).unwrap();
        assert!(sr.physical_id.contains("my-q"));
        assert_eq!(sr.resource_type, "AWS::SQS::Queue");
        prov.delete_resource(&sr).unwrap();
    }

    #[test]
    fn sqs_queue_fifo_with_suffix() {
        let prov = make_provisioner();
        let res = make_resource(
            "AWS::SQS::Queue",
            "FifoQ",
            serde_json::json!({"QueueName": "my-fifo.fifo", "FifoQueue": true}),
        );
        let sr = prov.create_resource(&res).unwrap();
        assert!(sr.physical_id.contains(".fifo"));
    }

    #[test]
    fn sns_topic_create_and_delete() {
        let prov = make_provisioner();
        let res = make_resource(
            "AWS::SNS::Topic",
            "MyTopic",
            serde_json::json!({"TopicName": "t1"}),
        );
        let sr = prov.create_resource(&res).unwrap();
        assert!(sr.physical_id.contains("t1"));
        prov.delete_resource(&sr).unwrap();
    }

    #[test]
    fn ssm_parameter_create_and_delete() {
        let prov = make_provisioner();
        let res = make_resource(
            "AWS::SSM::Parameter",
            "MyParam",
            serde_json::json!({
                "Name": "/my/param",
                "Type": "String",
                "Value": "v1"
            }),
        );
        let sr = prov.create_resource(&res).unwrap();
        assert_eq!(sr.physical_id, "/my/param");
        prov.delete_resource(&sr).unwrap();
    }

    #[test]
    fn iam_role_create_and_delete() {
        let prov = make_provisioner();
        let res = make_resource(
            "AWS::IAM::Role",
            "MyRole",
            serde_json::json!({
                "RoleName": "my-role",
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []}
            }),
        );
        let sr = prov.create_resource(&res).unwrap();
        assert!(sr.physical_id.contains("my-role"));
        prov.delete_resource(&sr).unwrap();
    }

    #[test]
    fn iam_policy_create_and_delete() {
        let prov = make_provisioner();
        let res = make_resource(
            "AWS::IAM::Policy",
            "MyPolicy",
            serde_json::json!({
                "PolicyName": "my-policy",
                "PolicyDocument": {"Version": "2012-10-17", "Statement": []}
            }),
        );
        let sr = prov.create_resource(&res).unwrap();
        assert!(sr.physical_id.contains("my-policy"));
        prov.delete_resource(&sr).unwrap();
    }

    #[test]
    fn s3_bucket_create_and_delete() {
        let prov = make_provisioner();
        let res = make_resource(
            "AWS::S3::Bucket",
            "MyBucket",
            serde_json::json!({"BucketName": "my-bucket"}),
        );
        let sr = prov.create_resource(&res).unwrap();
        assert_eq!(sr.physical_id, "my-bucket");
        prov.delete_resource(&sr).unwrap();
    }

    #[test]
    fn dynamodb_table_create_and_delete() {
        let prov = make_provisioner();
        let res = make_resource(
            "AWS::DynamoDB::Table",
            "MyTable",
            serde_json::json!({
                "TableName": "my-table",
                "KeySchema": [{"AttributeName": "pk", "KeyType": "HASH"}],
                "AttributeDefinitions": [{"AttributeName": "pk", "AttributeType": "S"}],
                "BillingMode": "PAY_PER_REQUEST"
            }),
        );
        let sr = prov.create_resource(&res).unwrap();
        assert!(sr.physical_id.contains("my-table"));
        prov.delete_resource(&sr).unwrap();
    }

    #[test]
    fn log_group_create_and_delete() {
        let prov = make_provisioner();
        let res = make_resource(
            "AWS::Logs::LogGroup",
            "MyLogs",
            serde_json::json!({"LogGroupName": "/app/logs"}),
        );
        let sr = prov.create_resource(&res).unwrap();
        assert!(sr.physical_id.contains("/app/logs"));
        prov.delete_resource(&sr).unwrap();
    }

    #[test]
    fn lambda_function_create_and_delete() {
        let prov = make_provisioner();
        let res = make_resource(
            "AWS::Lambda::Function",
            "MyFn",
            serde_json::json!({
                "FunctionName": "my-fn",
                "Runtime": "nodejs20.x",
                "Role": "arn:aws:iam::123456789012:role/lambda-role",
                "Handler": "index.handler",
                "MemorySize": 256,
                "Timeout": 10,
                "Environment": {"Variables": {"FOO": "bar"}}
            }),
        );
        let sr = prov.create_resource(&res).unwrap();
        assert_eq!(sr.physical_id, "my-fn");
        assert_eq!(
            sr.attributes.get("Arn").map(String::as_str),
            Some("arn:aws:lambda:us-east-1:123456789012:function:my-fn")
        );
        // Verify it landed in lambda state
        {
            let lam = prov.lambda_state.read();
            let st = lam.get("123456789012").unwrap();
            let f = st.functions.get("my-fn").unwrap();
            assert_eq!(f.runtime, "nodejs20.x");
            assert_eq!(f.memory_size, 256);
            assert_eq!(f.environment.get("FOO").unwrap(), "bar");
        }
        prov.delete_resource(&sr).unwrap();
        let lam = prov.lambda_state.read();
        let st = lam.get("123456789012").unwrap();
        assert!(!st.functions.contains_key("my-fn"));
    }

    #[test]
    fn unsupported_resource_type_fails() {
        let prov = make_provisioner();
        let res = make_resource("AWS::NonExistent::Thing", "X", serde_json::json!({}));
        assert!(prov.create_resource(&res).is_err());
    }

    #[test]
    fn iam_role_with_inline_policies() {
        let prov = make_provisioner();
        let res = make_resource(
            "AWS::IAM::Role",
            "MyRole",
            serde_json::json!({
                "RoleName": "role-inline",
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
                "Policies": [
                    {
                        "PolicyName": "inline-1",
                        "PolicyDocument": {"Version": "2012-10-17", "Statement": []}
                    }
                ]
            }),
        );
        let sr = prov.create_resource(&res).unwrap();
        assert!(sr.physical_id.contains("role-inline"));
    }

    #[test]
    fn sqs_queue_auto_name() {
        let prov = make_provisioner();
        let res = make_resource("AWS::SQS::Queue", "AutoQ", serde_json::json!({}));
        let sr = prov.create_resource(&res).unwrap();
        // Generated queue name should exist
        assert!(!sr.physical_id.is_empty());
    }

    #[test]
    fn sns_topic_auto_name() {
        let prov = make_provisioner();
        let res = make_resource("AWS::SNS::Topic", "AutoT", serde_json::json!({}));
        let sr = prov.create_resource(&res).unwrap();
        assert!(!sr.physical_id.is_empty());
    }

    // ── additional resource types ──

    #[test]
    fn unsupported_resource_type_errors() {
        let prov = make_provisioner();
        let res = make_resource("AWS::FooBar::Thing", "X", serde_json::json!({}));
        assert!(prov.create_resource(&res).is_err());
    }

    #[test]
    fn sqs_queue_with_redrive_policy() {
        let prov = make_provisioner();
        // Create DLQ first
        let dlq = make_resource(
            "AWS::SQS::Queue",
            "DLQ",
            serde_json::json!({"QueueName": "dlq1"}),
        );
        let dlq_resource = prov.create_resource(&dlq).unwrap();
        let _ = dlq_resource.physical_id;

        // Create source queue with redrive policy
        let src = make_resource(
            "AWS::SQS::Queue",
            "Src",
            serde_json::json!({
                "QueueName": "src1",
                "RedrivePolicy": {
                    "deadLetterTargetArn": "arn:aws:sqs:us-east-1:123456789012:dlq1",
                    "maxReceiveCount": 3
                }
            }),
        );
        let sr = prov.create_resource(&src).unwrap();
        assert!(!sr.physical_id.is_empty());
    }

    #[test]
    fn sns_topic_with_display_name() {
        let prov = make_provisioner();
        let res = make_resource(
            "AWS::SNS::Topic",
            "WithName",
            serde_json::json!({"TopicName": "named-topic", "DisplayName": "Named"}),
        );
        let sr = prov.create_resource(&res).unwrap();
        assert!(sr.physical_id.contains("named-topic"));
    }

    #[test]
    fn ssm_parameter_with_explicit_name() {
        let prov = make_provisioner();
        let res = make_resource(
            "AWS::SSM::Parameter",
            "Param",
            serde_json::json!({"Name": "/my/param", "Value": "v", "Type": "String"}),
        );
        let sr = prov.create_resource(&res).unwrap();
        assert!(sr.physical_id.contains("/my/param"));
    }

    #[test]
    fn ssm_parameter_missing_name_errors() {
        let prov = make_provisioner();
        let res = make_resource(
            "AWS::SSM::Parameter",
            "AutoP",
            serde_json::json!({"Value": "v", "Type": "String"}),
        );
        assert!(prov.create_resource(&res).is_err());
    }

    #[test]
    fn iam_managed_policy_auto_name() {
        let prov = make_provisioner();
        let res = make_resource(
            "AWS::IAM::Policy",
            "AutoPol",
            serde_json::json!({
                "PolicyName": "inline-pol",
                "PolicyDocument": {"Version": "2012-10-17", "Statement": []},
                "Users": []
            }),
        );
        let sr = prov.create_resource(&res).unwrap();
        assert!(!sr.physical_id.is_empty());
    }

    #[test]
    fn delete_resource_works_for_queue() {
        let prov = make_provisioner();
        let res = make_resource(
            "AWS::SQS::Queue",
            "ToDel",
            serde_json::json!({"QueueName": "todel"}),
        );
        let sr = prov.create_resource(&res).unwrap();
        assert!(prov.delete_resource(&sr).is_ok());
    }

    #[test]
    fn delete_resource_works_for_topic() {
        let prov = make_provisioner();
        let res = make_resource(
            "AWS::SNS::Topic",
            "DelT",
            serde_json::json!({"TopicName": "delt"}),
        );
        let sr = prov.create_resource(&res).unwrap();
        assert!(prov.delete_resource(&sr).is_ok());
    }

    #[test]
    fn sqs_queue_with_fifo_suffix() {
        let prov = make_provisioner();
        let res = make_resource(
            "AWS::SQS::Queue",
            "Fifo",
            serde_json::json!({"QueueName": "fq.fifo", "FifoQueue": true}),
        );
        let sr = prov.create_resource(&res).unwrap();
        assert!(sr.physical_id.ends_with(".fifo"));
    }
}
