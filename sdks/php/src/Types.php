<?php

declare(strict_types=1);

namespace FakeCloud;

// ── Health & Reset ─────────────────────────────────────────────

final class HealthResponse
{
    public function __construct(
        public readonly string $status,
        public readonly string $version,
        /** @var string[] */
        public readonly array $services,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['status'], $data['version'], $data['services']);
    }
}

final class ResetResponse
{
    public function __construct(
        public readonly string $status,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['status']);
    }
}

final class ResetServiceResponse
{
    public function __construct(
        public readonly string $reset,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['reset']);
    }
}

// ── RDS ────────────────────────────────────────────────────────

final class RdsTag
{
    public function __construct(
        public readonly string $key,
        public readonly string $value,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['key'], $data['value']);
    }
}

final class RdsInstance
{
    public function __construct(
        public readonly string $dbInstanceIdentifier,
        public readonly string $dbInstanceArn,
        public readonly string $dbInstanceClass,
        public readonly string $engine,
        public readonly string $engineVersion,
        public readonly string $dbInstanceStatus,
        public readonly string $masterUsername,
        public readonly ?string $dbName,
        public readonly ?string $endpointAddress,
        public readonly int $port,
        public readonly int $allocatedStorage,
        public readonly bool $publiclyAccessible,
        public readonly bool $deletionProtection,
        public readonly string $createdAt,
        public readonly string $dbiResourceId,
        public readonly ?string $containerId,
        public readonly ?int $hostPort,
        /** @var RdsTag[] */
        public readonly array $tags,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['dbInstanceIdentifier'],
            $data['dbInstanceArn'],
            $data['dbInstanceClass'],
            $data['engine'],
            $data['engineVersion'],
            $data['dbInstanceStatus'],
            $data['masterUsername'],
            $data['dbName'] ?? null,
            $data['endpointAddress'] ?? null,
            $data['port'],
            $data['allocatedStorage'],
            $data['publiclyAccessible'],
            $data['deletionProtection'],
            $data['createdAt'],
            $data['dbiResourceId'],
            $data['containerId'] ?? null,
            $data['hostPort'] ?? null,
            array_map(RdsTag::fromArray(...), $data['tags'] ?? []),
        );
    }
}

final class RdsInstancesResponse
{
    public function __construct(
        /** @var RdsInstance[] */
        public readonly array $instances,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(RdsInstance::fromArray(...), $data['instances']));
    }
}

// ── ElastiCache ────────────────────────────────────────────────

final class ElastiCacheCluster
{
    public function __construct(
        public readonly string $cacheClusterId,
        public readonly string $cacheClusterStatus,
        public readonly string $engine,
        public readonly string $engineVersion,
        public readonly string $cacheNodeType,
        public readonly int $numCacheNodes,
        public readonly ?string $replicationGroupId,
        public readonly ?int $port,
        public readonly ?int $hostPort,
        public readonly ?string $containerId,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['cacheClusterId'],
            $data['cacheClusterStatus'],
            $data['engine'],
            $data['engineVersion'],
            $data['cacheNodeType'],
            $data['numCacheNodes'],
            $data['replicationGroupId'] ?? null,
            $data['port'] ?? null,
            $data['hostPort'] ?? null,
            $data['containerId'] ?? null,
        );
    }
}

final class ElastiCacheClustersResponse
{
    public function __construct(
        /** @var ElastiCacheCluster[] */
        public readonly array $clusters,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(ElastiCacheCluster::fromArray(...), $data['clusters']));
    }
}

final class ElastiCacheReplicationGroup
{
    public function __construct(
        public readonly string $replicationGroupId,
        public readonly string $status,
        public readonly string $description,
        /** @var string[] */
        public readonly array $memberClusters,
        public readonly bool $automaticFailover,
        public readonly bool $multiAz,
        public readonly string $engine,
        public readonly string $engineVersion,
        public readonly string $cacheNodeType,
        public readonly int $numCacheClusters,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['replicationGroupId'],
            $data['status'],
            $data['description'],
            $data['memberClusters'],
            $data['automaticFailover'],
            $data['multiAz'],
            $data['engine'],
            $data['engineVersion'],
            $data['cacheNodeType'],
            $data['numCacheClusters'],
        );
    }
}

final class ElastiCacheReplicationGroupsResponse
{
    public function __construct(
        /** @var ElastiCacheReplicationGroup[] */
        public readonly array $replicationGroups,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(ElastiCacheReplicationGroup::fromArray(...), $data['replicationGroups']));
    }
}

final class ElastiCacheServerlessCache
{
    public function __construct(
        public readonly string $serverlessCacheName,
        public readonly string $status,
        public readonly string $engine,
        public readonly string $engineVersion,
        public readonly ?string $cacheNodeType,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['serverlessCacheName'],
            $data['status'],
            $data['engine'],
            $data['engineVersion'],
            $data['cacheNodeType'] ?? null,
        );
    }
}

final class ElastiCacheServerlessCachesResponse
{
    public function __construct(
        /** @var ElastiCacheServerlessCache[] */
        public readonly array $serverlessCaches,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(ElastiCacheServerlessCache::fromArray(...), $data['serverlessCaches']));
    }
}

// ── Lambda ─────────────────────────────────────────────────────

final class LambdaInvocation
{
    public function __construct(
        public readonly string $functionArn,
        public readonly string $payload,
        public readonly string $source,
        public readonly string $timestamp,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['functionArn'], $data['payload'], $data['source'], $data['timestamp']);
    }
}

final class LambdaInvocationsResponse
{
    public function __construct(
        /** @var LambdaInvocation[] */
        public readonly array $invocations,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(LambdaInvocation::fromArray(...), $data['invocations']));
    }
}

final class WarmContainer
{
    public function __construct(
        public readonly string $functionName,
        public readonly string $runtime,
        public readonly string $containerId,
        public readonly int $lastUsedSecsAgo,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['functionName'], $data['runtime'], $data['containerId'], $data['lastUsedSecsAgo']);
    }
}

final class WarmContainersResponse
{
    public function __construct(
        /** @var WarmContainer[] */
        public readonly array $containers,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(WarmContainer::fromArray(...), $data['containers']));
    }
}

final class EvictContainerResponse
{
    public function __construct(
        public readonly bool $evicted,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['evicted']);
    }
}

// ── SES ────────────────────────────────────────────────────────

final class SentEmail
{
    public function __construct(
        public readonly string $messageId,
        public readonly string $from,
        /** @var string[] */
        public readonly array $to,
        /** @var string[] */
        public readonly array $cc,
        /** @var string[] */
        public readonly array $bcc,
        public readonly ?string $subject,
        public readonly ?string $htmlBody,
        public readonly ?string $textBody,
        public readonly ?string $rawData,
        public readonly ?string $templateName,
        public readonly ?string $templateData,
        public readonly string $timestamp,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['messageId'],
            $data['from'],
            $data['to'] ?? [],
            $data['cc'] ?? [],
            $data['bcc'] ?? [],
            $data['subject'] ?? null,
            $data['htmlBody'] ?? null,
            $data['textBody'] ?? null,
            $data['rawData'] ?? null,
            $data['templateName'] ?? null,
            $data['templateData'] ?? null,
            $data['timestamp'],
        );
    }
}

final class SesEmailsResponse
{
    public function __construct(
        /** @var SentEmail[] */
        public readonly array $emails,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(SentEmail::fromArray(...), $data['emails']));
    }
}

final class InboundEmailRequest
{
    public function __construct(
        public readonly string $from,
        /** @var string[] */
        public readonly array $to,
        public readonly string $subject,
        public readonly string $body,
    ) {}

    public function toArray(): array
    {
        return [
            'from' => $this->from,
            'to' => $this->to,
            'subject' => $this->subject,
            'body' => $this->body,
        ];
    }
}

final class InboundActionExecuted
{
    public function __construct(
        public readonly string $rule,
        public readonly string $actionType,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['rule'], $data['actionType']);
    }
}

final class InboundEmailResponse
{
    public function __construct(
        public readonly string $messageId,
        /** @var string[] */
        public readonly array $matchedRules,
        /** @var InboundActionExecuted[] */
        public readonly array $actionsExecuted,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['messageId'],
            $data['matchedRules'],
            array_map(InboundActionExecuted::fromArray(...), $data['actionsExecuted']),
        );
    }
}

// ── SNS ────────────────────────────────────────────────────────

final class SnsMessage
{
    public function __construct(
        public readonly string $messageId,
        public readonly string $topicArn,
        public readonly string $message,
        public readonly ?string $subject,
        public readonly string $timestamp,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['messageId'], $data['topicArn'], $data['message'], $data['subject'] ?? null, $data['timestamp']);
    }
}

final class SnsMessagesResponse
{
    public function __construct(
        /** @var SnsMessage[] */
        public readonly array $messages,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(SnsMessage::fromArray(...), $data['messages']));
    }
}

final class PendingConfirmation
{
    public function __construct(
        public readonly string $subscriptionArn,
        public readonly string $topicArn,
        public readonly string $protocol,
        public readonly string $endpoint,
        public readonly string $token,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['subscriptionArn'], $data['topicArn'], $data['protocol'], $data['endpoint'], $data['token']);
    }
}

final class PendingConfirmationsResponse
{
    public function __construct(
        /** @var PendingConfirmation[] */
        public readonly array $pendingConfirmations,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(PendingConfirmation::fromArray(...), $data['pendingConfirmations']));
    }
}

final class ConfirmSubscriptionRequest
{
    public function __construct(
        public readonly string $subscriptionArn,
    ) {}

    public function toArray(): array
    {
        return ['subscriptionArn' => $this->subscriptionArn];
    }
}

final class ConfirmSubscriptionResponse
{
    public function __construct(
        public readonly bool $confirmed,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['confirmed']);
    }
}

// ── SQS ────────────────────────────────────────────────────────

final class SqsMessageInfo
{
    public function __construct(
        public readonly string $messageId,
        public readonly string $body,
        public readonly int $receiveCount,
        public readonly bool $inFlight,
        public readonly string $createdAt,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['messageId'], $data['body'], $data['receiveCount'], $data['inFlight'], $data['createdAt']);
    }
}

final class SqsQueueMessages
{
    public function __construct(
        public readonly string $queueUrl,
        public readonly string $queueName,
        /** @var SqsMessageInfo[] */
        public readonly array $messages,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['queueUrl'],
            $data['queueName'],
            array_map(SqsMessageInfo::fromArray(...), $data['messages']),
        );
    }
}

final class SqsMessagesResponse
{
    public function __construct(
        /** @var SqsQueueMessages[] */
        public readonly array $queues,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(SqsQueueMessages::fromArray(...), $data['queues']));
    }
}

final class ExpirationTickResponse
{
    public function __construct(
        public readonly int $expiredMessages,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['expiredMessages']);
    }
}

final class ForceDlqResponse
{
    public function __construct(
        public readonly int $movedMessages,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['movedMessages']);
    }
}

// ── EventBridge ────────────────────────────────────────────────

final class EventBridgeEvent
{
    public function __construct(
        public readonly string $eventId,
        public readonly string $source,
        public readonly string $detailType,
        public readonly string $detail,
        public readonly string $busName,
        public readonly string $timestamp,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['eventId'], $data['source'], $data['detailType'], $data['detail'], $data['busName'], $data['timestamp']);
    }
}

final class EventBridgeLambdaDelivery
{
    public function __construct(
        public readonly string $functionArn,
        public readonly string $payload,
        public readonly string $timestamp,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['functionArn'], $data['payload'], $data['timestamp']);
    }
}

final class EventBridgeLogDelivery
{
    public function __construct(
        public readonly string $logGroupArn,
        public readonly string $payload,
        public readonly string $timestamp,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['logGroupArn'], $data['payload'], $data['timestamp']);
    }
}

final class EventBridgeDeliveries
{
    public function __construct(
        /** @var EventBridgeLambdaDelivery[] */
        public readonly array $lambda,
        /** @var EventBridgeLogDelivery[] */
        public readonly array $logs,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            array_map(EventBridgeLambdaDelivery::fromArray(...), $data['lambda'] ?? []),
            array_map(EventBridgeLogDelivery::fromArray(...), $data['logs'] ?? []),
        );
    }
}

final class EventHistoryResponse
{
    public function __construct(
        /** @var EventBridgeEvent[] */
        public readonly array $events,
        public readonly EventBridgeDeliveries $deliveries,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            array_map(EventBridgeEvent::fromArray(...), $data['events']),
            EventBridgeDeliveries::fromArray($data['deliveries']),
        );
    }
}

final class FireRuleRequest
{
    public function __construct(
        public readonly string $ruleName,
        public readonly ?string $busName = null,
    ) {}

    public function toArray(): array
    {
        $data = ['ruleName' => $this->ruleName];
        if ($this->busName !== null) {
            $data['busName'] = $this->busName;
        }
        return $data;
    }
}

final class FireRuleTarget
{
    public function __construct(
        public readonly string $type,
        public readonly string $arn,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['type'], $data['arn']);
    }
}

final class FireRuleResponse
{
    public function __construct(
        /** @var FireRuleTarget[] */
        public readonly array $targets,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(FireRuleTarget::fromArray(...), $data['targets']));
    }
}

// ── Scheduler (EventBridge Scheduler) ───────────────────────────

final class SchedulerSchedule
{
    public function __construct(
        public readonly string $accountId,
        public readonly string $groupName,
        public readonly string $name,
        public readonly string $arn,
        public readonly string $state,
        public readonly string $scheduleExpression,
        public readonly string $targetArn,
        public readonly ?string $lastFired,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['accountId'] ?? '',
            $data['groupName'] ?? '',
            $data['name'] ?? '',
            $data['arn'] ?? '',
            $data['state'] ?? '',
            $data['scheduleExpression'] ?? '',
            $data['targetArn'] ?? '',
            $data['lastFired'] ?? null,
        );
    }
}

final class SchedulerSchedulesResponse
{
    public function __construct(
        /** @var SchedulerSchedule[] */
        public readonly array $schedules,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(
            SchedulerSchedule::fromArray(...),
            $data['schedules'] ?? [],
        ));
    }
}

final class FireScheduleResponse
{
    public function __construct(
        public readonly string $scheduleArn,
        public readonly string $targetArn,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['scheduleArn'] ?? '',
            $data['targetArn'] ?? '',
        );
    }
}

// ── S3 ─────────────────────────────────────────────────────────

final class S3Notification
{
    public function __construct(
        public readonly string $bucket,
        public readonly string $key,
        public readonly string $eventType,
        public readonly string $timestamp,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['bucket'], $data['key'], $data['eventType'], $data['timestamp']);
    }
}

final class S3NotificationsResponse
{
    public function __construct(
        /** @var S3Notification[] */
        public readonly array $notifications,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(S3Notification::fromArray(...), $data['notifications']));
    }
}

final class LifecycleTickResponse
{
    public function __construct(
        public readonly int $processedBuckets,
        public readonly int $expiredObjects,
        public readonly int $transitionedObjects,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['processedBuckets'], $data['expiredObjects'], $data['transitionedObjects']);
    }
}

// ── DynamoDB ───────────────────────────────────────────────────

final class TtlTickResponse
{
    public function __construct(
        public readonly int $expiredItems,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['expiredItems']);
    }
}

// ── SecretsManager ─────────────────────────────────────────────

final class RotationTickResponse
{
    public function __construct(
        /** @var string[] */
        public readonly array $rotatedSecrets,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['rotatedSecrets']);
    }
}

// ── Cognito ────────────────────────────────────────────────────

final class UserConfirmationCodes
{
    public function __construct(
        public readonly ?string $confirmationCode,
        /** @var array<string, mixed> */
        public readonly array $attributeVerificationCodes,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['confirmationCode'] ?? null, $data['attributeVerificationCodes'] ?? []);
    }
}

final class ConfirmationCode
{
    public function __construct(
        public readonly string $poolId,
        public readonly string $username,
        public readonly string $code,
        public readonly string $type,
        public readonly ?string $attribute,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['poolId'], $data['username'], $data['code'], $data['type'], $data['attribute'] ?? null);
    }
}

final class ConfirmationCodesResponse
{
    public function __construct(
        /** @var ConfirmationCode[] */
        public readonly array $codes,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(ConfirmationCode::fromArray(...), $data['codes']));
    }
}

final class ConfirmUserRequest
{
    public function __construct(
        public readonly string $userPoolId,
        public readonly string $username,
    ) {}

    public function toArray(): array
    {
        return ['userPoolId' => $this->userPoolId, 'username' => $this->username];
    }
}

final class ConfirmUserResponse
{
    public function __construct(
        public readonly bool $confirmed,
        public readonly ?string $error,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['confirmed'], $data['error'] ?? null);
    }
}

final class TokenInfo
{
    public function __construct(
        public readonly string $type,
        public readonly string $username,
        public readonly string $poolId,
        public readonly string $clientId,
        public readonly int $issuedAt,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['type'], $data['username'], $data['poolId'], $data['clientId'], $data['issuedAt']);
    }
}

final class TokensResponse
{
    public function __construct(
        /** @var TokenInfo[] */
        public readonly array $tokens,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(TokenInfo::fromArray(...), $data['tokens']));
    }
}

final class ExpireTokensRequest
{
    public function __construct(
        public readonly ?string $userPoolId = null,
        public readonly ?string $username = null,
    ) {}

    public function toArray(): array
    {
        $data = [];
        if ($this->userPoolId !== null) {
            $data['userPoolId'] = $this->userPoolId;
        }
        if ($this->username !== null) {
            $data['username'] = $this->username;
        }
        return $data;
    }
}

final class ExpireTokensResponse
{
    public function __construct(
        public readonly int $expiredTokens,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['expiredTokens']);
    }
}

final class AuthEvent
{
    public function __construct(
        public readonly string $eventType,
        public readonly string $username,
        public readonly string $userPoolId,
        public readonly string $clientId,
        public readonly int $timestamp,
        public readonly bool $success,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['eventType'], $data['username'], $data['userPoolId'], $data['clientId'], $data['timestamp'], $data['success']);
    }
}

final class AuthEventsResponse
{
    public function __construct(
        /** @var AuthEvent[] */
        public readonly array $events,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(AuthEvent::fromArray(...), $data['events']));
    }
}

// ── Step Functions ─────────────────────────────────────────────

final class StepFunctionsExecution
{
    public function __construct(
        public readonly string $executionArn,
        public readonly string $stateMachineArn,
        public readonly string $name,
        public readonly string $status,
        public readonly string $startDate,
        public readonly ?string $input,
        public readonly ?string $output,
        public readonly ?string $stopDate,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['executionArn'],
            $data['stateMachineArn'],
            $data['name'],
            $data['status'],
            $data['startDate'],
            $data['input'] ?? null,
            $data['output'] ?? null,
            $data['stopDate'] ?? null,
        );
    }
}

final class StepFunctionsExecutionsResponse
{
    public function __construct(
        /** @var StepFunctionsExecution[] */
        public readonly array $executions,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(StepFunctionsExecution::fromArray(...), $data['executions']));
    }
}

// ── Bedrock ────────────────────────────────────────────────────

final class BedrockInvocation
{
    public function __construct(
        public readonly string $modelId,
        public readonly string $input,
        public readonly ?string $output,
        public readonly string $timestamp,
        public readonly ?string $error,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['modelId'], $data['input'], $data['output'] ?? null, $data['timestamp'], $data['error'] ?? null);
    }
}

final class BedrockInvocationsResponse
{
    public function __construct(
        /** @var BedrockInvocation[] */
        public readonly array $invocations,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(BedrockInvocation::fromArray(...), $data['invocations']));
    }
}

final class BedrockModelResponseConfig
{
    public function __construct(
        public readonly string $status,
        public readonly string $modelId,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['status'], $data['modelId']);
    }
}

final class BedrockResponseRule
{
    public function __construct(
        public readonly ?string $promptContains,
        public readonly string $response,
    ) {}

    public function toArray(): array
    {
        $data = ['response' => $this->response];
        if ($this->promptContains !== null) {
            $data['promptContains'] = $this->promptContains;
        }
        return $data;
    }
}

final class BedrockFaultRule
{
    public function __construct(
        public readonly string $errorType,
        public readonly ?string $message = null,
        public readonly ?int $httpStatus = null,
        public readonly ?int $count = null,
        public readonly ?string $modelId = null,
        public readonly ?string $operation = null,
    ) {}

    public function toArray(): array
    {
        $data = ['errorType' => $this->errorType];
        if ($this->message !== null) {
            $data['message'] = $this->message;
        }
        if ($this->httpStatus !== null) {
            $data['httpStatus'] = $this->httpStatus;
        }
        if ($this->count !== null) {
            $data['count'] = $this->count;
        }
        if ($this->modelId !== null) {
            $data['modelId'] = $this->modelId;
        }
        if ($this->operation !== null) {
            $data['operation'] = $this->operation;
        }
        return $data;
    }
}

final class BedrockFaultRuleState
{
    public function __construct(
        public readonly string $errorType,
        public readonly ?string $message,
        public readonly int $httpStatus,
        public readonly int $remaining,
        public readonly ?string $modelId,
        public readonly ?string $operation,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['errorType'],
            $data['message'] ?? null,
            $data['httpStatus'],
            $data['remaining'],
            $data['modelId'] ?? null,
            $data['operation'] ?? null,
        );
    }
}

final class BedrockFaultsResponse
{
    public function __construct(
        /** @var BedrockFaultRuleState[] */
        public readonly array $faults,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(BedrockFaultRuleState::fromArray(...), $data['faults']));
    }
}

final class BedrockStatusResponse
{
    public function __construct(
        public readonly string $status,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['status']);
    }
}

// ── API Gateway v2 ─────────────────────────────────────────────

final class ApiGatewayV2Request
{
    public function __construct(
        public readonly string $requestId,
        public readonly string $apiId,
        public readonly string $stage,
        public readonly string $method,
        public readonly string $path,
        /** @var array<string, string> */
        public readonly array $headers,
        /** @var array<string, string> */
        public readonly array $queryParams,
        public readonly ?string $body,
        public readonly string $timestamp,
        public readonly int $statusCode,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['requestId'],
            $data['apiId'],
            $data['stage'],
            $data['method'],
            $data['path'],
            $data['headers'] ?? [],
            $data['queryParams'] ?? [],
            $data['body'] ?? null,
            $data['timestamp'],
            $data['statusCode'],
        );
    }
}

final class ApiGatewayV2RequestsResponse
{
    public function __construct(
        /** @var ApiGatewayV2Request[] */
        public readonly array $requests,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(ApiGatewayV2Request::fromArray(...), $data['requests']));
    }
}

// ── IAM ───────────────────────────────────────────────────────

final class CreateAdminResponse
{
    public function __construct(
        public readonly string $accessKeyId,
        public readonly string $secretAccessKey,
        public readonly string $accountId,
        public readonly string $arn,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['accessKeyId'],
            $data['secretAccessKey'],
            $data['accountId'],
            $data['arn'],
        );
    }
}

// ── ECR ────────────────────────────────────────────────────────────

final class EcrTag
{
    public function __construct(
        public readonly string $key,
        public readonly string $value,
    ) {}

    public static function fromArray(array $d): self
    {
        return new self($d['key'] ?? '', $d['value'] ?? '');
    }
}

final class EcrRepository
{
    /** @param EcrTag[] $tags */
    public function __construct(
        public readonly string $repositoryName,
        public readonly string $repositoryArn,
        public readonly string $registryId,
        public readonly string $repositoryUri,
        public readonly string $imageTagMutability,
        public readonly bool $scanOnPush,
        public readonly string $createdAt,
        public readonly array $tags,
        public readonly bool $hasPolicy,
        public readonly bool $hasLifecyclePolicy,
        public readonly int $imageCount,
        public readonly int $layerCount,
    ) {}

    public static function fromArray(array $d): self
    {
        return new self(
            $d['repositoryName'],
            $d['repositoryArn'],
            $d['registryId'],
            $d['repositoryUri'],
            $d['imageTagMutability'],
            $d['scanOnPush'] ?? false,
            $d['createdAt'],
            array_map(static fn($t) => EcrTag::fromArray($t), $d['tags'] ?? []),
            $d['hasPolicy'] ?? false,
            $d['hasLifecyclePolicy'] ?? false,
            $d['imageCount'] ?? 0,
            $d['layerCount'] ?? 0,
        );
    }
}

final class EcrRepositoriesResponse
{
    /** @param EcrRepository[] $repositories */
    public function __construct(public readonly array $repositories) {}

    public static function fromArray(array $d): self
    {
        return new self(
            array_map(static fn($r) => EcrRepository::fromArray($r), $d['repositories'] ?? []),
        );
    }
}

final class EcrImage
{
    /** @param string[] $imageTags */
    public function __construct(
        public readonly string $repositoryName,
        public readonly string $imageDigest,
        public readonly array $imageTags,
        public readonly int $imageSizeInBytes,
        public readonly string $imageManifestMediaType,
        public readonly string $imagePushedAt,
    ) {}

    public static function fromArray(array $d): self
    {
        return new self(
            $d['repositoryName'],
            $d['imageDigest'],
            $d['imageTags'] ?? [],
            $d['imageSizeInBytes'] ?? 0,
            $d['imageManifestMediaType'] ?? '',
            $d['imagePushedAt'] ?? '',
        );
    }
}

final class EcrImagesResponse
{
    /** @param EcrImage[] $images */
    public function __construct(public readonly array $images) {}

    public static function fromArray(array $d): self
    {
        return new self(
            array_map(static fn($i) => EcrImage::fromArray($i), $d['images'] ?? []),
        );
    }
}

final class EcrPullThroughRule
{
    public function __construct(
        public readonly string $ecrRepositoryPrefix,
        public readonly string $upstreamRegistryUrl,
        public readonly string $createdAt,
        public readonly string $updatedAt,
        public readonly ?string $upstreamRegistry = null,
        public readonly ?string $credentialArn = null,
        public readonly ?string $customRoleArn = null,
    ) {}

    public static function fromArray(array $d): self
    {
        return new self(
            $d['ecrRepositoryPrefix'],
            $d['upstreamRegistryUrl'],
            $d['createdAt'],
            $d['updatedAt'],
            $d['upstreamRegistry'] ?? null,
            $d['credentialArn'] ?? null,
            $d['customRoleArn'] ?? null,
        );
    }
}

final class EcrPullThroughRulesResponse
{
    /** @param EcrPullThroughRule[] $rules */
    public function __construct(public readonly array $rules) {}

    public static function fromArray(array $d): self
    {
        return new self(
            array_map(static fn($r) => EcrPullThroughRule::fromArray($r), $d['rules'] ?? []),
        );
    }
}

// ── ECS ───────────────────────────────────────────────────────

final class EcsTag
{
    public function __construct(
        public readonly string $key,
        public readonly string $value,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['key'], $data['value']);
    }
}

final class EcsCluster
{
    public function __construct(
        public readonly string $clusterName,
        public readonly string $clusterArn,
        public readonly string $status,
        public readonly int $runningTasksCount,
        public readonly int $pendingTasksCount,
        public readonly int $activeServicesCount,
        public readonly int $registeredContainerInstancesCount,
        /** @var string[] */
        public readonly array $capacityProviders,
        /** @var EcsTag[] */
        public readonly array $tags,
        public readonly string $createdAt,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['clusterName'],
            $data['clusterArn'],
            $data['status'],
            (int) ($data['runningTasksCount'] ?? 0),
            (int) ($data['pendingTasksCount'] ?? 0),
            (int) ($data['activeServicesCount'] ?? 0),
            (int) ($data['registeredContainerInstancesCount'] ?? 0),
            $data['capacityProviders'] ?? [],
            array_map(EcsTag::fromArray(...), $data['tags'] ?? []),
            $data['createdAt'] ?? '',
        );
    }
}

final class EcsClustersResponse
{
    public function __construct(
        /** @var EcsCluster[] */
        public readonly array $clusters,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(EcsCluster::fromArray(...), $data['clusters'] ?? []));
    }
}

// ── ELBv2 ──────────────────────────────────────────────────────

final class Elbv2Tag
{
    public function __construct(
        public readonly string $key,
        public readonly string $value,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['key'], $data['value']);
    }
}

final class Elbv2AvailabilityZone
{
    public function __construct(
        public readonly string $zoneName,
        public readonly string $subnetId,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self($data['zoneName'], $data['subnetId']);
    }
}

final class Elbv2LoadBalancer
{
    public function __construct(
        public readonly string $arn,
        public readonly string $name,
        public readonly string $dnsName,
        public readonly string $scheme,
        public readonly string $vpcId,
        public readonly string $stateCode,
        public readonly ?string $stateReason,
        public readonly string $lbType,
        public readonly string $ipAddressType,
        /** @var Elbv2AvailabilityZone[] */
        public readonly array $availabilityZones,
        /** @var string[] */
        public readonly array $securityGroups,
        public readonly string $createdTime,
        /** @var Elbv2Tag[] */
        public readonly array $tags,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['arn'],
            $data['name'],
            $data['dnsName'],
            $data['scheme'],
            $data['vpcId'],
            $data['stateCode'],
            $data['stateReason'] ?? null,
            $data['lbType'],
            $data['ipAddressType'],
            array_map(Elbv2AvailabilityZone::fromArray(...), $data['availabilityZones'] ?? []),
            $data['securityGroups'] ?? [],
            $data['createdTime'],
            array_map(Elbv2Tag::fromArray(...), $data['tags'] ?? []),
        );
    }
}

final class Elbv2LoadBalancersResponse
{
    public function __construct(
        /** @var Elbv2LoadBalancer[] */
        public readonly array $loadBalancers,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(Elbv2LoadBalancer::fromArray(...), $data['loadBalancers'] ?? []));
    }
}

final class Elbv2Target
{
    public function __construct(
        public readonly string $id,
        public readonly ?int $port,
        public readonly ?string $availabilityZone,
        public readonly string $healthState,
        public readonly ?string $healthReason,
        public readonly ?string $healthDescription,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['id'],
            isset($data['port']) ? (int) $data['port'] : null,
            $data['availabilityZone'] ?? null,
            $data['healthState'],
            $data['healthReason'] ?? null,
            $data['healthDescription'] ?? null,
        );
    }
}

final class Elbv2TargetGroup
{
    public function __construct(
        public readonly string $arn,
        public readonly string $name,
        public readonly ?string $protocol,
        public readonly ?int $port,
        public readonly ?string $vpcId,
        public readonly string $targetType,
        /** @var string[] */
        public readonly array $loadBalancerArns,
        /** @var Elbv2Target[] */
        public readonly array $targets,
        public readonly ?string $healthCheckProtocol,
        public readonly ?string $healthCheckPort,
        public readonly ?string $healthCheckPath,
        public readonly int $healthyThresholdCount,
        public readonly int $unhealthyThresholdCount,
        public readonly string $createdTime,
        /** @var Elbv2Tag[] */
        public readonly array $tags,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['arn'],
            $data['name'],
            $data['protocol'] ?? null,
            isset($data['port']) ? (int) $data['port'] : null,
            $data['vpcId'] ?? null,
            $data['targetType'],
            $data['loadBalancerArns'] ?? [],
            array_map(Elbv2Target::fromArray(...), $data['targets'] ?? []),
            $data['healthCheckProtocol'] ?? null,
            $data['healthCheckPort'] ?? null,
            $data['healthCheckPath'] ?? null,
            (int) ($data['healthyThresholdCount'] ?? 0),
            (int) ($data['unhealthyThresholdCount'] ?? 0),
            $data['createdTime'],
            array_map(Elbv2Tag::fromArray(...), $data['tags'] ?? []),
        );
    }
}

final class Elbv2TargetGroupsResponse
{
    public function __construct(
        /** @var Elbv2TargetGroup[] */
        public readonly array $targetGroups,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(Elbv2TargetGroup::fromArray(...), $data['targetGroups'] ?? []));
    }
}

final class Elbv2Listener
{
    public function __construct(
        public readonly string $arn,
        public readonly string $loadBalancerArn,
        public readonly ?int $port,
        public readonly ?string $protocol,
        public readonly ?string $sslPolicy,
        /** @var string[] */
        public readonly array $certificateArns,
        public readonly ?string $defaultActionType,
        public readonly ?string $defaultTargetGroupArn,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['arn'],
            $data['loadBalancerArn'],
            isset($data['port']) ? (int) $data['port'] : null,
            $data['protocol'] ?? null,
            $data['sslPolicy'] ?? null,
            $data['certificateArns'] ?? [],
            $data['defaultActionType'] ?? null,
            $data['defaultTargetGroupArn'] ?? null,
        );
    }
}

final class Elbv2ListenersResponse
{
    public function __construct(
        /** @var Elbv2Listener[] */
        public readonly array $listeners,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(Elbv2Listener::fromArray(...), $data['listeners'] ?? []));
    }
}

final class Elbv2Rule
{
    public function __construct(
        public readonly string $arn,
        public readonly string $listenerArn,
        public readonly string $priority,
        public readonly bool $isDefault,
        /** @var string[] */
        public readonly array $conditionFields,
        public readonly ?string $actionType,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(
            $data['arn'],
            $data['listenerArn'],
            $data['priority'],
            (bool) ($data['isDefault'] ?? false),
            $data['conditionFields'] ?? [],
            $data['actionType'] ?? null,
        );
    }
}

final class Elbv2RulesResponse
{
    public function __construct(
        /** @var Elbv2Rule[] */
        public readonly array $rules,
    ) {}

    public static function fromArray(array $data): self
    {
        return new self(array_map(Elbv2Rule::fromArray(...), $data['rules'] ?? []));
    }
}
