<?php

declare(strict_types=1);

namespace FakeCloud;

/**
 * Top-level client for the fakecloud introspection and simulation API.
 *
 * ```php
 * $fc = new FakeCloud('http://localhost:4566');
 * $fc->reset();
 * $emails = $fc->ses()->getEmails()->emails;
 * ```
 */
final class FakeCloud
{
    private const DEFAULT_BASE_URL = 'http://localhost:4566';

    private HttpTransport $http;
    private LambdaClient $lambda;
    private RdsClient $rds;
    private ElastiCacheClient $elasticache;
    private EcrClient $ecr;
    private SesClient $ses;
    private SnsClient $sns;
    private SqsClient $sqs;
    private EventsClient $events;
    private SchedulerClient $scheduler;
    private S3Client $s3;
    private DynamoDbClient $dynamodb;
    private SecretsManagerClient $secretsmanager;
    private CognitoClient $cognito;
    private ApiGatewayV2Client $apigatewayv2;
    private StepFunctionsClient $stepfunctions;
    private BedrockClient $bedrock;
    private EcsClient $ecs;

    public function __construct(string $baseUrl = self::DEFAULT_BASE_URL)
    {
        $this->http = new HttpTransport($baseUrl);
        $this->lambda = new LambdaClient($this->http);
        $this->rds = new RdsClient($this->http);
        $this->elasticache = new ElastiCacheClient($this->http);
        $this->ecr = new EcrClient($this->http);
        $this->ses = new SesClient($this->http);
        $this->sns = new SnsClient($this->http);
        $this->sqs = new SqsClient($this->http);
        $this->events = new EventsClient($this->http);
        $this->scheduler = new SchedulerClient($this->http);
        $this->s3 = new S3Client($this->http);
        $this->dynamodb = new DynamoDbClient($this->http);
        $this->secretsmanager = new SecretsManagerClient($this->http);
        $this->cognito = new CognitoClient($this->http);
        $this->apigatewayv2 = new ApiGatewayV2Client($this->http);
        $this->stepfunctions = new StepFunctionsClient($this->http);
        $this->bedrock = new BedrockClient($this->http);
        $this->ecs = new EcsClient($this->http);
    }

    public function baseUrl(): string
    {
        return $this->http->baseUrl();
    }

    // ── Health & Reset ─────────────────────────────────────────────

    public function health(): HealthResponse
    {
        return HealthResponse::fromArray($this->http->get('/_fakecloud/health'));
    }

    public function reset(): ResetResponse
    {
        return ResetResponse::fromArray($this->http->postEmpty('/_reset'));
    }

    public function resetService(string $service): ResetServiceResponse
    {
        return ResetServiceResponse::fromArray(
            $this->http->postEmpty('/_fakecloud/reset/' . HttpTransport::encodePath($service))
        );
    }

    // ── IAM ───────────────────────────────────────────────────────

    public function createAdmin(string $accountId, string $userName): CreateAdminResponse
    {
        return CreateAdminResponse::fromArray(
            $this->http->postJson('/_fakecloud/iam/create-admin', [
                'accountId' => $accountId,
                'userName' => $userName,
            ])
        );
    }

    // ── Sub-client accessors ───────────────────────────────────────

    public function lambda(): LambdaClient { return $this->lambda; }
    public function rds(): RdsClient { return $this->rds; }
    public function elasticache(): ElastiCacheClient { return $this->elasticache; }
    public function ecr(): EcrClient { return $this->ecr; }
    public function ses(): SesClient { return $this->ses; }
    public function sns(): SnsClient { return $this->sns; }
    public function sqs(): SqsClient { return $this->sqs; }
    public function events(): EventsClient { return $this->events; }

    public function scheduler(): SchedulerClient { return $this->scheduler; }
    public function s3(): S3Client { return $this->s3; }
    public function dynamodb(): DynamoDbClient { return $this->dynamodb; }
    public function secretsmanager(): SecretsManagerClient { return $this->secretsmanager; }
    public function cognito(): CognitoClient { return $this->cognito; }
    public function apigatewayv2(): ApiGatewayV2Client { return $this->apigatewayv2; }
    public function stepfunctions(): StepFunctionsClient { return $this->stepfunctions; }
    public function bedrock(): BedrockClient { return $this->bedrock; }
    public function ecs(): EcsClient { return $this->ecs; }
}

// ── Sub-clients ────────────────────────────────────────────────

final class LambdaClient
{
    public function __construct(private readonly HttpTransport $http) {}

    public function getInvocations(): LambdaInvocationsResponse
    {
        return LambdaInvocationsResponse::fromArray(
            $this->http->get('/_fakecloud/lambda/invocations')
        );
    }

    public function getWarmContainers(): WarmContainersResponse
    {
        return WarmContainersResponse::fromArray(
            $this->http->get('/_fakecloud/lambda/warm-containers')
        );
    }

    public function evictContainer(string $functionName): EvictContainerResponse
    {
        return EvictContainerResponse::fromArray(
            $this->http->postEmpty('/_fakecloud/lambda/' . HttpTransport::encodePath($functionName) . '/evict-container')
        );
    }
}

final class RdsClient
{
    public function __construct(private readonly HttpTransport $http) {}

    public function getInstances(): RdsInstancesResponse
    {
        return RdsInstancesResponse::fromArray(
            $this->http->get('/_fakecloud/rds/instances')
        );
    }
}

final class ElastiCacheClient
{
    public function __construct(private readonly HttpTransport $http) {}

    public function getClusters(): ElastiCacheClustersResponse
    {
        return ElastiCacheClustersResponse::fromArray(
            $this->http->get('/_fakecloud/elasticache/clusters')
        );
    }

    public function getReplicationGroups(): ElastiCacheReplicationGroupsResponse
    {
        return ElastiCacheReplicationGroupsResponse::fromArray(
            $this->http->get('/_fakecloud/elasticache/replication-groups')
        );
    }

    public function getServerlessCaches(): ElastiCacheServerlessCachesResponse
    {
        return ElastiCacheServerlessCachesResponse::fromArray(
            $this->http->get('/_fakecloud/elasticache/serverless-caches')
        );
    }
}

final class EcrClient
{
    public function __construct(private readonly HttpTransport $http) {}

    public function getRepositories(): EcrRepositoriesResponse
    {
        return EcrRepositoriesResponse::fromArray(
            $this->http->get('/_fakecloud/ecr/repositories')
        );
    }

    public function getImages(?string $repositoryName = null): EcrImagesResponse
    {
        $path = '/_fakecloud/ecr/images';
        if ($repositoryName !== null) {
            $path .= '?repo=' . rawurlencode($repositoryName);
        }
        return EcrImagesResponse::fromArray($this->http->get($path));
    }

    public function getPullThroughRules(): EcrPullThroughRulesResponse
    {
        return EcrPullThroughRulesResponse::fromArray(
            $this->http->get('/_fakecloud/ecr/pull-through-rules')
        );
    }
}

final class SesClient
{
    public function __construct(private readonly HttpTransport $http) {}

    public function getEmails(): SesEmailsResponse
    {
        return SesEmailsResponse::fromArray(
            $this->http->get('/_fakecloud/ses/emails')
        );
    }

    public function simulateInbound(InboundEmailRequest $req): InboundEmailResponse
    {
        return InboundEmailResponse::fromArray(
            $this->http->postJson('/_fakecloud/ses/inbound', $req->toArray())
        );
    }
}

final class SnsClient
{
    public function __construct(private readonly HttpTransport $http) {}

    public function getMessages(): SnsMessagesResponse
    {
        return SnsMessagesResponse::fromArray(
            $this->http->get('/_fakecloud/sns/messages')
        );
    }

    public function getPendingConfirmations(): PendingConfirmationsResponse
    {
        return PendingConfirmationsResponse::fromArray(
            $this->http->get('/_fakecloud/sns/pending-confirmations')
        );
    }

    public function confirmSubscription(ConfirmSubscriptionRequest $req): ConfirmSubscriptionResponse
    {
        return ConfirmSubscriptionResponse::fromArray(
            $this->http->postJson('/_fakecloud/sns/confirm-subscription', $req->toArray())
        );
    }
}

final class SqsClient
{
    public function __construct(private readonly HttpTransport $http) {}

    public function getMessages(): SqsMessagesResponse
    {
        return SqsMessagesResponse::fromArray(
            $this->http->get('/_fakecloud/sqs/messages')
        );
    }

    public function tickExpiration(): ExpirationTickResponse
    {
        return ExpirationTickResponse::fromArray(
            $this->http->postEmpty('/_fakecloud/sqs/expiration-processor/tick')
        );
    }

    public function forceDlq(string $queueName): ForceDlqResponse
    {
        return ForceDlqResponse::fromArray(
            $this->http->postEmpty('/_fakecloud/sqs/' . HttpTransport::encodePath($queueName) . '/force-dlq')
        );
    }
}

final class EventsClient
{
    public function __construct(private readonly HttpTransport $http) {}

    public function getHistory(): EventHistoryResponse
    {
        return EventHistoryResponse::fromArray(
            $this->http->get('/_fakecloud/events/history')
        );
    }

    public function fireRule(FireRuleRequest $req): FireRuleResponse
    {
        return FireRuleResponse::fromArray(
            $this->http->postJson('/_fakecloud/events/fire-rule', $req->toArray())
        );
    }
}

final class SchedulerClient
{
    public function __construct(private readonly HttpTransport $http) {}

    public function getSchedules(): SchedulerSchedulesResponse
    {
        return SchedulerSchedulesResponse::fromArray(
            $this->http->get('/_fakecloud/scheduler/schedules')
        );
    }

    public function fireSchedule(string $group, string $name): FireScheduleResponse
    {
        return FireScheduleResponse::fromArray(
            $this->http->postEmpty("/_fakecloud/scheduler/fire/{$group}/{$name}")
        );
    }
}

final class S3Client
{
    public function __construct(private readonly HttpTransport $http) {}

    public function getNotifications(): S3NotificationsResponse
    {
        return S3NotificationsResponse::fromArray(
            $this->http->get('/_fakecloud/s3/notifications')
        );
    }

    public function tickLifecycle(): LifecycleTickResponse
    {
        return LifecycleTickResponse::fromArray(
            $this->http->postEmpty('/_fakecloud/s3/lifecycle-processor/tick')
        );
    }
}

final class DynamoDbClient
{
    public function __construct(private readonly HttpTransport $http) {}

    public function tickTtl(): TtlTickResponse
    {
        return TtlTickResponse::fromArray(
            $this->http->postEmpty('/_fakecloud/dynamodb/ttl-processor/tick')
        );
    }
}

final class SecretsManagerClient
{
    public function __construct(private readonly HttpTransport $http) {}

    public function tickRotation(): RotationTickResponse
    {
        return RotationTickResponse::fromArray(
            $this->http->postEmpty('/_fakecloud/secretsmanager/rotation-scheduler/tick')
        );
    }
}

final class CognitoClient
{
    public function __construct(private readonly HttpTransport $http) {}

    public function getUserCodes(string $poolId, string $username): UserConfirmationCodes
    {
        return UserConfirmationCodes::fromArray(
            $this->http->get(
                '/_fakecloud/cognito/confirmation-codes/'
                . HttpTransport::encodePath($poolId)
                . '/'
                . HttpTransport::encodePath($username)
            )
        );
    }

    public function getConfirmationCodes(): ConfirmationCodesResponse
    {
        return ConfirmationCodesResponse::fromArray(
            $this->http->get('/_fakecloud/cognito/confirmation-codes')
        );
    }

    /**
     * Force-confirm a user, bypassing the confirmation code flow.
     *
     * fakecloud returns a JSON body with an `error` field on 404 for unknown users,
     * so we decode the body and surface it as a FakeCloudError.
     */
    public function confirmUser(ConfirmUserRequest $req): ConfirmUserResponse
    {
        $payload = json_encode($req->toArray(), JSON_THROW_ON_ERROR);
        $response = $this->http->execute('POST', '/_fakecloud/cognito/confirm-user', $payload, 'application/json');

        if ($response['status'] === 404) {
            $parsed = ConfirmUserResponse::fromArray(json_decode($response['body'], true, 512, JSON_THROW_ON_ERROR));
            throw new FakeCloudError(404, $parsed->error ?? 'user not found');
        }
        if ($response['status'] < 200 || $response['status'] >= 300) {
            throw new FakeCloudError($response['status'], $response['body']);
        }

        return ConfirmUserResponse::fromArray(json_decode($response['body'], true, 512, JSON_THROW_ON_ERROR));
    }

    public function getTokens(): TokensResponse
    {
        return TokensResponse::fromArray(
            $this->http->get('/_fakecloud/cognito/tokens')
        );
    }

    public function expireTokens(ExpireTokensRequest $req): ExpireTokensResponse
    {
        return ExpireTokensResponse::fromArray(
            $this->http->postJson('/_fakecloud/cognito/expire-tokens', $req->toArray())
        );
    }

    public function getAuthEvents(): AuthEventsResponse
    {
        return AuthEventsResponse::fromArray(
            $this->http->get('/_fakecloud/cognito/auth-events')
        );
    }
}

final class ApiGatewayV2Client
{
    public function __construct(private readonly HttpTransport $http) {}

    public function getRequests(): ApiGatewayV2RequestsResponse
    {
        return ApiGatewayV2RequestsResponse::fromArray(
            $this->http->get('/_fakecloud/apigatewayv2/requests')
        );
    }
}

final class StepFunctionsClient
{
    public function __construct(private readonly HttpTransport $http) {}

    public function getExecutions(): StepFunctionsExecutionsResponse
    {
        return StepFunctionsExecutionsResponse::fromArray(
            $this->http->get('/_fakecloud/stepfunctions/executions')
        );
    }
}

final class BedrockClient
{
    public function __construct(private readonly HttpTransport $http) {}

    public function getInvocations(): BedrockInvocationsResponse
    {
        return BedrockInvocationsResponse::fromArray(
            $this->http->get('/_fakecloud/bedrock/invocations')
        );
    }

    public function setModelResponse(string $modelId, string $response): BedrockModelResponseConfig
    {
        return BedrockModelResponseConfig::fromArray(
            $this->http->postText(
                '/_fakecloud/bedrock/models/' . HttpTransport::encodePath($modelId) . '/response',
                $response
            )
        );
    }

    /**
     * @param BedrockResponseRule[] $rules
     */
    public function setResponseRules(string $modelId, array $rules): BedrockModelResponseConfig
    {
        return BedrockModelResponseConfig::fromArray(
            $this->http->postJson(
                '/_fakecloud/bedrock/models/' . HttpTransport::encodePath($modelId) . '/responses',
                ['rules' => array_map(fn(BedrockResponseRule $r) => $r->toArray(), $rules)]
            )
        );
    }

    public function clearResponseRules(string $modelId): BedrockModelResponseConfig
    {
        return BedrockModelResponseConfig::fromArray(
            $this->http->delete('/_fakecloud/bedrock/models/' . HttpTransport::encodePath($modelId) . '/responses')
        );
    }

    public function queueFault(BedrockFaultRule $rule): BedrockStatusResponse
    {
        return BedrockStatusResponse::fromArray(
            $this->http->postJson('/_fakecloud/bedrock/faults', $rule->toArray())
        );
    }

    public function getFaults(): BedrockFaultsResponse
    {
        return BedrockFaultsResponse::fromArray(
            $this->http->get('/_fakecloud/bedrock/faults')
        );
    }

    public function clearFaults(): BedrockStatusResponse
    {
        return BedrockStatusResponse::fromArray(
            $this->http->delete('/_fakecloud/bedrock/faults')
        );
    }
}

final class EcsClient
{
    public function __construct(private readonly HttpTransport $http) {}

    public function getClusters(): EcsClustersResponse
    {
        return EcsClustersResponse::fromArray(
            $this->http->get('/_fakecloud/ecs/clusters')
        );
    }
}
