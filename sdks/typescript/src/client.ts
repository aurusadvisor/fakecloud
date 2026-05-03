import type {
  CreateAdminResponse,
  ApiGatewayV2RequestsResponse,
  BedrockFaultRule,
  BedrockFaultsResponse,
  BedrockInvocationsResponse,
  BedrockModelResponseConfig,
  BedrockResponseRule,
  BedrockStatusResponse,
  HealthResponse,
  ResetResponse,
  ResetServiceResponse,
  RdsInstancesResponse,
  ElastiCacheClustersResponse,
  ElastiCacheReplicationGroupsResponse,
  ElastiCacheServerlessCachesResponse,
  EcrRepositoriesResponse,
  EcrImagesResponse,
  EcrPullThroughRulesResponse,
  LambdaInvocationsResponse,
  WarmContainersResponse,
  EvictContainerResponse,
  SesEmailsResponse,
  InboundEmailRequest,
  InboundEmailResponse,
  SnsMessagesResponse,
  PendingConfirmationsResponse,
  ConfirmSubscriptionRequest,
  ConfirmSubscriptionResponse,
  SqsMessagesResponse,
  ExpirationTickResponse,
  ForceDlqResponse,
  EventHistoryResponse,
  FireRuleRequest,
  FireRuleResponse,
  FireScheduleResponse,
  SchedulerSchedulesResponse,
  S3NotificationsResponse,
  LifecycleTickResponse,
  TtlTickResponse,
  RotationTickResponse,
  UserConfirmationCodes,
  ConfirmationCodesResponse,
  ConfirmUserRequest,
  ConfirmUserResponse,
  TokensResponse,
  ExpireTokensRequest,
  ExpireTokensResponse,
  AuthEventsResponse,
  StepFunctionsExecutionsResponse,
  EcsClustersResponse,
  Elbv2LoadBalancersResponse,
  Elbv2TargetGroupsResponse,
  Elbv2ListenersResponse,
  Elbv2RulesResponse,
} from "./types.js";

export class FakeCloudError extends Error {
  constructor(
    public readonly status: number,
    public readonly body: string,
  ) {
    super(`fakecloud API error (${status}): ${body}`);
    this.name = "FakeCloudError";
  }
}

async function parse<T>(resp: Response): Promise<T> {
  if (!resp.ok) {
    const body = await resp.text().catch(() => "");
    throw new FakeCloudError(resp.status, body);
  }
  return resp.json() as Promise<T>;
}

// ── Sub-clients ────────────────────────────────────────────────────

export class LambdaClient {
  constructor(private baseUrl: string) {}

  async getInvocations(): Promise<LambdaInvocationsResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/lambda/invocations`);
    return parse(resp);
  }

  async getWarmContainers(): Promise<WarmContainersResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/lambda/warm-containers`,
    );
    return parse(resp);
  }

  async evictContainer(functionName: string): Promise<EvictContainerResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/lambda/${encodeURIComponent(functionName)}/evict-container`,
      { method: "POST" },
    );
    return parse(resp);
  }
}

export class RdsClient {
  constructor(private baseUrl: string) {}

  async getInstances(): Promise<RdsInstancesResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/rds/instances`);
    return parse(resp);
  }
}

export class ElastiCacheClient {
  constructor(private baseUrl: string) {}

  async getClusters(): Promise<ElastiCacheClustersResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/elasticache/clusters`);
    return parse(resp);
  }

  async getReplicationGroups(): Promise<ElastiCacheReplicationGroupsResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/elasticache/replication-groups`,
    );
    return parse(resp);
  }

  async getServerlessCaches(): Promise<ElastiCacheServerlessCachesResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/elasticache/serverless-caches`,
    );
    return parse(resp);
  }
}

export class EcrClient {
  constructor(private baseUrl: string) {}

  async getRepositories(): Promise<EcrRepositoriesResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/ecr/repositories`);
    return parse(resp);
  }

  async getImages(repositoryName?: string): Promise<EcrImagesResponse> {
    const url = repositoryName
      ? `${this.baseUrl}/_fakecloud/ecr/images?repo=${encodeURIComponent(repositoryName)}`
      : `${this.baseUrl}/_fakecloud/ecr/images`;
    const resp = await fetch(url);
    return parse(resp);
  }

  async getPullThroughRules(): Promise<EcrPullThroughRulesResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/ecr/pull-through-rules`,
    );
    return parse(resp);
  }
}

export class SesClient {
  constructor(private baseUrl: string) {}

  async getEmails(): Promise<SesEmailsResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/ses/emails`);
    return parse(resp);
  }

  async simulateInbound(
    req: InboundEmailRequest,
  ): Promise<InboundEmailResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/ses/inbound`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
    });
    return parse(resp);
  }
}

export class SnsClient {
  constructor(private baseUrl: string) {}

  async getMessages(): Promise<SnsMessagesResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/sns/messages`);
    return parse(resp);
  }

  async getPendingConfirmations(): Promise<PendingConfirmationsResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/sns/pending-confirmations`,
    );
    return parse(resp);
  }

  async confirmSubscription(
    req: ConfirmSubscriptionRequest,
  ): Promise<ConfirmSubscriptionResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/sns/confirm-subscription`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      },
    );
    return parse(resp);
  }
}

export class SqsClient {
  constructor(private baseUrl: string) {}

  async getMessages(): Promise<SqsMessagesResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/sqs/messages`);
    return parse(resp);
  }

  async tickExpiration(): Promise<ExpirationTickResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/sqs/expiration-processor/tick`,
      { method: "POST" },
    );
    return parse(resp);
  }

  async forceDlq(queueName: string): Promise<ForceDlqResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/sqs/${encodeURIComponent(queueName)}/force-dlq`,
      { method: "POST" },
    );
    return parse(resp);
  }
}

export class EventsClient {
  constructor(private baseUrl: string) {}

  async getHistory(): Promise<EventHistoryResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/events/history`);
    return parse(resp);
  }

  async fireRule(req: FireRuleRequest): Promise<FireRuleResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/events/fire-rule`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(req),
    });
    return parse(resp);
  }
}

export class SchedulerClient {
  constructor(private baseUrl: string) {}

  async getSchedules(): Promise<SchedulerSchedulesResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/scheduler/schedules`);
    return parse(resp);
  }

  async fireSchedule(
    group: string,
    name: string,
  ): Promise<FireScheduleResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/scheduler/fire/${encodeURIComponent(group)}/${encodeURIComponent(name)}`,
      { method: "POST" },
    );
    return parse(resp);
  }
}

export class S3Client {
  constructor(private baseUrl: string) {}

  async getNotifications(): Promise<S3NotificationsResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/s3/notifications`);
    return parse(resp);
  }

  async tickLifecycle(): Promise<LifecycleTickResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/s3/lifecycle-processor/tick`,
      { method: "POST" },
    );
    return parse(resp);
  }
}

export class DynamoDbClient {
  constructor(private baseUrl: string) {}

  async tickTtl(): Promise<TtlTickResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/dynamodb/ttl-processor/tick`,
      { method: "POST" },
    );
    return parse(resp);
  }
}

export class SecretsManagerClient {
  constructor(private baseUrl: string) {}

  async tickRotation(): Promise<RotationTickResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/secretsmanager/rotation-scheduler/tick`,
      { method: "POST" },
    );
    return parse(resp);
  }
}

export class CognitoClient {
  constructor(private baseUrl: string) {}

  async getUserCodes(
    poolId: string,
    username: string,
  ): Promise<UserConfirmationCodes> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/cognito/confirmation-codes/${encodeURIComponent(poolId)}/${encodeURIComponent(username)}`,
    );
    return parse(resp);
  }

  async getConfirmationCodes(): Promise<ConfirmationCodesResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/cognito/confirmation-codes`,
    );
    return parse(resp);
  }

  async confirmUser(req: ConfirmUserRequest): Promise<ConfirmUserResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/cognito/confirm-user`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      },
    );
    // This endpoint returns 404 for missing users but still has a JSON body
    if (resp.status === 404) {
      const body: ConfirmUserResponse = await resp.json();
      throw new FakeCloudError(404, body.error ?? "user not found");
    }
    return parse(resp);
  }

  async getTokens(): Promise<TokensResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/cognito/tokens`);
    return parse(resp);
  }

  async expireTokens(req: ExpireTokensRequest): Promise<ExpireTokensResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/cognito/expire-tokens`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      },
    );
    return parse(resp);
  }

  async getAuthEvents(): Promise<AuthEventsResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/cognito/auth-events`);
    return parse(resp);
  }
}

export class ApiGatewayV2Client {
  constructor(private readonly baseUrl: string) {}

  async getRequests(): Promise<ApiGatewayV2RequestsResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/apigatewayv2/requests`,
    );
    return parse(resp);
  }
}

export class StepFunctionsClient {
  constructor(private readonly baseUrl: string) {}

  async getExecutions(): Promise<StepFunctionsExecutionsResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/stepfunctions/executions`,
    );
    return parse(resp);
  }
}

export class BedrockClient {
  constructor(private readonly baseUrl: string) {}

  async getInvocations(): Promise<BedrockInvocationsResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/bedrock/invocations`);
    return parse(resp);
  }

  async setModelResponse(
    modelId: string,
    response: string,
  ): Promise<BedrockModelResponseConfig> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/bedrock/models/${encodeURIComponent(modelId)}/response`,
      {
        method: "POST",
        headers: { "Content-Type": "text/plain" },
        body: response,
      },
    );
    return parse(resp);
  }

  /** Replace the prompt-conditional response rules for a given model. */
  async setResponseRules(
    modelId: string,
    rules: BedrockResponseRule[],
  ): Promise<BedrockModelResponseConfig> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/bedrock/models/${encodeURIComponent(modelId)}/responses`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ rules }),
      },
    );
    return parse(resp);
  }

  /** Clear all prompt-conditional response rules for a given model. */
  async clearResponseRules(
    modelId: string,
  ): Promise<BedrockModelResponseConfig> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/bedrock/models/${encodeURIComponent(modelId)}/responses`,
      { method: "DELETE" },
    );
    return parse(resp);
  }

  /** Queue a fault rule that will cause the next matching Bedrock runtime call(s) to fail. */
  async queueFault(rule: BedrockFaultRule): Promise<BedrockStatusResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/bedrock/faults`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(rule),
    });
    return parse(resp);
  }

  /** List currently queued fault rules. */
  async getFaults(): Promise<BedrockFaultsResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/bedrock/faults`);
    return parse(resp);
  }

  /** Clear all queued fault rules. */
  async clearFaults(): Promise<BedrockStatusResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/bedrock/faults`, {
      method: "DELETE",
    });
    return parse(resp);
  }
}

// ── Main client ────────────────────────────────────────────────────

export class FakeCloud {
  private readonly baseUrl: string;

  private readonly _lambda: LambdaClient;
  private readonly _rds: RdsClient;
  private readonly _elasticache: ElastiCacheClient;
  private readonly _ecr: EcrClient;
  private readonly _ses: SesClient;
  private readonly _sns: SnsClient;
  private readonly _sqs: SqsClient;
  private readonly _events: EventsClient;
  private readonly _scheduler: SchedulerClient;
  private readonly _s3: S3Client;
  private readonly _dynamodb: DynamoDbClient;
  private readonly _secretsmanager: SecretsManagerClient;
  private readonly _cognito: CognitoClient;
  private readonly _apigatewayv2: ApiGatewayV2Client;
  private readonly _stepfunctions: StepFunctionsClient;
  private readonly _bedrock: BedrockClient;
  private readonly _ecs: EcsClient;
  private readonly _elbv2: Elbv2Client;
  private readonly _route53: Route53Client;
  private readonly _acm: AcmClient;

  constructor(baseUrl: string = "http://localhost:4566") {
    this.baseUrl = baseUrl.replace(/\/+$/, "");

    this._lambda = new LambdaClient(this.baseUrl);
    this._rds = new RdsClient(this.baseUrl);
    this._elasticache = new ElastiCacheClient(this.baseUrl);
    this._ecr = new EcrClient(this.baseUrl);
    this._ses = new SesClient(this.baseUrl);
    this._sns = new SnsClient(this.baseUrl);
    this._sqs = new SqsClient(this.baseUrl);
    this._events = new EventsClient(this.baseUrl);
    this._scheduler = new SchedulerClient(this.baseUrl);
    this._s3 = new S3Client(this.baseUrl);
    this._dynamodb = new DynamoDbClient(this.baseUrl);
    this._secretsmanager = new SecretsManagerClient(this.baseUrl);
    this._cognito = new CognitoClient(this.baseUrl);
    this._apigatewayv2 = new ApiGatewayV2Client(this.baseUrl);
    this._stepfunctions = new StepFunctionsClient(this.baseUrl);
    this._bedrock = new BedrockClient(this.baseUrl);
    this._ecs = new EcsClient(this.baseUrl);
    this._elbv2 = new Elbv2Client(this.baseUrl);
    this._route53 = new Route53Client(this.baseUrl);
    this._acm = new AcmClient(this.baseUrl);
  }

  // ── Health & Reset ─────────────────────────────────────────────

  async health(): Promise<HealthResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/health`);
    return parse(resp);
  }

  async reset(): Promise<ResetResponse> {
    const resp = await fetch(`${this.baseUrl}/_reset`, { method: "POST" });
    return parse(resp);
  }

  async resetService(service: string): Promise<ResetServiceResponse> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/reset/${encodeURIComponent(service)}`,
      { method: "POST" },
    );
    return parse(resp);
  }

  // ── IAM ────────────────────────────────────────────────────────

  async createAdmin(
    accountId: string,
    userName: string,
  ): Promise<CreateAdminResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/iam/create-admin`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ accountId, userName }),
    });
    return parse(resp);
  }

  // ── Sub-clients ────────────────────────────────────────────────

  get lambda(): LambdaClient {
    return this._lambda;
  }

  get rds(): RdsClient {
    return this._rds;
  }

  get elasticache(): ElastiCacheClient {
    return this._elasticache;
  }

  get ecr(): EcrClient {
    return this._ecr;
  }

  get ses(): SesClient {
    return this._ses;
  }

  get sns(): SnsClient {
    return this._sns;
  }

  get sqs(): SqsClient {
    return this._sqs;
  }

  get events(): EventsClient {
    return this._events;
  }

  get scheduler(): SchedulerClient {
    return this._scheduler;
  }

  get s3(): S3Client {
    return this._s3;
  }

  get dynamodb(): DynamoDbClient {
    return this._dynamodb;
  }

  get secretsmanager(): SecretsManagerClient {
    return this._secretsmanager;
  }

  get cognito(): CognitoClient {
    return this._cognito;
  }

  get apigatewayv2(): ApiGatewayV2Client {
    return this._apigatewayv2;
  }

  get stepfunctions(): StepFunctionsClient {
    return this._stepfunctions;
  }

  get bedrock(): BedrockClient {
    return this._bedrock;
  }

  get ecs(): EcsClient {
    return this._ecs;
  }

  get elbv2(): Elbv2Client {
    return this._elbv2;
  }

  get route53(): Route53Client {
    return this._route53;
  }

  get acm(): AcmClient {
    return this._acm;
  }
}

export class EcsClient {
  constructor(private baseUrl: string) {}

  /** List every ECS cluster fakecloud has seen, across every account. */
  async getClusters(): Promise<EcsClustersResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/ecs/clusters`);
    return parse(resp);
  }
}

export class Elbv2Client {
  constructor(private baseUrl: string) {}

  /** List every ELBv2 load balancer fakecloud has seen, across every account. */
  async getLoadBalancers(): Promise<Elbv2LoadBalancersResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/elbv2/load-balancers`);
    return parse(resp);
  }

  async getTargetGroups(): Promise<Elbv2TargetGroupsResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/elbv2/target-groups`);
    return parse(resp);
  }

  async getListeners(): Promise<Elbv2ListenersResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/elbv2/listeners`);
    return parse(resp);
  }

  async getRules(): Promise<Elbv2RulesResponse> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/elbv2/rules`);
    return parse(resp);
  }

  /**
   * Force every buffered ALB access-log + connection-log line to flush
   * to S3 right now, bypassing the periodic 60-second timer. Useful in
   * tests that need to assert log delivery without waiting.
   */
  async flushAccessLogs(): Promise<{ flushed: boolean }> {
    const resp = await fetch(`${this.baseUrl}/_fakecloud/elbv2/access-logs/flush`, {
      method: "POST",
    });
    return parse(resp);
  }
}

/** Body for `route53.setHealthCheckStatus`. */
export interface SetHealthCheckStatusRequest {
  /** "Success" or "Failure". */
  status: "Success" | "Failure";
  /** Optional reason appended to the `<Status>` element on Failure. */
  reason?: string;
}

/**
 * Route 53 admin client.
 *
 * Wraps the per-health-check status admin endpoint that lets tests flip a
 * stored health check between healthy and unhealthy without a live prober,
 * so failover and multi-value routing can be exercised end-to-end.
 */
export class Route53Client {
  constructor(private baseUrl: string) {}

  async setHealthCheckStatus(
    healthCheckId: string,
    req: SetHealthCheckStatusRequest,
  ): Promise<void> {
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/route53/health-checks/${encodeURIComponent(
        healthCheckId,
      )}/status`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      },
    );
    if (!resp.ok) {
      const body = await resp.text().catch(() => "");
      throw new FakeCloudError(resp.status, body);
    }
  }
}

/** Body for `acm.setCertificateStatus`. */
export interface SetCertificateStatusRequest {
  /** New certificate status. */
  status: "ISSUED" | "FAILED" | "VALIDATION_TIMED_OUT" | string;
  /** Optional reason recorded as `FailureReason` for non-ISSUED states. */
  reason?: string;
}

/**
 * ACM admin client.
 *
 * Wraps the per-certificate status admin endpoint that lets tests flip
 * a stored certificate between PENDING_VALIDATION, ISSUED, FAILED, and
 * VALIDATION_TIMED_OUT without waiting on the auto-issue tick, so
 * validation-failure flows can be exercised end-to-end.
 */
export class AcmClient {
  constructor(private baseUrl: string) {}

  /**
   * Flip an ACM certificate's status synchronously. `arnOrId` accepts
   * either the full ACM ARN or the trailing UUID portion; full ARNs
   * are reduced to their UUID before being embedded in the URL.
   */
  async setCertificateStatus(
    arnOrId: string,
    req: SetCertificateStatusRequest,
  ): Promise<void> {
    const idx = arnOrId.lastIndexOf("certificate/");
    const id =
      idx >= 0 ? arnOrId.substring(idx + "certificate/".length) : arnOrId;
    const resp = await fetch(
      `${this.baseUrl}/_fakecloud/acm/certificates/${encodeURIComponent(id)}/status`,
      {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
      },
    );
    if (!resp.ok) {
      const body = await resp.text().catch(() => "");
      throw new FakeCloudError(resp.status, body);
    }
  }
}
