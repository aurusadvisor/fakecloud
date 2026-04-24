package dev.fakecloud;

import static dev.fakecloud.HttpTransport.encodePath;

import dev.fakecloud.Types.ApiGatewayV2RequestsResponse;
import dev.fakecloud.Types.AuthEventsResponse;
import dev.fakecloud.Types.BedrockFaultRule;
import dev.fakecloud.Types.BedrockFaultsResponse;
import dev.fakecloud.Types.BedrockInvocationsResponse;
import dev.fakecloud.Types.BedrockModelResponseConfig;
import dev.fakecloud.Types.BedrockResponseRule;
import dev.fakecloud.Types.BedrockStatusResponse;
import dev.fakecloud.Types.CreateAdminRequest;
import dev.fakecloud.Types.CreateAdminResponse;
import dev.fakecloud.Types.ConfirmSubscriptionRequest;
import dev.fakecloud.Types.ConfirmSubscriptionResponse;
import dev.fakecloud.Types.ConfirmUserRequest;
import dev.fakecloud.Types.ConfirmUserResponse;
import dev.fakecloud.Types.ConfirmationCodesResponse;
import dev.fakecloud.Types.EcrImagesResponse;
import dev.fakecloud.Types.EcrPullThroughRulesResponse;
import dev.fakecloud.Types.EcrRepositoriesResponse;
import dev.fakecloud.Types.ElastiCacheClustersResponse;
import dev.fakecloud.Types.ElastiCacheReplicationGroupsResponse;
import dev.fakecloud.Types.ElastiCacheServerlessCachesResponse;
import dev.fakecloud.Types.EventHistoryResponse;
import dev.fakecloud.Types.EvictContainerResponse;
import dev.fakecloud.Types.ExpirationTickResponse;
import dev.fakecloud.Types.ExpireTokensRequest;
import dev.fakecloud.Types.ExpireTokensResponse;
import dev.fakecloud.Types.FireRuleRequest;
import dev.fakecloud.Types.FireRuleResponse;
import dev.fakecloud.Types.ForceDlqResponse;
import dev.fakecloud.Types.HealthResponse;
import dev.fakecloud.Types.InboundEmailRequest;
import dev.fakecloud.Types.InboundEmailResponse;
import dev.fakecloud.Types.LambdaInvocationsResponse;
import dev.fakecloud.Types.LifecycleTickResponse;
import dev.fakecloud.Types.PendingConfirmationsResponse;
import dev.fakecloud.Types.RdsInstancesResponse;
import dev.fakecloud.Types.ResetResponse;
import dev.fakecloud.Types.ResetServiceResponse;
import dev.fakecloud.Types.RotationTickResponse;
import dev.fakecloud.Types.S3NotificationsResponse;
import dev.fakecloud.Types.SesEmailsResponse;
import dev.fakecloud.Types.SnsMessagesResponse;
import dev.fakecloud.Types.SqsMessagesResponse;
import dev.fakecloud.Types.StepFunctionsExecutionsResponse;
import dev.fakecloud.Types.TokensResponse;
import dev.fakecloud.Types.TtlTickResponse;
import dev.fakecloud.Types.UserConfirmationCodes;
import dev.fakecloud.Types.WarmContainersResponse;

import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.List;
import java.util.Map;

/**
 * Top-level client for the fakecloud introspection and simulation API.
 *
 * <pre>{@code
 * FakeCloud fc = new FakeCloud("http://localhost:4566");
 * fc.reset();
 * var emails = fc.ses().getEmails().emails();
 * }</pre>
 */
public final class FakeCloud {
    private static final String DEFAULT_BASE_URL = "http://localhost:4566";

    private final HttpTransport http;

    private final LambdaClient lambda;
    private final RdsClient rds;
    private final ElastiCacheClient elasticache;
    private final EcrClient ecr;
    private final SesClient ses;
    private final SnsClient sns;
    private final SqsClient sqs;
    private final EventsClient events;
    private final SchedulerClient scheduler;
    private final S3Client s3;
    private final DynamoDbClient dynamodb;
    private final SecretsManagerClient secretsmanager;
    private final CognitoClient cognito;
    private final ApiGatewayV2Client apigatewayv2;
    private final StepFunctionsClient stepfunctions;
    private final BedrockClient bedrock;

    public FakeCloud() {
        this(DEFAULT_BASE_URL);
    }

    public FakeCloud(String baseUrl) {
        this.http = new HttpTransport(trimTrailingSlashes(baseUrl));
        this.lambda = new LambdaClient(http);
        this.rds = new RdsClient(http);
        this.elasticache = new ElastiCacheClient(http);
        this.ecr = new EcrClient(http);
        this.ses = new SesClient(http);
        this.sns = new SnsClient(http);
        this.sqs = new SqsClient(http);
        this.events = new EventsClient(http);
        this.scheduler = new SchedulerClient(http);
        this.s3 = new S3Client(http);
        this.dynamodb = new DynamoDbClient(http);
        this.secretsmanager = new SecretsManagerClient(http);
        this.cognito = new CognitoClient(http);
        this.apigatewayv2 = new ApiGatewayV2Client(http);
        this.stepfunctions = new StepFunctionsClient(http);
        this.bedrock = new BedrockClient(http);
    }

    static String trimTrailingSlashes(String url) {
        int end = url.length();
        while (end > 0 && url.charAt(end - 1) == '/') {
            end--;
        }
        return url.substring(0, end);
    }

    public String baseUrl() {
        return http.baseUrl();
    }

    // ── Health & Reset ─────────────────────────────────────────────

    public HealthResponse health() {
        return http.get("/_fakecloud/health", HealthResponse.class);
    }

    public ResetResponse reset() {
        return http.postEmpty("/_reset", ResetResponse.class);
    }

    public ResetServiceResponse resetService(String service) {
        return http.postEmpty("/_fakecloud/reset/" + encodePath(service), ResetServiceResponse.class);
    }

    // ── IAM ───────────────────────────────────────────────────────

    public CreateAdminResponse createAdmin(String accountId, String userName) {
        return http.postJson(
                "/_fakecloud/iam/create-admin",
                new CreateAdminRequest(accountId, userName),
                CreateAdminResponse.class);
    }

    // ── Sub-client accessors ───────────────────────────────────────

    public LambdaClient lambda() { return lambda; }
    public RdsClient rds() { return rds; }
    public ElastiCacheClient elasticache() { return elasticache; }
    public EcrClient ecr() { return ecr; }
    public SesClient ses() { return ses; }
    public SnsClient sns() { return sns; }
    public SqsClient sqs() { return sqs; }
    public EventsClient events() { return events; }
    public SchedulerClient scheduler() { return scheduler; }
    public S3Client s3() { return s3; }
    public DynamoDbClient dynamodb() { return dynamodb; }
    public SecretsManagerClient secretsmanager() { return secretsmanager; }
    public CognitoClient cognito() { return cognito; }
    public ApiGatewayV2Client apigatewayv2() { return apigatewayv2; }
    public StepFunctionsClient stepfunctions() { return stepfunctions; }
    public BedrockClient bedrock() { return bedrock; }

    // ── Sub-clients ────────────────────────────────────────────────

    public static final class LambdaClient {
        private final HttpTransport http;
        LambdaClient(HttpTransport http) { this.http = http; }

        public LambdaInvocationsResponse getInvocations() {
            return http.get("/_fakecloud/lambda/invocations", LambdaInvocationsResponse.class);
        }

        public WarmContainersResponse getWarmContainers() {
            return http.get("/_fakecloud/lambda/warm-containers", WarmContainersResponse.class);
        }

        public EvictContainerResponse evictContainer(String functionName) {
            return http.postEmpty(
                    "/_fakecloud/lambda/" + encodePath(functionName) + "/evict-container",
                    EvictContainerResponse.class);
        }
    }

    public static final class RdsClient {
        private final HttpTransport http;
        RdsClient(HttpTransport http) { this.http = http; }

        public RdsInstancesResponse getInstances() {
            return http.get("/_fakecloud/rds/instances", RdsInstancesResponse.class);
        }
    }

    public static final class ElastiCacheClient {
        private final HttpTransport http;
        ElastiCacheClient(HttpTransport http) { this.http = http; }

        public ElastiCacheClustersResponse getClusters() {
            return http.get("/_fakecloud/elasticache/clusters", ElastiCacheClustersResponse.class);
        }

        public ElastiCacheReplicationGroupsResponse getReplicationGroups() {
            return http.get(
                    "/_fakecloud/elasticache/replication-groups",
                    ElastiCacheReplicationGroupsResponse.class);
        }

        public ElastiCacheServerlessCachesResponse getServerlessCaches() {
            return http.get(
                    "/_fakecloud/elasticache/serverless-caches",
                    ElastiCacheServerlessCachesResponse.class);
        }
    }

    public static final class EcrClient {
        private final HttpTransport http;
        EcrClient(HttpTransport http) { this.http = http; }

        public EcrRepositoriesResponse getRepositories() {
            return http.get("/_fakecloud/ecr/repositories", EcrRepositoriesResponse.class);
        }

        public EcrImagesResponse getImages() {
            return http.get("/_fakecloud/ecr/images", EcrImagesResponse.class);
        }

        public EcrImagesResponse getImagesForRepository(String repositoryName) {
            return http.get(
                    "/_fakecloud/ecr/images?repo="
                            + java.net.URLEncoder.encode(
                                    repositoryName, java.nio.charset.StandardCharsets.UTF_8),
                    EcrImagesResponse.class);
        }

        public EcrPullThroughRulesResponse getPullThroughRules() {
            return http.get(
                    "/_fakecloud/ecr/pull-through-rules", EcrPullThroughRulesResponse.class);
        }
    }

    public static final class SesClient {
        private final HttpTransport http;
        SesClient(HttpTransport http) { this.http = http; }

        public SesEmailsResponse getEmails() {
            return http.get("/_fakecloud/ses/emails", SesEmailsResponse.class);
        }

        public InboundEmailResponse simulateInbound(InboundEmailRequest req) {
            return http.postJson("/_fakecloud/ses/inbound", req, InboundEmailResponse.class);
        }
    }

    public static final class SnsClient {
        private final HttpTransport http;
        SnsClient(HttpTransport http) { this.http = http; }

        public SnsMessagesResponse getMessages() {
            return http.get("/_fakecloud/sns/messages", SnsMessagesResponse.class);
        }

        public PendingConfirmationsResponse getPendingConfirmations() {
            return http.get(
                    "/_fakecloud/sns/pending-confirmations", PendingConfirmationsResponse.class);
        }

        public ConfirmSubscriptionResponse confirmSubscription(ConfirmSubscriptionRequest req) {
            return http.postJson(
                    "/_fakecloud/sns/confirm-subscription", req, ConfirmSubscriptionResponse.class);
        }
    }

    public static final class SqsClient {
        private final HttpTransport http;
        SqsClient(HttpTransport http) { this.http = http; }

        public SqsMessagesResponse getMessages() {
            return http.get("/_fakecloud/sqs/messages", SqsMessagesResponse.class);
        }

        public ExpirationTickResponse tickExpiration() {
            return http.postEmpty(
                    "/_fakecloud/sqs/expiration-processor/tick", ExpirationTickResponse.class);
        }

        public ForceDlqResponse forceDlq(String queueName) {
            return http.postEmpty(
                    "/_fakecloud/sqs/" + encodePath(queueName) + "/force-dlq",
                    ForceDlqResponse.class);
        }
    }

    public static final class EventsClient {
        private final HttpTransport http;
        EventsClient(HttpTransport http) { this.http = http; }

        public EventHistoryResponse getHistory() {
            return http.get("/_fakecloud/events/history", EventHistoryResponse.class);
        }

        public FireRuleResponse fireRule(FireRuleRequest req) {
            return http.postJson("/_fakecloud/events/fire-rule", req, FireRuleResponse.class);
        }
    }

    public static final class SchedulerClient {
        private final HttpTransport http;
        SchedulerClient(HttpTransport http) { this.http = http; }

        public Types.SchedulerSchedulesResponse getSchedules() {
            return http.get(
                    "/_fakecloud/scheduler/schedules",
                    Types.SchedulerSchedulesResponse.class);
        }

        public Types.FireScheduleResponse fireSchedule(String group, String name) {
            return http.postEmpty(
                    "/_fakecloud/scheduler/fire/" + group + "/" + name,
                    Types.FireScheduleResponse.class);
        }
    }

    public static final class S3Client {
        private final HttpTransport http;
        S3Client(HttpTransport http) { this.http = http; }

        public S3NotificationsResponse getNotifications() {
            return http.get("/_fakecloud/s3/notifications", S3NotificationsResponse.class);
        }

        public LifecycleTickResponse tickLifecycle() {
            return http.postEmpty(
                    "/_fakecloud/s3/lifecycle-processor/tick", LifecycleTickResponse.class);
        }
    }

    public static final class DynamoDbClient {
        private final HttpTransport http;
        DynamoDbClient(HttpTransport http) { this.http = http; }

        public TtlTickResponse tickTtl() {
            return http.postEmpty("/_fakecloud/dynamodb/ttl-processor/tick", TtlTickResponse.class);
        }
    }

    public static final class SecretsManagerClient {
        private final HttpTransport http;
        SecretsManagerClient(HttpTransport http) { this.http = http; }

        public RotationTickResponse tickRotation() {
            return http.postEmpty(
                    "/_fakecloud/secretsmanager/rotation-scheduler/tick",
                    RotationTickResponse.class);
        }
    }

    public static final class CognitoClient {
        private final HttpTransport http;
        CognitoClient(HttpTransport http) { this.http = http; }

        public UserConfirmationCodes getUserCodes(String poolId, String username) {
            return http.get(
                    "/_fakecloud/cognito/confirmation-codes/"
                            + encodePath(poolId)
                            + "/"
                            + encodePath(username),
                    UserConfirmationCodes.class);
        }

        public ConfirmationCodesResponse getConfirmationCodes() {
            return http.get(
                    "/_fakecloud/cognito/confirmation-codes", ConfirmationCodesResponse.class);
        }

        /**
         * Force-confirm a user, bypassing the confirmation code flow.
         *
         * <p>Mirrors the TypeScript SDK's special-case: fakecloud returns a JSON body with an
         * {@code error} field on 404 for unknown users, so we decode the body and surface it
         * as a {@link FakeCloudError}.
         */
        public ConfirmUserResponse confirmUser(ConfirmUserRequest req) {
            HttpRequest.Builder builder = http.builder("/_fakecloud/cognito/confirm-user")
                    .header("Content-Type", "application/json");
            try {
                byte[] payload = new com.fasterxml.jackson.databind.ObjectMapper().writeValueAsBytes(req);
                builder.POST(HttpRequest.BodyPublishers.ofByteArray(payload));
            } catch (Exception e) {
                throw new FakeCloudError(-1, "failed to encode request: " + e.getMessage());
            }
            HttpResponse<byte[]> resp = http.execute(builder);
            ConfirmUserResponse parsed;
            try {
                parsed = new com.fasterxml.jackson.databind.ObjectMapper()
                        .readValue(resp.body(), ConfirmUserResponse.class);
            } catch (Exception e) {
                throw new FakeCloudError(
                        resp.statusCode(),
                        new String(resp.body(), java.nio.charset.StandardCharsets.UTF_8));
            }
            if (resp.statusCode() == 404) {
                throw new FakeCloudError(
                        404, parsed.error() != null ? parsed.error() : "user not found");
            }
            if (resp.statusCode() < 200 || resp.statusCode() >= 300) {
                throw new FakeCloudError(
                        resp.statusCode(),
                        new String(resp.body(), java.nio.charset.StandardCharsets.UTF_8));
            }
            return parsed;
        }

        public TokensResponse getTokens() {
            return http.get("/_fakecloud/cognito/tokens", TokensResponse.class);
        }

        public ExpireTokensResponse expireTokens(ExpireTokensRequest req) {
            return http.postJson(
                    "/_fakecloud/cognito/expire-tokens", req, ExpireTokensResponse.class);
        }

        public AuthEventsResponse getAuthEvents() {
            return http.get("/_fakecloud/cognito/auth-events", AuthEventsResponse.class);
        }
    }

    public static final class ApiGatewayV2Client {
        private final HttpTransport http;
        ApiGatewayV2Client(HttpTransport http) { this.http = http; }

        public ApiGatewayV2RequestsResponse getRequests() {
            return http.get(
                    "/_fakecloud/apigatewayv2/requests", ApiGatewayV2RequestsResponse.class);
        }
    }

    public static final class StepFunctionsClient {
        private final HttpTransport http;
        StepFunctionsClient(HttpTransport http) { this.http = http; }

        public StepFunctionsExecutionsResponse getExecutions() {
            return http.get(
                    "/_fakecloud/stepfunctions/executions",
                    StepFunctionsExecutionsResponse.class);
        }
    }

    public static final class BedrockClient {
        private final HttpTransport http;
        BedrockClient(HttpTransport http) { this.http = http; }

        public BedrockInvocationsResponse getInvocations() {
            return http.get("/_fakecloud/bedrock/invocations", BedrockInvocationsResponse.class);
        }

        public BedrockModelResponseConfig setModelResponse(String modelId, String response) {
            return http.postText(
                    "/_fakecloud/bedrock/models/" + encodePath(modelId) + "/response",
                    response,
                    BedrockModelResponseConfig.class);
        }

        public BedrockModelResponseConfig setResponseRules(
                String modelId, List<BedrockResponseRule> rules) {
            return http.postJson(
                    "/_fakecloud/bedrock/models/" + encodePath(modelId) + "/responses",
                    Map.of("rules", rules),
                    BedrockModelResponseConfig.class);
        }

        public BedrockModelResponseConfig clearResponseRules(String modelId) {
            return http.delete(
                    "/_fakecloud/bedrock/models/" + encodePath(modelId) + "/responses",
                    BedrockModelResponseConfig.class);
        }

        public BedrockStatusResponse queueFault(BedrockFaultRule rule) {
            return http.postJson("/_fakecloud/bedrock/faults", rule, BedrockStatusResponse.class);
        }

        public BedrockFaultsResponse getFaults() {
            return http.get("/_fakecloud/bedrock/faults", BedrockFaultsResponse.class);
        }

        public BedrockStatusResponse clearFaults() {
            return http.delete("/_fakecloud/bedrock/faults", BedrockStatusResponse.class);
        }
    }
}
