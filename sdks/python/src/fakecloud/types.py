"""Dataclass types matching the fakecloud introspection API responses."""

from __future__ import annotations

from dataclasses import dataclass, field, fields
from typing import Any, Dict, List, Optional


def _camel_to_snake(name: str) -> str:
    """Convert camelCase to snake_case."""
    import re

    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    s = re.sub(r"([a-z0-9])([A-Z])", r"\1_\2", s)
    return s.lower()


def _convert_keys(data: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively convert camelCase dict keys to snake_case."""
    result: Dict[str, Any] = {}
    for key, value in data.items():
        snake_key = _camel_to_snake(key)
        if isinstance(value, dict):
            value = _convert_keys(value)
        elif isinstance(value, list):
            value = [_convert_keys(v) if isinstance(v, dict) else v for v in value]
        result[snake_key] = value
    return result


# ── Health & Reset ──────────────────────────────────────────────────


@dataclass
class HealthResponse:
    status: str
    version: str
    services: List[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> HealthResponse:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class ResetResponse:
    status: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ResetResponse:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class ResetServiceResponse:
    reset: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ResetServiceResponse:
        d = _convert_keys(data)
        return cls(**d)


# ── RDS ─────────────────────────────────────────────────────────────


@dataclass
class RdsTag:
    key: str
    value: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RdsTag:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class RdsInstance:
    db_instance_identifier: str
    db_instance_arn: str
    db_instance_class: str
    engine: str
    engine_version: str
    db_instance_status: str
    master_username: str
    db_name: Optional[str]
    endpoint_address: str
    port: int
    allocated_storage: int
    publicly_accessible: bool
    deletion_protection: bool
    created_at: str
    dbi_resource_id: str
    container_id: str
    host_port: int
    tags: List[RdsTag]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RdsInstance:
        d = _convert_keys(data)
        d["tags"] = [RdsTag.from_dict(tag) for tag in d.get("tags", [])]
        return cls(**d)


@dataclass
class RdsInstancesResponse:
    instances: List[RdsInstance]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RdsInstancesResponse:
        d = _convert_keys(data)
        return cls(
            instances=[RdsInstance.from_dict(item) for item in d.get("instances", [])],
        )


# ── ElastiCache ─────────────────────────────────────────────────────


@dataclass
class ElastiCacheCluster:
    cache_cluster_id: str
    cache_cluster_status: str
    engine: str
    engine_version: str
    cache_node_type: str
    num_cache_nodes: int
    replication_group_id: Optional[str]
    port: Optional[int]
    host_port: Optional[int]
    container_id: Optional[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ElastiCacheCluster:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class ElastiCacheClustersResponse:
    clusters: List[ElastiCacheCluster]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ElastiCacheClustersResponse:
        d = _convert_keys(data)
        return cls(
            clusters=[
                ElastiCacheCluster.from_dict(item) for item in d.get("clusters", [])
            ],
        )


@dataclass
class ElastiCacheReplicationGroupIntrospection:
    replication_group_id: str
    status: str
    description: str
    member_clusters: List[str]
    automatic_failover: bool
    multi_az: bool
    engine: str
    engine_version: str
    cache_node_type: str
    num_cache_clusters: int

    @classmethod
    def from_dict(
        cls, data: Dict[str, Any]
    ) -> ElastiCacheReplicationGroupIntrospection:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class ElastiCacheReplicationGroupsResponse:
    replication_groups: List[ElastiCacheReplicationGroupIntrospection]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ElastiCacheReplicationGroupsResponse:
        d = _convert_keys(data)
        return cls(
            replication_groups=[
                ElastiCacheReplicationGroupIntrospection.from_dict(item)
                for item in d.get("replication_groups", [])
            ],
        )


@dataclass
class ElastiCacheServerlessCacheIntrospection:
    serverless_cache_name: str
    status: str
    engine: str
    engine_version: str
    cache_node_type: Optional[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ElastiCacheServerlessCacheIntrospection:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class ElastiCacheServerlessCachesResponse:
    serverless_caches: List[ElastiCacheServerlessCacheIntrospection]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ElastiCacheServerlessCachesResponse:
        d = _convert_keys(data)
        return cls(
            serverless_caches=[
                ElastiCacheServerlessCacheIntrospection.from_dict(item)
                for item in d.get("serverless_caches", [])
            ],
        )


@dataclass
class ElastiCacheAclUser:
    name: str
    status: str
    access_string: str
    no_password_required: bool
    password_count: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ElastiCacheAclUser:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class ElastiCacheAclGroup:
    name: str
    members: List[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ElastiCacheAclGroup:
        d = _convert_keys(data)
        return cls(name=d["name"], members=list(d.get("members", [])))


@dataclass
class ElastiCacheAclCluster:
    cluster_id: str
    engine: str
    users: List[ElastiCacheAclUser]
    groups: List[ElastiCacheAclGroup]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ElastiCacheAclCluster:
        d = _convert_keys(data)
        return cls(
            cluster_id=d["cluster_id"],
            engine=d["engine"],
            users=[ElastiCacheAclUser.from_dict(u) for u in d.get("users", [])],
            groups=[ElastiCacheAclGroup.from_dict(g) for g in d.get("groups", [])],
        )


@dataclass
class ElastiCacheAclsResponse:
    acls: List[ElastiCacheAclCluster]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ElastiCacheAclsResponse:
        d = _convert_keys(data)
        return cls(
            acls=[ElastiCacheAclCluster.from_dict(a) for a in d.get("acls", [])],
        )


# ── Lambda ──────────────────────────────────────────────────────────


@dataclass
class LambdaInvocation:
    function_arn: str
    payload: str
    source: str
    timestamp: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> LambdaInvocation:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class LambdaInvocationsResponse:
    invocations: List[LambdaInvocation]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> LambdaInvocationsResponse:
        return cls(
            invocations=[
                LambdaInvocation.from_dict(i) for i in data.get("invocations", [])
            ],
        )


@dataclass
class WarmContainer:
    function_name: str
    runtime: str
    container_id: str
    last_used_secs_ago: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WarmContainer:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class WarmContainersResponse:
    containers: List[WarmContainer]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WarmContainersResponse:
        return cls(
            containers=[WarmContainer.from_dict(c) for c in data.get("containers", [])],
        )


@dataclass
class EvictContainerResponse:
    evicted: bool

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EvictContainerResponse:
        d = _convert_keys(data)
        return cls(**d)


# ── SES ─────────────────────────────────────────────────────────────


@dataclass
class SentEmail:
    message_id: str
    from_addr: str
    to: List[str]
    cc: List[str] = field(default_factory=list)
    bcc: List[str] = field(default_factory=list)
    subject: Optional[str] = None
    html_body: Optional[str] = None
    text_body: Optional[str] = None
    raw_data: Optional[str] = None
    template_name: Optional[str] = None
    template_data: Optional[str] = None
    timestamp: str = ""
    dkim_signature: Optional[str] = None
    dkim_domain: Optional[str] = None
    dkim_selector: Optional[str] = None
    headers: List[List[str]] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SentEmail:
        d = _convert_keys(data)
        # The JSON field is "from" but that's a Python keyword, so we map it.
        if "from" in data:
            d["from_addr"] = data["from"]
        d.pop("from", None)
        # Drop unknown fields the server might add to keep the SDK forward-compatible.
        known = {f.name for f in fields(cls)}
        d = {k: v for k, v in d.items() if k in known}
        return cls(**d)


@dataclass
class SesEmailsResponse:
    emails: List[SentEmail]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SesEmailsResponse:
        return cls(
            emails=[SentEmail.from_dict(e) for e in data.get("emails", [])],
        )


@dataclass
class AcmCertificateChainInfo:
    """PEM block + byte counts for an ACM certificate's stored chain.

    fakecloud isn't a PKI: ``external_ca_validated`` is always ``False``,
    documenting that imported chains are stored verbatim rather than
    verified against a real trust store. Callers use the byte/block
    counts to confirm the chain they uploaded round-trips intact.
    """

    certificate_arn: str
    certificate_pem_bytes: int
    certificate_pem_blocks: int
    chain_pem_bytes: int
    chain_pem_blocks: int
    external_ca_validated: bool
    status: str
    cert_type: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AcmCertificateChainInfo:
        return cls(
            certificate_arn=data.get("certificate_arn", ""),
            certificate_pem_bytes=int(data.get("certificate_pem_bytes", 0)),
            certificate_pem_blocks=int(data.get("certificate_pem_blocks", 0)),
            chain_pem_bytes=int(data.get("chain_pem_bytes", 0)),
            chain_pem_blocks=int(data.get("chain_pem_blocks", 0)),
            external_ca_validated=bool(data.get("external_ca_validated", False)),
            status=data.get("status", ""),
            cert_type=data.get("cert_type", ""),
        )


@dataclass
class InboundEmailRequest:
    from_addr: str
    to: List[str]
    subject: str
    body: str

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from": self.from_addr,
            "to": self.to,
            "subject": self.subject,
            "body": self.body,
        }


@dataclass
class InboundActionExecuted:
    rule: str
    action_type: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> InboundActionExecuted:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class InboundEmailResponse:
    message_id: str
    matched_rules: List[str]
    actions_executed: List[InboundActionExecuted]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> InboundEmailResponse:
        d = _convert_keys(data)
        return cls(
            message_id=d["message_id"],
            matched_rules=d.get("matched_rules", []),
            actions_executed=[
                InboundActionExecuted.from_dict(a)
                for a in data.get("actionsExecuted", [])
            ],
        )


@dataclass
class SesMetrics:
    suppressed_drops_total: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SesMetrics:
        d = _convert_keys(data)
        return cls(suppressed_drops_total=int(d.get("suppressed_drops_total", 0)))


@dataclass
class SesMailFromStatusResponse:
    identity: str
    mail_from_domain_status: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SesMailFromStatusResponse:
        d = _convert_keys(data)
        return cls(
            identity=d["identity"],
            mail_from_domain_status=d["mail_from_domain_status"],
        )


@dataclass
class SesDkimPublicKey:
    identity: str
    selector: Optional[str]
    public_key_base64: Optional[str]
    signing_enabled: bool

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SesDkimPublicKey:
        d = _convert_keys(data)
        return cls(
            identity=d["identity"],
            selector=d.get("selector"),
            public_key_base64=d.get("public_key_base64"),
            signing_enabled=bool(d.get("signing_enabled", False)),
        )


@dataclass
class SesSandboxResponse:
    sandbox: bool
    production_access_enabled: bool

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SesSandboxResponse:
        d = _convert_keys(data)
        return cls(
            sandbox=bool(d["sandbox"]),
            production_access_enabled=bool(d["production_access_enabled"]),
        )


# ── SNS ─────────────────────────────────────────────────────────────


@dataclass
class SnsMessage:
    message_id: str
    topic_arn: str
    message: str
    subject: Optional[str] = None
    timestamp: str = ""

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SnsMessage:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class SnsMessagesResponse:
    messages: List[SnsMessage]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SnsMessagesResponse:
        return cls(
            messages=[SnsMessage.from_dict(m) for m in data.get("messages", [])],
        )


@dataclass
class PendingConfirmation:
    subscription_arn: str
    topic_arn: str
    protocol: str
    endpoint: str
    token: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PendingConfirmation:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class PendingConfirmationsResponse:
    pending_confirmations: List[PendingConfirmation]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PendingConfirmationsResponse:
        return cls(
            pending_confirmations=[
                PendingConfirmation.from_dict(p)
                for p in data.get("pendingConfirmations", [])
            ],
        )


@dataclass
class ConfirmSubscriptionRequest:
    subscription_arn: str

    def to_dict(self) -> Dict[str, Any]:
        return {"subscriptionArn": self.subscription_arn}


@dataclass
class ConfirmSubscriptionResponse:
    confirmed: bool

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ConfirmSubscriptionResponse:
        d = _convert_keys(data)
        return cls(**d)


# ── SQS ─────────────────────────────────────────────────────────────


@dataclass
class SqsMessageInfo:
    message_id: str
    body: str
    receive_count: int
    in_flight: bool
    created_at: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SqsMessageInfo:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class SqsQueueMessages:
    queue_url: str
    queue_name: str
    messages: List[SqsMessageInfo]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SqsQueueMessages:
        d = _convert_keys(data)
        return cls(
            queue_url=d["queue_url"],
            queue_name=d["queue_name"],
            messages=[SqsMessageInfo.from_dict(m) for m in data.get("messages", [])],
        )


@dataclass
class SqsMessagesResponse:
    queues: List[SqsQueueMessages]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SqsMessagesResponse:
        return cls(
            queues=[SqsQueueMessages.from_dict(q) for q in data.get("queues", [])],
        )


@dataclass
class ExpirationTickResponse:
    expired_messages: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExpirationTickResponse:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class AppAsTickResponse:
    """Result of forcing one Application Auto Scaling watcher tick."""

    applied: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AppAsTickResponse:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class AppAsScheduledTickResponse:
    """Result of forcing one Application Auto Scaling scheduled-action tick."""

    fired: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AppAsScheduledTickResponse:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class ForceDlqResponse:
    moved_messages: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ForceDlqResponse:
        d = _convert_keys(data)
        return cls(**d)


# ── EventBridge ─────────────────────────────────────────────────────


@dataclass
class EventBridgeEvent:
    event_id: str
    source: str
    detail_type: str
    detail: str
    bus_name: str
    timestamp: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EventBridgeEvent:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class EventBridgeLambdaDelivery:
    function_arn: str
    payload: str
    timestamp: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EventBridgeLambdaDelivery:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class EventBridgeLogDelivery:
    log_group_arn: str
    payload: str
    timestamp: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EventBridgeLogDelivery:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class EventBridgeDeliveries:
    lambda_deliveries: List[EventBridgeLambdaDelivery] = field(default_factory=list)
    log_deliveries: List[EventBridgeLogDelivery] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EventBridgeDeliveries:
        return cls(
            lambda_deliveries=[
                EventBridgeLambdaDelivery.from_dict(d) for d in data.get("lambda", [])
            ],
            log_deliveries=[
                EventBridgeLogDelivery.from_dict(d) for d in data.get("logs", [])
            ],
        )


@dataclass
class EventHistoryResponse:
    events: List[EventBridgeEvent]
    deliveries: EventBridgeDeliveries

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EventHistoryResponse:
        return cls(
            events=[EventBridgeEvent.from_dict(e) for e in data.get("events", [])],
            deliveries=EventBridgeDeliveries.from_dict(data.get("deliveries", {})),
        )


@dataclass
class FireRuleRequest:
    rule_name: str
    bus_name: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"ruleName": self.rule_name}
        if self.bus_name is not None:
            d["busName"] = self.bus_name
        return d


@dataclass
class FireRuleTarget:
    target_type: str
    arn: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FireRuleTarget:
        return cls(target_type=data.get("type", ""), arn=data.get("arn", ""))


@dataclass
class FireRuleResponse:
    targets: List[FireRuleTarget]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FireRuleResponse:
        return cls(
            targets=[FireRuleTarget.from_dict(t) for t in data.get("targets", [])],
        )


# ── Glue ────────────────────────────────────────────────────────────


@dataclass
class GlueJob:
    account_id: str
    name: str
    role: str
    command: Any
    default_arguments: Dict[str, str]
    max_retries: int
    created_on: str
    last_modified_on: str
    max_capacity: Optional[float] = None
    timeout: Optional[int] = None
    glue_version: Optional[str] = None
    worker_type: Optional[str] = None
    number_of_workers: Optional[int] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GlueJob:
        return cls(
            account_id=data.get("accountId", ""),
            name=data.get("name", ""),
            role=data.get("role", ""),
            command=data.get("command"),
            default_arguments=dict(data.get("defaultArguments") or {}),
            max_retries=int(data.get("maxRetries", 0)),
            created_on=data.get("createdOn", ""),
            last_modified_on=data.get("lastModifiedOn", ""),
            max_capacity=data.get("maxCapacity"),
            timeout=data.get("timeout"),
            glue_version=data.get("glueVersion"),
            worker_type=data.get("workerType"),
            number_of_workers=data.get("numberOfWorkers"),
        )


@dataclass
class GlueJobsResponse:
    jobs: List[GlueJob]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GlueJobsResponse:
        return cls(jobs=[GlueJob.from_dict(j) for j in data.get("jobs", [])])


@dataclass
class GlueJobRun:
    account_id: str
    id: str
    job_name: str
    attempt: int
    started_on: str
    job_run_state: str
    arguments: Dict[str, str]
    execution_time: int
    completed_on: Optional[str] = None
    error_message: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GlueJobRun:
        return cls(
            account_id=data.get("accountId", ""),
            id=data.get("id", ""),
            job_name=data.get("jobName", ""),
            attempt=int(data.get("attempt", 0)),
            started_on=data.get("startedOn", ""),
            job_run_state=data.get("jobRunState", ""),
            arguments=dict(data.get("arguments") or {}),
            execution_time=int(data.get("executionTime", 0)),
            completed_on=data.get("completedOn"),
            error_message=data.get("errorMessage"),
        )


@dataclass
class GlueJobRunsResponse:
    runs: List[GlueJobRun]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> GlueJobRunsResponse:
        return cls(runs=[GlueJobRun.from_dict(r) for r in data.get("runs", [])])


# ── Scheduler (EventBridge Scheduler) ───────────────────────────────


@dataclass
class SchedulerSchedule:
    account_id: str
    group_name: str
    name: str
    arn: str
    state: str
    schedule_expression: str
    target_arn: str
    last_fired: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SchedulerSchedule:
        return cls(
            account_id=data.get("accountId", ""),
            group_name=data.get("groupName", ""),
            name=data.get("name", ""),
            arn=data.get("arn", ""),
            state=data.get("state", ""),
            schedule_expression=data.get("scheduleExpression", ""),
            target_arn=data.get("targetArn", ""),
            last_fired=data.get("lastFired"),
        )


@dataclass
class SchedulerSchedulesResponse:
    schedules: List[SchedulerSchedule]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SchedulerSchedulesResponse:
        return cls(
            schedules=[
                SchedulerSchedule.from_dict(s) for s in data.get("schedules", [])
            ],
        )


@dataclass
class FireScheduleResponse:
    schedule_arn: str
    target_arn: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> FireScheduleResponse:
        return cls(
            schedule_arn=data.get("scheduleArn", ""),
            target_arn=data.get("targetArn", ""),
        )


# ── S3 ──────────────────────────────────────────────────────────────


@dataclass
class S3Notification:
    bucket: str
    key: str
    event_type: str
    timestamp: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> S3Notification:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class S3NotificationsResponse:
    notifications: List[S3Notification]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> S3NotificationsResponse:
        return cls(
            notifications=[
                S3Notification.from_dict(n) for n in data.get("notifications", [])
            ],
        )


@dataclass
class LifecycleTickResponse:
    processed_buckets: int
    expired_objects: int
    transitioned_objects: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> LifecycleTickResponse:
        d = _convert_keys(data)
        return cls(**d)


# ── DynamoDB ────────────────────────────────────────────────────────


@dataclass
class TtlTickResponse:
    expired_items: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TtlTickResponse:
        d = _convert_keys(data)
        return cls(**d)


# ── SecretsManager ──────────────────────────────────────────────────


@dataclass
class RotationTickResponse:
    rotated_secrets: List[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> RotationTickResponse:
        d = _convert_keys(data)
        return cls(**d)


# ── Cognito ─────────────────────────────────────────────────────────


@dataclass
class UserConfirmationCodes:
    confirmation_code: Optional[str] = None
    attribute_verification_codes: Any = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> UserConfirmationCodes:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class ConfirmationCode:
    pool_id: str
    username: str
    code: str
    code_type: str
    attribute: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ConfirmationCode:
        d = _convert_keys(data)
        # JSON uses "type" which maps to "code_type"
        if "type" in data:
            d["code_type"] = data["type"]
        d.pop("type", None)
        return cls(**d)


@dataclass
class ConfirmationCodesResponse:
    codes: List[ConfirmationCode]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ConfirmationCodesResponse:
        return cls(
            codes=[ConfirmationCode.from_dict(c) for c in data.get("codes", [])],
        )


@dataclass
class ConfirmUserRequest:
    user_pool_id: str
    username: str

    def to_dict(self) -> Dict[str, Any]:
        return {"userPoolId": self.user_pool_id, "username": self.username}


@dataclass
class ConfirmUserResponse:
    confirmed: bool
    error: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ConfirmUserResponse:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class TokenInfo:
    token_type: str
    username: str
    pool_id: str
    client_id: str
    issued_at: float

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TokenInfo:
        d = _convert_keys(data)
        # JSON uses "type" which maps to "token_type"
        if "type" in data:
            d["token_type"] = data["type"]
        d.pop("type", None)
        return cls(**d)


@dataclass
class TokensResponse:
    tokens: List[TokenInfo]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> TokensResponse:
        return cls(
            tokens=[TokenInfo.from_dict(t) for t in data.get("tokens", [])],
        )


@dataclass
class ExpireTokensRequest:
    user_pool_id: Optional[str] = None
    username: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {}
        if self.user_pool_id is not None:
            d["userPoolId"] = self.user_pool_id
        if self.username is not None:
            d["username"] = self.username
        return d


@dataclass
class ExpireTokensResponse:
    expired_tokens: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ExpireTokensResponse:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class AuthEvent:
    event_type: str
    username: str
    user_pool_id: str
    client_id: Optional[str] = None
    timestamp: float = 0.0
    success: bool = False

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuthEvent:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class AuthEventsResponse:
    events: List[AuthEvent]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AuthEventsResponse:
        return cls(
            events=[AuthEvent.from_dict(e) for e in data.get("events", [])],
        )


@dataclass
class PreTokenGenInvocation:
    """One PreTokenGeneration Lambda trigger invocation captured by
    ``InitiateAuth``. ``claims_added`` / ``claims_overridden`` /
    ``group_overrides`` are pre-parsed from the Lambda response so test
    code doesn't have to walk the raw ``claimsAndScopeOverrideDetails``
    shape itself.
    """

    pool_id: str
    user_pool_arn: str
    username: str
    trigger_source: str
    lambda_arn: str
    request_payload: Dict[str, Any]
    response_payload: Optional[Dict[str, Any]]
    claims_added: List[str]
    claims_overridden: List[str]
    group_overrides: List[str]
    invoked_at: str
    duration_ms: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PreTokenGenInvocation:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class PreTokenGenInvocationsResponse:
    invocations: List[PreTokenGenInvocation]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> PreTokenGenInvocationsResponse:
        return cls(
            invocations=[
                PreTokenGenInvocation.from_dict(e) for e in data.get("invocations", [])
            ],
        )


@dataclass
class MintAuthorizationCodeRequest:
    """Payload for `POST /_fakecloud/cognito/authorization-codes`.

    Lets test harnesses pre-allocate a single-use OAuth2 authorization
    code that the `/oauth2/token` `authorization_code` grant will
    later consume.
    """

    user_pool_id: str
    client_id: str
    username: str
    redirect_uri: str
    scopes: Optional[List[str]] = None
    code_challenge: Optional[str] = None
    code_challenge_method: Optional[str] = None
    nonce: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {
            "userPoolId": self.user_pool_id,
            "clientId": self.client_id,
            "username": self.username,
            "redirectUri": self.redirect_uri,
        }
        if self.scopes is not None:
            out["scopes"] = self.scopes
        if self.code_challenge is not None:
            out["codeChallenge"] = self.code_challenge
        if self.code_challenge_method is not None:
            out["codeChallengeMethod"] = self.code_challenge_method
        if self.nonce is not None:
            out["nonce"] = self.nonce
        return out


@dataclass
class MintAuthorizationCodeResponse:
    code: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> MintAuthorizationCodeResponse:
        return cls(code=data["code"])


@dataclass
class CompromisedPasswordsRequest:
    """Payload for `POST /_fakecloud/cognito/compromised-passwords`.

    Each plaintext is SHA-256 hashed server-side and added to the
    per-account compromised-password set; subsequent `SignUp` /
    `AdminInitiateAuth` calls fail with `InvalidPasswordException` on
    any pool whose
    `CompromisedCredentialsRiskConfiguration.Actions.EventAction` is
    `BLOCK`.
    """

    passwords: List[str]

    def to_dict(self) -> Dict[str, Any]:
        return {"passwords": list(self.passwords)}


@dataclass
class CompromisedPasswordsResponse:
    added: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CompromisedPasswordsResponse:
        return cls(added=int(data["added"]))


@dataclass
class WebAuthnCredential:
    """Registered WebAuthn credential surfaced by introspection.

    `attestation_info` is the parsed-attestation JSON object (packed
    format details, AAGUID, certificate chain summary, signature
    counter); its shape depends on the attestation format so it is
    surfaced as an opaque mapping.
    """

    account_id: str
    pool_user: str
    credential_id: str
    relying_party_id: str
    attestation_info: Any

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WebAuthnCredential:
        return cls(
            account_id=data["account_id"],
            pool_user=data["pool_user"],
            credential_id=data["credential_id"],
            relying_party_id=data["relying_party_id"],
            attestation_info=data.get("attestation_info"),
        )


@dataclass
class WebAuthnCredentialsResponse:
    credentials: List[WebAuthnCredential]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> WebAuthnCredentialsResponse:
        return cls(
            credentials=[
                WebAuthnCredential.from_dict(c) for c in data.get("credentials", [])
            ],
        )


# ── Step Functions ──────────────────────────────────────────────────


@dataclass
class StepFunctionsExecution:
    execution_arn: str
    state_machine_arn: str
    name: str
    status: str
    start_date: str
    input: Optional[str] = None
    output: Optional[str] = None
    stop_date: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> StepFunctionsExecution:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class StepFunctionsExecutionsResponse:
    executions: List[StepFunctionsExecution]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> StepFunctionsExecutionsResponse:
        return cls(
            executions=[
                StepFunctionsExecution.from_dict(e) for e in data.get("executions", [])
            ],
        )


@dataclass
class SfnEnqueueActivityTaskRequest:
    activity_arn: str
    input: Optional[str] = None
    heartbeat_seconds: Optional[int] = None
    timeout_seconds: Optional[int] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"activityArn": self.activity_arn}
        if self.input is not None:
            d["input"] = self.input
        if self.heartbeat_seconds is not None:
            d["heartbeatSeconds"] = self.heartbeat_seconds
        if self.timeout_seconds is not None:
            d["timeoutSeconds"] = self.timeout_seconds
        return d


@dataclass
class SfnEnqueueActivityTaskResponse:
    task_token: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> SfnEnqueueActivityTaskResponse:
        return cls(task_token=data["taskToken"])


# ── Bedrock ────────────────────────────────────────────────────────────


@dataclass
class BedrockInvocation:
    model_id: str
    input: str
    output: str
    timestamp: str
    error: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BedrockInvocation:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class BedrockInvocationsResponse:
    invocations: List[BedrockInvocation]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BedrockInvocationsResponse:
        return cls(
            invocations=[
                BedrockInvocation.from_dict(i) for i in data.get("invocations", [])
            ],
        )


@dataclass
class BedrockModelResponseConfig:
    status: str
    model_id: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BedrockModelResponseConfig:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class BedrockResponseRule:
    """One rule in a per-model response rule list.

    ``prompt_contains`` is a substring that must appear in the prompt for this
    rule to match. ``None`` (or an empty string) matches any prompt.
    """

    response: str
    prompt_contains: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "promptContains": self.prompt_contains,
            "response": self.response,
        }


@dataclass
class BedrockFaultRule:
    """Configuration for a fault to inject on Bedrock runtime calls."""

    error_type: str
    message: Optional[str] = None
    http_status: Optional[int] = None
    count: Optional[int] = None
    model_id: Optional[str] = None
    operation: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {"errorType": self.error_type}
        if self.message is not None:
            d["message"] = self.message
        if self.http_status is not None:
            d["httpStatus"] = self.http_status
        if self.count is not None:
            d["count"] = self.count
        if self.model_id is not None:
            d["modelId"] = self.model_id
        if self.operation is not None:
            d["operation"] = self.operation
        return d


@dataclass
class BedrockFaultRuleState:
    error_type: str
    message: str
    http_status: int
    remaining: int
    model_id: Optional[str] = None
    operation: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BedrockFaultRuleState:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class BedrockFaultsResponse:
    faults: List[BedrockFaultRuleState]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BedrockFaultsResponse:
        return cls(
            faults=[BedrockFaultRuleState.from_dict(f) for f in data.get("faults", [])],
        )


@dataclass
class BedrockStatusResponse:
    status: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> BedrockStatusResponse:
        return cls(status=data.get("status", ""))


# ── IAM ────────────────────────────────────────────────────────────────


@dataclass
class CreateAdminRequest:
    account_id: str
    user_name: str

    def to_dict(self) -> Dict[str, Any]:
        return {"accountId": self.account_id, "userName": self.user_name}


@dataclass
class CreateAdminResponse:
    access_key_id: str
    secret_access_key: str
    account_id: str
    arn: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> CreateAdminResponse:
        d = _convert_keys(data)
        return cls(**d)


# ── API Gateway v2 ──────────────────────────────────────────────────────


@dataclass
class ApiGatewayV2Request:
    request_id: str
    api_id: str
    stage: str
    method: str
    path: str
    headers: Dict[str, str]
    query_params: Dict[str, str]
    timestamp: str
    status_code: int
    body: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ApiGatewayV2Request:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class ApiGatewayV2RequestsResponse:
    requests: List[ApiGatewayV2Request]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> ApiGatewayV2RequestsResponse:
        return cls(
            requests=[
                ApiGatewayV2Request.from_dict(r) for r in data.get("requests", [])
            ],
        )


# ── ECR ─────────────────────────────────────────────────────────────


@dataclass
class EcrTag:
    key: str
    value: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EcrTag:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class EcrRepository:
    repository_name: str
    repository_arn: str
    registry_id: str
    repository_uri: str
    image_tag_mutability: str
    scan_on_push: bool
    created_at: str
    tags: List[EcrTag]
    has_policy: bool
    has_lifecycle_policy: bool
    image_count: int
    layer_count: int

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EcrRepository:
        tags = [EcrTag.from_dict(t) for t in data.get("tags", [])]
        d = _convert_keys(data)
        d["tags"] = tags
        return cls(**d)


@dataclass
class EcrRepositoriesResponse:
    repositories: List[EcrRepository]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EcrRepositoriesResponse:
        return cls(
            repositories=[
                EcrRepository.from_dict(r) for r in data.get("repositories", [])
            ],
        )


@dataclass
class EcrImage:
    repository_name: str
    image_digest: str
    image_tags: List[str]
    image_size_in_bytes: int
    image_manifest_media_type: str
    image_pushed_at: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EcrImage:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class EcrImagesResponse:
    images: List[EcrImage]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EcrImagesResponse:
        return cls(images=[EcrImage.from_dict(i) for i in data.get("images", [])])


@dataclass
class EcrPullThroughRule:
    ecr_repository_prefix: str
    upstream_registry_url: str
    created_at: str
    updated_at: str
    upstream_registry: Optional[str] = None
    credential_arn: Optional[str] = None
    custom_role_arn: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EcrPullThroughRule:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class EcrPullThroughRulesResponse:
    rules: List[EcrPullThroughRule]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EcrPullThroughRulesResponse:
        return cls(
            rules=[EcrPullThroughRule.from_dict(r) for r in data.get("rules", [])],
        )


# ── ECS ─────────────────────────────────────────────────────────────


@dataclass
class EcsTag:
    key: str
    value: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EcsTag:
        return cls(**_convert_keys(data))


@dataclass
class EcsCluster:
    cluster_name: str
    cluster_arn: str
    status: str
    running_tasks_count: int
    pending_tasks_count: int
    active_services_count: int
    registered_container_instances_count: int
    capacity_providers: List[str]
    tags: List[EcsTag]
    created_at: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EcsCluster:
        d = _convert_keys(data)
        d["tags"] = [EcsTag.from_dict(t) for t in d.get("tags", [])]
        return cls(**d)


@dataclass
class EcsClustersResponse:
    clusters: List[EcsCluster]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EcsClustersResponse:
        return cls(
            clusters=[EcsCluster.from_dict(c) for c in data.get("clusters", [])],
        )


@dataclass
class EcsTaskContainer:
    name: str
    image: str
    last_status: str
    essential: bool
    exit_code: Optional[int] = None
    runtime_id: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EcsTaskContainer:
        return cls(**_convert_keys(data))


@dataclass
class EcsTask:
    task_arn: str
    task_id: str
    cluster_arn: str
    cluster_name: str
    task_definition_arn: str
    family: str
    revision: int
    last_status: str
    desired_status: str
    launch_type: str
    created_at: str
    containers: List[EcsTaskContainer]
    captured_log_bytes: int
    started_at: Optional[str] = None
    stopping_at: Optional[str] = None
    stopped_at: Optional[str] = None
    stop_code: Optional[str] = None
    stopped_reason: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EcsTask:
        d = _convert_keys(data)
        d["containers"] = [
            EcsTaskContainer.from_dict(c) for c in d.get("containers", [])
        ]
        return cls(**d)


@dataclass
class EcsTasksResponse:
    tasks: List[EcsTask]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EcsTasksResponse:
        return cls(tasks=[EcsTask.from_dict(t) for t in data.get("tasks", [])])


@dataclass
class EcsTaskLogsResponse:
    task_arn: str
    logs: str
    last_status: str
    exit_code: Optional[int] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EcsTaskLogsResponse:
        return cls(**_convert_keys(data))


@dataclass
class EcsMarkFailedRequest:
    exit_code: Optional[int] = None
    reason: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        out: Dict[str, Any] = {}
        if self.exit_code is not None:
            out["exitCode"] = self.exit_code
        if self.reason is not None:
            out["reason"] = self.reason
        return out


@dataclass
class EcsLifecycleEvent:
    at: str
    event_type: str
    detail: Any
    task_arn: Optional[str] = None
    cluster_arn: Optional[str] = None
    last_status: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EcsLifecycleEvent:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class EcsEventsResponse:
    events: List[EcsLifecycleEvent]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> EcsEventsResponse:
        return cls(
            events=[EcsLifecycleEvent.from_dict(e) for e in data.get("events", [])],
        )


# ── ELBv2 ───────────────────────────────────────────────────────────


@dataclass
class Elbv2Tag:
    key: str
    value: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Elbv2Tag:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class Elbv2AvailabilityZone:
    zone_name: str
    subnet_id: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Elbv2AvailabilityZone:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class Elbv2LoadBalancer:
    arn: str
    name: str
    dns_name: str
    scheme: str
    vpc_id: str
    state_code: str
    lb_type: str
    ip_address_type: str
    availability_zones: List[Elbv2AvailabilityZone]
    security_groups: List[str]
    created_time: str
    tags: List[Elbv2Tag]
    state_reason: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Elbv2LoadBalancer:
        return cls(
            arn=data["arn"],
            name=data["name"],
            dns_name=data["dnsName"],
            scheme=data["scheme"],
            vpc_id=data["vpcId"],
            state_code=data["stateCode"],
            lb_type=data["lbType"],
            ip_address_type=data["ipAddressType"],
            availability_zones=[
                Elbv2AvailabilityZone.from_dict(z)
                for z in data.get("availabilityZones", [])
            ],
            security_groups=list(data.get("securityGroups", [])),
            created_time=data["createdTime"],
            tags=[Elbv2Tag.from_dict(t) for t in data.get("tags", [])],
            state_reason=data.get("stateReason"),
        )


@dataclass
class Elbv2LoadBalancersResponse:
    load_balancers: List[Elbv2LoadBalancer]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Elbv2LoadBalancersResponse:
        return cls(
            load_balancers=[
                Elbv2LoadBalancer.from_dict(lb) for lb in data.get("loadBalancers", [])
            ],
        )


@dataclass
class Elbv2Target:
    id: str
    health_state: str
    port: Optional[int] = None
    availability_zone: Optional[str] = None
    health_reason: Optional[str] = None
    health_description: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Elbv2Target:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class Elbv2TargetGroup:
    arn: str
    name: str
    target_type: str
    load_balancer_arns: List[str]
    targets: List[Elbv2Target]
    healthy_threshold_count: int
    unhealthy_threshold_count: int
    created_time: str
    tags: List[Elbv2Tag]
    protocol: Optional[str] = None
    port: Optional[int] = None
    vpc_id: Optional[str] = None
    health_check_protocol: Optional[str] = None
    health_check_port: Optional[str] = None
    health_check_path: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Elbv2TargetGroup:
        return cls(
            arn=data["arn"],
            name=data["name"],
            target_type=data["targetType"],
            load_balancer_arns=list(data.get("loadBalancerArns", [])),
            targets=[Elbv2Target.from_dict(t) for t in data.get("targets", [])],
            healthy_threshold_count=data["healthyThresholdCount"],
            unhealthy_threshold_count=data["unhealthyThresholdCount"],
            created_time=data["createdTime"],
            tags=[Elbv2Tag.from_dict(t) for t in data.get("tags", [])],
            protocol=data.get("protocol"),
            port=data.get("port"),
            vpc_id=data.get("vpcId"),
            health_check_protocol=data.get("healthCheckProtocol"),
            health_check_port=data.get("healthCheckPort"),
            health_check_path=data.get("healthCheckPath"),
        )


@dataclass
class Elbv2TargetGroupsResponse:
    target_groups: List[Elbv2TargetGroup]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Elbv2TargetGroupsResponse:
        return cls(
            target_groups=[
                Elbv2TargetGroup.from_dict(tg) for tg in data.get("targetGroups", [])
            ],
        )


@dataclass
class Elbv2Listener:
    arn: str
    load_balancer_arn: str
    certificate_arns: List[str]
    port: Optional[int] = None
    protocol: Optional[str] = None
    ssl_policy: Optional[str] = None
    default_action_type: Optional[str] = None
    default_target_group_arn: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Elbv2Listener:
        return cls(
            arn=data["arn"],
            load_balancer_arn=data["loadBalancerArn"],
            certificate_arns=list(data.get("certificateArns", [])),
            port=data.get("port"),
            protocol=data.get("protocol"),
            ssl_policy=data.get("sslPolicy"),
            default_action_type=data.get("defaultActionType"),
            default_target_group_arn=data.get("defaultTargetGroupArn"),
        )


@dataclass
class Elbv2ListenersResponse:
    listeners: List[Elbv2Listener]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Elbv2ListenersResponse:
        return cls(
            listeners=[
                Elbv2Listener.from_dict(item) for item in data.get("listeners", [])
            ],
        )


@dataclass
class Elbv2Rule:
    arn: str
    listener_arn: str
    priority: str
    is_default: bool
    condition_fields: List[str]
    action_type: Optional[str] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Elbv2Rule:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class Elbv2RulesResponse:
    rules: List[Elbv2Rule]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> Elbv2RulesResponse:
        return cls(
            rules=[Elbv2Rule.from_dict(r) for r in data.get("rules", [])],
        )


# ── CloudWatch Logs ─────────────────────────────────────────────────


@dataclass
class LogsAnomalyInjectRequest:
    """Admin payload for `/_fakecloud/logs/anomalies/inject`.

    Lets tests seed synthetic CloudWatch Logs anomalies so they can
    exercise `ListAnomalies`/`UpdateAnomaly` deterministically.
    """

    anomaly_detector_arn: str
    pattern_string: str
    log_group_arns: List[str] = field(default_factory=list)
    priority: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        d: Dict[str, Any] = {
            "anomalyDetectorArn": self.anomaly_detector_arn,
            "patternString": self.pattern_string,
            "logGroupArns": list(self.log_group_arns),
        }
        if self.priority is not None:
            d["priority"] = self.priority
        return d


@dataclass
class LogsAnomalyInjectResponse:
    anomaly_id: str

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> LogsAnomalyInjectResponse:
        d = _convert_keys(data)
        return cls(**d)


@dataclass
class LogsDeliveryConfiguration:
    """One entry of `/_fakecloud/logs/delivery-config`.

    Joins a `Delivery` with the `log_type` from its `DeliverySource`
    so callers can assert end-to-end wiring without re-querying the
    AWS-shaped APIs.
    """

    id: str
    name: str
    delivery_destination_arn: str
    delivery_source_name: str
    log_type: str
    created_at: int
    record_fields: List[str] = field(default_factory=list)
    field_delimiter: Optional[str] = None
    s3_delivery_configuration: Optional[Dict[str, Any]] = None

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> LogsDeliveryConfiguration:
        d = _convert_keys(data)
        valid = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in valid})


@dataclass
class LogsDeliveryConfigResponse:
    configurations: List[LogsDeliveryConfiguration] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> LogsDeliveryConfigResponse:
        return cls(
            configurations=[
                LogsDeliveryConfiguration.from_dict(c)
                for c in data.get("configurations", [])
            ]
# ── Athena ──────────────────────────────────────────────────────────


@dataclass
class AthenaNamedQuery:
    """One row in the Athena named-query introspection listing."""

    named_query_id: str
    name: str
    description: Optional[str]
    database: str
    query_string: str
    workgroup: str
    # RFC3339 timestamp of the most recent ``StartQueryExecution`` that
    # resolved its query string from this named query. ``None`` until the
    # first such invocation.
    last_used_at: Optional[str]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AthenaNamedQuery:
        d = _convert_keys(data)
        return cls(
            named_query_id=d["named_query_id"],
            name=d["name"],
            description=d.get("description"),
            database=d["database"],
            query_string=d["query_string"],
            workgroup=d["workgroup"],
            last_used_at=d.get("last_used_at"),
        )


@dataclass
class LogsFieldIndex:
    """One parsed `Fields` entry from an index policy on a log group."""

    fields: List[str] = field(default_factory=list)
    created_at: int = 0
    last_used_at: int = 0

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> LogsFieldIndex:
        return cls(
            fields=list(data.get("fields", [])),
            created_at=int(data.get("createdAt", 0)),
            last_used_at=int(data.get("lastUsedAt", 0)),
        )


@dataclass
class LogsFieldIndexesResponse:
    log_group_name: str
    indexes: List[LogsFieldIndex] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> LogsFieldIndexesResponse:
        return cls(
            log_group_name=data.get("logGroupName", ""),
            indexes=[LogsFieldIndex.from_dict(i) for i in data.get("indexes", [])],
class AthenaNamedQueriesResponse:
    queries: List[AthenaNamedQuery]

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> AthenaNamedQueriesResponse:
        d = _convert_keys(data)
        return cls(
            queries=[AthenaNamedQuery.from_dict(q) for q in d.get("queries", [])],
        )
