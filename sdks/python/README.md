# fakecloud

Python SDK for [fakecloud](https://github.com/faiscadev/fakecloud) — a local AWS cloud emulator.

This package provides async and sync clients for the fakecloud introspection and simulation API (`/_fakecloud/*` endpoints), letting you inspect sent emails, published messages, Lambda invocations, and more from your tests.

## Installation

```bash
pip install fakecloud
```

## Quick start

### Async

```python
import asyncio
from fakecloud import FakeCloud

async def main():
    async with FakeCloud("http://localhost:4566") as fc:
        # Check server health
        health = await fc.health()
        print(health.status, health.version)

        # List sent SES emails
        emails = await fc.ses.get_emails()
        for email in emails.emails:
            print(f"{email.from_addr} -> {email.to}: {email.subject}")

        # List SNS messages
        messages = await fc.sns.get_messages()
        for msg in messages.messages:
            print(f"{msg.topic_arn}: {msg.message}")

        # Inspect Lambda invocations
        invocations = await fc.lambda_.get_invocations()
        for inv in invocations.invocations:
            print(f"{inv.function_arn}: {inv.payload}")

        # Reset all state between tests
        await fc.reset()

asyncio.run(main())
```

### Sync

```python
from fakecloud import FakeCloudSync

with FakeCloudSync("http://localhost:4566") as fc:
    health = fc.health()
    print(health.status)

    emails = fc.ses.get_emails()
    for email in emails.emails:
        print(email.subject)
```

## API reference

### `FakeCloud` / `FakeCloudSync`

Top-level client. Pass `base_url` (default `http://localhost:4566`).

| Method | Description |
|---|---|
| `health()` | Server health check |
| `reset()` | Reset all service state |
| `reset_service(service)` | Reset a single service |

### Service sub-clients

Access via properties on the main client:

| Property | Service | Methods |
|---|---|---|
| `lambda_` | Lambda | `get_invocations()`, `get_warm_containers()`, `evict_container(name)` |
| `ses` | SES | `get_emails()`, `simulate_inbound(req)` |
| `sns` | SNS | `get_messages()`, `get_pending_confirmations()`, `confirm_subscription(req)` |
| `sqs` | SQS | `get_messages()`, `tick_expiration()`, `force_dlq(queue_name)` |
| `events` | EventBridge | `get_history()`, `fire_rule(req)` |
| `s3` | S3 | `get_notifications()`, `tick_lifecycle()` |
| `dynamodb` | DynamoDB | `tick_ttl()` |
| `secretsmanager` | SecretsManager | `tick_rotation()` |
| `cognito` | Cognito | `get_user_codes(pool_id, username)`, `get_confirmation_codes()`, `confirm_user(req)`, `get_tokens()`, `expire_tokens(req)`, `get_auth_events()` |
| `rds` | RDS | `get_instances()` |
| `elasticache` | ElastiCache | `get_clusters()`, `get_replication_groups()`, `get_serverless_caches()` |
| `stepfunctions` | Step Functions | `get_executions()` |
| `apigatewayv2` | API Gateway v2 | `get_requests()`, `get_connections()` |
| `bedrock` | Bedrock Runtime | `get_invocations()`, `set_model_response(model_id, text)`, `set_response_rules(model_id, rules)`, `clear_response_rules(model_id)`, `queue_fault(rule)`, `get_faults()`, `clear_faults()` |
| `route53` | Route 53 | `set_health_check_status(id, status, reason=None)` — flip a health check between `Success` / `Failure` to drive failover routing in tests |

### Testing Bedrock-calling code end-to-end

```python
from fakecloud import FakeCloudSync
from fakecloud.types import BedrockResponseRule, BedrockFaultRule

fc = FakeCloudSync()
model_id = "anthropic.claude-3-haiku-20240307-v1:0"


def test_classifier_branches_on_spam_vs_ham():
    fc.reset()
    fc.bedrock.set_response_rules(
        model_id,
        [
            BedrockResponseRule(prompt_contains="buy now", response='{"label":"spam"}'),
            BedrockResponseRule(prompt_contains=None, response='{"label":"ham"}'),
        ],
    )

    classify("hello friend")           # user code that calls Bedrock
    classify("buy now cheap pills")

    invocations = fc.bedrock.get_invocations().invocations
    assert len(invocations) == 2
    assert "ham" in invocations[0].output
    assert "spam" in invocations[1].output


def test_retries_on_throttling():
    fc.reset()
    fc.bedrock.queue_fault(
        BedrockFaultRule(
            error_type="ThrottlingException",
            message="Rate exceeded",
            http_status=429,
            count=1,  # only the first call faults; the retry succeeds
        )
    )

    classify("hello")

    invocations = fc.bedrock.get_invocations().invocations
    assert len(invocations) == 2
    assert "ThrottlingException" in (invocations[0].error or "")
    assert invocations[1].error is None
```

### Error handling

All methods raise `FakeCloudError` on non-2xx responses:

```python
from fakecloud.client import FakeCloudError

try:
    await fc.health()
except FakeCloudError as e:
    print(e.status, e.body)
```

## pytest fixture example

```python
import pytest
from fakecloud import FakeCloudSync

@pytest.fixture(autouse=True)
def reset_fakecloud():
    fc = FakeCloudSync()
    fc.reset()
    yield fc
    fc.close()

def test_email_sent(reset_fakecloud):
    # ... your code that sends an email via SES ...
    emails = reset_fakecloud.ses.get_emails()
    assert len(emails.emails) == 1
    assert emails.emails[0].subject == "Welcome"
```
