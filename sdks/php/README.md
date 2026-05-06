# fakecloud

PHP client SDK for [fakecloud](https://github.com/faiscadev/fakecloud) — a local AWS cloud emulator.

Provides typed access to the fakecloud introspection and simulation API (`/_fakecloud/*` endpoints), letting you inspect emulator state and trigger time-based processors in tests.

Requires **PHP 8.1+**. Uses the built-in `curl` extension and `json_decode`/`json_encode`. No external dependencies.

## Installation

```bash
composer require fakecloud/fakecloud
```

## Quick start

```php
use FakeCloud\FakeCloud;

$fc = new FakeCloud('http://localhost:4566');

// Check server health
$health = $fc->health();
echo $health->version . ' ' . implode(', ', $health->services);

// Reset all state between tests
$fc->reset();

// Inspect SES emails sent during a test
$emails = $fc->ses()->getEmails()->emails;
echo 'Sent ' . count($emails) . ' emails';

// Inspect SNS messages
$messages = $fc->sns()->getMessages()->messages;

// Inspect SQS messages across all queues
$queues = $fc->sqs()->getMessages()->queues;

// Advance DynamoDB TTL processor
$expired = $fc->dynamodb()->tickTtl()->expiredItems;

// Advance S3 lifecycle processor
$expiredObjects = $fc->s3()->tickLifecycle()->expiredObjects;
```

## API reference

### `FakeCloud`

```php
$fc = new FakeCloud();                       // defaults to http://localhost:4566
$fc = new FakeCloud('http://localhost:4566'); // explicit base URL
```

| Method                   | Description             |
| ------------------------ | ----------------------- |
| `health()`               | Server health check     |
| `reset()`                | Reset all service state |
| `resetService($service)` | Reset a single service  |

### `$fc->lambda()`

| Method                          | Description                          |
| ------------------------------- | ------------------------------------ |
| `getInvocations()`              | List recorded Lambda invocations     |
| `getWarmContainers()`           | List warm (cached) Lambda containers |
| `evictContainer($functionName)` | Evict a warm container               |

### `$fc->ses()`

| Method                 | Description                               |
| ---------------------- | ----------------------------------------- |
| `getEmails()`          | List all sent emails                      |
| `simulateInbound($req)` | Simulate an inbound email (receipt rules) |

### `$fc->sns()`

| Method                       | Description                             |
| ---------------------------- | --------------------------------------- |
| `getMessages()`              | List all published messages             |
| `getPendingConfirmations()`  | List subscriptions pending confirmation |
| `confirmSubscription($req)`  | Confirm a pending subscription          |

### `$fc->sqs()`

| Method                  | Description                           |
| ----------------------- | ------------------------------------- |
| `getMessages()`         | List all messages across all queues   |
| `tickExpiration()`      | Tick the message expiration processor |
| `forceDlq($queueName)` | Force all messages to the queue's DLQ |

### `$fc->events()`

| Method           | Description                            |
| ---------------- | -------------------------------------- |
| `getHistory()`   | Get event history and delivery records |
| `fireRule($req)` | Fire an EventBridge rule manually      |

### `$fc->s3()`

| Method                | Description                  |
| --------------------- | ---------------------------- |
| `getNotifications()`  | List S3 notification events  |
| `tickLifecycle()`     | Tick the lifecycle processor |

### `$fc->dynamodb()`

| Method       | Description            |
| ------------ | ---------------------- |
| `tickTtl()`  | Tick the TTL processor |

### `$fc->secretsmanager()`

| Method            | Description                 |
| ----------------- | --------------------------- |
| `tickRotation()`  | Tick the rotation scheduler |

### `$fc->cognito()`

| Method                            | Description                          |
| --------------------------------- | ------------------------------------ |
| `getUserCodes($poolId, $username)` | Get confirmation codes for a user    |
| `getConfirmationCodes()`          | List all confirmation codes          |
| `confirmUser($req)`               | Confirm a user (bypass verification) |
| `getTokens()`                     | List all active tokens               |
| `expireTokens($req)`              | Expire tokens (optionally filtered)  |
| `getAuthEvents()`                 | List auth events                     |
| `mintAuthorizationCode($req)`     | Mint a single-use OAuth2 authorization code (programmatic alternative to driving /oauth2/authorize) |

### `$fc->rds()`

| Method            | Description                              |
| ----------------- | ---------------------------------------- |
| `getInstances()`  | List RDS instances with runtime metadata |

### `$fc->elasticache()`

| Method                    | Description                         |
| ------------------------- | ----------------------------------- |
| `getClusters()`           | List ElastiCache cache clusters     |
| `getReplicationGroups()`  | List ElastiCache replication groups |
| `getServerlessCaches()`   | List ElastiCache serverless caches  |

### `$fc->stepfunctions()`

| Method             | Description                              |
| ------------------ | ---------------------------------------- |
| `getExecutions()`  | List all state machine execution history |

### `$fc->apigatewayv2()`

| Method           | Description                         |
| ---------------- | ----------------------------------- |
| `getRequests()`  | List all HTTP API requests received |

### `$fc->bedrock()`

| Method                              | Description                                                          |
| ----------------------------------- | -------------------------------------------------------------------- |
| `getInvocations()`                  | List recorded Bedrock runtime invocations                            |
| `setModelResponse($modelId, $text)` | Configure a single canned response for a model                       |
| `setResponseRules($modelId, $rules)` | Replace prompt-conditional response rules for a model               |
| `clearResponseRules($modelId)`      | Clear all prompt-conditional response rules for a model              |
| `queueFault($rule)`                 | Queue a fault rule for the next N calls                              |
| `getFaults()`                       | List currently queued fault rules                                    |
| `clearFaults()`                     | Clear all queued fault rules                                         |

### `$fc->route53()`

| Method                                              | Description                                                                                                                                       |
| --------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------- |
| `setHealthCheckStatus($id, $status, $reason)`       | Flip a health check between `Success` / `Failure` / `Timeout` / `DnsError` / `InsufficientDataPoints` / `Unknown` to drive failover routing in tests; reason is appended to the `<Status>` element for failure-flavoured statuses (omit for null) |

#### Full test loop — asserting on Bedrock calls

```php
use FakeCloud\FakeCloud;
use FakeCloud\BedrockFaultRule;
use FakeCloud\BedrockResponseRule;

$fc = new FakeCloud();
$modelId = 'anthropic.claude-3-haiku-20240307-v1:0';

// beforeEach
$fc->reset();

// Prime prompt-conditional responses
$fc->bedrock()->setResponseRules($modelId, [
    new BedrockResponseRule('buy now', '{"label":"spam"}'),
    new BedrockResponseRule(null, '{"label":"ham"}'), // catch-all
]);

classify('hello friend');           // user code calls Bedrock
classify('buy now cheap pills');

$invocations = $fc->bedrock()->getInvocations()->invocations;
assert(count($invocations) === 2);
assert(str_contains($invocations[0]->output, 'ham'));
assert(str_contains($invocations[1]->output, 'spam'));
```

### Error handling

All methods throw `FakeCloudError` (a `RuntimeException`) on non-2xx responses:

```php
use FakeCloud\FakeCloudError;
use FakeCloud\ConfirmUserRequest;

try {
    $fc->cognito()->confirmUser(new ConfirmUserRequest('pool-1', 'nobody'));
} catch (FakeCloudError $err) {
    echo $err->status; // 404
    echo $err->body;   // "user not found"
}
```

## Local development

```bash
# Build fakecloud (from repo root)
cargo build --release

# Install PHP dependencies
cd sdks/php
composer install

# Run unit tests
vendor/bin/phpunit tests/ClientTest.php

# Run E2E tests against the freshly-built binary
vendor/bin/phpunit tests/E2ETest.php
```
