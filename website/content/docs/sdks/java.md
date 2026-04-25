+++
title = "Java SDK"
description = "Install and use the fakecloud SDK for JVM tests (JUnit, Spring Boot, Micronaut, Quarkus)."
weight = 4
+++

## Install

Gradle (Kotlin DSL):

```kotlin
dependencies {
    testImplementation("dev.fakecloud:fakecloud:0.11.0")
}
```

Maven:

```xml
<dependency>
    <groupId>dev.fakecloud</groupId>
    <artifactId>fakecloud</artifactId>
    <version>0.11.0</version>
    <scope>test</scope>
</dependency>
```

Requires Java 17+. Uses the JDK's built-in `HttpClient` and Jackson for JSON.

## Initialize

```java
import dev.fakecloud.FakeCloud;

FakeCloud fc = new FakeCloud();                         // defaults to http://localhost:4566
FakeCloud fc2 = new FakeCloud("http://localhost:5000"); // explicit base URL
```

## Top-level

| Method                  | Description             |
| ----------------------- | ----------------------- |
| `health()`              | Server health check     |
| `reset()`               | Reset all service state |
| `resetService(service)` | Reset a single service  |

## `fc.bedrock()`

| Method                              | Description                                                          |
| ----------------------------------- | -------------------------------------------------------------------- |
| `getInvocations()`                  | List recorded Bedrock runtime invocations                            |
| `setModelResponse(modelId, text)`   | Configure a single canned response for a model                       |
| `setResponseRules(modelId, rules)`  | Replace prompt-conditional response rules for a model                |
| `clearResponseRules(modelId)`       | Clear all prompt-conditional response rules for a model              |
| `queueFault(rule)`                  | Queue a fault rule for the next N calls                              |
| `getFaults()`                       | List currently queued fault rules                                    |
| `clearFaults()`                     | Clear all queued fault rules                                         |

## `fc.lambda()`, `fc.ses()`, `fc.sns()`, `fc.sqs()`, `fc.events()`, `fc.s3()`, `fc.dynamodb()`, `fc.secretsmanager()`, `fc.cognito()`, `fc.stepfunctions()`, `fc.rds()`, `fc.elasticache()`, `fc.apigatewayv2()`

Each sub-client mirrors the TypeScript SDK method list 1:1. See the
[SDK README](https://github.com/faiscadev/fakecloud/blob/main/sdks/java/README.md)
for the full, always-current surface.

## Error handling

All methods throw `FakeCloudError` (a `RuntimeException`) on non-2xx responses:

```java
import dev.fakecloud.FakeCloudError;
import dev.fakecloud.Types.ConfirmUserRequest;

try {
    fc.cognito().confirmUser(new ConfirmUserRequest("pool-1", "nobody"));
} catch (FakeCloudError err) {
    System.out.println(err.status()); // 404
    System.out.println(err.body());   // error body from fakecloud
}
```

## Example: full test loop

```java
import dev.fakecloud.FakeCloud;
import dev.fakecloud.Types.BedrockFaultRule;
import dev.fakecloud.Types.BedrockResponseRule;
import java.util.List;

FakeCloud fc = new FakeCloud();
String modelId = "anthropic.claude-3-haiku-20240307-v1:0";

@BeforeEach
void reset() { fc.reset(); }

@Test
void classifierBranchesOnSpamVsHam() {
    fc.bedrock().setResponseRules(modelId, List.of(
            new BedrockResponseRule("buy now", "{\"label\":\"spam\"}"),
            new BedrockResponseRule(null, "{\"label\":\"ham\"}")));

    classify("hello friend");
    classify("buy now cheap pills");

    var invocations = fc.bedrock().getInvocations().invocations();
    assertEquals(2, invocations.size());
    assertTrue(invocations.get(0).output().contains("ham"));
    assertTrue(invocations.get(1).output().contains("spam"));
}

@Test
void retriesOnThrottlingException() {
    fc.bedrock().queueFault(new BedrockFaultRule(
            "ThrottlingException", "Rate exceeded", 429, 1, null, null));

    classify("hello");

    var invocations = fc.bedrock().getInvocations().invocations();
    assertEquals(2, invocations.size());
    assertTrue(invocations.get(0).error().contains("ThrottlingException"));
    assertNull(invocations.get(1).error());
}
```

## Source

- [`sdks/java`](https://github.com/faiscadev/fakecloud/tree/main/sdks/java)
- [Source README](https://github.com/faiscadev/fakecloud/blob/main/sdks/java/README.md) — always-current method list
