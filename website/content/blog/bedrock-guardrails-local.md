+++
title = "Testing Bedrock Guardrails without the AWS bill"
date = 2026-04-22
description = "Bedrock Guardrails evaluate content policies, PII filters, topic filters, and contextual grounding. Testing a guardrail setup against real AWS is slow and expensive. fakecloud runs the guardrail control plane and the ApplyGuardrail data plane locally, with real content evaluation."

[extra]
author = "Lucas Vieira"
+++

Bedrock Guardrails are one of the better pieces of AWS infrastructure in the last year. You define a policy — filter out hate, block PII leakage, deny certain topics, enforce contextual grounding on RAG outputs — and either apply it to an entire model invocation via `guardrailIdentifier`, or call `ApplyGuardrail` directly on arbitrary text. Useful, sharp, limited-in-scope.

The problem is testing. A serious guardrail config is an iterative thing — you tune filter strengths, add denied topics, tweak word filters, and test each change. Each test-cycle turn against real AWS costs tokens and time. And if the thing you're trying to guard against is LLM output, you're paying for the model call *and* the guardrail evaluation.

fakecloud runs the full Bedrock Guardrails surface locally. `CreateGuardrail`, versioning, `UpdateGuardrail`, `DeleteGuardrail`, `ApplyGuardrail`, `ListGuardrails` — the whole thing. More interestingly, the data plane actually evaluates content. PII detection works. Content filters return sensible scores on real test text. You can write tests that verify your guardrail actually blocks what you think it blocks.

## The shape of the problem

The standard AWS recipe, cleaned up:

```python
import boto3

bedrock = boto3.client('bedrock', region_name='us-east-1')

g = bedrock.create_guardrail(
    name='customer-facing-v1',
    contentPolicyConfig={
        'filtersConfig': [
            {'type': 'HATE', 'inputStrength': 'HIGH', 'outputStrength': 'HIGH'},
            {'type': 'VIOLENCE', 'inputStrength': 'HIGH', 'outputStrength': 'HIGH'},
            {'type': 'SEXUAL', 'inputStrength': 'HIGH', 'outputStrength': 'HIGH'},
            {'type': 'INSULTS', 'inputStrength': 'MEDIUM', 'outputStrength': 'MEDIUM'},
        ],
    },
    sensitiveInformationPolicyConfig={
        'piiEntitiesConfig': [
            {'type': 'EMAIL', 'action': 'BLOCK'},
            {'type': 'PHONE', 'action': 'BLOCK'},
            {'type': 'CREDIT_DEBIT_CARD_NUMBER', 'action': 'BLOCK'},
        ],
    },
    topicPolicyConfig={
        'topicsConfig': [
            {
                'name': 'medical-advice',
                'definition': 'Providing specific medical diagnoses or treatment recommendations',
                'examples': ['What dose should I take?', 'Do I have cancer?'],
                'type': 'DENY',
            },
        ],
    },
    blockedInputMessaging='Cannot process this input.',
    blockedOutputsMessaging='Cannot respond to this.',
)
```

Now you want to test: does an email containing `bob@example.com` trigger the EMAIL filter and return the blocked-input message? Does a prompt asking "what medication should I take for my headache" get denied via the medical-advice topic? Does the HATE filter catch slurs at HIGH strength?

Against real AWS: each of those is an API call that costs a few cents, takes a second, and requires valid credentials. You'll do 50 of these across a tuning session. Repeated for each PR that touches guardrail config.

## Against fakecloud

Same code, different endpoint:

```python
import boto3

bedrock = boto3.client('bedrock',
    endpoint_url='http://localhost:4566',
    aws_access_key_id='test',
    aws_secret_access_key='test',
    region_name='us-east-1')

# same create_guardrail call as above
g = bedrock.create_guardrail(...)

rt = boto3.client('bedrock-runtime',
    endpoint_url='http://localhost:4566',
    aws_access_key_id='test',
    aws_secret_access_key='test',
    region_name='us-east-1')

resp = rt.apply_guardrail(
    guardrailIdentifier=g['guardrailId'],
    guardrailVersion='DRAFT',
    source='INPUT',
    content=[{'text': {'text': 'contact me at bob@example.com'}}],
)

assert resp['action'] == 'GUARDRAIL_INTERVENED'
assert resp['outputs'][0]['text'] == 'Cannot process this input.'
assert any(a['type'] == 'EMAIL' for a in resp['assessments'][0]['sensitiveInformationPolicy']['piiEntities'])
```

Real PII detection — the email is caught. Real blocked-input messaging returned. Assessments returned in the shape real AWS would return.

No tokens. No AWS bill. No credentials. 30ms.

## What's actually evaluated

fakecloud's guardrail evaluator ships opinionated implementations of each policy type. Concrete checks you can rely on in tests:

- **PII entities**: regex + context for email, phone (various formats), credit card (Luhn), SSN, IP, URL, name, address hints.
- **Content filters**: keyword + pattern matching tuned for the common categories. HIGH strength catches more, LOW catches less — same directional behavior as real AWS.
- **Topic filters**: pattern matching against the topic definition + examples you provided. Won't pass a Stanford NLI benchmark, but does what you need for testing: asserts the policy fires on obvious positives and passes obvious negatives.
- **Word filters**: exact match + stemming.
- **Regex filters**: the regex you supplied, as-is.

It's shape-correct evaluation. For tests that verify "my guardrail config blocks what I intended," that's exactly what you need. If you want bulletproof production-grade content filtering, you're going to tune against real AWS or roll your own anyway — this gets you 95% of the iteration speed.

## Versioning

```python
# publish a version
v = bedrock.create_guardrail_version(
    guardrailIdentifier=g['guardrailId'],
    description='initial pinned version for prod',
)

# list versions
versions = bedrock.list_guardrails(guardrailIdentifier=g['guardrailId'])

# apply a specific version in production
rt.apply_guardrail(
    guardrailIdentifier=g['guardrailId'],
    guardrailVersion=v['version'],  # '1'
    source='INPUT',
    content=[{'text': {'text': '...'}}],
)
```

DRAFT is mutable. Numbered versions (1, 2, 3, ...) are immutable once created — same as real AWS. Your prod code should pin. Your dev iteration happens against DRAFT.

## A realistic test suite

```ts
import { FakeCloud } from "fakecloud";
import { BedrockRuntimeClient, ApplyGuardrailCommand } from "@aws-sdk/client-bedrock-runtime";
import { BedrockClient, CreateGuardrailCommand } from "@aws-sdk/client-bedrock";

const fc = new FakeCloud();
const control = new BedrockClient({ endpoint: "http://localhost:4566" });
const rt = new BedrockRuntimeClient({ endpoint: "http://localhost:4566" });

let guardrailId: string;

beforeAll(async () => {
  const created = await control.send(new CreateGuardrailCommand({
    name: "test-guardrail",
    contentPolicyConfig: {
      filtersConfig: [
        { type: "HATE", inputStrength: "HIGH", outputStrength: "HIGH" },
      ],
    },
    sensitiveInformationPolicyConfig: {
      piiEntitiesConfig: [
        { type: "EMAIL", action: "BLOCK" },
        { type: "PHONE", action: "ANONYMIZE" },
      ],
    },
    blockedInputMessaging: "Blocked.",
    blockedOutputsMessaging: "Blocked.",
  }));
  guardrailId = created.guardrailId!;
});

beforeEach(() => fc.reset({ preserve: ["bedrock:guardrails"] }));

test("blocks input containing email", async () => {
  const resp = await rt.send(new ApplyGuardrailCommand({
    guardrailIdentifier: guardrailId,
    guardrailVersion: "DRAFT",
    source: "INPUT",
    content: [{ text: { text: "contact me at alice@example.com" } }],
  }));

  expect(resp.action).toBe("GUARDRAIL_INTERVENED");
  expect(resp.outputs?.[0].text).toBe("Blocked.");
});

test("anonymizes phone in output", async () => {
  const resp = await rt.send(new ApplyGuardrailCommand({
    guardrailIdentifier: guardrailId,
    guardrailVersion: "DRAFT",
    source: "OUTPUT",
    content: [{ text: { text: "call me at 555-123-4567 tomorrow" } }],
  }));

  expect(resp.action).toBe("GUARDRAIL_INTERVENED");
  expect(resp.outputs?.[0].text).not.toContain("555-123-4567");
});

test("passes clean input through", async () => {
  const resp = await rt.send(new ApplyGuardrailCommand({
    guardrailIdentifier: guardrailId,
    guardrailVersion: "DRAFT",
    source: "INPUT",
    content: [{ text: { text: "what's the weather in Paris?" } }],
  }));

  expect(resp.action).toBe("NONE");
});
```

These run in milliseconds, are deterministic, and test the thing that matters — that your guardrail config enforces what you think it enforces.

## Why this matters for agent systems

Guardrails become critical when you're building tool-using agents. A tool call that leaks customer PII is a real incident; a model output that contains violence content is a real incident. You want those failure modes caught in CI, not in production.

The pattern:

1. Compose the guardrail config as code (Terraform / CDK) alongside your agent definition.
2. In CI, deploy the guardrail to fakecloud, run a test matrix of adversarial inputs through your agent, assert that the guardrail fires (or doesn't fire) where expected.
3. On merge to main, deploy the same config to real AWS.

The first two steps cost nothing. The third is the one that actually consumes budget.

This is the test loop real AWS makes nearly impossible — not because of technical obstacles, but because the cost-per-iteration is too high for the number of iterations you actually need.

## Links

- **Bedrock emulator** (landing): [/bedrock-emulator/](/bedrock-emulator/)
- **Test Bedrock locally**: [/test-bedrock-locally/](/test-bedrock-locally/)
- **Why not a real LLM in tests**: [/blog/bedrock-tests-real-llm/](/blog/bedrock-tests-real-llm/)
- **Testing LLM guardrails** (broader view): [/blog/llm-guardrails/](/blog/llm-guardrails/)
- **GitHub**: [github.com/faiscadev/fakecloud](https://github.com/faiscadev/fakecloud)
