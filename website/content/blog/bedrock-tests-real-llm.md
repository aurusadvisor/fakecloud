+++
title = "Why your Bedrock tests shouldn't call a real LLM (not even a local one)"
date = 2026-04-22
description = "Every AI-team engineer eventually asks: should my Bedrock tests hit a real model? Even a local one like Ollama? Short answer: no. Here's what tests actually need, and what happens when you try to use real inference instead."

[extra]
author = "Lucas Vieira"
+++

Every team building on Bedrock eventually asks the same question: for tests, should we call a real model? If the cost of real Bedrock is the concern, can we run Ollama locally and point our SDK at that?

The answer is no — but the reason is worth spelling out, because it shapes how you should think about tests for any LLM-calling code.

## What a test is for

A test asserts that *your code* behaves correctly under a given input. Not that a model behaves correctly. Not that an API is up. Just that the code you wrote, given a response from its upstream, does the thing you expected.

The upstream, for Bedrock code, is `InvokeModel` or `Converse`. Your code sends a prompt, gets a response, and does something with it: parses JSON, branches on a label, stores it in a DB, passes it to another tool call, retries on throttling, falls back on a cheaper model. Every one of those behaviors is yours to test.

The model's behavior is AWS's problem.

## What goes wrong with real models in tests

Once you try to use real inference — whether it's actual Bedrock or a local Ollama — four things break, in roughly ascending order of annoyance:

### 1. Non-determinism

Real models return different text on every call. Temperature = 0 doesn't save you: there's non-determinism in attention kernel implementations across GPU/CPU backends, in tokenizer versions, in batching behavior. Anthropic's own docs say "don't rely on deterministic outputs."

What this means for tests:

```ts
// hope this passes
expect(output).toBe("Classification: spam");
```

On run 1 the model returned `"Classification: spam"`. On run 2 it returned `"The email is spam."`. Both correct. Your test fails.

The usual fix is to assert loosely:

```ts
expect(output.toLowerCase()).toContain("spam");
```

This passes even if the model returns `"This is not spam"`. Your test is now worthless.

People end up using LLM-as-judge ("ask Claude if this response is approximately correct"). That's a research paper, not a CI pipeline.

### 2. Speed

Real Bedrock: 100-2000ms per call. Ollama on a developer laptop: 1-30s per call. Ollama on a CI runner without a GPU: 5-60s per call.

A test suite with 50 tests hitting the model at 5s each is 4 minutes. Ten times that and your developers stop running tests locally. CI times out. The TDD loop dies. The whole point of unit tests — fast feedback — is gone.

### 3. Resource overhead

Ollama-sized models are 3-70 GB on disk. `docker pull` on a CI runner taking 3 GB of layer cache makes your pipeline brittle. A laptop without a GPU starts thrashing memory and swapping. You now need an infrastructure project just to make tests runnable, which is the opposite of "tests should be easy to run."

### 4. You're testing the wrong thing

Even if determinism, speed, and memory weren't problems, the thing you'd be testing is whether the model handles the prompt correctly. That's AWS's problem. Your code could be catastrophically broken — build requests wrong, parse responses wrong, handle errors wrong — and if the model happens to hallucinate a passable answer, your test passes.

Conversely, if the model has a bad day (bad weights snapshot, a silent version bump), your tests fail even though your code is fine. You spend an hour bisecting the CI failure only to discover Claude got 3% worse at following instructions last Tuesday.

This inverts cause and effect. Tests should tell you about your code. They shouldn't be a regression suite against a foundation model.

## What tests actually need

1. **Deterministic output.** Given the same input, same output. Every time.
2. **Configurable responses.** Different tests want the model to return different things. You want to control that explicitly.
3. **Fault injection.** Your retry logic needs to be exercised. Your fallback-model logic needs to be exercised. Your rate-limit handler needs to be exercised. You can't wait for real throttling to happen.
4. **Call history.** Did my code send the right prompt? Did it set the right temperature? Did it include the right system message? Right tool definitions? Those are assertions about *your code*.
5. **Sub-millisecond latency.** Tests should fly.
6. **No external dependencies.** CI should work offline.

A real LLM gives you none of those. A mock library (moto, `@aws-sdk-client-mock`) gives you 1, 2, and 4, but misses the HTTP path entirely — your code's request-assembly bugs go untested.

The thing that gives you all six is a [Bedrock emulator](/bedrock-emulator/): a real HTTP server speaking Bedrock's wire protocol, with configurable responses and fault injection. That's what fakecloud is.

## What this looks like in practice

You write a test. You configure fakecloud to return a specific response when it sees a specific prompt. Your code runs. It sends a real HTTP request to `localhost:4566`. The request is parsed by a real JSON parser, routed through a real request validator, and responded to with your fixture. Your code parses the response, does its thing, and you assert on the outcome.

```ts
import { FakeCloud } from "fakecloud";
import {
  BedrockRuntimeClient,
  InvokeModelCommand,
} from "@aws-sdk/client-bedrock-runtime";

const fc = new FakeCloud();
const rt = new BedrockRuntimeClient({ endpoint: "http://localhost:4566" });

beforeEach(() => fc.reset());

test("spam classifier marks borderline scores for human review", async () => {
  await fc.bedrock.setResponseRule({
    whenPromptContains: "classify spam",
    respond: {
      completion: JSON.stringify({ label: "borderline", confidence: 0.62 }),
    },
  });

  const { routedTo } = await classifyEmail(rt, "buy now!!");

  expect(routedTo).toBe("human-review");
});

test("classifier retries on throttling with backoff", async () => {
  await fc.bedrock.injectFault({
    operation: "InvokeModel",
    error: "ThrottlingException",
    count: 2,
  });
  await fc.bedrock.setResponseRule({
    whenPromptContains: "classify spam",
    respond: { completion: JSON.stringify({ label: "spam" }) },
  });

  const { routedTo } = await classifyEmail(rt, "buy now!!");

  expect(routedTo).toBe("spam-folder");
  expect((await fc.bedrock.getCallHistory()).length).toBe(3);
});
```

Both tests run in 30ms. Both are deterministic. Both test your code, not the model.

## But I want *some* tests that hit real Bedrock

Good instinct. Keep those separate.

Put them in a suite gated behind an env var (`RUN_REAL_BEDROCK_TESTS=1`). Run them once per release, not once per PR. They'll catch:

- Major AWS API shape changes
- Model version bumps that alter response format
- IAM permission changes

That's a fundamentally different job from "did my PR break my code." Mixing them produces a test suite that's flaky, slow, expensive, and hides real regressions under model noise.

The unit/integration suite, which is 99% of your runs, should hit fakecloud. The real-bedrock suite, which is a few dozen targeted tests, runs weekly. This is the same pattern every team that tests against cloud APIs converges on — you just have to name it.

## A word on Ollama

Ollama is great. It's not a Bedrock emulator. It speaks its own HTTP protocol (roughly OpenAI-compatible), runs real models, and is the right tool for developer-time exploratory prompting.

LocalStack's Ultimate tier wraps Ollama in a Bedrock-shaped response — you get real inference on the local machine through the Bedrock SDK. Interesting product. Wrong tool for tests.

If you want to prototype a prompt, run Ollama directly. If you want to test the code that calls Bedrock with that prompt, use an emulator.

## Closing

The "tests should use a real LLM" instinct comes from a reasonable place — a fear that mocks lie, that configured responses can drift from reality, that you'll ship a bug because your tests were checking something different than production. That fear is real, and the answer is a real server (an emulator) that speaks the real wire protocol. What you don't need is real inference.

Your tests are about your code. The model is not your code.

## Links

- **Bedrock emulator** (landing): [/bedrock-emulator/](/bedrock-emulator/)
- **Tutorial with running code**: [How to test Bedrock code locally, for free, deterministically](/blog/bedrock-local-testing/)
- **LocalStack alternative for Bedrock**: [/localstack-bedrock-alternative/](/localstack-bedrock-alternative/)
- **GitHub**: [github.com/faiscadev/fakecloud](https://github.com/faiscadev/fakecloud)
