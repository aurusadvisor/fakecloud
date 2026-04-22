+++
title = "fakecloud vs aws-sdk-client-mock"
description = "How fakecloud compares to aws-sdk-client-mock. In-process Node mocks vs a real HTTP AWS emulator; when each fits."
template = "page.html"
+++

[aws-sdk-client-mock](https://github.com/m-radzikowski/aws-sdk-client-mock) is an in-process mocking library for AWS SDK v3 in Node.js. You declare what responses each SDK call should return, and the library intercepts calls at the client level.

fakecloud is a real HTTP server that your SDK talks to.

## Architectural split

**aws-sdk-client-mock** is in-process. Your test process imports it, sets expectations, and the library patches SDK behavior. Never touches the network. Returns the exact shapes you scripted.

**fakecloud** is a separate process on port 4566, speaking the AWS wire protocol. Your SDK serializes a real HTTP request; fakecloud parses it, runs the emulated service behavior, and returns a real HTTP response. Cross-service wiring runs server-side.

## When to pick aws-sdk-client-mock

- **Pure unit tests** where you want the SDK to return specific, scripted responses.
- **You're asserting the SDK was called correctly**, not that downstream behavior worked.
- **No external process** in your CI — zero runtime dependencies.
- **Failure-path testing.** Scripting a specific error response is trivial with mocks and hard with real AWS-shaped emulation.

aws-sdk-client-mock excels at this. Don't drop it if it already works for your unit tests.

## When to pick fakecloud

- **Integration tests** that exercise cross-service flows (S3 -> Lambda, SQS -> Lambda, SNS fan-out).
- **Multi-language tests** — aws-sdk-client-mock is Node-only; fakecloud's HTTP server works with any AWS SDK.
- **Tests that need Lambda to actually run** — aws-sdk-client-mock stubs responses; fakecloud executes your function code.
- **Tests against Terraform/CDK/Serverless Framework deploys** — IaC tools talk to an HTTP endpoint, not an in-process library.
- **"Does my whole system actually work"** questions vs "does my SDK call look right."

## Complementary

Most Node teams use both:
- **aws-sdk-client-mock** for unit tests against a specific file (mock SQS return shape, check behavior).
- **fakecloud** for integration tests across files (put an object, expect the Lambda to run, expect the message to land in DynamoDB).

Both tools, different tiers of the test pyramid.

## Feature-level comparison

| | fakecloud | aws-sdk-client-mock |
|---|---|---|
| Language | Any (HTTP) | Node.js only |
| Runtime | External process | In-process |
| Real Lambda execution | Yes | No (stubbed) |
| Real cross-service wiring | Yes | No |
| Works with Terraform/CDK | Yes | No |
| Failure-path specificity | Medium (via normal AWS error codes) | High (script any response) |
| Test isolation | `/_fakecloud/reset` or unique resource names | Per-test by default |

## Links

- [fakecloud GitHub](https://github.com/faiscadev/fakecloud)
- [aws-sdk-client-mock GitHub](https://github.com/m-radzikowski/aws-sdk-client-mock)
- [Moto equivalent for Go/Java/Node](/blog/moto-equivalent-go-java-node/)
