+++
title = "API Gateway v2"
description = "HTTP APIs, Lambda proxy integration, JWT and Lambda authorizers, CORS."
weight = 20
+++

fakecloud implements **103 of 103** API Gateway v2 operations at 100% conformance (HTTP APIs). REST APIs are covered separately on the [API Gateway v1](./apigateway.md) page.

## Supported features

- **HTTP APIs** — CreateApi, UpdateApi, DeleteApi, GetApis
- **WebSocket APIs** — CreateApi with `protocolType=WEBSOCKET`, live data plane upgrade endpoint
- **Routes** — path parameters, wildcards, HTTP method routing
- **Integrations** — Lambda proxy (v2.0 format), HTTP proxy, Mock integration
- **Stages** — CRUD, deployments, default stage
- **Authorizers** — JWT (OIDC issuers, audience validation) and Lambda authorizers
- **CORS** — configuration on routes and globally
- **Request history** — every request served is recorded for introspection
- **Deployments** — CreateDeployment, GetDeployments
- **Management API** — `apigatewaymanagementapi` ops (PostToConnection, GetConnection, DeleteConnection) at `/@connections/{id}` and `/{stage}/@connections/{id}`

## Protocol

REST for management, path-based routing for the executed API. WebSocket APIs upgrade at `/_fakecloud/apigatewayv2/ws/{api_id}` and the management API is served on the same host:port — point the AWS SDK's `apigatewaymanagementapi` client at the fakecloud endpoint URL.

## Introspection

- `GET /_fakecloud/apigatewayv2/requests` — list all HTTP API requests received (method, path, headers, query params, status code, integration response)
- `GET /_fakecloud/apigatewayv2/connections` — list live WebSocket connections with `connectionId`, `apiId`, `stage`, `connectedAt`, `lastActiveAt`, `sourceIp`

## Cross-service delivery

- **API Gateway v2 -> Lambda** — HTTP API routes invoke Lambda functions with proxy integration v2.0 event format

## Why this matters

LocalStack paywalls API Gateway v2. fakecloud implements the full HTTP API surface free, with real route matching, real Lambda proxy integration, and full request introspection. Webhook testing for event-driven applications is fully supported.

## Limitations

- The data plane is partially implemented. WebSocket support (`$connect`/`$disconnect`/`$default`), Lambda proxy integration, and HTTP proxy integration work. JWT authorizer enforcement, Lambda authorizer enforcement, AWS service integrations, stage-variable substitution, custom-domain `ApiMapping`, and access log delivery are either stubbed or partially implemented.

## Source

- [`crates/fakecloud-apigatewayv2`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-apigatewayv2)
- [AWS API Gateway v2 API reference](https://docs.aws.amazon.com/apigatewayv2/latest/api-reference/api-reference.html)
