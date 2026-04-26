+++
title = "API Gateway v1"
description = "REST APIs, resources/methods/integrations, deployments, stages, API keys, usage plans, authorizers."
weight = 19
+++

fakecloud implements **124 of 124** API Gateway v1 (REST APIs) operations at 100% conformance for the implemented surface. v1 is exposed under the same SigV4 service name (`apigateway`) as v2; URL prefix selects which handler runs.

REST APIs (v1) and HTTP APIs (v2) are independent AWS services. The v2 (HTTP APIs) page is at [API Gateway v2](./apigatewayv2.md).

## Supported features

- **REST APIs** — CreateRestApi, GetRestApi(s), UpdateRestApi, PutRestApi (OpenAPI overwrite/merge), ImportRestApi, DeleteRestApi
- **Resources & methods** — full CRUD; nested paths; method requests/responses
- **Integrations** — `MOCK`, `HTTP`/`HTTP_PROXY`, `AWS_PROXY` (Lambda); integration responses
- **Deployments & stages** — CreateDeployment auto-creates a stage when `stageName` is set; cache flush operations
- **Models & request validators** — schema management; validator CRUD
- **Authorizers** — TOKEN, REQUEST, COGNITO_USER_POOLS shapes
- **API keys & usage plans** — CRUD + association via `usage_plan_keys`
- **VPC links, domain names, base path mappings, client certificates** — full CRUD
- **Documentation parts/versions** — full CRUD
- **Gateway responses** — full CRUD
- **Tags** — TagResource/UntagResource/GetTags
- **Account & SDKs** — GetAccount/UpdateAccount; GetSdk(Type|Types); GetExport
- **Test invoke** — TestInvokeMethod / TestInvokeAuthorizer

## Data plane

When a request arrives at a deployed stage URL (`/restapis/{api_id}/{stage}/{path...}` or via the configured stage), fakecloud walks the resource tree, picks the matching method/integration, and dispatches:

- `AWS_PROXY` — invokes the target Lambda via the same `DeliveryBus` used elsewhere; builds the v1.0 Lambda proxy event envelope (`event.version = "1.0"`, `requestContext.identity`, `multiValueHeaders`, `multiValueQueryStringParameters`, `pathParameters`, `stageVariables`, base64 body when binary).
- `HTTP` / `HTTP_PROXY` — forwards via `reqwest` to the configured URI.
- `MOCK` — returns an empty JSON body unless an integration response template overrides it.

## Protocol

REST-style URL dispatch. fakecloud's facade routes `/restapis/...`, `/apikeys`, `/usageplans`, `/vpclinks`, `/domainnames`, `/clientcertificates`, `/sdktypes`, `/tags`, `/account` to the v1 service; `/v2/...` to v2; the data plane (deployed stage URLs) is dispatched to whichever service owns the matching API. Wire format is HAL+JSON, matching the AWS SDK's expectation that list responses use the singular `item` key.

## Introspection

- `GET /_fakecloud/apigateway/requests` — list all data-plane requests served (method, path, headers, query params, status code, integration response)

## Cross-service delivery

- **API Gateway v1 -> Lambda** — REST API methods with `AWS_PROXY` integrations invoke Lambda functions with proxy event v1.0 format

## Why this matters

LocalStack paywalls API Gateway v1. fakecloud implements the full REST API surface free, with real route matching, real Lambda proxy integration, and full request introspection.

## Not yet implemented

- **DomainNameAccessAssociation** ops (4 ops): the AWS-side cross-account access association resource
- **CreateDocumentationPart** with the full property language: storage works, but property templating semantics are stubbed
- WAF wiring, VPC private endpoints, and edge-level canary deployments — these belong on the v1 follow-up roadmap

## Source

- [`crates/fakecloud-apigateway`](https://github.com/faiscadev/fakecloud/tree/main/crates/fakecloud-apigateway)
- [AWS API Gateway v1 API reference](https://docs.aws.amazon.com/apigateway/latest/api/API_Operations.html)
