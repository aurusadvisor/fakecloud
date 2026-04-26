+++
title = "CloudFront"
description = "CloudFront control plane — distributions, invalidations, web ACL/alias association, tags. Full DistributionConfig round-trip with ETag/If-Match concurrency."
weight = 24
+++

fakecloud implements CloudFront's REST-XML control plane focused on the operations real applications and Terraform stacks rely on: distribution lifecycle, invalidations, alias and web ACL association, tags, and the full Origin Access Control + policy resource surface. 59 operations.

**Status: Batches 1-2 shipped.** CloudFront Functions, key groups, OAIs (legacy), public keys, streaming distributions, field-level encryption, real-time log config, VPC origins, anycast IP lists, trust stores, distribution tenants, and connection functions/groups are still pending across subsequent batches.

## Supported today

- **Distributions** — `CreateDistribution`, `CreateDistributionWithTags`, `GetDistribution`, `GetDistributionConfig`, `UpdateDistribution`, `DeleteDistribution`, `ListDistributions`, `CopyDistribution`. Returns `ETag` headers; `UpdateDistribution` and `DeleteDistribution` enforce `If-Match`.
- **Distributions-by-X listings** — `ListDistributionsByCachePolicyId`, `ListDistributionsByOriginRequestPolicyId`, `ListDistributionsByResponseHeadersPolicyId`, `ListDistributionsByKeyGroup`, `ListDistributionsByWebACLId`, `ListDistributionsByVpcOriginId`, `ListDistributionsByAnycastIpListId`, `ListDistributionsByConnectionMode`, `ListDistributionsByConnectionFunction`, `ListDistributionsByOwnedResource`, `ListDistributionsByTrustStore`, `ListDistributionsByRealtimeLogConfig`.
- **Invalidations** — `CreateInvalidation` (returns `Completed` immediately for deterministic tests), `GetInvalidation`, `ListInvalidations`.
- **Tags** — `TagResource`, `UntagResource`, `ListTagsForResource` keyed by distribution ARN.
- **Aliases / Web ACL** — `AssociateAlias`, `ListConflictingAliases`, `AssociateDistributionWebACL`, `DisassociateDistributionWebACL`.
- **Origin Access Control** — `CreateOriginAccessControl`, `GetOriginAccessControl`, `GetOriginAccessControlConfig`, `UpdateOriginAccessControl`, `DeleteOriginAccessControl`, `ListOriginAccessControls`. Full ETag/If-Match concurrency.
- **Cache Policy** — `CreateCachePolicy`, `GetCachePolicy`, `GetCachePolicyConfig`, `UpdateCachePolicy`, `DeleteCachePolicy`, `ListCachePolicies` with `?Type=managed|custom`. AWS-managed `Managed-CachingOptimized`, `Managed-CachingDisabled`, `Managed-CachingOptimizedForUncompressedObjects`, `Managed-Elemental*` are pre-seeded by their well-known IDs and reject `Update`/`Delete`.
- **Origin Request Policy** — `CreateOriginRequestPolicy`, `GetOriginRequestPolicy`, `GetOriginRequestPolicyConfig`, `UpdateOriginRequestPolicy`, `DeleteOriginRequestPolicy`, `ListOriginRequestPolicies`. Managed `Managed-CORS-S3Origin`, `Managed-CORS-CustomOrigin`, `Managed-AllViewer`, `Managed-UserAgentRefererHeaders`, `Managed-AllViewerExceptHostHeader` pre-seeded.
- **Response Headers Policy** — `CreateResponseHeadersPolicy`, `GetResponseHeadersPolicy`, `GetResponseHeadersPolicyConfig`, `UpdateResponseHeadersPolicy`, `DeleteResponseHeadersPolicy`, `ListResponseHeadersPolicies`. Managed `Managed-SimpleCORS`, `Managed-CORS-With-Preflight`, `Managed-SecurityHeadersPolicy` pre-seeded.
- **Continuous Deployment Policy** — `CreateContinuousDeploymentPolicy`, `GetContinuousDeploymentPolicy`, `GetContinuousDeploymentPolicyConfig`, `UpdateContinuousDeploymentPolicy`, `DeleteContinuousDeploymentPolicy`, `ListContinuousDeploymentPolicies`.

### Concurrency semantics

CloudFront's `ETag` model is preserved. Every successful `Create`/`Get`/`Update` returns the current `ETag` header, and `UpdateDistribution`/`DeleteDistribution` reject requests whose `If-Match` does not match the in-memory revision with `412 PreconditionFailed`. `DeleteDistribution` also enforces the AWS rule that the distribution must be `Enabled = false` before deletion (`DistributionNotDisabled`).

### `DistributionConfig` round-trip

`DistributionConfig` is parsed into typed Rust structs that cover the full standard surface — origins (S3, custom, VPC, OAC fields), cache behaviors (forwarded values, allowed methods, cached methods, function associations, lambda function associations, gRPC config), custom error responses, viewer certificates, geo restrictions, logging config, origin groups, tenant config — and is serialized back element-for-element. `GetDistributionConfig` returns exactly what `CreateDistribution`/`UpdateDistribution` accepted.

### Idempotency

`CreateDistribution` rejects a second call with the same `CallerReference` with `DistributionAlreadyExists` (matches AWS).

## Smoke test

```sh
fakecloud &

# Create a distribution
DIST=$(aws --endpoint-url http://localhost:4566 cloudfront create-distribution \
  --distribution-config '{
    "CallerReference": "smoke-1",
    "Comment": "smoke",
    "Enabled": true,
    "Origins": {
      "Quantity": 1,
      "Items": [
        { "Id": "primary", "DomainName": "origin.example.com",
          "CustomOriginConfig": { "HTTPPort": 80, "HTTPSPort": 443, "OriginProtocolPolicy": "https-only" } }
      ]
    },
    "DefaultCacheBehavior": {
      "TargetOriginId": "primary",
      "ViewerProtocolPolicy": "redirect-to-https",
      "MinTTL": 0
    }
  }')

ID=$(echo "$DIST" | jq -r '.Distribution.Id')

# Invalidate something
aws --endpoint-url http://localhost:4566 cloudfront create-invalidation \
  --distribution-id "$ID" \
  --invalidation-batch '{"Paths":{"Quantity":1,"Items":["/*"]},"CallerReference":"inv-1"}'

# List
aws --endpoint-url http://localhost:4566 cloudfront list-invalidations --distribution-id "$ID"
```

## Not yet implemented (planned)

| Surface                                | Status                  |
|----------------------------------------|-------------------------|
| Origin Access Identity (legacy OAI)    | Batch 3                 |
| CloudFront Functions + Key Value Stores | Batch 3                |
| Public Keys + Key Groups               | Batch 3                 |
| Field-Level Encryption                 | Batch 4                 |
| Real-time Log Config + Monitoring      | Batch 4                 |
| Streaming Distributions (legacy RTMP)  | Batch 4                 |
| VPC Origins + Anycast IP Lists         | Batch 5                 |
| Trust Stores + Distribution Tenants    | Batch 5                 |
| Connection Functions / Groups          | Batch 5                 |

There is no edge data plane: requests against a CloudFront distribution domain are not actually proxied to origins. Use ELBv2's in-process data plane for HTTP request matching tests today.
