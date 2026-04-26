+++
title = "CloudFront"
description = "CloudFront control plane — distributions, invalidations, web ACL/alias association, tags. Full DistributionConfig round-trip with ETag/If-Match concurrency."
weight = 24
+++

fakecloud implements CloudFront's REST-XML control plane focused on the operations real applications and Terraform stacks rely on: distribution lifecycle, invalidations, alias and web ACL association, tags, and read-only "by predicate" listings. 29 operations in this batch.

**Status: Batch 1 — distributions, invalidations, tagging, alias/web-ACL associations.** Origin Access Control, cache policies, origin request policies, response headers policies, CloudFront Functions, key groups, OAIs, streaming distributions, and the rest of the surface ship in subsequent batches.

## Supported today

- **Distributions** — `CreateDistribution`, `CreateDistributionWithTags`, `GetDistribution`, `GetDistributionConfig`, `UpdateDistribution`, `DeleteDistribution`, `ListDistributions`, `CopyDistribution`. Returns `ETag` headers; `UpdateDistribution` and `DeleteDistribution` enforce `If-Match`.
- **Distributions-by-X listings** — `ListDistributionsByCachePolicyId`, `ListDistributionsByOriginRequestPolicyId`, `ListDistributionsByResponseHeadersPolicyId`, `ListDistributionsByKeyGroup`, `ListDistributionsByWebACLId`, `ListDistributionsByVpcOriginId`, `ListDistributionsByAnycastIpListId`, `ListDistributionsByConnectionMode`, `ListDistributionsByConnectionFunction`, `ListDistributionsByOwnedResource`, `ListDistributionsByTrustStore`, `ListDistributionsByRealtimeLogConfig`.
- **Invalidations** — `CreateInvalidation` (returns `Completed` immediately for deterministic tests), `GetInvalidation`, `ListInvalidations`.
- **Tags** — `TagResource`, `UntagResource`, `ListTagsForResource` keyed by distribution ARN.
- **Aliases / Web ACL** — `AssociateAlias`, `ListConflictingAliases`, `AssociateDistributionWebACL`, `DisassociateDistributionWebACL`.

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
  --paths "/*" \
  --invalidation-batch '{"Paths":{"Quantity":1,"Items":["/*"]},"CallerReference":"inv-1"}'

# List
aws --endpoint-url http://localhost:4566 cloudfront list-invalidations --distribution-id "$ID"
```

## Not yet implemented (planned)

| Surface                                | Status                  |
|----------------------------------------|-------------------------|
| Origin Access Control + OAI (legacy)   | Batch 2 / 3             |
| Cache / Origin Request / Response Headers policies | Batch 2     |
| Continuous Deployment Policy           | Batch 2                 |
| CloudFront Functions + Key Value Stores | Batch 3                |
| Public Keys + Key Groups               | Batch 3                 |
| Field-Level Encryption                 | Batch 4                 |
| Real-time Log Config + Monitoring      | Batch 4                 |
| Streaming Distributions (legacy RTMP)  | Batch 4                 |
| VPC Origins + Anycast IP Lists         | Batch 5                 |
| Trust Stores + Distribution Tenants    | Batch 5                 |
| Connection Functions / Groups          | Batch 5                 |

There is no edge data plane: requests against a CloudFront distribution domain are not actually proxied to origins. Use ELBv2's in-process data plane for HTTP request matching tests today.
