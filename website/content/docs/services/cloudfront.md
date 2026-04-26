+++
title = "CloudFront"
description = "CloudFront control plane — distributions, invalidations, web ACL/alias association, tags. Full DistributionConfig round-trip with ETag/If-Match concurrency."
weight = 24
+++

fakecloud implements CloudFront's REST-XML control plane focused on the operations real applications and Terraform stacks rely on: distribution lifecycle, invalidations, alias and web ACL association, tags, the full policy resource surface (OAC + Cache/OriginRequest/ResponseHeaders/ContinuousDeployment), CloudFront Functions, public keys + key groups, key value stores, legacy origin access identities, per-distribution monitoring subscriptions, the legacy RTMP streaming distributions, field-level encryption configs + profiles, realtime log configs, VPC origins, anycast IP lists, trust stores, and resource policies. 136 operations.

**Status: Batches 1-6a shipped.** Distribution tenants, connection groups, connection functions, domain ops, and managed certificate details are still pending in subsequent batches.

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
- **CloudFront Functions** — `CreateFunction`, `DescribeFunction`, `GetFunction` (returns raw source bytes), `UpdateFunction`, `DeleteFunction`, `ListFunctions`, `PublishFunction` (DEVELOPMENT -> LIVE), `TestFunction` (no-op execution returning the supplied event verbatim).
- **Public Keys + Key Groups** — full CRUD with `CallerReference` immutability on update.
- **Key Value Stores** — `CreateKeyValueStore` (with optional `ImportSource`), `DescribeKeyValueStore`, `UpdateKeyValueStore`, `DeleteKeyValueStore`, `ListKeyValueStores`.
- **Legacy Origin Access Identities** — `CreateCloudFrontOriginAccessIdentity`, `Get`, `GetConfig`, `Update`, `Delete`, `List`.
- **Monitoring Subscriptions** — `CreateMonitoringSubscription`, `GetMonitoringSubscription`, `DeleteMonitoringSubscription` keyed by distribution id.
- **Streaming Distributions (legacy RTMP)** — `CreateStreamingDistribution`, `CreateStreamingDistributionWithTags`, `GetStreamingDistribution`, `GetStreamingDistributionConfig`, `UpdateStreamingDistribution`, `DeleteStreamingDistribution`, `ListStreamingDistributions`. ETag/If-Match concurrency. `DeleteStreamingDistribution` enforces the AWS rule that the distribution must be `Enabled = false` before deletion (`StreamingDistributionNotDisabled`).
- **Field-Level Encryption** — `CreateFieldLevelEncryptionConfig`, `GetFieldLevelEncryption`, `GetFieldLevelEncryptionConfig`, `UpdateFieldLevelEncryptionConfig`, `DeleteFieldLevelEncryptionConfig`, `ListFieldLevelEncryptionConfigs`. ETag/If-Match concurrency, `CallerReference` immutability on update, duplicate `CallerReference` rejected with `FieldLevelEncryptionConfigAlreadyExists`.
- **Field-Level Encryption Profiles** — `CreateFieldLevelEncryptionProfile`, `GetFieldLevelEncryptionProfile`, `GetFieldLevelEncryptionProfileConfig`, `UpdateFieldLevelEncryptionProfile`, `DeleteFieldLevelEncryptionProfile`, `ListFieldLevelEncryptionProfiles`. Same concurrency + idempotency model as FLE configs.
- **Realtime Log Configs** — `CreateRealtimeLogConfig`, `GetRealtimeLogConfig` (by `Name` or `ARN`), `UpdateRealtimeLogConfig`, `DeleteRealtimeLogConfig` (by `Name` or `ARN`), `ListRealtimeLogConfigs`. Endpoint round-trip preserves `KinesisStreamConfig` `RoleARN`/`StreamARN` exactly.
- **VPC Origins** — `CreateVpcOrigin`, `GetVpcOrigin`, `UpdateVpcOrigin`, `DeleteVpcOrigin`, `ListVpcOrigins`. ETag/If-Match concurrency, duplicate `Name` rejected with `EntityAlreadyExists`. `DeleteVpcOrigin` returns the deleted resource and `ETag`. Status seeded as `Deployed` immediately for deterministic tests.
- **Anycast IP Lists** — `CreateAnycastIpList`, `GetAnycastIpList`, `UpdateAnycastIpList`, `DeleteAnycastIpList`, `ListAnycastIpLists`. `IpCount` validated to AWS allowed values (3 or 21). Synthesized deterministic `AnycastIps` payload returned on every read.
- **Trust Stores** — `CreateTrustStore`, `GetTrustStore` (by `identifier`), `UpdateTrustStore`, `DeleteTrustStore`, `ListTrustStores`. ETag/If-Match concurrency. `UpdateTrustStore` accepts the `httpPayload` `CaCertificatesBundleSource` body shape AWS uses (no name).
- **Resource Policies** — `PutResourcePolicy`, `GetResourcePolicy`, `DeleteResourcePolicy`. Policy documents are stored verbatim per resource ARN and round-tripped on get.

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
| Distribution Tenants                   | Batch 6b                |
| Connection Functions / Groups          | Batch 6b                |
| Domain ops + Managed Certificate       | Batch 6b                |

There is no edge data plane: requests against a CloudFront distribution domain are not actually proxied to origins. Use ELBv2's in-process data plane for HTTP request matching tests today.
