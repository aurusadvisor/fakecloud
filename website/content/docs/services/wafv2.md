+++
title = "WAF v2"
description = "AWS WAF v2 — Web ACLs, rule groups, IP sets, regex pattern sets, API keys, logging configs, managed rule catalog, mobile SDK. JSON 1.1 protocol."
weight = 28
+++

fakecloud implements AWS WAF v2's full JSON 1.1 control plane: 55 operations covering Web ACLs, rule groups, IP sets, regex pattern sets, API keys, logging, permission policies, the managed rule catalog, and mobile SDK lookups. 100% Smithy conformance.

**Status: 100% control-plane coverage. No data-plane (no actual HTTP request inspection).**

## Supported today

- **Resource CRUD** — `WebACL`, `RuleGroup`, `IPSet`, `RegexPatternSet` all share the standard Create/Get/List/Update/Delete shape with `LockToken` optimistic concurrency. Every successful mutation rotates the token; using a stale value returns `WAFOptimisticLockException`. The `Id` in `Update`/`Delete` requests must match the named resource. Names are unique within `(Scope, Name)`. Both `REGIONAL` and `CLOUDFRONT` scope are supported and the ARN segment reflects the scope (`regional/webacl/...` vs `global/webacl/...`).
- **Capacity (WCU)** — `CheckCapacity` returns the WCU cost of a rule list as the recursive count of statement leaves through `AndStatement` / `OrStatement` / `NotStatement` composition. `CreateRuleGroup` rejects rules whose total exceeds the declared `Capacity` with `WAFLimitsExceededException`; `UpdateRuleGroup` re-validates against the existing capacity.
- **Web ACL <-> resource associations** — `AssociateWebACL`, `DisassociateWebACL`, `GetWebACLForResource`, `ListResourcesForWebACL`. Deleting a Web ACL with active associations returns `WAFAssociatedItemException`. Same exception fires when deleting a Rule Group still referenced by a Web ACL via `RuleGroupReferenceStatement`.
- **API keys** — `CreateAPIKey` / `DeleteAPIKey` / `GetDecryptedAPIKey` / `ListAPIKeys`. The opaque blob is a deterministic base64-encoded payload that round-trips the configured `TokenDomains`, so callers can verify their key contents without storing extra state.
- **Logging configurations** — `PutLoggingConfiguration` (validates the referenced Web ACL exists) / `GetLoggingConfiguration` / `DeleteLoggingConfiguration` / `ListLoggingConfigurations` (filters by scope).
- **Permission policies** — `PutPermissionPolicy` / `GetPermissionPolicy` / `DeletePermissionPolicy` for cross-account RuleGroup share. The policy string is stored verbatim.
- **Tags** — `TagResource` / `UntagResource` / `ListTagsForResource`. Unknown ARNs return `WAFNonexistentItemException`.
- **Managed rule catalog** — `AWSManagedRulesCommonRuleSet`, `AWSManagedRulesKnownBadInputsRuleSet`, `AWSManagedRulesSQLiRuleSet` are discoverable via `ListAvailableManagedRuleGroups`, with versioning history via `ListAvailableManagedRuleGroupVersions`. `DescribeManagedRuleGroup`, `DescribeAllManagedProducts`, `DescribeManagedProductsByVendor`, `GetManagedRuleSet` return shape-correct catalog metadata. Vendor-publishing ops (`PutManagedRuleSetVersions`, `UpdateManagedRuleSetVersionExpiryDate`, `ListManagedRuleSets`) accept the request and rotate the lock token but don't run a real publishing pipeline.
- **Mobile SDK** — `GenerateMobileSdkReleaseUrl`, `GetMobileSdkRelease`, `ListMobileSdkReleases` return synthesized URLs and metadata for the requested platform + release version.
- **Observability stubs** — `GetSampledRequests`, `GetTopPathStatisticsByTraffic`, `GetRateBasedStatementManagedKeys` return shape-correct empty windows. fakecloud doesn't observe real traffic.
- **Firewall Manager** — `DeleteFirewallManagerRuleGroups` clears the pre/post FM rule arrays on a Web ACL and rotates the lock token.

## Smoke test

```sh
fakecloud &

# Create an IP set we can reference from a Web ACL.
IPSET_ARN=$(aws --endpoint-url http://localhost:4566 wafv2 create-ip-set \
  --name blocklist --scope REGIONAL --ip-address-version IPV4 \
  --addresses 198.51.100.0/24 \
  --query 'Summary.ARN' --output text)

# Create a Web ACL with a single block-by-IP rule.
aws --endpoint-url http://localhost:4566 wafv2 create-web-acl \
  --name api-front \
  --scope REGIONAL \
  --default-action Allow={} \
  --rules "[{\"Name\":\"BlockBadIps\",\"Priority\":1,\"Action\":{\"Block\":{}},\"Statement\":{\"IPSetReferenceStatement\":{\"ARN\":\"$IPSET_ARN\"}},\"VisibilityConfig\":{\"SampledRequestsEnabled\":false,\"CloudWatchMetricsEnabled\":false,\"MetricName\":\"BlockBadIps\"}}]" \
  --visibility-config SampledRequestsEnabled=false,CloudWatchMetricsEnabled=false,MetricName=api-front

# List the Web ACLs in the REGIONAL scope and verify the new one is there.
aws --endpoint-url http://localhost:4566 wafv2 list-web-acls --scope REGIONAL

# Get the full Web ACL to inspect the computed WCU (Capacity field).
aws --endpoint-url http://localhost:4566 wafv2 get-web-acl \
  --name api-front --scope REGIONAL \
  --id $(aws --endpoint-url http://localhost:4566 wafv2 list-web-acls --scope REGIONAL --query 'WebACLs[?Name==`api-front`].Id | [0]' --output text)
```

## Caveats

fakecloud does not run any traffic through Web ACLs. There is no in-process HTTP filter for ALB / API Gateway / CloudFront associations — `AssociateWebACL` only updates the control-plane mapping so callers can verify their wiring. Real request blocking, rate limiting, CAPTCHA challenges, bot scoring, or label propagation does not happen.

`CheckCapacity` returns a leaf-count approximation of WCU rather than the exact published WCU costs per statement type. The relative ordering is correct (more leaves = more cost) and the `WAFLimitsExceededException` path is exercised, which is enough for capacity-planning unit tests but not for billing parity.

The managed rule catalog is a static seed of three popular AWS-vendor rule groups (`Common`, `KnownBadInputs`, `SQLi`). Vendor-publishing ops are accepted but no rule set is actually published; `ListManagedRuleSets` always returns an empty list. The Mobile SDK release URLs are synthesized — they don't point at a downloadable artifact.

`GetSampledRequests`, `GetTopPathStatisticsByTraffic`, and `GetRateBasedStatementManagedKeys` always return empty observability windows. fakecloud does not observe live traffic, so there is no real data to sample or rank.
