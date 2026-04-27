+++
title = "Route 53"
description = "Route 53 control plane — hosted zones, RRsets, health checks, traffic policies, DNSSEC + KSK, query logging, CIDR collections, VPC associations, reusable delegation sets, geo locations, account limits, tags."
weight = 25
+++

fakecloud implements Amazon Route 53's REST-XML control plane end-to-end: hosted zone lifecycle, resource record sets with the full `ChangeResourceRecordSets` semantics (CREATE/UPSERT/DELETE), change tracking, hosted zone limits, list-by-name pagination, `TestDNSAnswer` synthesis, the full health-check lifecycle, versioned traffic policies with policy instances, DNSSEC signing + key-signing keys, query logging configs, CIDR collections, VPC associations + cross-account authorizations, reusable delegation sets, geo locations, account limits, and tags. 71 operations — the entire Route 53 control plane.

**Status: 100% control-plane coverage.** Batches 1–5 shipped.

## Supported today

- **Hosted Zones** — `CreateHostedZone`, `GetHostedZone`, `DeleteHostedZone`, `ListHostedZones`, `ListHostedZonesByName`, `GetHostedZoneCount`, `UpdateHostedZoneComment`, `UpdateHostedZoneFeatures`, `GetHostedZoneLimit`. `CreateHostedZone` seeds default `SOA` + `NS` records at the zone apex matching real Route 53 behavior, returns synthesized AWS name servers (`ns-2048.awsdns-64.com` + 3 siblings) in a `DelegationSet`, and rejects duplicate `CallerReference` with `HostedZoneAlreadyExists`. Private zones require a `VPC`. `DeleteHostedZone` enforces the `HostedZoneNotEmpty` rule when user-managed records exist. Comment and features are updatable in place.
- **Resource Record Sets** — `ChangeResourceRecordSets` accepts the full `ChangeBatch` shape with multiple `Change` entries and supports `CREATE` (rejects existing), `UPSERT` (replace-or-insert), and `DELETE` (errors on the default SOA/NS apex records). `ListResourceRecordSets` returns all record types with optional `SetIdentifier` for weighted/latency/failover routing. Each successful change emits a tracked `ChangeInfo` whose status is reported as `INSYNC` immediately for deterministic tests.
- **Change tracking** — `GetChange` returns per-batch `ChangeInfo` with the `INSYNC` status, submitted timestamp, and the comment from the originating batch.
- **DNS test** — `TestDNSAnswer` synthesizes an answer from the in-memory record set: it looks up the named record/type in the supplied hosted zone and returns the recorded values inside `<RecordData>` with `ResponseCode = NOERROR`. Resolver IP and EDNS0 client subnet IP are echoed back into the response.
- **Health Checks** — `CreateHealthCheck`, `GetHealthCheck`, `UpdateHealthCheck`, `DeleteHealthCheck`, `ListHealthChecks`, `GetHealthCheckCount`, `GetHealthCheckStatus`, `GetHealthCheckLastFailureReason`, `GetCheckerIpRanges`. Full lifecycle for HTTP/HTTPS/TCP/HTTP_STR_MATCH/HTTPS_STR_MATCH/CALCULATED/CLOUDWATCH_METRIC/RECOVERY_CONTROL types with the documented `HealthCheckConfig` shape (port, path, FQDN, search string, request interval, failure threshold, regions, alarm identifier, child checks, routing-control ARN, etc.). `CreateHealthCheck` rejects duplicate `CallerReference` with `HealthCheckAlreadyExists`. `UpdateHealthCheck` enforces optimistic concurrency via `HealthCheckVersion` (mismatch -> `HealthCheckVersionMismatch`), bumps the version on success, and honors the `ResetElements` list to clear `ChildHealthChecks` / `FullyQualifiedDomainName` / `Regions` / `ResourcePath`. `DeleteHealthCheck` rejects with `HealthCheckInUse` while any record set still references the check via `HealthCheckId`. `GetHealthCheckStatus` returns synthetic per-region observations (no real prober runs). `GetHealthCheckLastFailureReason` returns an empty observations list (fakecloud has no live checker). `GetCheckerIpRanges` returns the documented Route 53 health checker CIDRs.
- **Traffic Policies** — `CreateTrafficPolicy`, `GetTrafficPolicy`, `CreateTrafficPolicyVersion`, `UpdateTrafficPolicyComment`, `DeleteTrafficPolicy`, `ListTrafficPolicies`, `ListTrafficPolicyVersions`. Each policy carries an immutable `Id` and a monotonically increasing `Version`; `CreateTrafficPolicyVersion` keeps every prior version queryable via `GetTrafficPolicy(Id, Version)`. `CreateTrafficPolicy` rejects a duplicate `Name` with `TrafficPolicyAlreadyExists`. `DeleteTrafficPolicy` rejects with `TrafficPolicyInUse` while any traffic policy instance still references that `(Id, Version)`. The `Type` field is inferred from the policy document's `RecordType` JSON key and defaults to `A` when absent.
- **Traffic Policy Instances** — `CreateTrafficPolicyInstance`, `GetTrafficPolicyInstance`, `UpdateTrafficPolicyInstance`, `DeleteTrafficPolicyInstance`, `ListTrafficPolicyInstances`, `ListTrafficPolicyInstancesByHostedZone`, `ListTrafficPolicyInstancesByPolicy`, `GetTrafficPolicyInstanceCount`. `CreateTrafficPolicyInstance` validates the target hosted zone exists, validates the `(TrafficPolicyId, TrafficPolicyVersion)` resolves to a real policy, and rejects a duplicate `(HostedZoneId, Name, Type)` instance with `TrafficPolicyInstanceAlreadyExists`. The instance `State` is reported as `Applied` immediately for deterministic tests — fakecloud does not emulate the real `Creating -> Applied` propagation window.
- **DNSSEC + Key Signing Keys** — `GetDNSSEC`, `EnableHostedZoneDNSSEC`, `DisableHostedZoneDNSSEC`, `CreateKeySigningKey`, `DeleteKeySigningKey`, `ActivateKeySigningKey`, `DeactivateKeySigningKey`. `GetDNSSEC` returns the per-zone `ServeSignature` (`SIGNING`/`NOT_SIGNING`, default `NOT_SIGNING`) plus every KSK attached to the zone. `CreateKeySigningKey` requires `CallerReference`, `HostedZoneId`, `KeyManagementServiceArn`, `Name`, and `Status`; rejects a duplicate `Name` per zone with `KeySigningKeyAlreadyExists`; synthesizes the `KeyTag`/`Flag`/`SigningAlgorithm`/`DigestAlgorithm` fields with the documented `ECDSAP256SHA256`/SHA-256 defaults. `DeleteKeySigningKey` returns `InvalidKeySigningKeyStatus` when the KSK is still `ACTIVE` — flip to `INACTIVE` via `DeactivateKeySigningKey` first. `Enable`/`Disable`/`Activate`/`Deactivate` each emit a tracked `ChangeInfo` (`INSYNC`).
- **Query Logging** — `CreateQueryLoggingConfig`, `GetQueryLoggingConfig`, `DeleteQueryLoggingConfig`, `ListQueryLoggingConfigs`. One config per zone; private zones are rejected with `InvalidInput`; duplicate per zone returns `QueryLoggingConfigAlreadyExists`. Configs persist the `CloudWatchLogsLogGroupArn` round-trip but fakecloud doesn't actually publish DNS query logs (no real DNS resolver runs).
- **CIDR Collections** — `CreateCidrCollection`, `ChangeCidrCollection`, `DeleteCidrCollection`, `ListCidrCollections`, `ListCidrLocations`, `ListCidrBlocks`. `CreateCidrCollection` rejects duplicate `Name` with `CidrCollectionAlreadyExistsException` and synthesizes a real Route 53 ARN. `ChangeCidrCollection` honors `PUT` and `DELETE_IF_EXISTS` change actions, applies the entire batch atomically (any unknown action rolls back), and enforces optimistic concurrency via `CollectionVersion` (`CidrCollectionVersionMismatchException`). `DeleteCidrCollection` returns `CidrCollectionInUseException` while any location still has CIDR blocks.
- **VPC Associations** — `AssociateVPCWithHostedZone`, `DisassociateVPCFromHostedZone`, `CreateVPCAssociationAuthorization`, `DeleteVPCAssociationAuthorization`, `ListVPCAssociationAuthorizations`, `ListHostedZonesByVPC`. Both `Associate`/`Disassociate` validate that the target hosted zone exists and is private; public zones are rejected with `PublicZoneVPCAssociation`, and `Disassociate` refuses to remove the last remaining VPC with `LastVPCAssociation`. `CreateVPCAssociationAuthorization` records the authorized `(VPCId, VPCRegion)` per zone (idempotent on duplicate), and `Delete` removes a single entry — both reject unknown zones with `NoSuchHostedZone` and unknown authorizations with `VPCAssociationAuthorizationNotFound`. `ListHostedZonesByVPC` returns every zone associated with the supplied VPC, with the `/hostedzone/{Id}` prefix and an `Owner.OwningAccount` block.
- **Reusable Delegation Sets** — `CreateReusableDelegationSet`, `GetReusableDelegationSet`, `DeleteReusableDelegationSet`, `ListReusableDelegationSets`, `GetReusableDelegationSetLimit`. Each create synthesizes 4 NS records (the same `awsdns-*` shape as hosted zones) and rejects duplicate `CallerReference` with `DelegationSetAlreadyCreated`. `Delete` is blocked with `DelegationSetInUse` while any hosted zone still references the set. `GetReusableDelegationSetLimit` returns `MAX_ZONES_BY_REUSABLE_DELEGATION_SET` (value 500) with a live `Count` of zones currently using the set.
- **Geo Locations** — `ListGeoLocations`, `GetGeoLocation`. fakecloud ships a representative dataset (the 7 continents, the `*` default fallback, a sample of countries — BR, CA, DE, FR, GB, JP, US — and US subdivisions CA/NY/TX/WA) sufficient for `IsTruncated` + `NextContinentCode`/`NextCountryCode`/`NextSubdivisionCode` pagination. `GetGeoLocation` looks up the exact `(continent, country, subdivision)` triple and returns `NoSuchGeoLocation` when no entry matches.
- **Account Limits** — `GetAccountLimit`. All 5 owner-scoped limit types are honored: `MAX_HEALTH_CHECKS_BY_OWNER` (200), `MAX_HOSTED_ZONES_BY_OWNER` (500), `MAX_REUSABLE_DELEGATION_SETS_BY_OWNER` (100), `MAX_TRAFFIC_POLICIES_BY_OWNER` (50), `MAX_TRAFFIC_POLICY_INSTANCES_BY_OWNER` (5). The `Count` field is computed live from the in-memory state (e.g. `MAX_TRAFFIC_POLICIES_BY_OWNER` reports the distinct policy count, not the version count).
- **Tags** — `ChangeTagsForResource`, `ListTagsForResource`, `ListTagsForResources`. Both supported `ResourceType` values (`healthcheck`, `hostedzone`) round-trip the same tag bag. `Change` accepts `AddTags` (insert or update on key collision) and `RemoveTagKeys` in the same call; missing zones/health-checks return `NoSuchHostedZone`/`NoSuchHealthCheck`. The list responses sort tags by key for deterministic test output. Tags are independent of the hosted zone tag passed at create time and don't count toward `MAX_RRSETS_BY_ZONE`.

### Concurrency semantics

Route 53's wire protocol is REST-XML. There is no `If-Match` / `ETag` enforcement at the wire level for hosted zones — Route 53 itself does not require optimistic concurrency control here, and fakecloud follows the same model.

### Idempotency

`CreateHostedZone` rejects a duplicate `CallerReference` with `HostedZoneAlreadyExists` (matches real Route 53). The error response carries the existing zone's resource record set count.

### `ChangeBatch` semantics

The full action set is honored:

- `CREATE`: rejected with `InvalidChangeBatch` if `(Name, Type, SetIdentifier)` already exists.
- `UPSERT`: replaces an existing record set with the same `(Name, Type, SetIdentifier)` tuple, otherwise inserts.
- `DELETE`: rejected with `InvalidChangeBatch` if the target is not found, or if it would remove the default `SOA`/`NS` records at the zone apex.

The default SOA/NS records seeded by `CreateHostedZone` carry the AWS-shaped `awsdns-hostmaster.amazon.com.` mailbox and the synthesized name servers from the delegation set. `DeleteHostedZone` ignores them when checking emptiness.

## Smoke test

```sh
fakecloud &

# Create a hosted zone
ZONE=$(aws --endpoint-url http://localhost:4566 route53 create-hosted-zone \
  --name example.com \
  --caller-reference "$(date +%s)")

ID=$(echo "$ZONE" | jq -r '.HostedZone.Id')

# Add an A record
aws --endpoint-url http://localhost:4566 route53 change-resource-record-sets \
  --hosted-zone-id "$ID" \
  --change-batch '{
    "Changes": [
      {
        "Action": "UPSERT",
        "ResourceRecordSet": {
          "Name": "api.example.com.",
          "Type": "A",
          "TTL": 60,
          "ResourceRecords": [{"Value": "203.0.113.1"}]
        }
      }
    ]
  }'

# List records
aws --endpoint-url http://localhost:4566 route53 list-resource-record-sets --hosted-zone-id "$ID"

# Test DNS resolution
aws --endpoint-url http://localhost:4566 route53 test-dns-answer \
  --hosted-zone-id "${ID#/hostedzone/}" \
  --record-name api.example.com \
  --record-type A
```

## Caveats

There is no actual DNS server: requests against the synthesized name servers don't return live responses. `TestDNSAnswer` looks up records from the in-memory state and returns them; treat it as a record-set lookup, not a real DNS resolver. Likewise, fakecloud does not run real health probes: `GetHealthCheckStatus` returns synthesized observations and `GetHealthCheckLastFailureReason` is always empty. The data is structurally valid but never reflects a real endpoint outage. fakecloud also does not actually publish DNS query logs to CloudWatch Logs (no real DNS resolver runs) and ships a representative geo-location dataset rather than the full 200+-country ISO catalog Route 53 supports — sufficient for code paths that page through the catalog, but not exhaustive for every country lookup.
