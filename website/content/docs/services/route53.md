+++
title = "Route 53"
description = "Route 53 control plane — hosted zones, resource record sets, change tracking, TestDNSAnswer synthesis."
weight = 25
+++

fakecloud implements Amazon Route 53's REST-XML control plane focused on the operations real applications and Terraform stacks rely on for DNS management: hosted zone lifecycle, resource record sets with the full `ChangeResourceRecordSets` semantics (CREATE/UPSERT/DELETE), change tracking, hosted zone limits, list-by-name pagination, and `TestDNSAnswer` synthesis. 13 operations.

**Status: Batch 1 shipped.** Health checks, traffic policies, DNSSEC + key signing keys, query logging configs, CIDR collections, VPC associations + delegation sets, geo location lookups, account limits, and tags land in subsequent batches.

## Supported today

- **Hosted Zones** — `CreateHostedZone`, `GetHostedZone`, `DeleteHostedZone`, `ListHostedZones`, `ListHostedZonesByName`, `GetHostedZoneCount`, `UpdateHostedZoneComment`, `UpdateHostedZoneFeatures`, `GetHostedZoneLimit`. `CreateHostedZone` seeds default `SOA` + `NS` records at the zone apex matching real Route 53 behavior, returns synthesized AWS name servers (`ns-2048.awsdns-64.com` + 3 siblings) in a `DelegationSet`, and rejects duplicate `CallerReference` with `HostedZoneAlreadyExists`. Private zones require a `VPC`. `DeleteHostedZone` enforces the `HostedZoneNotEmpty` rule when user-managed records exist. Comment and features are updatable in place.
- **Resource Record Sets** — `ChangeResourceRecordSets` accepts the full `ChangeBatch` shape with multiple `Change` entries and supports `CREATE` (rejects existing), `UPSERT` (replace-or-insert), and `DELETE` (errors on the default SOA/NS apex records). `ListResourceRecordSets` returns all record types with optional `SetIdentifier` for weighted/latency/failover routing. Each successful change emits a tracked `ChangeInfo` whose status is reported as `INSYNC` immediately for deterministic tests.
- **Change tracking** — `GetChange` returns per-batch `ChangeInfo` with the `INSYNC` status, submitted timestamp, and the comment from the originating batch.
- **DNS test** — `TestDNSAnswer` synthesizes an answer from the in-memory record set: it looks up the named record/type in the supplied hosted zone and returns the recorded values inside `<RecordData>` with `ResponseCode = NOERROR`. Resolver IP and EDNS0 client subnet IP are echoed back into the response.

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

## Not yet implemented (planned)

| Surface                                | Status                  |
|----------------------------------------|-------------------------|
| Health Checks                          | next batch              |
| Traffic Policies + Instances           | next batch              |
| DNSSEC + Key Signing Keys              | next batch              |
| Query Logging Configs                  | next batch              |
| CIDR Collections                       | next batch              |
| VPC Associations + Delegation Sets     | next batch              |
| Geo Location lookups                   | next batch              |
| Tags                                   | next batch              |

There is no actual DNS server: requests against the synthesized name servers don't return live responses. `TestDNSAnswer` looks up records from the in-memory state and returns them; treat it as a record-set lookup, not a real DNS resolver.
