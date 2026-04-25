+++
title = "Elastic Load Balancing v2"
description = "ELBv2 control plane — Application/Network/Gateway Load Balancer: load balancers, target groups + targets, listeners + rules + certificates, mTLS trust stores, attributes, capacity reservations, resource policies."
weight = 23
+++

fakecloud implements ELBv2 with full control-plane coverage across all three load balancer types: Application (ALB), Network (NLB), and Gateway (GWLB). 51 operations.

**Status: full API.** Covers load balancer CRUD, target groups + targets + health, listeners + rules + certificates, listener/load-balancer/target-group attributes, capacity reservations, mTLS trust stores + revocations, resource policies, IP pools, IP address types, subnets, security groups, SSL policies, and tags.

## Supported today (full API)

- **Load balancers** — `CreateLoadBalancer`, `DescribeLoadBalancers`, `DeleteLoadBalancer`, `SetSubnets`, `SetSecurityGroups`, `SetIpAddressType`, `ModifyIpPools`
- **Load balancer attributes** — `ModifyLoadBalancerAttributes`, `DescribeLoadBalancerAttributes`
- **Capacity reservations** — `ModifyCapacityReservation`, `DescribeCapacityReservation`
- **Target groups** — `CreateTargetGroup`, `DescribeTargetGroups`, `ModifyTargetGroup`, `DeleteTargetGroup` with cross-resource reference checks (rejects delete while a listener or rule still references the target group, including `ForwardConfig.TargetGroups`)
- **Targets** — `RegisterTargets`, `DeregisterTargets`, `DescribeTargetHealth`
- **Target group attributes** — `ModifyTargetGroupAttributes`, `DescribeTargetGroupAttributes`
- **Listeners** — `CreateListener`, `DescribeListeners`, `ModifyListener`, `DeleteListener` (cascades to rules), `DescribeListenerAttributes`, `ModifyListenerAttributes`
- **Listener certificates** — `AddListenerCertificates`, `RemoveListenerCertificates`, `DescribeListenerCertificates`
- **Listener rules** — `CreateRule`, `DescribeRules`, `ModifyRule`, `DeleteRule`, `SetRulePriorities` with positive-integer priority validation and target-group existence checks on `Actions`
- **mTLS trust stores** — `CreateTrustStore`, `DescribeTrustStores`, `ModifyTrustStore`, `DeleteTrustStore`, `DescribeTrustStoreAssociations`, `DeleteSharedTrustStoreAssociation`, `GetTrustStoreCaCertificatesBundle`
- **Trust store revocations** — `AddTrustStoreRevocations`, `RemoveTrustStoreRevocations`, `DescribeTrustStoreRevocations`, `GetTrustStoreRevocationContent`
- **Resource policies** — `GetResourcePolicy`
- **Tags** — `AddTags`, `RemoveTags`, `DescribeTags` across load balancers, target groups, listeners, rules, and trust stores
- **Limits / SSL policies** — `DescribeAccountLimits` returns AWS-published default limits; `DescribeSSLPolicies` returns predefined ALB security policies with exact protocol + cipher lists

### Validation matches AWS

- Load balancer name is 1-32 chars, alphanumeric or hyphens, no leading hyphen, no `internal-` prefix on `internet-facing` schemes — returns `ValidationError` with the same wire shape.
- `IpAddressType` is restricted to `ipv4`, `dualstack`, `dualstack-without-public-ipv4` — same enum check on `CreateLoadBalancer`, `SetIpAddressType`, and `SetSubnets`.
- Target group name validation, target type enum (`instance`, `ip`, `lambda`, `alb`), health check threshold ranges all match AWS.
- `DeleteTargetGroup` returns `ResourceInUse` when any listener default action or rule action — including those wrapped in `ForwardConfig.TargetGroups` — still references the target group.
- `CreateRule`/`ModifyRule` reject priority values <= 0 with `ValidationError`, and rule actions referencing a non-existent target group return `TargetGroupNotFound`.

### Idempotent creates

`CreateLoadBalancer` and `CreateTargetGroup` are idempotent on name within a single account: a second call with the same name returns the existing resource instead of throwing, matching AWS's documented idempotency behaviour.

## Smoke test

```sh
fakecloud &

# Create an ALB
LB=$(aws --endpoint-url http://localhost:4566 elbv2 create-load-balancer \
    --name web-alb --type application \
    --subnets subnet-aaa subnet-bbb \
    --query 'LoadBalancers[0].LoadBalancerArn' --output text)

# Create a target group
TG=$(aws --endpoint-url http://localhost:4566 elbv2 create-target-group \
    --name web-tg --protocol HTTP --port 80 --vpc-id vpc-12345 \
    --target-type instance \
    --query 'TargetGroups[0].TargetGroupArn' --output text)

# Wire the listener -> target group
aws --endpoint-url http://localhost:4566 elbv2 create-listener \
    --load-balancer-arn "$LB" --protocol HTTP --port 80 \
    --default-actions Type=forward,TargetGroupArn=$TG

# Register a target
aws --endpoint-url http://localhost:4566 elbv2 register-targets \
    --target-group-arn "$TG" --targets Id=i-deadbeef,Port=80

# Health is `healthy` by default — fakecloud doesn't probe the target.
aws --endpoint-url http://localhost:4566 elbv2 describe-target-health \
    --target-group-arn "$TG"
```

## Introspection

The `/_fakecloud/elbv2/*` endpoints let your tests assert directly on the persisted control-plane state without parsing XML responses:

- `GET /_fakecloud/elbv2/load-balancers` — every ALB/NLB/GWLB across every account
- `GET /_fakecloud/elbv2/target-groups` — every target group, including registered targets and current health
- `GET /_fakecloud/elbv2/listeners` — every listener, with port/protocol/SSL policy/default action
- `GET /_fakecloud/elbv2/rules` — every rule, including the default rules AWS auto-creates per listener

Wrapped by the first-party SDKs: `fc.elbv2().getLoadBalancers()` (TS/Java), `fc.elbv2.getLoadBalancers()` (Python), `fc.ELBv2().GetLoadBalancers(ctx)` (Go), `$fc->elbv2()->getLoadBalancers()` (PHP).

## Not yet implemented

- **In-process HTTP routing.** fakecloud stores the listener/rule wiring exactly, but does not bind a port per ALB and forward HTTP requests to registered targets. The control plane is complete; the data plane is the next axis. Open an issue if you have a use case that needs it.
- **Health probes.** Targets default to `healthy` since fakecloud does not actually call the target's health check endpoint. `DescribeTargetHealth` returns the synthetic state.
