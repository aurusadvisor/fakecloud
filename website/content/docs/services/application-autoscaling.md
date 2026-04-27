+++
title = "Application Auto Scaling"
description = "AWS Application Auto Scaling — scalable targets, step / target-tracking / predictive policies, scheduled actions, scaling activities, predictive forecasts, tags. JSON 1.1 protocol."
weight = 27
+++

fakecloud implements AWS Application Auto Scaling's full JSON 1.1 control plane: 14 operations covering scalable targets, scaling policies, scheduled actions, scaling activities, predictive forecasts, and tags. 100% Smithy conformance.

**Status: 100% control-plane coverage.**

## Supported today

- **Scalable targets** — `RegisterScalableTarget` accepts `ServiceNamespace`, `ResourceId`, `ScalableDimension`, `MinCapacity`, `MaxCapacity`, `RoleARN`, `SuspendedState`. Re-registering an existing target only patches the supplied fields (PUT-merge). `RoleARN` defaults to the per-namespace service-linked role ARN (e.g. `AWSServiceRoleForApplicationAutoScaling_ECSService`). `DescribeScalableTargets` filters by `ServiceNamespace` + `ResourceIds` + `ScalableDimension` with `MaxResults` + `NextToken` pagination. `DeregisterScalableTarget` cascades: any `ScalingPolicy` or `ScheduledAction` for the same target is removed, so test state stays consistent. Supported namespaces include `ecs`, `lambda`, `dynamodb`, `rds`, `elasticache`, `sagemaker`, `elasticmapreduce`, `appstream`, `cassandra`, `kafka`, `neptune`, `ec2`, `comprehend`.
- **Scaling policies** — `PutScalingPolicy` accepts `PolicyName` + `PolicyType` (`StepScaling` / `TargetTrackingScaling` / `PredictiveScaling`) and stores the corresponding configuration verbatim (round-tripped through `DescribeScalingPolicies`). Returns a deterministic `PolicyARN` and an empty `Alarms` list. Without a registered scalable target, returns `ObjectNotFoundException`. `DescribeScalingPolicies` filters by `PolicyNames`/`ResourceId`/`ScalableDimension` and paginates. `DeleteScalingPolicy` removes by name + target tuple.
- **Scheduled actions** — `PutScheduledAction` accepts `Schedule` (`at(...)` / `rate(...)` / `cron(...)`), `Timezone`, `StartTime`, `EndTime`, `ScalableTargetAction` (`MinCapacity`/`MaxCapacity`). Existing actions PUT-merge supplied fields. `DescribeScheduledActions` paginates, filters by names + target. `DeleteScheduledAction` removes by name + target tuple. Targets must already be registered.
- **Scaling activities** — `DescribeScalingActivities` returns the per-target activity log newest-first with `IncludeNotScaledActivities` filtering (default suppresses `Failed`).
- **Predictive scaling forecast** — `GetPredictiveScalingForecast` requires the policy to be `PolicyType = PredictiveScaling` (otherwise `ValidationException`), then returns deterministic hourly Load + Capacity buckets between `StartTime` and `EndTime` capped at one week. Values are computed from the hour-of-day so tests can assert specific points.
- **Tags** — `TagResource` upserts tag pairs keyed by `ResourceARN`, `UntagResource` removes by `TagKeys`, `ListTagsForResource` returns the current tag map. Unknown ARNs return `ObjectNotFoundException`.

## Smoke test

```sh
fakecloud &

aws --endpoint-url http://localhost:4566 application-autoscaling register-scalable-target \
  --service-namespace ecs \
  --resource-id service/cluster/api \
  --scalable-dimension ecs:service:DesiredCount \
  --min-capacity 1 --max-capacity 10

aws --endpoint-url http://localhost:4566 application-autoscaling put-scaling-policy \
  --service-namespace ecs \
  --resource-id service/cluster/api \
  --scalable-dimension ecs:service:DesiredCount \
  --policy-name scale-out \
  --policy-type TargetTrackingScaling \
  --target-tracking-scaling-policy-configuration '{
    "TargetValue": 70.0,
    "PredefinedMetricSpecification": {"PredefinedMetricType": "ECSServiceAverageCPUUtilization"}
  }'

aws --endpoint-url http://localhost:4566 application-autoscaling describe-scaling-policies \
  --service-namespace ecs
```

## Caveats

fakecloud does not actually scale anything. `PutScalingPolicy` and `PutScheduledAction` store configurations verbatim and return them on `Describe*`, but no metric is collected, no alarm is created, and ECS task counts / Lambda concurrency / DynamoDB capacity are never adjusted. Predictive forecasts are deterministic synthetic curves, not actual ML predictions — useful for asserting your code reads the response shape correctly, not for any business logic. Scaling activities are an in-memory log seeded by the service itself; fakecloud doesn't emit any. CloudWatch alarms reported under `ScalingPolicy.Alarms` are always empty.
