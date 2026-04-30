mod helpers;

use aws_sdk_s3::types::{
    BucketLifecycleConfiguration, ExpirationStatus, LifecycleExpiration, LifecycleRule,
    LifecycleRuleAndOperator, LifecycleRuleFilter, NoncurrentVersionExpiration, Tag, Transition,
    TransitionDefaultMinimumObjectSize, TransitionStorageClass,
};
use helpers::TestServer;

async fn round_trip(label: &str, rule: LifecycleRule) {
    let server = TestServer::start().await;
    let client = server.s3_client().await;
    let bucket = format!("lc-{}", label);

    client.create_bucket().bucket(&bucket).send().await.unwrap();

    client
        .put_bucket_lifecycle_configuration()
        .bucket(&bucket)
        .lifecycle_configuration(
            BucketLifecycleConfiguration::builder()
                .rules(rule.clone())
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    let resp = client
        .get_bucket_lifecycle_configuration()
        .bucket(&bucket)
        .send()
        .await
        .unwrap();

    let returned = resp.rules();
    assert_eq!(returned.len(), 1, "{label}: rule count mismatch");
    assert_eq!(&returned[0], &rule, "{label}: round-trip must match input");
}

#[tokio::test]
async fn lifecycle_prefix_filter_round_trips() {
    let rule = LifecycleRule::builder()
        .id("r1")
        .status(ExpirationStatus::Enabled)
        .filter(LifecycleRuleFilter::builder().prefix("logs/").build())
        .noncurrent_version_expiration(
            NoncurrentVersionExpiration::builder()
                .noncurrent_days(30)
                .build(),
        )
        .build()
        .unwrap();
    round_trip("prefix", rule).await;
}

#[tokio::test]
async fn lifecycle_empty_filter_round_trips() {
    let rule = LifecycleRule::builder()
        .id("r1")
        .status(ExpirationStatus::Enabled)
        .filter(LifecycleRuleFilter::builder().build())
        .expiration(LifecycleExpiration::builder().days(7).build())
        .build()
        .unwrap();
    round_trip("empty-filter", rule).await;
}

#[tokio::test]
async fn lifecycle_and_filter_round_trips() {
    let rule = LifecycleRule::builder()
        .id("r1")
        .status(ExpirationStatus::Enabled)
        .filter(
            LifecycleRuleFilter::builder()
                .and(
                    LifecycleRuleAndOperator::builder()
                        .prefix("data/")
                        .tags(Tag::builder().key("env").value("prod").build().unwrap())
                        .object_size_greater_than(1024)
                        .build(),
                )
                .build(),
        )
        .transitions(
            Transition::builder()
                .days(30)
                .storage_class(TransitionStorageClass::Glacier)
                .build(),
        )
        .build()
        .unwrap();
    round_trip("and-filter", rule).await;
}

/// Regression for the Terraform provider hang on `aws_s3_bucket_lifecycle_configuration`.
///
/// The provider's stable-state waiter polls `GetBucketLifecycleConfiguration`
/// until its response — including the `TransitionDefaultMinimumObjectSize`
/// field carried in the `x-amz-transition-default-minimum-object-size`
/// header — `reflect.DeepEqual`s the user's input. The provider schema
/// defaults the field to `all_storage_classes_128K`, so omitting the header
/// on GET makes the waiter loop until the resource times out.
#[tokio::test]
async fn lifecycle_get_returns_default_transition_min_size_header() {
    let server = TestServer::start().await;
    let client = server.s3_client().await;
    let bucket = "lc-tdmos-default";

    client.create_bucket().bucket(bucket).send().await.unwrap();

    let rule = LifecycleRule::builder()
        .id("expire")
        .status(ExpirationStatus::Enabled)
        .filter(LifecycleRuleFilter::builder().prefix("").build())
        .expiration(LifecycleExpiration::builder().days(1).build())
        .build()
        .unwrap();
    client
        .put_bucket_lifecycle_configuration()
        .bucket(bucket)
        .lifecycle_configuration(
            BucketLifecycleConfiguration::builder()
                .rules(rule)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();

    let resp = client
        .get_bucket_lifecycle_configuration()
        .bucket(bucket)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.transition_default_minimum_object_size(),
        Some(&TransitionDefaultMinimumObjectSize::AllStorageClasses128K),
        "GET must echo the AWS default header so Terraform's stable-state waiter terminates"
    );
}

#[tokio::test]
async fn lifecycle_round_trips_explicit_transition_min_size_header() {
    let server = TestServer::start().await;
    let client = server.s3_client().await;
    let bucket = "lc-tdmos-explicit";

    client.create_bucket().bucket(bucket).send().await.unwrap();

    let rule = LifecycleRule::builder()
        .id("expire")
        .status(ExpirationStatus::Enabled)
        .filter(LifecycleRuleFilter::builder().prefix("").build())
        .expiration(LifecycleExpiration::builder().days(1).build())
        .build()
        .unwrap();
    let put = client
        .put_bucket_lifecycle_configuration()
        .bucket(bucket)
        .transition_default_minimum_object_size(
            TransitionDefaultMinimumObjectSize::VariesByStorageClass,
        )
        .lifecycle_configuration(
            BucketLifecycleConfiguration::builder()
                .rules(rule)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    assert_eq!(
        put.transition_default_minimum_object_size(),
        Some(&TransitionDefaultMinimumObjectSize::VariesByStorageClass),
    );

    let resp = client
        .get_bucket_lifecycle_configuration()
        .bucket(bucket)
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.transition_default_minimum_object_size(),
        Some(&TransitionDefaultMinimumObjectSize::VariesByStorageClass),
    );
}
