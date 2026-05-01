use aws_sdk_firehose::primitives::Blob;
use aws_sdk_firehose::types::{BufferingHints, ExtendedS3DestinationConfiguration, Record};
use aws_sdk_s3::types::CreateBucketConfiguration;
use fakecloud_testkit::TestServer;

async fn setup(server: &TestServer, bucket: &str) -> aws_sdk_firehose::Client {
    let s3 = server.s3_client().await;
    let _ = s3
        .create_bucket()
        .bucket(bucket)
        .create_bucket_configuration(
            CreateBucketConfiguration::builder()
                .location_constraint(aws_sdk_s3::types::BucketLocationConstraint::UsWest2)
                .build(),
        )
        .send()
        .await;
    server.firehose_client().await
}

fn ext_s3(bucket_arn: &str) -> ExtendedS3DestinationConfiguration {
    ExtendedS3DestinationConfiguration::builder()
        .role_arn("arn:aws:iam::123456789012:role/firehose")
        .bucket_arn(bucket_arn)
        .buffering_hints(
            BufferingHints::builder()
                .size_in_mbs(5)
                .interval_in_seconds(60)
                .build(),
        )
        .build()
        .unwrap()
}

#[tokio::test]
async fn firehose_create_describe_delete_roundtrip() {
    let server = TestServer::start().await;
    let firehose = setup(&server, "fh-bucket-create").await;
    let bucket_arn = "arn:aws:s3:::fh-bucket-create";

    let create = firehose
        .create_delivery_stream()
        .delivery_stream_name("fh-stream-1")
        .extended_s3_destination_configuration(ext_s3(bucket_arn))
        .send()
        .await
        .expect("create");
    assert!(create
        .delivery_stream_arn()
        .unwrap()
        .ends_with(":deliverystream/fh-stream-1"));

    let desc = firehose
        .describe_delivery_stream()
        .delivery_stream_name("fh-stream-1")
        .send()
        .await
        .expect("describe");
    let d = desc.delivery_stream_description().unwrap();
    assert_eq!(d.delivery_stream_name(), "fh-stream-1");
    assert_eq!(d.delivery_stream_status().as_str(), "ACTIVE");

    let listed = firehose.list_delivery_streams().send().await.expect("list");
    assert!(listed
        .delivery_stream_names()
        .iter()
        .any(|n| n == "fh-stream-1"));

    firehose
        .delete_delivery_stream()
        .delivery_stream_name("fh-stream-1")
        .send()
        .await
        .expect("delete");

    let err = firehose
        .describe_delivery_stream()
        .delivery_stream_name("fh-stream-1")
        .send()
        .await;
    assert!(err.is_err());
}

#[tokio::test]
async fn firehose_put_record_writes_to_s3() {
    let server = TestServer::start().await;
    let firehose = setup(&server, "fh-bucket-put").await;
    let bucket_arn = "arn:aws:s3:::fh-bucket-put";

    firehose
        .create_delivery_stream()
        .delivery_stream_name("fh-put-stream")
        .extended_s3_destination_configuration(ext_s3(bucket_arn))
        .send()
        .await
        .expect("create");

    firehose
        .put_record()
        .delivery_stream_name("fh-put-stream")
        .record(
            Record::builder()
                .data(Blob::new(b"hello-firehose"))
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("put record");

    let s3 = server.s3_client().await;
    let listing = s3
        .list_objects_v2()
        .bucket("fh-bucket-put")
        .send()
        .await
        .expect("list");
    let key = listing
        .contents()
        .first()
        .expect("at least one object")
        .key()
        .unwrap()
        .to_string();
    let obj = s3
        .get_object()
        .bucket("fh-bucket-put")
        .key(&key)
        .send()
        .await
        .expect("get");
    let bytes = obj.body.collect().await.expect("collect").into_bytes();
    assert!(bytes.starts_with(b"hello-firehose"));
}

#[tokio::test]
async fn firehose_put_record_batch_aggregates_payloads() {
    let server = TestServer::start().await;
    let firehose = setup(&server, "fh-bucket-batch").await;
    let bucket_arn = "arn:aws:s3:::fh-bucket-batch";

    firehose
        .create_delivery_stream()
        .delivery_stream_name("fh-batch-stream")
        .extended_s3_destination_configuration(ext_s3(bucket_arn))
        .send()
        .await
        .expect("create");

    let resp = firehose
        .put_record_batch()
        .delivery_stream_name("fh-batch-stream")
        .records(
            Record::builder()
                .data(Blob::new(b"line-a"))
                .build()
                .unwrap(),
        )
        .records(
            Record::builder()
                .data(Blob::new(b"line-b"))
                .build()
                .unwrap(),
        )
        .records(
            Record::builder()
                .data(Blob::new(b"line-c"))
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("put batch");
    assert_eq!(resp.failed_put_count(), 0);
    assert_eq!(resp.request_responses().len(), 3);

    let s3 = server.s3_client().await;
    let listing = s3
        .list_objects_v2()
        .bucket("fh-bucket-batch")
        .send()
        .await
        .expect("list");
    let key = listing
        .contents()
        .first()
        .unwrap()
        .key()
        .unwrap()
        .to_string();
    let obj = s3
        .get_object()
        .bucket("fh-bucket-batch")
        .key(&key)
        .send()
        .await
        .expect("get");
    let bytes = obj.body.collect().await.expect("collect").into_bytes();
    let s = std::str::from_utf8(&bytes).unwrap();
    assert!(s.contains("line-a"));
    assert!(s.contains("line-b"));
    assert!(s.contains("line-c"));
}

#[tokio::test]
async fn firehose_tags_roundtrip() {
    let server = TestServer::start().await;
    let firehose = setup(&server, "fh-bucket-tags").await;
    let bucket_arn = "arn:aws:s3:::fh-bucket-tags";

    firehose
        .create_delivery_stream()
        .delivery_stream_name("fh-tags-stream")
        .extended_s3_destination_configuration(ext_s3(bucket_arn))
        .send()
        .await
        .expect("create");

    firehose
        .tag_delivery_stream()
        .delivery_stream_name("fh-tags-stream")
        .tags(
            aws_sdk_firehose::types::Tag::builder()
                .key("env")
                .value("prod")
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("tag");

    let listed = firehose
        .list_tags_for_delivery_stream()
        .delivery_stream_name("fh-tags-stream")
        .send()
        .await
        .expect("list tags");
    assert_eq!(listed.tags().len(), 1);
    assert_eq!(listed.tags()[0].key(), "env");

    firehose
        .untag_delivery_stream()
        .delivery_stream_name("fh-tags-stream")
        .tag_keys("env")
        .send()
        .await
        .expect("untag");
    let listed = firehose
        .list_tags_for_delivery_stream()
        .delivery_stream_name("fh-tags-stream")
        .send()
        .await
        .expect("list tags");
    assert_eq!(listed.tags().len(), 0);
}
