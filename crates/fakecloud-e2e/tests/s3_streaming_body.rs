mod helpers;

use aws_sdk_s3::primitives::ByteStream;
use helpers::TestServer;

/// PutObject for an object larger than the legacy 128 MiB dispatch
/// cap must succeed. The streaming dispatch path skips the cap for
/// S3 PUT object routes; the per-service handler materializes via
/// `drain_request_stream` (no upper bound) and stores the bytes.
/// 200 MiB is comfortably above the old 128 MiB rejection threshold
/// while staying small enough to keep the test fast.
#[tokio::test]
async fn s3_streaming_put_object_above_legacy_cap() {
    let server = TestServer::start().await;
    let s3 = server.s3_client().await;

    s3.create_bucket()
        .bucket("stream-bucket")
        .send()
        .await
        .unwrap();

    // 200 MiB of zeros — well above the prior 128 MiB cap.
    let size = 200 * 1024 * 1024;
    let body = vec![0u8; size];

    let resp = s3
        .put_object()
        .bucket("stream-bucket")
        .key("big.bin")
        .body(ByteStream::from(body.clone()))
        .send()
        .await
        .expect("PutObject should succeed for 200 MiB body");
    assert!(resp.e_tag().is_some());

    let head = s3
        .head_object()
        .bucket("stream-bucket")
        .key("big.bin")
        .send()
        .await
        .unwrap();
    assert_eq!(head.content_length(), Some(size as i64));

    // Round-trip the bytes via GetObject to confirm full integrity.
    let got = s3
        .get_object()
        .bucket("stream-bucket")
        .key("big.bin")
        .send()
        .await
        .unwrap();
    let got_bytes = got.body.collect().await.unwrap().into_bytes();
    assert_eq!(got_bytes.len(), size);
    assert!(got_bytes.iter().all(|&b| b == 0));
}
