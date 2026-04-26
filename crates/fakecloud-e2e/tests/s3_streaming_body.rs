mod helpers;

use aws_sdk_s3::primitives::ByteStream;
use aws_sdk_s3::types::{CompletedMultipartUpload, CompletedPart};
use helpers::TestServer;

/// PutObject for an object larger than the legacy 128 MiB dispatch
/// cap must succeed. The streaming dispatch path skips the cap for
/// S3 PUT object routes; the per-service handler spools chunks to a
/// tempfile while computing MD5 in constant memory and hands the
/// resulting [`BodySource::File`] to the persistence store, so the
/// payload never materializes as a single in-memory `Bytes`.
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

/// UploadPart with a >128 MiB part body must succeed. UploadPart goes
/// through the same streaming spool path as PutObject — each part is
/// written to a tempfile chunk-by-chunk, MD5 computed streaming, and
/// the resulting `BodyRef` (Disk in persistent mode, Memory after
/// read-back in memory mode) is what the in-memory MPU state retains.
/// A multipart upload that combines two 80 MiB parts exercises the
/// full pipeline: CreateMultipartUpload -> two streamed UploadPart
/// calls -> CompleteMultipartUpload -> GetObject round-trip.
#[tokio::test]
async fn s3_streaming_upload_part_round_trip() {
    let server = TestServer::start().await;
    let s3 = server.s3_client().await;

    s3.create_bucket()
        .bucket("stream-mpu")
        .send()
        .await
        .unwrap();

    let init = s3
        .create_multipart_upload()
        .bucket("stream-mpu")
        .key("big.bin")
        .send()
        .await
        .unwrap();
    let upload_id = init.upload_id().unwrap().to_string();

    // Two 80 MiB parts — each well below the historical buffered cap
    // but large enough to verify chunked spool reads/writes.
    let part_size = 80 * 1024 * 1024;
    let part1 = vec![0xA5u8; part_size];
    let part2 = vec![0x5Au8; part_size];

    let resp1 = s3
        .upload_part()
        .bucket("stream-mpu")
        .key("big.bin")
        .upload_id(&upload_id)
        .part_number(1)
        .body(ByteStream::from(part1.clone()))
        .send()
        .await
        .expect("UploadPart 1 should succeed");
    let resp2 = s3
        .upload_part()
        .bucket("stream-mpu")
        .key("big.bin")
        .upload_id(&upload_id)
        .part_number(2)
        .body(ByteStream::from(part2.clone()))
        .send()
        .await
        .expect("UploadPart 2 should succeed");

    let completed = CompletedMultipartUpload::builder()
        .parts(
            CompletedPart::builder()
                .part_number(1)
                .e_tag(resp1.e_tag().unwrap())
                .build(),
        )
        .parts(
            CompletedPart::builder()
                .part_number(2)
                .e_tag(resp2.e_tag().unwrap())
                .build(),
        )
        .build();

    s3.complete_multipart_upload()
        .bucket("stream-mpu")
        .key("big.bin")
        .upload_id(&upload_id)
        .multipart_upload(completed)
        .send()
        .await
        .expect("CompleteMultipartUpload should succeed");

    let got = s3
        .get_object()
        .bucket("stream-mpu")
        .key("big.bin")
        .send()
        .await
        .unwrap();
    let got_bytes = got.body.collect().await.unwrap().into_bytes();
    assert_eq!(got_bytes.len(), part_size * 2);
    assert!(got_bytes[..part_size].iter().all(|&b| b == 0xA5));
    assert!(got_bytes[part_size..].iter().all(|&b| b == 0x5A));
}
