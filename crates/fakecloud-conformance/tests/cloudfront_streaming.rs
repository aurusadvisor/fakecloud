//! CloudFront Batch 4 conformance tests: legacy Streaming Distributions.
#![allow(deprecated)]

mod helpers;

use aws_sdk_cloudfront::types::{
    PriceClass, S3Origin, StreamingDistributionConfig, StreamingDistributionConfigWithTags, Tag,
    Tags, TrustedSigners,
};
use fakecloud_conformance_macros::test_action;
use helpers::TestServer;

fn streaming_cfg(caller_ref: &str, enabled: bool) -> StreamingDistributionConfig {
    StreamingDistributionConfig::builder()
        .caller_reference(caller_ref)
        .s3_origin(
            S3Origin::builder()
                .domain_name("origin.example.com.s3.amazonaws.com")
                .origin_access_identity("")
                .build()
                .unwrap(),
        )
        .comment("conf streaming")
        .price_class(PriceClass::PriceClassAll)
        .enabled(enabled)
        .trusted_signers(
            TrustedSigners::builder()
                .enabled(false)
                .quantity(0)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

#[test_action("cloudfront", "CreateStreamingDistribution", checksum = "05c28ba1")]
#[tokio::test]
async fn cf_create_streaming() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    cf.create_streaming_distribution()
        .streaming_distribution_config(streaming_cfg("conf-sd-1", true))
        .send()
        .await
        .unwrap();
}

#[test_action(
    "cloudfront",
    "CreateStreamingDistributionWithTags",
    checksum = "8213fb25"
)]
#[tokio::test]
async fn cf_create_streaming_with_tags() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    cf.create_streaming_distribution_with_tags()
        .streaming_distribution_config_with_tags(
            StreamingDistributionConfigWithTags::builder()
                .streaming_distribution_config(streaming_cfg("conf-sd-tags", true))
                .tags(
                    Tags::builder()
                        .items(Tag::builder().key("env").value("conf").build().unwrap())
                        .build(),
                )
                .build(),
        )
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "GetStreamingDistribution", checksum = "f93c8468")]
#[tokio::test]
async fn cf_get_streaming() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let c = cf
        .create_streaming_distribution()
        .streaming_distribution_config(streaming_cfg("conf-sd-2", true))
        .send()
        .await
        .unwrap();
    let id = c.streaming_distribution().unwrap().id().to_string();
    cf.get_streaming_distribution()
        .id(&id)
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "GetStreamingDistributionConfig", checksum = "7fd6122b")]
#[tokio::test]
async fn cf_get_streaming_config() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let c = cf
        .create_streaming_distribution()
        .streaming_distribution_config(streaming_cfg("conf-sd-3", true))
        .send()
        .await
        .unwrap();
    let id = c.streaming_distribution().unwrap().id().to_string();
    cf.get_streaming_distribution_config()
        .id(&id)
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "UpdateStreamingDistribution", checksum = "93bc7366")]
#[tokio::test]
async fn cf_update_streaming() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let c = cf
        .create_streaming_distribution()
        .streaming_distribution_config(streaming_cfg("conf-sd-4", true))
        .send()
        .await
        .unwrap();
    let id = c.streaming_distribution().unwrap().id().to_string();
    let etag = c.e_tag().unwrap().to_string();
    cf.update_streaming_distribution()
        .id(&id)
        .if_match(&etag)
        .streaming_distribution_config(streaming_cfg("conf-sd-4", false))
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "DeleteStreamingDistribution", checksum = "303045d4")]
#[tokio::test]
async fn cf_delete_streaming() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let c = cf
        .create_streaming_distribution()
        .streaming_distribution_config(streaming_cfg("conf-sd-5", false))
        .send()
        .await
        .unwrap();
    let id = c.streaming_distribution().unwrap().id().to_string();
    let etag = c.e_tag().unwrap().to_string();
    cf.delete_streaming_distribution()
        .id(&id)
        .if_match(&etag)
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "ListStreamingDistributions", checksum = "b109420c")]
#[tokio::test]
async fn cf_list_streaming() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    cf.list_streaming_distributions().send().await.unwrap();
}
