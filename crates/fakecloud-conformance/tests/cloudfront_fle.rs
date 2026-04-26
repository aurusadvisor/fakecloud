//! CloudFront Batch 5 conformance tests: Field-Level Encryption + Realtime Log Configs.

mod helpers;

use aws_sdk_cloudfront::types::{
    ContentTypeProfileConfig, ContentTypeProfiles, EncryptionEntities, EndPoint,
    FieldLevelEncryptionConfig, FieldLevelEncryptionProfileConfig, FieldPatterns,
    KinesisStreamConfig, QueryArgProfileConfig, QueryArgProfiles,
};
use fakecloud_conformance_macros::test_action;
use helpers::TestServer;

fn fle_cfg(caller_ref: &str, profile_id: &str) -> FieldLevelEncryptionConfig {
    FieldLevelEncryptionConfig::builder()
        .caller_reference(caller_ref)
        .comment("conf fle config")
        .query_arg_profile_config(
            QueryArgProfileConfig::builder()
                .forward_when_query_arg_profile_is_unknown(true)
                .query_arg_profiles(QueryArgProfiles::builder().quantity(0).build().unwrap())
                .build()
                .unwrap(),
        )
        .content_type_profile_config(
            ContentTypeProfileConfig::builder()
                .forward_when_content_type_is_unknown(true)
                .content_type_profiles(
                    ContentTypeProfiles::builder()
                        .quantity(1)
                        .items(
                            aws_sdk_cloudfront::types::ContentTypeProfile::builder()
                                .format(aws_sdk_cloudfront::types::Format::UrlEncoded)
                                .profile_id(profile_id)
                                .content_type("application/x-www-form-urlencoded")
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

fn fle_profile_cfg(
    name: &str,
    caller_ref: &str,
    public_key_id: &str,
) -> FieldLevelEncryptionProfileConfig {
    FieldLevelEncryptionProfileConfig::builder()
        .name(name)
        .caller_reference(caller_ref)
        .comment("conf fle profile")
        .encryption_entities(
            EncryptionEntities::builder()
                .quantity(1)
                .items(
                    aws_sdk_cloudfront::types::EncryptionEntity::builder()
                        .public_key_id(public_key_id)
                        .provider_id("provider-1")
                        .field_patterns(
                            FieldPatterns::builder()
                                .quantity(1)
                                .items("ssn")
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

fn rtl_endpoint() -> EndPoint {
    EndPoint::builder()
        .stream_type("Kinesis")
        .kinesis_stream_config(
            KinesisStreamConfig::builder()
                .role_arn("arn:aws:iam::000000000000:role/cf-rtl")
                .stream_arn("arn:aws:kinesis:us-east-1:000000000000:stream/cf-rtl")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

// ─── Field-Level Encryption Profile ──────────────────────────────────

#[test_action(
    "cloudfront",
    "CreateFieldLevelEncryptionProfile",
    checksum = "981cd6c0"
)]
#[tokio::test]
async fn cf_create_fle_profile() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    cf.create_field_level_encryption_profile()
        .field_level_encryption_profile_config(fle_profile_cfg(
            "conf-prof-1",
            "conf-prof-1-ref",
            "K-conf",
        ))
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "GetFieldLevelEncryptionProfile", checksum = "dfa748cb")]
#[tokio::test]
async fn cf_get_fle_profile() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let c = cf
        .create_field_level_encryption_profile()
        .field_level_encryption_profile_config(fle_profile_cfg(
            "conf-prof-2",
            "conf-prof-2-ref",
            "K-conf-2",
        ))
        .send()
        .await
        .unwrap();
    let id = c.field_level_encryption_profile().unwrap().id().to_string();
    cf.get_field_level_encryption_profile()
        .id(&id)
        .send()
        .await
        .unwrap();
}

#[test_action(
    "cloudfront",
    "GetFieldLevelEncryptionProfileConfig",
    checksum = "7a1a298c"
)]
#[tokio::test]
async fn cf_get_fle_profile_config() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let c = cf
        .create_field_level_encryption_profile()
        .field_level_encryption_profile_config(fle_profile_cfg(
            "conf-prof-3",
            "conf-prof-3-ref",
            "K-conf-3",
        ))
        .send()
        .await
        .unwrap();
    let id = c.field_level_encryption_profile().unwrap().id().to_string();
    cf.get_field_level_encryption_profile_config()
        .id(&id)
        .send()
        .await
        .unwrap();
}

#[test_action(
    "cloudfront",
    "UpdateFieldLevelEncryptionProfile",
    checksum = "2c31e0a4"
)]
#[tokio::test]
async fn cf_update_fle_profile() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let c = cf
        .create_field_level_encryption_profile()
        .field_level_encryption_profile_config(fle_profile_cfg(
            "conf-prof-4",
            "conf-prof-4-ref",
            "K-conf-4",
        ))
        .send()
        .await
        .unwrap();
    let id = c.field_level_encryption_profile().unwrap().id().to_string();
    let etag = c.e_tag().unwrap().to_string();
    cf.update_field_level_encryption_profile()
        .id(&id)
        .if_match(&etag)
        .field_level_encryption_profile_config(fle_profile_cfg(
            "conf-prof-4",
            "conf-prof-4-ref",
            "K-conf-4-updated",
        ))
        .send()
        .await
        .unwrap();
}

#[test_action(
    "cloudfront",
    "DeleteFieldLevelEncryptionProfile",
    checksum = "babee9a8"
)]
#[tokio::test]
async fn cf_delete_fle_profile() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let c = cf
        .create_field_level_encryption_profile()
        .field_level_encryption_profile_config(fle_profile_cfg(
            "conf-prof-5",
            "conf-prof-5-ref",
            "K-conf-5",
        ))
        .send()
        .await
        .unwrap();
    let id = c.field_level_encryption_profile().unwrap().id().to_string();
    let etag = c.e_tag().unwrap().to_string();
    cf.delete_field_level_encryption_profile()
        .id(&id)
        .if_match(&etag)
        .send()
        .await
        .unwrap();
}

#[test_action(
    "cloudfront",
    "ListFieldLevelEncryptionProfiles",
    checksum = "ef5d8331"
)]
#[tokio::test]
async fn cf_list_fle_profiles() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    cf.list_field_level_encryption_profiles()
        .send()
        .await
        .unwrap();
}

// ─── Field-Level Encryption Config ───────────────────────────────────

#[test_action(
    "cloudfront",
    "CreateFieldLevelEncryptionConfig",
    checksum = "473ca30b"
)]
#[tokio::test]
async fn cf_create_fle_config() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let p = cf
        .create_field_level_encryption_profile()
        .field_level_encryption_profile_config(fle_profile_cfg(
            "conf-cfg-1-prof",
            "conf-cfg-1-prof-ref",
            "K-conf-cfg-1",
        ))
        .send()
        .await
        .unwrap();
    let pid = p.field_level_encryption_profile().unwrap().id().to_string();
    cf.create_field_level_encryption_config()
        .field_level_encryption_config(fle_cfg("conf-fle-1", &pid))
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "GetFieldLevelEncryption", checksum = "f48f22fb")]
#[tokio::test]
async fn cf_get_fle() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let p = cf
        .create_field_level_encryption_profile()
        .field_level_encryption_profile_config(fle_profile_cfg(
            "conf-cfg-2-prof",
            "conf-cfg-2-prof-ref",
            "K-conf-cfg-2",
        ))
        .send()
        .await
        .unwrap();
    let pid = p.field_level_encryption_profile().unwrap().id().to_string();
    let c = cf
        .create_field_level_encryption_config()
        .field_level_encryption_config(fle_cfg("conf-fle-2", &pid))
        .send()
        .await
        .unwrap();
    let id = c.field_level_encryption().unwrap().id().to_string();
    cf.get_field_level_encryption()
        .id(&id)
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "GetFieldLevelEncryptionConfig", checksum = "0c9cd446")]
#[tokio::test]
async fn cf_get_fle_config() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let p = cf
        .create_field_level_encryption_profile()
        .field_level_encryption_profile_config(fle_profile_cfg(
            "conf-cfg-3-prof",
            "conf-cfg-3-prof-ref",
            "K-conf-cfg-3",
        ))
        .send()
        .await
        .unwrap();
    let pid = p.field_level_encryption_profile().unwrap().id().to_string();
    let c = cf
        .create_field_level_encryption_config()
        .field_level_encryption_config(fle_cfg("conf-fle-3", &pid))
        .send()
        .await
        .unwrap();
    let id = c.field_level_encryption().unwrap().id().to_string();
    cf.get_field_level_encryption_config()
        .id(&id)
        .send()
        .await
        .unwrap();
}

#[test_action(
    "cloudfront",
    "UpdateFieldLevelEncryptionConfig",
    checksum = "bfdec725"
)]
#[tokio::test]
async fn cf_update_fle_config() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let p = cf
        .create_field_level_encryption_profile()
        .field_level_encryption_profile_config(fle_profile_cfg(
            "conf-cfg-4-prof",
            "conf-cfg-4-prof-ref",
            "K-conf-cfg-4",
        ))
        .send()
        .await
        .unwrap();
    let pid = p.field_level_encryption_profile().unwrap().id().to_string();
    let c = cf
        .create_field_level_encryption_config()
        .field_level_encryption_config(fle_cfg("conf-fle-4", &pid))
        .send()
        .await
        .unwrap();
    let id = c.field_level_encryption().unwrap().id().to_string();
    let etag = c.e_tag().unwrap().to_string();
    cf.update_field_level_encryption_config()
        .id(&id)
        .if_match(&etag)
        .field_level_encryption_config(fle_cfg("conf-fle-4", &pid))
        .send()
        .await
        .unwrap();
}

#[test_action(
    "cloudfront",
    "DeleteFieldLevelEncryptionConfig",
    checksum = "cfdfa01a"
)]
#[tokio::test]
async fn cf_delete_fle_config() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let p = cf
        .create_field_level_encryption_profile()
        .field_level_encryption_profile_config(fle_profile_cfg(
            "conf-cfg-5-prof",
            "conf-cfg-5-prof-ref",
            "K-conf-cfg-5",
        ))
        .send()
        .await
        .unwrap();
    let pid = p.field_level_encryption_profile().unwrap().id().to_string();
    let c = cf
        .create_field_level_encryption_config()
        .field_level_encryption_config(fle_cfg("conf-fle-5", &pid))
        .send()
        .await
        .unwrap();
    let id = c.field_level_encryption().unwrap().id().to_string();
    let etag = c.e_tag().unwrap().to_string();
    cf.delete_field_level_encryption_config()
        .id(&id)
        .if_match(&etag)
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "ListFieldLevelEncryptionConfigs", checksum = "cb22cfcd")]
#[tokio::test]
async fn cf_list_fle_configs() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    cf.list_field_level_encryption_configs()
        .send()
        .await
        .unwrap();
}

// ─── Realtime Log Config ─────────────────────────────────────────────

#[test_action("cloudfront", "CreateRealtimeLogConfig", checksum = "0a168a6c")]
#[tokio::test]
async fn cf_create_realtime_log() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    cf.create_realtime_log_config()
        .name("conf-rtl-1")
        .sampling_rate(50)
        .end_points(rtl_endpoint())
        .fields("timestamp")
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "GetRealtimeLogConfig", checksum = "df17669a")]
#[tokio::test]
async fn cf_get_realtime_log() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    cf.create_realtime_log_config()
        .name("conf-rtl-2")
        .sampling_rate(50)
        .end_points(rtl_endpoint())
        .fields("timestamp")
        .send()
        .await
        .unwrap();
    cf.get_realtime_log_config()
        .name("conf-rtl-2")
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "UpdateRealtimeLogConfig", checksum = "7d7ec1bf")]
#[tokio::test]
async fn cf_update_realtime_log() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let c = cf
        .create_realtime_log_config()
        .name("conf-rtl-3")
        .sampling_rate(50)
        .end_points(rtl_endpoint())
        .fields("timestamp")
        .send()
        .await
        .unwrap();
    let arn = c.realtime_log_config().unwrap().arn().to_string();
    cf.update_realtime_log_config()
        .name("conf-rtl-3")
        .arn(&arn)
        .sampling_rate(75)
        .end_points(rtl_endpoint())
        .fields("timestamp")
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "DeleteRealtimeLogConfig", checksum = "045810aa")]
#[tokio::test]
async fn cf_delete_realtime_log() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    cf.create_realtime_log_config()
        .name("conf-rtl-4")
        .sampling_rate(50)
        .end_points(rtl_endpoint())
        .fields("timestamp")
        .send()
        .await
        .unwrap();
    cf.delete_realtime_log_config()
        .name("conf-rtl-4")
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "ListRealtimeLogConfigs", checksum = "8edb787c")]
#[tokio::test]
async fn cf_list_realtime_logs() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    cf.list_realtime_log_configs().send().await.unwrap();
}
