//! CloudFront Batch 6b conformance tests: Connection Groups, Domain ops,
//! Managed Certificate Details, UpdateDistributionWithStagingConfig.
#![allow(deprecated)]

mod helpers;

use aws_sdk_cloudfront::types::{
    CookiePreference, DefaultCacheBehavior, DistributionConfig, DistributionResourceId,
    ForwardedValues, Headers, ItemSelection, Origin, Origins, ViewerProtocolPolicy,
};
use fakecloud_conformance_macros::test_action;
use helpers::TestServer;

fn minimal_config(caller_ref: &str) -> DistributionConfig {
    DistributionConfig::builder()
        .caller_reference(caller_ref)
        .comment("conf6b")
        .enabled(true)
        .origins(
            Origins::builder()
                .quantity(1)
                .items(
                    Origin::builder()
                        .id("primary")
                        .domain_name("example.com")
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .default_cache_behavior(
            DefaultCacheBehavior::builder()
                .target_origin_id("primary")
                .viewer_protocol_policy(ViewerProtocolPolicy::AllowAll)
                .forwarded_values(
                    ForwardedValues::builder()
                        .query_string(false)
                        .cookies(
                            CookiePreference::builder()
                                .forward(ItemSelection::None)
                                .build()
                                .unwrap(),
                        )
                        .headers(Headers::builder().quantity(0).build().unwrap())
                        .build()
                        .unwrap(),
                )
                .min_ttl(0)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

// ─── Connection Group ────────────────────────────────────────────────

#[test_action("cloudfront", "CreateConnectionGroup", checksum = "782b04fe")]
#[tokio::test]
async fn cf_create_connection_group() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    cf.create_connection_group()
        .name("conf-cg-1")
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "GetConnectionGroup", checksum = "b478c699")]
#[tokio::test]
async fn cf_get_connection_group() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let c = cf
        .create_connection_group()
        .name("conf-cg-2")
        .send()
        .await
        .unwrap();
    let id = c.connection_group().unwrap().id().unwrap().to_string();
    cf.get_connection_group()
        .identifier(&id)
        .send()
        .await
        .unwrap();
}

#[test_action(
    "cloudfront",
    "GetConnectionGroupByRoutingEndpoint",
    checksum = "11d95bf0"
)]
#[tokio::test]
async fn cf_get_connection_group_by_routing_endpoint() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let c = cf
        .create_connection_group()
        .name("conf-cg-3")
        .send()
        .await
        .unwrap();
    let re = c
        .connection_group()
        .unwrap()
        .routing_endpoint()
        .unwrap()
        .to_string();
    cf.get_connection_group_by_routing_endpoint()
        .routing_endpoint(&re)
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "UpdateConnectionGroup", checksum = "bcf2aca5")]
#[tokio::test]
async fn cf_update_connection_group() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let c = cf
        .create_connection_group()
        .name("conf-cg-4")
        .send()
        .await
        .unwrap();
    let id = c.connection_group().unwrap().id().unwrap().to_string();
    let etag = c.e_tag().unwrap().to_string();
    cf.update_connection_group()
        .id(&id)
        .if_match(&etag)
        .enabled(false)
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "DeleteConnectionGroup", checksum = "1c529024")]
#[tokio::test]
async fn cf_delete_connection_group() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let c = cf
        .create_connection_group()
        .name("conf-cg-5")
        .enabled(false)
        .send()
        .await
        .unwrap();
    let id = c.connection_group().unwrap().id().unwrap().to_string();
    let etag = c.e_tag().unwrap().to_string();
    cf.delete_connection_group()
        .id(&id)
        .if_match(&etag)
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "ListConnectionGroups", checksum = "dbbb2b6b")]
#[tokio::test]
async fn cf_list_connection_groups() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    cf.list_connection_groups().send().await.unwrap();
}

// ─── Domain ops ──────────────────────────────────────────────────────

#[test_action("cloudfront", "ListDomainConflicts", checksum = "cd7f51a5")]
#[tokio::test]
async fn cf_list_domain_conflicts() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    cf.list_domain_conflicts()
        .domain("example.com")
        .domain_control_validation_resource(
            DistributionResourceId::builder()
                .distribution_id("E1234")
                .build(),
        )
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "UpdateDomainAssociation", checksum = "5eac5bbc")]
#[tokio::test]
async fn cf_update_domain_association() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    cf.update_domain_association()
        .domain("docs.example.com")
        .target_resource(
            DistributionResourceId::builder()
                .distribution_id("E1234")
                .build(),
        )
        .send()
        .await
        .unwrap();
}

#[test_action("cloudfront", "VerifyDnsConfiguration", checksum = "5ae578cb")]
#[tokio::test]
async fn cf_verify_dns_configuration() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    cf.verify_dns_configuration()
        .identifier("CG123")
        .domain("docs.example.com")
        .send()
        .await
        .unwrap();
}

// ─── Managed certificate ─────────────────────────────────────────────

#[test_action("cloudfront", "GetManagedCertificateDetails", checksum = "83592b20")]
#[tokio::test]
async fn cf_get_managed_certificate_details() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    cf.get_managed_certificate_details()
        .identifier("CG123")
        .send()
        .await
        .unwrap();
}

// ─── Staging config ──────────────────────────────────────────────────

#[test_action(
    "cloudfront",
    "UpdateDistributionWithStagingConfig",
    checksum = "5275ba50"
)]
#[tokio::test]
async fn cf_update_distribution_with_staging_config() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let prod = cf
        .create_distribution()
        .distribution_config(minimal_config("conf-prod"))
        .send()
        .await
        .unwrap();
    let prod_id = prod.distribution().unwrap().id().to_string();
    let prod_etag = prod.e_tag().unwrap().to_string();
    let staging = cf
        .create_distribution()
        .distribution_config(minimal_config("conf-staging"))
        .send()
        .await
        .unwrap();
    let staging_id = staging.distribution().unwrap().id().to_string();
    cf.update_distribution_with_staging_config()
        .id(&prod_id)
        .staging_distribution_id(&staging_id)
        .if_match(&prod_etag)
        .send()
        .await
        .unwrap();
}
