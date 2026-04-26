//! Route 53 batch 1 conformance tests.

mod helpers;

use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType,
};
use fakecloud_conformance_macros::test_action;
use helpers::TestServer;

async fn create_zone(name: &str, caller_ref: &str) -> (TestServer, String) {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    let create = r53
        .create_hosted_zone()
        .name(name)
        .caller_reference(caller_ref)
        .send()
        .await
        .unwrap();
    let id = create.hosted_zone().unwrap().id().to_string();
    (server, id)
}

#[test_action("route53", "CreateHostedZone", checksum = "e594e59e")]
#[tokio::test]
async fn r53_create_hosted_zone() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.create_hosted_zone()
        .name("conf-create.example.com")
        .caller_reference("conf-create-1")
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "GetHostedZone", checksum = "43794ed0")]
#[tokio::test]
async fn r53_get_hosted_zone() {
    let (server, id) = create_zone("conf-get.example.com", "conf-get-1").await;
    let r53 = server.route53_client().await;
    r53.get_hosted_zone().id(&id).send().await.unwrap();
}

#[test_action("route53", "DeleteHostedZone", checksum = "1a69497f")]
#[tokio::test]
async fn r53_delete_hosted_zone() {
    let (server, id) = create_zone("conf-delete.example.com", "conf-delete-1").await;
    let r53 = server.route53_client().await;
    r53.delete_hosted_zone().id(&id).send().await.unwrap();
}

#[test_action("route53", "ListHostedZones", checksum = "0e45c3d2")]
#[tokio::test]
async fn r53_list_hosted_zones() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.list_hosted_zones().send().await.unwrap();
}

#[test_action("route53", "ListHostedZonesByName", checksum = "3e23374c")]
#[tokio::test]
async fn r53_list_hosted_zones_by_name() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.list_hosted_zones_by_name().send().await.unwrap();
}

#[test_action("route53", "GetHostedZoneCount", checksum = "1c2fc609")]
#[tokio::test]
async fn r53_get_hosted_zone_count() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.get_hosted_zone_count().send().await.unwrap();
}

#[test_action("route53", "UpdateHostedZoneComment", checksum = "dd19e245")]
#[tokio::test]
async fn r53_update_hosted_zone_comment() {
    let (server, id) = create_zone("conf-uc.example.com", "conf-uc-1").await;
    let r53 = server.route53_client().await;
    r53.update_hosted_zone_comment()
        .id(&id)
        .comment("updated")
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "UpdateHostedZoneFeatures", checksum = "ef731732")]
#[tokio::test]
async fn r53_update_hosted_zone_features() {
    let (server, id) = create_zone("conf-uf.example.com", "conf-uf-1").await;
    let r53 = server.route53_client().await;
    r53.update_hosted_zone_features()
        .hosted_zone_id(&id)
        .enable_accelerated_recovery(true)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "GetHostedZoneLimit", checksum = "740e6203")]
#[tokio::test]
async fn r53_get_hosted_zone_limit() {
    use aws_sdk_route53::types::HostedZoneLimitType;
    let (server, id) = create_zone("conf-lim.example.com", "conf-lim-1").await;
    let r53 = server.route53_client().await;
    r53.get_hosted_zone_limit()
        .hosted_zone_id(&id)
        .r#type(HostedZoneLimitType::MaxRrsetsByZone)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "ChangeResourceRecordSets", checksum = "ae7dc2da")]
#[tokio::test]
async fn r53_change_resource_record_sets() {
    let (server, id) = create_zone("conf-rrset.example.com", "conf-rrset-1").await;
    let r53 = server.route53_client().await;
    r53.change_resource_record_sets()
        .hosted_zone_id(&id)
        .change_batch(
            ChangeBatch::builder()
                .changes(
                    Change::builder()
                        .action(ChangeAction::Upsert)
                        .resource_record_set(
                            ResourceRecordSet::builder()
                                .name("a.conf-rrset.example.com.")
                                .r#type(RrType::A)
                                .ttl(60)
                                .resource_records(
                                    ResourceRecord::builder().value("1.2.3.4").build().unwrap(),
                                )
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "ListResourceRecordSets", checksum = "eae68038")]
#[tokio::test]
async fn r53_list_resource_record_sets() {
    let (server, id) = create_zone("conf-list.example.com", "conf-list-1").await;
    let r53 = server.route53_client().await;
    r53.list_resource_record_sets()
        .hosted_zone_id(&id)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "GetChange", checksum = "5b044b89")]
#[tokio::test]
async fn r53_get_change() {
    let (server, id) = create_zone("conf-change.example.com", "conf-change-1").await;
    let r53 = server.route53_client().await;
    let upsert = r53
        .change_resource_record_sets()
        .hosted_zone_id(&id)
        .change_batch(
            ChangeBatch::builder()
                .changes(
                    Change::builder()
                        .action(ChangeAction::Upsert)
                        .resource_record_set(
                            ResourceRecordSet::builder()
                                .name("a.conf-change.example.com.")
                                .r#type(RrType::A)
                                .ttl(60)
                                .resource_records(
                                    ResourceRecord::builder().value("1.2.3.4").build().unwrap(),
                                )
                                .build()
                                .unwrap(),
                        )
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
    let change_id = upsert.change_info().unwrap().id().to_string();
    r53.get_change().id(&change_id).send().await.unwrap();
}

#[test_action("route53", "TestDNSAnswer", checksum = "ed84eb75")]
#[tokio::test]
async fn r53_test_dns_answer() {
    let (server, id) = create_zone("conf-dns.example.com", "conf-dns-1").await;
    let r53 = server.route53_client().await;
    let id_short = id.trim_start_matches("/hostedzone/").to_string();
    r53.test_dns_answer()
        .hosted_zone_id(id_short)
        .record_name("conf-dns.example.com")
        .record_type(RrType::A)
        .send()
        .await
        .unwrap();
}
