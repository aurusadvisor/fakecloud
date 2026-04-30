//! Route 53 E2E tests against the AWS Rust SDK.

mod helpers;

use aws_sdk_route53::types::{
    Change, ChangeAction, ChangeBatch, HostedZoneConfig, ResourceRecord, ResourceRecordSet, RrType,
};
use helpers::TestServer;

#[tokio::test]
async fn create_get_delete_hosted_zone_lifecycle() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    let create = r53
        .create_hosted_zone()
        .name("example.com")
        .caller_reference("e2e-1")
        .hosted_zone_config(
            HostedZoneConfig::builder()
                .comment("e2e zone")
                .private_zone(false)
                .build(),
        )
        .send()
        .await
        .expect("create hosted zone");
    let zone = create.hosted_zone().expect("zone");
    let id = zone.id().to_string();
    assert!(id.starts_with("/hostedzone/"));
    let name = zone.name();
    assert_eq!(name, "example.com.");
    let dset = create.delegation_set().expect("delegation set");
    assert_eq!(dset.name_servers().len(), 4);

    let got = r53
        .get_hosted_zone()
        .id(&id)
        .send()
        .await
        .expect("get hosted zone");
    assert_eq!(got.hosted_zone().unwrap().id(), id);
    assert_eq!(
        got.hosted_zone().unwrap().resource_record_set_count(),
        Some(2)
    );

    let count = r53.get_hosted_zone_count().send().await.expect("count");
    assert!(count.hosted_zone_count() >= 1);

    let list = r53.list_hosted_zones().send().await.expect("list");
    assert!(!list.hosted_zones().is_empty());

    r53.delete_hosted_zone()
        .id(&id)
        .send()
        .await
        .expect("delete");
}

#[tokio::test]
async fn change_and_list_resource_record_sets() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    let create = r53
        .create_hosted_zone()
        .name("rrset.example.com")
        .caller_reference("e2e-rrset")
        .send()
        .await
        .expect("create");
    let zone_id = create.hosted_zone().unwrap().id().to_string();

    let rrset = ResourceRecordSet::builder()
        .name("api.rrset.example.com.")
        .r#type(RrType::A)
        .ttl(60)
        .resource_records(
            ResourceRecord::builder()
                .value("203.0.113.1")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let change = Change::builder()
        .action(ChangeAction::Upsert)
        .resource_record_set(rrset)
        .build()
        .unwrap();
    let batch = ChangeBatch::builder()
        .changes(change)
        .comment("upsert api A")
        .build()
        .unwrap();

    let upsert = r53
        .change_resource_record_sets()
        .hosted_zone_id(&zone_id)
        .change_batch(batch)
        .send()
        .await
        .expect("change RRsets");
    let change_info = upsert.change_info().expect("change info");
    let change_id = change_info.id().to_string();

    let list = r53
        .list_resource_record_sets()
        .hosted_zone_id(&zone_id)
        .send()
        .await
        .expect("list RRsets");
    let names: Vec<&str> = list
        .resource_record_sets()
        .iter()
        .map(|r| r.name())
        .collect();
    assert!(names.contains(&"api.rrset.example.com."));

    // Real Route53 returns PENDING during the propagation window then
    // INSYNC. Poll up to 10 reads — fakecloud flips after a small
    // fixed read-count threshold.
    let mut status = String::new();
    for _ in 0..10 {
        let got = r53
            .get_change()
            .id(&change_id)
            .send()
            .await
            .expect("get change");
        status = got.change_info().unwrap().status().as_str().to_string();
        if status == "INSYNC" {
            break;
        }
    }
    assert_eq!(status, "INSYNC");
}

#[tokio::test]
async fn delete_rrset_via_change_batch() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    let create = r53
        .create_hosted_zone()
        .name("delete.example.com")
        .caller_reference("e2e-delete")
        .send()
        .await
        .expect("create");
    let zone_id = create.hosted_zone().unwrap().id().to_string();

    let rrset = ResourceRecordSet::builder()
        .name("temp.delete.example.com.")
        .r#type(RrType::Cname)
        .ttl(300)
        .resource_records(
            ResourceRecord::builder()
                .value("origin.example.com")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    r53.change_resource_record_sets()
        .hosted_zone_id(&zone_id)
        .change_batch(
            ChangeBatch::builder()
                .changes(
                    Change::builder()
                        .action(ChangeAction::Create)
                        .resource_record_set(rrset.clone())
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("create rr");

    r53.change_resource_record_sets()
        .hosted_zone_id(&zone_id)
        .change_batch(
            ChangeBatch::builder()
                .changes(
                    Change::builder()
                        .action(ChangeAction::Delete)
                        .resource_record_set(rrset)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("delete rr");

    let list = r53
        .list_resource_record_sets()
        .hosted_zone_id(&zone_id)
        .send()
        .await
        .expect("list");
    let names: Vec<&str> = list
        .resource_record_sets()
        .iter()
        .map(|r| r.name())
        .collect();
    assert!(!names.contains(&"temp.delete.example.com."));
}

#[tokio::test]
async fn change_batch_is_atomic_on_invalid_change() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    let create = r53
        .create_hosted_zone()
        .name("atomic.example.com")
        .caller_reference("e2e-atomic")
        .send()
        .await
        .expect("create");
    let zone_id = create.hosted_zone().unwrap().id().to_string();

    let valid = ResourceRecordSet::builder()
        .name("ok.atomic.example.com.")
        .r#type(RrType::A)
        .ttl(60)
        .resource_records(
            ResourceRecord::builder()
                .value("203.0.113.10")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let invalid = ResourceRecordSet::builder()
        .name("missing.atomic.example.com.")
        .r#type(RrType::A)
        .ttl(60)
        .resource_records(
            ResourceRecord::builder()
                .value("203.0.113.20")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    let result = r53
        .change_resource_record_sets()
        .hosted_zone_id(&zone_id)
        .change_batch(
            ChangeBatch::builder()
                .changes(
                    Change::builder()
                        .action(ChangeAction::Create)
                        .resource_record_set(valid)
                        .build()
                        .unwrap(),
                )
                .changes(
                    Change::builder()
                        .action(ChangeAction::Delete)
                        .resource_record_set(invalid)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await;
    assert!(result.is_err(), "expected the batch to be rejected");

    // Atomicity: even though the first change was valid, the failure of
    // the second change must roll back the create so the zone still has
    // only its default SOA + NS records.
    let list = r53
        .list_resource_record_sets()
        .hosted_zone_id(&zone_id)
        .send()
        .await
        .expect("list after rejected batch");
    let names: Vec<&str> = list
        .resource_record_sets()
        .iter()
        .map(|r| r.name())
        .collect();
    assert!(!names.contains(&"ok.atomic.example.com."));
}

#[tokio::test]
async fn list_hosted_zones_by_name_works() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    r53.create_hosted_zone()
        .name("alpha.example.com")
        .caller_reference("byname-1")
        .send()
        .await
        .expect("create alpha");
    r53.create_hosted_zone()
        .name("beta.example.com")
        .caller_reference("byname-2")
        .send()
        .await
        .expect("create beta");

    let list = r53
        .list_hosted_zones_by_name()
        .send()
        .await
        .expect("list by name");
    assert!(list.hosted_zones().len() >= 2);
}

#[tokio::test]
async fn test_dns_answer_returns_record() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    let create = r53
        .create_hosted_zone()
        .name("dns.example.com")
        .caller_reference("e2e-dns")
        .send()
        .await
        .expect("create");
    let zone_id = create.hosted_zone().unwrap().id().to_string();
    // Strip /hostedzone/ prefix for the testdnsanswer endpoint.
    let zone_id_short = zone_id.trim_start_matches("/hostedzone/").to_string();

    let rrset = ResourceRecordSet::builder()
        .name("www.dns.example.com.")
        .r#type(RrType::A)
        .ttl(60)
        .resource_records(
            ResourceRecord::builder()
                .value("203.0.113.42")
                .build()
                .unwrap(),
        )
        .build()
        .unwrap();
    r53.change_resource_record_sets()
        .hosted_zone_id(&zone_id)
        .change_batch(
            ChangeBatch::builder()
                .changes(
                    Change::builder()
                        .action(ChangeAction::Upsert)
                        .resource_record_set(rrset)
                        .build()
                        .unwrap(),
                )
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("upsert");

    let answer = r53
        .test_dns_answer()
        .hosted_zone_id(zone_id_short)
        .record_name("www.dns.example.com")
        .record_type(RrType::A)
        .send()
        .await
        .expect("test dns");
    let data: Vec<&str> = answer.record_data().iter().map(|s| s.as_str()).collect();
    assert!(data.contains(&"203.0.113.42"));
}
