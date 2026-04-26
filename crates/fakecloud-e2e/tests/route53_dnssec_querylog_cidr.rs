//! Route 53 batch 4 E2E: DNSSEC + KSK + Query Logging + CIDR Collections.

mod helpers;

use aws_sdk_route53::types::CidrCollectionChange;
use helpers::TestServer;

async fn make_zone(server: &TestServer, name: &str, caller: &str) -> String {
    let r53 = server.route53_client().await;
    r53.create_hosted_zone()
        .name(name)
        .caller_reference(caller)
        .send()
        .await
        .expect("zone")
        .hosted_zone()
        .unwrap()
        .id()
        .to_string()
}

#[tokio::test]
async fn dnssec_status_default_and_toggle() {
    let server = TestServer::start().await;
    let zone = make_zone(&server, "dnssec.example.com", "dnssec-zone-1").await;
    let r53 = server.route53_client().await;

    let initial = r53
        .get_dnssec()
        .hosted_zone_id(&zone)
        .send()
        .await
        .expect("get dnssec");
    assert_eq!(
        initial.status().unwrap().serve_signature(),
        Some("NOT_SIGNING")
    );

    r53.enable_hosted_zone_dnssec()
        .hosted_zone_id(&zone)
        .send()
        .await
        .expect("enable");
    let after_enable = r53
        .get_dnssec()
        .hosted_zone_id(&zone)
        .send()
        .await
        .expect("get");
    assert_eq!(
        after_enable.status().unwrap().serve_signature(),
        Some("SIGNING")
    );

    r53.disable_hosted_zone_dnssec()
        .hosted_zone_id(&zone)
        .send()
        .await
        .expect("disable");
    let after_disable = r53
        .get_dnssec()
        .hosted_zone_id(&zone)
        .send()
        .await
        .expect("get");
    assert_eq!(
        after_disable.status().unwrap().serve_signature(),
        Some("NOT_SIGNING")
    );
}

#[tokio::test]
async fn ksk_lifecycle_and_status_transitions() {
    let server = TestServer::start().await;
    let zone = make_zone(&server, "ksk.example.com", "ksk-zone-1").await;
    let r53 = server.route53_client().await;

    let create = r53
        .create_key_signing_key()
        .caller_reference("ksk-1")
        .hosted_zone_id(&zone)
        .key_management_service_arn(
            "arn:aws:kms:us-east-1:000000000000:key/abcd1234-ee11-4422-bb33-aabbccddeeff",
        )
        .name("primary_ksk")
        .status("INACTIVE")
        .send()
        .await
        .expect("create ksk");
    let ksk = create.key_signing_key().expect("ksk");
    assert_eq!(ksk.name(), Some("primary_ksk"));
    assert_eq!(ksk.status(), Some("INACTIVE"));
    assert_eq!(ksk.flag(), 257);

    // Cannot delete an ACTIVE KSK; flip to ACTIVE first to confirm guard.
    r53.activate_key_signing_key()
        .hosted_zone_id(&zone)
        .name("primary_ksk")
        .send()
        .await
        .expect("activate");
    let bad = r53
        .delete_key_signing_key()
        .hosted_zone_id(&zone)
        .name("primary_ksk")
        .send()
        .await;
    assert!(bad.is_err(), "expected ACTIVE KSK to block delete");

    r53.deactivate_key_signing_key()
        .hosted_zone_id(&zone)
        .name("primary_ksk")
        .send()
        .await
        .expect("deactivate");

    r53.delete_key_signing_key()
        .hosted_zone_id(&zone)
        .name("primary_ksk")
        .send()
        .await
        .expect("delete");

    let dnssec = r53
        .get_dnssec()
        .hosted_zone_id(&zone)
        .send()
        .await
        .expect("get dnssec");
    assert!(dnssec.key_signing_keys().is_empty());
}

#[tokio::test]
async fn duplicate_ksk_name_is_rejected() {
    let server = TestServer::start().await;
    let zone = make_zone(&server, "dup-ksk.example.com", "dup-ksk-zone").await;
    let r53 = server.route53_client().await;

    r53.create_key_signing_key()
        .caller_reference("dup-1")
        .hosted_zone_id(&zone)
        .key_management_service_arn(
            "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000001",
        )
        .name("dup_ksk")
        .status("INACTIVE")
        .send()
        .await
        .expect("first");

    let dup = r53
        .create_key_signing_key()
        .caller_reference("dup-2")
        .hosted_zone_id(&zone)
        .key_management_service_arn(
            "arn:aws:kms:us-east-1:000000000000:key/00000000-0000-0000-0000-000000000002",
        )
        .name("dup_ksk")
        .status("INACTIVE")
        .send()
        .await;
    assert!(dup.is_err(), "expected duplicate name to be rejected");
}

#[tokio::test]
async fn query_logging_lifecycle() {
    let server = TestServer::start().await;
    let zone = make_zone(&server, "qlog.example.com", "qlog-zone-1").await;
    let r53 = server.route53_client().await;

    let create = r53
        .create_query_logging_config()
        .hosted_zone_id(&zone)
        .cloud_watch_logs_log_group_arn(
            "arn:aws:logs:us-east-1:000000000000:log-group:/route53/qlog",
        )
        .send()
        .await
        .expect("create");
    let id = create.query_logging_config().unwrap().id().to_string();

    let got = r53
        .get_query_logging_config()
        .id(&id)
        .send()
        .await
        .expect("get");
    assert_eq!(got.query_logging_config().unwrap().id(), id);

    let list = r53.list_query_logging_configs().send().await.expect("list");
    assert!(!list.query_logging_configs().is_empty());

    // Duplicate per zone is rejected.
    let dup = r53
        .create_query_logging_config()
        .hosted_zone_id(&zone)
        .cloud_watch_logs_log_group_arn(
            "arn:aws:logs:us-east-1:000000000000:log-group:/route53/qlog2",
        )
        .send()
        .await;
    assert!(dup.is_err(), "duplicate query logging config rejected");

    r53.delete_query_logging_config()
        .id(&id)
        .send()
        .await
        .expect("delete");
    let after = r53.get_query_logging_config().id(&id).send().await;
    assert!(after.is_err(), "expected NoSuchQueryLoggingConfig");
}

#[tokio::test]
async fn cidr_collection_lifecycle() {
    use aws_sdk_route53::types::CidrCollectionChangeAction;
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    let create = r53
        .create_cidr_collection()
        .name("collection-lifecycle")
        .caller_reference("cidr-1")
        .send()
        .await
        .expect("create");
    let id = create.collection().unwrap().id().unwrap().to_string();
    assert_eq!(create.collection().unwrap().version(), Some(1));

    let put = CidrCollectionChange::builder()
        .location_name("us-east-1")
        .action(CidrCollectionChangeAction::Put)
        .cidr_list("10.0.0.0/24")
        .cidr_list("10.0.1.0/24")
        .build()
        .unwrap();
    r53.change_cidr_collection()
        .id(&id)
        .collection_version(1)
        .changes(put)
        .send()
        .await
        .expect("put cidrs");

    let locs = r53
        .list_cidr_locations()
        .collection_id(&id)
        .send()
        .await
        .expect("list locations");
    assert_eq!(locs.cidr_locations().len(), 1);

    let blocks = r53
        .list_cidr_blocks()
        .collection_id(&id)
        .location_name("us-east-1")
        .send()
        .await
        .expect("list blocks");
    assert_eq!(blocks.cidr_blocks().len(), 2);

    let del = CidrCollectionChange::builder()
        .location_name("us-east-1")
        .action(CidrCollectionChangeAction::DeleteIfExists)
        .cidr_list("10.0.0.0/24")
        .cidr_list("10.0.1.0/24")
        .build()
        .unwrap();
    r53.change_cidr_collection()
        .id(&id)
        .collection_version(2)
        .changes(del)
        .send()
        .await
        .expect("delete cidrs");

    r53.delete_cidr_collection()
        .id(&id)
        .send()
        .await
        .expect("delete collection");
}

#[tokio::test]
async fn cidr_collection_in_use_blocks_delete() {
    use aws_sdk_route53::types::CidrCollectionChangeAction;
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    let id = r53
        .create_cidr_collection()
        .name("collection-inuse")
        .caller_reference("cidr-inuse")
        .send()
        .await
        .expect("create")
        .collection()
        .unwrap()
        .id()
        .unwrap()
        .to_string();

    let put = CidrCollectionChange::builder()
        .location_name("eu-west-1")
        .action(CidrCollectionChangeAction::Put)
        .cidr_list("192.0.2.0/24")
        .build()
        .unwrap();
    r53.change_cidr_collection()
        .id(&id)
        .changes(put)
        .send()
        .await
        .expect("put");

    let res = r53.delete_cidr_collection().id(&id).send().await;
    assert!(res.is_err(), "non-empty collection should block delete");
}

#[tokio::test]
async fn cidr_collection_version_mismatch_rejected() {
    use aws_sdk_route53::types::CidrCollectionChangeAction;
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    let id = r53
        .create_cidr_collection()
        .name("collection-version")
        .caller_reference("cidr-ver")
        .send()
        .await
        .expect("create")
        .collection()
        .unwrap()
        .id()
        .unwrap()
        .to_string();

    let change = CidrCollectionChange::builder()
        .location_name("ap-south-1")
        .action(CidrCollectionChangeAction::Put)
        .cidr_list("198.51.100.0/24")
        .build()
        .unwrap();
    let stale = r53
        .change_cidr_collection()
        .id(&id)
        .collection_version(99)
        .changes(change)
        .send()
        .await;
    assert!(stale.is_err(), "stale collection version rejected");
}
