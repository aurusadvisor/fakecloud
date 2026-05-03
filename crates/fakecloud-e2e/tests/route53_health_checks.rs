//! Route 53 health check E2E tests against the AWS Rust SDK.

mod helpers;

use aws_sdk_route53::types::{HealthCheckConfig, HealthCheckType, ResettableElementName};
use helpers::TestServer;

#[tokio::test]
async fn create_get_delete_health_check_lifecycle() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    let create = r53
        .create_health_check()
        .caller_reference("hc-lifecycle-1")
        .health_check_config(
            HealthCheckConfig::builder()
                .ip_address("203.0.113.10")
                .port(80)
                .r#type(HealthCheckType::Http)
                .resource_path("/")
                .request_interval(30)
                .failure_threshold(3)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("create health check");
    let hc = create.health_check().expect("hc");
    let id = hc.id().to_string();
    assert!(!id.is_empty());
    assert_eq!(hc.health_check_version(), 1);
    assert_eq!(
        hc.health_check_config().unwrap().ip_address(),
        Some("203.0.113.10")
    );

    let got = r53
        .get_health_check()
        .health_check_id(&id)
        .send()
        .await
        .expect("get hc");
    assert_eq!(got.health_check().unwrap().id(), id);

    r53.delete_health_check()
        .health_check_id(&id)
        .send()
        .await
        .expect("delete hc");

    let after = r53.get_health_check().health_check_id(&id).send().await;
    assert!(after.is_err(), "expected NoSuchHealthCheck after delete");
}

#[tokio::test]
async fn duplicate_caller_reference_is_rejected() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    r53.create_health_check()
        .caller_reference("hc-dup")
        .health_check_config(
            HealthCheckConfig::builder()
                .r#type(HealthCheckType::Tcp)
                .ip_address("203.0.113.20")
                .port(443)
                .request_interval(30)
                .failure_threshold(3)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("first create");

    let res = r53
        .create_health_check()
        .caller_reference("hc-dup")
        .health_check_config(
            HealthCheckConfig::builder()
                .r#type(HealthCheckType::Tcp)
                .ip_address("203.0.113.21")
                .port(443)
                .request_interval(30)
                .failure_threshold(3)
                .build()
                .unwrap(),
        )
        .send()
        .await;
    assert!(
        res.is_err(),
        "expected duplicate caller reference to be rejected"
    );
}

#[tokio::test]
async fn update_health_check_bumps_version_and_persists_fields() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    let id = r53
        .create_health_check()
        .caller_reference("hc-upd")
        .health_check_config(
            HealthCheckConfig::builder()
                .r#type(HealthCheckType::Http)
                .ip_address("203.0.113.30")
                .port(80)
                .resource_path("/old")
                .request_interval(30)
                .failure_threshold(3)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("create")
        .health_check()
        .unwrap()
        .id()
        .to_string();

    let updated = r53
        .update_health_check()
        .health_check_id(&id)
        .health_check_version(1)
        .resource_path("/new")
        .failure_threshold(5)
        .send()
        .await
        .expect("update");
    let hc = updated.health_check().unwrap();
    assert_eq!(hc.health_check_version(), 2);
    assert_eq!(
        hc.health_check_config().unwrap().resource_path(),
        Some("/new")
    );
    assert_eq!(
        hc.health_check_config().unwrap().failure_threshold(),
        Some(5)
    );

    // Mismatched version is rejected.
    let stale = r53
        .update_health_check()
        .health_check_id(&id)
        .health_check_version(1)
        .resource_path("/even-newer")
        .send()
        .await;
    assert!(stale.is_err(), "expected version mismatch error");
}

#[tokio::test]
async fn update_health_check_reset_elements_clears_fields() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    let id = r53
        .create_health_check()
        .caller_reference("hc-reset")
        .health_check_config(
            HealthCheckConfig::builder()
                .r#type(HealthCheckType::Http)
                .fully_qualified_domain_name("example.com")
                .resource_path("/health")
                .port(80)
                .request_interval(30)
                .failure_threshold(3)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("create")
        .health_check()
        .unwrap()
        .id()
        .to_string();

    let updated = r53
        .update_health_check()
        .health_check_id(&id)
        .reset_elements(ResettableElementName::FullyQualifiedDomainName)
        .reset_elements(ResettableElementName::ResourcePath)
        .send()
        .await
        .expect("reset");
    let cfg = updated
        .health_check()
        .unwrap()
        .health_check_config()
        .unwrap();
    assert_eq!(cfg.fully_qualified_domain_name(), None);
    assert_eq!(cfg.resource_path(), None);
}

#[tokio::test]
async fn list_count_status_and_failure_reason() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    for i in 0..3 {
        r53.create_health_check()
            .caller_reference(format!("hc-list-{i}"))
            .health_check_config(
                HealthCheckConfig::builder()
                    .r#type(HealthCheckType::Tcp)
                    .ip_address(format!("203.0.113.{}", 100 + i))
                    .port(80)
                    .request_interval(30)
                    .failure_threshold(3)
                    .build()
                    .unwrap(),
            )
            .send()
            .await
            .expect("create");
    }

    let list = r53.list_health_checks().send().await.expect("list");
    assert!(list.health_checks().len() >= 3);

    let count = r53.get_health_check_count().send().await.expect("count");
    assert!(count.health_check_count() >= 3);

    let id = list.health_checks()[0].id().to_string();
    let status = r53
        .get_health_check_status()
        .health_check_id(&id)
        .send()
        .await
        .expect("status");
    assert!(!status.health_check_observations().is_empty());

    let last = r53
        .get_health_check_last_failure_reason()
        .health_check_id(&id)
        .send()
        .await
        .expect("last failure");
    assert!(last.health_check_observations().is_empty());
}

#[tokio::test]
async fn checker_ip_ranges_returns_cidrs() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    let resp = r53
        .get_checker_ip_ranges()
        .send()
        .await
        .expect("checker ip ranges");
    let ranges = resp.checker_ip_ranges();
    assert!(!ranges.is_empty());
    for cidr in ranges {
        assert!(cidr.contains('/'), "unexpected CIDR: {cidr}");
    }
}

#[tokio::test]
async fn delete_rejects_health_check_in_use() {
    use aws_sdk_route53::types::{
        Change, ChangeAction, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType,
    };
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    let zone = r53
        .create_hosted_zone()
        .name("inuse.example.com")
        .caller_reference("hc-inuse-zone")
        .send()
        .await
        .expect("zone")
        .hosted_zone()
        .unwrap()
        .id()
        .to_string();

    let hc_id = r53
        .create_health_check()
        .caller_reference("hc-inuse")
        .health_check_config(
            HealthCheckConfig::builder()
                .r#type(HealthCheckType::Http)
                .ip_address("203.0.113.50")
                .port(80)
                .resource_path("/")
                .request_interval(30)
                .failure_threshold(3)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("create hc")
        .health_check()
        .unwrap()
        .id()
        .to_string();

    r53.change_resource_record_sets()
        .hosted_zone_id(&zone)
        .change_batch(
            ChangeBatch::builder()
                .changes(
                    Change::builder()
                        .action(ChangeAction::Upsert)
                        .resource_record_set(
                            ResourceRecordSet::builder()
                                .name("api.inuse.example.com.")
                                .r#type(RrType::A)
                                .ttl(60)
                                .resource_records(
                                    ResourceRecord::builder()
                                        .value("203.0.113.50")
                                        .build()
                                        .unwrap(),
                                )
                                .health_check_id(&hc_id)
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
        .expect("upsert with hc");

    let res = r53
        .delete_health_check()
        .health_check_id(&hc_id)
        .send()
        .await;
    assert!(
        res.is_err(),
        "expected delete to be rejected while record set still references the health check"
    );
}

#[tokio::test]
async fn admin_endpoint_flips_health_check_status_and_reason() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    let id = r53
        .create_health_check()
        .caller_reference("hc-admin-flip")
        .health_check_config(
            HealthCheckConfig::builder()
                .r#type(HealthCheckType::Tcp)
                .ip_address("203.0.113.50")
                .port(80)
                .request_interval(30)
                .failure_threshold(3)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .expect("create")
        .health_check()
        .unwrap()
        .id()
        .to_string();

    let initial = r53
        .get_health_check_status()
        .health_check_id(&id)
        .send()
        .await
        .expect("status before flip");
    let observations = initial.health_check_observations();
    assert!(!observations.is_empty());
    for obs in observations {
        let status = obs.status_report().unwrap().status().unwrap();
        assert_eq!(status, "Success", "expected Success before admin flip");
    }

    let code = server
        .set_route53_health_check_status(&id, "Failure", Some("Endpoint timed out"))
        .await;
    assert_eq!(code, 204, "expected 204 No Content from admin flip");

    let after = r53
        .get_health_check_status()
        .health_check_id(&id)
        .send()
        .await
        .expect("status after flip");
    for obs in after.health_check_observations() {
        let status = obs.status_report().unwrap().status().unwrap();
        assert_eq!(status, "Failure: Endpoint timed out");
    }

    // GetHealthCheckLastFailureReason should now surface the same reason.
    let last = r53
        .get_health_check_last_failure_reason()
        .health_check_id(&id)
        .send()
        .await
        .expect("last failure after flip");
    let last_obs = last.health_check_observations();
    assert!(!last_obs.is_empty(), "expected last-failure observations");
    for obs in last_obs {
        let s = obs.status_report().unwrap().status().unwrap();
        assert!(
            s.contains("Endpoint timed out"),
            "expected stored reason in observation, got {s}"
        );
    }

    // Flipping back to Success clears the reported status but leaves the
    // historical reason intact.
    let code = server
        .set_route53_health_check_status(&id, "Success", None)
        .await;
    assert_eq!(code, 204);
    let recovered = r53
        .get_health_check_status()
        .health_check_id(&id)
        .send()
        .await
        .expect("status after recovery");
    for obs in recovered.health_check_observations() {
        let status = obs.status_report().unwrap().status().unwrap();
        assert_eq!(status, "Success");
    }
}

#[tokio::test]
async fn admin_endpoint_returns_404_for_unknown_health_check() {
    let server = TestServer::start().await;
    let code = server
        .set_route53_health_check_status("ghost-hc", "Failure", Some("missing"))
        .await;
    assert_eq!(code, 404);
}
