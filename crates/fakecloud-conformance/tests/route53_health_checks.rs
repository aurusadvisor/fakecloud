//! Route 53 health check conformance tests.

mod helpers;

use aws_sdk_route53::types::{HealthCheckConfig, HealthCheckType};
use fakecloud_conformance_macros::test_action;
use helpers::TestServer;

async fn create_check(caller_ref: &str) -> (TestServer, String) {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    let id = r53
        .create_health_check()
        .caller_reference(caller_ref)
        .health_check_config(
            HealthCheckConfig::builder()
                .r#type(HealthCheckType::Http)
                .ip_address("203.0.113.10")
                .port(80)
                .resource_path("/")
                .request_interval(30)
                .failure_threshold(3)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap()
        .health_check()
        .unwrap()
        .id()
        .to_string();
    (server, id)
}

#[test_action("route53", "CreateHealthCheck", checksum = "6d6386bc")]
#[tokio::test]
async fn r53_create_health_check() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.create_health_check()
        .caller_reference("conf-hc-create-1")
        .health_check_config(
            HealthCheckConfig::builder()
                .r#type(HealthCheckType::Tcp)
                .ip_address("203.0.113.11")
                .port(80)
                .request_interval(30)
                .failure_threshold(3)
                .build()
                .unwrap(),
        )
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "GetHealthCheck", checksum = "1abee3c9")]
#[tokio::test]
async fn r53_get_health_check() {
    let (server, id) = create_check("conf-hc-get-1").await;
    let r53 = server.route53_client().await;
    r53.get_health_check()
        .health_check_id(&id)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "UpdateHealthCheck", checksum = "9bfd826a")]
#[tokio::test]
async fn r53_update_health_check() {
    let (server, id) = create_check("conf-hc-upd-1").await;
    let r53 = server.route53_client().await;
    r53.update_health_check()
        .health_check_id(&id)
        .resource_path("/healthz")
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "DeleteHealthCheck", checksum = "7cea993f")]
#[tokio::test]
async fn r53_delete_health_check() {
    let (server, id) = create_check("conf-hc-del-1").await;
    let r53 = server.route53_client().await;
    r53.delete_health_check()
        .health_check_id(&id)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "ListHealthChecks", checksum = "1f2da2ca")]
#[tokio::test]
async fn r53_list_health_checks() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.list_health_checks().send().await.unwrap();
}

#[test_action("route53", "GetHealthCheckCount", checksum = "112e72ba")]
#[tokio::test]
async fn r53_get_health_check_count() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.get_health_check_count().send().await.unwrap();
}

#[test_action("route53", "GetHealthCheckStatus", checksum = "b39a7eec")]
#[tokio::test]
async fn r53_get_health_check_status() {
    let (server, id) = create_check("conf-hc-status-1").await;
    let r53 = server.route53_client().await;
    r53.get_health_check_status()
        .health_check_id(&id)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "GetHealthCheckLastFailureReason", checksum = "642cbda4")]
#[tokio::test]
async fn r53_get_health_check_last_failure_reason() {
    let (server, id) = create_check("conf-hc-failure-1").await;
    let r53 = server.route53_client().await;
    r53.get_health_check_last_failure_reason()
        .health_check_id(&id)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "GetCheckerIpRanges", checksum = "efa6b072")]
#[tokio::test]
async fn r53_get_checker_ip_ranges() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.get_checker_ip_ranges().send().await.unwrap();
}
