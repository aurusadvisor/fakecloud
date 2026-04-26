//! Route 53 traffic policy + instance conformance tests.

mod helpers;

use fakecloud_conformance_macros::test_action;
use helpers::TestServer;

const SIMPLE_DOC: &str = r#"{"AWSPolicyFormatVersion":"2015-10-01","RecordType":"A","Endpoints":{"main":{"Type":"value","Value":"203.0.113.10"}},"StartEndpoint":"main"}"#;

async fn create_policy(name: &str) -> (TestServer, String) {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    let id = r53
        .create_traffic_policy()
        .name(name)
        .document(SIMPLE_DOC)
        .send()
        .await
        .unwrap()
        .traffic_policy()
        .unwrap()
        .id()
        .to_string();
    (server, id)
}

async fn create_zone_and_instance(name_prefix: &str) -> (TestServer, String, String) {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    let zone_id = r53
        .create_hosted_zone()
        .name(format!("{name_prefix}.example.com"))
        .caller_reference(format!("{name_prefix}-zone"))
        .send()
        .await
        .unwrap()
        .hosted_zone()
        .unwrap()
        .id()
        .to_string();
    let policy_id = r53
        .create_traffic_policy()
        .name(format!("{name_prefix}-policy"))
        .document(SIMPLE_DOC)
        .send()
        .await
        .unwrap()
        .traffic_policy()
        .unwrap()
        .id()
        .to_string();
    let inst_id = r53
        .create_traffic_policy_instance()
        .hosted_zone_id(&zone_id)
        .name(format!("inst.{name_prefix}.example.com."))
        .ttl(60)
        .traffic_policy_id(&policy_id)
        .traffic_policy_version(1)
        .send()
        .await
        .unwrap()
        .traffic_policy_instance()
        .unwrap()
        .id()
        .to_string();
    (server, policy_id, inst_id)
}

#[test_action("route53", "CreateTrafficPolicy", checksum = "f79f5acb")]
#[tokio::test]
async fn r53_create_traffic_policy() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.create_traffic_policy()
        .name("conf-tp-create-1")
        .document(SIMPLE_DOC)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "GetTrafficPolicy", checksum = "fb91987d")]
#[tokio::test]
async fn r53_get_traffic_policy() {
    let (server, id) = create_policy("conf-tp-get-1").await;
    let r53 = server.route53_client().await;
    r53.get_traffic_policy()
        .id(&id)
        .version(1)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "CreateTrafficPolicyVersion", checksum = "69c4be4b")]
#[tokio::test]
async fn r53_create_traffic_policy_version() {
    let (server, id) = create_policy("conf-tp-ver-1").await;
    let r53 = server.route53_client().await;
    r53.create_traffic_policy_version()
        .id(&id)
        .document(SIMPLE_DOC)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "UpdateTrafficPolicyComment", checksum = "4d5f14a0")]
#[tokio::test]
async fn r53_update_traffic_policy_comment() {
    let (server, id) = create_policy("conf-tp-upd-1").await;
    let r53 = server.route53_client().await;
    r53.update_traffic_policy_comment()
        .id(&id)
        .version(1)
        .comment("conformance")
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "DeleteTrafficPolicy", checksum = "fbd9cd58")]
#[tokio::test]
async fn r53_delete_traffic_policy() {
    let (server, id) = create_policy("conf-tp-del-1").await;
    let r53 = server.route53_client().await;
    r53.delete_traffic_policy()
        .id(&id)
        .version(1)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "ListTrafficPolicies", checksum = "53aeed7d")]
#[tokio::test]
async fn r53_list_traffic_policies() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.list_traffic_policies().send().await.unwrap();
}

#[test_action("route53", "ListTrafficPolicyVersions", checksum = "309f8f76")]
#[tokio::test]
async fn r53_list_traffic_policy_versions() {
    let (server, id) = create_policy("conf-tp-list-1").await;
    let r53 = server.route53_client().await;
    r53.list_traffic_policy_versions()
        .id(&id)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "CreateTrafficPolicyInstance", checksum = "51126c8d")]
#[tokio::test]
async fn r53_create_traffic_policy_instance() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    let zone_id = r53
        .create_hosted_zone()
        .name("conf-inst-create.example.com")
        .caller_reference("conf-inst-create-zone")
        .send()
        .await
        .unwrap()
        .hosted_zone()
        .unwrap()
        .id()
        .to_string();
    let policy_id = r53
        .create_traffic_policy()
        .name("conf-inst-create-policy")
        .document(SIMPLE_DOC)
        .send()
        .await
        .unwrap()
        .traffic_policy()
        .unwrap()
        .id()
        .to_string();
    r53.create_traffic_policy_instance()
        .hosted_zone_id(&zone_id)
        .name("svc.conf-inst-create.example.com.")
        .ttl(60)
        .traffic_policy_id(&policy_id)
        .traffic_policy_version(1)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "GetTrafficPolicyInstance", checksum = "5a24dee6")]
#[tokio::test]
async fn r53_get_traffic_policy_instance() {
    let (server, _, inst_id) = create_zone_and_instance("conf-inst-get-1").await;
    let r53 = server.route53_client().await;
    r53.get_traffic_policy_instance()
        .id(&inst_id)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "UpdateTrafficPolicyInstance", checksum = "ff18bbde")]
#[tokio::test]
async fn r53_update_traffic_policy_instance() {
    let (server, policy_id, inst_id) = create_zone_and_instance("conf-inst-upd-1").await;
    let r53 = server.route53_client().await;
    r53.update_traffic_policy_instance()
        .id(&inst_id)
        .ttl(120)
        .traffic_policy_id(&policy_id)
        .traffic_policy_version(1)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "DeleteTrafficPolicyInstance", checksum = "f631f930")]
#[tokio::test]
async fn r53_delete_traffic_policy_instance() {
    let (server, _, inst_id) = create_zone_and_instance("conf-inst-del-1").await;
    let r53 = server.route53_client().await;
    r53.delete_traffic_policy_instance()
        .id(&inst_id)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "ListTrafficPolicyInstances", checksum = "51308699")]
#[tokio::test]
async fn r53_list_traffic_policy_instances() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.list_traffic_policy_instances().send().await.unwrap();
}

#[test_action(
    "route53",
    "ListTrafficPolicyInstancesByHostedZone",
    checksum = "a23f00ed"
)]
#[tokio::test]
async fn r53_list_traffic_policy_instances_by_hosted_zone() {
    let (server, _, _) = create_zone_and_instance("conf-inst-byzone-1").await;
    let r53 = server.route53_client().await;
    let zones = r53.list_hosted_zones().send().await.unwrap();
    let zone_id = zones.hosted_zones()[0].id().to_string();
    r53.list_traffic_policy_instances_by_hosted_zone()
        .hosted_zone_id(&zone_id)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "ListTrafficPolicyInstancesByPolicy", checksum = "8af75474")]
#[tokio::test]
async fn r53_list_traffic_policy_instances_by_policy() {
    let (server, policy_id, _) = create_zone_and_instance("conf-inst-bypol-1").await;
    let r53 = server.route53_client().await;
    r53.list_traffic_policy_instances_by_policy()
        .traffic_policy_id(&policy_id)
        .traffic_policy_version(1)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "GetTrafficPolicyInstanceCount", checksum = "de5859da")]
#[tokio::test]
async fn r53_get_traffic_policy_instance_count() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.get_traffic_policy_instance_count()
        .send()
        .await
        .unwrap();
}
