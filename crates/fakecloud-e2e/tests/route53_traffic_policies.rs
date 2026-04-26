//! Route 53 traffic policy + instance E2E tests.

mod helpers;

use helpers::TestServer;

const SIMPLE_DOC: &str = r#"{"AWSPolicyFormatVersion":"2015-10-01","RecordType":"A","Endpoints":{"main":{"Type":"value","Value":"203.0.113.10"}},"StartEndpoint":"main"}"#;

const CNAME_DOC: &str = r#"{"AWSPolicyFormatVersion":"2015-10-01","RecordType":"CNAME","Endpoints":{"main":{"Type":"value","Value":"origin.example.com"}},"StartEndpoint":"main"}"#;

#[tokio::test]
async fn create_get_delete_traffic_policy_lifecycle() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    let create = r53
        .create_traffic_policy()
        .name("policy-lifecycle")
        .document(SIMPLE_DOC)
        .comment("first version")
        .send()
        .await
        .expect("create");
    let p = create.traffic_policy().expect("policy");
    let id = p.id().to_string();
    assert_eq!(p.version(), 1);
    assert_eq!(p.r#type().as_str(), "A");

    let got = r53
        .get_traffic_policy()
        .id(&id)
        .version(1)
        .send()
        .await
        .expect("get");
    assert_eq!(got.traffic_policy().unwrap().id(), id);

    r53.update_traffic_policy_comment()
        .id(&id)
        .version(1)
        .comment("updated")
        .send()
        .await
        .expect("update comment");

    r53.delete_traffic_policy()
        .id(&id)
        .version(1)
        .send()
        .await
        .expect("delete");

    let after = r53.get_traffic_policy().id(&id).version(1).send().await;
    assert!(after.is_err(), "expected NoSuchTrafficPolicy after delete");
}

#[tokio::test]
async fn create_traffic_policy_version_bumps_version() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    let id = r53
        .create_traffic_policy()
        .name("policy-versions")
        .document(SIMPLE_DOC)
        .send()
        .await
        .expect("create v1")
        .traffic_policy()
        .unwrap()
        .id()
        .to_string();

    let v2 = r53
        .create_traffic_policy_version()
        .id(&id)
        .document(CNAME_DOC)
        .comment("v2")
        .send()
        .await
        .expect("create v2");
    assert_eq!(v2.traffic_policy().unwrap().version(), 2);
    assert_eq!(v2.traffic_policy().unwrap().r#type().as_str(), "CNAME");

    let v3 = r53
        .create_traffic_policy_version()
        .id(&id)
        .document(SIMPLE_DOC)
        .send()
        .await
        .expect("create v3");
    assert_eq!(v3.traffic_policy().unwrap().version(), 3);

    let list = r53
        .list_traffic_policy_versions()
        .id(&id)
        .send()
        .await
        .expect("list versions");
    assert_eq!(list.traffic_policies().len(), 3);
}

#[tokio::test]
async fn duplicate_name_is_rejected() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    r53.create_traffic_policy()
        .name("dup-policy")
        .document(SIMPLE_DOC)
        .send()
        .await
        .expect("first");

    let res = r53
        .create_traffic_policy()
        .name("dup-policy")
        .document(SIMPLE_DOC)
        .send()
        .await;
    assert!(res.is_err(), "expected duplicate name to be rejected");
}

#[tokio::test]
async fn list_traffic_policies_returns_summaries() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    for i in 0..3 {
        r53.create_traffic_policy()
            .name(format!("list-policy-{i}"))
            .document(SIMPLE_DOC)
            .send()
            .await
            .expect("create");
    }
    let list = r53.list_traffic_policies().send().await.expect("list");
    assert!(list.traffic_policy_summaries().len() >= 3);
}

#[tokio::test]
async fn traffic_policy_instance_lifecycle() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    let zone_id = r53
        .create_hosted_zone()
        .name("instance.example.com")
        .caller_reference("inst-zone-1")
        .send()
        .await
        .expect("zone")
        .hosted_zone()
        .unwrap()
        .id()
        .to_string();

    let policy_id = r53
        .create_traffic_policy()
        .name("inst-policy")
        .document(SIMPLE_DOC)
        .send()
        .await
        .expect("policy")
        .traffic_policy()
        .unwrap()
        .id()
        .to_string();

    let create = r53
        .create_traffic_policy_instance()
        .hosted_zone_id(&zone_id)
        .name("api.instance.example.com.")
        .ttl(60)
        .traffic_policy_id(&policy_id)
        .traffic_policy_version(1)
        .send()
        .await
        .expect("create instance");
    let inst = create.traffic_policy_instance().unwrap();
    let inst_id = inst.id().to_string();
    assert_eq!(inst.state(), "Applied");
    assert_eq!(inst.ttl(), 60);

    r53.update_traffic_policy_instance()
        .id(&inst_id)
        .ttl(300)
        .traffic_policy_id(&policy_id)
        .traffic_policy_version(1)
        .send()
        .await
        .expect("update");

    let got = r53
        .get_traffic_policy_instance()
        .id(&inst_id)
        .send()
        .await
        .expect("get");
    assert_eq!(got.traffic_policy_instance().unwrap().ttl(), 300);

    let by_zone = r53
        .list_traffic_policy_instances_by_hosted_zone()
        .hosted_zone_id(&zone_id)
        .send()
        .await
        .expect("by zone");
    assert_eq!(by_zone.traffic_policy_instances().len(), 1);

    let by_policy = r53
        .list_traffic_policy_instances_by_policy()
        .traffic_policy_id(&policy_id)
        .traffic_policy_version(1)
        .send()
        .await
        .expect("by policy");
    assert_eq!(by_policy.traffic_policy_instances().len(), 1);

    let count = r53
        .get_traffic_policy_instance_count()
        .send()
        .await
        .expect("count");
    assert!(count.traffic_policy_instance_count() >= 1);

    r53.delete_traffic_policy_instance()
        .id(&inst_id)
        .send()
        .await
        .expect("delete");

    let after = r53.get_traffic_policy_instance().id(&inst_id).send().await;
    assert!(after.is_err(), "expected NoSuchTrafficPolicyInstance");
}

#[tokio::test]
async fn delete_in_use_traffic_policy_is_rejected() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    let zone = r53
        .create_hosted_zone()
        .name("inuse-policy.example.com")
        .caller_reference("inuse-policy-zone")
        .send()
        .await
        .expect("zone")
        .hosted_zone()
        .unwrap()
        .id()
        .to_string();

    let policy_id = r53
        .create_traffic_policy()
        .name("inuse-policy")
        .document(SIMPLE_DOC)
        .send()
        .await
        .expect("policy")
        .traffic_policy()
        .unwrap()
        .id()
        .to_string();

    r53.create_traffic_policy_instance()
        .hosted_zone_id(&zone)
        .name("svc.inuse-policy.example.com.")
        .ttl(60)
        .traffic_policy_id(&policy_id)
        .traffic_policy_version(1)
        .send()
        .await
        .expect("create instance");

    let res = r53
        .delete_traffic_policy()
        .id(&policy_id)
        .version(1)
        .send()
        .await;
    assert!(res.is_err(), "expected TrafficPolicyInUse");
}
