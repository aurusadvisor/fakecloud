//! ELBv2 (Elastic Load Balancing v2) Batch 1 conformance tests.
//!
//! Each `#[test_action]` pairs a real AWS SDK call with the Smithy shape
//! checksum. If AWS rev-bumps the ELBv2 model the checksum goes stale and
//! the build fails loudly so we know to refresh it.

mod helpers;

use aws_sdk_elasticloadbalancingv2::types::{
    IpAddressType, LoadBalancerSchemeEnum, LoadBalancerTypeEnum, Tag,
};
use fakecloud_conformance_macros::test_action;
use helpers::TestServer;

#[test_action("elasticloadbalancingv2", "CreateLoadBalancer", checksum = "6b358bc7")]
#[tokio::test]
async fn elbv2_create_load_balancer() {
    let server = TestServer::start().await;
    let client = server.elbv2_client().await;
    let resp = client
        .create_load_balancer()
        .name("confo-create")
        .subnets("subnet-aaaa1111")
        .subnets("subnet-bbbb2222")
        .r#type(LoadBalancerTypeEnum::Application)
        .send()
        .await
        .unwrap();
    let lb = resp.load_balancers().first().unwrap();
    assert_eq!(lb.load_balancer_name(), Some("confo-create"));
    assert_eq!(lb.r#type(), Some(&LoadBalancerTypeEnum::Application));
}

#[test_action(
    "elasticloadbalancingv2",
    "DescribeLoadBalancers",
    checksum = "f6143c04"
)]
#[tokio::test]
async fn elbv2_describe_load_balancers() {
    let server = TestServer::start().await;
    let client = server.elbv2_client().await;
    client
        .create_load_balancer()
        .name("confo-describe")
        .send()
        .await
        .unwrap();
    let resp = client.describe_load_balancers().send().await.unwrap();
    assert!(resp
        .load_balancers()
        .iter()
        .any(|lb| lb.load_balancer_name() == Some("confo-describe")));
}

#[test_action("elasticloadbalancingv2", "DeleteLoadBalancer", checksum = "bd05afdd")]
#[tokio::test]
async fn elbv2_delete_load_balancer() {
    let server = TestServer::start().await;
    let client = server.elbv2_client().await;
    let create = client
        .create_load_balancer()
        .name("confo-delete")
        .send()
        .await
        .unwrap();
    let arn = create
        .load_balancers()
        .first()
        .unwrap()
        .load_balancer_arn()
        .unwrap();
    client
        .delete_load_balancer()
        .load_balancer_arn(arn)
        .send()
        .await
        .unwrap();
}

#[test_action("elasticloadbalancingv2", "SetSubnets", checksum = "6c077cf2")]
#[tokio::test]
async fn elbv2_set_subnets() {
    let server = TestServer::start().await;
    let client = server.elbv2_client().await;
    let create = client
        .create_load_balancer()
        .name("confo-subnets")
        .subnets("subnet-old")
        .send()
        .await
        .unwrap();
    let arn = create
        .load_balancers()
        .first()
        .unwrap()
        .load_balancer_arn()
        .unwrap();
    let resp = client
        .set_subnets()
        .load_balancer_arn(arn)
        .subnets("subnet-new1")
        .subnets("subnet-new2")
        .send()
        .await
        .unwrap();
    assert!(!resp.availability_zones().is_empty());
}

#[test_action("elasticloadbalancingv2", "SetSecurityGroups", checksum = "4df7135e")]
#[tokio::test]
async fn elbv2_set_security_groups() {
    let server = TestServer::start().await;
    let client = server.elbv2_client().await;
    let create = client
        .create_load_balancer()
        .name("confo-sg")
        .send()
        .await
        .unwrap();
    let arn = create
        .load_balancers()
        .first()
        .unwrap()
        .load_balancer_arn()
        .unwrap();
    let resp = client
        .set_security_groups()
        .load_balancer_arn(arn)
        .security_groups("sg-1234")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.security_group_ids().len(), 1);
}

#[test_action("elasticloadbalancingv2", "SetIpAddressType", checksum = "8445a5ab")]
#[tokio::test]
async fn elbv2_set_ip_address_type() {
    let server = TestServer::start().await;
    let client = server.elbv2_client().await;
    let create = client
        .create_load_balancer()
        .name("confo-ipt")
        .send()
        .await
        .unwrap();
    let arn = create
        .load_balancers()
        .first()
        .unwrap()
        .load_balancer_arn()
        .unwrap();
    let resp = client
        .set_ip_address_type()
        .load_balancer_arn(arn)
        .ip_address_type(IpAddressType::Dualstack)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.ip_address_type(), Some(&IpAddressType::Dualstack));
}

#[test_action("elasticloadbalancingv2", "AddTags", checksum = "04a8d014")]
#[tokio::test]
async fn elbv2_add_tags() {
    let server = TestServer::start().await;
    let client = server.elbv2_client().await;
    let create = client
        .create_load_balancer()
        .name("confo-addtags")
        .send()
        .await
        .unwrap();
    let arn = create
        .load_balancers()
        .first()
        .unwrap()
        .load_balancer_arn()
        .unwrap();
    client
        .add_tags()
        .resource_arns(arn)
        .tags(Tag::builder().key("env").value("prod").build())
        .send()
        .await
        .unwrap();
}

#[test_action("elasticloadbalancingv2", "RemoveTags", checksum = "49e9e8cd")]
#[tokio::test]
async fn elbv2_remove_tags() {
    let server = TestServer::start().await;
    let client = server.elbv2_client().await;
    let create = client
        .create_load_balancer()
        .name("confo-removetags")
        .send()
        .await
        .unwrap();
    let arn = create
        .load_balancers()
        .first()
        .unwrap()
        .load_balancer_arn()
        .unwrap();
    client
        .add_tags()
        .resource_arns(arn)
        .tags(Tag::builder().key("k").value("v").build())
        .send()
        .await
        .unwrap();
    client
        .remove_tags()
        .resource_arns(arn)
        .tag_keys("k")
        .send()
        .await
        .unwrap();
}

#[test_action("elasticloadbalancingv2", "DescribeTags", checksum = "965f2ac2")]
#[tokio::test]
async fn elbv2_describe_tags() {
    let server = TestServer::start().await;
    let client = server.elbv2_client().await;
    let create = client
        .create_load_balancer()
        .name("confo-desctags")
        .send()
        .await
        .unwrap();
    let arn = create
        .load_balancers()
        .first()
        .unwrap()
        .load_balancer_arn()
        .unwrap();
    let resp = client
        .describe_tags()
        .resource_arns(arn)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.tag_descriptions().len(), 1);
}

#[test_action(
    "elasticloadbalancingv2",
    "DescribeAccountLimits",
    checksum = "629d38f7"
)]
#[tokio::test]
async fn elbv2_describe_account_limits() {
    let server = TestServer::start().await;
    let client = server.elbv2_client().await;
    let resp = client.describe_account_limits().send().await.unwrap();
    assert!(!resp.limits().is_empty());
}

#[test_action("elasticloadbalancingv2", "DescribeSSLPolicies", checksum = "6cba0418")]
#[tokio::test]
async fn elbv2_describe_ssl_policies() {
    let server = TestServer::start().await;
    let client = server.elbv2_client().await;
    let resp = client.describe_ssl_policies().send().await.unwrap();
    assert!(!resp.ssl_policies().is_empty());
}

#[test_action("elasticloadbalancingv2", "ModifyIpPools", checksum = "1bd4f0e7")]
#[tokio::test]
async fn elbv2_modify_ip_pools() {
    let server = TestServer::start().await;
    let client = server.elbv2_client().await;
    let create = client
        .create_load_balancer()
        .name("confo-pools")
        .scheme(LoadBalancerSchemeEnum::InternetFacing)
        .send()
        .await
        .unwrap();
    let arn = create
        .load_balancers()
        .first()
        .unwrap()
        .load_balancer_arn()
        .unwrap();
    let _ = client.modify_ip_pools().load_balancer_arn(arn).send().await;
}
