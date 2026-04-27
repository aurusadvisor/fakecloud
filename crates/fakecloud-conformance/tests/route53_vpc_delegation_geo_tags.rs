//! Route 53 batch 5 conformance: VPC + delegation sets + geo + tags.

mod helpers;

use aws_sdk_route53::types::{
    AccountLimitType, HostedZoneConfig, ReusableDelegationSetLimitType, Tag, Vpc, VpcRegion,
};
use fakecloud_conformance_macros::test_action;
use helpers::TestServer;

fn vpc(id: &str) -> Vpc {
    Vpc::builder()
        .vpc_id(id)
        .vpc_region(VpcRegion::UsEast1)
        .build()
}

async fn private_zone(server: &TestServer, name: &str, caller: &str, vpc_obj: Vpc) -> String {
    let r53 = server.route53_client().await;
    r53.create_hosted_zone()
        .name(name)
        .caller_reference(caller)
        .hosted_zone_config(HostedZoneConfig::builder().private_zone(true).build())
        .vpc(vpc_obj)
        .send()
        .await
        .unwrap()
        .hosted_zone()
        .unwrap()
        .id()
        .to_string()
}

async fn public_zone(server: &TestServer, name: &str, caller: &str) -> String {
    let r53 = server.route53_client().await;
    r53.create_hosted_zone()
        .name(name)
        .caller_reference(caller)
        .send()
        .await
        .unwrap()
        .hosted_zone()
        .unwrap()
        .id()
        .to_string()
}

#[test_action("route53", "AssociateVPCWithHostedZone", checksum = "b1d609a4")]
#[tokio::test]
async fn r53_associate_vpc() {
    let server = TestServer::start().await;
    let zone = private_zone(
        &server,
        "conf-assoc.example.com",
        "conf-assoc-1",
        vpc("vpc-conf1"),
    )
    .await;
    let r53 = server.route53_client().await;
    r53.associate_vpc_with_hosted_zone()
        .hosted_zone_id(&zone)
        .vpc(vpc("vpc-conf2"))
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "DisassociateVPCFromHostedZone", checksum = "effdd924")]
#[tokio::test]
async fn r53_disassociate_vpc() {
    let server = TestServer::start().await;
    let zone = private_zone(
        &server,
        "conf-disassoc.example.com",
        "conf-disassoc-1",
        vpc("vpc-conf3"),
    )
    .await;
    let r53 = server.route53_client().await;
    r53.associate_vpc_with_hosted_zone()
        .hosted_zone_id(&zone)
        .vpc(vpc("vpc-conf4"))
        .send()
        .await
        .unwrap();
    r53.disassociate_vpc_from_hosted_zone()
        .hosted_zone_id(&zone)
        .vpc(vpc("vpc-conf4"))
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "CreateVPCAssociationAuthorization", checksum = "5540eb6a")]
#[tokio::test]
async fn r53_create_vpc_authorization() {
    let server = TestServer::start().await;
    let zone = public_zone(&server, "conf-auth.example.com", "conf-auth-1").await;
    let r53 = server.route53_client().await;
    r53.create_vpc_association_authorization()
        .hosted_zone_id(&zone)
        .vpc(vpc("vpc-conf5"))
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "DeleteVPCAssociationAuthorization", checksum = "fc079648")]
#[tokio::test]
async fn r53_delete_vpc_authorization() {
    let server = TestServer::start().await;
    let zone = public_zone(&server, "conf-deauth.example.com", "conf-deauth-1").await;
    let r53 = server.route53_client().await;
    r53.create_vpc_association_authorization()
        .hosted_zone_id(&zone)
        .vpc(vpc("vpc-conf6"))
        .send()
        .await
        .unwrap();
    r53.delete_vpc_association_authorization()
        .hosted_zone_id(&zone)
        .vpc(vpc("vpc-conf6"))
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "ListVPCAssociationAuthorizations", checksum = "26d194fb")]
#[tokio::test]
async fn r53_list_vpc_authorizations() {
    let server = TestServer::start().await;
    let zone = public_zone(&server, "conf-listauth.example.com", "conf-listauth-1").await;
    let r53 = server.route53_client().await;
    r53.list_vpc_association_authorizations()
        .hosted_zone_id(&zone)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "ListHostedZonesByVPC", checksum = "30898c68")]
#[tokio::test]
async fn r53_list_hosted_zones_by_vpc() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.list_hosted_zones_by_vpc()
        .vpc_id("vpc-empty")
        .vpc_region(VpcRegion::UsEast1)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "CreateReusableDelegationSet", checksum = "1def898a")]
#[tokio::test]
async fn r53_create_delegation_set() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.create_reusable_delegation_set()
        .caller_reference("conf-ds-1")
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "GetReusableDelegationSet", checksum = "80e63dec")]
#[tokio::test]
async fn r53_get_delegation_set() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    let id = r53
        .create_reusable_delegation_set()
        .caller_reference("conf-ds-2")
        .send()
        .await
        .unwrap()
        .delegation_set()
        .unwrap()
        .id()
        .unwrap()
        .to_string();
    r53.get_reusable_delegation_set()
        .id(&id)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "DeleteReusableDelegationSet", checksum = "78ff8ba5")]
#[tokio::test]
async fn r53_delete_delegation_set() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    let id = r53
        .create_reusable_delegation_set()
        .caller_reference("conf-ds-3")
        .send()
        .await
        .unwrap()
        .delegation_set()
        .unwrap()
        .id()
        .unwrap()
        .to_string();
    r53.delete_reusable_delegation_set()
        .id(&id)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "ListReusableDelegationSets", checksum = "d78d67da")]
#[tokio::test]
async fn r53_list_delegation_sets() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.list_reusable_delegation_sets().send().await.unwrap();
}

#[test_action("route53", "GetReusableDelegationSetLimit", checksum = "9810cf2a")]
#[tokio::test]
async fn r53_get_delegation_set_limit() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    let id = r53
        .create_reusable_delegation_set()
        .caller_reference("conf-ds-4")
        .send()
        .await
        .unwrap()
        .delegation_set()
        .unwrap()
        .id()
        .unwrap()
        .to_string();
    r53.get_reusable_delegation_set_limit()
        .delegation_set_id(&id)
        .r#type(ReusableDelegationSetLimitType::MaxZonesByReusableDelegationSet)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "ListGeoLocations", checksum = "3542311c")]
#[tokio::test]
async fn r53_list_geo_locations() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.list_geo_locations().send().await.unwrap();
}

#[test_action("route53", "GetGeoLocation", checksum = "9f971346")]
#[tokio::test]
async fn r53_get_geo_location() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.get_geo_location()
        .country_code("US")
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "GetAccountLimit", checksum = "02f39703")]
#[tokio::test]
async fn r53_get_account_limit() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.get_account_limit()
        .r#type(AccountLimitType::MaxHostedZonesByOwner)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "ChangeTagsForResource", checksum = "71ad0cce")]
#[tokio::test]
async fn r53_change_tags_for_resource() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    let zone = public_zone(&server, "conf-tags.example.com", "conf-tags-1").await;
    let bare = zone.trim_start_matches("/hostedzone/");
    r53.change_tags_for_resource()
        .resource_type("hostedzone".into())
        .resource_id(bare)
        .add_tags(Tag::builder().key("env").value("conf").build())
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "ListTagsForResource", checksum = "0081d94a")]
#[tokio::test]
async fn r53_list_tags_for_resource() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    let zone = public_zone(&server, "conf-tags-list.example.com", "conf-tags-list-1").await;
    let bare = zone.trim_start_matches("/hostedzone/");
    r53.list_tags_for_resource()
        .resource_type("hostedzone".into())
        .resource_id(bare)
        .send()
        .await
        .unwrap();
}

#[test_action("route53", "ListTagsForResources", checksum = "1ed221f9")]
#[tokio::test]
async fn r53_list_tags_for_resources() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    let zone = public_zone(&server, "conf-tags-multi.example.com", "conf-tags-multi-1").await;
    let bare = zone.trim_start_matches("/hostedzone/");
    r53.list_tags_for_resources()
        .resource_type("hostedzone".into())
        .resource_ids(bare)
        .send()
        .await
        .unwrap();
}
