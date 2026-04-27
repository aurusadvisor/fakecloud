//! Route 53 batch 5 E2E: VPC associations + delegation sets + geo + tags.

mod helpers;

use aws_sdk_route53::types::{
    AccountLimitType, HostedZoneConfig, ReusableDelegationSetLimitType, Tag, Vpc, VpcRegion,
};
use helpers::TestServer;

async fn make_private_zone(server: &TestServer, name: &str, caller: &str, vpc: Vpc) -> String {
    let r53 = server.route53_client().await;
    r53.create_hosted_zone()
        .name(name)
        .caller_reference(caller)
        .hosted_zone_config(HostedZoneConfig::builder().private_zone(true).build())
        .vpc(vpc)
        .send()
        .await
        .expect("zone")
        .hosted_zone()
        .unwrap()
        .id()
        .to_string()
}

fn vpc(id: &str) -> Vpc {
    Vpc::builder()
        .vpc_id(id)
        .vpc_region(VpcRegion::UsEast1)
        .build()
}

#[tokio::test]
async fn vpc_association_lifecycle() {
    let server = TestServer::start().await;
    let zone = make_private_zone(&server, "vpc.example.com", "vpc-1", vpc("vpc-aaaa")).await;
    let r53 = server.route53_client().await;

    // Authorize a second VPC for cross-account-style association then attach.
    r53.create_vpc_association_authorization()
        .hosted_zone_id(&zone)
        .vpc(vpc("vpc-bbbb"))
        .send()
        .await
        .expect("authorize");
    let auths = r53
        .list_vpc_association_authorizations()
        .hosted_zone_id(&zone)
        .send()
        .await
        .expect("list auths");
    assert_eq!(auths.vpcs().len(), 1);

    r53.associate_vpc_with_hosted_zone()
        .hosted_zone_id(&zone)
        .vpc(vpc("vpc-bbbb"))
        .send()
        .await
        .expect("associate");

    // Look up the zone via VPC and confirm it shows up.
    let by_vpc = r53
        .list_hosted_zones_by_vpc()
        .vpc_id("vpc-bbbb")
        .vpc_region(VpcRegion::UsEast1)
        .send()
        .await
        .expect("list by vpc");
    assert!(by_vpc
        .hosted_zone_summaries()
        .iter()
        .any(|s| s.hosted_zone_id() == zone));

    // Disassociate the second VPC (still leaves vpc-aaaa).
    r53.disassociate_vpc_from_hosted_zone()
        .hosted_zone_id(&zone)
        .vpc(vpc("vpc-bbbb"))
        .send()
        .await
        .expect("disassociate");

    // Attempting to disassociate the only remaining VPC must fail.
    let last = r53
        .disassociate_vpc_from_hosted_zone()
        .hosted_zone_id(&zone)
        .vpc(vpc("vpc-aaaa"))
        .send()
        .await;
    assert!(last.is_err(), "removing last VPC should be rejected");

    // Revoke the authorization. Second revoke errors.
    r53.delete_vpc_association_authorization()
        .hosted_zone_id(&zone)
        .vpc(vpc("vpc-bbbb"))
        .send()
        .await
        .expect("delete auth");
    let revoke_again = r53
        .delete_vpc_association_authorization()
        .hosted_zone_id(&zone)
        .vpc(vpc("vpc-bbbb"))
        .send()
        .await;
    assert!(revoke_again.is_err());
}

#[tokio::test]
async fn associate_vpc_rejects_public_zone() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    let zone = r53
        .create_hosted_zone()
        .name("public.example.com")
        .caller_reference("public-1")
        .send()
        .await
        .expect("zone")
        .hosted_zone()
        .unwrap()
        .id()
        .to_string();
    let bad = r53
        .associate_vpc_with_hosted_zone()
        .hosted_zone_id(&zone)
        .vpc(vpc("vpc-cccc"))
        .send()
        .await;
    assert!(bad.is_err(), "public zone associate should fail");
}

#[tokio::test]
async fn reusable_delegation_set_lifecycle() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    let create = r53
        .create_reusable_delegation_set()
        .caller_reference("ds-1")
        .send()
        .await
        .expect("create ds");
    let id = create.delegation_set().unwrap().id().unwrap().to_string();

    let got = r53
        .get_reusable_delegation_set()
        .id(&id)
        .send()
        .await
        .expect("get ds");
    assert_eq!(
        got.delegation_set().unwrap().name_servers().len(),
        4,
        "every reusable delegation set seeds 4 NS records"
    );

    let listed = r53
        .list_reusable_delegation_sets()
        .send()
        .await
        .expect("list ds");
    assert!(listed
        .delegation_sets()
        .iter()
        .any(|d| d.id() == Some(id.as_str())));

    let lim = r53
        .get_reusable_delegation_set_limit()
        .delegation_set_id(&id)
        .r#type(ReusableDelegationSetLimitType::MaxZonesByReusableDelegationSet)
        .send()
        .await
        .expect("limit");
    assert_eq!(lim.count(), 0);
    assert_eq!(lim.limit().unwrap().value(), 500);

    r53.delete_reusable_delegation_set()
        .id(&id)
        .send()
        .await
        .expect("delete");
}

#[tokio::test]
async fn duplicate_delegation_set_caller_reference_rejected() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.create_reusable_delegation_set()
        .caller_reference("dup-ds")
        .send()
        .await
        .expect("first");
    let dup = r53
        .create_reusable_delegation_set()
        .caller_reference("dup-ds")
        .send()
        .await;
    assert!(dup.is_err(), "duplicate caller reference must be rejected");
}

#[tokio::test]
async fn geo_locations_listing_and_lookup() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;

    let listed = r53
        .list_geo_locations()
        .max_items(5)
        .send()
        .await
        .expect("list");
    assert!(listed.is_truncated());
    assert_eq!(listed.geo_location_details_list().len(), 5);

    let got = r53
        .get_geo_location()
        .country_code("US")
        .subdivision_code("CA")
        .send()
        .await
        .expect("get geo");
    let g = got.geo_location_details().unwrap();
    assert_eq!(g.country_code(), Some("US"));
    assert_eq!(g.subdivision_code(), Some("CA"));
    assert_eq!(g.subdivision_name(), Some("California"));

    let missing = r53.get_geo_location().country_code("ZZ").send().await;
    assert!(missing.is_err());
}

#[tokio::test]
async fn account_limits_reflect_state() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    r53.create_hosted_zone()
        .name("limits.example.com")
        .caller_reference("limits-1")
        .send()
        .await
        .expect("zone");

    let got = r53
        .get_account_limit()
        .r#type(AccountLimitType::MaxHostedZonesByOwner)
        .send()
        .await
        .expect("limit");
    assert_eq!(got.count(), 1);
    assert_eq!(got.limit().unwrap().value(), 500);
}

#[tokio::test]
async fn tags_lifecycle_for_hosted_zone() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    let zone = r53
        .create_hosted_zone()
        .name("tagged.example.com")
        .caller_reference("tagged-1")
        .send()
        .await
        .expect("zone")
        .hosted_zone()
        .unwrap()
        .id()
        .to_string();
    // Strip the `/hostedzone/` prefix the SDK reports because the tag endpoint
    // uses the bare resource ID in the URL.
    let bare_zone = zone.trim_start_matches("/hostedzone/").to_string();

    r53.change_tags_for_resource()
        .resource_type("hostedzone".into())
        .resource_id(&bare_zone)
        .add_tags(Tag::builder().key("env").value("prod").build())
        .add_tags(Tag::builder().key("team").value("dns").build())
        .send()
        .await
        .expect("add");

    let listed = r53
        .list_tags_for_resource()
        .resource_type("hostedzone".into())
        .resource_id(&bare_zone)
        .send()
        .await
        .expect("list");
    let set = listed.resource_tag_set().unwrap();
    assert_eq!(set.tags().len(), 2);

    // Edit + remove in a single request.
    r53.change_tags_for_resource()
        .resource_type("hostedzone".into())
        .resource_id(&bare_zone)
        .add_tags(Tag::builder().key("env").value("staging").build())
        .remove_tag_keys("team")
        .send()
        .await
        .expect("edit");
    let after = r53
        .list_tags_for_resource()
        .resource_type("hostedzone".into())
        .resource_id(&bare_zone)
        .send()
        .await
        .expect("list2");
    let s2 = after.resource_tag_set().unwrap();
    assert_eq!(s2.tags().len(), 1);
    let only = &s2.tags()[0];
    assert_eq!(only.key(), Some("env"));
    assert_eq!(only.value(), Some("staging"));

    let multi = r53
        .list_tags_for_resources()
        .resource_type("hostedzone".into())
        .resource_ids(&bare_zone)
        .send()
        .await
        .expect("multi");
    assert_eq!(multi.resource_tag_sets().len(), 1);
}

#[tokio::test]
async fn tags_for_unknown_resource_errors() {
    let server = TestServer::start().await;
    let r53 = server.route53_client().await;
    let bad = r53
        .list_tags_for_resource()
        .resource_type("hostedzone".into())
        .resource_id("Z00000000000000")
        .send()
        .await;
    assert!(bad.is_err(), "unknown hosted zone tag list must fail");
}
