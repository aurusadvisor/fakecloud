//! CloudFront Batch 6a E2E: VPC Origins, Anycast IP Lists, Trust Stores, Resource Policies.

mod helpers;

use aws_sdk_cloudfront::types::{
    CaCertificatesBundleS3Location, CaCertificatesBundleSource, IpAddressType,
    OriginProtocolPolicy, OriginSslProtocols, SslProtocol, VpcOriginEndpointConfig,
};
use helpers::TestServer;

fn vpc_endpoint_cfg(name: &str) -> VpcOriginEndpointConfig {
    VpcOriginEndpointConfig::builder()
        .name(name)
        .arn("arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/x/y")
        .http_port(80)
        .https_port(443)
        .origin_protocol_policy(OriginProtocolPolicy::HttpsOnly)
        .origin_ssl_protocols(
            OriginSslProtocols::builder()
                .quantity(1)
                .items(SslProtocol::TlSv12)
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
}

#[tokio::test]
async fn vpc_origin_lifecycle() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;

    let create = cf
        .create_vpc_origin()
        .vpc_origin_endpoint_config(vpc_endpoint_cfg("e2e-vpc"))
        .send()
        .await
        .expect("create");
    let v = create.vpc_origin().expect("vpc origin");
    let id = v.id().to_string();
    let etag = create.e_tag().expect("etag").to_string();

    cf.get_vpc_origin().id(&id).send().await.expect("get");

    let upd = cf
        .update_vpc_origin()
        .id(&id)
        .if_match(&etag)
        .vpc_origin_endpoint_config(vpc_endpoint_cfg("e2e-vpc"))
        .send()
        .await
        .expect("update");
    let new_etag = upd.e_tag().unwrap().to_string();

    let list = cf.list_vpc_origins().send().await.expect("list");
    assert!(list.vpc_origin_list().unwrap().quantity() >= 1);

    cf.delete_vpc_origin()
        .id(&id)
        .if_match(&new_etag)
        .send()
        .await
        .expect("delete");
}

#[tokio::test]
async fn anycast_ip_list_lifecycle() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;

    let create = cf
        .create_anycast_ip_list()
        .name("e2e-aip")
        .ip_count(3)
        .ip_address_type(IpAddressType::Ipv4)
        .send()
        .await
        .expect("create");
    let a = create.anycast_ip_list().expect("aip");
    let id = a.id().to_string();
    let etag = create.e_tag().unwrap().to_string();
    assert_eq!(a.anycast_ips().len(), 3);

    cf.get_anycast_ip_list().id(&id).send().await.expect("get");

    let list = cf.list_anycast_ip_lists().send().await.expect("list");
    assert!(list.anycast_ip_lists().unwrap().quantity() >= 1);

    cf.delete_anycast_ip_list()
        .id(&id)
        .if_match(&etag)
        .send()
        .await
        .expect("delete");
}

#[tokio::test]
async fn trust_store_lifecycle() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;

    let create = cf
        .create_trust_store()
        .name("e2e-ts")
        .ca_certificates_bundle_source(CaCertificatesBundleSource::CaCertificatesBundleS3Location(
            CaCertificatesBundleS3Location::builder()
                .bucket("ca-bundle")
                .key("certs/bundle.pem")
                .region("us-east-1")
                .build()
                .unwrap(),
        ))
        .send()
        .await
        .expect("create");
    let t = create.trust_store().expect("trust store");
    let id = t.id().expect("id").to_string();
    let etag = create.e_tag().unwrap().to_string();

    cf.get_trust_store()
        .identifier(&id)
        .send()
        .await
        .expect("get");

    let list = cf.list_trust_stores().send().await.expect("list");
    assert!(!list.trust_store_list().is_empty());

    cf.delete_trust_store()
        .id(&id)
        .if_match(&etag)
        .send()
        .await
        .expect("delete");
}

#[tokio::test]
async fn resource_policy_round_trip() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;

    let arn = "arn:aws:cloudfront::000000000000:distribution/E1234".to_string();
    let policy = r#"{"Version":"2012-10-17","Statement":[]}"#;

    cf.put_resource_policy()
        .resource_arn(&arn)
        .policy_document(policy)
        .send()
        .await
        .expect("put");

    let got = cf
        .get_resource_policy()
        .resource_arn(&arn)
        .send()
        .await
        .expect("get");
    assert_eq!(got.policy_document().unwrap(), policy);

    cf.delete_resource_policy()
        .resource_arn(&arn)
        .send()
        .await
        .expect("delete");
}
