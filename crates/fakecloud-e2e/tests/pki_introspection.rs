//! PKI-stub introspection endpoints. Tests assert that fakecloud exposes
//! what it accepted from clients without claiming to validate external
//! CA chains.

mod helpers;

use aws_sdk_acm::primitives::Blob;
use helpers::TestServer;

const SELF_SIGNED_PEM: &str =
    "-----BEGIN CERTIFICATE-----\nMIIBnzCCAQgCCQ==\n-----END CERTIFICATE-----\n";
const SELF_SIGNED_KEY: &str =
    "-----BEGIN PRIVATE KEY-----\nMIIBnzCCAQgCCQ==\n-----END PRIVATE KEY-----\n";

#[tokio::test]
async fn acm_chain_info_exposes_block_counts_and_no_external_validation() {
    let server = TestServer::start().await;
    let acm = server.acm_client().await;

    let chain_pem = format!("{SELF_SIGNED_PEM}{SELF_SIGNED_PEM}");
    let imported = acm
        .import_certificate()
        .certificate(Blob::new(SELF_SIGNED_PEM.as_bytes()))
        .private_key(Blob::new(SELF_SIGNED_KEY.as_bytes()))
        .certificate_chain(Blob::new(chain_pem.as_bytes()))
        .send()
        .await
        .unwrap();

    let arn = imported.certificate_arn.unwrap();
    let id = arn.rsplit('/').next().unwrap();

    let info: serde_json::Value = reqwest::get(format!(
        "{}/_fakecloud/acm/certificates/{}/chain-info",
        server.endpoint(),
        id
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    assert_eq!(info["certificate_pem_blocks"], 1);
    assert_eq!(info["chain_pem_blocks"], 2);
    assert_eq!(info["external_ca_validated"], false);
    assert_eq!(info["certificate_arn"], arn);
}

#[tokio::test]
async fn apigatewayv2_mtls_info_reports_trust_store_without_validation() {
    let server = TestServer::start().await;
    let api = server.apigatewayv2_client().await;

    api.create_domain_name()
        .domain_name("api.example.com")
        .mutual_tls_authentication(
            aws_sdk_apigatewayv2::types::MutualTlsAuthenticationInput::builder()
                .truststore_uri("s3://my-bucket/truststore.pem")
                .truststore_version("v1")
                .build(),
        )
        .send()
        .await
        .unwrap();

    let info: serde_json::Value = reqwest::get(format!(
        "{}/_fakecloud/apigatewayv2/domain-names/api.example.com/mtls-info",
        server.endpoint()
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();

    assert_eq!(info["domain_name"], "api.example.com");
    let mtls = &info["mutual_tls_authentication"];
    let uri = mtls
        .get("TruststoreUri")
        .or_else(|| mtls.get("truststoreUri"));
    assert_eq!(
        uri.and_then(|v| v.as_str()),
        Some("s3://my-bucket/truststore.pem"),
        "mtls block = {mtls:?}"
    );
    assert_eq!(info["external_ca_validated"], false);
}
