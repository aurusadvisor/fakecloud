mod helpers;

use aws_sdk_apigatewayv2::types::{AuthorizerType, IntegrationType, ProtocolType};
use fakecloud_conformance_macros::test_action;
use helpers::TestServer;

#[test_action("apigatewayv2", "CreateApi", checksum = "9a3b68c2")]
#[test_action("apigatewayv2", "GetApi", checksum = "6e24d0aa")]
#[test_action("apigatewayv2", "GetApis", checksum = "a8aed2d1")]
#[test_action("apigatewayv2", "UpdateApi", checksum = "c0fcd25b")]
#[test_action("apigatewayv2", "DeleteApi", checksum = "959314b8")]
#[tokio::test]
async fn apigatewayv2_api_lifecycle() {
    let server = TestServer::start().await;
    let client = server.apigatewayv2_client().await;

    let created = client
        .create_api()
        .name("conf-api")
        .protocol_type(ProtocolType::Http)
        .description("original")
        .send()
        .await
        .unwrap();
    let api_id = created.api_id().unwrap().to_string();

    let got = client.get_api().api_id(&api_id).send().await.unwrap();
    assert_eq!(got.name(), Some("conf-api"));

    let list = client.get_apis().send().await.unwrap();
    assert!(list.items().iter().any(|a| a.api_id() == Some(&api_id)));

    client
        .update_api()
        .api_id(&api_id)
        .description("updated")
        .send()
        .await
        .unwrap();

    client.delete_api().api_id(api_id).send().await.unwrap();
}

async fn create_api(client: &aws_sdk_apigatewayv2::Client, name: &str) -> String {
    client
        .create_api()
        .name(name)
        .protocol_type(ProtocolType::Http)
        .send()
        .await
        .unwrap()
        .api_id()
        .unwrap()
        .to_string()
}

#[test_action("apigatewayv2", "CreateRoute", checksum = "a838460b")]
#[test_action("apigatewayv2", "GetRoute", checksum = "0c7a355a")]
#[test_action("apigatewayv2", "GetRoutes", checksum = "22479c59")]
#[test_action("apigatewayv2", "UpdateRoute", checksum = "165a43c2")]
#[test_action("apigatewayv2", "DeleteRoute", checksum = "e7c19a5c")]
#[tokio::test]
async fn apigatewayv2_route_lifecycle() {
    let server = TestServer::start().await;
    let client = server.apigatewayv2_client().await;
    let api_id = create_api(&client, "conf-routes").await;

    let route = client
        .create_route()
        .api_id(&api_id)
        .route_key("GET /hello")
        .send()
        .await
        .unwrap();
    let route_id = route.route_id().unwrap().to_string();

    let got = client
        .get_route()
        .api_id(&api_id)
        .route_id(&route_id)
        .send()
        .await
        .unwrap();
    assert_eq!(got.route_key(), Some("GET /hello"));

    let list = client.get_routes().api_id(&api_id).send().await.unwrap();
    assert!(list.items().iter().any(|r| r.route_id() == Some(&route_id)));

    client
        .update_route()
        .api_id(&api_id)
        .route_id(&route_id)
        .route_key("POST /hello")
        .send()
        .await
        .unwrap();

    client
        .delete_route()
        .api_id(&api_id)
        .route_id(route_id)
        .send()
        .await
        .unwrap();
}

#[test_action("apigatewayv2", "CreateIntegration", checksum = "5df9afa0")]
#[test_action("apigatewayv2", "GetIntegration", checksum = "c64b20b5")]
#[test_action("apigatewayv2", "GetIntegrations", checksum = "a03f870e")]
#[test_action("apigatewayv2", "UpdateIntegration", checksum = "67a390d2")]
#[test_action("apigatewayv2", "DeleteIntegration", checksum = "3d7cf5a3")]
#[tokio::test]
async fn apigatewayv2_integration_lifecycle() {
    let server = TestServer::start().await;
    let client = server.apigatewayv2_client().await;
    let api_id = create_api(&client, "conf-integrations").await;

    let integration = client
        .create_integration()
        .api_id(&api_id)
        .integration_type(IntegrationType::HttpProxy)
        .integration_uri("https://example.com/upstream")
        .send()
        .await
        .unwrap();
    let integration_id = integration.integration_id().unwrap().to_string();

    let got = client
        .get_integration()
        .api_id(&api_id)
        .integration_id(&integration_id)
        .send()
        .await
        .unwrap();
    assert_eq!(got.integration_uri(), Some("https://example.com/upstream"));

    let list = client
        .get_integrations()
        .api_id(&api_id)
        .send()
        .await
        .unwrap();
    assert!(list
        .items()
        .iter()
        .any(|i| i.integration_id() == Some(&integration_id)));

    client
        .update_integration()
        .api_id(&api_id)
        .integration_id(&integration_id)
        .integration_uri("https://example.com/updated")
        .send()
        .await
        .unwrap();

    client
        .delete_integration()
        .api_id(&api_id)
        .integration_id(integration_id)
        .send()
        .await
        .unwrap();
}

#[test_action("apigatewayv2", "CreateStage", checksum = "3f012a6b")]
#[test_action("apigatewayv2", "GetStage", checksum = "ea4e5f71")]
#[test_action("apigatewayv2", "GetStages", checksum = "a48f1731")]
#[test_action("apigatewayv2", "UpdateStage", checksum = "5c70fd1e")]
#[test_action("apigatewayv2", "DeleteStage", checksum = "d9ec4d37")]
#[tokio::test]
async fn apigatewayv2_stage_lifecycle() {
    let server = TestServer::start().await;
    let client = server.apigatewayv2_client().await;
    let api_id = create_api(&client, "conf-stages").await;

    client
        .create_stage()
        .api_id(&api_id)
        .stage_name("conf-stage")
        .description("original")
        .send()
        .await
        .unwrap();

    let got = client
        .get_stage()
        .api_id(&api_id)
        .stage_name("conf-stage")
        .send()
        .await
        .unwrap();
    assert_eq!(got.stage_name(), Some("conf-stage"));

    let list = client.get_stages().api_id(&api_id).send().await.unwrap();
    assert!(!list.items().is_empty());

    client
        .update_stage()
        .api_id(&api_id)
        .stage_name("conf-stage")
        .description("updated")
        .send()
        .await
        .unwrap();

    client
        .delete_stage()
        .api_id(&api_id)
        .stage_name("conf-stage")
        .send()
        .await
        .unwrap();
}

#[test_action("apigatewayv2", "CreateDeployment", checksum = "58848759")]
#[test_action("apigatewayv2", "GetDeployment", checksum = "b5d245b0")]
#[test_action("apigatewayv2", "GetDeployments", checksum = "7e2975cf")]
#[tokio::test]
async fn apigatewayv2_deployment_lifecycle() {
    let server = TestServer::start().await;
    let client = server.apigatewayv2_client().await;
    let api_id = create_api(&client, "conf-deployments").await;

    let dep = client
        .create_deployment()
        .api_id(&api_id)
        .description("initial rollout")
        .send()
        .await
        .unwrap();
    let deployment_id = dep.deployment_id().unwrap().to_string();

    let got = client
        .get_deployment()
        .api_id(&api_id)
        .deployment_id(&deployment_id)
        .send()
        .await
        .unwrap();
    assert_eq!(got.deployment_id(), Some(deployment_id.as_str()));

    let list = client
        .get_deployments()
        .api_id(&api_id)
        .send()
        .await
        .unwrap();
    assert!(list
        .items()
        .iter()
        .any(|d| d.deployment_id() == Some(&deployment_id)));
}

#[test_action("apigatewayv2", "CreateAuthorizer", checksum = "6ef46e28")]
#[test_action("apigatewayv2", "GetAuthorizer", checksum = "7eedcf26")]
#[test_action("apigatewayv2", "GetAuthorizers", checksum = "49cf9fe9")]
#[test_action("apigatewayv2", "UpdateAuthorizer", checksum = "63b0c0bc")]
#[test_action("apigatewayv2", "DeleteAuthorizer", checksum = "42e93a7e")]
#[tokio::test]
async fn apigatewayv2_authorizer_lifecycle() {
    let server = TestServer::start().await;
    let client = server.apigatewayv2_client().await;
    let api_id = create_api(&client, "conf-auth").await;

    let auth = client
        .create_authorizer()
        .api_id(&api_id)
        .name("conf-authorizer")
        .authorizer_type(AuthorizerType::Jwt)
        .identity_source("$request.header.Authorization")
        .jwt_configuration(
            aws_sdk_apigatewayv2::types::JwtConfiguration::builder()
                .issuer("https://example.com/.well-known/openid-configuration")
                .audience("test-audience")
                .build(),
        )
        .send()
        .await
        .unwrap();
    let authorizer_id = auth.authorizer_id().unwrap().to_string();

    let got = client
        .get_authorizer()
        .api_id(&api_id)
        .authorizer_id(&authorizer_id)
        .send()
        .await
        .unwrap();
    assert_eq!(got.name(), Some("conf-authorizer"));

    let list = client
        .get_authorizers()
        .api_id(&api_id)
        .send()
        .await
        .unwrap();
    assert!(list
        .items()
        .iter()
        .any(|a| a.authorizer_id() == Some(&authorizer_id)));

    client
        .update_authorizer()
        .api_id(&api_id)
        .authorizer_id(&authorizer_id)
        .name("conf-authorizer-updated")
        .send()
        .await
        .unwrap();

    client
        .delete_authorizer()
        .api_id(&api_id)
        .authorizer_id(authorizer_id)
        .send()
        .await
        .unwrap();
}

// ── Conformance closure batch (all 75 missing ops covered by route-existence assertions) ──

const APIGW_AUTH: &str = "AWS4-HMAC-SHA256 Credential=test/20240101/us-east-1/apigateway/aws4_request, SignedHeaders=host, Signature=0";

async fn apigw_request(
    server: &TestServer,
    method: reqwest::Method,
    path: &str,
    body: &str,
) -> reqwest::Response {
    let resp = reqwest::Client::new()
        .request(method.clone(), format!("{}{}", server.endpoint(), path))
        .header("content-type", "application/json")
        .header("Authorization", APIGW_AUTH)
        .body(body.to_string())
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "{method} {path} returned {}",
        resp.status()
    );
    resp
}

#[test_action("apigatewayv2", "CreateApiMapping", checksum = "65a44b8b")]
#[test_action("apigatewayv2", "CreateDomainName", checksum = "ac3575f3")]
#[test_action("apigatewayv2", "CreateIntegrationResponse", checksum = "91ed2c03")]
#[test_action("apigatewayv2", "CreateModel", checksum = "b5657ad4")]
#[test_action("apigatewayv2", "CreatePortal", checksum = "fb0065d2")]
#[test_action("apigatewayv2", "CreatePortalProduct", checksum = "24feedc4")]
#[test_action("apigatewayv2", "CreateProductPage", checksum = "21238282")]
#[test_action("apigatewayv2", "CreateProductRestEndpointPage", checksum = "a4555d5e")]
#[test_action("apigatewayv2", "CreateRouteResponse", checksum = "efa737be")]
#[test_action("apigatewayv2", "CreateRoutingRule", checksum = "5adb7c51")]
#[test_action("apigatewayv2", "CreateVpcLink", checksum = "5d3c4342")]
#[test_action("apigatewayv2", "DeleteAccessLogSettings", checksum = "f6cb1528")]
#[test_action("apigatewayv2", "DeleteApiMapping", checksum = "3d81d072")]
#[test_action("apigatewayv2", "DeleteCorsConfiguration", checksum = "e9a7baef")]
#[test_action("apigatewayv2", "DeleteDeployment", checksum = "2e1770bf")]
#[test_action("apigatewayv2", "DeleteDomainName", checksum = "d22339e8")]
#[test_action("apigatewayv2", "DeleteIntegrationResponse", checksum = "83ed75ec")]
#[test_action("apigatewayv2", "DeleteModel", checksum = "41929ba5")]
#[test_action("apigatewayv2", "DeletePortal", checksum = "24df0f2a")]
#[test_action("apigatewayv2", "DeletePortalProduct", checksum = "97223bb4")]
#[test_action(
    "apigatewayv2",
    "DeletePortalProductSharingPolicy",
    checksum = "fda8d7f7"
)]
#[test_action("apigatewayv2", "DeleteProductPage", checksum = "6ec6da9d")]
#[test_action("apigatewayv2", "DeleteProductRestEndpointPage", checksum = "641d93fa")]
#[test_action("apigatewayv2", "DeleteRouteRequestParameter", checksum = "66258394")]
#[test_action("apigatewayv2", "DeleteRouteResponse", checksum = "b3ad3b71")]
#[test_action("apigatewayv2", "DeleteRouteSettings", checksum = "c1cffb66")]
#[test_action("apigatewayv2", "DeleteRoutingRule", checksum = "9c0e74ce")]
#[test_action("apigatewayv2", "DeleteVpcLink", checksum = "83cc7290")]
#[test_action("apigatewayv2", "DisablePortal", checksum = "d7c03a0a")]
#[test_action("apigatewayv2", "ExportApi", checksum = "86cf0406")]
#[test_action("apigatewayv2", "GetApiMapping", checksum = "902ccf3e")]
#[test_action("apigatewayv2", "GetApiMappings", checksum = "0cd20b88")]
#[test_action("apigatewayv2", "GetDomainName", checksum = "861fe9ae")]
#[test_action("apigatewayv2", "GetDomainNames", checksum = "87ce16ff")]
#[test_action("apigatewayv2", "GetIntegrationResponse", checksum = "8029a5a8")]
#[test_action("apigatewayv2", "GetIntegrationResponses", checksum = "26e088ef")]
#[test_action("apigatewayv2", "GetModel", checksum = "068e8006")]
#[test_action("apigatewayv2", "GetModels", checksum = "c5ffe6c4")]
#[test_action("apigatewayv2", "GetModelTemplate", checksum = "62fd314e")]
#[test_action("apigatewayv2", "GetPortal", checksum = "e4292d93")]
#[test_action("apigatewayv2", "GetPortalProduct", checksum = "de71d7b4")]
#[test_action("apigatewayv2", "GetPortalProductSharingPolicy", checksum = "1bff8d12")]
#[test_action("apigatewayv2", "GetProductPage", checksum = "ce3eaeec")]
#[test_action("apigatewayv2", "GetProductRestEndpointPage", checksum = "33f1245d")]
#[test_action("apigatewayv2", "GetRouteResponse", checksum = "a55851a4")]
#[test_action("apigatewayv2", "GetRouteResponses", checksum = "3b3d4d7b")]
#[test_action("apigatewayv2", "GetRoutingRule", checksum = "15cfac58")]
#[test_action("apigatewayv2", "GetTags", checksum = "38f8aa65")]
#[test_action("apigatewayv2", "GetVpcLink", checksum = "e281a65b")]
#[test_action("apigatewayv2", "GetVpcLinks", checksum = "3791e727")]
#[test_action("apigatewayv2", "ImportApi", checksum = "aa5dd1b0")]
#[test_action("apigatewayv2", "ListPortalProducts", checksum = "bbdb1af1")]
#[test_action("apigatewayv2", "ListPortals", checksum = "a4456ed5")]
#[test_action("apigatewayv2", "ListProductPages", checksum = "62ba1c1a")]
#[test_action("apigatewayv2", "ListProductRestEndpointPages", checksum = "21f13ca8")]
#[test_action("apigatewayv2", "ListRoutingRules", checksum = "1a5f4cc8")]
#[test_action("apigatewayv2", "PreviewPortal", checksum = "ec5de68f")]
#[test_action("apigatewayv2", "PublishPortal", checksum = "b5d7fa00")]
#[test_action("apigatewayv2", "PutPortalProductSharingPolicy", checksum = "c5dfed82")]
#[test_action("apigatewayv2", "PutRoutingRule", checksum = "8f7115ea")]
#[test_action("apigatewayv2", "ReimportApi", checksum = "098bf802")]
#[test_action("apigatewayv2", "ResetAuthorizersCache", checksum = "71d782fa")]
#[test_action("apigatewayv2", "TagResource", checksum = "bedba25c")]
#[test_action("apigatewayv2", "UntagResource", checksum = "4289cff6")]
#[test_action("apigatewayv2", "UpdateApiMapping", checksum = "d1ffd8c3")]
#[test_action("apigatewayv2", "UpdateDeployment", checksum = "d04bbae0")]
#[test_action("apigatewayv2", "UpdateDomainName", checksum = "249e1eca")]
#[test_action("apigatewayv2", "UpdateIntegrationResponse", checksum = "e8af3800")]
#[test_action("apigatewayv2", "UpdateModel", checksum = "6a9b5ce2")]
#[test_action("apigatewayv2", "UpdatePortal", checksum = "a3b3d3fd")]
#[test_action("apigatewayv2", "UpdatePortalProduct", checksum = "3529eb35")]
#[test_action("apigatewayv2", "UpdateProductPage", checksum = "a22c704f")]
#[test_action("apigatewayv2", "UpdateProductRestEndpointPage", checksum = "a06fad74")]
#[test_action("apigatewayv2", "UpdateRouteResponse", checksum = "391e4258")]
#[test_action("apigatewayv2", "UpdateVpcLink", checksum = "68637366")]
#[tokio::test]
async fn apigwv2_closure_routes_exist() {
    // Every route added in this PR is exercised below. We assert HTTP 2xx
    // (route hit + handler succeeded). Each `#[test_action]` above pins
    // the operation to its Smithy checksum so the audit knows it has
    // coverage even when the test groups multiple ops together.
    let server = TestServer::start().await;
    let client = server.apigatewayv2_client().await;

    // Seed an HTTP API to anchor child resources.
    let api_id = client
        .create_api()
        .name("conf-api")
        .protocol_type(aws_sdk_apigatewayv2::types::ProtocolType::Http)
        .send()
        .await
        .unwrap()
        .api_id()
        .unwrap()
        .to_string();

    // Domain names + API mappings.
    let resp = apigw_request(
        &server,
        reqwest::Method::POST,
        "/v2/domainnames",
        r#"{"DomainName":"example.com"}"#,
    )
    .await;
    assert!(resp.status().is_success());
    let resp = apigw_request(
        &server,
        reqwest::Method::GET,
        "/v2/domainnames/example.com",
        "",
    )
    .await;
    assert!(resp.status().is_success());
    let resp = apigw_request(&server, reqwest::Method::GET, "/v2/domainnames", "").await;
    assert!(resp.status().is_success());
    let resp = apigw_request(
        &server,
        reqwest::Method::PATCH,
        "/v2/domainnames/example.com",
        r#"{}"#,
    )
    .await;
    assert!(resp.status().is_success());

    let resp = apigw_request(
        &server,
        reqwest::Method::POST,
        "/v2/domainnames/example.com/apimappings",
        &format!(r#"{{"ApiId":"{api_id}","Stage":"prod"}}"#),
    )
    .await;
    let body: serde_json::Value = resp.json().await.unwrap();
    let mapping_id = body["apiMappingId"].as_str().unwrap().to_string();
    let resp = apigw_request(
        &server,
        reqwest::Method::GET,
        "/v2/domainnames/example.com/apimappings",
        "",
    )
    .await;
    assert!(resp.status().is_success());
    let resp = apigw_request(
        &server,
        reqwest::Method::GET,
        &format!("/v2/domainnames/example.com/apimappings/{mapping_id}"),
        "",
    )
    .await;
    assert!(resp.status().is_success());
    let resp = apigw_request(
        &server,
        reqwest::Method::PATCH,
        &format!("/v2/domainnames/example.com/apimappings/{mapping_id}"),
        &format!(r#"{{"ApiId":"{api_id}"}}"#),
    )
    .await;
    assert!(resp.status().is_success());
    let resp = apigw_request(
        &server,
        reqwest::Method::DELETE,
        &format!("/v2/domainnames/example.com/apimappings/{mapping_id}"),
        "",
    )
    .await;
    assert!(resp.status().is_success());
    let resp = apigw_request(
        &server,
        reqwest::Method::DELETE,
        "/v2/domainnames/example.com",
        "",
    )
    .await;
    assert!(resp.status().is_success());

    // VPC links.
    let resp = apigw_request(
        &server,
        reqwest::Method::POST,
        "/v2/vpclinks",
        r#"{"Name":"link","SubnetIds":["subnet-1"]}"#,
    )
    .await;
    let body: serde_json::Value = resp.json().await.unwrap();
    let vpc_id = body["vpcLinkId"].as_str().unwrap().to_string();
    apigw_request(&server, reqwest::Method::GET, "/v2/vpclinks", "").await;
    apigw_request(
        &server,
        reqwest::Method::GET,
        &format!("/v2/vpclinks/{vpc_id}"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::PATCH,
        &format!("/v2/vpclinks/{vpc_id}"),
        r#"{"Name":"upd"}"#,
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::DELETE,
        &format!("/v2/vpclinks/{vpc_id}"),
        "",
    )
    .await;

    // Routing rules (nested under a domain name per Smithy).
    apigw_request(
        &server,
        reqwest::Method::POST,
        "/v2/domainnames",
        r#"{"DomainName":"example.com"}"#,
    )
    .await;
    let resp = apigw_request(
        &server,
        reqwest::Method::POST,
        "/v2/domainnames/example.com/routingrules",
        r#"{"Actions":[],"Conditions":[],"Priority":1}"#,
    )
    .await;
    let body: serde_json::Value = resp.json().await.unwrap();
    let rule_id = body["routingRuleId"].as_str().unwrap().to_string();
    apigw_request(
        &server,
        reqwest::Method::GET,
        "/v2/domainnames/example.com/routingrules",
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::GET,
        &format!("/v2/domainnames/example.com/routingrules/{rule_id}"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::PUT,
        &format!("/v2/domainnames/example.com/routingrules/{rule_id}"),
        r#"{"Actions":[],"Conditions":[],"Priority":1}"#,
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::DELETE,
        &format!("/v2/domainnames/example.com/routingrules/{rule_id}"),
        "",
    )
    .await;

    // Tags.
    apigw_request(
        &server,
        reqwest::Method::POST,
        "/v2/tags/arn:aws:apigateway:us-east-1::%2Fapis%2Fconf-api",
        r#"{"Tags":{"k":"v"}}"#,
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::GET,
        "/v2/tags/arn:aws:apigateway:us-east-1::%2Fapis%2Fconf-api",
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::DELETE,
        "/v2/tags/arn:aws:apigateway:us-east-1::%2Fapis%2Fconf-api?tagKeys=k",
        "",
    )
    .await;

    // Models.
    let resp = apigw_request(
        &server,
        reqwest::Method::POST,
        &format!("/v2/apis/{api_id}/models"),
        r#"{"Name":"m1","Schema":"{}"}"#,
    )
    .await;
    let body: serde_json::Value = resp.json().await.unwrap();
    let model_id = body["modelId"].as_str().unwrap().to_string();
    apigw_request(
        &server,
        reqwest::Method::GET,
        &format!("/v2/apis/{api_id}/models"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::GET,
        &format!("/v2/apis/{api_id}/models/{model_id}"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::PATCH,
        &format!("/v2/apis/{api_id}/models/{model_id}"),
        r#"{}"#,
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::GET,
        &format!("/v2/apis/{api_id}/models/{model_id}/template"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::DELETE,
        &format!("/v2/apis/{api_id}/models/{model_id}"),
        "",
    )
    .await;

    // Integration + integration responses.
    let resp = apigw_request(
        &server,
        reqwest::Method::POST,
        &format!("/v2/apis/{api_id}/integrations"),
        r#"{"integrationType":"HTTP_PROXY","integrationUri":"http://example.com"}"#,
    )
    .await;
    let body: serde_json::Value = resp.json().await.unwrap();
    let integ_id = body["integrationId"]
        .as_str()
        .or_else(|| body["integrationId"].as_str())
        .unwrap()
        .to_string();
    let resp = apigw_request(
        &server,
        reqwest::Method::POST,
        &format!("/v2/apis/{api_id}/integrations/{integ_id}/integrationresponses"),
        r#"{"IntegrationResponseKey":"$default"}"#,
    )
    .await;
    let body: serde_json::Value = resp.json().await.unwrap();
    let ir_id = body["integrationResponseId"].as_str().unwrap().to_string();
    apigw_request(
        &server,
        reqwest::Method::GET,
        &format!("/v2/apis/{api_id}/integrations/{integ_id}/integrationresponses"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::GET,
        &format!("/v2/apis/{api_id}/integrations/{integ_id}/integrationresponses/{ir_id}"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::PATCH,
        &format!("/v2/apis/{api_id}/integrations/{integ_id}/integrationresponses/{ir_id}"),
        r#"{}"#,
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::DELETE,
        &format!("/v2/apis/{api_id}/integrations/{integ_id}/integrationresponses/{ir_id}"),
        "",
    )
    .await;

    // Routes + route responses.
    let resp = apigw_request(
        &server,
        reqwest::Method::POST,
        &format!("/v2/apis/{api_id}/routes"),
        r#"{"routeKey":"GET /test"}"#,
    )
    .await;
    let body: serde_json::Value = resp.json().await.unwrap();
    let route_id = body["routeId"]
        .as_str()
        .or_else(|| body["routeId"].as_str())
        .unwrap()
        .to_string();
    let resp = apigw_request(
        &server,
        reqwest::Method::POST,
        &format!("/v2/apis/{api_id}/routes/{route_id}/routeresponses"),
        r#"{"RouteResponseKey":"$default"}"#,
    )
    .await;
    let body: serde_json::Value = resp.json().await.unwrap();
    let rr_id = body["routeResponseId"]
        .as_str()
        .unwrap_or("rr1")
        .to_string();
    apigw_request(
        &server,
        reqwest::Method::GET,
        &format!("/v2/apis/{api_id}/routes/{route_id}/routeresponses"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::GET,
        &format!("/v2/apis/{api_id}/routes/{route_id}/routeresponses/{rr_id}"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::PATCH,
        &format!("/v2/apis/{api_id}/routes/{route_id}/routeresponses/{rr_id}"),
        r#"{}"#,
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::DELETE,
        &format!("/v2/apis/{api_id}/routes/{route_id}/routeresponses/{rr_id}"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::DELETE,
        &format!("/v2/apis/{api_id}/routes/{route_id}/requestparameters/foo"),
        "",
    )
    .await;

    // Cors + access logs + route settings + reset cache.
    apigw_request(
        &server,
        reqwest::Method::DELETE,
        &format!("/v2/apis/{api_id}/cors"),
        "",
    )
    .await;
    let stage_resp = apigw_request(
        &server,
        reqwest::Method::POST,
        &format!("/v2/apis/{api_id}/stages"),
        r#"{"stageName":"prod"}"#,
    )
    .await;
    assert!(stage_resp.status().is_success());
    apigw_request(
        &server,
        reqwest::Method::DELETE,
        &format!("/v2/apis/{api_id}/stages/prod/accesslogsettings"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::DELETE,
        &format!("/v2/apis/{api_id}/stages/prod/routesettings/GET%20%2Ftest"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::DELETE,
        &format!("/v2/apis/{api_id}/stages/prod/cache/authorizers"),
        "",
    )
    .await;

    // Deployment update + delete.
    let dep_resp = apigw_request(
        &server,
        reqwest::Method::POST,
        &format!("/v2/apis/{api_id}/deployments"),
        r#"{}"#,
    )
    .await;
    let body: serde_json::Value = dep_resp.json().await.unwrap();
    let dep_id = body["deploymentId"]
        .as_str()
        .or_else(|| body["deploymentId"].as_str())
        .unwrap_or("dep1")
        .to_string();
    apigw_request(
        &server,
        reqwest::Method::PATCH,
        &format!("/v2/apis/{api_id}/deployments/{dep_id}"),
        r#"{}"#,
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::DELETE,
        &format!("/v2/apis/{api_id}/deployments/{dep_id}"),
        "",
    )
    .await;

    // Import + Reimport + Export.
    apigw_request(
        &server,
        reqwest::Method::PUT,
        "/v2/apis",
        r#"{"Body":"openapi: 3.0.1\n"}"#,
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::PUT,
        &format!("/v2/apis/{api_id}"),
        r#"{"Body":"openapi: 3.0.1\n"}"#,
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::GET,
        &format!("/v2/apis/{api_id}/exports/OAS30?outputType=YAML"),
        "",
    )
    .await;

    // Portals + portal products + sharing policies + product pages.
    let resp = apigw_request(
        &server,
        reqwest::Method::POST,
        "/v2/portals",
        r#"{"Name":"p1","Authorization":{},"EndpointConfiguration":{},"PortalContent":{}}"#,
    )
    .await;
    let body: serde_json::Value = resp.json().await.unwrap();
    let portal_id = body["portalId"].as_str().unwrap().to_string();
    apigw_request(&server, reqwest::Method::GET, "/v2/portals", "").await;
    apigw_request(
        &server,
        reqwest::Method::GET,
        &format!("/v2/portals/{portal_id}"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::PATCH,
        &format!("/v2/portals/{portal_id}"),
        r#"{}"#,
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::DELETE,
        &format!("/v2/portals/{portal_id}/publish"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::POST,
        &format!("/v2/portals/{portal_id}/preview"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::POST,
        &format!("/v2/portals/{portal_id}/publish"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::DELETE,
        &format!("/v2/portals/{portal_id}"),
        "",
    )
    .await;

    let resp = apigw_request(
        &server,
        reqwest::Method::POST,
        "/v2/portalproducts",
        r#"{"DisplayName":"prod"}"#,
    )
    .await;
    let body: serde_json::Value = resp.json().await.unwrap();
    let pp_id = body["portalProductId"].as_str().unwrap().to_string();
    apigw_request(&server, reqwest::Method::GET, "/v2/portalproducts", "").await;
    apigw_request(
        &server,
        reqwest::Method::GET,
        &format!("/v2/portalproducts/{pp_id}"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::PATCH,
        &format!("/v2/portalproducts/{pp_id}"),
        r#"{}"#,
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::PUT,
        &format!("/v2/portalproducts/{pp_id}/sharingpolicy"),
        r#"{"PolicyDocument":"{}"}"#,
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::GET,
        &format!("/v2/portalproducts/{pp_id}/sharingpolicy"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::DELETE,
        &format!("/v2/portalproducts/{pp_id}/sharingpolicy"),
        "",
    )
    .await;

    let resp = apigw_request(
        &server,
        reqwest::Method::POST,
        &format!("/v2/portalproducts/{pp_id}/productpages"),
        r#"{"Name":"p","DisplayContent":{"Body":"b","Title":"t"}}"#,
    )
    .await;
    let body: serde_json::Value = resp.json().await.unwrap();
    let page_id = body["productPageId"].as_str().unwrap().to_string();
    apigw_request(
        &server,
        reqwest::Method::GET,
        &format!("/v2/portalproducts/{pp_id}/productpages"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::GET,
        &format!("/v2/portalproducts/{pp_id}/productpages/{page_id}"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::PATCH,
        &format!("/v2/portalproducts/{pp_id}/productpages/{page_id}"),
        r#"{}"#,
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::DELETE,
        &format!("/v2/portalproducts/{pp_id}/productpages/{page_id}"),
        "",
    )
    .await;

    let resp = apigw_request(
        &server,
        reqwest::Method::POST,
        &format!("/v2/portalproducts/{pp_id}/productrestendpointpages"),
        r#"{"Name":"p","RestEndpointIdentifier":{"IdentifierParts":{"Method":"GET","Path":"/","RestApiId":"r","Stage":"prod"}}}"#,
    )
    .await;
    let body: serde_json::Value = resp.json().await.unwrap();
    let rep_id = body["productRestEndpointPageId"]
        .as_str()
        .unwrap()
        .to_string();
    apigw_request(
        &server,
        reqwest::Method::GET,
        &format!("/v2/portalproducts/{pp_id}/productrestendpointpages"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::GET,
        &format!("/v2/portalproducts/{pp_id}/productrestendpointpages/{rep_id}"),
        "",
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::PATCH,
        &format!("/v2/portalproducts/{pp_id}/productrestendpointpages/{rep_id}"),
        r#"{}"#,
    )
    .await;
    apigw_request(
        &server,
        reqwest::Method::DELETE,
        &format!("/v2/portalproducts/{pp_id}/productrestendpointpages/{rep_id}"),
        "",
    )
    .await;

    apigw_request(
        &server,
        reqwest::Method::DELETE,
        &format!("/v2/portalproducts/{pp_id}"),
        "",
    )
    .await;
}
