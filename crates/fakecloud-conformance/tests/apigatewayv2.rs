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
