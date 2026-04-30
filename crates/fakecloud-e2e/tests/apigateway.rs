//! End-to-end coverage for API Gateway v1 (REST APIs).
//!
//! Verifies the full create -> resource -> method -> integration ->
//! deployment -> stage chain that AWS SDK callers walk to stand up a
//! REST API. Hits the AWS JSON surface directly through the SDK so
//! the test passes only if both the URL routing (REST-style) and the
//! response shapes match what the SDK expects.

mod helpers;

use helpers::TestServer;

#[tokio::test]
async fn create_rest_api_round_trip() {
    let server = TestServer::start().await;
    let client = server.apigateway_client().await;

    let api = client
        .create_rest_api()
        .name("petstore")
        .description("integration test")
        .send()
        .await
        .expect("create_rest_api");
    assert_eq!(api.name(), Some("petstore"));
    let api_id = api.id().expect("id").to_string();
    assert!(!api_id.is_empty());
    let root_resource_id = api.root_resource_id().expect("root").to_string();

    let described = client
        .get_rest_api()
        .rest_api_id(&api_id)
        .send()
        .await
        .expect("get_rest_api");
    assert_eq!(described.name(), Some("petstore"));

    let listed = client.get_rest_apis().send().await.expect("get_rest_apis");
    assert_eq!(listed.items().len(), 1);

    // Create a child resource and a method on it.
    let resource = client
        .create_resource()
        .rest_api_id(&api_id)
        .parent_id(&root_resource_id)
        .path_part("pets")
        .send()
        .await
        .expect("create_resource");
    let res_id = resource.id().expect("res id").to_string();
    assert_eq!(resource.path_part(), Some("pets"));
    assert_eq!(resource.path(), Some("/pets"));

    client
        .put_method()
        .rest_api_id(&api_id)
        .resource_id(&res_id)
        .http_method("GET")
        .authorization_type("NONE")
        .send()
        .await
        .expect("put_method");

    client
        .put_integration()
        .rest_api_id(&api_id)
        .resource_id(&res_id)
        .http_method("GET")
        .r#type(aws_sdk_apigateway::types::IntegrationType::Mock)
        .send()
        .await
        .expect("put_integration");

    let deployment = client
        .create_deployment()
        .rest_api_id(&api_id)
        .stage_name("prod")
        .send()
        .await
        .expect("create_deployment");
    assert!(deployment.id().is_some());

    // The auto-created stage from create_deployment with stageName.
    let stage = client
        .get_stage()
        .rest_api_id(&api_id)
        .stage_name("prod")
        .send()
        .await
        .expect("get_stage");
    assert_eq!(stage.stage_name(), Some("prod"));

    // Cleanup.
    client
        .delete_rest_api()
        .rest_api_id(&api_id)
        .send()
        .await
        .expect("delete_rest_api");
    let listed_after = client
        .get_rest_apis()
        .send()
        .await
        .expect("get after delete");
    assert!(listed_after.items().is_empty());
}

#[tokio::test]
async fn api_keys_and_usage_plans() {
    let server = TestServer::start().await;
    let client = server.apigateway_client().await;

    let key = client
        .create_api_key()
        .name("my-key")
        .enabled(true)
        .send()
        .await
        .expect("create_api_key");
    let key_id = key.id().expect("key id").to_string();
    assert_eq!(key.name(), Some("my-key"));

    let plan = client
        .create_usage_plan()
        .name("standard")
        .send()
        .await
        .expect("create_usage_plan");
    let plan_id = plan.id().expect("plan id").to_string();

    client
        .create_usage_plan_key()
        .usage_plan_id(&plan_id)
        .key_id(&key_id)
        .key_type("API_KEY")
        .send()
        .await
        .expect("create_usage_plan_key");

    let listed = client
        .get_usage_plan_keys()
        .usage_plan_id(&plan_id)
        .send()
        .await
        .expect("get_usage_plan_keys");
    assert_eq!(listed.items().len(), 1);

    client
        .delete_usage_plan_key()
        .usage_plan_id(&plan_id)
        .key_id(&key_id)
        .send()
        .await
        .expect("delete_usage_plan_key");
    client
        .delete_usage_plan()
        .usage_plan_id(&plan_id)
        .send()
        .await
        .expect("delete_usage_plan");
    client
        .delete_api_key()
        .api_key(&key_id)
        .send()
        .await
        .expect("delete_api_key");
}

#[tokio::test]
async fn get_export_returns_openapi_with_real_paths() {
    let server = TestServer::start().await;
    let client = server.apigateway_client().await;

    let api = client
        .create_rest_api()
        .name("export-target")
        .send()
        .await
        .expect("create_rest_api");
    let api_id = api.id().unwrap().to_string();
    let root = api.root_resource_id().unwrap().to_string();

    let resource = client
        .create_resource()
        .rest_api_id(&api_id)
        .parent_id(&root)
        .path_part("widgets")
        .send()
        .await
        .expect("create_resource");
    let res_id = resource.id().unwrap().to_string();

    client
        .put_method()
        .rest_api_id(&api_id)
        .resource_id(&res_id)
        .http_method("GET")
        .authorization_type("NONE")
        .operation_name("GetWidgets")
        .request_parameters("method.request.querystring.limit", false)
        .send()
        .await
        .expect("put_method GET");

    client
        .put_integration()
        .rest_api_id(&api_id)
        .resource_id(&res_id)
        .http_method("GET")
        .r#type(aws_sdk_apigateway::types::IntegrationType::Mock)
        .send()
        .await
        .expect("put_integration");

    client
        .create_deployment()
        .rest_api_id(&api_id)
        .stage_name("v1")
        .send()
        .await
        .expect("create_deployment");

    let export = client
        .get_export()
        .rest_api_id(&api_id)
        .stage_name("v1")
        .export_type("oas30")
        .send()
        .await
        .expect("get_export");
    let body_blob = export.body().expect("export body should be present");
    let body: serde_json::Value =
        serde_json::from_slice(body_blob.as_ref()).expect("export body must be JSON");
    assert_eq!(body["openapi"], "3.0.1");
    assert_eq!(body["info"]["title"], "export-target");
    let paths = body["paths"].as_object().expect("paths object");
    let widgets = paths
        .get("/widgets")
        .expect("widgets path should be in OpenAPI export");
    let get_op = widgets
        .as_object()
        .unwrap()
        .get("get")
        .expect("GET operation should be present");
    assert_eq!(get_op["operationId"], "GetWidgets");
    let params = get_op["parameters"].as_array().expect("parameters array");
    assert!(params
        .iter()
        .any(|p| p["name"] == "limit" && p["in"] == "query"));
}
