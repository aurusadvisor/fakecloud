use super::*;
use bytes::Bytes;
use http::{HeaderMap, Method};
use parking_lot::RwLock;
use std::collections::HashMap;
use std::sync::Arc;

fn make_state() -> SharedLambdaState {
    Arc::new(RwLock::new(
        fakecloud_core::multi_account::MultiAccountState::new("123456789012", "us-east-1", ""),
    ))
}

fn make_request(method: Method, path: &str, body: &str) -> AwsRequest {
    let path_segments: Vec<String> = path
        .split('/')
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
        .collect();
    AwsRequest {
        service: "lambda".to_string(),
        action: String::new(),
        region: "us-east-1".to_string(),
        account_id: "123456789012".to_string(),
        request_id: "test-request-id".to_string(),
        headers: HeaderMap::new(),
        query_params: HashMap::new(),
        body: Bytes::from(body.to_string()),
        body_stream: parking_lot::Mutex::new(None),
        path_segments,
        raw_path: path.to_string(),
        raw_query: String::new(),
        method,
        is_query_protocol: false,
        access_key_id: None,
        principal: None,
    }
}

#[test]
fn normalize_function_name_bare_name_passes_through() {
    assert_eq!(normalize_function_name("MyFunction"), "MyFunction");
}

#[test]
fn normalize_function_name_strips_qualifier_from_bare_name() {
    assert_eq!(normalize_function_name("MyFunction:PROD"), "MyFunction");
    assert_eq!(normalize_function_name("MyFunction:1"), "MyFunction");
}

#[test]
fn normalize_function_name_strips_full_arn() {
    assert_eq!(
        normalize_function_name("arn:aws:lambda:us-east-1:123456789012:function:MyFunction"),
        "MyFunction"
    );
}

#[test]
fn normalize_function_name_strips_qualified_full_arn() {
    assert_eq!(
        normalize_function_name("arn:aws:lambda:us-east-1:123456789012:function:MyFunction:PROD"),
        "MyFunction"
    );
}

#[test]
fn normalize_function_name_strips_partial_arn() {
    assert_eq!(
        normalize_function_name("123456789012:function:MyFunction"),
        "MyFunction"
    );
    assert_eq!(
        normalize_function_name("123456789012:function:MyFunction:1"),
        "MyFunction"
    );
}

#[test]
fn normalize_function_name_leaves_malformed_arn_alone() {
    // wrong service in ARN — multiple colons, no lambda prefix → unchanged
    let s = "arn:aws:s3:us-east-1:123456789012:function:Foo";
    assert_eq!(normalize_function_name(s), s);
    // partial ARN with non-numeric account-shaped prefix → unchanged
    let s2 = "abc:function:Foo";
    assert_eq!(normalize_function_name(s2), s2);
}

#[test]
fn normalize_function_name_empty() {
    assert_eq!(normalize_function_name(""), "");
}

#[test]
fn normalize_function_name_decodes_percent_encoded_arn() {
    // SDKs URL-encode `:` in path segments. The toolkit / aws-sdk-lambda
    // wire form for `arn:aws:lambda:...` is `arn%3Aaws%3Alambda%3A...`.
    let encoded = "arn%3Aaws%3Alambda%3Aus-east-1%3A123456789012%3Afunction%3AMyFunc";
    assert_eq!(normalize_function_name(encoded), "MyFunc");
}

#[tokio::test]
async fn get_function_accepts_full_arn() {
    let svc = LambdaService::new(make_state());
    // Seed a function via CreateFunction
    let create_body = json!({
        "FunctionName": "MyFunc",
        "Runtime": "nodejs20.x",
        "Role": "arn:aws:iam::123456789012:role/lambda-role",
        "Handler": "index.handler",
        "Code": {"ZipFile": ""},
    })
    .to_string();
    let req = make_request(Method::POST, "/2015-03-31/functions", &create_body);
    svc.handle(req).await.expect("create function");

    // GetFunction by full ARN
    let req = make_request(
        Method::GET,
        "/2015-03-31/functions/arn:aws:lambda:us-east-1:123456789012:function:MyFunc",
        "",
    );
    let resp = svc.handle(req).await.expect("get function by ARN");
    assert_eq!(resp.status, StatusCode::OK);
}

#[tokio::test]
async fn get_function_accepts_partial_arn() {
    let svc = LambdaService::new(make_state());
    let create_body = json!({
        "FunctionName": "MyFunc",
        "Runtime": "nodejs20.x",
        "Role": "arn:aws:iam::123456789012:role/lambda-role",
        "Handler": "index.handler",
        "Code": {"ZipFile": ""},
    })
    .to_string();
    let req = make_request(Method::POST, "/2015-03-31/functions", &create_body);
    svc.handle(req).await.expect("create function");

    let req = make_request(
        Method::GET,
        "/2015-03-31/functions/123456789012:function:MyFunc",
        "",
    );
    let resp = svc.handle(req).await.expect("get function by partial ARN");
    assert_eq!(resp.status, StatusCode::OK);
}

#[tokio::test]
async fn get_function_accepts_name_with_qualifier() {
    let svc = LambdaService::new(make_state());
    let create_body = json!({
        "FunctionName": "MyFunc",
        "Runtime": "nodejs20.x",
        "Role": "arn:aws:iam::123456789012:role/lambda-role",
        "Handler": "index.handler",
        "Code": {"ZipFile": ""},
    })
    .to_string();
    let req = make_request(Method::POST, "/2015-03-31/functions", &create_body);
    svc.handle(req).await.expect("create function");

    let req = make_request(Method::GET, "/2015-03-31/functions/MyFunc:1", "");
    let resp = svc
        .handle(req)
        .await
        .expect("get function by name:qualifier");
    assert_eq!(resp.status, StatusCode::OK);
}

#[test]
fn iam_condition_keys_for_add_permission_populates_arn_and_principal() {
    let svc = LambdaService::new(make_state());
    let body = json!({
        "StatementId": "stmt",
        "Action": "lambda:InvokeFunction",
        "Principal": "s3.amazonaws.com",
    })
    .to_string();
    let req = make_request(Method::POST, "/2015-03-31/functions/my-func/policy", &body);
    let action = fakecloud_core::auth::IamAction {
        service: "lambda",
        action: "AddPermission",
        resource: "arn:aws:lambda:us-east-1:123456789012:function:my-func".to_string(),
    };
    let keys = svc.iam_condition_keys_for(&req, &action);
    assert_eq!(
        keys.get("lambda:functionarn"),
        Some(&vec![
            "arn:aws:lambda:us-east-1:123456789012:function:my-func".to_string()
        ])
    );
    assert_eq!(
        keys.get("lambda:principal"),
        Some(&vec!["s3.amazonaws.com".to_string()])
    );
}

#[test]
fn iam_condition_keys_for_add_permission_omits_missing_principal() {
    let svc = LambdaService::new(make_state());
    let body = json!({"StatementId": "stmt", "Action": "lambda:InvokeFunction"}).to_string();
    let req = make_request(Method::POST, "/2015-03-31/functions/my-func/policy", &body);
    let action = fakecloud_core::auth::IamAction {
        service: "lambda",
        action: "AddPermission",
        resource: "arn:aws:lambda:us-east-1:123456789012:function:my-func".to_string(),
    };
    let keys = svc.iam_condition_keys_for(&req, &action);
    assert!(!keys.contains_key("lambda:principal"));
    assert!(keys.contains_key("lambda:functionarn"));
}

#[test]
fn iam_condition_keys_for_non_add_permission_is_empty() {
    let svc = LambdaService::new(make_state());
    let req = make_request(Method::GET, "/2015-03-31/functions/my-func", "");
    let action = fakecloud_core::auth::IamAction {
        service: "lambda",
        action: "GetFunction",
        resource: "arn:aws:lambda:us-east-1:123456789012:function:my-func".to_string(),
    };
    assert!(svc.iam_condition_keys_for(&req, &action).is_empty());
}

#[tokio::test]
async fn test_create_and_get_function() {
    let state = make_state();
    let svc = LambdaService::new(state);

    let create_body = json!({
        "FunctionName": "my-func",
        "Runtime": "python3.12",
        "Role": "arn:aws:iam::123456789012:role/test-role",
        "Handler": "index.handler",
        "Code": { "ZipFile": "UEsFBgAAAAAAAAAAAAAAAAAAAAA=" }
    });

    let req = make_request(
        Method::POST,
        "/2015-03-31/functions",
        &create_body.to_string(),
    );
    let resp = svc.handle(req).await.unwrap();
    assert_eq!(resp.status, StatusCode::CREATED);

    let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
    assert_eq!(body["FunctionName"], "my-func");
    assert_eq!(body["Runtime"], "python3.12");

    // Get
    let req = make_request(Method::GET, "/2015-03-31/functions/my-func", "");
    let resp = svc.handle(req).await.unwrap();
    assert_eq!(resp.status, StatusCode::OK);
    let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
    assert_eq!(body["Configuration"]["FunctionName"], "my-func");
}

#[tokio::test]
async fn test_delete_function() {
    let state = make_state();
    let svc = LambdaService::new(state);

    let create_body = json!({
        "FunctionName": "to-delete",
        "Runtime": "nodejs20.x",
        "Role": "arn:aws:iam::123456789012:role/test",
        "Handler": "index.handler",
        "Code": {}
    });

    let req = make_request(
        Method::POST,
        "/2015-03-31/functions",
        &create_body.to_string(),
    );
    svc.handle(req).await.unwrap();

    let req = make_request(Method::DELETE, "/2015-03-31/functions/to-delete", "");
    let resp = svc.handle(req).await.unwrap();
    assert_eq!(resp.status, StatusCode::NO_CONTENT);

    // Verify deleted
    let req = make_request(Method::GET, "/2015-03-31/functions/to-delete", "");
    let resp = svc.handle(req).await;
    assert!(resp.is_err());
}

#[tokio::test]
async fn test_invoke_without_runtime_returns_error() {
    let state = make_state();
    let svc = LambdaService::new(state);

    let create_body = json!({
        "FunctionName": "invoke-me",
        "Runtime": "python3.12",
        "Role": "arn:aws:iam::123456789012:role/test",
        "Handler": "index.handler",
        "Code": {}
    });

    let req = make_request(
        Method::POST,
        "/2015-03-31/functions",
        &create_body.to_string(),
    );
    svc.handle(req).await.unwrap();

    let req = make_request(
        Method::POST,
        "/2015-03-31/functions/invoke-me/invocations",
        r#"{"key": "value"}"#,
    );
    let resp = svc.handle(req).await;
    assert!(resp.is_err());
}

#[tokio::test]
async fn test_invoke_nonexistent_function() {
    let state = make_state();
    let svc = LambdaService::new(state);

    let req = make_request(
        Method::POST,
        "/2015-03-31/functions/does-not-exist/invocations",
        "{}",
    );
    let resp = svc.handle(req).await;
    assert!(resp.is_err());
}

#[tokio::test]
async fn test_list_functions() {
    let state = make_state();
    let svc = LambdaService::new(state);

    for name in &["func-a", "func-b"] {
        let create_body = json!({
            "FunctionName": name,
            "Runtime": "python3.12",
            "Role": "arn:aws:iam::123456789012:role/test",
            "Handler": "index.handler",
            "Code": {}
        });
        let req = make_request(
            Method::POST,
            "/2015-03-31/functions",
            &create_body.to_string(),
        );
        svc.handle(req).await.unwrap();
    }

    let req = make_request(Method::GET, "/2015-03-31/functions", "");
    let resp = svc.handle(req).await.unwrap();
    let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
    assert_eq!(body["Functions"].as_array().unwrap().len(), 2);
}

#[tokio::test]
async fn test_event_source_mapping() {
    let state = make_state();
    let svc = LambdaService::new(state);

    // Create function first
    let create_body = json!({
        "FunctionName": "esm-func",
        "Runtime": "python3.12",
        "Role": "arn:aws:iam::123456789012:role/test",
        "Handler": "index.handler",
        "Code": {}
    });
    let req = make_request(
        Method::POST,
        "/2015-03-31/functions",
        &create_body.to_string(),
    );
    svc.handle(req).await.unwrap();

    // Create mapping
    let mapping_body = json!({
        "FunctionName": "esm-func",
        "EventSourceArn": "arn:aws:sqs:us-east-1:123456789012:my-queue",
        "BatchSize": 5
    });
    let req = make_request(
        Method::POST,
        "/2015-03-31/event-source-mappings",
        &mapping_body.to_string(),
    );
    let resp = svc.handle(req).await.unwrap();
    assert_eq!(resp.status, StatusCode::ACCEPTED);
    let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
    let uuid = body["UUID"].as_str().unwrap().to_string();

    // List mappings
    let req = make_request(Method::GET, "/2015-03-31/event-source-mappings", "");
    let resp = svc.handle(req).await.unwrap();
    let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
    assert_eq!(body["EventSourceMappings"].as_array().unwrap().len(), 1);

    // Delete mapping
    let req = make_request(
        Method::DELETE,
        &format!("/2015-03-31/event-source-mappings/{uuid}"),
        "",
    );
    let resp = svc.handle(req).await.unwrap();
    assert_eq!(resp.status, StatusCode::ACCEPTED);
}

async fn seed_function(svc: &LambdaService, name: &str) {
    let body = json!({
        "FunctionName": name,
        "Runtime": "python3.12",
        "Role": "arn:aws:iam::123456789012:role/r",
        "Handler": "index.handler",
        "Code": {}
    });
    let req = make_request(Method::POST, "/2015-03-31/functions", &body.to_string());
    svc.handle(req).await.unwrap();
}

#[tokio::test]
async fn update_function_code_replaces_zip_and_bumps_revision() {
    let svc = LambdaService::new(make_state());
    seed_function(&svc, "ucode").await;

    // GetFunctionConfiguration to capture the original revisionId
    let req = make_request(Method::GET, "/2015-03-31/functions/ucode/configuration", "");
    let resp = svc.handle(req).await.unwrap();
    let pre: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
    let pre_revision = pre["RevisionId"].as_str().unwrap().to_string();
    let pre_sha = pre["CodeSha256"].as_str().unwrap().to_string();

    // UpdateFunctionCode with a real ZipFile payload
    let new_zip_b64 = base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        b"fresh-zip-bytes",
    );
    let body = json!({ "ZipFile": new_zip_b64 });
    let req = make_request(
        Method::PUT,
        "/2015-03-31/functions/ucode/code",
        &body.to_string(),
    );
    let resp = svc.handle(req).await.unwrap();
    let post: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
    assert_ne!(post["RevisionId"].as_str().unwrap(), pre_revision);
    assert_ne!(post["CodeSha256"].as_str().unwrap(), pre_sha);
    assert_eq!(
        post["CodeSize"].as_i64().unwrap(),
        b"fresh-zip-bytes".len() as i64
    );
}

#[tokio::test]
async fn update_function_code_replaces_image_uri() {
    let svc = LambdaService::new(make_state());
    // Seed an image-package function so UpdateFunctionCode can swap URIs.
    let body = json!({
        "FunctionName": "img-fn",
        "Runtime": "python3.12",
        "Role": "arn:aws:iam::123456789012:role/r",
        "Handler": "index.handler",
        "PackageType": "Image",
        "Code": {"ImageUri": "old.example.com/image:1"},
    });
    let req = make_request(Method::POST, "/2015-03-31/functions", &body.to_string());
    svc.handle(req).await.unwrap();

    let body = json!({ "ImageUri": "new.example.com/image:2" });
    let req = make_request(
        Method::PUT,
        "/2015-03-31/functions/img-fn/code",
        &body.to_string(),
    );
    let resp = svc.handle(req).await.unwrap();
    let post: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
    assert_eq!(
        post["Code"]["ImageUri"].as_str().unwrap(),
        "new.example.com/image:2"
    );
}

#[tokio::test]
async fn publish_version_increments_and_snapshots_config() {
    let svc = LambdaService::new(make_state());
    seed_function(&svc, "vfn").await;

    // Publish v1 with the seed Description ("")
    let req = make_request(Method::POST, "/2015-03-31/functions/vfn/versions", "{}");
    let resp = svc.handle(req).await.unwrap();
    let v1: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
    assert_eq!(v1["Version"], "1");
    assert!(v1["FunctionArn"].as_str().unwrap().ends_with(":1"));
    assert_eq!(
        v1["MasterArn"].as_str().unwrap(),
        "arn:aws:lambda:us-east-1:123456789012:function:vfn"
    );

    // Mutate $LATEST description via UpdateFunctionConfiguration
    let body = json!({ "Description": "after-v1" });
    let req = make_request(
        Method::PUT,
        "/2015-03-31/functions/vfn/configuration",
        &body.to_string(),
    );
    svc.handle(req).await.unwrap();

    // Publish v2 with the new Description
    let req = make_request(Method::POST, "/2015-03-31/functions/vfn/versions", "{}");
    let resp = svc.handle(req).await.unwrap();
    let v2: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
    assert_eq!(v2["Version"], "2");
    assert_eq!(v2["Description"].as_str().unwrap(), "after-v1");

    // ListVersionsByFunction returns $LATEST + v1 + v2 with snapshots intact:
    // v1 keeps its old description even after $LATEST was mutated.
    let req = make_request(Method::GET, "/2015-03-31/functions/vfn/versions", "");
    let resp = svc.handle(req).await.unwrap();
    let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
    let versions = body["Versions"].as_array().unwrap();
    assert_eq!(versions.len(), 3);
    assert_eq!(versions[0]["Version"], "$LATEST");
    assert_eq!(versions[0]["Description"].as_str().unwrap(), "after-v1");
    assert_eq!(versions[1]["Version"], "1");
    assert_eq!(versions[1]["Description"].as_str().unwrap(), "");
    assert_eq!(versions[2]["Version"], "2");
    assert_eq!(versions[2]["Description"].as_str().unwrap(), "after-v1");
}

#[tokio::test]
async fn add_permission_builds_canonical_statement() {
    let svc = LambdaService::new(make_state());
    seed_function(&svc, "f").await;

    let body = json!({
        "StatementId": "s3-invoke",
        "Action": "InvokeFunction",
        "Principal": "s3.amazonaws.com",
        "SourceArn": "arn:aws:s3:::my-bucket",
        "SourceAccount": "123456789012",
    });
    let req = make_request(
        Method::POST,
        "/2015-03-31/functions/f/policy",
        &body.to_string(),
    );
    let resp = svc.handle(req).await.unwrap();
    assert_eq!(resp.status, StatusCode::CREATED);

    let out: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
    let statement: Value = serde_json::from_str(out["Statement"].as_str().unwrap()).unwrap();
    assert_eq!(statement["Sid"], "s3-invoke");
    assert_eq!(statement["Effect"], "Allow");
    assert_eq!(statement["Principal"]["Service"], "s3.amazonaws.com");
    assert_eq!(statement["Action"], "lambda:InvokeFunction");
    assert_eq!(
        statement["Resource"],
        "arn:aws:lambda:us-east-1:123456789012:function:f"
    );
    assert_eq!(
        statement["Condition"]["ArnLike"]["aws:SourceArn"],
        "arn:aws:s3:::my-bucket"
    );
    assert_eq!(
        statement["Condition"]["StringEquals"]["aws:SourceAccount"],
        "123456789012"
    );
}

#[tokio::test]
async fn add_permission_aws_principal_emits_aws_key() {
    let svc = LambdaService::new(make_state());
    seed_function(&svc, "f").await;

    let body = json!({
        "StatementId": "user-invoke",
        "Action": "InvokeFunction",
        "Principal": "arn:aws:iam::123456789012:user/alice",
    });
    let req = make_request(
        Method::POST,
        "/2015-03-31/functions/f/policy",
        &body.to_string(),
    );
    svc.handle(req).await.unwrap();

    // Fetch via GetPolicy and inspect the stored doc.
    let req = make_request(Method::GET, "/2015-03-31/functions/f/policy", "");
    let resp = svc.handle(req).await.unwrap();
    let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
    let doc: Value = serde_json::from_str(body["Policy"].as_str().unwrap()).unwrap();
    let statements = doc["Statement"].as_array().unwrap();
    assert_eq!(statements.len(), 1);
    assert_eq!(
        statements[0]["Principal"]["AWS"],
        "arn:aws:iam::123456789012:user/alice"
    );
    assert!(statements[0].get("Condition").is_none());
}

#[tokio::test]
async fn add_permission_rejects_duplicate_statement_id() {
    let svc = LambdaService::new(make_state());
    seed_function(&svc, "f").await;

    let body = json!({
        "StatementId": "dup",
        "Action": "InvokeFunction",
        "Principal": "arn:aws:iam::123456789012:user/a",
    });
    let req = make_request(
        Method::POST,
        "/2015-03-31/functions/f/policy",
        &body.to_string(),
    );
    svc.handle(req).await.unwrap();

    let req = make_request(
        Method::POST,
        "/2015-03-31/functions/f/policy",
        &body.to_string(),
    );
    let err = match svc.handle(req).await {
        Err(e) => e,
        Ok(_) => panic!("expected error"),
    };
    assert_eq!(err.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn get_policy_returns_404_when_no_policy_attached() {
    let svc = LambdaService::new(make_state());
    seed_function(&svc, "f").await;

    let req = make_request(Method::GET, "/2015-03-31/functions/f/policy", "");
    let err = match svc.handle(req).await {
        Err(e) => e,
        Ok(_) => panic!("expected error"),
    };
    assert_eq!(err.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn remove_permission_strips_matching_sid_and_leaves_empty_doc() {
    let svc = LambdaService::new(make_state());
    seed_function(&svc, "f").await;

    for sid in ["a", "b"] {
        let body = json!({
            "StatementId": sid,
            "Action": "InvokeFunction",
            "Principal": "arn:aws:iam::123456789012:user/u",
        });
        let req = make_request(
            Method::POST,
            "/2015-03-31/functions/f/policy",
            &body.to_string(),
        );
        svc.handle(req).await.unwrap();
    }

    // Remove "a"
    let req = make_request(Method::DELETE, "/2015-03-31/functions/f/policy/a", "");
    let resp = svc.handle(req).await.unwrap();
    assert_eq!(resp.status, StatusCode::NO_CONTENT);

    // GetPolicy still returns the doc with just "b".
    let req = make_request(Method::GET, "/2015-03-31/functions/f/policy", "");
    let resp = svc.handle(req).await.unwrap();
    let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
    let doc: Value = serde_json::from_str(body["Policy"].as_str().unwrap()).unwrap();
    let stmts = doc["Statement"].as_array().unwrap();
    assert_eq!(stmts.len(), 1);
    assert_eq!(stmts[0]["Sid"], "b");

    // Remove the last one — doc stays (empty Statement array).
    let req = make_request(Method::DELETE, "/2015-03-31/functions/f/policy/b", "");
    svc.handle(req).await.unwrap();

    let req = make_request(Method::GET, "/2015-03-31/functions/f/policy", "");
    let resp = svc.handle(req).await.unwrap();
    let body: Value = serde_json::from_slice(resp.body.expect_bytes()).unwrap();
    let doc: Value = serde_json::from_str(body["Policy"].as_str().unwrap()).unwrap();
    assert_eq!(doc["Statement"].as_array().unwrap().len(), 0);
}

#[tokio::test]
async fn remove_permission_unknown_sid_is_404() {
    let svc = LambdaService::new(make_state());
    seed_function(&svc, "f").await;

    let body = json!({
        "StatementId": "known",
        "Action": "InvokeFunction",
        "Principal": "arn:aws:iam::123456789012:user/u",
    });
    let req = make_request(
        Method::POST,
        "/2015-03-31/functions/f/policy",
        &body.to_string(),
    );
    svc.handle(req).await.unwrap();

    let req = make_request(Method::DELETE, "/2015-03-31/functions/f/policy/other", "");
    let err = match svc.handle(req).await {
        Err(e) => e,
        Ok(_) => panic!("expected error"),
    };
    assert_eq!(err.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn add_permission_on_missing_function_is_404() {
    let svc = LambdaService::new(make_state());
    let body = json!({
        "StatementId": "s",
        "Action": "InvokeFunction",
        "Principal": "arn:aws:iam::123456789012:user/u",
    });
    let req = make_request(
        Method::POST,
        "/2015-03-31/functions/missing/policy",
        &body.to_string(),
    );
    let err = match svc.handle(req).await {
        Err(e) => e,
        Ok(_) => panic!("expected error"),
    };
    assert_eq!(err.status(), StatusCode::NOT_FOUND);
}

#[test]
fn iam_action_for_maps_invoke_to_function_arn() {
    let svc = LambdaService::new(make_state());
    let req = make_request(Method::POST, "/2015-03-31/functions/f/invocations", "");
    let action = svc.iam_action_for(&req).unwrap();
    assert_eq!(action.service, "lambda");
    assert_eq!(action.action, "InvokeFunction");
    assert_eq!(
        action.resource,
        "arn:aws:lambda:us-east-1:123456789012:function:f"
    );
}

#[test]
fn iam_action_for_maps_list_to_star() {
    let svc = LambdaService::new(make_state());
    let req = make_request(Method::GET, "/2015-03-31/functions", "");
    let action = svc.iam_action_for(&req).unwrap();
    assert_eq!(action.action, "ListFunctions");
    assert_eq!(action.resource, "*");
}

#[test]
fn iam_action_for_create_reads_function_name_from_body() {
    let svc = LambdaService::new(make_state());
    let body = json!({
        "FunctionName": "newfn",
        "Runtime": "python3.12",
        "Role": "arn:aws:iam::123456789012:role/r",
        "Handler": "index.handler",
        "Code": {}
    });
    let req = make_request(Method::POST, "/2015-03-31/functions", &body.to_string());
    let action = svc.iam_action_for(&req).unwrap();
    assert_eq!(action.action, "CreateFunction");
    assert_eq!(
        action.resource,
        "arn:aws:lambda:us-east-1:123456789012:function:newfn"
    );
}

// ── Error branch tests ──

#[tokio::test]
async fn create_function_duplicate_returns_conflict() {
    let svc = LambdaService::new(make_state());
    seed_function(&svc, "dup-fn").await;

    let body = json!({
        "FunctionName": "dup-fn",
        "Runtime": "python3.12",
        "Role": "arn:aws:iam::123456789012:role/r",
        "Handler": "index.handler",
        "Code": {"ZipFile": "UEsDBBQ="},
    });
    let req = make_request(Method::POST, "/2015-03-31/functions", &body.to_string());
    let err = match svc.handle(req).await {
        Err(e) => e,
        Ok(_) => panic!("expected ResourceConflictException"),
    };
    assert_eq!(err.status(), StatusCode::CONFLICT);
}

#[tokio::test]
async fn get_function_not_found() {
    let svc = LambdaService::new(make_state());
    let req = make_request(Method::GET, "/2015-03-31/functions/nope", "");
    let err = match svc.handle(req).await {
        Err(e) => e,
        Ok(_) => panic!("expected error"),
    };
    assert_eq!(err.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_function_not_found() {
    let svc = LambdaService::new(make_state());
    let req = make_request(Method::DELETE, "/2015-03-31/functions/nope", "");
    let err = match svc.handle(req).await {
        Err(e) => e,
        Ok(_) => panic!("expected error"),
    };
    assert_eq!(err.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_event_source_mapping_not_found() {
    let svc = LambdaService::new(make_state());
    let req = make_request(
        Method::GET,
        "/2015-03-31/event-source-mappings/nonexistent",
        "",
    );
    let err = match svc.handle(req).await {
        Err(e) => e,
        Ok(_) => panic!("expected error"),
    };
    assert_eq!(err.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn delete_event_source_mapping_not_found() {
    let svc = LambdaService::new(make_state());
    let req = make_request(
        Method::DELETE,
        "/2015-03-31/event-source-mappings/nonexistent",
        "",
    );
    let err = match svc.handle(req).await {
        Err(e) => e,
        Ok(_) => panic!("expected error"),
    };
    assert_eq!(err.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn get_policy_on_missing_function() {
    let svc = LambdaService::new(make_state());
    let req = make_request(Method::GET, "/2015-03-31/functions/nope/policy", "");
    let err = match svc.handle(req).await {
        Err(e) => e,
        Ok(_) => panic!("expected error"),
    };
    assert_eq!(err.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn remove_permission_on_missing_function() {
    let svc = LambdaService::new(make_state());
    let req = make_request(
        Method::DELETE,
        "/2015-03-31/functions/nope/policy/stmt1",
        "",
    );
    let err = match svc.handle(req).await {
        Err(e) => e,
        Ok(_) => panic!("expected error"),
    };
    assert_eq!(err.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn publish_version_on_missing_function() {
    let svc = LambdaService::new(make_state());
    let req = make_request(Method::POST, "/2015-03-31/functions/nope/versions", "{}");
    let err = match svc.handle(req).await {
        Err(e) => e,
        Ok(_) => panic!("expected error"),
    };
    assert_eq!(err.status(), StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn unknown_route_returns_error() {
    let svc = LambdaService::new(make_state());
    let req = make_request(Method::POST, "/unknown/route", "{}");
    assert!(svc.handle(req).await.is_err());
}

#[tokio::test]
async fn publish_version_unknown_function_errors() {
    let svc = LambdaService::new(make_state());
    assert!(svc.publish_version("ghost", "123456789012").is_err());
}

#[tokio::test]
async fn get_function_unknown_errors() {
    let svc = LambdaService::new(make_state());
    assert!(svc
        .get_function("ghost", "123456789012", "us-east-1")
        .is_err());
}

#[tokio::test]
async fn delete_function_unknown_errors() {
    let svc = LambdaService::new(make_state());
    assert!(svc.delete_function("ghost", "123456789012").is_err());
}

#[tokio::test]
async fn get_event_source_mapping_unknown_errors() {
    let svc = LambdaService::new(make_state());
    assert!(svc
        .get_event_source_mapping("ghost", "123456789012")
        .is_err());
}

#[tokio::test]
async fn delete_event_source_mapping_unknown_errors() {
    let svc = LambdaService::new(make_state());
    assert!(svc
        .delete_event_source_mapping("ghost", "123456789012")
        .is_err());
}

#[tokio::test]
async fn list_functions_empty_ok() {
    let svc = LambdaService::new(make_state());
    let resp = svc.list_functions("123456789012").unwrap();
    assert_eq!(resp.status, http::StatusCode::OK);
}

#[tokio::test]
async fn list_event_source_mappings_empty_ok() {
    let svc = LambdaService::new(make_state());
    let resp = svc.list_event_source_mappings("123456789012").unwrap();
    assert_eq!(resp.status, http::StatusCode::OK);
}

#[tokio::test]
async fn invoke_returns_429_when_reserved_concurrency_is_zero() {
    // Reserved concurrency of 0 makes the function unavailable —
    // every invoke should bounce with `TooManyRequestsException`,
    // mirroring AWS's `ReservedFunctionConcurrentInvocationLimitExceeded`.
    let svc = LambdaService::new(make_state());
    seed_function(&svc, "throttled").await;

    let body = json!({"ReservedConcurrentExecutions": 0});
    let req = make_request(
        Method::PUT,
        "/2017-10-31/functions/throttled/concurrency",
        &body.to_string(),
    );
    svc.handle(req).await.unwrap();

    let req = make_request(
        Method::POST,
        "/2015-03-31/functions/throttled/invocations",
        "{}",
    );
    let err = match svc.handle(req).await {
        Err(e) => e,
        Ok(_) => panic!("expected 429 when reserved concurrency is exhausted"),
    };
    assert_eq!(err.status(), http::StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn invoke_inflight_counter_releases_on_completion() {
    // After an invoke errors out (no runtime configured), the
    // in-flight counter must be back to 0 — otherwise the next
    // invocation under a reserved cap of 1 would falsely 429.
    let svc = LambdaService::new(make_state());
    seed_function(&svc, "leak-check").await;

    let body = json!({"ReservedConcurrentExecutions": 1});
    let req = make_request(
        Method::PUT,
        "/2017-10-31/functions/leak-check/concurrency",
        &body.to_string(),
    );
    svc.handle(req).await.unwrap();

    // First invoke fails (no code package or no runtime), but the
    // guard must still drop. Second invoke should hit the same
    // failure path, NOT a 429.
    for _ in 0..2 {
        let req = make_request(
            Method::POST,
            "/2015-03-31/functions/leak-check/invocations",
            "{}",
        );
        let err = match svc.handle(req).await {
            Err(e) => e,
            Ok(_) => panic!("invoke should fail without runtime"),
        };
        assert_ne!(
            err.status(),
            http::StatusCode::TOO_MANY_REQUESTS,
            "second invoke unexpectedly throttled — counter leaked"
        );
    }
}

#[test]
fn resolve_qualifier_to_version_handles_latest_numeric_and_alias() {
    use crate::state::{FunctionAlias, LambdaState};

    let mut state = LambdaState::new("123456789012", "us-east-1");
    state.aliases.insert(
        "f:PROD".to_string(),
        FunctionAlias {
            alias_arn: "arn:aws:lambda:us-east-1:123456789012:function:f:PROD".to_string(),
            name: "PROD".to_string(),
            function_version: "3".to_string(),
            description: String::new(),
            revision_id: "rev".to_string(),
            routing_config: None,
        },
    );

    assert_eq!(
        crate::service::resolve_qualifier_to_version(&state, "f", None),
        None,
        "no qualifier means $LATEST"
    );
    assert_eq!(
        crate::service::resolve_qualifier_to_version(&state, "f", Some("$LATEST")),
        None
    );
    assert_eq!(
        crate::service::resolve_qualifier_to_version(&state, "f", Some("7")),
        Some("7".to_string()),
        "numeric qualifier passes through"
    );
    assert_eq!(
        crate::service::resolve_qualifier_to_version(&state, "f", Some("PROD")),
        Some("3".to_string()),
        "alias resolves to its primary function_version"
    );
    assert_eq!(
        crate::service::resolve_qualifier_to_version(&state, "f", Some("nope")),
        None,
        "unknown alias returns None"
    );
}

#[test]
fn resolve_qualifier_to_version_weighted_routing_picks_among_versions() {
    use crate::state::{FunctionAlias, LambdaState};

    let mut state = LambdaState::new("123456789012", "us-east-1");
    state.aliases.insert(
        "f:CANARY".to_string(),
        FunctionAlias {
            alias_arn: "arn:aws:lambda:us-east-1:123456789012:function:f:CANARY".to_string(),
            name: "CANARY".to_string(),
            function_version: "1".to_string(),
            description: String::new(),
            revision_id: "rev".to_string(),
            routing_config: Some(json!({
                "AdditionalVersionWeights": {"2": 0.5}
            })),
        },
    );

    // Primary "1" gets 0.5 weight, "2" gets 0.5. Over many picks
    // each must appear at least once.
    let mut saw_one = false;
    let mut saw_two = false;
    for _ in 0..50 {
        std::thread::sleep(std::time::Duration::from_millis(1));
        match crate::service::resolve_qualifier_to_version(&state, "f", Some("CANARY")).as_deref() {
            Some("1") => saw_one = true,
            Some("2") => saw_two = true,
            other => panic!("unexpected pick: {other:?}"),
        }
    }
    assert!(saw_one, "weighted pick never selected primary version");
    assert!(saw_two, "weighted pick never selected additional version");
}
