mod helpers;

use std::io::Write;

use aws_sdk_lambda::primitives::Blob;
use helpers::TestServer;

fn make_python_zip() -> Vec<u8> {
    let buf = Vec::new();
    let cursor = std::io::Cursor::new(buf);
    let mut writer = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default();
    writer.start_file("index.py", options).unwrap();
    writer
        .write_all(b"def handler(event, context):\n    return {\"statusCode\": 200}\n")
        .unwrap();
    let cursor = writer.finish().unwrap();
    cursor.into_inner()
}

#[tokio::test]
async fn lambda_create_get_delete_function() {
    let server = TestServer::start().await;
    let client = server.lambda_client().await;

    // Create
    let resp = client
        .create_function()
        .function_name("my-func")
        .runtime(aws_sdk_lambda::types::Runtime::Python312)
        .role("arn:aws:iam::123456789012:role/test-role")
        .handler("index.handler")
        .code(
            aws_sdk_lambda::types::FunctionCode::builder()
                .zip_file(Blob::new(make_python_zip()))
                .build(),
        )
        .send()
        .await
        .unwrap();

    assert_eq!(resp.function_name().unwrap(), "my-func");
    assert!(resp.function_arn().unwrap().contains("function:my-func"));

    // Get
    let resp = client
        .get_function()
        .function_name("my-func")
        .send()
        .await
        .unwrap();
    let config = resp.configuration().unwrap();
    assert_eq!(config.function_name().unwrap(), "my-func");
    assert_eq!(config.runtime().unwrap().as_str(), "python3.12");
    assert_eq!(config.handler().unwrap(), "index.handler");

    // Delete
    client
        .delete_function()
        .function_name("my-func")
        .send()
        .await
        .unwrap();

    // Verify deleted
    let result = client.get_function().function_name("my-func").send().await;
    assert!(result.is_err());
}

#[tokio::test]
async fn lambda_get_function_accepts_arn_partial_arn_and_qualifier() {
    let server = TestServer::start().await;
    let client = server.lambda_client().await;

    client
        .create_function()
        .function_name("arn-target")
        .runtime(aws_sdk_lambda::types::Runtime::Python312)
        .role("arn:aws:iam::123456789012:role/test-role")
        .handler("index.handler")
        .code(
            aws_sdk_lambda::types::FunctionCode::builder()
                .zip_file(Blob::new(make_python_zip()))
                .build(),
        )
        .send()
        .await
        .unwrap();

    // Full ARN — what the VS Code AWS Toolkit sends.
    let resp = client
        .get_function()
        .function_name("arn:aws:lambda:us-east-1:123456789012:function:arn-target")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.configuration().unwrap().function_name().unwrap(),
        "arn-target"
    );

    // Partial ARN.
    let resp = client
        .get_function()
        .function_name("123456789012:function:arn-target")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.configuration().unwrap().function_name().unwrap(),
        "arn-target"
    );

    // Bare name with version qualifier.
    let resp = client
        .get_function()
        .function_name("arn-target:1")
        .send()
        .await
        .unwrap();
    assert_eq!(
        resp.configuration().unwrap().function_name().unwrap(),
        "arn-target"
    );
}

#[tokio::test]
async fn lambda_list_functions() {
    let server = TestServer::start().await;
    let client = server.lambda_client().await;

    for name in &["func-a", "func-b", "func-c"] {
        client
            .create_function()
            .function_name(*name)
            .runtime(aws_sdk_lambda::types::Runtime::Nodejs20x)
            .role("arn:aws:iam::123456789012:role/test-role")
            .handler("index.handler")
            .code(
                aws_sdk_lambda::types::FunctionCode::builder()
                    .zip_file(Blob::new(make_python_zip()))
                    .build(),
            )
            .send()
            .await
            .unwrap();
    }

    let resp = client.list_functions().send().await.unwrap();
    assert_eq!(resp.functions().len(), 3);
}

async fn invoke_with_cli(cli: &str) {
    let available = std::process::Command::new(cli)
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false);

    if !available {
        if std::env::var("CI").is_ok() {
            panic!("{cli} is not available but is required in CI");
        }
        eprintln!("skipping: {cli} is not available");
        return;
    }

    let server = TestServer::start_with_env(&[("FAKECLOUD_CONTAINER_CLI", cli)]).await;
    let client = server.lambda_client().await;

    client
        .create_function()
        .function_name("invoke-me")
        .runtime(aws_sdk_lambda::types::Runtime::Python312)
        .role("arn:aws:iam::123456789012:role/test-role")
        .handler("index.handler")
        .code(
            aws_sdk_lambda::types::FunctionCode::builder()
                .zip_file(Blob::new(make_python_zip()))
                .build(),
        )
        .send()
        .await
        .unwrap();

    let resp = client
        .invoke()
        .function_name("invoke-me")
        .payload(Blob::new(br#"{"key": "value"}"#))
        .send()
        .await
        .unwrap();

    assert_eq!(resp.status_code(), 200);
    let body: serde_json::Value = serde_json::from_slice(resp.payload().unwrap().as_ref()).unwrap();
    assert_eq!(body["statusCode"], 200);
}

#[tokio::test]
async fn lambda_invoke_docker() {
    invoke_with_cli("docker").await;
}

#[tokio::test]
async fn lambda_invoke_podman() {
    invoke_with_cli("podman").await;
}

#[tokio::test]
async fn lambda_create_function_conflict() {
    let server = TestServer::start().await;
    let client = server.lambda_client().await;

    client
        .create_function()
        .function_name("dup-func")
        .runtime(aws_sdk_lambda::types::Runtime::Python312)
        .role("arn:aws:iam::123456789012:role/test-role")
        .handler("index.handler")
        .code(
            aws_sdk_lambda::types::FunctionCode::builder()
                .zip_file(Blob::new(make_python_zip()))
                .build(),
        )
        .send()
        .await
        .unwrap();

    // Creating again should fail
    let result = client
        .create_function()
        .function_name("dup-func")
        .runtime(aws_sdk_lambda::types::Runtime::Python312)
        .role("arn:aws:iam::123456789012:role/test-role")
        .handler("index.handler")
        .code(
            aws_sdk_lambda::types::FunctionCode::builder()
                .zip_file(Blob::new(make_python_zip()))
                .build(),
        )
        .send()
        .await;
    assert!(result.is_err());
}

#[tokio::test]
async fn lambda_add_get_remove_permission_roundtrip() {
    // Drives AddPermission / GetPolicy / RemovePermission through
    // aws-sdk-lambda against the real fakecloud binary — verifies the
    // canonical-policy-doc round trip we rely on in the IAM evaluator
    // path. FAKECLOUD_IAM is off for this test; it only exercises the
    // handler shape, not enforcement.
    let server = TestServer::start().await;
    let client = server.lambda_client().await;

    client
        .create_function()
        .function_name("perm-fn")
        .runtime(aws_sdk_lambda::types::Runtime::Python312)
        .role("arn:aws:iam::123456789012:role/test-role")
        .handler("index.handler")
        .code(
            aws_sdk_lambda::types::FunctionCode::builder()
                .zip_file(Blob::new(make_python_zip()))
                .build(),
        )
        .send()
        .await
        .unwrap();

    // GetPolicy on a function with no resource policy -> ResourceNotFoundException.
    let missing = client.get_policy().function_name("perm-fn").send().await;
    assert!(
        missing.is_err(),
        "GetPolicy on unpolicied function should 404"
    );

    // AddPermission for EventBridge with SourceArn + SourceAccount.
    let add_resp = client
        .add_permission()
        .function_name("perm-fn")
        .statement_id("events-invoke")
        .action("InvokeFunction")
        .principal("events.amazonaws.com")
        .source_arn("arn:aws:events:us-east-1:123456789012:rule/my-rule")
        .source_account("123456789012")
        .send()
        .await
        .unwrap();
    let statement_str = add_resp.statement().unwrap();
    let statement: serde_json::Value = serde_json::from_str(statement_str).unwrap();
    assert_eq!(statement["Sid"], "events-invoke");
    assert_eq!(statement["Principal"]["Service"], "events.amazonaws.com");
    // Action is stored verbatim — caller passed `InvokeFunction`, so
    // the round-trip preserves that, matching real AWS behavior.
    assert_eq!(statement["Action"], "InvokeFunction");
    assert_eq!(
        statement["Condition"]["ArnLike"]["aws:SourceArn"],
        "arn:aws:events:us-east-1:123456789012:rule/my-rule"
    );

    // Add a second statement so RemovePermission has something to
    // leave behind after it strips the first one.
    client
        .add_permission()
        .function_name("perm-fn")
        .statement_id("s3-invoke")
        .action("InvokeFunction")
        .principal("s3.amazonaws.com")
        .send()
        .await
        .unwrap();

    // GetPolicy returns the composed document with both statements.
    let got = client
        .get_policy()
        .function_name("perm-fn")
        .send()
        .await
        .unwrap();
    let doc: serde_json::Value = serde_json::from_str(got.policy().unwrap()).unwrap();
    let statements = doc["Statement"].as_array().unwrap();
    assert_eq!(statements.len(), 2);
    let ids: Vec<&str> = statements
        .iter()
        .map(|s| s["Sid"].as_str().unwrap())
        .collect();
    assert!(ids.contains(&"events-invoke"));
    assert!(ids.contains(&"s3-invoke"));

    // RemovePermission strips only the named statement.
    client
        .remove_permission()
        .function_name("perm-fn")
        .statement_id("events-invoke")
        .send()
        .await
        .unwrap();

    let got = client
        .get_policy()
        .function_name("perm-fn")
        .send()
        .await
        .unwrap();
    let doc: serde_json::Value = serde_json::from_str(got.policy().unwrap()).unwrap();
    let statements = doc["Statement"].as_array().unwrap();
    assert_eq!(statements.len(), 1);
    assert_eq!(statements[0]["Sid"], "s3-invoke");

    // Removing a non-existent statement id is a 404.
    let err = client
        .remove_permission()
        .function_name("perm-fn")
        .statement_id("nope")
        .send()
        .await;
    assert!(err.is_err());
}

fn make_python_zip_returning(payload: &str) -> Vec<u8> {
    // A second-flavor zip whose handler returns a payload-derived value,
    // so callers can confirm UpdateFunctionCode actually swapped the code
    // bundle (rather than just the metadata).
    let buf = Vec::new();
    let cursor = std::io::Cursor::new(buf);
    let mut writer = zip::ZipWriter::new(cursor);
    let options = zip::write::SimpleFileOptions::default();
    writer.start_file("index.py", options).unwrap();
    writer
        .write_all(
            format!("def handler(event, context):\n    return {{\"payload\": \"{payload}\"}}\n")
                .as_bytes(),
        )
        .unwrap();
    let cursor = writer.finish().unwrap();
    cursor.into_inner()
}

#[tokio::test]
async fn lambda_update_function_code_replaces_zip_and_recomputes_hash() {
    // Fresh zip -> CodeSha256 + CodeSize must move; same zip again ->
    // RevisionId stays put. GetFunctionConfiguration round-trips the new
    // hash, proving the update persisted in state and not just the
    // immediate response.
    let server = TestServer::start().await;
    let client = server.lambda_client().await;

    let initial_zip = make_python_zip();
    client
        .create_function()
        .function_name("upd-code")
        .runtime(aws_sdk_lambda::types::Runtime::Python312)
        .role("arn:aws:iam::123456789012:role/r")
        .handler("index.handler")
        .code(
            aws_sdk_lambda::types::FunctionCode::builder()
                .zip_file(Blob::new(initial_zip.clone()))
                .build(),
        )
        .send()
        .await
        .unwrap();

    let pre = client
        .get_function_configuration()
        .function_name("upd-code")
        .send()
        .await
        .unwrap();
    let pre_sha = pre.code_sha256().unwrap().to_string();
    let pre_rev = pre.revision_id().unwrap().to_string();
    let pre_size = pre.code_size();
    assert_eq!(pre_size, initial_zip.len() as i64);

    // Replace with a different zip -- CodeSha256 + CodeSize must change,
    // RevisionId must rotate.
    let new_zip = make_python_zip_returning("v2");
    let updated = client
        .update_function_code()
        .function_name("upd-code")
        .zip_file(Blob::new(new_zip.clone()))
        .send()
        .await
        .unwrap();
    let post_sha = updated.code_sha256().unwrap().to_string();
    let post_rev = updated.revision_id().unwrap().to_string();
    assert_ne!(post_sha, pre_sha, "CodeSha256 should change");
    assert_ne!(post_rev, pre_rev, "RevisionId should rotate on real change");
    assert_eq!(updated.code_size(), new_zip.len() as i64);

    // Persisted in state.
    let cfg = client
        .get_function_configuration()
        .function_name("upd-code")
        .send()
        .await
        .unwrap();
    assert_eq!(cfg.code_sha256().unwrap(), post_sha);
    assert_eq!(cfg.code_size(), new_zip.len() as i64);

    // Same bytes again -> RevisionId must stay put.
    let same = client
        .update_function_code()
        .function_name("upd-code")
        .zip_file(Blob::new(new_zip.clone()))
        .send()
        .await
        .unwrap();
    assert_eq!(same.revision_id().unwrap(), post_rev);
    assert_eq!(same.code_sha256().unwrap(), post_sha);
}

#[tokio::test]
async fn lambda_update_function_code_with_s3_descriptor_rotates_hash() {
    // S3Bucket+S3Key swap fingerprints the descriptor; a different
    // descriptor must rotate CodeSha256 / RevisionId, identical
    // descriptor must not.
    let server = TestServer::start().await;
    let client = server.lambda_client().await;

    client
        .create_function()
        .function_name("upd-s3")
        .runtime(aws_sdk_lambda::types::Runtime::Python312)
        .role("arn:aws:iam::123456789012:role/r")
        .handler("index.handler")
        .code(
            aws_sdk_lambda::types::FunctionCode::builder()
                .zip_file(Blob::new(make_python_zip()))
                .build(),
        )
        .send()
        .await
        .unwrap();

    let pre_sha = client
        .get_function_configuration()
        .function_name("upd-s3")
        .send()
        .await
        .unwrap()
        .code_sha256()
        .unwrap()
        .to_string();

    let updated = client
        .update_function_code()
        .function_name("upd-s3")
        .s3_bucket("deploy-bucket")
        .s3_key("lambdas/v2.zip")
        .send()
        .await
        .unwrap();
    let post_sha = updated.code_sha256().unwrap().to_string();
    assert_ne!(post_sha, pre_sha);

    // Adding S3ObjectVersion changes the descriptor, so the hash rotates.
    let versioned = client
        .update_function_code()
        .function_name("upd-s3")
        .s3_bucket("deploy-bucket")
        .s3_key("lambdas/v2.zip")
        .s3_object_version("ver-abc123")
        .send()
        .await
        .unwrap();
    assert_ne!(versioned.code_sha256().unwrap(), post_sha);
}

#[tokio::test]
async fn lambda_update_function_code_with_image_uri_clears_size_and_sha() {
    // Real AWS reports CodeSize=0 and an empty CodeSha256 for image
    // functions; verify UpdateFunctionCode lines those fields up when
    // swapping to a new image URI.
    let server = TestServer::start().await;
    let client = server.lambda_client().await;

    client
        .create_function()
        .function_name("upd-img")
        .runtime(aws_sdk_lambda::types::Runtime::Python312)
        .role("arn:aws:iam::123456789012:role/r")
        .handler("index.handler")
        .package_type(aws_sdk_lambda::types::PackageType::Image)
        .code(
            aws_sdk_lambda::types::FunctionCode::builder()
                .image_uri("old.example.com/image:1")
                .build(),
        )
        .send()
        .await
        .unwrap();

    let updated = client
        .update_function_code()
        .function_name("upd-img")
        .image_uri("new.example.com/image:2")
        .send()
        .await
        .unwrap();
    assert_eq!(updated.code_size(), 0);
    assert_eq!(updated.code_sha256().unwrap_or(""), "");
    assert_eq!(
        updated.package_type().unwrap(),
        &aws_sdk_lambda::types::PackageType::Image
    );
}
