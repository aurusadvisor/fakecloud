//! E2E tests for CloudFront Functions / ConnectionFunctions JavaScript
//! execution: TestFunction and TestConnectionFunction now run real
//! `function handler(event) { ... }` code via boa_engine, return the
//! JSON-encoded result in `FunctionOutput`, surface JS exceptions in
//! `FunctionErrorMessage`, and pick the right code per `Stage`.

#![allow(deprecated)]

mod helpers;

use aws_sdk_cloudfront::primitives::Blob;
use aws_sdk_cloudfront::types::{FunctionConfig, FunctionRuntime, FunctionStage};
use helpers::TestServer;

async fn create_fn(
    cf: &aws_sdk_cloudfront::Client,
    name: &str,
    code: &[u8],
) -> aws_sdk_cloudfront::operation::create_function::CreateFunctionOutput {
    cf.create_function()
        .name(name)
        .function_config(
            FunctionConfig::builder()
                .comment("e2e")
                .runtime(FunctionRuntime::CloudfrontJs20)
                .build()
                .unwrap(),
        )
        .function_code(Blob::new(code.to_vec()))
        .send()
        .await
        .expect("create_function")
}

async fn current_etag(cf: &aws_sdk_cloudfront::Client, name: &str) -> String {
    cf.describe_function()
        .name(name)
        .send()
        .await
        .expect("describe_function")
        .e_tag()
        .unwrap()
        .to_string()
}

#[tokio::test]
async fn test_function_echoes_request() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let create = create_fn(
        &cf,
        "e2e-tfn-echo",
        b"function handler(event) { return event.request; }",
    )
    .await;
    let etag = create.e_tag().unwrap().to_string();

    let event = br#"{"version":"1.0","context":{"distributionDomainName":"d1.cloudfront.net","requestId":"abc","eventType":"viewer-request"},"viewer":{"ip":"203.0.113.1"},"request":{"method":"GET","uri":"/index.html","querystring":{},"headers":{"host":{"value":"example.com"}},"cookies":{}}}"#;

    let res = cf
        .test_function()
        .name("e2e-tfn-echo")
        .if_match(&etag)
        .stage(FunctionStage::Development)
        .event_object(Blob::new(event.to_vec()))
        .send()
        .await
        .expect("test_function");
    let r = res.test_result().expect("test_result");
    let out = r.function_output().expect("function_output");
    assert!(
        r.function_error_message().unwrap_or("").is_empty(),
        "unexpected error: {:?}",
        r.function_error_message()
    );
    // Echoed request preserves method + uri + the host header we put in.
    assert!(out.contains("\"method\":\"GET\""), "got {out}");
    assert!(out.contains("\"uri\":\"/index.html\""), "got {out}");
    assert!(out.contains("\"host\""), "got {out}");
    assert!(out.contains("example.com"), "got {out}");
}

#[tokio::test]
async fn test_function_mutates_request_headers() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let create = create_fn(
        &cf,
        "e2e-tfn-headers",
        br#"function handler(event) {
            event.request.headers["custom-header"] = {value: "x"};
            return event.request;
        }"#,
    )
    .await;
    let etag = create.e_tag().unwrap().to_string();

    let event = br#"{"version":"1.0","context":{},"viewer":{},"request":{"method":"GET","uri":"/","querystring":{},"headers":{},"cookies":{}}}"#;
    let res = cf
        .test_function()
        .name("e2e-tfn-headers")
        .if_match(&etag)
        .stage(FunctionStage::Development)
        .event_object(Blob::new(event.to_vec()))
        .send()
        .await
        .expect("test_function");
    let r = res.test_result().expect("test_result");
    assert!(
        r.function_error_message().unwrap_or("").is_empty(),
        "unexpected error: {:?}",
        r.function_error_message()
    );
    let out = r.function_output().expect("function_output");
    assert!(out.contains("custom-header"), "got {out}");
    assert!(out.contains("\"value\":\"x\""), "got {out}");
}

#[tokio::test]
async fn test_function_throw_populates_error_message() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;
    let create = create_fn(
        &cf,
        "e2e-tfn-throw",
        b"function handler() { throw new Error('boom'); }",
    )
    .await;
    let etag = create.e_tag().unwrap().to_string();

    let res = cf
        .test_function()
        .name("e2e-tfn-throw")
        .if_match(&etag)
        .stage(FunctionStage::Development)
        .event_object(Blob::new(b"{}".to_vec()))
        .send()
        .await
        .expect("test_function");
    let r = res.test_result().expect("test_result");
    let err = r.function_error_message().unwrap_or("");
    assert!(!err.is_empty(), "expected non-empty error message");
    assert!(err.contains("boom"), "expected boom in {err}");
    // Output is empty on error.
    assert_eq!(r.function_output().unwrap_or(""), "");
    // Logs include the synthetic ERROR line.
    assert!(
        r.function_execution_logs()
            .iter()
            .any(|l| l.contains("ERROR") && l.contains("boom")),
        "expected error log line in {:?}",
        r.function_execution_logs()
    );
}

#[tokio::test]
async fn test_function_stage_picks_published_or_development_code() {
    let server = TestServer::start().await;
    let cf = server.cloudfront_client().await;

    // v1 is the code we publish; v2 is the post-publish update that
    // only DEVELOPMENT should observe.
    let create = create_fn(&cf, "e2e-tfn-stage", b"function handler() { return 'v1'; }").await;
    let etag = create.e_tag().unwrap().to_string();

    cf.publish_function()
        .name("e2e-tfn-stage")
        .if_match(&etag)
        .send()
        .await
        .expect("publish");
    // PublishFunctionOutput doesn't surface the post-publish ETag; pull
    // it back via DescribeFunction for the subsequent UpdateFunction.
    let pub_etag = current_etag(&cf, "e2e-tfn-stage").await;

    let cfg = FunctionConfig::builder()
        .comment("e2e")
        .runtime(FunctionRuntime::CloudfrontJs20)
        .build()
        .unwrap();
    cf.update_function()
        .name("e2e-tfn-stage")
        .if_match(&pub_etag)
        .function_config(cfg)
        .function_code(Blob::new(b"function handler() { return 'v2'; }".to_vec()))
        .send()
        .await
        .expect("update_function");

    let live_etag = current_etag(&cf, "e2e-tfn-stage").await;

    // DEVELOPMENT runs v2 (the post-publish body).
    let dev = cf
        .test_function()
        .name("e2e-tfn-stage")
        .if_match(&live_etag)
        .stage(FunctionStage::Development)
        .event_object(Blob::new(b"{}".to_vec()))
        .send()
        .await
        .expect("test_function dev");
    let dev_out = dev
        .test_result()
        .and_then(|r| r.function_output())
        .unwrap_or("");
    assert!(
        dev_out.contains("v2"),
        "DEVELOPMENT should run v2: {dev_out}"
    );

    // LIVE runs v1 (the snapshot frozen at publish time, immune to
    // subsequent UpdateFunction).
    let live = cf
        .test_function()
        .name("e2e-tfn-stage")
        .if_match(&live_etag)
        .stage(FunctionStage::Live)
        .event_object(Blob::new(b"{}".to_vec()))
        .send()
        .await
        .expect("test_function live");
    let live_out = live
        .test_result()
        .and_then(|r| r.function_output())
        .unwrap_or("");
    assert!(
        live_out.contains("v1"),
        "LIVE should run v1 snapshot: {live_out}"
    );
}
