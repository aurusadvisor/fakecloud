//! Introspection endpoints for S3 (access points + Object Lambda).

mod helpers;

use helpers::TestServer;

#[tokio::test]
async fn access_points_introspection_lists_created_access_points() {
    let server = TestServer::start().await;
    let s3 = server.s3_client().await;

    s3.create_bucket()
        .bucket("intro-ap-bucket")
        .send()
        .await
        .unwrap();

    let endpoint = server.endpoint();
    let http = reqwest::Client::new();
    let port = server.port();
    let control_host = format!(
        "000000000000.s3-control.us-east-1.localhost.localstack.cloud:{}",
        port
    );

    let create_resp = http
        .put(format!("{}/v20180820/accesspoint/intro-ap", endpoint))
        .header("Host", &control_host)
        .header("Content-Type", "application/xml")
        .body(
            "<CreateAccessPointConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Bucket>intro-ap-bucket</Bucket>\
             </CreateAccessPointConfiguration>",
        )
        .send()
        .await
        .unwrap();
    assert!(create_resp.status().is_success());

    let resp: serde_json::Value =
        reqwest::get(format!("{}/_fakecloud/s3/access-points", server.endpoint()))
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
    let arr = resp["accessPoints"].as_array().expect("accessPoints array");
    let entry = arr
        .iter()
        .find(|e| e["name"] == "intro-ap")
        .expect("created access point present");
    assert_eq!(entry["bucket"], "intro-ap-bucket");
    assert_eq!(entry["accountId"], "000000000000");
    assert_eq!(entry["networkOrigin"], "Internet");
    assert_eq!(entry["alias"], "intro-ap-000000000000");
    assert!(entry["createdAt"].is_string());
}

#[tokio::test]
async fn object_lambda_responses_introspection_captures_write_get_object_response() {
    let server = TestServer::start().await;

    let endpoint = server.endpoint();
    let http = reqwest::Client::new();
    let port = server.port();
    // WriteGetObjectResponse uses the s3-object-lambda Host header.
    let host = format!(
        "s3-object-lambda.us-east-1.localhost.localstack.cloud:{}",
        port
    );

    let body = "hello-from-lambda";
    let resp = http
        .post(format!("{}/WriteGetObjectResponse", endpoint))
        .header("Host", &host)
        .header("x-amz-request-route", "intro-route")
        .header("x-amz-request-token", "intro-token")
        .header("x-amz-fwd-status", "200")
        .header("x-amz-fwd-header-Content-Type", "text/plain")
        .header("x-amz-meta-source", "intro-test")
        .body(body)
        .send()
        .await
        .unwrap();
    assert!(
        resp.status().is_success(),
        "WriteGetObjectResponse failed: {}",
        resp.text().await.unwrap_or_default()
    );

    let resp: serde_json::Value = reqwest::get(format!(
        "{}/_fakecloud/s3/object-lambda-responses",
        server.endpoint()
    ))
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let arr = resp["responses"].as_array().expect("responses array");
    let entry = arr
        .iter()
        .find(|e| e["requestToken"] == "intro-token")
        .expect("stored response present");
    assert_eq!(entry["requestRoute"], "intro-route");
    assert_eq!(entry["statusCode"], 200);
    assert_eq!(entry["contentType"], "text/plain");
    assert_eq!(entry["bodySize"], body.len() as u64);
    use base64::Engine as _;
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(entry["bodyBase64"].as_str().unwrap())
        .unwrap();
    assert_eq!(decoded, body.as_bytes());
    assert_eq!(entry["metadata"]["source"], "intro-test");
}
