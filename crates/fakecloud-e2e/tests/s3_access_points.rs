mod helpers;

use helpers::TestServer;

#[tokio::test]
async fn s3_access_point_control_plane_crud() {
    let server = TestServer::start().await;
    let s3 = server.s3_client().await;

    // Pre-create bucket.
    s3.create_bucket().bucket("ap-bucket").send().await.unwrap();

    let endpoint = server.endpoint();
    let http = reqwest::Client::new();
    let port = server.port();
    let control_host = format!(
        "000000000000.s3-control.us-east-1.localhost.localstack.cloud:{}",
        port
    );

    // Create access point.
    let create_resp = http
        .put(format!("{}/v20180820/accesspoint/my-ap", endpoint))
        .header("Host", &control_host)
        .header("Content-Type", "application/xml")
        .body(
            "<CreateAccessPointConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Bucket>ap-bucket</Bucket>\
             </CreateAccessPointConfiguration>",
        )
        .send()
        .await
        .unwrap();
    assert!(
        create_resp.status().is_success(),
        "create-access-point failed: {}",
        create_resp.text().await.unwrap_or_default()
    );

    // Get access point.
    let get_resp = http
        .get(format!("{}/v20180820/accesspoint/my-ap", endpoint))
        .header("Host", &control_host)
        .send()
        .await
        .unwrap();
    assert!(
        get_resp.status().is_success(),
        "get-access-point failed: {}",
        get_resp.text().await.unwrap_or_default()
    );
    let body = get_resp.text().await.unwrap();
    assert!(body.contains("my-ap"));
    assert!(body.contains("ap-bucket"));

    // List access points.
    let list_resp = http
        .get(format!("{}/v20180820/accesspoint", endpoint))
        .header("Host", &control_host)
        .send()
        .await
        .unwrap();
    assert!(
        list_resp.status().is_success(),
        "list-access-points failed: {}",
        list_resp.text().await.unwrap_or_default()
    );
    let body = list_resp.text().await.unwrap();
    assert!(body.contains("my-ap"));

    // Delete access point.
    let del_resp = http
        .delete(format!("{}/v20180820/accesspoint/my-ap", endpoint))
        .header("Host", &control_host)
        .send()
        .await
        .unwrap();
    assert!(del_resp.status().is_success());

    // Verify deleted.
    let list_resp = http
        .get(format!("{}/v20180820/accesspoint", endpoint))
        .header("Host", &control_host)
        .send()
        .await
        .unwrap();
    assert!(list_resp.status().is_success());
    let body = list_resp.text().await.unwrap();
    assert!(!body.contains("my-ap"));
}

#[tokio::test]
async fn s3_access_point_data_plane_put_get() {
    let server = TestServer::start().await;
    let s3 = server.s3_client().await;

    s3.create_bucket()
        .bucket("ap-data-bucket")
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
    let ap_host = format!(
        "data-ap-123456789012.s3-accesspoint.us-east-1.localhost.localstack.cloud:{}",
        port
    );

    // Create access point.
    let create_resp = http
        .put(format!("{}/v20180820/accesspoint/data-ap", endpoint))
        .header("Host", &control_host)
        .header("Content-Type", "application/xml")
        .body(
            "<CreateAccessPointConfiguration xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
             <Bucket>ap-data-bucket</Bucket>\
             </CreateAccessPointConfiguration>",
        )
        .send()
        .await
        .unwrap();
    assert!(
        create_resp.status().is_success(),
        "create-access-point failed: {}",
        create_resp.text().await.unwrap_or_default()
    );

    // Put object via access point endpoint (raw HTTP).
    // Fake SigV4 auth header so the streaming dispatch path recognizes
    // this as an S3 PUT and wires body_stream.
    let put_resp = http
        .put(format!("{}/hello.txt", endpoint))
        .header("Host", &ap_host)
        .header(
            "Authorization",
            "AWS4-HMAC-SHA256 Credential=AKID/20240101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc",
        )
        .body("world")
        .send()
        .await
        .unwrap();
    assert!(
        put_resp.status().is_success(),
        "put-object via AP failed: {}",
        put_resp.text().await.unwrap_or_default()
    );

    // Get object via access point endpoint.
    let get_resp = http
        .get(format!("{}/hello.txt", endpoint))
        .header("Host", &ap_host)
        .header(
            "Authorization",
            "AWS4-HMAC-SHA256 Credential=AKID/20240101/us-east-1/s3/aws4_request, SignedHeaders=host, Signature=abc",
        )
        .send()
        .await
        .unwrap();
    assert!(
        get_resp.status().is_success(),
        "get-object via AP failed: {}",
        get_resp.text().await.unwrap_or_default()
    );
    let body = get_resp.text().await.unwrap();
    assert_eq!(body, "world");
}
