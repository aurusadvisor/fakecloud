//! End-to-end coverage for the ELBv2 dataplane access-log /
//! connection-log -> S3 path.
//!
//! Sets `access_logs.s3.enabled = true` (and `connection_logs.s3.enabled
//! = true`) on a freshly-created ALB, drives one request through the
//! data plane, hits the introspection flush endpoint, and asserts the
//! configured S3 bucket now contains a gzipped log object.

mod helpers;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aws_sdk_elasticloadbalancingv2::types::{
    Action, ActionTypeEnum, LoadBalancerAttribute, ProtocolEnum, TargetDescription, TargetTypeEnum,
};
use helpers::TestServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

struct EchoTarget {
    addr: SocketAddr,
}

impl EchoTarget {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let code = Arc::new(AtomicU16::new(200));
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let code = code.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0u8; 8192];
                    let n = sock.read(&mut buf).await.unwrap_or(0);
                    let req = String::from_utf8_lossy(&buf[..n]);
                    let path = req
                        .lines()
                        .next()
                        .and_then(|l| l.split_whitespace().nth(1))
                        .unwrap_or("/")
                        .to_string();
                    let c = code.load(Ordering::SeqCst);
                    let body = format!("ECHO {path}");
                    let resp = format!(
                        "HTTP/1.1 {c} OK\r\n\
                         Content-Length: {len}\r\n\
                         Content-Type: text/plain\r\n\
                         Connection: close\r\n\r\n{body}",
                        len = body.len()
                    );
                    let _ = sock.write_all(resp.as_bytes()).await;
                });
            }
        });
        Self { addr }
    }
}

async fn wait_for_bound_port(server: &TestServer, lb_arn: &str, deadline: Duration) -> Option<u16> {
    let url = format!("{}/_fakecloud/elbv2/load-balancers", server.endpoint());
    let client = reqwest::Client::new();
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        if let Ok(r) = client.get(&url).send().await {
            if let Ok(v) = r.json::<serde_json::Value>().await {
                if let Some(arr) = v.get("loadBalancers").and_then(|x| x.as_array()) {
                    for lb in arr {
                        let arn = lb.get("arn").and_then(|x| x.as_str()).unwrap_or("");
                        if arn == lb_arn {
                            if let Some(p) = lb.get("boundPort").and_then(|x| x.as_u64()) {
                                return Some(p as u16);
                            }
                        }
                    }
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    None
}

async fn wait_for_target_healthy(
    elbv2: &aws_sdk_elasticloadbalancingv2::Client,
    tg_arn: &str,
    deadline: Duration,
) -> bool {
    let start = std::time::Instant::now();
    while start.elapsed() < deadline {
        let resp = elbv2
            .describe_target_health()
            .target_group_arn(tg_arn)
            .send()
            .await
            .unwrap();
        if let Some(d) = resp.target_health_descriptions().first() {
            if let Some(h) = d.target_health() {
                if h.state().map(|s| s.as_str()) == Some("healthy") {
                    return true;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    false
}

#[tokio::test]
async fn elbv2_dataplane_emits_access_log_to_s3_after_flush() {
    let server = TestServer::start().await;
    let elbv2 = server.elbv2_client().await;
    let s3 = server.s3_client().await;
    let target = EchoTarget::start().await;

    // 1. Create the destination bucket the LB will write its access
    //    logs into. The S3 service requires it to exist before the
    //    delivery hook can write objects (otherwise put_object
    //    returns NoSuchBucket).
    s3.create_bucket()
        .bucket("alb-access-logs")
        .send()
        .await
        .unwrap();

    // 2. Create the ALB.
    let lb = elbv2
        .create_load_balancer()
        .name("dp-log-lb")
        .scheme(aws_sdk_elasticloadbalancingv2::types::LoadBalancerSchemeEnum::Internal)
        .send()
        .await
        .unwrap();
    let lb_arn = lb
        .load_balancers()
        .first()
        .unwrap()
        .load_balancer_arn()
        .unwrap()
        .to_string();

    // 3. Turn on access + connection logs pointing at our bucket.
    elbv2
        .modify_load_balancer_attributes()
        .load_balancer_arn(&lb_arn)
        .attributes(
            LoadBalancerAttribute::builder()
                .key("access_logs.s3.enabled")
                .value("true")
                .build(),
        )
        .attributes(
            LoadBalancerAttribute::builder()
                .key("access_logs.s3.bucket")
                .value("alb-access-logs")
                .build(),
        )
        .attributes(
            LoadBalancerAttribute::builder()
                .key("access_logs.s3.prefix")
                .value("alb")
                .build(),
        )
        .attributes(
            LoadBalancerAttribute::builder()
                .key("connection_logs.s3.enabled")
                .value("true")
                .build(),
        )
        .attributes(
            LoadBalancerAttribute::builder()
                .key("connection_logs.s3.bucket")
                .value("alb-access-logs")
                .build(),
        )
        .send()
        .await
        .unwrap();

    // 4. Target group + register echo target.
    let tg = elbv2
        .create_target_group()
        .name("dp-log-tg")
        .protocol(ProtocolEnum::Http)
        .port(80)
        .target_type(TargetTypeEnum::Ip)
        .health_check_protocol(ProtocolEnum::Http)
        .health_check_path("/")
        .health_check_interval_seconds(1)
        .health_check_timeout_seconds(2)
        .healthy_threshold_count(1)
        .unhealthy_threshold_count(2)
        .send()
        .await
        .unwrap();
    let tg_arn = tg
        .target_groups()
        .first()
        .unwrap()
        .target_group_arn()
        .unwrap()
        .to_string();
    elbv2
        .register_targets()
        .target_group_arn(&tg_arn)
        .targets(
            TargetDescription::builder()
                .id(target.addr.ip().to_string())
                .port(target.addr.port() as i32)
                .build(),
        )
        .send()
        .await
        .unwrap();
    elbv2
        .create_listener()
        .load_balancer_arn(&lb_arn)
        .protocol(ProtocolEnum::Http)
        .port(80)
        .default_actions(
            Action::builder()
                .r#type(ActionTypeEnum::Forward)
                .target_group_arn(&tg_arn)
                .build(),
        )
        .send()
        .await
        .unwrap();

    // 5. Wait for the supervisor to bind a port and the target to
    //    transition to healthy.
    let port = wait_for_bound_port(&server, &lb_arn, Duration::from_secs(8))
        .await
        .expect("data plane should bind a port for the active LB");
    assert!(
        wait_for_target_healthy(&elbv2, &tg_arn, Duration::from_secs(10)).await,
        "target should reach healthy state"
    );

    // 6. Drive one request through the dataplane.
    let resp = reqwest::Client::new()
        .get(format!("http://127.0.0.1:{port}/log/me/please"))
        .header("user-agent", "elbv2-access-log-test/1.0")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status().as_u16(), 200);

    // 7. Drop the client so its TCP connection closes — that's what
    //    the dataplane's accept_loop watches for to emit the
    //    connection-log entry. Then sleep briefly so the spawn task
    //    has a chance to record into the buffer before we flush.
    drop(resp);
    tokio::time::sleep(Duration::from_millis(300)).await;
    // Trigger the periodic flusher synchronously via the
    // introspection endpoint so the test doesn't have to wait for
    // the 60s tick.
    let flush_url = format!("{}/_fakecloud/elbv2/access-logs/flush", server.endpoint());
    let flush_resp = reqwest::Client::new()
        .post(&flush_url)
        .send()
        .await
        .unwrap();
    assert!(
        flush_resp.status().is_success(),
        "flush endpoint should succeed, got {}",
        flush_resp.status()
    );

    // 8. The destination bucket should now contain at least one
    //    `*.log.gz` object whose body, when decoded, contains the
    //    request line we just sent.
    let listed = s3
        .list_objects_v2()
        .bucket("alb-access-logs")
        .send()
        .await
        .unwrap();
    let access_obj = listed
        .contents()
        .iter()
        .find(|o| {
            o.key()
                .map(|k| {
                    k.starts_with("alb/AWSLogs/") && k.ends_with(".log.gz") && !k.contains("_conn_")
                })
                .unwrap_or(false)
        })
        .expect("expected one access-log object under alb/AWSLogs/...");
    let key = access_obj.key().unwrap().to_string();
    let body_resp = s3
        .get_object()
        .bucket("alb-access-logs")
        .key(&key)
        .send()
        .await
        .unwrap();
    let body_bytes = body_resp.body.collect().await.unwrap().into_bytes();
    let decoded = helpers::gunzip(&body_bytes);
    let decoded_str = String::from_utf8_lossy(&decoded);
    assert!(
        decoded_str.contains("/log/me/please"),
        "decoded body should contain request URL, got: {decoded_str}"
    );
    assert!(
        decoded_str.contains("\"elbv2-access-log-test/1.0\""),
        "decoded body should contain user-agent, got: {decoded_str}"
    );
    // Connection log should also have shipped.
    let conn_obj = listed
        .contents()
        .iter()
        .find(|o| o.key().map(|k| k.contains("_conn_")).unwrap_or(false));
    assert!(
        conn_obj.is_some(),
        "expected at least one connection-log object (key with _conn_)"
    );
    // Decode the connection log and assert exactly one record was
    // emitted for the request. This guards against the regression
    // where keep-alive connections double-counted by emitting one
    // connection-log record per request instead of per connection.
    let conn_key = conn_obj.unwrap().key().unwrap().to_string();
    let conn_body = s3
        .get_object()
        .bucket("alb-access-logs")
        .key(&conn_key)
        .send()
        .await
        .unwrap()
        .body
        .collect()
        .await
        .unwrap()
        .into_bytes();
    let conn_decoded = helpers::gunzip(&conn_body);
    let conn_text = String::from_utf8_lossy(&conn_decoded);
    let line_count = conn_text.lines().filter(|l| !l.is_empty()).count();
    assert_eq!(
        line_count, 1,
        "exactly one connection-log entry expected per established connection, got {line_count}: {conn_text}"
    );
}
