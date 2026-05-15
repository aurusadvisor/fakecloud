mod helpers;

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::Arc;
use std::time::Duration;

use aws_sdk_elasticloadbalancingv2::types::{TargetDescription, TargetTypeEnum};
use helpers::TestServer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Tiny HTTP server whose response code is configurable at runtime.
/// Listens on 127.0.0.1, returns the current `code` for every GET.
struct TestTarget {
    addr: SocketAddr,
    code: Arc<AtomicU16>,
}

impl TestTarget {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let code = Arc::new(AtomicU16::new(200));
        let code_for_task = code.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut sock, _)) = listener.accept().await else {
                    return;
                };
                let code = code_for_task.clone();
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let _ = sock.read(&mut buf).await;
                    let c = code.load(Ordering::SeqCst);
                    let body = format!(
                        "HTTP/1.1 {c} OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                    );
                    let _ = sock.write_all(body.as_bytes()).await;
                });
            }
        });
        Self { addr, code }
    }

    fn set_code(&self, c: u16) {
        self.code.store(c, Ordering::SeqCst);
    }
}

#[tokio::test]
async fn elbv2_prober_marks_target_healthy_then_unhealthy() {
    let server = TestServer::start().await;
    let elbv2 = server.elbv2_client().await;
    let target = TestTarget::start().await;

    let lb = elbv2
        .create_load_balancer()
        .name("hb-lb")
        .scheme(aws_sdk_elasticloadbalancingv2::types::LoadBalancerSchemeEnum::Internal)
        .send()
        .await
        .unwrap();
    let _lb_arn = lb
        .load_balancers()
        .first()
        .unwrap()
        .load_balancer_arn()
        .unwrap()
        .to_string();

    let tg = elbv2
        .create_target_group()
        .name("hb-tg")
        .protocol(aws_sdk_elasticloadbalancingv2::types::ProtocolEnum::Http)
        .port(80)
        .target_type(TargetTypeEnum::Ip)
        .health_check_protocol(aws_sdk_elasticloadbalancingv2::types::ProtocolEnum::Http)
        .health_check_path("/")
        // AWS @range bounds: interval 5..=300, timeout 2..=120,
        // threshold 2..=10. Stick to the minimum so the test still
        // converges fast (~10-20s per state transition).
        .health_check_interval_seconds(5)
        .health_check_timeout_seconds(2)
        .healthy_threshold_count(2)
        .unhealthy_threshold_count(2)
        .matcher(
            aws_sdk_elasticloadbalancingv2::types::Matcher::builder()
                .http_code("200")
                .build(),
        )
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

    let healthy = wait_for_state(&elbv2, &tg_arn, "healthy", Duration::from_secs(45)).await;
    assert!(
        healthy,
        "target should reach healthy state with 200 responses"
    );

    target.set_code(503);

    let unhealthy = wait_for_state(&elbv2, &tg_arn, "unhealthy", Duration::from_secs(45)).await;
    assert!(
        unhealthy,
        "target should reach unhealthy state with 503 responses"
    );
}

async fn wait_for_state(
    elbv2: &aws_sdk_elasticloadbalancingv2::Client,
    tg_arn: &str,
    want: &str,
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
                if h.state().map(|s| s.as_str()) == Some(want) {
                    return true;
                }
            }
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    false
}
