//! End-to-end WebSocket data plane tests.
//!
//! Boots a minimal axum app that mirrors the server's wiring: the WebSocket
//! upgrade endpoint at `/_fakecloud/apigatewayv2/ws/{api_id}` plus the
//! `apigatewaymanagementapi` router at `/@connections/{id}` and
//! `/{stage}/@connections/{id}`. Drives them through `tokio-tungstenite` and
//! `reqwest` to exercise the upgrade -> message -> close round-trip and the
//! PostToConnection / GetConnection / DeleteConnection ops.

use std::collections::HashMap;
use std::sync::Arc;

use axum::Router;
use fakecloud_apigatewayv2::{management, websocket, SharedWebSocketRegistry, WebSocketRegistry};
use futures_util::StreamExt as _;
use tokio::net::TcpListener;

fn make_app(registry: SharedWebSocketRegistry) -> Router {
    let ws_router = Router::new().route(
        "/_fakecloud/apigatewayv2/ws/{api_id}",
        axum::routing::get({
            let reg = registry.clone();
            move |ws: axum::extract::WebSocketUpgrade,
                  axum::extract::Path(api_id): axum::extract::Path<String>,
                  axum::extract::Query(_params): axum::extract::Query<HashMap<String, String>>,
                  headers: axum::http::HeaderMap| {
                let reg = reg.clone();
                async move {
                    let user_agent = headers
                        .get(axum::http::header::USER_AGENT)
                        .and_then(|v| v.to_str().ok())
                        .map(|s| s.to_string());
                    ws.on_upgrade(move |socket| async move {
                        let (conn_id, rx) = websocket::register(
                            reg.clone(),
                            api_id,
                            "$default".to_string(),
                            "127.0.0.1".to_string(),
                            user_agent,
                        );
                        let conn_id_clone = conn_id.clone();
                        websocket::run_lifecycle_tracked(
                            socket,
                            rx,
                            |_b, _t| async {},
                            reg.clone(),
                            conn_id_clone,
                        )
                        .await;
                        websocket::deregister(&reg, &conn_id);
                    })
                }
            }
        }),
    );
    ws_router.merge(management::router_with_stage_prefix(registry))
}

async fn spawn_app(registry: SharedWebSocketRegistry) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let app = make_app(registry);
    tokio::spawn(async move {
        axum::serve(listener, app).await.unwrap();
    });
    format!("127.0.0.1:{}", addr.port())
}

async fn open_ws(
    addr: &str,
    api_id: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    let url = format!("ws://{}/_fakecloud/apigatewayv2/ws/{}", addr, api_id);
    let (stream, _) = tokio_tungstenite::connect_async(url).await.unwrap();
    stream
}

async fn open_ws_with_user_agent(
    addr: &str,
    api_id: &str,
    user_agent: &str,
) -> tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<tokio::net::TcpStream>> {
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;
    let url = format!("ws://{}/_fakecloud/apigatewayv2/ws/{}", addr, api_id);
    let mut req = url.into_client_request().unwrap();
    req.headers_mut().insert(
        "User-Agent",
        tokio_tungstenite::tungstenite::http::HeaderValue::from_str(user_agent).unwrap(),
    );
    let (stream, _) = tokio_tungstenite::connect_async(req).await.unwrap();
    stream
}

async fn wait_for_connection(registry: &SharedWebSocketRegistry) -> String {
    for _ in 0..50 {
        if let Some(id) = registry.read().connections.keys().next().cloned() {
            return id;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("no connection registered within timeout");
}

#[tokio::test]
async fn websocket_upgrade_creates_connection_record() {
    let registry: SharedWebSocketRegistry =
        Arc::new(parking_lot::RwLock::new(WebSocketRegistry::default()));
    let addr = spawn_app(registry.clone()).await;
    let _ws = open_ws(&addr, "api-1").await;
    let id = wait_for_connection(&registry).await;
    assert!(registry.read().contains(&id));
}

#[tokio::test]
async fn websocket_disconnect_removes_connection() {
    let registry: SharedWebSocketRegistry =
        Arc::new(parking_lot::RwLock::new(WebSocketRegistry::default()));
    let addr = spawn_app(registry.clone()).await;
    let mut ws = open_ws(&addr, "api-1").await;
    let _id = wait_for_connection(&registry).await;
    ws.close(None).await.unwrap();
    drop(ws);
    for _ in 0..50 {
        if registry.read().connections.is_empty() {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("connection not removed within timeout");
}

#[tokio::test]
async fn post_to_connections_endpoint_sends_message_to_client() {
    let registry: SharedWebSocketRegistry =
        Arc::new(parking_lot::RwLock::new(WebSocketRegistry::default()));
    let addr = spawn_app(registry.clone()).await;
    let mut ws = open_ws(&addr, "api-1").await;
    let id = wait_for_connection(&registry).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/@connections/{}", addr, id))
        .body("hello-from-server")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let msg = ws.next().await.unwrap().unwrap();
    match msg {
        tokio_tungstenite::tungstenite::Message::Text(t) => {
            assert_eq!(t.as_str(), "hello-from-server");
        }
        other => panic!("expected text frame, got {other:?}"),
    }
}

#[tokio::test]
async fn post_to_connections_with_stage_prefix_routes_same_handler() {
    let registry: SharedWebSocketRegistry =
        Arc::new(parking_lot::RwLock::new(WebSocketRegistry::default()));
    let addr = spawn_app(registry.clone()).await;
    let mut ws = open_ws(&addr, "api-1").await;
    let id = wait_for_connection(&registry).await;
    let client = reqwest::Client::new();
    // Real AWS SDKs hit `/<stage>/@connections/<id>`. We accept the same
    // shape and ignore the stage segment.
    let resp = client
        .post(format!("http://{}/prod/@connections/{}", addr, id))
        .body("hello-staged")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let msg = ws.next().await.unwrap().unwrap();
    match msg {
        tokio_tungstenite::tungstenite::Message::Text(t) => {
            assert_eq!(t.as_str(), "hello-staged");
        }
        other => panic!("expected text frame, got {other:?}"),
    }
}

#[tokio::test]
async fn post_to_connections_endpoint_returns_410_when_connection_gone() {
    let registry: SharedWebSocketRegistry =
        Arc::new(parking_lot::RwLock::new(WebSocketRegistry::default()));
    let addr = spawn_app(registry.clone()).await;
    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://{}/@connections/{}", addr, "missing="))
        .body("payload")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 410);
    // AWS SDKs read the error class from the `x-amzn-errortype` header.
    assert_eq!(
        resp.headers()
            .get("x-amzn-errortype")
            .and_then(|v| v.to_str().ok()),
        Some("GoneException")
    );
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body
        .get("message")
        .and_then(|v| v.as_str())
        .is_some_and(|m| !m.is_empty()));
}

#[tokio::test]
async fn get_connection_returns_metadata() {
    let registry: SharedWebSocketRegistry =
        Arc::new(parking_lot::RwLock::new(WebSocketRegistry::default()));
    let addr = spawn_app(registry.clone()).await;
    let _ws = open_ws_with_user_agent(&addr, "api-1", "fakecloud-test/1.0").await;
    let id = wait_for_connection(&registry).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/@connections/{}", addr, id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    let body: serde_json::Value = resp.json().await.unwrap();
    assert!(body
        .get("connectedAt")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty()));
    assert!(body
        .get("lastActiveAt")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.is_empty()));
    let identity = body.get("identity").expect("identity present");
    assert_eq!(
        identity.get("sourceIp").and_then(|v| v.as_str()),
        Some("127.0.0.1")
    );
    assert_eq!(
        identity.get("userAgent").and_then(|v| v.as_str()),
        Some("fakecloud-test/1.0")
    );
}

#[tokio::test]
async fn get_connection_returns_410_when_missing() {
    let registry: SharedWebSocketRegistry =
        Arc::new(parking_lot::RwLock::new(WebSocketRegistry::default()));
    let addr = spawn_app(registry.clone()).await;
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://{}/@connections/{}", addr, "missing="))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 410);
    assert_eq!(
        resp.headers()
            .get("x-amzn-errortype")
            .and_then(|v| v.to_str().ok()),
        Some("GoneException")
    );
}

#[tokio::test]
async fn delete_connection_closes_websocket() {
    let registry: SharedWebSocketRegistry =
        Arc::new(parking_lot::RwLock::new(WebSocketRegistry::default()));
    let addr = spawn_app(registry.clone()).await;
    let mut ws = open_ws(&addr, "api-1").await;
    let id = wait_for_connection(&registry).await;
    let client = reqwest::Client::new();
    let resp = client
        .delete(format!("http://{}/@connections/{}", addr, id))
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 204);
    // The server should send a close frame; tungstenite surfaces it as
    // either a Close message or an end-of-stream.
    let msg = ws.next().await;
    match msg {
        Some(Ok(tokio_tungstenite::tungstenite::Message::Close(_))) | None => {}
        Some(Ok(other)) => panic!("expected close, got {other:?}"),
        Some(Err(err)) => panic!("ws error: {err}"),
    }
}

#[tokio::test]
async fn post_to_connections_after_delete_returns_410() {
    let registry: SharedWebSocketRegistry =
        Arc::new(parking_lot::RwLock::new(WebSocketRegistry::default()));
    let addr = spawn_app(registry.clone()).await;
    let _ws = open_ws(&addr, "api-1").await;
    let id = wait_for_connection(&registry).await;
    let client = reqwest::Client::new();
    let del = client
        .delete(format!("http://{}/@connections/{}", addr, id))
        .send()
        .await
        .unwrap();
    assert_eq!(del.status(), 204);
    let resp = client
        .post(format!("http://{}/@connections/{}", addr, id))
        .body("after-delete")
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 410);
}

#[tokio::test]
async fn inbound_message_bumps_last_active_at() {
    let registry: SharedWebSocketRegistry =
        Arc::new(parking_lot::RwLock::new(WebSocketRegistry::default()));
    let addr = spawn_app(registry.clone()).await;
    let mut ws = open_ws(&addr, "api-1").await;
    let id = wait_for_connection(&registry).await;
    let initial = registry.read().get(&id).unwrap().last_active_at;
    // Wait a moment so the resolution can show progress, then send a frame.
    tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    use futures_util::SinkExt as _;
    ws.send(tokio_tungstenite::tungstenite::Message::Text("ping".into()))
        .await
        .unwrap();
    // Give the server a chance to process the inbound frame.
    for _ in 0..50 {
        let now = registry.read().get(&id).unwrap().last_active_at;
        if now > initial {
            return;
        }
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    panic!("last_active_at did not advance after inbound frame");
}
