//! End-to-end WebSocket data plane tests.
//!
//! Boots a minimal axum app with the same routes the server wires up and
//! drives them through `tokio-tungstenite` to assert real upgrade -> message
//! -> close round-trips. Mirrors the server's `/_fakecloud/apigatewayv2/ws/{api_id}`
//! and `/@connections/{id}` handlers; if the server's wiring drifts, these
//! tests will pass against the harness but the production server still needs
//! the same shape — see `crates/fakecloud-server/src/main.rs`.

use std::collections::HashMap;
use std::sync::Arc;

use axum::extract::ws::Message;
use axum::Router;
use fakecloud_apigatewayv2::{websocket, SharedWebSocketRegistry, WebSocketRegistry};
use futures_util::StreamExt as _;
use tokio::net::TcpListener;

fn make_app(registry: SharedWebSocketRegistry) -> Router {
    Router::new()
        .route(
            "/_fakecloud/apigatewayv2/ws/{api_id}",
            axum::routing::get({
                let reg = registry.clone();
                move |ws: axum::extract::WebSocketUpgrade,
                      axum::extract::Path(api_id): axum::extract::Path<String>,
                      axum::extract::Query(_params): axum::extract::Query<
                    HashMap<String, String>,
                >| {
                    let reg = reg.clone();
                    async move {
                        ws.on_upgrade(move |socket| async move {
                            let (conn_id, rx) = websocket::register(
                                reg.clone(),
                                api_id,
                                "$default".to_string(),
                                "127.0.0.1".to_string(),
                            );
                            websocket::run_lifecycle(socket, rx, |_b, _t| async {}).await;
                            websocket::deregister(&reg, &conn_id);
                        })
                    }
                }
            }),
        )
        .route(
            "/@connections/{connection_id}",
            axum::routing::post({
                let reg = registry.clone();
                move |axum::extract::Path(id): axum::extract::Path<String>,
                      body: axum::body::Bytes| {
                    let reg = reg.clone();
                    async move {
                        let sender = {
                            let r = reg.read();
                            r.get(&id).map(|c| c.sender.clone())
                        };
                        let Some(sender) = sender else {
                            return axum::http::StatusCode::GONE;
                        };
                        let msg = match std::str::from_utf8(&body) {
                            Ok(s) => Message::Text(s.to_string().into()),
                            Err(_) => Message::Binary(body),
                        };
                        if sender.send(msg).is_err() {
                            reg.write().remove(&id);
                            return axum::http::StatusCode::GONE;
                        }
                        axum::http::StatusCode::OK
                    }
                }
            })
            .delete({
                let reg = registry.clone();
                move |axum::extract::Path(id): axum::extract::Path<String>| {
                    let reg = reg.clone();
                    async move {
                        let removed = reg.write().remove(&id);
                        let Some(info) = removed else {
                            return axum::http::StatusCode::GONE;
                        };
                        let _ = info.sender.send(Message::Close(None));
                        axum::http::StatusCode::NO_CONTENT
                    }
                }
            }),
        )
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
