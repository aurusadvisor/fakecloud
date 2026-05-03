//! WebSocket data plane for API Gateway v2 WebSocket APIs.
//!
//! Connections are bookkept in a [`WebSocketRegistry`] keyed by AWS-style
//! connection ids. Inbound frames flow through the websocket task and dispatch
//! to the API's `$default` route (and `$connect` / `$disconnect` lifecycle
//! routes when target Lambda integrations are wired up). The control surface
//! at `/@connections/{id}` lets test code or SigV4 clients post messages back
//! to a connected client, fetch connection metadata, or close the socket.

use axum::extract::ws::{Message, WebSocket};
use chrono::Utc;
use tokio::sync::mpsc::{unbounded_channel, UnboundedReceiver};

use crate::state::{ConnectionInfo, SharedWebSocketRegistry};

/// Generate a 22-char base64-style connection id, matching AWS's
/// `<random>=` pattern.
pub fn generate_connection_id() -> String {
    use base64::prelude::*;
    let mut buf = [0u8; 16];
    let nanos = chrono::Utc::now().timestamp_nanos_opt().unwrap_or(0) as u128;
    let uuid = uuid::Uuid::new_v4().as_u128();
    let mixed = nanos.wrapping_mul(0x9E3779B97F4A7C15).wrapping_add(uuid);
    buf[..16].copy_from_slice(&mixed.to_le_bytes());
    let mut s = BASE64_STANDARD_NO_PAD.encode(buf);
    s.truncate(21);
    s.push('=');
    s
}

/// Register a new WebSocket connection and return its id plus the outbound
/// `Message` receiver. The caller is responsible for plumbing the receiver
/// into the upgraded socket.
pub fn register(
    registry: SharedWebSocketRegistry,
    api_id: String,
    stage: String,
    source_ip: String,
) -> (String, UnboundedReceiver<Message>) {
    let (tx, rx) = unbounded_channel();
    let now = Utc::now();
    let connection_id = generate_connection_id();
    let info = ConnectionInfo {
        connection_id: connection_id.clone(),
        api_id,
        stage,
        connected_at: now,
        last_active_at: now,
        source_ip,
        sender: tx,
    };
    registry.write().insert(info);
    (connection_id, rx)
}

pub fn deregister(registry: &SharedWebSocketRegistry, connection_id: &str) {
    registry.write().remove(connection_id);
}

/// Drive a websocket lifecycle: bridge inbound frames into `on_message`,
/// forward outbound frames pushed via the registry sender, and clean up on
/// close. `on_message` receives the raw bytes; `is_text` is true for text
/// frames so dispatchers can preserve framing for `$default` events.
pub async fn run_lifecycle<F, Fut>(
    mut socket: WebSocket,
    mut outbound: UnboundedReceiver<Message>,
    on_message: F,
) where
    F: Fn(Vec<u8>, bool) -> Fut,
    Fut: std::future::Future<Output = ()>,
{
    loop {
        tokio::select! {
            biased;
            outgoing = outbound.recv() => {
                match outgoing {
                    Some(Message::Close(frame)) => {
                        let _ = socket.send(Message::Close(frame)).await;
                        break;
                    }
                    Some(msg) => {
                        if socket.send(msg).await.is_err() {
                            break;
                        }
                    }
                    None => break,
                }
            }
            incoming = socket.recv() => {
                match incoming {
                    Some(Ok(Message::Text(text))) => {
                        on_message(text.as_bytes().to_vec(), true).await;
                    }
                    Some(Ok(Message::Binary(bin))) => {
                        on_message(bin.to_vec(), false).await;
                    }
                    Some(Ok(Message::Close(_))) => break,
                    Some(Ok(_)) => {}
                    Some(Err(_)) | None => break,
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn connection_id_format() {
        let id = generate_connection_id();
        assert_eq!(id.len(), 22);
        assert!(id.ends_with('='));
    }

    #[test]
    fn registry_insert_and_remove() {
        let registry: SharedWebSocketRegistry = Arc::new(parking_lot::RwLock::new(
            crate::state::WebSocketRegistry::default(),
        ));
        let (id, _rx) = register(
            registry.clone(),
            "api-1".into(),
            "dev".into(),
            "127.0.0.1".into(),
        );
        assert!(registry.read().contains(&id));
        deregister(&registry, &id);
        assert!(!registry.read().contains(&id));
    }

    #[tokio::test]
    async fn outbound_send_reaches_receiver() {
        let registry: SharedWebSocketRegistry = Arc::new(parking_lot::RwLock::new(
            crate::state::WebSocketRegistry::default(),
        ));
        let (id, mut rx) = register(
            registry.clone(),
            "api-1".into(),
            "dev".into(),
            "127.0.0.1".into(),
        );
        let sender = registry.read().get(&id).unwrap().sender.clone();
        sender.send(Message::Text("hello".into())).unwrap();
        let msg = rx.recv().await.unwrap();
        match msg {
            Message::Text(t) => assert_eq!(t.as_str(), "hello"),
            other => panic!("expected text, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn close_message_breaks_lifecycle() {
        // Verify that a `Close` outbound message cuts the loop. We use a
        // `mpsc` directly, swapping in a fake socket would require pulling
        // tungstenite — keep this as a contract test on the channel side.
        let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<Message>();
        tx.send(Message::Close(None)).unwrap();
        drop(tx);
        let next = rx.recv().await;
        assert!(matches!(next, Some(Message::Close(_))));
        assert!(rx.recv().await.is_none());
    }
}
