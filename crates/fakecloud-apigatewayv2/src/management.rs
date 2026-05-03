//! API Gateway v2 `apigatewaymanagementapi` data plane.
//!
//! AWS exposes the management API at
//! `https://<api-id>.execute-api.<region>.amazonaws.com/<stage>/@connections/{connectionId}`
//! and clients use it via the `apigatewaymanagementapi` SDK (PostToConnection,
//! GetConnection, DeleteConnection). fakecloud serves a single host:port per
//! process, so we accept the same `@connections/{id}` resource at both
//! `/@connections/{id}` and `/{stage}/@connections/{id}` — the stage path
//! prefix that real AWS includes in the URL is stripped by axum and ignored
//! here, since connection ids are globally unique within a process.
//!
//! Errors match AWS's wire shape: 4xx responses carry a JSON `{"message": ...}`
//! body and an `x-amzn-errortype` header so that botocore / aws-sdk-* clients
//! surface the right exception class.

use axum::{
    extract::{Path, State},
    http::{HeaderMap, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use serde_json::json;

use crate::state::SharedWebSocketRegistry;

/// Build the `@connections/{id}` router served at the root path. AWS SDK
/// clients usually hit the stage-prefixed form — see
/// [`router_with_stage_prefix`].
pub fn router(registry: SharedWebSocketRegistry) -> Router {
    Router::new()
        .route(
            "/@connections/{connection_id}",
            post(post_to_connection)
                .get(get_connection)
                .delete(delete_connection),
        )
        .with_state(registry)
}

/// Build a router that mounts the management routes both at the root and
/// under a `/{stage}` prefix. AWS SDK clients hit
/// `/<stage>/@connections/{id}`; tests and ad-hoc callers often hit
/// `/@connections/{id}` directly.
pub fn router_with_stage_prefix(registry: SharedWebSocketRegistry) -> Router {
    Router::new()
        .route(
            "/@connections/{connection_id}",
            post(post_to_connection)
                .get(get_connection)
                .delete(delete_connection),
        )
        .route(
            "/{stage}/@connections/{connection_id}",
            post(post_to_connection_staged)
                .get(get_connection_staged)
                .delete(delete_connection_staged),
        )
        .with_state(registry)
}

fn gone_response() -> Response {
    aws_error_response(
        StatusCode::GONE,
        "GoneException",
        "Connection is no longer available.",
    )
}

fn aws_error_response(status: StatusCode, error_type: &str, message: &str) -> Response {
    let mut headers = HeaderMap::new();
    if let Ok(v) = HeaderValue::from_str(error_type) {
        headers.insert("x-amzn-errortype", v);
    }
    (
        status,
        headers,
        Json(json!({ "message": message, "Message": message })),
    )
        .into_response()
}

async fn post_to_connection(
    State(registry): State<SharedWebSocketRegistry>,
    Path(connection_id): Path<String>,
    body: axum::body::Bytes,
) -> Response {
    post_to_connection_inner(registry, connection_id, body).await
}

/// Stage-prefixed variant matches AWS's actual endpoint shape; we ignore the
/// stage segment because connection ids are unique per process.
async fn post_to_connection_staged(
    State(registry): State<SharedWebSocketRegistry>,
    Path((_stage, connection_id)): Path<(String, String)>,
    body: axum::body::Bytes,
) -> Response {
    post_to_connection_inner(registry, connection_id, body).await
}

async fn post_to_connection_inner(
    registry: SharedWebSocketRegistry,
    connection_id: String,
    body: axum::body::Bytes,
) -> Response {
    let sender = {
        let r = registry.read();
        r.get(&connection_id).map(|c| c.sender.clone())
    };
    let Some(sender) = sender else {
        return gone_response();
    };
    let msg = match std::str::from_utf8(&body) {
        Ok(s) => axum::extract::ws::Message::Text(s.to_string().into()),
        Err(_) => axum::extract::ws::Message::Binary(body),
    };
    if sender.send(msg).is_err() {
        // Receiver dropped between our read and send; clean up the stale
        // entry and report gone so retries don't keep hitting this branch.
        registry.write().remove(&connection_id);
        return gone_response();
    }
    // Touch lastActiveAt — outbound traffic counts as activity in AWS too.
    registry.write().touch(&connection_id);
    (StatusCode::OK, Json(json!({}))).into_response()
}

async fn get_connection(
    State(registry): State<SharedWebSocketRegistry>,
    Path(connection_id): Path<String>,
) -> Response {
    get_connection_inner(registry, connection_id)
}

async fn get_connection_staged(
    State(registry): State<SharedWebSocketRegistry>,
    Path((_stage, connection_id)): Path<(String, String)>,
) -> Response {
    get_connection_inner(registry, connection_id)
}

fn get_connection_inner(registry: SharedWebSocketRegistry, connection_id: String) -> Response {
    let r = registry.read();
    let Some(c) = r.get(&connection_id) else {
        return gone_response();
    };
    let mut identity = serde_json::Map::new();
    identity.insert("sourceIp".to_string(), json!(c.source_ip));
    if let Some(ua) = c.user_agent.as_deref() {
        identity.insert("userAgent".to_string(), json!(ua));
    }
    (
        StatusCode::OK,
        Json(json!({
            "connectedAt": c.connected_at.to_rfc3339(),
            "lastActiveAt": c.last_active_at.to_rfc3339(),
            "identity": serde_json::Value::Object(identity),
        })),
    )
        .into_response()
}

async fn delete_connection(
    State(registry): State<SharedWebSocketRegistry>,
    Path(connection_id): Path<String>,
) -> Response {
    delete_connection_inner(registry, connection_id)
}

async fn delete_connection_staged(
    State(registry): State<SharedWebSocketRegistry>,
    Path((_stage, connection_id)): Path<(String, String)>,
) -> Response {
    delete_connection_inner(registry, connection_id)
}

fn delete_connection_inner(registry: SharedWebSocketRegistry, connection_id: String) -> Response {
    let removed = registry.write().remove(&connection_id);
    let Some(info) = removed else {
        return gone_response();
    };
    // Drop the sender after sending Close so the lifecycle task wakes up,
    // forwards the close frame, and exits. Ignored if the receiver is
    // already gone.
    let _ = info.sender.send(axum::extract::ws::Message::Close(None));
    StatusCode::NO_CONTENT.into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::WebSocketRegistry;
    use std::sync::Arc;

    fn empty_registry() -> SharedWebSocketRegistry {
        Arc::new(parking_lot::RwLock::new(WebSocketRegistry::default()))
    }

    #[tokio::test]
    async fn get_connection_inner_returns_410_when_missing() {
        let resp = get_connection_inner(empty_registry(), "nope=".into());
        assert_eq!(resp.status(), StatusCode::GONE);
    }

    #[tokio::test]
    async fn delete_connection_inner_returns_410_when_missing() {
        let resp = delete_connection_inner(empty_registry(), "nope=".into());
        assert_eq!(resp.status(), StatusCode::GONE);
    }

    #[tokio::test]
    async fn post_to_connection_inner_returns_410_when_missing() {
        let resp = post_to_connection_inner(
            empty_registry(),
            "nope=".into(),
            axum::body::Bytes::from_static(b"x"),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::GONE);
    }
}
