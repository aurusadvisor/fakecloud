//! OCI Distribution v2 HTTP handlers.
//!
//! Implements the subset of
//! <https://github.com/opencontainers/distribution-spec> needed for
//! `docker push` / `docker pull` / `aws ecr get-login-password |
//! docker login` against a running fakecloud. All blob and manifest
//! state lives in the existing repository state (see `state.rs`); this
//! module is the HTTP-layer adapter that shapes those operations into
//! the content-addressed REST surface that Docker/OCI clients expect.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use bytes::Bytes;
use chrono::Utc;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde_json::json;
use sha2::{Digest, Sha256};
use uuid::Uuid;

use fakecloud_core::service::{AwsRequest, AwsResponse, AwsServiceError, ResponseBody};

use crate::service::EcrService;
use crate::state::{Image, Layer, LayerUpload};

/// Classify an OCI v2 request by method + path. Returns `None` when
/// the path is not a recognised OCI endpoint (the caller responds
/// with 404 in that case).
pub(crate) fn dispatch(
    service: &EcrService,
    request: &AwsRequest,
) -> Result<AwsResponse, AwsServiceError> {
    // `/v2/...` — path_segments already splits off the leading `/`.
    let segs: Vec<&str> = request
        .path_segments
        .iter()
        .map(|s| s.as_str())
        .filter(|s| !s.is_empty())
        .collect();
    // API version probe: `/v2/` or `/v2`.
    if segs.len() == 1 && segs[0] == "v2" {
        if !authorized(request)? {
            return Err(unauthorized());
        }
        return Ok(base_response(
            StatusCode::OK,
            "application/json",
            b"{}".to_vec(),
        ));
    }
    if segs.is_empty() || segs[0] != "v2" {
        return Err(not_found());
    }
    if !authorized(request)? {
        return Err(unauthorized());
    }

    // Split the repository name out of segs[1..n]. OCI allows
    // slash-separated names so `v2/team/svc/...` means repo `team/svc`.
    // Anchor on the trailing segments (`blobs/...`, `manifests/...`,
    // `tags/list`) to find where the name ends.
    let (repo_name, action_segs) = match split_name(&segs[1..]) {
        Some(parts) => parts,
        None => return Err(not_found()),
    };

    let method = &request.method;
    let parts: Vec<&str> = action_segs.iter().map(|s| s.as_str()).collect();
    match (method, parts.as_slice()) {
        (&Method::GET, ["tags", "list"]) => tags_list(service, request, &repo_name),
        (&Method::HEAD, ["blobs", digest]) => blob_head(service, request, &repo_name, digest),
        (&Method::GET, ["blobs", digest]) => blob_get(service, request, &repo_name, digest),
        (&Method::DELETE, ["blobs", digest]) => blob_delete(service, request, &repo_name, digest),
        (&Method::POST, ["blobs", "uploads"]) | (&Method::POST, ["blobs", "uploads", ""]) => {
            blob_upload_start(service, request, &repo_name)
        }
        (&Method::PATCH, ["blobs", "uploads", upload_id]) => {
            blob_upload_patch(service, request, &repo_name, upload_id)
        }
        (&Method::PUT, ["blobs", "uploads", upload_id]) => {
            blob_upload_finish(service, request, &repo_name, upload_id)
        }
        (&Method::DELETE, ["blobs", "uploads", upload_id]) => {
            blob_upload_cancel(service, request, &repo_name, upload_id)
        }
        (&Method::HEAD, ["manifests", reference]) => {
            manifest_head(service, request, &repo_name, reference)
        }
        (&Method::GET, ["manifests", reference]) => {
            manifest_get(service, request, &repo_name, reference)
        }
        (&Method::PUT, ["manifests", reference]) => {
            manifest_put(service, request, &repo_name, reference)
        }
        (&Method::DELETE, ["manifests", reference]) => {
            manifest_delete(service, request, &repo_name, reference)
        }
        _ => Err(not_found()),
    }
}

/// Walk backwards from the end to find where the OCI action subpath
/// starts (`blobs/...`, `manifests/...`, `tags/list`). Everything
/// before it is the repository name.
fn split_name(segs: &[&str]) -> Option<(String, Vec<String>)> {
    for (i, s) in segs.iter().enumerate() {
        match *s {
            "blobs" | "manifests" | "tags" => {
                if i == 0 {
                    return None;
                }
                let name = segs[..i].join("/");
                let action = segs[i..].iter().map(|s| s.to_string()).collect();
                return Some((name, action));
            }
            _ => {}
        }
    }
    None
}

/// Accept Basic Auth with any token fakecloud issued via
/// `GetAuthorizationToken`, or the `test*` dev-bypass used elsewhere.
/// For convenience during local tests, a missing Authorization header
/// is also accepted so `curl` can exercise the protocol without Docker
/// managing credentials. Wire format:
/// `Authorization: Basic base64("AWS:<token>")`.
fn authorized(request: &AwsRequest) -> Result<bool, AwsServiceError> {
    let Some(header) = request.headers.get("authorization") else {
        return Ok(true);
    };
    let value = header.to_str().map_err(|_| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "UNAUTHORIZED",
            "Bad Authorization header",
        )
    })?;
    if let Some(rest) = value.strip_prefix("Basic ") {
        let decoded = B64.decode(rest.trim().as_bytes()).map_err(|_| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "UNAUTHORIZED",
                "Bad Basic credentials",
            )
        })?;
        let pair = String::from_utf8_lossy(&decoded);
        let mut parts = pair.splitn(2, ':');
        let user = parts.next().unwrap_or("");
        let _pass = parts.next().unwrap_or("");
        // AWS emits `AWS:<token>`; the legacy CLI uses `AWS:<bearer>`.
        // Dev bypass: user starts with `test`.
        return Ok(user == "AWS" || user.starts_with("test"));
    }
    // SigV4-signed requests (shouldn't happen on /v2/ but allow it —
    // the main dispatcher already validated the signature upstream if
    // verify_sigv4 is on).
    Ok(value.starts_with("AWS4-HMAC-SHA256"))
}

fn base_response(status: StatusCode, content_type: &str, body: Vec<u8>) -> AwsResponse {
    let mut headers = HeaderMap::new();
    headers.insert(
        "Docker-Distribution-Api-Version",
        HeaderValue::from_static("registry/2.0"),
    );
    AwsResponse {
        status,
        content_type: content_type.to_string(),
        body: ResponseBody::Bytes(Bytes::from(body)),
        headers,
    }
}

fn unauthorized() -> AwsServiceError {
    AwsServiceError::aws_error_with_headers(
        StatusCode::UNAUTHORIZED,
        "UNAUTHORIZED",
        "authentication required",
        vec![
            (
                "WWW-Authenticate".to_string(),
                "Basic realm=\"fakecloud-ecr\"".to_string(),
            ),
            (
                "Docker-Distribution-Api-Version".to_string(),
                "registry/2.0".to_string(),
            ),
        ],
    )
}

fn not_found() -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::NOT_FOUND,
        "NotFound",
        "The requested resource could not be found.",
    )
}

fn repo_not_found(name: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::NOT_FOUND,
        "NAME_UNKNOWN",
        format!("repository name not known to registry: {name}"),
    )
}

fn blob_not_found(name: &str, digest: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::NOT_FOUND,
        "BLOB_UNKNOWN",
        format!("blob {digest} not found in repository {name}"),
    )
}

fn manifest_not_found(name: &str, reference: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::NOT_FOUND,
        "MANIFEST_UNKNOWN",
        format!("manifest {reference} not found in repository {name}"),
    )
}

fn digest_invalid() -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::BAD_REQUEST,
        "DIGEST_INVALID",
        "provided digest did not match uploaded content",
    )
}

fn upload_unknown(upload_id: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::NOT_FOUND,
        "BLOB_UPLOAD_UNKNOWN",
        format!("upload {upload_id} not found"),
    )
}

fn sha256_digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    format!("sha256:{:x}", hasher.finalize())
}

// -------- handlers --------

fn tags_list(
    service: &EcrService,
    request: &AwsRequest,
    name: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let accounts = service.state_handle().read();
    let state = accounts
        .get(&request.account_id)
        .ok_or_else(|| repo_not_found(name))?;
    let repo = state
        .repositories
        .get(name)
        .ok_or_else(|| repo_not_found(name))?;
    let mut tags: Vec<&str> = repo.image_tags.keys().map(|k| k.as_str()).collect();
    tags.sort();
    let body = json!({ "name": name, "tags": tags });
    Ok(base_response(
        StatusCode::OK,
        "application/json",
        serde_json::to_vec(&body).unwrap(),
    ))
}

fn blob_head(
    service: &EcrService,
    request: &AwsRequest,
    name: &str,
    digest: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let accounts = service.state_handle().read();
    let state = accounts
        .get(&request.account_id)
        .ok_or_else(|| repo_not_found(name))?;
    let repo = state
        .repositories
        .get(name)
        .ok_or_else(|| repo_not_found(name))?;
    let layer = repo
        .layers
        .get(digest)
        .ok_or_else(|| blob_not_found(name, digest))?;
    let mut resp = base_response(StatusCode::OK, "application/octet-stream", Vec::new());
    resp.headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(digest).unwrap(),
    );
    resp.headers
        .insert("Content-Length", HeaderValue::from(layer.size));
    Ok(resp)
}

fn blob_get(
    service: &EcrService,
    request: &AwsRequest,
    name: &str,
    digest: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let accounts = service.state_handle().read();
    let state = accounts
        .get(&request.account_id)
        .ok_or_else(|| repo_not_found(name))?;
    let repo = state
        .repositories
        .get(name)
        .ok_or_else(|| repo_not_found(name))?;
    let layer = repo
        .layers
        .get(digest)
        .ok_or_else(|| blob_not_found(name, digest))?;
    let bytes = B64.decode(layer.blob_b64.as_bytes()).unwrap_or_default();
    let mut resp = base_response(StatusCode::OK, &layer.media_type, bytes);
    resp.headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(digest).unwrap(),
    );
    Ok(resp)
}

fn blob_delete(
    service: &EcrService,
    request: &AwsRequest,
    name: &str,
    digest: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let mut accounts = service.state_handle().write();
    let state = accounts
        .get_mut(&request.account_id)
        .ok_or_else(|| repo_not_found(name))?;
    let repo = state
        .repositories
        .get_mut(name)
        .ok_or_else(|| repo_not_found(name))?;
    if repo.layers.remove(digest).is_none() {
        return Err(blob_not_found(name, digest));
    }
    Ok(base_response(
        StatusCode::ACCEPTED,
        "application/json",
        Vec::new(),
    ))
}

fn blob_upload_start(
    service: &EcrService,
    request: &AwsRequest,
    name: &str,
) -> Result<AwsResponse, AwsServiceError> {
    // Support single-POST upload with `?digest=...` + body per the spec.
    let digest_q = request.query_params.get("digest").cloned();
    let upload_id = Uuid::new_v4().to_string();
    let body_bytes = request.body.to_vec();

    let mut accounts = service.state_handle().write();
    let state = accounts
        .get_mut(&request.account_id)
        .ok_or_else(|| repo_not_found(name))?;
    if !state.repositories.contains_key(name) {
        return Err(repo_not_found(name));
    }

    if let Some(expected) = digest_q {
        let computed = sha256_digest(&body_bytes);
        if expected != computed {
            return Err(digest_invalid());
        }
        let repo = state.repositories.get_mut(name).unwrap();
        let size = body_bytes.len() as u64;
        repo.layers.insert(
            computed.clone(),
            Layer {
                digest: computed.clone(),
                size,
                blob_b64: B64.encode(&body_bytes),
                media_type: "application/octet-stream".to_string(),
            },
        );
        let mut resp = base_response(StatusCode::CREATED, "application/json", Vec::new());
        resp.headers.insert(
            "Location",
            HeaderValue::from_str(&format!("/v2/{name}/blobs/{digest}", digest = computed,))
                .unwrap(),
        );
        resp.headers.insert(
            "Docker-Content-Digest",
            HeaderValue::from_str(&computed).unwrap(),
        );
        return Ok(resp);
    }

    state.layer_uploads.insert(
        upload_id.clone(),
        LayerUpload {
            upload_id: upload_id.clone(),
            repository_name: name.to_string(),
            created_at: Utc::now(),
            blob_b64: String::new(),
            last_byte_received: 0,
        },
    );
    let mut resp = base_response(StatusCode::ACCEPTED, "application/json", Vec::new());
    resp.headers.insert(
        "Location",
        HeaderValue::from_str(&format!("/v2/{name}/blobs/uploads/{upload_id}")).unwrap(),
    );
    resp.headers.insert(
        "Docker-Upload-UUID",
        HeaderValue::from_str(&upload_id).unwrap(),
    );
    resp.headers
        .insert("Range", HeaderValue::from_static("0-0"));
    Ok(resp)
}

fn blob_upload_patch(
    service: &EcrService,
    request: &AwsRequest,
    name: &str,
    upload_id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let chunk = request.body.to_vec();
    let mut accounts = service.state_handle().write();
    let state = accounts
        .get_mut(&request.account_id)
        .ok_or_else(|| repo_not_found(name))?;
    let upload = state
        .layer_uploads
        .get_mut(upload_id)
        .ok_or_else(|| upload_unknown(upload_id))?;
    if upload.repository_name != name {
        return Err(upload_unknown(upload_id));
    }
    let mut existing = B64.decode(upload.blob_b64.as_bytes()).unwrap_or_default();
    let start = existing.len() as u64;
    existing.extend_from_slice(&chunk);
    upload.blob_b64 = B64.encode(&existing);
    upload.last_byte_received = start + chunk.len() as u64;
    let range_end = upload.last_byte_received.saturating_sub(1);
    let mut resp = base_response(StatusCode::ACCEPTED, "application/json", Vec::new());
    resp.headers.insert(
        "Location",
        HeaderValue::from_str(&format!("/v2/{name}/blobs/uploads/{upload_id}")).unwrap(),
    );
    resp.headers.insert(
        "Docker-Upload-UUID",
        HeaderValue::from_str(upload_id).unwrap(),
    );
    resp.headers.insert(
        "Range",
        HeaderValue::from_str(&format!("0-{range_end}")).unwrap(),
    );
    Ok(resp)
}

fn blob_upload_finish(
    service: &EcrService,
    request: &AwsRequest,
    name: &str,
    upload_id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let digest = request.query_params.get("digest").cloned().ok_or_else(|| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "DIGEST_INVALID",
            "digest query parameter required on PUT",
        )
    })?;
    let final_chunk = request.body.to_vec();

    let mut accounts = service.state_handle().write();
    let state = accounts
        .get_mut(&request.account_id)
        .ok_or_else(|| repo_not_found(name))?;
    let upload = state
        .layer_uploads
        .get(upload_id)
        .ok_or_else(|| upload_unknown(upload_id))?;
    if upload.repository_name != name {
        return Err(upload_unknown(upload_id));
    }
    let mut combined = B64.decode(upload.blob_b64.as_bytes()).unwrap_or_default();
    combined.extend_from_slice(&final_chunk);
    let computed = sha256_digest(&combined);
    if digest != computed {
        return Err(digest_invalid());
    }
    // Commit. Removing upload after validation so retries can correct
    // a bad digest query param on the last PUT.
    let upload = state.layer_uploads.remove(upload_id).unwrap();
    let _ = upload;
    let repo = state
        .repositories
        .get_mut(name)
        .ok_or_else(|| repo_not_found(name))?;
    let size = combined.len() as u64;
    repo.layers.insert(
        computed.clone(),
        Layer {
            digest: computed.clone(),
            size,
            blob_b64: B64.encode(&combined),
            media_type: "application/octet-stream".to_string(),
        },
    );
    let mut resp = base_response(StatusCode::CREATED, "application/json", Vec::new());
    resp.headers.insert(
        "Location",
        HeaderValue::from_str(&format!("/v2/{name}/blobs/{digest}", digest = computed)).unwrap(),
    );
    resp.headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(&computed).unwrap(),
    );
    Ok(resp)
}

fn blob_upload_cancel(
    service: &EcrService,
    request: &AwsRequest,
    name: &str,
    upload_id: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let mut accounts = service.state_handle().write();
    let state = accounts
        .get_mut(&request.account_id)
        .ok_or_else(|| repo_not_found(name))?;
    // Match patch/finish: refuse to cancel an upload scoped to a
    // different repository so a DELETE request for repo A can't tear
    // down an in-flight upload in repo B.
    let belongs = state
        .layer_uploads
        .get(upload_id)
        .map(|u| u.repository_name == name)
        .unwrap_or(false);
    if !belongs {
        return Err(upload_unknown(upload_id));
    }
    state.layer_uploads.remove(upload_id);
    Ok(base_response(
        StatusCode::NO_CONTENT,
        "application/json",
        Vec::new(),
    ))
}

fn manifest_head(
    service: &EcrService,
    request: &AwsRequest,
    name: &str,
    reference: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let accounts = service.state_handle().read();
    let state = accounts
        .get(&request.account_id)
        .ok_or_else(|| repo_not_found(name))?;
    let repo = state
        .repositories
        .get(name)
        .ok_or_else(|| repo_not_found(name))?;
    let digest =
        resolve_reference(repo, reference).ok_or_else(|| manifest_not_found(name, reference))?;
    let image = repo.images.get(&digest).unwrap();
    let mut resp = base_response(StatusCode::OK, &image.image_manifest_media_type, Vec::new());
    resp.headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(&digest).unwrap(),
    );
    resp.headers.insert(
        "Content-Length",
        HeaderValue::from(image.image_manifest.len() as u64),
    );
    Ok(resp)
}

fn manifest_get(
    service: &EcrService,
    request: &AwsRequest,
    name: &str,
    reference: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let accounts = service.state_handle().read();
    let state = accounts
        .get(&request.account_id)
        .ok_or_else(|| repo_not_found(name))?;
    let repo = state
        .repositories
        .get(name)
        .ok_or_else(|| repo_not_found(name))?;
    let digest =
        resolve_reference(repo, reference).ok_or_else(|| manifest_not_found(name, reference))?;
    let image = repo.images.get(&digest).unwrap();
    let mut resp = base_response(
        StatusCode::OK,
        &image.image_manifest_media_type,
        image.image_manifest.as_bytes().to_vec(),
    );
    resp.headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(&digest).unwrap(),
    );
    Ok(resp)
}

fn manifest_put(
    service: &EcrService,
    request: &AwsRequest,
    name: &str,
    reference: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let body = request.body.to_vec();
    let digest = sha256_digest(&body);
    let media_type = request
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/vnd.docker.distribution.manifest.v2+json")
        .to_string();

    let mut accounts = service.state_handle().write();
    let state = accounts
        .get_mut(&request.account_id)
        .ok_or_else(|| repo_not_found(name))?;
    let repo = state
        .repositories
        .get_mut(name)
        .ok_or_else(|| repo_not_found(name))?;
    repo.images.insert(
        digest.clone(),
        Image {
            image_digest: digest.clone(),
            image_manifest: String::from_utf8_lossy(&body).to_string(),
            image_manifest_media_type: media_type,
            artifact_media_type: None,
            image_size_in_bytes: body.len() as u64,
            image_pushed_at: Utc::now(),
            last_recorded_pull_time: None,
        },
    );
    // If the reference isn't a digest, treat it as a tag.
    if !reference.starts_with("sha256:") {
        repo.image_tags
            .insert(reference.to_string(), digest.clone());
    }

    let mut resp = base_response(StatusCode::CREATED, "application/json", Vec::new());
    resp.headers.insert(
        "Location",
        HeaderValue::from_str(&format!("/v2/{name}/manifests/{digest}", digest = digest,)).unwrap(),
    );
    resp.headers.insert(
        "Docker-Content-Digest",
        HeaderValue::from_str(&digest).unwrap(),
    );
    Ok(resp)
}

fn manifest_delete(
    service: &EcrService,
    request: &AwsRequest,
    name: &str,
    reference: &str,
) -> Result<AwsResponse, AwsServiceError> {
    let mut accounts = service.state_handle().write();
    let state = accounts
        .get_mut(&request.account_id)
        .ok_or_else(|| repo_not_found(name))?;
    let repo = state
        .repositories
        .get_mut(name)
        .ok_or_else(|| repo_not_found(name))?;
    if reference.starts_with("sha256:") {
        if repo.images.remove(reference).is_none() {
            return Err(manifest_not_found(name, reference));
        }
        repo.image_tags.retain(|_, d| d != reference);
    } else {
        let digest = repo
            .image_tags
            .remove(reference)
            .ok_or_else(|| manifest_not_found(name, reference))?;
        let still_tagged = repo.image_tags.values().any(|d| d == &digest);
        if !still_tagged {
            repo.images.remove(&digest);
        }
    }
    Ok(base_response(
        StatusCode::ACCEPTED,
        "application/json",
        Vec::new(),
    ))
}

fn resolve_reference(repo: &crate::state::Repository, reference: &str) -> Option<String> {
    if reference.starts_with("sha256:") {
        if repo.images.contains_key(reference) {
            return Some(reference.to_string());
        }
        return None;
    }
    repo.image_tags.get(reference).cloned()
}
