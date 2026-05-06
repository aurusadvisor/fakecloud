use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::Engine;
use parking_lot::RwLock;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use crate::state::LambdaFunction;

/// A running container kept warm for reuse.
struct WarmContainer {
    container_id: String,
    host_port: u16,
    last_used: RwLock<Instant>,
    /// Combined fingerprint of the function's code SHA-256 plus the
    /// SHA-256 of every attached layer's ZIP bytes, joined in attach
    /// order. Layers mutate `/opt`, so a layer change invalidates the
    /// warm container even when the function code is unchanged.
    deploy_id: String,
}

/// Compute the warm-container key for a function with its current layer
/// set. Stable across calls — layer ARNs are immutable in AWS, so the
/// hash of their bytes is the right cache key.
fn deploy_id_for(func: &LambdaFunction, layers: &[Vec<u8>]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(func.code_sha256.as_bytes());
    for bytes in layers {
        let mut layer_hasher = Sha256::new();
        layer_hasher.update(bytes);
        hasher.update(b":");
        hasher.update(layer_hasher.finalize());
    }
    base64::Engine::encode(
        &base64::engine::general_purpose::STANDARD,
        hasher.finalize(),
    )
}

/// Docker/Podman-based Lambda execution engine.
pub struct ContainerRuntime {
    cli: String,
    containers: RwLock<HashMap<String, WarmContainer>>,
    /// Serializes container startup per function to prevent duplicate containers.
    starting: RwLock<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    instance_id: String,
    /// IP address that containers should use to reach the host
    host_ip: String,
    /// Port the main fakecloud server bound to. Used to translate AWS
    /// private-ECR URIs in `PackageType=Image` functions to fakecloud's
    /// local OCI v2 registry.
    server_port: u16,
    /// Isolated DOCKER_CONFIG dir with Basic auth for `127.0.0.1:<port>`.
    /// Lets `docker pull` talk to fakecloud ECR without mutating the user's
    /// `~/.docker/config.json`.
    docker_config: Option<Arc<TempDir>>,
}

/// Wrapper around an in-flight streaming invocation. Yields raw body
/// chunks via [`Self::next_chunk`] until the RIE closes the response,
/// at which point the final `Ok(None)` signals the caller to emit the
/// terminal `InvokeComplete` frame.
pub struct StreamingInvocation {
    resp: reqwest::Response,
}

impl StreamingInvocation {
    /// Read the next chunk of the function's response body. Returns
    /// `Ok(None)` once the RIE has finished streaming. Buffered
    /// handlers tend to deliver a single chunk; streaming handlers
    /// deliver one chunk per `responseStream.write(...)` call.
    pub async fn next_chunk(&mut self) -> Result<Option<bytes::Bytes>, RuntimeError> {
        match self.resp.chunk().await {
            Ok(Some(b)) => Ok(Some(b)),
            Ok(None) => Ok(None),
            Err(e) => Err(RuntimeError::InvocationFailed(e.to_string())),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("no code ZIP provided for function {0}")]
    NoCodeZip(String),
    #[error("unsupported runtime: {0}")]
    UnsupportedRuntime(String),
    #[error("container failed to start: {0}")]
    ContainerStartFailed(String),
    #[error("invocation failed: {0}")]
    InvocationFailed(String),
    #[error("ZIP extraction failed: {0}")]
    ZipExtractionFailed(String),
}

impl ContainerRuntime {
    /// Auto-detect Docker or Podman. Returns `None` if neither is available.
    /// Override with `FAKECLOUD_CONTAINER_CLI` env var.
    /// `server_port` is the port the main fakecloud server bound to; used
    /// to resolve `PackageType=Image` ECR URIs against fakecloud ECR.
    pub fn new(server_port: u16) -> Option<Self> {
        let cli = if let Ok(cli) = std::env::var("FAKECLOUD_CONTAINER_CLI") {
            // Verify the configured CLI works
            if std::process::Command::new(&cli)
                .arg("info")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false)
            {
                cli
            } else {
                return None;
            }
        } else if is_cli_available("docker") {
            "docker".to_string()
        } else if is_cli_available("podman") {
            "podman".to_string()
        } else {
            return None;
        };

        let instance_id = format!("fakecloud-{}", std::process::id());

        // Detect the appropriate host address for containers
        // On Linux, use the bridge gateway IP directly (more reliable)
        // On Mac/Windows, use host-gateway which Docker Desktop handles
        let host_ip = if cfg!(target_os = "linux") {
            detect_bridge_gateway(&cli).unwrap_or_else(|| "172.17.0.1".to_string())
        } else {
            "host-gateway".to_string()
        };

        let docker_config = build_local_registry_docker_config(server_port).map(Arc::new);
        Some(Self {
            cli,
            containers: RwLock::new(HashMap::new()),
            starting: RwLock::new(HashMap::new()),
            instance_id,
            host_ip,
            server_port,
            docker_config,
        })
    }

    fn docker_config_path(&self) -> Option<PathBuf> {
        self.docker_config.as_ref().map(|d| d.path().to_path_buf())
    }

    pub fn cli_name(&self) -> &str {
        &self.cli
    }

    /// Invoke a Lambda function, starting a container if needed. Layer
    /// ZIPs are extracted into `/opt` of the runtime sandbox; AWS base
    /// images already include `/opt/python`, `/opt/nodejs/node_modules`,
    /// `/opt/lib`, and `/opt/bin` on the right import paths.
    pub async fn invoke(
        &self,
        func: &LambdaFunction,
        payload: &[u8],
        layers: &[Vec<u8>],
    ) -> Result<Vec<u8>, RuntimeError> {
        let port = self.ensure_warm_container(func, layers).await?;

        // POST to the RIE endpoint
        let url = format!(
            "http://localhost:{}/2015-03-31/functions/function/invocations",
            port
        );
        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .body(payload.to_vec())
            .timeout(Duration::from_secs(func.timeout as u64 + 5))
            .send()
            .await
            .map_err(|e| RuntimeError::InvocationFailed(e.to_string()))?;

        let body = resp
            .bytes()
            .await
            .map_err(|e| RuntimeError::InvocationFailed(e.to_string()))?;

        Ok(body.to_vec())
    }

    /// Invoke a Lambda function and yield the raw HTTP body as a stream
    /// of byte chunks. Each chunk corresponds to one HTTP frame the RIE
    /// flushed to the wire — for streaming-aware handlers (Node.js
    /// `awslambda.streamifyResponse`, Python streaming response, custom
    /// runtimes that flush mid-handler) this preserves the chunk
    /// boundaries the function emitted. Buffered handlers come back as
    /// a single chunk, which is still a valid streamed response.
    pub async fn invoke_streaming(
        &self,
        func: &LambdaFunction,
        payload: &[u8],
        layers: &[Vec<u8>],
    ) -> Result<StreamingInvocation, RuntimeError> {
        let port = self.ensure_warm_container(func, layers).await?;

        let url = format!(
            "http://localhost:{}/2015-03-31/functions/function/invocations",
            port
        );
        let client = reqwest::Client::new();
        let resp = client
            .post(&url)
            .body(payload.to_vec())
            .timeout(Duration::from_secs(func.timeout as u64 + 5))
            .send()
            .await
            .map_err(|e| RuntimeError::InvocationFailed(e.to_string()))?;

        Ok(StreamingInvocation { resp })
    }

    /// Resolve a warm container for `func`, starting one if its
    /// fingerprint doesn't match (or there isn't one yet). Returns the
    /// host port the RIE is bound to. Shared by `invoke` and
    /// `invoke_streaming` so both paths use the same warm-pool logic.
    async fn ensure_warm_container(
        &self,
        func: &LambdaFunction,
        layers: &[Vec<u8>],
    ) -> Result<u16, RuntimeError> {
        // Zip-based functions need code bytes; image-based functions have
        // everything baked into the image. Defer the zip check until we
        // know we need to start a fresh container.
        let is_image = func.package_type == "Image";
        if !is_image && func.code_zip.is_none() {
            return Err(RuntimeError::NoCodeZip(func.function_name.clone()));
        }

        let deploy_id = deploy_id_for(func, layers);

        // Check for warm container with matching deploy fingerprint
        let port = {
            let containers = self.containers.read();
            if let Some(container) = containers.get(&func.function_name) {
                if container.deploy_id == deploy_id {
                    *container.last_used.write() = Instant::now();
                    Some(container.host_port)
                } else {
                    None
                }
            } else {
                None
            }
        };

        if let Some(p) = port {
            return Ok(p);
        }

        // Serialize container startup per function to prevent duplicates
        let startup_lock = {
            let mut starting = self.starting.write();
            starting
                .entry(func.function_name.clone())
                .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
                .clone()
        };
        let _guard = startup_lock.lock().await;

        // Re-check after acquiring lock — another task may have started it
        let existing_port = {
            let containers = self.containers.read();
            containers
                .get(&func.function_name)
                .filter(|c| c.deploy_id == deploy_id)
                .map(|c| {
                    *c.last_used.write() = Instant::now();
                    c.host_port
                })
        };
        if let Some(p) = existing_port {
            return Ok(p);
        }

        self.stop_container(&func.function_name).await;
        let container = if is_image {
            self.start_image_container(func, layers, &deploy_id).await?
        } else {
            let zip_bytes = func
                .code_zip
                .as_ref()
                .ok_or_else(|| RuntimeError::NoCodeZip(func.function_name.clone()))?;
            self.start_container(func, zip_bytes, layers, &deploy_id)
                .await?
        };
        let p = container.host_port;
        self.containers
            .write()
            .insert(func.function_name.clone(), container);
        Ok(p)
    }

    /// Start a container for a `PackageType=Image` function. The image is
    /// expected to already embed the Runtime Interface Emulator (RIE) or
    /// an equivalent, exposing port 8080 — that's the AWS convention for
    /// container-based Lambda. AWS private-ECR URIs get translated to
    /// fakecloud's local OCI v2 registry and retagged so the container
    /// reports its user-visible image name.
    async fn start_image_container(
        &self,
        func: &LambdaFunction,
        layers: &[Vec<u8>],
        deploy_id: &str,
    ) -> Result<WarmContainer, RuntimeError> {
        let image = func.image_uri.as_deref().ok_or_else(|| {
            RuntimeError::ContainerStartFailed("PackageType=Image function has no ImageUri".into())
        })?;

        // Translate AWS private-ECR URIs to fakecloud ECR's local endpoint.
        let local_pull_uri = fakecloud_core::ecr_uri::translate_to_local(image, self.server_port);
        let pull_uri = local_pull_uri.as_deref().unwrap_or(image);

        let mut pull_cmd = tokio::process::Command::new(&self.cli);
        if let Some(p) = self.docker_config_path() {
            pull_cmd.env("DOCKER_CONFIG", p);
        }
        let pull_out = pull_cmd
            .args(["pull", pull_uri])
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(format!("docker pull: {e}")))?;
        if !pull_out.status.success() {
            return Err(RuntimeError::ContainerStartFailed(format!(
                "docker pull failed: {}",
                String::from_utf8_lossy(&pull_out.stderr)
            )));
        }
        // Retag the local pull URI to the AWS URI so `docker create`
        // finds the image under the user-visible name. Digest-pinned
        // refs can't be `docker tag` targets, so fall through and
        // create under the local URI instead.
        let run_image = if let Some(ref local_uri) = local_pull_uri {
            if fakecloud_core::ecr_uri::is_digest_ref(image) {
                local_uri.clone()
            } else {
                let _ = tokio::process::Command::new(&self.cli)
                    .args(["tag", local_uri, image])
                    .output()
                    .await;
                image.to_string()
            }
        } else {
            image.to_string()
        };

        let mut cmd = tokio::process::Command::new(&self.cli);
        cmd.arg("create")
            .arg("-p")
            .arg(":8080")
            .arg("--label")
            .arg(format!("fakecloud-lambda={}", func.function_name))
            .arg("--label")
            .arg(format!("fakecloud-instance={}", self.instance_id))
            .arg("--add-host")
            .arg(format!("host.docker.internal:{}", self.host_ip));

        for (key, value) in &func.environment {
            let transformed_value = value
                .replace("http://127.0.0.1:", "http://host.docker.internal:")
                .replace("https://127.0.0.1:", "https://host.docker.internal:")
                .replace("http://localhost:", "http://host.docker.internal:")
                .replace("https://localhost:", "https://host.docker.internal:");
            cmd.arg("-e").arg(format!("{}={}", key, transformed_value));
        }
        cmd.arg("-e")
            .arg(format!("AWS_LAMBDA_FUNCTION_TIMEOUT={}", func.timeout));

        // EphemeralStorage.Size (MiB) maps to a tmpfs at /tmp so
        // function code that writes there hits the configured limit
        // instead of the docker default. Default 512 MiB matches AWS.
        // `exec` matches AWS Lambda's /tmp behavior (binaries unpacked
        // there can be invoked); the default `noexec` would break that.
        let tmpfs_arg = ephemeral_storage_tmpfs_arg(func.ephemeral_storage_size);
        cmd.arg("--tmpfs").arg(tmpfs_arg);

        cmd.arg(&run_image);

        let output = cmd
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;
        if !output.status.success() {
            return Err(RuntimeError::ContainerStartFailed(
                String::from_utf8_lossy(&output.stderr).to_string(),
            ));
        }
        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

        if let Err(e) = self.copy_layers_into(&container_id, layers).await {
            let _ = self.remove_container(&container_id).await;
            return Err(e);
        }

        let start_result = tokio::process::Command::new(&self.cli)
            .args(["start", &container_id])
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;
        if !start_result.status.success() {
            let _ = self.remove_container(&container_id).await;
            return Err(RuntimeError::ContainerStartFailed(format!(
                "docker start failed: {}",
                String::from_utf8_lossy(&start_result.stderr)
            )));
        }

        let port_output = tokio::process::Command::new(&self.cli)
            .args(["port", &container_id, "8080"])
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;
        let port_str = String::from_utf8_lossy(&port_output.stdout);
        let port: u16 = port_str
            .trim()
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .ok_or_else(|| {
                RuntimeError::ContainerStartFailed(format!(
                    "could not determine port from: {}",
                    port_str.trim()
                ))
            })?;

        let mut ready = false;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .is_ok()
            {
                ready = true;
                break;
            }
        }
        if !ready {
            let _ = self.remove_container(&container_id).await;
            return Err(RuntimeError::ContainerStartFailed(
                "container did not become ready within 10 seconds".to_string(),
            ));
        }

        tracing::info!(
            function = %func.function_name,
            container_id = %container_id,
            port = port,
            image = %image,
            "Lambda image container started"
        );

        Ok(WarmContainer {
            container_id,
            host_port: port,
            last_used: RwLock::new(Instant::now()),
            deploy_id: deploy_id.to_string(),
        })
    }

    async fn start_container(
        &self,
        func: &LambdaFunction,
        zip_bytes: &[u8],
        layers: &[Vec<u8>],
        deploy_id: &str,
    ) -> Result<WarmContainer, RuntimeError> {
        let image = runtime_to_image(&func.runtime)
            .ok_or_else(|| RuntimeError::UnsupportedRuntime(func.runtime.clone()))?;

        // Extract ZIP to a temp directory (only needed during container setup).
        // Run in spawn_blocking to avoid blocking the async runtime with fs I/O.
        let code_dir =
            TempDir::new().map_err(|e| RuntimeError::ZipExtractionFailed(e.to_string()))?;
        let zip_bytes = zip_bytes.to_vec();
        let code_path = code_dir.path().to_path_buf();
        tokio::task::spawn_blocking(move || extract_zip(&zip_bytes, &code_path))
            .await
            .map_err(|e| RuntimeError::ZipExtractionFailed(e.to_string()))??;

        // Step 1: docker create (no volume mounts — works in Docker-in-Docker)
        let mut cmd = tokio::process::Command::new(&self.cli);
        cmd.arg("create")
            .arg("-p")
            .arg(":8080")
            .arg("--label")
            .arg(format!("fakecloud-lambda={}", func.function_name))
            .arg("--label")
            .arg(format!("fakecloud-instance={}", self.instance_id))
            // Map host.docker.internal to the detected host IP (bridge gateway on Linux, or explicit IP)
            .arg("--add-host")
            .arg(format!("host.docker.internal:{}", self.host_ip));

        for (key, value) in &func.environment {
            // Transform localhost URLs to use host.docker.internal, which we've set up via --add-host
            let transformed_value = value
                .replace("http://127.0.0.1:", "http://host.docker.internal:")
                .replace("https://127.0.0.1:", "https://host.docker.internal:")
                .replace("http://localhost:", "http://host.docker.internal:")
                .replace("https://localhost:", "https://host.docker.internal:");
            cmd.arg("-e").arg(format!("{}={}", key, transformed_value));
        }

        cmd.arg("-e")
            .arg(format!("AWS_LAMBDA_FUNCTION_TIMEOUT={}", func.timeout));

        // EphemeralStorage.Size (MiB) maps to a tmpfs at /tmp so
        // function code that writes there hits the configured limit
        // instead of the docker default. Default 512 MiB matches AWS.
        // `exec` matches AWS Lambda's /tmp behavior (binaries unpacked
        // there can be invoked); the default `noexec` would break that.
        let tmpfs_arg = ephemeral_storage_tmpfs_arg(func.ephemeral_storage_size);
        cmd.arg("--tmpfs").arg(tmpfs_arg);

        cmd.arg(&image).arg(&func.handler);

        let output = cmd
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;

        if !output.status.success() {
            let stderr = String::from_utf8_lossy(&output.stderr);
            return Err(RuntimeError::ContainerStartFailed(stderr.to_string()));
        }

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();

        // Step 2: docker cp — copy code into the container
        let cp_result = tokio::process::Command::new(&self.cli)
            .arg("cp")
            .arg(format!("{}/.", code_dir.path().display()))
            .arg(format!("{}:/var/task", container_id))
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;

        if !cp_result.status.success() {
            let _ = self.remove_container(&container_id).await;
            let stderr = String::from_utf8_lossy(&cp_result.stderr);
            return Err(RuntimeError::ContainerStartFailed(format!(
                "docker cp failed: {}",
                stderr
            )));
        }

        // For provided/custom runtimes, also copy to /var/runtime
        if func.runtime.starts_with("provided") {
            let cp_runtime = tokio::process::Command::new(&self.cli)
                .arg("cp")
                .arg(format!("{}/.", code_dir.path().display()))
                .arg(format!("{}:/var/runtime", container_id))
                .output()
                .await
                .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;

            if !cp_runtime.status.success() {
                let _ = self.remove_container(&container_id).await;
                let stderr = String::from_utf8_lossy(&cp_runtime.stderr);
                return Err(RuntimeError::ContainerStartFailed(format!(
                    "docker cp to /var/runtime failed: {}",
                    stderr
                )));
            }
        }

        if let Err(e) = self.copy_layers_into(&container_id, layers).await {
            let _ = self.remove_container(&container_id).await;
            return Err(e);
        }

        // TempDir is dropped here — code now lives inside the container

        // Step 3: docker start
        let start_result = tokio::process::Command::new(&self.cli)
            .args(["start", &container_id])
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;

        if !start_result.status.success() {
            let _ = self.remove_container(&container_id).await;
            let stderr = String::from_utf8_lossy(&start_result.stderr);
            return Err(RuntimeError::ContainerStartFailed(format!(
                "docker start failed: {}",
                stderr
            )));
        }

        // Query the actual assigned port
        let port_output = tokio::process::Command::new(&self.cli)
            .args(["port", &container_id, "8080"])
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;

        let port_str = String::from_utf8_lossy(&port_output.stdout);
        let port: u16 = port_str
            .trim()
            .rsplit(':')
            .next()
            .and_then(|p| p.parse().ok())
            .ok_or_else(|| {
                RuntimeError::ContainerStartFailed(format!(
                    "could not determine port from: {}",
                    port_str.trim()
                ))
            })?;

        // Wait for RIE to start accepting connections
        let mut ready = false;
        for _ in 0..20 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if tokio::net::TcpStream::connect(format!("127.0.0.1:{}", port))
                .await
                .is_ok()
            {
                ready = true;
                break;
            }
        }

        if !ready {
            let _ = self.remove_container(&container_id).await;
            return Err(RuntimeError::ContainerStartFailed(
                "container did not become ready within 10 seconds".to_string(),
            ));
        }

        tracing::info!(
            function = %func.function_name,
            container_id = %container_id,
            port = port,
            runtime = %func.runtime,
            "Lambda container started"
        );

        Ok(WarmContainer {
            container_id,
            host_port: port,
            last_used: RwLock::new(Instant::now()),
            deploy_id: deploy_id.to_string(),
        })
    }

    /// Extract each layer ZIP into a shared temp directory and `docker cp`
    /// it into `/opt/` of the target container. Layer ZIPs include
    /// language-specific subpaths (`python/`, `nodejs/`, `java/`, `lib/`,
    /// `bin/`) that AWS base images already wire onto the runtime's
    /// import paths, so plain extraction at the temp root produces the
    /// correct on-disk layout. Empty `layers` is a no-op.
    async fn copy_layers_into(
        &self,
        container_id: &str,
        layers: &[Vec<u8>],
    ) -> Result<(), RuntimeError> {
        if layers.is_empty() {
            return Ok(());
        }
        let layers_dir =
            TempDir::new().map_err(|e| RuntimeError::ZipExtractionFailed(e.to_string()))?;
        let layers_path = layers_dir.path().to_path_buf();
        let layers_owned: Vec<Vec<u8>> = layers.to_vec();
        tokio::task::spawn_blocking(move || {
            for bytes in &layers_owned {
                extract_zip(bytes, &layers_path)?;
            }
            Ok::<_, RuntimeError>(())
        })
        .await
        .map_err(|e| RuntimeError::ZipExtractionFailed(e.to_string()))??;

        let cp_result = tokio::process::Command::new(&self.cli)
            .arg("cp")
            .arg(format!("{}/.", layers_dir.path().display()))
            .arg(format!("{}:/opt", container_id))
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;
        if !cp_result.status.success() {
            let stderr = String::from_utf8_lossy(&cp_result.stderr);
            return Err(RuntimeError::ContainerStartFailed(format!(
                "docker cp layers to /opt failed: {stderr}"
            )));
        }
        Ok(())
    }

    /// Remove a container (stop + rm, since we don't use --rm with docker create).
    async fn remove_container(&self, container_id: &str) {
        let _ = tokio::process::Command::new(&self.cli)
            .args(["rm", "-f", container_id])
            .output()
            .await;
    }

    /// Stop and remove a container for a specific function.
    pub async fn stop_container(&self, function_name: &str) {
        let container = self.containers.write().remove(function_name);
        if let Some(container) = container {
            tracing::info!(
                function = %function_name,
                container_id = %container.container_id,
                "stopping Lambda container"
            );
            self.remove_container(&container.container_id).await;
        }
    }

    /// Stop and remove all containers (used on server shutdown or reset).
    pub async fn stop_all(&self) {
        let containers: Vec<(String, String)> = {
            let mut map = self.containers.write();
            map.drain()
                .map(|(name, c)| (name, c.container_id))
                .collect()
        };
        for (name, container_id) in containers {
            tracing::info!(
                function = %name,
                container_id = %container_id,
                "stopping Lambda container (cleanup)"
            );
            self.remove_container(&container_id).await;
        }
    }

    /// List all warm containers and their metadata for introspection.
    pub fn list_warm_containers(
        &self,
        lambda_state: &crate::state::SharedLambdaState,
    ) -> Vec<serde_json::Value> {
        let containers = self.containers.read();
        let accounts = lambda_state.read();
        containers
            .iter()
            .map(|(name, container)| {
                let runtime = accounts
                    .iter()
                    .find_map(|(_, state)| state.functions.get(name).map(|f| f.runtime.clone()))
                    .unwrap_or_default();
                let last_used = container.last_used.read();
                let idle_secs = last_used.elapsed().as_secs();
                serde_json::json!({
                    "functionName": name,
                    "runtime": runtime,
                    "containerId": container.container_id,
                    "lastUsedSecsAgo": idle_secs,
                })
            })
            .collect()
    }

    /// Evict (stop and remove) the warm container for a specific function.
    /// Returns true if a container was found and evicted.
    pub async fn evict_container(&self, function_name: &str) -> bool {
        let container = self.containers.write().remove(function_name);
        if let Some(container) = container {
            tracing::info!(
                function = %function_name,
                container_id = %container.container_id,
                "evicting Lambda container via simulation API"
            );
            self.remove_container(&container.container_id).await;
            true
        } else {
            false
        }
    }

    /// Background loop that stops containers idle longer than `ttl`.
    pub async fn run_cleanup_loop(self: Arc<Self>, ttl: Duration) {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        loop {
            interval.tick().await;
            self.cleanup_idle(ttl).await;
        }
    }

    async fn cleanup_idle(&self, ttl: Duration) {
        let expired: Vec<String> = {
            let containers = self.containers.read();
            containers
                .iter()
                .filter(|(_, c)| c.last_used.read().elapsed() > ttl)
                .map(|(name, _)| name.clone())
                .collect()
        };
        for name in expired {
            tracing::info!(function = %name, "stopping idle Lambda container");
            self.stop_container(&name).await;
        }
    }
}

/// Map AWS runtime identifier to a Docker image tag.
pub fn runtime_to_image(runtime: &str) -> Option<String> {
    let (base, tag) = match runtime {
        "python3.14" => ("python", "3.14"),
        "python3.13" => ("python", "3.13"),
        "python3.12" => ("python", "3.12"),
        "python3.11" => ("python", "3.11"),
        "python3.10" => ("python", "3.10"),
        "python3.9" => ("python", "3.9"),
        "python3.8" => ("python", "3.8"),
        "nodejs24.x" => ("nodejs", "24"),
        "nodejs22.x" => ("nodejs", "22"),
        "nodejs20.x" => ("nodejs", "20"),
        "nodejs18.x" => ("nodejs", "18"),
        "nodejs16.x" => ("nodejs", "16"),
        "ruby3.4" => ("ruby", "3.4"),
        "ruby3.3" => ("ruby", "3.3"),
        "java25" => ("java", "25"),
        "java21" => ("java", "21"),
        "java17" => ("java", "17"),
        "java11" => ("java", "11"),
        "dotnet10" => ("dotnet", "10"),
        "dotnet8" => ("dotnet", "8"),
        "go1.x" => ("go", "1"),
        "provided.al2023" => ("provided", "al2023"),
        "provided.al2" => ("provided", "al2"),
        _ => return None,
    };
    Some(format!("public.ecr.aws/lambda/{}:{}", base, tag))
}

/// Build the `--tmpfs` argument string used by `docker create` so that
/// `/tmp` inside the container is sized to the function's
/// `EphemeralStorage.Size`. Pure helper extracted from the container
/// boot path so unit tests can verify the flag without spawning Docker.
///
/// Defaults to AWS's 512 MiB when `size` is `None`, and clamps to a 64
/// MiB minimum so legacy snapshots that smuggled in absurd values still
/// produce a tmpfs Docker accepts. The `exec` mount option matches AWS
/// Lambda's `/tmp` behavior — handlers that unpack and run binaries
/// from `/tmp` would otherwise hit `EACCES` against Docker's default
/// `noexec` tmpfs.
pub(crate) fn ephemeral_storage_tmpfs_arg(size: Option<i64>) -> String {
    let mib = size.unwrap_or(512).max(64);
    format!("/tmp:size={mib}m,exec")
}

/// Extract a ZIP archive to a destination directory.
pub fn extract_zip(zip_bytes: &[u8], dest: &Path) -> Result<(), RuntimeError> {
    let cursor = std::io::Cursor::new(zip_bytes);
    let mut archive = zip::ZipArchive::new(cursor)
        .map_err(|e| RuntimeError::ZipExtractionFailed(e.to_string()))?;

    for i in 0..archive.len() {
        let mut file = archive
            .by_index(i)
            .map_err(|e| RuntimeError::ZipExtractionFailed(e.to_string()))?;

        let out_path = dest.join(file.enclosed_name().ok_or_else(|| {
            RuntimeError::ZipExtractionFailed("invalid file name in ZIP".to_string())
        })?);

        if file.is_dir() {
            std::fs::create_dir_all(&out_path)
                .map_err(|e| RuntimeError::ZipExtractionFailed(e.to_string()))?;
        } else {
            if let Some(parent) = out_path.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| RuntimeError::ZipExtractionFailed(e.to_string()))?;
            }
            let mut out_file = std::fs::File::create(&out_path)
                .map_err(|e| RuntimeError::ZipExtractionFailed(e.to_string()))?;
            std::io::copy(&mut file, &mut out_file)
                .map_err(|e| RuntimeError::ZipExtractionFailed(e.to_string()))?;

            // Preserve executable permissions
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                if let Some(mode) = file.unix_mode() {
                    std::fs::set_permissions(&out_path, std::fs::Permissions::from_mode(mode))
                        .map_err(|e| RuntimeError::ZipExtractionFailed(e.to_string()))?;
                }
            }
        }
    }
    Ok(())
}

/// Detect the Docker bridge gateway IP on Linux.
/// Returns None if detection fails.
fn detect_bridge_gateway(cli: &str) -> Option<String> {
    let output = std::process::Command::new(cli)
        .args([
            "network",
            "inspect",
            "bridge",
            "--format",
            "{{range .IPAM.Config}}{{.Gateway}}{{end}}",
        ])
        .output()
        .ok()?;

    if output.status.success() {
        let gateway = String::from_utf8_lossy(&output.stdout).trim().to_string();
        if !gateway.is_empty() && gateway.contains('.') {
            tracing::info!(
                gateway = %gateway,
                "Detected Docker bridge gateway for Lambda containers"
            );
            return Some(gateway);
        }
    }
    None
}

fn is_cli_available(name: &str) -> bool {
    std::process::Command::new(name)
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn build_local_registry_docker_config(server_port: u16) -> Option<TempDir> {
    let dir = TempDir::new().ok()?;
    let auth = base64::engine::general_purpose::STANDARD.encode("AWS:fakecloud-lambda-runtime");
    let config = serde_json::json!({
        "auths": {
            format!("127.0.0.1:{server_port}"): { "auth": auth },
        }
    });
    std::fs::write(dir.path().join("config.json"), config.to_string()).ok()?;
    Some(dir)
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};

    use super::*;

    #[test]
    fn test_runtime_to_image() {
        assert_eq!(
            runtime_to_image("python3.12"),
            Some("public.ecr.aws/lambda/python:3.12".to_string())
        );
        assert_eq!(
            runtime_to_image("nodejs20.x"),
            Some("public.ecr.aws/lambda/nodejs:20".to_string())
        );
        assert_eq!(
            runtime_to_image("provided.al2023"),
            Some("public.ecr.aws/lambda/provided:al2023".to_string())
        );
        assert_eq!(
            runtime_to_image("ruby3.4"),
            Some("public.ecr.aws/lambda/ruby:3.4".to_string())
        );
        assert_eq!(
            runtime_to_image("java21"),
            Some("public.ecr.aws/lambda/java:21".to_string())
        );
        assert_eq!(
            runtime_to_image("dotnet8"),
            Some("public.ecr.aws/lambda/dotnet:8".to_string())
        );
        assert_eq!(
            runtime_to_image("nodejs16.x"),
            Some("public.ecr.aws/lambda/nodejs:16".to_string())
        );
        assert_eq!(
            runtime_to_image("python3.10"),
            Some("public.ecr.aws/lambda/python:3.10".to_string())
        );
        assert_eq!(
            runtime_to_image("python3.9"),
            Some("public.ecr.aws/lambda/python:3.9".to_string())
        );
        assert_eq!(
            runtime_to_image("python3.8"),
            Some("public.ecr.aws/lambda/python:3.8".to_string())
        );
        assert_eq!(
            runtime_to_image("java11"),
            Some("public.ecr.aws/lambda/java:11".to_string())
        );
        assert_eq!(
            runtime_to_image("go1.x"),
            Some("public.ecr.aws/lambda/go:1".to_string())
        );
        assert_eq!(
            runtime_to_image("nodejs24.x"),
            Some("public.ecr.aws/lambda/nodejs:24".to_string())
        );
        assert_eq!(
            runtime_to_image("python3.14"),
            Some("public.ecr.aws/lambda/python:3.14".to_string())
        );
        assert_eq!(
            runtime_to_image("java25"),
            Some("public.ecr.aws/lambda/java:25".to_string())
        );
        assert_eq!(
            runtime_to_image("dotnet10"),
            Some("public.ecr.aws/lambda/dotnet:10".to_string())
        );
        assert_eq!(runtime_to_image("unknown"), None);
    }

    #[test]
    fn test_extract_zip() {
        // Create a minimal ZIP in memory
        let buf = Vec::new();
        let cursor = std::io::Cursor::new(buf);
        let mut writer = zip::ZipWriter::new(cursor);
        let options = zip::write::SimpleFileOptions::default();
        writer.start_file("handler.py", options).unwrap();
        writer
            .write_all(b"def handler(event, context):\n    return {'statusCode': 200}\n")
            .unwrap();
        let cursor = writer.finish().unwrap();
        let zip_bytes = cursor.into_inner();

        let dir = TempDir::new().unwrap();
        extract_zip(&zip_bytes, dir.path()).unwrap();

        let handler_path = dir.path().join("handler.py");
        assert!(handler_path.exists());

        let mut content = String::new();
        std::fs::File::open(&handler_path)
            .unwrap()
            .read_to_string(&mut content)
            .unwrap();
        assert!(content.contains("def handler"));
    }

    #[test]
    fn ephemeral_storage_tmpfs_arg_defaults_to_512_when_none() {
        // None -> AWS default of 512 MiB. The `exec` flag is required so
        // handlers that unpack and run binaries from /tmp don't hit
        // EACCES against Docker's default `noexec` tmpfs.
        assert_eq!(ephemeral_storage_tmpfs_arg(None), "/tmp:size=512m,exec");
    }

    #[test]
    fn ephemeral_storage_tmpfs_arg_uses_supplied_size() {
        assert_eq!(
            ephemeral_storage_tmpfs_arg(Some(2048)),
            "/tmp:size=2048m,exec"
        );
        assert_eq!(
            ephemeral_storage_tmpfs_arg(Some(10240)),
            "/tmp:size=10240m,exec"
        );
    }

    #[test]
    fn ephemeral_storage_tmpfs_arg_clamps_to_64_floor() {
        // API-level validation already rejects values below 512, but the
        // runtime defends against legacy snapshots and stale state by
        // clamping to a 64 MiB floor that Docker still accepts.
        assert_eq!(ephemeral_storage_tmpfs_arg(Some(0)), "/tmp:size=64m,exec");
        assert_eq!(ephemeral_storage_tmpfs_arg(Some(32)), "/tmp:size=64m,exec");
    }
}
