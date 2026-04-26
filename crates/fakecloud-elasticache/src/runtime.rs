use std::collections::HashMap;
use std::time::Duration;

use parking_lot::RwLock;

#[derive(Debug, Clone)]
pub struct RunningCacheContainer {
    pub container_id: String,
    pub host_port: u16,
}

#[derive(Debug, Clone, Copy)]
enum CacheEngineKind {
    Redis,
    Memcached,
}

pub struct ElastiCacheRuntime {
    cli: String,
    containers: RwLock<HashMap<String, RunningCacheContainer>>,
    instance_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("container runtime is unavailable")]
    Unavailable,
    #[error("container failed to start: {0}")]
    ContainerStartFailed(String),
}

impl ElastiCacheRuntime {
    pub fn new() -> Option<Self> {
        let cli = if let Ok(cli) = std::env::var("FAKECLOUD_CONTAINER_CLI") {
            if cli_available(&cli) {
                cli
            } else {
                return None;
            }
        } else if cli_available("docker") {
            "docker".to_string()
        } else if cli_available("podman") {
            "podman".to_string()
        } else {
            return None;
        };

        Some(Self {
            cli,
            containers: RwLock::new(HashMap::new()),
            instance_id: format!("fakecloud-{}", std::process::id()),
        })
    }

    pub fn cli_name(&self) -> &str {
        &self.cli
    }

    pub async fn ensure_redis(
        &self,
        resource_id: &str,
    ) -> Result<RunningCacheContainer, RuntimeError> {
        self.spawn_container(resource_id, "redis:7-alpine", 6379, CacheEngineKind::Redis)
            .await
    }

    pub async fn ensure_memcached(
        &self,
        resource_id: &str,
    ) -> Result<RunningCacheContainer, RuntimeError> {
        self.spawn_container(
            resource_id,
            "memcached:1.6-alpine",
            11211,
            CacheEngineKind::Memcached,
        )
        .await
    }

    async fn spawn_container(
        &self,
        resource_id: &str,
        image: &str,
        container_port: u16,
        engine: CacheEngineKind,
    ) -> Result<RunningCacheContainer, RuntimeError> {
        self.stop_container(resource_id).await;

        let output = tokio::process::Command::new(&self.cli)
            .args([
                "create",
                "-p",
                &format!(":{container_port}"),
                "--label",
                &format!("fakecloud-elasticache={resource_id}"),
                "--label",
                &format!("fakecloud-instance={}", self.instance_id),
                image,
            ])
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;

        if !output.status.success() {
            return Err(RuntimeError::ContainerStartFailed(
                String::from_utf8_lossy(&output.stderr).trim().to_string(),
            ));
        }

        let container_id = String::from_utf8_lossy(&output.stdout).trim().to_string();
        let start_result = tokio::process::Command::new(&self.cli)
            .args(["start", &container_id])
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;

        if !start_result.status.success() {
            self.remove_container(&container_id).await;
            return Err(RuntimeError::ContainerStartFailed(format!(
                "container start failed: {}",
                String::from_utf8_lossy(&start_result.stderr).trim()
            )));
        }

        let host_port = match self.lookup_port(&container_id, container_port).await {
            Ok(host_port) => host_port,
            Err(error) => {
                self.remove_container(&container_id).await;
                return Err(error);
            }
        };

        let wait_result = match engine {
            CacheEngineKind::Redis => self.wait_for_redis(host_port).await,
            CacheEngineKind::Memcached => self.wait_for_memcached(host_port).await,
        };
        if let Err(error) = wait_result {
            self.remove_container(&container_id).await;
            return Err(error);
        }

        let running = RunningCacheContainer {
            container_id,
            host_port,
        };
        self.containers
            .write()
            .insert(resource_id.to_string(), running.clone());
        Ok(running)
    }

    pub async fn stop_container(&self, resource_id: &str) {
        let container = self.containers.write().remove(resource_id);
        if let Some(container) = container {
            self.remove_container(&container.container_id).await;
        }
    }

    pub async fn stop_all(&self) {
        let containers: Vec<String> = {
            let mut containers = self.containers.write();
            containers
                .drain()
                .map(|(_, container)| container.container_id)
                .collect()
        };
        for container_id in containers {
            self.remove_container(&container_id).await;
        }
    }

    async fn lookup_port(
        &self,
        container_id: &str,
        container_port: u16,
    ) -> Result<u16, RuntimeError> {
        let port_output = tokio::process::Command::new(&self.cli)
            .args(["port", container_id, &container_port.to_string()])
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;

        if !port_output.status.success() {
            let stderr = String::from_utf8_lossy(&port_output.stderr);
            return Err(RuntimeError::ContainerStartFailed(format!(
                "port lookup failed: {stderr}"
            )));
        }

        let port_str = String::from_utf8_lossy(&port_output.stdout);
        port_str
            .trim()
            .rsplit(':')
            .next()
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| {
                RuntimeError::ContainerStartFailed(format!(
                    "could not determine redis port from '{}'",
                    port_str.trim()
                ))
            })
    }

    async fn wait_for_redis(&self, host_port: u16) -> Result<(), RuntimeError> {
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            if tokio::net::TcpStream::connect(format!("127.0.0.1:{host_port}"))
                .await
                .is_ok()
            {
                return Ok(());
            }
        }

        Err(RuntimeError::ContainerStartFailed(
            "redis container did not become ready within 20 seconds".to_string(),
        ))
    }

    async fn wait_for_memcached(&self, host_port: u16) -> Result<(), RuntimeError> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let Ok(mut stream) =
                tokio::net::TcpStream::connect(format!("127.0.0.1:{host_port}")).await
            else {
                continue;
            };
            if stream.write_all(b"version\r\n").await.is_err() {
                continue;
            }
            let mut buf = [0u8; 32];
            match tokio::time::timeout(Duration::from_secs(2), stream.read(&mut buf)).await {
                Ok(Ok(n)) if n > 0 && buf.starts_with(b"VERSION") => return Ok(()),
                _ => continue,
            }
        }

        Err(RuntimeError::ContainerStartFailed(
            "memcached container did not become ready within 20 seconds".to_string(),
        ))
    }

    async fn remove_container(&self, container_id: &str) {
        let _ = tokio::process::Command::new(&self.cli)
            .args(["rm", "-f", container_id])
            .output()
            .await;
    }
}

fn cli_available(cli: &str) -> bool {
    std::process::Command::new(cli)
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}
