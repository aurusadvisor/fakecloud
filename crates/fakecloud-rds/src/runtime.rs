use std::collections::HashMap;
use std::time::Duration;

use parking_lot::RwLock;
use tokio_postgres::NoTls;

#[derive(Debug, Clone)]
pub struct RunningDbContainer {
    pub container_id: String,
    pub host_port: u16,
}

pub struct RdsRuntime {
    cli: String,
    containers: RwLock<HashMap<String, RunningDbContainer>>,
    instance_id: String,
}

#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    #[error("container runtime is unavailable")]
    Unavailable,
    #[error("container failed to start: {0}")]
    ContainerStartFailed(String),
}

impl RdsRuntime {
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

    pub async fn ensure_postgres(
        &self,
        db_instance_identifier: &str,
        engine: &str,
        engine_version: &str,
        username: &str,
        password: &str,
        db_name: &str,
    ) -> Result<RunningDbContainer, RuntimeError> {
        self.stop_container(db_instance_identifier).await;

        // Determine Docker image and port based on engine
        let (image, port, env_vars) = match engine {
            "postgres" => {
                let major_version = engine_version.split('.').next().unwrap_or("16");
                let image = format!("postgres:{}-alpine", major_version);
                let env_vars = vec![
                    format!("POSTGRES_USER={username}"),
                    format!("POSTGRES_PASSWORD={password}"),
                    format!("POSTGRES_DB={db_name}"),
                ];
                (image, "5432", env_vars)
            }
            "mysql" => {
                let major_version = if engine_version.starts_with("5.7") {
                    "5.7"
                } else {
                    "8.0"
                };
                let image = format!("mysql:{}", major_version);
                let env_vars = vec![
                    format!("MYSQL_ROOT_PASSWORD={password}"),
                    format!("MYSQL_USER={username}"),
                    format!("MYSQL_PASSWORD={password}"),
                    format!("MYSQL_DATABASE={db_name}"),
                ];
                (image, "3306", env_vars)
            }
            "mariadb" => {
                let major_version = if engine_version.starts_with("10.11") {
                    "10.11"
                } else {
                    "10.6"
                };
                let image = format!("mariadb:{}", major_version);
                let env_vars = vec![
                    format!("MARIADB_ROOT_PASSWORD={password}"),
                    format!("MARIADB_USER={username}"),
                    format!("MARIADB_PASSWORD={password}"),
                    format!("MARIADB_DATABASE={db_name}"),
                ];
                (image, "3306", env_vars)
            }
            "oracle-ee" | "oracle-se2" | "oracle-ee-cdb" | "oracle-se2-cdb" => {
                // Oracle Database Free is the no-cost dev edition shipped by
                // Oracle. The container exposes a "FREEPDB1" pluggable
                // database and creates the SYSTEM user with the password
                // from ORACLE_PASSWORD.
                let image = "gvenzl/oracle-free:23-slim".to_string();
                let env_vars = vec![
                    format!("ORACLE_PASSWORD={password}"),
                    format!("APP_USER={username}"),
                    format!("APP_USER_PASSWORD={password}"),
                    format!("ORACLE_DATABASE={db_name}"),
                ];
                (image, "1521", env_vars)
            }
            "sqlserver-ee" | "sqlserver-se" | "sqlserver-ex" | "sqlserver-web" => {
                // SQL Server Express is free for dev/test with no license
                // ceiling. SA password must satisfy MSSQL's complexity
                // requirements (>=8 chars, mix of classes); callers should
                // supply one that does or the container will refuse to
                // start.
                let image = "mcr.microsoft.com/mssql/server:2022-latest".to_string();
                let env_vars = vec![
                    "ACCEPT_EULA=Y".to_string(),
                    format!("MSSQL_SA_PASSWORD={password}"),
                    "MSSQL_PID=Express".to_string(),
                ];
                (image, "1433", env_vars)
            }
            "db2-se" | "db2-ae" => {
                // Db2 Community Edition is free under the standard IBM
                // Community License. The container exposes a single
                // database named after DBNAME, owned by db2inst1.
                let image = "icr.io/db2_community/db2:latest".to_string();
                let env_vars = vec![
                    "LICENSE=accept".to_string(),
                    "DB2INSTANCE=db2inst1".to_string(),
                    format!("DB2INST1_PASSWORD={password}"),
                    format!("DBNAME={db_name}"),
                ];
                (image, "50000", env_vars)
            }
            _ => {
                return Err(RuntimeError::ContainerStartFailed(format!(
                    "Unsupported engine: {}",
                    engine
                )))
            }
        };

        // Db2 needs --privileged to set kernel parameters during startup.
        let needs_privileged = matches!(engine, "db2-se" | "db2-ae");

        // Build container create args
        let mut args = vec![
            "create".to_string(),
            "-p".to_string(),
            format!(":{}", port),
            "--label".to_string(),
            format!("fakecloud-rds={db_instance_identifier}"),
            "--label".to_string(),
            format!("fakecloud-instance={}", self.instance_id),
        ];

        if needs_privileged {
            args.push("--privileged".to_string());
        }

        for env_var in env_vars {
            args.push("-e".to_string());
            args.push(env_var);
        }

        args.push(image);

        let output = tokio::process::Command::new(&self.cli)
            .args(&args)
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

        let host_port = match self.lookup_port(&container_id, port).await {
            Ok(host_port) => host_port,
            Err(error) => {
                self.remove_container(&container_id).await;
                return Err(error);
            }
        };

        // Wait for database to be ready
        let wait_result = match engine {
            "postgres" => {
                self.wait_for_postgres(username, password, db_name, host_port)
                    .await
            }
            "mysql" | "mariadb" => {
                self.wait_for_mysql(username, password, db_name, host_port)
                    .await
            }
            "oracle-ee" | "oracle-se2" | "oracle-ee-cdb" | "oracle-se2-cdb" => {
                self.wait_for_oracle(&container_id, host_port).await
            }
            "sqlserver-ee" | "sqlserver-se" | "sqlserver-ex" | "sqlserver-web" => {
                self.wait_for_sqlserver(&container_id, host_port).await
            }
            "db2-se" | "db2-ae" => self.wait_for_db2(&container_id, host_port).await,
            _ => unreachable!("engine already validated"),
        };

        if let Err(error) = wait_result {
            self.remove_container(&container_id).await;
            return Err(error);
        }

        let running = RunningDbContainer {
            container_id,
            host_port,
        };
        self.containers
            .write()
            .insert(db_instance_identifier.to_string(), running.clone());
        Ok(running)
    }

    pub async fn stop_container(&self, db_instance_identifier: &str) {
        let container = self.containers.write().remove(db_instance_identifier);
        if let Some(container) = container {
            self.remove_container(&container.container_id).await;
        }
    }

    pub async fn restart_container(
        &self,
        db_instance_identifier: &str,
        engine: &str,
        username: &str,
        password: &str,
        db_name: &str,
    ) -> Result<RunningDbContainer, RuntimeError> {
        let running = self
            .containers
            .read()
            .get(db_instance_identifier)
            .cloned()
            .ok_or(RuntimeError::Unavailable)?;

        let output = tokio::process::Command::new(&self.cli)
            .args(["restart", &running.container_id])
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;

        if !output.status.success() {
            return Err(RuntimeError::ContainerStartFailed(format!(
                "container restart failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }

        let port = match engine {
            "postgres" => "5432",
            "mysql" | "mariadb" => "3306",
            "oracle-ee" | "oracle-se2" | "oracle-ee-cdb" | "oracle-se2-cdb" => "1521",
            "sqlserver-ee" | "sqlserver-se" | "sqlserver-ex" | "sqlserver-web" => "1433",
            "db2-se" | "db2-ae" => "50000",
            _ => "5432", // fallback
        };

        let host_port = self.lookup_port(&running.container_id, port).await?;

        match engine {
            "postgres" => {
                self.wait_for_postgres(username, password, db_name, host_port)
                    .await?
            }
            "mysql" | "mariadb" => {
                self.wait_for_mysql(username, password, db_name, host_port)
                    .await?
            }
            "oracle-ee" | "oracle-se2" | "oracle-ee-cdb" | "oracle-se2-cdb" => {
                self.wait_for_oracle(&running.container_id, host_port)
                    .await?
            }
            "sqlserver-ee" | "sqlserver-se" | "sqlserver-ex" | "sqlserver-web" => {
                self.wait_for_sqlserver(&running.container_id, host_port)
                    .await?
            }
            "db2-se" | "db2-ae" => self.wait_for_db2(&running.container_id, host_port).await?,
            _ => {
                self.wait_for_postgres(username, password, db_name, host_port)
                    .await?
            }
        };
        let running = RunningDbContainer {
            container_id: running.container_id,
            host_port,
        };
        self.containers
            .write()
            .insert(db_instance_identifier.to_string(), running.clone());
        Ok(running)
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

    async fn lookup_port(&self, container_id: &str, port: &str) -> Result<u16, RuntimeError> {
        let port_output = tokio::process::Command::new(&self.cli)
            .args(["port", container_id, port])
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;

        let port_str = String::from_utf8_lossy(&port_output.stdout);
        port_str
            .trim()
            .rsplit(':')
            .next()
            .and_then(|value| value.parse::<u16>().ok())
            .ok_or_else(|| {
                RuntimeError::ContainerStartFailed(format!(
                    "could not determine container port from '{}'",
                    port_str.trim()
                ))
            })
    }

    async fn wait_for_postgres(
        &self,
        username: &str,
        password: &str,
        db_name: &str,
        host_port: u16,
    ) -> Result<(), RuntimeError> {
        for _ in 0..40 {
            tokio::time::sleep(Duration::from_millis(500)).await;
            let connection_string = format!(
                "host=127.0.0.1 port={host_port} user={username} password={password} dbname={db_name}"
            );
            if let Ok((client, connection)) =
                tokio_postgres::connect(&connection_string, NoTls).await
            {
                tokio::spawn(async move {
                    let _ = connection.await;
                });
                if client.simple_query("SELECT 1").await.is_ok() {
                    return Ok(());
                }
            }
        }

        Err(RuntimeError::ContainerStartFailed(
            "postgres container did not become ready within 20 seconds".to_string(),
        ))
    }

    async fn wait_for_mysql(
        &self,
        username: &str,
        password: &str,
        db_name: &str,
        host_port: u16,
    ) -> Result<(), RuntimeError> {
        use mysql_async::prelude::*;
        use mysql_async::OptsBuilder;

        for attempt in 1..=40 {
            let opts = OptsBuilder::default()
                .ip_or_hostname("127.0.0.1")
                .tcp_port(host_port)
                .user(Some(username))
                .pass(Some(password))
                .db_name(Some(db_name));

            match mysql_async::Conn::new(opts).await {
                Ok(mut conn) => {
                    if conn.query_drop("SELECT 1").await.is_ok() {
                        let _ = conn.disconnect().await;
                        return Ok(());
                    }
                }
                Err(_) => {
                    if attempt < 40 {
                        tokio::time::sleep(Duration::from_millis(500)).await;
                    }
                    continue;
                }
            }
        }

        Err(RuntimeError::ContainerStartFailed(
            "MySQL/MariaDB container did not become ready within 20 seconds".to_string(),
        ))
    }

    /// Wait for Oracle Database Free to finish bootstrapping. The
    /// `gvenzl/oracle-free` image prints `DATABASE IS READY TO USE!`
    /// to stdout once the listener accepts connections, so we poll
    /// `docker logs` until that marker appears (or the deadline elapses).
    /// Oracle XE/Free typically takes 30-90 seconds on first start.
    async fn wait_for_oracle(
        &self,
        container_id: &str,
        host_port: u16,
    ) -> Result<(), RuntimeError> {
        self.wait_for_log_marker(container_id, "DATABASE IS READY TO USE!", 240)
            .await?;
        self.wait_for_tcp(host_port, 30).await
    }

    /// Wait for SQL Server to be ready. The official mssql/server image
    /// emits `SQL Server is now ready for client connections.` once it
    /// accepts TCP connections on 1433.
    async fn wait_for_sqlserver(
        &self,
        container_id: &str,
        host_port: u16,
    ) -> Result<(), RuntimeError> {
        self.wait_for_log_marker(
            container_id,
            "SQL Server is now ready for client connections",
            180,
        )
        .await?;
        self.wait_for_tcp(host_port, 30).await
    }

    /// Wait for Db2 Community Edition to finish setup. The
    /// `icr.io/db2_community/db2` image prints `Setup has completed.`
    /// once the instance is up and the database has been created.
    async fn wait_for_db2(&self, container_id: &str, host_port: u16) -> Result<(), RuntimeError> {
        self.wait_for_log_marker(container_id, "Setup has completed", 360)
            .await?;
        self.wait_for_tcp(host_port, 60).await
    }

    /// Poll `docker logs <container>` until the supplied marker appears
    /// in stdout or stderr. `deadline_secs` caps total wait.
    async fn wait_for_log_marker(
        &self,
        container_id: &str,
        marker: &str,
        deadline_secs: u64,
    ) -> Result<(), RuntimeError> {
        let deadline = std::time::Instant::now() + Duration::from_secs(deadline_secs);
        while std::time::Instant::now() < deadline {
            let output = tokio::process::Command::new(&self.cli)
                .args(["logs", container_id])
                .output()
                .await
                .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;
            let stdout = String::from_utf8_lossy(&output.stdout);
            let stderr = String::from_utf8_lossy(&output.stderr);
            if stdout.contains(marker) || stderr.contains(marker) {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_secs(2)).await;
        }
        Err(RuntimeError::ContainerStartFailed(format!(
            "container did not log '{}' within {} seconds",
            marker, deadline_secs
        )))
    }

    /// TCP-probe the host port until it accepts a connection or the
    /// deadline elapses. Use after `wait_for_log_marker` since the
    /// listener may bind a moment after the readiness log line.
    async fn wait_for_tcp(&self, host_port: u16, deadline_secs: u64) -> Result<(), RuntimeError> {
        let deadline = std::time::Instant::now() + Duration::from_secs(deadline_secs);
        while std::time::Instant::now() < deadline {
            if tokio::net::TcpStream::connect(("127.0.0.1", host_port))
                .await
                .is_ok()
            {
                return Ok(());
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        Err(RuntimeError::ContainerStartFailed(format!(
            "TCP probe to 127.0.0.1:{} did not succeed within {}s",
            host_port, deadline_secs
        )))
    }

    async fn remove_container(&self, container_id: &str) {
        let _ = tokio::process::Command::new(&self.cli)
            .args(["rm", "-f", container_id])
            .output()
            .await;
    }

    pub async fn dump_database(
        &self,
        db_instance_identifier: &str,
        engine: &str,
        username: &str,
        password: &str,
        db_name: &str,
    ) -> Result<Vec<u8>, RuntimeError> {
        let container = self
            .containers
            .read()
            .get(db_instance_identifier)
            .cloned()
            .ok_or(RuntimeError::Unavailable)?;

        let args: Vec<String> = match engine {
            "mysql" | "mariadb" => vec![
                "exec".into(),
                container.container_id.clone(),
                "mysqldump".into(),
                "-u".into(),
                username.into(),
                format!("-p{password}"),
                db_name.into(),
            ],
            "postgres" => vec![
                "exec".into(),
                container.container_id.clone(),
                "pg_dump".into(),
                "-U".into(),
                username.into(),
                "-d".into(),
                db_name.into(),
                "--no-password".into(),
            ],
            // Heavy engines don't ship with a portable dump CLI we can
            // shell out to from the host the same way pg_dump and
            // mysqldump are guaranteed available. Surface a clear
            // error so callers (snapshot/read-replica) don't silently
            // run the wrong tool against an Oracle/SQL Server/Db2
            // container.
            "oracle-ee" | "oracle-se2" | "oracle-ee-cdb" | "oracle-se2-cdb" | "sqlserver-ee"
            | "sqlserver-se" | "sqlserver-ex" | "sqlserver-web" | "db2-se" | "db2-ae" => {
                return Err(RuntimeError::ContainerStartFailed(format!(
                    "engine {engine} is not yet supported by the snapshot/read-replica path; \
                     emulator stores the API state but cannot dump the underlying database"
                )));
            }
            other => {
                return Err(RuntimeError::ContainerStartFailed(format!(
                    "engine {other} is not supported by dump_database"
                )));
            }
        };

        let output = tokio::process::Command::new(&self.cli)
            .args(&args)
            .output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;

        if !output.status.success() {
            return Err(RuntimeError::ContainerStartFailed(format!(
                "dump failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }

        Ok(output.stdout)
    }

    pub async fn restore_database(
        &self,
        db_instance_identifier: &str,
        engine: &str,
        username: &str,
        password: &str,
        db_name: &str,
        dump_data: &[u8],
    ) -> Result<(), RuntimeError> {
        let container = self
            .containers
            .read()
            .get(db_instance_identifier)
            .cloned()
            .ok_or(RuntimeError::Unavailable)?;

        let args: Vec<String> = match engine {
            "mysql" | "mariadb" => vec![
                "exec".into(),
                "-i".into(),
                container.container_id.clone(),
                "mysql".into(),
                "-u".into(),
                username.into(),
                format!("-p{password}"),
                db_name.into(),
            ],
            "postgres" => vec![
                "exec".into(),
                "-i".into(),
                container.container_id.clone(),
                "psql".into(),
                "-U".into(),
                username.into(),
                "-d".into(),
                db_name.into(),
                "--no-password".into(),
                "-v".into(),
                "ON_ERROR_STOP=1".into(),
            ],
            "oracle-ee" | "oracle-se2" | "oracle-ee-cdb" | "oracle-se2-cdb" | "sqlserver-ee"
            | "sqlserver-se" | "sqlserver-ex" | "sqlserver-web" | "db2-se" | "db2-ae" => {
                return Err(RuntimeError::ContainerStartFailed(format!(
                    "engine {engine} is not yet supported by the snapshot-restore path"
                )));
            }
            other => {
                return Err(RuntimeError::ContainerStartFailed(format!(
                    "engine {other} is not supported by restore_database"
                )));
            }
        };

        let mut child = tokio::process::Command::new(&self.cli)
            .args(&args)
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;

        if let Some(mut stdin) = child.stdin.take() {
            use tokio::io::AsyncWriteExt;
            stdin
                .write_all(dump_data)
                .await
                .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;
            drop(stdin);
        }

        let output = child
            .wait_with_output()
            .await
            .map_err(|e| RuntimeError::ContainerStartFailed(e.to_string()))?;

        if !output.status.success() {
            return Err(RuntimeError::ContainerStartFailed(format!(
                "restore failed: {}",
                String::from_utf8_lossy(&output.stderr).trim()
            )));
        }

        Ok(())
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
