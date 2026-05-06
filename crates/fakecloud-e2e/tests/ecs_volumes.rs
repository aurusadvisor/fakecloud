//! ECS task definition `volumes[]` + container `mountPoints[]`.
//!
//! Confirms the runtime translates each `mountPoint` into a real
//! `docker run -v <source>:<containerPath>[:ro]` flag, with the source
//! resolved from the task definition's volume kind:
//!
//! - **host bind**: file written by the container is visible on the
//!   host bind path after the task stops.
//! - **EFS stub**: the runtime materialises
//!   `/tmp/fakecloud/efs/<filesystemId>[/<root>]` and binds it; the same
//!   stub is reused across tasks targeting the same filesystem id, so
//!   one task can write a file and another task can read it back.
//!
//! Docker-gated the same way the other ECS runtime tests are.

mod helpers;

use std::time::Duration;

use aws_sdk_ecs::types::{
    ContainerDefinition, EfsVolumeConfiguration, HostVolumeProperties, MountPoint, Volume,
};
use helpers::TestServer;

fn docker_available() -> bool {
    std::process::Command::new("docker")
        .arg("info")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

fn require_docker_or_skip(test: &str) -> bool {
    if docker_available() {
        return true;
    }
    if std::env::var("CI").is_ok() {
        panic!("docker is required for {test} in CI");
    }
    eprintln!("skipping {test}: docker is not available");
    false
}

async fn wait_stopped(ecs: &aws_sdk_ecs::Client, cluster: &str, arn: &str) {
    for _ in 0..120 {
        let desc = ecs
            .describe_tasks()
            .cluster(cluster)
            .tasks(arn)
            .send()
            .await
            .unwrap();
        if desc.tasks()[0].last_status() == Some("STOPPED") {
            return;
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    panic!("task {arn} never reached STOPPED");
}

/// `host.sourcePath` mounts the host directory into the container. A
/// file written by the container shows up on the host path after the
/// task stops, proving the bind mount is real.
#[tokio::test]
async fn ecs_task_with_host_bind_volume_writes_to_host_path() {
    if !require_docker_or_skip("ecs_task_with_host_bind_volume_writes_to_host_path") {
        return;
    }
    let server = TestServer::start().await;
    let ecs = server.ecs_client().await;

    // Per-test temp dir on the host. Tagged with PID + nanos so two
    // concurrent runs of this test don't collide.
    let unique = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let host_dir = std::env::temp_dir().join(format!("fakecloud-ecs-volume-{unique}"));
    std::fs::create_dir_all(&host_dir).unwrap();
    let host_path = host_dir.to_string_lossy().to_string();

    ecs.create_cluster()
        .cluster_name("volume-cluster")
        .send()
        .await
        .unwrap();

    ecs.register_task_definition()
        .family("host-bind-family")
        .volumes(
            Volume::builder()
                .name("data")
                .host(
                    HostVolumeProperties::builder()
                        .source_path(&host_path)
                        .build(),
                )
                .build(),
        )
        .container_definitions(
            ContainerDefinition::builder()
                .name("writer")
                .image("public.ecr.aws/docker/library/alpine:3.20")
                .essential(true)
                .mount_points(
                    MountPoint::builder()
                        .source_volume("data")
                        .container_path("/mnt/data")
                        .read_only(false)
                        .build(),
                )
                .command("sh")
                .command("-c")
                .command("echo hello-from-container > /mnt/data/marker.txt")
                .build(),
        )
        .send()
        .await
        .unwrap();

    let run = ecs
        .run_task()
        .cluster("volume-cluster")
        .task_definition("host-bind-family")
        .send()
        .await
        .unwrap();
    let arn = run.tasks()[0].task_arn().unwrap().to_string();
    wait_stopped(&ecs, "volume-cluster", &arn).await;

    // The container wrote `marker.txt` into `/mnt/data` which is bound
    // to `host_dir` on the host. If the bind mount worked, the file
    // is now sitting on the host filesystem.
    let marker = host_dir.join("marker.txt");
    let body = std::fs::read_to_string(&marker)
        .unwrap_or_else(|e| panic!("expected marker file at {marker:?}: {e}"));
    assert!(
        body.contains("hello-from-container"),
        "unexpected marker contents: {body:?}"
    );

    let _ = std::fs::remove_dir_all(&host_dir);
}

/// `efsVolumeConfiguration` mounts a host-side stub directory under
/// `/tmp/fakecloud/efs/<filesystemId>[/<rootDirectory>]`. Two tasks
/// targeting the same filesystem id share the stub, so a file written
/// by the first task is readable by the second.
#[tokio::test]
async fn ecs_efs_stub_is_shared_across_tasks() {
    if !require_docker_or_skip("ecs_efs_stub_is_shared_across_tasks") {
        return;
    }
    let server = TestServer::start().await;
    let ecs = server.ecs_client().await;

    // Unique fs id per test run so concurrent runs don't see each
    // other's stub state. Real EFS would have an actual lifecycle
    // here; the stub is content-addressed by id, which is enough for
    // E2E parity.
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    let fs_id = format!("fs-{unique:x}");

    ecs.create_cluster()
        .cluster_name("efs-cluster")
        .send()
        .await
        .unwrap();

    // Writer task: drop a marker into the EFS stub.
    ecs.register_task_definition()
        .family("efs-writer-family")
        .volumes(
            Volume::builder()
                .name("efs-vol")
                .efs_volume_configuration(
                    EfsVolumeConfiguration::builder()
                        .file_system_id(&fs_id)
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .container_definitions(
            ContainerDefinition::builder()
                .name("writer")
                .image("public.ecr.aws/docker/library/alpine:3.20")
                .essential(true)
                .mount_points(
                    MountPoint::builder()
                        .source_volume("efs-vol")
                        .container_path("/mnt/efs")
                        .build(),
                )
                .command("sh")
                .command("-c")
                .command("echo wrote-by-task1 > /mnt/efs/from-task1.txt")
                .build(),
        )
        .send()
        .await
        .unwrap();

    let run = ecs
        .run_task()
        .cluster("efs-cluster")
        .task_definition("efs-writer-family")
        .send()
        .await
        .unwrap();
    let arn = run.tasks()[0].task_arn().unwrap().to_string();
    wait_stopped(&ecs, "efs-cluster", &arn).await;

    // Reader task: read the marker the writer left behind. If the EFS
    // stub is reused across tasks (correct behaviour), `cat` succeeds
    // and the bytes show up in the captured logs.
    ecs.register_task_definition()
        .family("efs-reader-family")
        .volumes(
            Volume::builder()
                .name("efs-vol")
                .efs_volume_configuration(
                    EfsVolumeConfiguration::builder()
                        .file_system_id(&fs_id)
                        .build()
                        .unwrap(),
                )
                .build(),
        )
        .container_definitions(
            ContainerDefinition::builder()
                .name("reader")
                .image("public.ecr.aws/docker/library/alpine:3.20")
                .essential(true)
                .mount_points(
                    MountPoint::builder()
                        .source_volume("efs-vol")
                        .container_path("/mnt/efs")
                        .read_only(true)
                        .build(),
                )
                .command("sh")
                .command("-c")
                .command("cat /mnt/efs/from-task1.txt")
                .build(),
        )
        .send()
        .await
        .unwrap();

    let run = ecs
        .run_task()
        .cluster("efs-cluster")
        .task_definition("efs-reader-family")
        .send()
        .await
        .unwrap();
    let reader_arn = run.tasks()[0].task_arn().unwrap().to_string();
    wait_stopped(&ecs, "efs-cluster", &reader_arn).await;

    let task_id = reader_arn.rsplit('/').next().unwrap();
    let logs: serde_json::Value = reqwest::Client::new()
        .get(format!(
            "{}/_fakecloud/ecs/tasks/{task_id}/logs",
            server.endpoint()
        ))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let body = logs["logs"].as_str().unwrap_or_default().to_string();
    assert!(
        body.contains("wrote-by-task1"),
        "expected reader to see writer's marker; logs: {body}"
    );

    // Cleanup: remove the stub directory so successive test runs on
    // the same machine don't accumulate.
    let _ = std::fs::remove_dir_all(format!("/tmp/fakecloud/efs/{fs_id}"));
}
