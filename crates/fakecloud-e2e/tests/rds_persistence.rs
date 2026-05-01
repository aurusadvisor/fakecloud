mod helpers;

use helpers::TestServer;

/// DB instances survive a restart. Reproduces issue #914: a DB instance
/// created with `aws rds create-db-instance` disappeared after restart
/// because the background container-start task flipped status to
/// `available` without persisting, and the load path then dropped the
/// row as a "stuck creating" placeholder.
///
/// Uses `start_full` rather than `start_persistent` because the latter
/// disables the container CLI (most persistence tests cover metadata-
/// only ops); CreateDBInstance needs real Docker.
#[tokio::test]
async fn persistence_round_trip_db_instance() {
    let tmp = tempfile::tempdir().unwrap();
    let data_path = tmp.path().display().to_string();
    let extra_args = ["--storage-mode", "persistent", "--data-path", &data_path];
    let mut server = TestServer::start_full(&[], &extra_args).await;
    let client = server.rds_client().await;

    client
        .create_db_instance()
        .db_instance_identifier("persist-db")
        .allocated_storage(20)
        .db_instance_class("db.t3.micro")
        .engine("postgres")
        .engine_version("16.3")
        .master_username("admin")
        .master_user_password("secret123")
        .db_name("appdb")
        .send()
        .await
        .unwrap();

    let _ = helpers::wait_for_db_available(&client, "persist-db", 180).await;

    drop(client);
    server.restart().await;
    let client = server.rds_client().await;

    let resp = client
        .describe_db_instances()
        .db_instance_identifier("persist-db")
        .send()
        .await
        .unwrap();
    let instances = resp.db_instances();
    assert_eq!(instances.len(), 1, "DB instance should survive restart");
    let inst = &instances[0];
    assert_eq!(inst.db_instance_identifier(), Some("persist-db"));
    assert_eq!(inst.engine(), Some("postgres"));
    assert_eq!(inst.master_username(), Some("admin"));
    assert_eq!(
        inst.db_instance_status(),
        Some("available"),
        "status should persist as `available`, not be dropped as `creating`",
    );
}

/// Parameter groups survive a restart.
#[tokio::test]
async fn persistence_round_trip_parameter_group() {
    let tmp = tempfile::tempdir().unwrap();
    let mut server = TestServer::start_persistent(tmp.path()).await;
    let client = server.rds_client().await;

    client
        .create_db_parameter_group()
        .db_parameter_group_name("persist-pg")
        .db_parameter_group_family("postgres16")
        .description("Persistence test parameter group")
        .send()
        .await
        .unwrap();

    drop(client);
    server.restart().await;
    let client = server.rds_client().await;

    let groups = client
        .describe_db_parameter_groups()
        .db_parameter_group_name("persist-pg")
        .send()
        .await
        .unwrap();
    let pgs = groups.db_parameter_groups();
    assert!(
        pgs.iter()
            .any(|g| g.db_parameter_group_name() == Some("persist-pg")),
        "parameter group should survive restart"
    );
    let pg = pgs
        .iter()
        .find(|g| g.db_parameter_group_name() == Some("persist-pg"))
        .unwrap();
    assert_eq!(pg.db_parameter_group_family(), Some("postgres16"));
    assert_eq!(pg.description(), Some("Persistence test parameter group"));
}

/// Subnet groups survive a restart.
#[tokio::test]
async fn persistence_round_trip_subnet_group() {
    let tmp = tempfile::tempdir().unwrap();
    let mut server = TestServer::start_persistent(tmp.path()).await;
    let client = server.rds_client().await;

    client
        .create_db_subnet_group()
        .db_subnet_group_name("persist-subnet-grp")
        .db_subnet_group_description("Persistence test subnet group")
        .subnet_ids("subnet-aaa")
        .subnet_ids("subnet-bbb")
        .send()
        .await
        .unwrap();

    drop(client);
    server.restart().await;
    let client = server.rds_client().await;

    let groups = client
        .describe_db_subnet_groups()
        .db_subnet_group_name("persist-subnet-grp")
        .send()
        .await
        .unwrap();
    let sgs = groups.db_subnet_groups();
    assert_eq!(sgs.len(), 1);
    let sg = &sgs[0];
    assert_eq!(sg.db_subnet_group_name(), Some("persist-subnet-grp"));
    assert_eq!(
        sg.db_subnet_group_description(),
        Some("Persistence test subnet group")
    );
    let subnet_ids: Vec<&str> = sg
        .subnets()
        .iter()
        .filter_map(|s| s.subnet_identifier())
        .collect();
    assert!(subnet_ids.contains(&"subnet-aaa"));
    assert!(subnet_ids.contains(&"subnet-bbb"));
}

/// Deletion survives a restart: a deleted parameter group does not reappear.
#[tokio::test]
async fn persistence_deletion_survives_restart() {
    let tmp = tempfile::tempdir().unwrap();
    let mut server = TestServer::start_persistent(tmp.path()).await;
    let client = server.rds_client().await;

    client
        .create_db_parameter_group()
        .db_parameter_group_name("doomed-pg")
        .db_parameter_group_family("postgres16")
        .description("Will be deleted")
        .send()
        .await
        .unwrap();

    client
        .delete_db_parameter_group()
        .db_parameter_group_name("doomed-pg")
        .send()
        .await
        .unwrap();

    drop(client);
    server.restart().await;
    let client = server.rds_client().await;

    let groups = client.describe_db_parameter_groups().send().await.unwrap();
    assert!(
        !groups
            .db_parameter_groups()
            .iter()
            .any(|g| g.db_parameter_group_name() == Some("doomed-pg")),
        "deleted parameter group should not reappear"
    );
}
