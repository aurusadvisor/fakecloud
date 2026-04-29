use std::sync::Arc;

use async_trait::async_trait;
use base64::engine::general_purpose::STANDARD as BASE64;
use base64::Engine;
use chrono::Utc;
use http::StatusCode;
use tokio::sync::Mutex as AsyncMutex;

use fakecloud_aws::xml::xml_escape;
use fakecloud_core::delivery::DeliveryBus;
use fakecloud_core::query::{optional_query_param, query_response_xml, required_query_param};
use fakecloud_core::service::{AwsRequest, AwsResponse, AwsService, AwsServiceError};
use fakecloud_persistence::SnapshotStore;

use crate::runtime::{RdsRuntime, RuntimeError};
use crate::state::{
    default_engine_versions, default_orderable_options, DbInstance, DbParameterGroup, DbSnapshot,
    DbSubnetGroup, EngineVersionInfo, OrderableDbInstanceOption, RdsSnapshot, RdsState, RdsTag,
    SharedRdsState, RDS_SNAPSHOT_SCHEMA_VERSION,
};

const RDS_NS: &str = "http://rds.amazonaws.com/doc/2014-10-31/";

fn is_mutating_action(action: &str) -> bool {
    if matches!(
        action,
        "AddTagsToResource"
            | "CreateDBInstance"
            | "CreateDBInstanceReadReplica"
            | "CreateDBParameterGroup"
            | "CreateDBSnapshot"
            | "CreateDBSubnetGroup"
            | "DeleteDBInstance"
            | "DeleteDBParameterGroup"
            | "DeleteDBSnapshot"
            | "DeleteDBSubnetGroup"
            | "ModifyDBInstance"
            | "ModifyDBParameterGroup"
            | "ModifyDBSubnetGroup"
            | "RebootDBInstance"
            | "RemoveTagsFromResource"
            | "RestoreDBInstanceFromDBSnapshot"
    ) {
        return true;
    }
    // Heuristic for the 140 extra ops: any verb that mutates state.
    let mutating_prefixes = [
        "Create",
        "Modify",
        "Delete",
        "Reboot",
        "Start",
        "Stop",
        "Failover",
        "Switchover",
        "Promote",
        "Reset",
        "Apply",
        "Authorize",
        "Revoke",
        "Add",
        "Remove",
        "Register",
        "Deregister",
        "Copy",
        "Restore",
        "Backtrack",
        "Cancel",
        "Purchase",
        "Disable",
        "Enable",
    ];
    mutating_prefixes.iter().any(|p| action.starts_with(p))
}
const SUPPORTED_ACTIONS: &[&str] = &[
    "AddRoleToDBCluster",
    "AddRoleToDBInstance",
    "AddSourceIdentifierToSubscription",
    "AddTagsToResource",
    "ApplyPendingMaintenanceAction",
    "AuthorizeDBSecurityGroupIngress",
    "BacktrackDBCluster",
    "CancelExportTask",
    "CopyDBClusterParameterGroup",
    "CopyDBClusterSnapshot",
    "CopyDBParameterGroup",
    "CopyDBSnapshot",
    "CopyOptionGroup",
    "CreateBlueGreenDeployment",
    "CreateCustomDBEngineVersion",
    "CreateDBCluster",
    "CreateDBClusterEndpoint",
    "CreateDBClusterParameterGroup",
    "CreateDBClusterSnapshot",
    "CreateDBInstance",
    "CreateDBInstanceReadReplica",
    "CreateDBParameterGroup",
    "CreateDBProxy",
    "CreateDBProxyEndpoint",
    "CreateDBSecurityGroup",
    "CreateDBShardGroup",
    "CreateDBSnapshot",
    "CreateDBSubnetGroup",
    "CreateEventSubscription",
    "CreateGlobalCluster",
    "CreateIntegration",
    "CreateOptionGroup",
    "CreateTenantDatabase",
    "DeleteBlueGreenDeployment",
    "DeleteCustomDBEngineVersion",
    "DeleteDBCluster",
    "DeleteDBClusterAutomatedBackup",
    "DeleteDBClusterEndpoint",
    "DeleteDBClusterParameterGroup",
    "DeleteDBClusterSnapshot",
    "DeleteDBInstance",
    "DeleteDBInstanceAutomatedBackup",
    "DeleteDBParameterGroup",
    "DeleteDBProxy",
    "DeleteDBProxyEndpoint",
    "DeleteDBSecurityGroup",
    "DeleteDBShardGroup",
    "DeleteDBSnapshot",
    "DeleteDBSubnetGroup",
    "DeleteEventSubscription",
    "DeleteGlobalCluster",
    "DeleteIntegration",
    "DeleteOptionGroup",
    "DeleteTenantDatabase",
    "DeregisterDBProxyTargets",
    "DescribeAccountAttributes",
    "DescribeBlueGreenDeployments",
    "DescribeCertificates",
    "DescribeDBClusterAutomatedBackups",
    "DescribeDBClusterBacktracks",
    "DescribeDBClusterEndpoints",
    "DescribeDBClusterParameterGroups",
    "DescribeDBClusterParameters",
    "DescribeDBClusterSnapshotAttributes",
    "DescribeDBClusterSnapshots",
    "DescribeDBClusters",
    "DescribeDBEngineVersions",
    "DescribeDBInstanceAutomatedBackups",
    "DescribeDBInstances",
    "DescribeDBLogFiles",
    "DescribeDBMajorEngineVersions",
    "DescribeDBParameterGroups",
    "DescribeDBParameters",
    "DescribeDBProxies",
    "DescribeDBProxyEndpoints",
    "DescribeDBProxyTargetGroups",
    "DescribeDBProxyTargets",
    "DescribeDBRecommendations",
    "DescribeDBSecurityGroups",
    "DescribeDBShardGroups",
    "DescribeDBSnapshotAttributes",
    "DescribeDBSnapshotTenantDatabases",
    "DescribeDBSnapshots",
    "DescribeDBSubnetGroups",
    "DescribeEngineDefaultClusterParameters",
    "DescribeEngineDefaultParameters",
    "DescribeEventCategories",
    "DescribeEventSubscriptions",
    "DescribeEvents",
    "DescribeExportTasks",
    "DescribeGlobalClusters",
    "DescribeIntegrations",
    "DescribeOptionGroupOptions",
    "DescribeOptionGroups",
    "DescribeOrderableDBInstanceOptions",
    "DescribePendingMaintenanceActions",
    "DescribeReservedDBInstances",
    "DescribeReservedDBInstancesOfferings",
    "DescribeSourceRegions",
    "DescribeTenantDatabases",
    "DescribeValidDBInstanceModifications",
    "DisableHttpEndpoint",
    "DownloadDBLogFilePortion",
    "EnableHttpEndpoint",
    "FailoverDBCluster",
    "FailoverGlobalCluster",
    "ListTagsForResource",
    "ModifyActivityStream",
    "ModifyCertificates",
    "ModifyCurrentDBClusterCapacity",
    "ModifyCustomDBEngineVersion",
    "ModifyDBCluster",
    "ModifyDBClusterEndpoint",
    "ModifyDBClusterParameterGroup",
    "ModifyDBClusterSnapshotAttribute",
    "ModifyDBInstance",
    "ModifyDBParameterGroup",
    "ModifyDBProxy",
    "ModifyDBProxyEndpoint",
    "ModifyDBProxyTargetGroup",
    "ModifyDBRecommendation",
    "ModifyDBShardGroup",
    "ModifyDBSnapshot",
    "ModifyDBSnapshotAttribute",
    "ModifyDBSubnetGroup",
    "ModifyEventSubscription",
    "ModifyGlobalCluster",
    "ModifyIntegration",
    "ModifyOptionGroup",
    "ModifyTenantDatabase",
    "PromoteReadReplica",
    "PromoteReadReplicaDBCluster",
    "PurchaseReservedDBInstancesOffering",
    "RebootDBCluster",
    "RebootDBInstance",
    "RebootDBShardGroup",
    "RegisterDBProxyTargets",
    "RemoveFromGlobalCluster",
    "RemoveRoleFromDBCluster",
    "RemoveRoleFromDBInstance",
    "RemoveSourceIdentifierFromSubscription",
    "RemoveTagsFromResource",
    "ResetDBClusterParameterGroup",
    "ResetDBParameterGroup",
    "RestoreDBClusterFromS3",
    "RestoreDBClusterFromSnapshot",
    "RestoreDBClusterToPointInTime",
    "RestoreDBInstanceFromDBSnapshot",
    "RestoreDBInstanceFromS3",
    "RestoreDBInstanceToPointInTime",
    "RevokeDBSecurityGroupIngress",
    "StartActivityStream",
    "StartDBCluster",
    "StartDBInstance",
    "StartDBInstanceAutomatedBackupsReplication",
    "StartExportTask",
    "StopActivityStream",
    "StopDBCluster",
    "StopDBInstance",
    "StopDBInstanceAutomatedBackupsReplication",
    "SwitchoverBlueGreenDeployment",
    "SwitchoverGlobalCluster",
    "SwitchoverReadReplica",
];

pub struct RdsService {
    pub(crate) state: SharedRdsState,
    runtime: Option<Arc<RdsRuntime>>,
    snapshot_store: Option<Arc<dyn SnapshotStore>>,
    snapshot_lock: Arc<AsyncMutex<()>>,
    pub(crate) delivery_bus: Option<Arc<DeliveryBus>>,
}

/// Source type for RDS EventBridge events. Maps `aws.rds` detail-type.
#[derive(Clone, Copy)]
#[allow(dead_code, clippy::enum_variant_names)]
pub(crate) enum RdsSourceType {
    DbInstance,
    DbSnapshot,
    DbParameterGroup,
}

impl RdsSourceType {
    fn as_str(self) -> &'static str {
        match self {
            Self::DbInstance => "DB_INSTANCE",
            Self::DbSnapshot => "DB_SNAPSHOT",
            Self::DbParameterGroup => "DB_PARAMETER_GROUP",
        }
    }

    fn detail_type(self) -> &'static str {
        match self {
            Self::DbInstance => "RDS DB Instance Event",
            Self::DbSnapshot => "RDS DB Snapshot Event",
            Self::DbParameterGroup => "RDS DB Parameter Group Event",
        }
    }
}

impl RdsService {
    pub(crate) fn state_handle(&self) -> &SharedRdsState {
        &self.state
    }
}

impl RdsService {
    pub fn new(state: SharedRdsState) -> Self {
        Self {
            state,
            runtime: None,
            snapshot_store: None,
            snapshot_lock: Arc::new(AsyncMutex::new(())),
            delivery_bus: None,
        }
    }

    pub fn with_runtime(mut self, runtime: Arc<RdsRuntime>) -> Self {
        self.runtime = Some(runtime);
        self
    }

    pub fn with_snapshot_store(mut self, store: Arc<dyn SnapshotStore>) -> Self {
        self.snapshot_store = Some(store);
        self
    }

    pub fn with_delivery_bus(mut self, bus: Arc<DeliveryBus>) -> Self {
        self.delivery_bus = Some(bus);
        self
    }

    /// Emit an `aws.rds` EventBridge event mirroring the AWS RDS event schema.
    /// No-op when the delivery bus isn't wired (tests, minimal configs).
    pub(crate) fn emit_event(
        &self,
        source_type: RdsSourceType,
        source_identifier: &str,
        source_arn: &str,
        event_id: &str,
        event_categories: &[&str],
        message: &str,
    ) {
        emit_event_static(
            self.delivery_bus.as_ref(),
            source_type,
            source_identifier,
            source_arn,
            event_id,
            event_categories,
            message,
        );
    }

    async fn save_snapshot(&self) {
        let Some(store) = self.snapshot_store.clone() else {
            return;
        };
        let _guard = self.snapshot_lock.lock().await;
        let snapshot = RdsSnapshot {
            schema_version: RDS_SNAPSHOT_SCHEMA_VERSION,
            state: None,
            accounts: Some(self.state.read().clone()),
        };
        let join = tokio::task::spawn_blocking(move || -> std::io::Result<()> {
            let bytes = serde_json::to_vec(&snapshot)
                .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e.to_string()))?;
            store.save(&bytes)
        })
        .await;
        match join {
            Ok(Ok(())) => {}
            Ok(Err(err)) => tracing::error!(%err, "failed to write rds snapshot"),
            Err(err) => tracing::error!(%err, "rds snapshot task panicked"),
        }
    }

    /// Return the runtime or a ``ServiceUnavailable`` error if it was not configured.
    ///
    /// RDS operations that start, stop, or reach into a database container fail
    /// with a consistent wire error when the daemon (Docker/Podman) is missing
    /// rather than each caller restating the message.
    fn require_runtime(&self) -> Result<&Arc<RdsRuntime>, AwsServiceError> {
        self.runtime.as_ref().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "InvalidParameterValue",
                "Docker/Podman is required for RDS DB instances but is not available",
            )
        })
    }
}

#[async_trait]
impl AwsService for RdsService {
    fn service_name(&self) -> &str {
        "rds"
    }

    async fn handle(&self, request: AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let mutates = is_mutating_action(request.action.as_str());
        let result = match request.action.as_str() {
            "AddTagsToResource" => self.add_tags_to_resource(&request),
            "CreateDBInstance" => self.create_db_instance(&request).await,
            "CreateDBInstanceReadReplica" => self.create_db_instance_read_replica(&request).await,
            "CreateDBParameterGroup" => self.create_db_parameter_group(&request),
            "CreateDBSnapshot" => self.create_db_snapshot(&request).await,
            "CreateDBSubnetGroup" => self.create_db_subnet_group(&request),
            "DeleteDBInstance" => self.delete_db_instance(&request).await,
            "DeleteDBParameterGroup" => self.delete_db_parameter_group(&request),
            "DeleteDBSnapshot" => self.delete_db_snapshot(&request),
            "DeleteDBSubnetGroup" => self.delete_db_subnet_group(&request),
            "DescribeDBEngineVersions" => self.describe_db_engine_versions(&request),
            "DescribeDBInstances" => self.describe_db_instances(&request),
            "DescribeDBParameterGroups" => self.describe_db_parameter_groups(&request),
            "DescribeDBSnapshots" => self.describe_db_snapshots(&request),
            "DescribeDBSubnetGroups" => self.describe_db_subnet_groups(&request),
            "DescribeOrderableDBInstanceOptions" => {
                self.describe_orderable_db_instance_options(&request)
            }
            "ListTagsForResource" => self.list_tags_for_resource(&request),
            "ModifyDBInstance" => self.modify_db_instance(&request),
            "ModifyDBParameterGroup" => self.modify_db_parameter_group(&request),
            "ModifyDBSubnetGroup" => self.modify_db_subnet_group(&request),
            "RebootDBInstance" => self.reboot_db_instance(&request).await,
            "RemoveTagsFromResource" => self.remove_tags_from_resource(&request),
            "RestoreDBInstanceFromDBSnapshot" => {
                self.restore_db_instance_from_db_snapshot(&request).await
            }
            _ => self.handle_extra_action(&request),
        };
        if mutates && matches!(result.as_ref(), Ok(resp) if resp.status.is_success()) {
            self.save_snapshot().await;
        }
        result
    }

    fn supported_actions(&self) -> &[&str] {
        SUPPORTED_ACTIONS
    }
}

impl RdsService {
    async fn create_db_instance(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let db_instance_identifier = required_query_param(request, "DBInstanceIdentifier")?;
        let allocated_storage = required_i32_param(request, "AllocatedStorage")?;
        let db_instance_class = required_query_param(request, "DBInstanceClass")?;
        let engine = required_query_param(request, "Engine")?;
        let master_username = required_query_param(request, "MasterUsername")?;
        let master_user_password = required_query_param(request, "MasterUserPassword")?;
        let db_name = optional_query_param(request, "DBName");
        let engine_version =
            optional_query_param(request, "EngineVersion").unwrap_or_else(|| "16.3".to_string());
        let publicly_accessible =
            parse_optional_bool(optional_query_param(request, "PubliclyAccessible").as_deref())?
                .unwrap_or(true);
        let deletion_protection =
            parse_optional_bool(optional_query_param(request, "DeletionProtection").as_deref())?
                .unwrap_or(false);
        let port = optional_i32_param(request, "Port")?
            .unwrap_or_else(|| default_port_for_engine(&engine));
        let vpc_security_group_ids = parse_vpc_security_group_ids(request);

        let db_parameter_group_name = optional_query_param(request, "DBParameterGroupName")
            .or_else(|| Some(default_parameter_group(&engine, &engine_version)));

        let backup_retention_period =
            optional_i32_param(request, "BackupRetentionPeriod")?.unwrap_or(1);
        let preferred_backup_window = optional_query_param(request, "PreferredBackupWindow")
            .unwrap_or_else(|| "03:00-04:00".to_string());
        let option_group_name = optional_query_param(request, "OptionGroupName");
        let multi_az = parse_optional_bool(optional_query_param(request, "MultiAZ").as_deref())?
            .unwrap_or(false);

        validate_create_request(
            &db_instance_identifier,
            allocated_storage,
            &db_instance_class,
            &engine,
            &engine_version,
            port,
        )?;

        {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);
            if !state.begin_instance_creation(&db_instance_identifier) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "DBInstanceAlreadyExists",
                    format!("DBInstance {} already exists.", db_instance_identifier),
                ));
            }
            // Validate parameter group exists if specified by the caller
            if let Some(ref pg_name) = db_parameter_group_name {
                if !state.parameter_groups.contains_key(pg_name) {
                    state.cancel_instance_creation(&db_instance_identifier);
                    return Err(AwsServiceError::aws_error(
                        StatusCode::NOT_FOUND,
                        "DBParameterGroupNotFound",
                        format!("DBParameterGroup {} not found.", pg_name),
                    ));
                }
            }
        }

        let runtime = self.require_runtime()?.clone();

        let logical_db_name = db_name
            .clone()
            .unwrap_or_else(|| default_db_name(&engine).to_string());

        // Insert a "creating" placeholder synchronously and spawn the
        // container start in a background task. CreateDBInstance returns
        // ~immediately; DescribeDBInstances flips to "available" (or
        // "failed") when the container is up. Matches AWS RDS behavior:
        // CreateDBInstance never blocks on the container coming up.
        let created_at = Utc::now();
        let instance = {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);
            let placeholder = DbInstance {
                db_instance_identifier: db_instance_identifier.clone(),
                db_instance_arn: state.db_instance_arn(&db_instance_identifier),
                db_instance_class: db_instance_class.clone(),
                engine: engine.clone(),
                engine_version: engine_version.clone(),
                db_instance_status: "creating".to_string(),
                master_username: master_username.clone(),
                db_name: db_name.clone(),
                endpoint_address: String::new(),
                port: 0,
                allocated_storage,
                publicly_accessible,
                deletion_protection,
                created_at,
                dbi_resource_id: state.next_dbi_resource_id(),
                master_user_password: master_user_password.clone(),
                container_id: String::new(),
                host_port: 0,
                tags: Vec::new(),
                read_replica_source_db_instance_identifier: None,
                read_replica_db_instance_identifiers: Vec::new(),
                vpc_security_group_ids,
                db_parameter_group_name,
                backup_retention_period,
                preferred_backup_window,
                latest_restorable_time: if backup_retention_period > 0 {
                    Some(created_at)
                } else {
                    None
                },
                option_group_name,
                multi_az,
                pending_modified_values: None,
            };
            state.finish_instance_creation(placeholder.clone());
            placeholder
        };
        let instance_arn = instance.db_instance_arn.clone();

        self.emit_event(
            RdsSourceType::DbInstance,
            &db_instance_identifier,
            &instance_arn,
            "RDS-EVENT-0005",
            &["creation"],
            "DB instance created",
        );

        {
            let state_handle = self.state.clone();
            let delivery_bus = self.delivery_bus.clone();
            let runtime = runtime.clone();
            let id = db_instance_identifier.clone();
            let engine = engine.clone();
            let engine_version = engine_version.clone();
            let master_username = master_username.clone();
            let master_user_password = master_user_password.clone();
            let account_id = request.account_id.clone();
            let region = request.region.clone();
            let arn = instance_arn.clone();
            tokio::spawn(async move {
                match runtime
                    .ensure_postgres(
                        &id,
                        &engine,
                        &engine_version,
                        &master_username,
                        &master_user_password,
                        &logical_db_name,
                        &account_id,
                        &region,
                    )
                    .await
                {
                    Ok(running) => {
                        let mut accounts = state_handle.write();
                        let state = accounts.get_or_create(&account_id);
                        if let Some(inst) = state.instances.get_mut(&id) {
                            inst.db_instance_status = "available".to_string();
                            inst.endpoint_address = "127.0.0.1".to_string();
                            inst.port = i32::from(running.host_port);
                            inst.host_port = running.host_port;
                            inst.container_id = running.container_id;
                        }
                    }
                    Err(error) => {
                        tracing::error!(%error, db_instance_identifier=%id, "create_db_instance background task failed");
                        {
                            let mut accounts = state_handle.write();
                            let state = accounts.get_or_create(&account_id);
                            state.instances.remove(&id);
                        }
                        emit_event_static(
                            delivery_bus.as_ref(),
                            RdsSourceType::DbInstance,
                            &id,
                            &arn,
                            "RDS-EVENT-0058",
                            &["failure"],
                            &format!("DB instance failed to create: {}", error),
                        );
                    }
                }
            });
        }

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "CreateDBInstance",
                RDS_NS,
                &format!(
                    "<DBInstance>{}</DBInstance>",
                    db_instance_xml(&instance, None)
                ),
                &request.request_id,
            ),
        ))
    }

    async fn delete_db_instance(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let db_instance_identifier = required_query_param(request, "DBInstanceIdentifier")?;
        let skip_final_snapshot =
            parse_optional_bool(optional_query_param(request, "SkipFinalSnapshot").as_deref())?
                .unwrap_or(false);
        let final_db_snapshot_identifier =
            optional_query_param(request, "FinalDBSnapshotIdentifier");

        if skip_final_snapshot && final_db_snapshot_identifier.is_some() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterCombination",
                "FinalDBSnapshotIdentifier cannot be specified when SkipFinalSnapshot is enabled.",
            ));
        }
        if !skip_final_snapshot && final_db_snapshot_identifier.is_none() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterCombination",
                "FinalDBSnapshotIdentifier is required when SkipFinalSnapshot is false or not specified.",
            ));
        }

        // Check deletion protection BEFORE creating snapshot or making any changes
        {
            let accounts = self.state.read();
            let empty = RdsState::new(&request.account_id, &request.region);
            let state = accounts.get(&request.account_id).unwrap_or(&empty);
            if let Some(instance) = state.instances.get(&db_instance_identifier) {
                if instance.deletion_protection {
                    return Err(AwsServiceError::aws_error(
                        StatusCode::BAD_REQUEST,
                        "InvalidDBInstanceState",
                        format!(
                            "DBInstance {} cannot be deleted because deletion protection is enabled.",
                            db_instance_identifier
                        ),
                    ));
                }
            } else {
                return Err(db_instance_not_found(&db_instance_identifier));
            }
        }

        if let Some(ref snapshot_id) = final_db_snapshot_identifier {
            self.create_final_db_snapshot(
                &db_instance_identifier,
                snapshot_id,
                &request.account_id,
                &request.region,
            )
            .await?;
        }

        let instance = {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);
            let instance = state
                .instances
                .remove(&db_instance_identifier)
                .ok_or_else(|| db_instance_not_found(&db_instance_identifier))?;

            if let Some(source_id) = &instance.read_replica_source_db_instance_identifier {
                if let Some(source) = state.instances.get_mut(source_id) {
                    source
                        .read_replica_db_instance_identifiers
                        .retain(|id| id != &db_instance_identifier);
                }
            }

            for replica_id in &instance.read_replica_db_instance_identifiers {
                if let Some(replica) = state.instances.get_mut(replica_id) {
                    replica.read_replica_source_db_instance_identifier = None;
                }
            }

            instance
        };

        if let Some(runtime) = &self.runtime {
            runtime.stop_container(&db_instance_identifier).await;
        }

        self.emit_event(
            RdsSourceType::DbInstance,
            &db_instance_identifier,
            &instance.db_instance_arn,
            "RDS-EVENT-0003",
            &["deletion"],
            "DB instance deleted",
        );

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DeleteDBInstance",
                RDS_NS,
                &format!(
                    "<DBInstance>{}</DBInstance>",
                    db_instance_xml(&instance, Some("deleting"))
                ),
                &request.request_id,
            ),
        ))
    }

    /// Take a final snapshot of an instance that is about to be deleted,
    /// persisting the dumped database into `state.snapshots`. The DLQ-style
    /// conflict check runs twice — once under the read lock before paying
    /// for the dump, once under the write lock before committing — to keep
    /// concurrent deletes from colliding.
    async fn create_final_db_snapshot(
        &self,
        db_instance_identifier: &str,
        snapshot_id: &str,
        account_id: &str,
        region: &str,
    ) -> Result<(), AwsServiceError> {
        let runtime = self.runtime.as_ref().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "InvalidParameterValue",
                "Docker/Podman is required for RDS snapshots but is not available",
            )
        })?;

        let (instance_for_snapshot, db_name) = {
            let accounts = self.state.read();
            let empty = RdsState::new(account_id, region);
            let state = accounts.get(account_id).unwrap_or(&empty);

            if state.snapshots.contains_key(snapshot_id) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::CONFLICT,
                    "DBSnapshotAlreadyExists",
                    format!("DBSnapshot {snapshot_id} already exists."),
                ));
            }

            let instance = state
                .instances
                .get(db_instance_identifier)
                .cloned()
                .ok_or_else(|| db_instance_not_found(db_instance_identifier))?;

            let default_db = default_db_name(&instance.engine);
            let db_name = instance
                .db_name
                .as_deref()
                .unwrap_or(default_db)
                .to_string();

            (instance, db_name)
        };

        let dump_data = runtime
            .dump_database(
                db_instance_identifier,
                &instance_for_snapshot.engine,
                &instance_for_snapshot.master_username,
                &instance_for_snapshot.master_user_password,
                &db_name,
            )
            .await
            .map_err(runtime_error_to_service_error)?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(account_id);

        if state.snapshots.contains_key(snapshot_id) {
            return Err(AwsServiceError::aws_error(
                StatusCode::CONFLICT,
                "DBSnapshotAlreadyExists",
                format!("DBSnapshot {snapshot_id} already exists."),
            ));
        }

        let snapshot_arn = state.db_snapshot_arn(snapshot_id);

        let snapshot = DbSnapshot {
            db_snapshot_identifier: snapshot_id.to_string(),
            db_snapshot_arn: snapshot_arn,
            db_instance_identifier: db_instance_identifier.to_string(),
            snapshot_create_time: Utc::now(),
            engine: instance_for_snapshot.engine.clone(),
            engine_version: instance_for_snapshot.engine_version.clone(),
            allocated_storage: instance_for_snapshot.allocated_storage,
            status: "available".to_string(),
            port: instance_for_snapshot.port,
            master_username: instance_for_snapshot.master_username.clone(),
            db_name: instance_for_snapshot.db_name.clone(),
            dbi_resource_id: instance_for_snapshot.dbi_resource_id.clone(),
            snapshot_type: "manual".to_string(),
            master_user_password: instance_for_snapshot.master_user_password.clone(),
            tags: Vec::new(),
            dump_data,
        };

        state.snapshots.insert(snapshot_id.to_string(), snapshot);
        Ok(())
    }

    fn modify_db_instance(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let db_instance_identifier = required_query_param(request, "DBInstanceIdentifier")?;
        let db_instance_class = optional_query_param(request, "DBInstanceClass");
        let deletion_protection =
            parse_optional_bool(optional_query_param(request, "DeletionProtection").as_deref())?;
        let apply_immediately =
            parse_optional_bool(optional_query_param(request, "ApplyImmediately").as_deref())?;

        // Parse VPC security group IDs - only if at least one is provided
        let vpc_security_group_ids = {
            let mut ids = Vec::new();
            for index in 1.. {
                let sg_id_name = format!("VpcSecurityGroupIds.VpcSecurityGroupId.{index}");
                match optional_query_param(request, &sg_id_name) {
                    Some(sg_id) => ids.push(sg_id),
                    None => break,
                }
            }
            if ids.is_empty() {
                None
            } else {
                Some(ids)
            }
        };

        if db_instance_class.is_none()
            && deletion_protection.is_none()
            && vpc_security_group_ids.is_none()
        {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterCombination",
                "At least one supported mutable field must be provided.",
            ));
        }
        if let Some(ref class) = db_instance_class {
            validate_db_instance_class(class)?;
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let instance = state
            .instances
            .get_mut(&db_instance_identifier)
            .ok_or_else(|| db_instance_not_found(&db_instance_identifier))?;

        // If ApplyImmediately is false, stage changes as pending
        if apply_immediately == Some(false) {
            let pending = instance
                .pending_modified_values
                .get_or_insert(Default::default());
            if let Some(class) = db_instance_class {
                pending.db_instance_class = Some(class);
            }
            // Note: deletion_protection and vpc_security_group_ids are applied immediately
            // regardless of ApplyImmediately flag (per AWS behavior)
            if let Some(deletion_protection) = deletion_protection {
                instance.deletion_protection = deletion_protection;
            }
            if let Some(security_group_ids) = vpc_security_group_ids {
                instance.vpc_security_group_ids = security_group_ids;
            }
        } else {
            // Apply immediately (default behavior)
            if let Some(class) = db_instance_class {
                instance.db_instance_class = class;
            }
            if let Some(deletion_protection) = deletion_protection {
                instance.deletion_protection = deletion_protection;
            }
            if let Some(security_group_ids) = vpc_security_group_ids {
                instance.vpc_security_group_ids = security_group_ids;
            }
        }
        let instance_arn = instance.db_instance_arn.clone();
        let xml = query_response_xml(
            "ModifyDBInstance",
            RDS_NS,
            &format!(
                "<DBInstance>{}</DBInstance>",
                db_instance_xml(instance, Some("modifying"))
            ),
            &request.request_id,
        );
        drop(accounts);

        self.emit_event(
            RdsSourceType::DbInstance,
            &db_instance_identifier,
            &instance_arn,
            "RDS-EVENT-0014",
            &["configuration change"],
            "DB instance was modified",
        );

        Ok(AwsResponse::xml(StatusCode::OK, xml))
    }

    async fn reboot_db_instance(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let db_instance_identifier = required_query_param(request, "DBInstanceIdentifier")?;
        let force_failover =
            parse_optional_bool(optional_query_param(request, "ForceFailover").as_deref())?;
        if force_failover == Some(true) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterCombination",
                "ForceFailover is not supported for single-instance PostgreSQL DB instances.",
            ));
        }

        let instance = {
            let accounts = self.state.read();
            let empty = RdsState::new(&request.account_id, &request.region);
            let state = accounts.get(&request.account_id).unwrap_or(&empty);
            state
                .instances
                .get(&db_instance_identifier)
                .cloned()
                .ok_or_else(|| db_instance_not_found(&db_instance_identifier))?
        };

        let runtime = self.require_runtime()?;

        let running = runtime
            .restart_container(
                &db_instance_identifier,
                &instance.engine,
                &instance.master_username,
                &instance.master_user_password,
                instance
                    .db_name
                    .as_deref()
                    .unwrap_or(default_db_name(&instance.engine)),
            )
            .await
            .map_err(runtime_error_to_service_error)?;

        let instance = {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);
            let instance = state
                .instances
                .get_mut(&db_instance_identifier)
                .ok_or_else(|| db_instance_not_found(&db_instance_identifier))?;
            instance.host_port = running.host_port;
            instance.port = i32::from(running.host_port);

            // Apply any pending modifications
            if let Some(pending) = instance.pending_modified_values.take() {
                if let Some(class) = pending.db_instance_class {
                    instance.db_instance_class = class;
                }
                if let Some(allocated_storage) = pending.allocated_storage {
                    instance.allocated_storage = allocated_storage;
                }
                if let Some(backup_retention_period) = pending.backup_retention_period {
                    instance.backup_retention_period = backup_retention_period;
                }
                if let Some(multi_az) = pending.multi_az {
                    instance.multi_az = multi_az;
                }
                if let Some(engine_version) = pending.engine_version {
                    instance.engine_version = engine_version;
                }
                if let Some(master_user_password) = pending.master_user_password {
                    instance.master_user_password = master_user_password;
                }
            }

            instance.clone()
        };

        self.emit_event(
            RdsSourceType::DbInstance,
            &db_instance_identifier,
            &instance.db_instance_arn,
            "RDS-EVENT-0006",
            &["availability"],
            "DB instance restarted",
        );

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "RebootDBInstance",
                RDS_NS,
                &format!(
                    "<DBInstance>{}</DBInstance>",
                    db_instance_xml(&instance, Some("rebooting"))
                ),
                &request.request_id,
            ),
        ))
    }

    fn describe_db_engine_versions(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let engine = optional_query_param(request, "Engine");
        let engine_version = optional_query_param(request, "EngineVersion");
        let family = optional_query_param(request, "DBParameterGroupFamily");
        let default_only =
            parse_optional_bool(optional_query_param(request, "DefaultOnly").as_deref())?;

        let mut versions = filter_engine_versions(
            &default_engine_versions(),
            &engine,
            &engine_version,
            &family,
        );

        if default_only.unwrap_or(false) {
            versions.truncate(1);
        }

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeDBEngineVersions",
                RDS_NS,
                &format!(
                    "<DBEngineVersions>{}</DBEngineVersions>",
                    versions.iter().map(engine_version_xml).collect::<String>()
                ),
                &request.request_id,
            ),
        ))
    }

    fn describe_db_instances(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let db_instance_identifier = optional_query_param(request, "DBInstanceIdentifier");
        let marker = optional_query_param(request, "Marker");
        let max_records = optional_query_param(request, "MaxRecords");

        let accounts = self.state.read();
        let empty = RdsState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);

        // If specific identifier requested, return just that one (no pagination)
        if let Some(identifier) = db_instance_identifier {
            let instance = state
                .instances
                .get(&identifier)
                .cloned()
                .ok_or_else(|| db_instance_not_found(&identifier))?;

            return Ok(AwsResponse::xml(
                StatusCode::OK,
                query_response_xml(
                    "DescribeDBInstances",
                    RDS_NS,
                    &format!(
                        "<DBInstances><DBInstance>{}</DBInstance></DBInstances>",
                        db_instance_xml(&instance, None)
                    ),
                    &request.request_id,
                ),
            ));
        }

        // Get all instances sorted by created_at, then identifier
        let mut instances: Vec<DbInstance> = state.instances.values().cloned().collect();
        instances.sort_by(|a, b| {
            a.created_at
                .cmp(&b.created_at)
                .then_with(|| a.db_instance_identifier.cmp(&b.db_instance_identifier))
        });

        // Apply pagination
        let paginated = paginate(instances, marker, max_records, |inst| {
            &inst.db_instance_identifier
        })?;

        let marker_xml = paginated
            .next_marker
            .as_ref()
            .map(|m| format!("<Marker>{}</Marker>", xml_escape(m)))
            .unwrap_or_default();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeDBInstances",
                RDS_NS,
                &format!(
                    "<DBInstances>{}</DBInstances>{}",
                    paginated
                        .items
                        .iter()
                        .map(|instance| {
                            format!(
                                "<DBInstance>{}</DBInstance>",
                                db_instance_xml(instance, None)
                            )
                        })
                        .collect::<String>(),
                    marker_xml
                ),
                &request.request_id,
            ),
        ))
    }

    fn describe_orderable_db_instance_options(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let engine = optional_query_param(request, "Engine");
        let engine_version = optional_query_param(request, "EngineVersion");
        let db_instance_class = optional_query_param(request, "DBInstanceClass");
        let license_model = optional_query_param(request, "LicenseModel");
        let vpc = parse_optional_bool(optional_query_param(request, "Vpc").as_deref())?;

        let options = filter_orderable_options(
            &default_orderable_options(),
            &engine,
            &engine_version,
            &db_instance_class,
            &license_model,
            vpc,
        );

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeOrderableDBInstanceOptions",
                RDS_NS,
                &format!(
                    "<OrderableDBInstanceOptions>{}</OrderableDBInstanceOptions>",
                    options.iter().map(orderable_option_xml).collect::<String>()
                ),
                &request.request_id,
            ),
        ))
    }

    fn add_tags_to_resource(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let resource_name = required_query_param(request, "ResourceName")?;
        let tags = parse_tags(request)?;

        if tags.is_empty() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "The request must contain the parameter Tags.",
            ));
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let instance = find_instance_by_arn_mut(state, &resource_name)?;
        merge_tags(&mut instance.tags, &tags);

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml("AddTagsToResource", RDS_NS, "", &request.request_id),
        ))
    }

    fn list_tags_for_resource(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let resource_name = required_query_param(request, "ResourceName")?;
        if query_param_prefix_exists(request, "Filters.") {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                "Filters are not yet supported for ListTagsForResource.",
            ));
        }

        let accounts = self.state.read();
        let empty = RdsState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);
        let instance = find_instance_by_arn(state, &resource_name)?;
        let tag_xml = instance.tags.iter().map(tag_xml).collect::<String>();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "ListTagsForResource",
                RDS_NS,
                &format!("<TagList>{tag_xml}</TagList>"),
                &request.request_id,
            ),
        ))
    }

    fn remove_tags_from_resource(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let resource_name = required_query_param(request, "ResourceName")?;
        let tag_keys = parse_tag_keys(request)?;

        if tag_keys.is_empty() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "MissingParameter",
                "The request must contain the parameter TagKeys.",
            ));
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);
        let instance = find_instance_by_arn_mut(state, &resource_name)?;
        instance
            .tags
            .retain(|tag| !tag_keys.iter().any(|key| key == &tag.key));

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml("RemoveTagsFromResource", RDS_NS, "", &request.request_id),
        ))
    }

    async fn create_db_snapshot(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let db_snapshot_identifier = required_query_param(request, "DBSnapshotIdentifier")?;
        let db_instance_identifier = required_query_param(request, "DBInstanceIdentifier")?;

        let runtime = self.runtime.as_ref().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "InvalidParameterValue",
                "Docker/Podman is required for RDS snapshots but is not available",
            )
        })?;

        let (instance, db_name) = {
            let accounts = self.state.read();
            let empty = RdsState::new(&request.account_id, &request.region);
            let state = accounts.get(&request.account_id).unwrap_or(&empty);

            if state.snapshots.contains_key(&db_snapshot_identifier) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::CONFLICT,
                    "DBSnapshotAlreadyExists",
                    format!("DBSnapshot {db_snapshot_identifier} already exists."),
                ));
            }

            let instance = state
                .instances
                .get(&db_instance_identifier)
                .cloned()
                .ok_or_else(|| db_instance_not_found(&db_instance_identifier))?;

            let default_db = default_db_name(&instance.engine);
            let db_name = instance
                .db_name
                .as_deref()
                .unwrap_or(default_db)
                .to_string();

            (instance, db_name)
        };

        let dump_data = runtime
            .dump_database(
                &db_instance_identifier,
                &instance.engine,
                &instance.master_username,
                &instance.master_user_password,
                &db_name,
            )
            .await
            .map_err(runtime_error_to_service_error)?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        if state.snapshots.contains_key(&db_snapshot_identifier) {
            return Err(AwsServiceError::aws_error(
                StatusCode::CONFLICT,
                "DBSnapshotAlreadyExists",
                format!("DBSnapshot {db_snapshot_identifier} already exists."),
            ));
        }

        let snapshot = DbSnapshot {
            db_snapshot_identifier: db_snapshot_identifier.clone(),
            db_snapshot_arn: state.db_snapshot_arn(&db_snapshot_identifier),
            db_instance_identifier: instance.db_instance_identifier.clone(),
            snapshot_create_time: Utc::now(),
            engine: instance.engine.clone(),
            engine_version: instance.engine_version.clone(),
            allocated_storage: instance.allocated_storage,
            status: "available".to_string(),
            port: instance.port,
            master_username: instance.master_username.clone(),
            db_name: instance.db_name.clone(),
            dbi_resource_id: instance.dbi_resource_id.clone(),
            snapshot_type: "manual".to_string(),
            master_user_password: instance.master_user_password.clone(),
            tags: Vec::new(),
            dump_data,
        };

        state
            .snapshots
            .insert(db_snapshot_identifier.clone(), snapshot.clone());
        let snapshot_arn = snapshot.db_snapshot_arn.clone();
        drop(accounts);

        self.emit_event(
            RdsSourceType::DbSnapshot,
            &db_snapshot_identifier,
            &snapshot_arn,
            "RDS-EVENT-0042",
            &["creation"],
            "Manual snapshot created",
        );

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "CreateDBSnapshot",
                RDS_NS,
                &format!("<DBSnapshot>{}</DBSnapshot>", db_snapshot_xml(&snapshot)),
                &request.request_id,
            ),
        ))
    }

    fn describe_db_snapshots(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let db_snapshot_identifier = optional_query_param(request, "DBSnapshotIdentifier");
        let db_instance_identifier = optional_query_param(request, "DBInstanceIdentifier");
        let marker = optional_query_param(request, "Marker");
        let max_records = optional_query_param(request, "MaxRecords");

        if db_snapshot_identifier.is_some() && db_instance_identifier.is_some() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterCombination",
                "Cannot specify both DBSnapshotIdentifier and DBInstanceIdentifier.",
            ));
        }

        let accounts = self.state.read();
        let empty = RdsState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);

        // If specific snapshot requested, return just that one (no pagination)
        if let Some(snapshot_id) = db_snapshot_identifier {
            let snapshot = state
                .snapshots
                .get(&snapshot_id)
                .cloned()
                .ok_or_else(|| db_snapshot_not_found(&snapshot_id))?;

            return Ok(AwsResponse::xml(
                StatusCode::OK,
                query_response_xml(
                    "DescribeDBSnapshots",
                    RDS_NS,
                    &format!(
                        "<DBSnapshots><DBSnapshot>{}</DBSnapshot></DBSnapshots>",
                        db_snapshot_xml(&snapshot)
                    ),
                    &request.request_id,
                ),
            ));
        }

        // Get snapshots, filtered by instance identifier if provided
        let mut snapshots: Vec<DbSnapshot> = if let Some(instance_id) = db_instance_identifier {
            state
                .snapshots
                .values()
                .filter(|s| s.db_instance_identifier == instance_id)
                .cloned()
                .collect()
        } else {
            state.snapshots.values().cloned().collect()
        };

        // Sort by creation time, then identifier
        snapshots.sort_by(|a, b| {
            a.snapshot_create_time
                .cmp(&b.snapshot_create_time)
                .then_with(|| a.db_snapshot_identifier.cmp(&b.db_snapshot_identifier))
        });

        // Apply pagination
        let paginated = paginate(snapshots, marker, max_records, |snap| {
            &snap.db_snapshot_identifier
        })?;

        let marker_xml = paginated
            .next_marker
            .as_ref()
            .map(|m| format!("<Marker>{}</Marker>", xml_escape(m)))
            .unwrap_or_default();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeDBSnapshots",
                RDS_NS,
                &format!(
                    "<DBSnapshots>{}</DBSnapshots>{}",
                    paginated
                        .items
                        .iter()
                        .map(|snapshot| format!(
                            "<DBSnapshot>{}</DBSnapshot>",
                            db_snapshot_xml(snapshot)
                        ))
                        .collect::<String>(),
                    marker_xml
                ),
                &request.request_id,
            ),
        ))
    }

    fn delete_db_snapshot(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let db_snapshot_identifier = required_query_param(request, "DBSnapshotIdentifier")?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        let snapshot = state
            .snapshots
            .remove(&db_snapshot_identifier)
            .ok_or_else(|| db_snapshot_not_found(&db_snapshot_identifier))?;
        let snapshot_arn = snapshot.db_snapshot_arn.clone();
        drop(accounts);

        self.emit_event(
            RdsSourceType::DbSnapshot,
            &db_snapshot_identifier,
            &snapshot_arn,
            "RDS-EVENT-0041",
            &["deletion"],
            "Manual snapshot deleted",
        );

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DeleteDBSnapshot",
                RDS_NS,
                &format!("<DBSnapshot>{}</DBSnapshot>", db_snapshot_xml(&snapshot)),
                &request.request_id,
            ),
        ))
    }

    async fn restore_db_instance_from_db_snapshot(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let db_instance_identifier = required_query_param(request, "DBInstanceIdentifier")?;
        let db_snapshot_identifier = required_query_param(request, "DBSnapshotIdentifier")?;
        let vpc_security_group_ids = parse_vpc_security_group_ids(request);

        let runtime = self.require_runtime()?;

        let (snapshot, dbi_resource_id, db_instance_arn, created_at) = {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);

            if !state.begin_instance_creation(&db_instance_identifier) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::CONFLICT,
                    "DBInstanceAlreadyExists",
                    format!("DBInstance {db_instance_identifier} already exists."),
                ));
            }

            let snapshot = match state.snapshots.get(&db_snapshot_identifier).cloned() {
                Some(s) => s,
                None => {
                    state.cancel_instance_creation(&db_instance_identifier);
                    return Err(db_snapshot_not_found(&db_snapshot_identifier));
                }
            };

            let dbi_resource_id = state.next_dbi_resource_id();
            let db_instance_arn = state.db_instance_arn(&db_instance_identifier);
            let created_at = Utc::now();

            (snapshot, dbi_resource_id, db_instance_arn, created_at)
        };

        let db_name = snapshot
            .db_name
            .as_deref()
            .unwrap_or(default_db_name(&snapshot.engine));
        let running = match runtime
            .ensure_postgres(
                &db_instance_identifier,
                &snapshot.engine,
                &snapshot.engine_version,
                &snapshot.master_username,
                &snapshot.master_user_password,
                db_name,
                &request.account_id,
                &request.region,
            )
            .await
        {
            Ok(running) => running,
            Err(e) => {
                self.state
                    .write()
                    .get_or_create(&request.account_id)
                    .cancel_instance_creation(&db_instance_identifier);
                return Err(runtime_error_to_service_error(e));
            }
        };

        if let Err(e) = runtime
            .restore_database(
                &db_instance_identifier,
                &snapshot.engine,
                &snapshot.master_username,
                &snapshot.master_user_password,
                db_name,
                &snapshot.dump_data,
            )
            .await
        {
            self.state
                .write()
                .get_or_create(&request.account_id)
                .cancel_instance_creation(&db_instance_identifier);
            runtime.stop_container(&db_instance_identifier).await;
            return Err(runtime_error_to_service_error(e));
        }

        let instance = build_restored_instance(
            &db_instance_identifier,
            db_instance_arn,
            dbi_resource_id,
            created_at,
            vpc_security_group_ids,
            &snapshot,
            &running,
        );

        self.state
            .write()
            .get_or_create(&request.account_id)
            .finish_instance_creation(instance.clone());

        self.emit_event(
            RdsSourceType::DbInstance,
            &db_instance_identifier,
            &instance.db_instance_arn,
            "RDS-EVENT-0043",
            &["creation"],
            "DB instance restored from snapshot",
        );

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "RestoreDBInstanceFromDBSnapshot",
                RDS_NS,
                &format!(
                    "<DBInstance>{}</DBInstance>",
                    db_instance_xml(&instance, None)
                ),
                &request.request_id,
            ),
        ))
    }

    async fn create_db_instance_read_replica(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let db_instance_identifier = required_query_param(request, "DBInstanceIdentifier")?;
        let source_db_instance_identifier =
            required_query_param(request, "SourceDBInstanceIdentifier")?;

        let runtime = self.runtime.as_ref().ok_or_else(|| {
            AwsServiceError::aws_error(
                StatusCode::SERVICE_UNAVAILABLE,
                "InvalidParameterValue",
                "Docker/Podman is required for RDS read replicas but is not available",
            )
        })?;

        let (source_instance, db_name) = {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);

            if !state.begin_instance_creation(&db_instance_identifier) {
                return Err(AwsServiceError::aws_error(
                    StatusCode::CONFLICT,
                    "DBInstanceAlreadyExists",
                    format!("DBInstance {db_instance_identifier} already exists."),
                ));
            }

            let source_instance = match state.instances.get(&source_db_instance_identifier).cloned()
            {
                Some(inst) => inst,
                None => {
                    state.cancel_instance_creation(&db_instance_identifier);
                    return Err(db_instance_not_found(&source_db_instance_identifier));
                }
            };

            let default_db = default_db_name(&source_instance.engine);
            let db_name = source_instance
                .db_name
                .as_deref()
                .unwrap_or(default_db)
                .to_string();

            (source_instance, db_name)
        };

        let dump_data = match runtime
            .dump_database(
                &source_db_instance_identifier,
                &source_instance.engine,
                &source_instance.master_username,
                &source_instance.master_user_password,
                &db_name,
            )
            .await
        {
            Ok(data) => data,
            Err(e) => {
                self.state
                    .write()
                    .get_or_create(&request.account_id)
                    .cancel_instance_creation(&db_instance_identifier);
                return Err(runtime_error_to_service_error(e));
            }
        };

        let (dbi_resource_id, db_instance_arn) = {
            let accounts = self.state.read();
            let empty = RdsState::new(&request.account_id, &request.region);
            let s = accounts.get(&request.account_id).unwrap_or(&empty);
            (
                s.next_dbi_resource_id(),
                s.db_instance_arn(&db_instance_identifier),
            )
        };
        let created_at = Utc::now();

        let running = match runtime
            .ensure_postgres(
                &db_instance_identifier,
                &source_instance.engine,
                &source_instance.engine_version,
                &source_instance.master_username,
                &source_instance.master_user_password,
                &db_name,
                &request.account_id,
                &request.region,
            )
            .await
        {
            Ok(running) => running,
            Err(e) => {
                self.state
                    .write()
                    .get_or_create(&request.account_id)
                    .cancel_instance_creation(&db_instance_identifier);
                return Err(runtime_error_to_service_error(e));
            }
        };

        if let Err(e) = runtime
            .restore_database(
                &db_instance_identifier,
                &source_instance.engine,
                &source_instance.master_username,
                &source_instance.master_user_password,
                &db_name,
                &dump_data,
            )
            .await
        {
            self.state
                .write()
                .get_or_create(&request.account_id)
                .cancel_instance_creation(&db_instance_identifier);
            runtime.stop_container(&db_instance_identifier).await;
            return Err(runtime_error_to_service_error(e));
        }

        let replica = build_read_replica_instance(
            &db_instance_identifier,
            db_instance_arn,
            dbi_resource_id,
            created_at,
            &source_db_instance_identifier,
            &source_instance,
            &running,
        );

        let source_missing = {
            let mut accounts = self.state.write();
            let state = accounts.get_or_create(&request.account_id);
            match state.instances.get_mut(&source_db_instance_identifier) {
                Some(source) => {
                    source
                        .read_replica_db_instance_identifiers
                        .push(db_instance_identifier.clone());
                    state.finish_instance_creation(replica.clone());
                    false
                }
                None => {
                    state.cancel_instance_creation(&db_instance_identifier);
                    true
                }
            }
        };

        if source_missing {
            runtime.stop_container(&db_instance_identifier).await;
            return Err(db_instance_not_found(&source_db_instance_identifier));
        }

        self.emit_event(
            RdsSourceType::DbInstance,
            &db_instance_identifier,
            &replica.db_instance_arn,
            "RDS-EVENT-0005",
            &["creation", "read replica"],
            "Read replica DB instance created",
        );

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "CreateDBInstanceReadReplica",
                RDS_NS,
                &format!(
                    "<DBInstance>{}</DBInstance>",
                    db_instance_xml(&replica, None)
                ),
                &request.request_id,
            ),
        ))
    }

    fn create_db_subnet_group(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let db_subnet_group_name = required_query_param(request, "DBSubnetGroupName")?;
        let db_subnet_group_description =
            required_query_param(request, "DBSubnetGroupDescription")?;
        let subnet_ids = parse_subnet_ids(request)?;

        if subnet_ids.is_empty() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                "At least one subnet must be specified.",
            ));
        }

        if subnet_ids.len() < 2 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "DBSubnetGroupDoesNotCoverEnoughAZs",
                "DB Subnet Group must contain at least 2 subnets in different Availability Zones.",
            ));
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        if state.subnet_groups.contains_key(&db_subnet_group_name) {
            return Err(AwsServiceError::aws_error(
                StatusCode::CONFLICT,
                "DBSubnetGroupAlreadyExists",
                format!("DBSubnetGroup {db_subnet_group_name} already exists."),
            ));
        }

        let vpc_id = format!("vpc-{}", uuid::Uuid::new_v4().simple());
        let subnet_availability_zones: Vec<String> = (0..subnet_ids.len())
            .map(|i| format!("{}{}", &state.region, char::from(b'a' + (i % 6) as u8)))
            .collect();

        // Validate that subnets span at least 2 unique Availability Zones
        let unique_azs: std::collections::HashSet<_> = subnet_availability_zones.iter().collect();
        if unique_azs.len() < 2 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "DBSubnetGroupDoesNotCoverEnoughAZs",
                "DB Subnet Group must contain at least 2 subnets in different Availability Zones.",
            ));
        }

        let db_subnet_group_arn = state.db_subnet_group_arn(&db_subnet_group_name);
        let tags = parse_tags(request)?;

        let subnet_group = DbSubnetGroup {
            db_subnet_group_name: db_subnet_group_name.clone(),
            db_subnet_group_arn,
            db_subnet_group_description,
            vpc_id,
            subnet_ids,
            subnet_availability_zones,
            tags,
        };

        state
            .subnet_groups
            .insert(db_subnet_group_name, subnet_group.clone());

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "CreateDBSubnetGroup",
                RDS_NS,
                &format!(
                    "<DBSubnetGroup>{}</DBSubnetGroup>",
                    db_subnet_group_xml(&subnet_group)
                ),
                &request.request_id,
            ),
        ))
    }

    fn describe_db_subnet_groups(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let db_subnet_group_name = optional_query_param(request, "DBSubnetGroupName");
        let marker = optional_query_param(request, "Marker");
        let max_records = optional_query_param(request, "MaxRecords");

        let accounts = self.state.read();
        let empty = RdsState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);

        // If specific subnet group requested, return just that one (no pagination)
        if let Some(name) = db_subnet_group_name {
            let sg = state.subnet_groups.get(&name).ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "DBSubnetGroupNotFoundFault",
                    format!("DBSubnetGroup {} not found.", name),
                )
            })?;

            return Ok(AwsResponse::xml(
                StatusCode::OK,
                query_response_xml(
                    "DescribeDBSubnetGroups",
                    RDS_NS,
                    &format!(
                        "<DBSubnetGroups><DBSubnetGroup>{}</DBSubnetGroup></DBSubnetGroups>",
                        db_subnet_group_xml(sg)
                    ),
                    &request.request_id,
                ),
            ));
        }

        // Get all subnet groups sorted by name
        let mut subnet_groups: Vec<DbSubnetGroup> = state.subnet_groups.values().cloned().collect();
        subnet_groups.sort_by(|a, b| a.db_subnet_group_name.cmp(&b.db_subnet_group_name));

        // Apply pagination
        let paginated = paginate(subnet_groups, marker, max_records, |sg| {
            &sg.db_subnet_group_name
        })?;

        let marker_xml = paginated
            .next_marker
            .as_ref()
            .map(|m| format!("<Marker>{}</Marker>", xml_escape(m)))
            .unwrap_or_default();

        let body = paginated
            .items
            .iter()
            .map(|sg| format!("<DBSubnetGroup>{}</DBSubnetGroup>", db_subnet_group_xml(sg)))
            .collect::<Vec<_>>()
            .join("");

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeDBSubnetGroups",
                RDS_NS,
                &format!("<DBSubnetGroups>{}</DBSubnetGroups>{}", body, marker_xml),
                &request.request_id,
            ),
        ))
    }

    fn delete_db_subnet_group(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let db_subnet_group_name = required_query_param(request, "DBSubnetGroupName")?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        if state.subnet_groups.remove(&db_subnet_group_name).is_none() {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "DBSubnetGroupNotFoundFault",
                format!("DBSubnetGroup {db_subnet_group_name} not found."),
            ));
        }

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml("DeleteDBSubnetGroup", RDS_NS, "", &request.request_id),
        ))
    }

    fn modify_db_subnet_group(&self, request: &AwsRequest) -> Result<AwsResponse, AwsServiceError> {
        let db_subnet_group_name = required_query_param(request, "DBSubnetGroupName")?;
        let subnet_ids = parse_subnet_ids(request)?;

        if subnet_ids.is_empty() {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                "At least one subnet must be specified.",
            ));
        }

        if subnet_ids.len() < 2 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "DBSubnetGroupDoesNotCoverEnoughAZs",
                "DB Subnet Group must contain at least 2 subnets in different Availability Zones.",
            ));
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        let region = state.region.clone();

        let subnet_group = state
            .subnet_groups
            .get_mut(&db_subnet_group_name)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "DBSubnetGroupNotFoundFault",
                    format!("DBSubnetGroup {db_subnet_group_name} not found."),
                )
            })?;

        let subnet_availability_zones: Vec<String> = (0..subnet_ids.len())
            .map(|i| format!("{}{}", &region, char::from(b'a' + (i % 6) as u8)))
            .collect();

        // Validate that subnets span at least 2 unique Availability Zones
        let unique_azs: std::collections::HashSet<_> = subnet_availability_zones.iter().collect();
        if unique_azs.len() < 2 {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "DBSubnetGroupDoesNotCoverEnoughAZs",
                "DB Subnet Group must contain at least 2 subnets in different Availability Zones.",
            ));
        }

        subnet_group.subnet_ids = subnet_ids;
        subnet_group.subnet_availability_zones = subnet_availability_zones;

        let subnet_group_clone = subnet_group.clone();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "ModifyDBSubnetGroup",
                RDS_NS,
                &format!(
                    "<DBSubnetGroup>{}</DBSubnetGroup>",
                    db_subnet_group_xml(&subnet_group_clone)
                ),
                &request.request_id,
            ),
        ))
    }

    fn create_db_parameter_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let db_parameter_group_name = required_query_param(request, "DBParameterGroupName")?;
        let db_parameter_group_family = required_query_param(request, "DBParameterGroupFamily")?;
        let description = required_query_param(request, "Description")?;

        // Validate parameter group family against supported engines and versions
        let valid_families = [
            "postgres16",
            "postgres15",
            "postgres14",
            "postgres13",
            "mysql8.0",
            "mysql5.7",
            "mariadb10.11",
            "mariadb10.6",
        ];

        if !valid_families.contains(&db_parameter_group_family.as_str()) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                format!("DBParameterGroupFamily '{db_parameter_group_family}' is not supported."),
            ));
        }

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        if state
            .parameter_groups
            .contains_key(&db_parameter_group_name)
        {
            return Err(AwsServiceError::aws_error(
                StatusCode::CONFLICT,
                "DBParameterGroupAlreadyExists",
                format!("DBParameterGroup {db_parameter_group_name} already exists."),
            ));
        }

        let db_parameter_group_arn = state.db_parameter_group_arn(&db_parameter_group_name);
        let tags = parse_tags(request)?;

        let parameter_group = DbParameterGroup {
            db_parameter_group_name: db_parameter_group_name.clone(),
            db_parameter_group_arn,
            db_parameter_group_family,
            description,
            parameters: std::collections::BTreeMap::new(),
            tags,
        };

        state
            .parameter_groups
            .insert(db_parameter_group_name, parameter_group.clone());

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "CreateDBParameterGroup",
                RDS_NS,
                &format!(
                    "<DBParameterGroup>{}</DBParameterGroup>",
                    db_parameter_group_xml(&parameter_group)
                ),
                &request.request_id,
            ),
        ))
    }

    fn describe_db_parameter_groups(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let db_parameter_group_name = optional_query_param(request, "DBParameterGroupName");
        let marker = optional_query_param(request, "Marker");
        let max_records = optional_query_param(request, "MaxRecords");

        let accounts = self.state.read();
        let empty = RdsState::new(&request.account_id, &request.region);
        let state = accounts.get(&request.account_id).unwrap_or(&empty);

        // If specific parameter group requested, return just that one (no pagination)
        if let Some(name) = db_parameter_group_name {
            let pg = state.parameter_groups.get(&name).ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "DBParameterGroupNotFound",
                    format!("DBParameterGroup {} not found.", name),
                )
            })?;

            return Ok(AwsResponse::xml(
                StatusCode::OK,
                query_response_xml(
                    "DescribeDBParameterGroups", RDS_NS,
                    &format!(
                        "<DBParameterGroups><DBParameterGroup>{}</DBParameterGroup></DBParameterGroups>",
                        db_parameter_group_xml(pg)
                    ),
                    &request.request_id,
                ),
            ));
        }

        // Get all parameter groups sorted by name
        let mut parameter_groups: Vec<DbParameterGroup> =
            state.parameter_groups.values().cloned().collect();
        parameter_groups.sort_by(|a, b| a.db_parameter_group_name.cmp(&b.db_parameter_group_name));

        // Apply pagination
        let paginated = paginate(parameter_groups, marker, max_records, |pg| {
            &pg.db_parameter_group_name
        })?;

        let marker_xml = paginated
            .next_marker
            .as_ref()
            .map(|m| format!("<Marker>{}</Marker>", xml_escape(m)))
            .unwrap_or_default();

        let body = paginated
            .items
            .iter()
            .map(|pg| {
                format!(
                    "<DBParameterGroup>{}</DBParameterGroup>",
                    db_parameter_group_xml(pg)
                )
            })
            .collect::<Vec<_>>()
            .join("");

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "DescribeDBParameterGroups",
                RDS_NS,
                &format!(
                    "<DBParameterGroups>{}</DBParameterGroups>{}",
                    body, marker_xml
                ),
                &request.request_id,
            ),
        ))
    }

    fn delete_db_parameter_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let db_parameter_group_name = required_query_param(request, "DBParameterGroupName")?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        if db_parameter_group_name.starts_with("default.") {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                "Cannot delete default parameter groups.",
            ));
        }

        if state
            .parameter_groups
            .remove(&db_parameter_group_name)
            .is_none()
        {
            return Err(AwsServiceError::aws_error(
                StatusCode::NOT_FOUND,
                "DBParameterGroupNotFound",
                format!("DBParameterGroup {db_parameter_group_name} not found."),
            ));
        }

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml("DeleteDBParameterGroup", RDS_NS, "", &request.request_id),
        ))
    }

    fn modify_db_parameter_group(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let db_parameter_group_name = required_query_param(request, "DBParameterGroupName")?;

        let mut accounts = self.state.write();
        let state = accounts.get_or_create(&request.account_id);

        let parameter_group = state
            .parameter_groups
            .get_mut(&db_parameter_group_name)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "DBParameterGroupNotFound",
                    format!("DBParameterGroup {db_parameter_group_name} not found."),
                )
            })?;

        if let Some(new_description) = optional_query_param(request, "Description") {
            parameter_group.description = new_description;
        }

        let parameter_group_clone = parameter_group.clone();

        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml(
                "ModifyDBParameterGroup",
                RDS_NS,
                &format!(
                    "<DBParameterGroupName>{}</DBParameterGroupName>",
                    xml_escape(&parameter_group_clone.db_parameter_group_name)
                ),
                &request.request_id,
            ),
        ))
    }
}

fn required_i32_param(req: &AwsRequest, name: &str) -> Result<i32, AwsServiceError> {
    let value = required_query_param(req, name)?;
    value.parse::<i32>().map_err(|_| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterValue",
            format!("Parameter {name} must be a valid integer."),
        )
    })
}

fn optional_i32_param(req: &AwsRequest, name: &str) -> Result<Option<i32>, AwsServiceError> {
    optional_query_param(req, name)
        .map(|value| {
            value.parse::<i32>().map_err(|_| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    format!("Parameter {name} must be a valid integer."),
                )
            })
        })
        .transpose()
}

fn parse_tags(req: &AwsRequest) -> Result<Vec<RdsTag>, AwsServiceError> {
    let mut tags = Vec::new();
    for index in 1.. {
        let key_name = format!("Tags.Tag.{index}.Key");
        let value_name = format!("Tags.Tag.{index}.Value");
        let key = optional_query_param(req, &key_name);
        let value = optional_query_param(req, &value_name);

        match (key, value) {
            (Some(key), Some(value)) => tags.push(RdsTag { key, value }),
            (None, None) => break,
            _ => {
                return Err(AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    "Each tag must include both Key and Value.",
                ));
            }
        }
    }

    Ok(tags)
}

fn parse_tag_keys(req: &AwsRequest) -> Result<Vec<String>, AwsServiceError> {
    let mut keys = Vec::new();
    for index in 1.. {
        let key_name = format!("TagKeys.member.{index}");
        match optional_query_param(req, &key_name) {
            Some(key) => keys.push(key),
            None => break,
        }
    }

    Ok(keys)
}

fn parse_subnet_ids(req: &AwsRequest) -> Result<Vec<String>, AwsServiceError> {
    let mut subnet_ids = Vec::new();
    for index in 1.. {
        let subnet_id_name = format!("SubnetIds.SubnetIdentifier.{index}");
        match optional_query_param(req, &subnet_id_name) {
            Some(subnet_id) => subnet_ids.push(subnet_id),
            None => break,
        }
    }

    Ok(subnet_ids)
}

fn parse_vpc_security_group_ids(req: &AwsRequest) -> Vec<String> {
    let mut security_group_ids = Vec::new();
    for index in 1.. {
        let sg_id_name = format!("VpcSecurityGroupIds.VpcSecurityGroupId.{index}");
        match optional_query_param(req, &sg_id_name) {
            Some(sg_id) => security_group_ids.push(sg_id),
            None => break,
        }
    }

    // If no security groups provided, return a default one
    if security_group_ids.is_empty() {
        security_group_ids.push("sg-default".to_string());
    }

    security_group_ids
}

fn query_param_prefix_exists(req: &AwsRequest, prefix: &str) -> bool {
    req.query_params.keys().any(|key| key.starts_with(prefix))
}

fn parse_optional_bool(value: Option<&str>) -> Result<Option<bool>, AwsServiceError> {
    value
        .map(|raw| match raw {
            "true" | "True" | "TRUE" => Ok(true),
            "false" | "False" | "FALSE" => Ok(false),
            _ => Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                format!("Boolean parameter value '{raw}' is invalid."),
            )),
        })
        .transpose()
}

struct PaginationResult<T> {
    items: Vec<T>,
    next_marker: Option<String>,
}

fn paginate<T, F>(
    mut items: Vec<T>,
    marker: Option<String>,
    max_records: Option<String>,
    get_id: F,
) -> Result<PaginationResult<T>, AwsServiceError>
where
    F: Fn(&T) -> &str,
{
    // Parse max_records with default 100, max 100
    let max = if let Some(max_str) = max_records {
        let parsed = max_str.parse::<i32>().map_err(|_| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                "MaxRecords must be a valid integer.",
            )
        })?;
        if !(1..=100).contains(&parsed) {
            return Err(AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                "MaxRecords must be between 1 and 100.",
            ));
        }
        parsed as usize
    } else {
        100
    };

    // Decode marker to get starting identifier
    let start_id = if let Some(encoded_marker) = marker {
        let decoded = BASE64.decode(encoded_marker.as_bytes()).map_err(|_| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                "Marker is invalid.",
            )
        })?;
        let id = String::from_utf8(decoded).map_err(|_| {
            AwsServiceError::aws_error(
                StatusCode::BAD_REQUEST,
                "InvalidParameterValue",
                "Marker is invalid.",
            )
        })?;
        Some(id)
    } else {
        None
    };

    // Find starting position
    let start_index = if let Some(ref start_id) = start_id {
        items
            .iter()
            .position(|item| get_id(item) == start_id)
            .map(|pos| pos + 1) // Start after the marker
            .unwrap_or(items.len()) // If not found, return empty result
    } else {
        0
    };

    // Take items from start_index
    let total_items = items.len();
    let end_index = std::cmp::min(start_index + max, total_items);
    let paginated_items: Vec<T> = items.drain(start_index..end_index).collect();

    // Create next marker if there are more items
    let next_marker = if end_index < total_items {
        paginated_items
            .last()
            .map(|item| BASE64.encode(get_id(item).as_bytes()))
    } else {
        None
    };

    Ok(PaginationResult {
        items: paginated_items,
        next_marker,
    })
}

fn validate_create_request(
    db_instance_identifier: &str,
    allocated_storage: i32,
    db_instance_class: &str,
    engine: &str,
    engine_version: &str,
    port: i32,
) -> Result<(), AwsServiceError> {
    if allocated_storage <= 0 {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterValue",
            "AllocatedStorage must be greater than zero.",
        ));
    }
    if port <= 0 {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterValue",
            "Port must be greater than zero.",
        ));
    }
    if !db_instance_identifier
        .chars()
        .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
    {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterValue",
            "DBInstanceIdentifier must contain only alphanumeric characters or hyphens.",
        ));
    }
    // Validate engine
    let supported_engines = [
        "postgres",
        "mysql",
        "mariadb",
        "oracle-ee",
        "oracle-se2",
        "oracle-ee-cdb",
        "oracle-se2-cdb",
        "sqlserver-ee",
        "sqlserver-se",
        "sqlserver-ex",
        "sqlserver-web",
        "db2-se",
        "db2-ae",
    ];
    if !supported_engines.contains(&engine) {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterValue",
            format!("Engine '{}' is not supported.", engine),
        ));
    }

    // Validate engine version. The Oracle/SQL Server/Db2 lists track
    // the major-minor versions actually shipped by the upstream
    // dev-edition images (gvenzl/oracle-free 23, mssql-server 2022,
    // db2_community 11.5). Adding a new version here also requires
    // wiring the image tag in `RdsRuntime::ensure_postgres`.
    // Major versions ("8.0", "10.11", ...) are accepted alongside the
    // full `<major>.<minor>.<patch>` triplets — AWS RDS validates both
    // forms and the runtime resolves the matching prebuilt image regardless.
    let supported_versions = match engine {
        "postgres" => vec!["16", "15", "14", "13", "16.3", "15.5", "14.10", "13.13"],
        "mysql" => vec!["8.0", "8.0.35", "8.0.28", "5.7.44"],
        "mariadb" => vec!["10.6", "10.11", "11.4", "11.4.5", "10.11.6", "10.6.16"],
        "oracle-ee" | "oracle-se2" | "oracle-ee-cdb" | "oracle-se2-cdb" => {
            vec!["23.0.0", "21.0.0", "19.0.0"]
        }
        "sqlserver-ee" | "sqlserver-se" | "sqlserver-ex" | "sqlserver-web" => {
            vec!["16.00.4085.2.v1", "15.00.4322.2.v1"]
        }
        "db2-se" | "db2-ae" => vec!["11.5.9.0.sb00000000.r1", "11.5.8.0.sb00000000.r1"],
        _ => vec![],
    };

    if !supported_versions.contains(&engine_version) {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterValue",
            format!("EngineVersion '{engine_version}' is not supported yet."),
        ));
    }
    validate_db_instance_class(db_instance_class)?;
    Ok(())
}

fn validate_db_instance_class(db_instance_class: &str) -> Result<(), AwsServiceError> {
    if !crate::state::SUPPORTED_INSTANCE_CLASSES.contains(&db_instance_class) {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterValue",
            format!("DBInstanceClass '{}' is not supported.", db_instance_class),
        ));
    }
    Ok(())
}

fn filter_engine_versions(
    versions: &[EngineVersionInfo],
    engine: &Option<String>,
    engine_version: &Option<String>,
    family: &Option<String>,
) -> Vec<EngineVersionInfo> {
    versions
        .iter()
        .filter(|candidate| {
            engine
                .as_ref()
                .is_none_or(|expected| candidate.engine == *expected)
        })
        .filter(|candidate| {
            engine_version
                .as_ref()
                .is_none_or(|expected| candidate.engine_version == *expected)
        })
        .filter(|candidate| {
            family
                .as_ref()
                .is_none_or(|expected| candidate.db_parameter_group_family == *expected)
        })
        .cloned()
        .collect()
}

fn filter_orderable_options(
    options: &[OrderableDbInstanceOption],
    engine: &Option<String>,
    engine_version: &Option<String>,
    db_instance_class: &Option<String>,
    license_model: &Option<String>,
    vpc: Option<bool>,
) -> Vec<OrderableDbInstanceOption> {
    options
        .iter()
        .filter(|candidate| {
            engine
                .as_ref()
                .is_none_or(|expected| candidate.engine == *expected)
        })
        .filter(|candidate| {
            engine_version
                .as_ref()
                .is_none_or(|expected| candidate.engine_version == *expected)
        })
        .filter(|candidate| {
            db_instance_class
                .as_ref()
                .is_none_or(|expected| candidate.db_instance_class == *expected)
        })
        .filter(|candidate| {
            license_model
                .as_ref()
                .is_none_or(|expected| candidate.license_model == *expected)
        })
        .filter(|_| vpc.unwrap_or(true))
        .cloned()
        .collect()
}

/// Build a `DbInstance` for a newly-created read replica, copying the
/// source instance's physical attributes and binding the replica's
/// identifier, ARN, resource id, container id and host port.
#[allow(clippy::too_many_arguments)]
/// Build a `DbInstance` from a restored snapshot. Copies the physical
/// attributes off the snapshot and binds the new instance's identifier,
/// ARN, resource id, container id and host port.
fn build_restored_instance(
    db_instance_identifier: &str,
    db_instance_arn: String,
    dbi_resource_id: String,
    created_at: chrono::DateTime<Utc>,
    vpc_security_group_ids: Vec<String>,
    snapshot: &DbSnapshot,
    running: &crate::runtime::RunningDbContainer,
) -> DbInstance {
    DbInstance {
        db_instance_identifier: db_instance_identifier.to_string(),
        db_instance_arn,
        db_instance_class: "db.t3.micro".to_string(),
        engine: snapshot.engine.clone(),
        engine_version: snapshot.engine_version.clone(),
        db_instance_status: "available".to_string(),
        master_username: snapshot.master_username.clone(),
        db_name: snapshot.db_name.clone(),
        endpoint_address: "127.0.0.1".to_string(),
        port: i32::from(running.host_port),
        allocated_storage: snapshot.allocated_storage,
        publicly_accessible: true,
        deletion_protection: false,
        created_at,
        dbi_resource_id,
        master_user_password: snapshot.master_user_password.clone(),
        container_id: running.container_id.clone(),
        host_port: running.host_port,
        tags: Vec::new(),
        read_replica_source_db_instance_identifier: None,
        read_replica_db_instance_identifiers: Vec::new(),
        vpc_security_group_ids,
        db_parameter_group_name: None,
        backup_retention_period: 1,
        preferred_backup_window: "03:00-04:00".to_string(),
        latest_restorable_time: Some(created_at),
        option_group_name: None,
        multi_az: false,
        pending_modified_values: None,
    }
}

fn build_read_replica_instance(
    db_instance_identifier: &str,
    db_instance_arn: String,
    dbi_resource_id: String,
    created_at: chrono::DateTime<Utc>,
    source_db_instance_identifier: &str,
    source: &DbInstance,
    running: &crate::runtime::RunningDbContainer,
) -> DbInstance {
    DbInstance {
        db_instance_identifier: db_instance_identifier.to_string(),
        db_instance_arn,
        db_instance_class: source.db_instance_class.clone(),
        engine: source.engine.clone(),
        engine_version: source.engine_version.clone(),
        db_instance_status: "available".to_string(),
        master_username: source.master_username.clone(),
        db_name: source.db_name.clone(),
        endpoint_address: "127.0.0.1".to_string(),
        port: i32::from(running.host_port),
        allocated_storage: source.allocated_storage,
        publicly_accessible: source.publicly_accessible,
        deletion_protection: false,
        created_at,
        dbi_resource_id,
        master_user_password: source.master_user_password.clone(),
        container_id: running.container_id.clone(),
        host_port: running.host_port,
        tags: Vec::new(),
        read_replica_source_db_instance_identifier: Some(source_db_instance_identifier.to_string()),
        read_replica_db_instance_identifiers: Vec::new(),
        vpc_security_group_ids: source.vpc_security_group_ids.clone(),
        db_parameter_group_name: source.db_parameter_group_name.clone(),
        backup_retention_period: source.backup_retention_period,
        preferred_backup_window: source.preferred_backup_window.clone(),
        latest_restorable_time: if source.backup_retention_period > 0 {
            Some(created_at)
        } else {
            None
        },
        option_group_name: source.option_group_name.clone(),
        multi_az: source.multi_az,
        pending_modified_values: None,
    }
}

fn engine_version_xml(version: &EngineVersionInfo) -> String {
    format!(
        "<DBEngineVersion>\
         <Engine>{}</Engine>\
         <EngineVersion>{}</EngineVersion>\
         <DBParameterGroupFamily>{}</DBParameterGroupFamily>\
         <DBEngineDescription>{}</DBEngineDescription>\
         <DBEngineVersionDescription>{}</DBEngineVersionDescription>\
         <Status>{}</Status>\
         </DBEngineVersion>",
        xml_escape(&version.engine),
        xml_escape(&version.engine_version),
        xml_escape(&version.db_parameter_group_family),
        xml_escape(&version.db_engine_description),
        xml_escape(&version.db_engine_version_description),
        xml_escape(&version.status),
    )
}

fn orderable_option_xml(option: &OrderableDbInstanceOption) -> String {
    format!(
        "<OrderableDBInstanceOption>\
         <Engine>{}</Engine>\
         <EngineVersion>{}</EngineVersion>\
         <DBInstanceClass>{}</DBInstanceClass>\
         <LicenseModel>{}</LicenseModel>\
         <AvailabilityZones><AvailabilityZone><Name>us-east-1a</Name></AvailabilityZone></AvailabilityZones>\
         <MultiAZCapable>true</MultiAZCapable>\
         <ReadReplicaCapable>true</ReadReplicaCapable>\
         <Vpc>true</Vpc>\
         <SupportsStorageEncryption>true</SupportsStorageEncryption>\
         <StorageType>{}</StorageType>\
         <SupportsIops>false</SupportsIops>\
         <MinStorageSize>{}</MinStorageSize>\
         <MaxStorageSize>{}</MaxStorageSize>\
         <SupportsIAMDatabaseAuthentication>true</SupportsIAMDatabaseAuthentication>\
         </OrderableDBInstanceOption>",
        xml_escape(&option.engine),
        xml_escape(&option.engine_version),
        xml_escape(&option.db_instance_class),
        xml_escape(&option.license_model),
        xml_escape(&option.storage_type),
        option.min_storage_size,
        option.max_storage_size,
    )
}

fn tag_xml(tag: &RdsTag) -> String {
    format!(
        "<Tag><Key>{}</Key><Value>{}</Value></Tag>",
        xml_escape(&tag.key),
        xml_escape(&tag.value),
    )
}

/// Free-standing version of `emit_event` so background tasks (which
/// don't have a `&self`) can publish RDS events through the same path.
pub(crate) fn emit_event_static(
    delivery_bus: Option<&Arc<DeliveryBus>>,
    source_type: RdsSourceType,
    source_identifier: &str,
    source_arn: &str,
    event_id: &str,
    event_categories: &[&str],
    message: &str,
) {
    let Some(bus) = delivery_bus else {
        return;
    };
    let detail = serde_json::json!({
        "EventCategories": event_categories,
        "SourceType": source_type.as_str(),
        "SourceArn": source_arn,
        "Date": Utc::now().to_rfc3339(),
        "Message": message,
        "SourceIdentifier": source_identifier,
        "EventID": event_id,
    });
    bus.put_event_to_eventbridge(
        "aws.rds",
        source_type.detail_type(),
        &detail.to_string(),
        "default",
    );
}

fn db_instance_xml(instance: &DbInstance, status_override: Option<&str>) -> String {
    let status = status_override.unwrap_or(&instance.db_instance_status);
    let db_name_xml = instance
        .db_name
        .as_ref()
        .map(|db_name| format!("<DBName>{}</DBName>", xml_escape(db_name)))
        .unwrap_or_default();

    let read_replica_source_xml = instance
        .read_replica_source_db_instance_identifier
        .as_ref()
        .map(|source| {
            format!(
                "<ReadReplicaSourceDBInstanceIdentifier>{}</ReadReplicaSourceDBInstanceIdentifier>",
                xml_escape(source)
            )
        })
        .unwrap_or_default();

    let read_replica_identifiers_xml = if instance.read_replica_db_instance_identifiers.is_empty() {
        "<ReadReplicaDBInstanceIdentifiers/>".to_string()
    } else {
        format!(
            "<ReadReplicaDBInstanceIdentifiers>{}</ReadReplicaDBInstanceIdentifiers>",
            instance
                .read_replica_db_instance_identifiers
                .iter()
                .map(|id| format!(
                    "<ReadReplicaDBInstanceIdentifier>{}</ReadReplicaDBInstanceIdentifier>",
                    xml_escape(id)
                ))
                .collect::<String>()
        )
    };

    let vpc_security_groups_xml = if instance.vpc_security_group_ids.is_empty() {
        "<VpcSecurityGroups/>".to_string()
    } else {
        format!(
            "<VpcSecurityGroups>{}</VpcSecurityGroups>",
            instance
                .vpc_security_group_ids
                .iter()
                .map(|sg_id| format!(
                    "<VpcSecurityGroupMembership>\
                     <VpcSecurityGroupId>{}</VpcSecurityGroupId>\
                     <Status>active</Status>\
                     </VpcSecurityGroupMembership>",
                    xml_escape(sg_id)
                ))
                .collect::<String>()
        )
    };

    let db_parameter_groups_xml = match &instance.db_parameter_group_name {
        Some(pg_name) => format!(
            "<DBParameterGroups>\
             <DBParameterGroup>\
             <DBParameterGroupName>{}</DBParameterGroupName>\
             <ParameterApplyStatus>in-sync</ParameterApplyStatus>\
             </DBParameterGroup>\
             </DBParameterGroups>",
            xml_escape(pg_name)
        ),
        None => "<DBParameterGroups/>".to_string(),
    };

    let option_group_memberships_xml = match &instance.option_group_name {
        Some(og_name) => format!(
            "<OptionGroupMemberships>\
             <OptionGroupMembership>\
             <OptionGroupName>{}</OptionGroupName>\
             <Status>in-sync</Status>\
             </OptionGroupMembership>\
             </OptionGroupMemberships>",
            xml_escape(og_name)
        ),
        None => "<OptionGroupMemberships/>".to_string(),
    };

    let pending_modified_values_xml = if let Some(ref pending) = instance.pending_modified_values {
        let mut fields = Vec::new();
        if let Some(ref class) = pending.db_instance_class {
            fields.push(format!(
                "<DBInstanceClass>{}</DBInstanceClass>",
                xml_escape(class)
            ));
        }
        if let Some(allocated_storage) = pending.allocated_storage {
            fields.push(format!(
                "<AllocatedStorage>{}</AllocatedStorage>",
                allocated_storage
            ));
        }
        if let Some(backup_retention_period) = pending.backup_retention_period {
            fields.push(format!(
                "<BackupRetentionPeriod>{}</BackupRetentionPeriod>",
                backup_retention_period
            ));
        }
        if let Some(multi_az) = pending.multi_az {
            fields.push(format!(
                "<MultiAZ>{}</MultiAZ>",
                if multi_az { "true" } else { "false" }
            ));
        }
        if let Some(ref engine_version) = pending.engine_version {
            fields.push(format!(
                "<EngineVersion>{}</EngineVersion>",
                xml_escape(engine_version)
            ));
        }
        if pending.master_user_password.is_some() {
            fields.push("<MasterUserPassword>****</MasterUserPassword>".to_string());
        }
        if !fields.is_empty() {
            format!(
                "<PendingModifiedValues>{}</PendingModifiedValues>",
                fields.join("")
            )
        } else {
            String::new()
        }
    } else {
        String::new()
    };

    let latest_restorable_time_xml = instance
        .latest_restorable_time
        .map(|t| {
            format!(
                "<LatestRestorableTime>{}</LatestRestorableTime>",
                t.to_rfc3339()
            )
        })
        .unwrap_or_default();

    // Endpoint is suppressed while the container is still coming up so
    // SDK callers don't try to dial an empty host:0. Once the background
    // task fills in `endpoint_address` and `port`, DescribeDBInstances
    // returns the real endpoint.
    let endpoint_xml = if instance.endpoint_address.is_empty() || instance.port == 0 {
        String::new()
    } else {
        format!(
            "<Endpoint><Address>{}</Address><Port>{}</Port></Endpoint>",
            xml_escape(&instance.endpoint_address),
            instance.port
        )
    };

    format!(
        "<DBInstanceIdentifier>{identifier}</DBInstanceIdentifier>\
         <DBInstanceClass>{class}</DBInstanceClass>\
         <Engine>{engine}</Engine>\
         <DBInstanceStatus>{status}</DBInstanceStatus>\
         <MasterUsername>{master_username}</MasterUsername>\
         {db_name_xml}\
         {endpoint_xml}\
         <AllocatedStorage>{allocated_storage}</AllocatedStorage>\
         <InstanceCreateTime>{create_time}</InstanceCreateTime>\
         <PreferredBackupWindow>{preferred_backup_window}</PreferredBackupWindow>\
         <BackupRetentionPeriod>{backup_retention_period}</BackupRetentionPeriod>\
         <DBSecurityGroups/>\
         {vpc_security_groups_xml}\
         {db_parameter_groups_xml}\
         <AvailabilityZone>us-east-1a</AvailabilityZone>\
         {latest_restorable_time_xml}\
         <PreferredMaintenanceWindow>sun:00:00-sun:00:30</PreferredMaintenanceWindow>\
         <MultiAZ>{multi_az}</MultiAZ>\
         <EngineVersion>{engine_version}</EngineVersion>\
         <AutoMinorVersionUpgrade>true</AutoMinorVersionUpgrade>\
         {read_replica_identifiers_xml}\
         {read_replica_source_xml}\
         <LicenseModel>{license_model}</LicenseModel>\
         {option_group_memberships_xml}\
         <PubliclyAccessible>{publicly_accessible}</PubliclyAccessible>\
         <StorageType>gp2</StorageType>\
         <DbInstancePort>{port}</DbInstancePort>\
         <StorageEncrypted>false</StorageEncrypted>\
         <DbiResourceId>{dbi_resource_id}</DbiResourceId>\
         <DeletionProtection>{deletion_protection}</DeletionProtection>\
         {pending_modified_values_xml}\
         <DBInstanceArn>{arn}</DBInstanceArn>",
        identifier = xml_escape(&instance.db_instance_identifier),
        class = xml_escape(&instance.db_instance_class),
        engine = xml_escape(&instance.engine),
        status = xml_escape(status),
        master_username = xml_escape(&instance.master_username),
        port = instance.port,
        allocated_storage = instance.allocated_storage,
        create_time = instance.created_at.to_rfc3339(),
        preferred_backup_window = xml_escape(&instance.preferred_backup_window),
        backup_retention_period = instance.backup_retention_period,
        multi_az = if instance.multi_az { "true" } else { "false" },
        engine_version = xml_escape(&instance.engine_version),
        license_model = license_model_for_engine(&instance.engine),
        publicly_accessible = if instance.publicly_accessible {
            "true"
        } else {
            "false"
        },
        dbi_resource_id = xml_escape(&instance.dbi_resource_id),
        deletion_protection = if instance.deletion_protection {
            "true"
        } else {
            "false"
        },
        arn = xml_escape(&instance.db_instance_arn),
    )
}

fn db_snapshot_xml(snapshot: &DbSnapshot) -> String {
    format!(
        "<DBSnapshotIdentifier>{}</DBSnapshotIdentifier>\
         <DBInstanceIdentifier>{}</DBInstanceIdentifier>\
         <SnapshotCreateTime>{}</SnapshotCreateTime>\
         <Engine>{}</Engine>\
         <EngineVersion>{}</EngineVersion>\
         <AllocatedStorage>{}</AllocatedStorage>\
         <Status>{}</Status>\
         <Port>{}</Port>\
         <MasterUsername>{}</MasterUsername>\
         {}\
         <DbiResourceId>{}</DbiResourceId>\
         <SnapshotType>{}</SnapshotType>\
         <DBSnapshotArn>{}</DBSnapshotArn>",
        xml_escape(&snapshot.db_snapshot_identifier),
        xml_escape(&snapshot.db_instance_identifier),
        snapshot.snapshot_create_time.to_rfc3339(),
        xml_escape(&snapshot.engine),
        xml_escape(&snapshot.engine_version),
        snapshot.allocated_storage,
        xml_escape(&snapshot.status),
        snapshot.port,
        xml_escape(&snapshot.master_username),
        snapshot
            .db_name
            .as_ref()
            .map(|name| format!("<DBName>{}</DBName>", xml_escape(name)))
            .unwrap_or_default(),
        xml_escape(&snapshot.dbi_resource_id),
        xml_escape(&snapshot.snapshot_type),
        xml_escape(&snapshot.db_snapshot_arn),
    )
}

fn db_subnet_group_xml(subnet_group: &DbSubnetGroup) -> String {
    let subnets_xml = subnet_group
        .subnet_ids
        .iter()
        .zip(&subnet_group.subnet_availability_zones)
        .map(|(subnet_id, az)| {
            format!(
                "<Subnet>\
                 <SubnetIdentifier>{}</SubnetIdentifier>\
                 <SubnetAvailabilityZone><Name>{}</Name></SubnetAvailabilityZone>\
                 <SubnetStatus>Active</SubnetStatus>\
                 </Subnet>",
                xml_escape(subnet_id),
                xml_escape(az)
            )
        })
        .collect::<String>();

    format!(
        "<DBSubnetGroupName>{}</DBSubnetGroupName>\
         <DBSubnetGroupDescription>{}</DBSubnetGroupDescription>\
         <VpcId>{}</VpcId>\
         <SubnetGroupStatus>Complete</SubnetGroupStatus>\
         <Subnets>{}</Subnets>\
         <DBSubnetGroupArn>{}</DBSubnetGroupArn>",
        xml_escape(&subnet_group.db_subnet_group_name),
        xml_escape(&subnet_group.db_subnet_group_description),
        xml_escape(&subnet_group.vpc_id),
        subnets_xml,
        xml_escape(&subnet_group.db_subnet_group_arn),
    )
}

fn db_parameter_group_xml(parameter_group: &DbParameterGroup) -> String {
    format!(
        "<DBParameterGroupName>{}</DBParameterGroupName>\
         <DBParameterGroupFamily>{}</DBParameterGroupFamily>\
         <Description>{}</Description>\
         <DBParameterGroupArn>{}</DBParameterGroupArn>",
        xml_escape(&parameter_group.db_parameter_group_name),
        xml_escape(&parameter_group.db_parameter_group_family),
        xml_escape(&parameter_group.description),
        xml_escape(&parameter_group.db_parameter_group_arn),
    )
}

fn db_instance_not_found(identifier: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::NOT_FOUND,
        "DBInstanceNotFound",
        format!("DBInstance {} not found.", identifier),
    )
}

fn db_snapshot_not_found(identifier: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::NOT_FOUND,
        "DBSnapshotNotFound",
        format!("DBSnapshot {} not found.", identifier),
    )
}

fn db_instance_not_found_by_arn(resource_name: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::NOT_FOUND,
        "DBInstanceNotFound",
        format!("DBInstance {resource_name} not found."),
    )
}

fn find_instance_by_arn<'a>(
    state: &'a crate::state::RdsState,
    resource_name: &str,
) -> Result<&'a DbInstance, AwsServiceError> {
    state
        .instances
        .values()
        .find(|instance| instance.db_instance_arn == resource_name)
        .ok_or_else(|| db_instance_not_found_by_arn(resource_name))
}

fn find_instance_by_arn_mut<'a>(
    state: &'a mut crate::state::RdsState,
    resource_name: &str,
) -> Result<&'a mut DbInstance, AwsServiceError> {
    state
        .instances
        .values_mut()
        .find(|instance| instance.db_instance_arn == resource_name)
        .ok_or_else(|| db_instance_not_found_by_arn(resource_name))
}

fn merge_tags(existing: &mut Vec<RdsTag>, incoming: &[RdsTag]) {
    for tag in incoming {
        if let Some(existing_tag) = existing
            .iter_mut()
            .find(|candidate| candidate.key == tag.key)
        {
            existing_tag.value = tag.value.clone();
        } else {
            existing.push(tag.clone());
        }
    }
}

fn license_model_for_engine(engine: &str) -> &'static str {
    // Match AWS's reported license model exactly. Oracle and SQL Server
    // both use the BYOL/license-included split; fakecloud reports
    // license-included since the upstream dev-edition images are
    // free-to-use. Db2 is reported as bring-your-own-license to mirror
    // AWS's RDS for Db2 default.
    match engine {
        "mysql" | "mariadb" => "general-public-license",
        "oracle-ee" | "oracle-se2" | "oracle-ee-cdb" | "oracle-se2-cdb" => "license-included",
        "sqlserver-ee" | "sqlserver-se" | "sqlserver-ex" | "sqlserver-web" => "license-included",
        "db2-se" | "db2-ae" => "bring-your-own-license",
        _ => "postgresql-license",
    }
}

fn default_db_name(engine: &str) -> &'static str {
    match engine {
        "mysql" | "mariadb" => "mysql",
        // Oracle's gvenzl image creates an `ORACLE_DATABASE` alongside
        // the built-in FREEPDB1 — keep `ORCL` as the default name to
        // match what AWS RDS for Oracle returns when you don't pass
        // `DBName`.
        "oracle-ee" | "oracle-se2" | "oracle-ee-cdb" | "oracle-se2-cdb" => "ORCL",
        // SQL Server installs system DBs by default; AWS doesn't
        // create a user DB unless `DBName` is supplied. Use `master`
        // as the default the SDK can connect to.
        "sqlserver-ee" | "sqlserver-se" | "sqlserver-ex" | "sqlserver-web" => "master",
        "db2-se" | "db2-ae" => "BLUDB",
        _ => "postgres",
    }
}

/// Pick the port AWS defaults to for a freshly-created instance of
/// `engine`. Mirrors the AWS RDS defaults so client SDKs that connect
/// without an explicit `--port` flag hit the right listener.
fn default_port_for_engine(engine: &str) -> i32 {
    match engine {
        "postgres" => 5432,
        "mysql" | "mariadb" => 3306,
        "oracle-ee" | "oracle-se2" | "oracle-ee-cdb" | "oracle-se2-cdb" => 1521,
        "sqlserver-ee" | "sqlserver-se" | "sqlserver-ex" | "sqlserver-web" => 1433,
        "db2-se" | "db2-ae" => 50000,
        _ => 5432,
    }
}

/// Pick the built-in parameter group name AWS assigns to a new
/// instance when the caller doesn't override it. The name encodes the
/// engine family plus its major version (e.g. `default.postgres16`,
/// `default.mysql8.0`, `default.oracle-ee-23`, `default.sqlserver-ex-16`,
/// `default.db2-se-11.5`).
fn default_parameter_group(engine: &str, engine_version: &str) -> String {
    match engine {
        "postgres" => {
            let major = engine_version.split('.').next().unwrap_or("16");
            format!("default.postgres{}", major)
        }
        "mysql" => {
            let major = if engine_version.starts_with("5.7") {
                "5.7"
            } else {
                "8.0"
            };
            format!("default.mysql{}", major)
        }
        "mariadb" => {
            let major = if engine_version.starts_with("11.4") {
                "11.4"
            } else if engine_version.starts_with("10.11") {
                "10.11"
            } else {
                "10.6"
            };
            format!("default.mariadb{}", major)
        }
        "oracle-ee" | "oracle-se2" | "oracle-ee-cdb" | "oracle-se2-cdb" => {
            let major = engine_version.split('.').next().unwrap_or("23");
            format!("default.{engine}-{major}")
        }
        "sqlserver-ee" | "sqlserver-se" | "sqlserver-ex" | "sqlserver-web" => {
            // AWS uses the SQL Server major-version number ("16" for
            // 2022, "15" for 2019) in the default parameter group.
            let major = engine_version.split('.').next().unwrap_or("16");
            format!("default.{engine}-{major}")
        }
        "db2-se" | "db2-ae" => {
            // Db2 ships major.minor as the parameter-group key
            // (e.g. `default.db2-se-11.5`).
            let mut parts = engine_version.split('.');
            let major = parts.next().unwrap_or("11");
            let minor = parts.next().unwrap_or("5");
            format!("default.{engine}-{major}.{minor}")
        }
        _ => "default.postgres16".to_string(),
    }
}

fn runtime_error_to_service_error(error: RuntimeError) -> AwsServiceError {
    match error {
        RuntimeError::Unavailable => AwsServiceError::aws_error(
            StatusCode::SERVICE_UNAVAILABLE,
            "InvalidParameterValue",
            "Docker/Podman is required for RDS DB instances but is not available",
        ),
        RuntimeError::ContainerStartFailed(message) => AwsServiceError::aws_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "InternalFailure",
            message,
        ),
    }
}

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
