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
    /// Also records into the per-account events ring so DescribeEvents
    /// can serve the row. No-op for the EventBridge side when the bus
    /// isn't wired (tests, minimal configs).
    pub(crate) fn emit_event(
        &self,
        source_type: RdsSourceType,
        source_identifier: &str,
        source_arn: &str,
        event_id: &str,
        event_categories: &[&str],
        message: &str,
    ) {
        // Source the account_id off the source_arn (segment 4) — that's
        // the canonical ARN form for RDS resources.
        let account_id = source_arn.split(':').nth(4).unwrap_or("");
        emit_event_static_with_state(
            self.delivery_bus.as_ref(),
            Some(&self.state),
            if account_id.is_empty() {
                None
            } else {
                Some(account_id)
            },
            source_type,
            source_identifier,
            source_arn,
            event_id,
            event_categories,
            message,
        );
    }

    async fn save_snapshot(&self) {
        save_snapshot_static(
            self.state.clone(),
            self.snapshot_store.clone(),
            self.snapshot_lock.clone(),
        )
        .await;
    }
}

/// Persist the current `RdsState` to the configured snapshot store. Free
/// function so background tasks (e.g. the create-DB-instance container-start
/// task) can save without holding a `&RdsService`. Returns immediately when
/// no store is configured (memory-mode runs).
async fn save_snapshot_static(
    state: SharedRdsState,
    store: Option<Arc<dyn SnapshotStore>>,
    lock: Arc<AsyncMutex<()>>,
) {
    let Some(store) = store else {
        return;
    };
    let _guard = lock.lock().await;
    let snapshot = RdsSnapshot {
        schema_version: RDS_SNAPSHOT_SCHEMA_VERSION,
        state: None,
        accounts: Some(state.read().clone()),
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

impl RdsService {
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
            "DescribeDBParameters" => self.describe_db_parameters_real(&request),
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
        let availability_zone = optional_query_param(request, "AvailabilityZone");
        let storage_type = optional_query_param(request, "StorageType");
        let storage_encrypted =
            parse_optional_bool(optional_query_param(request, "StorageEncrypted").as_deref())?
                .unwrap_or(false);
        let kms_key_id = optional_query_param(request, "KmsKeyId");
        let iam_database_authentication_enabled = parse_optional_bool(
            optional_query_param(request, "EnableIAMDatabaseAuthentication").as_deref(),
        )?
        .unwrap_or(false);
        let iops = optional_i32_param(request, "Iops")?;
        let monitoring_interval = optional_i32_param(request, "MonitoringInterval")?;
        let monitoring_role_arn = optional_query_param(request, "MonitoringRoleArn");
        let performance_insights_enabled = parse_optional_bool(
            optional_query_param(request, "EnablePerformanceInsights").as_deref(),
        )?
        .unwrap_or(false);
        let performance_insights_kms_key_id =
            optional_query_param(request, "PerformanceInsightsKMSKeyId");
        let performance_insights_retention_period =
            optional_i32_param(request, "PerformanceInsightsRetentionPeriod")?;
        let enabled_cloudwatch_logs_exports =
            parse_cloudwatch_logs_exports(request, "EnableCloudwatchLogsExports");
        let ca_certificate_identifier = optional_query_param(request, "CACertificateIdentifier");
        let network_type = optional_query_param(request, "NetworkType");
        let character_set_name = optional_query_param(request, "CharacterSetName");
        let auto_minor_version_upgrade = parse_optional_bool(
            optional_query_param(request, "AutoMinorVersionUpgrade").as_deref(),
        )?;
        let copy_tags_to_snapshot =
            parse_optional_bool(optional_query_param(request, "CopyTagsToSnapshot").as_deref())?;

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
                preferred_maintenance_window: None,
                latest_restorable_time: if backup_retention_period > 0 {
                    Some(created_at)
                } else {
                    None
                },
                option_group_name,
                multi_az,
                pending_modified_values: None,
                availability_zone,
                storage_type,
                storage_encrypted,
                kms_key_id,
                iam_database_authentication_enabled,
                iops,
                monitoring_interval,
                monitoring_role_arn,
                performance_insights_enabled,
                performance_insights_kms_key_id,
                performance_insights_retention_period,
                enabled_cloudwatch_logs_exports,
                ca_certificate_identifier,
                network_type,
                character_set_name,
                auto_minor_version_upgrade,
                copy_tags_to_snapshot,
                master_user_secret_arn: None,
                master_user_secret_kms_key_id: None,
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
            let snapshot_store = self.snapshot_store.clone();
            let snapshot_lock = self.snapshot_lock.clone();
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
                        {
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
                        // Persist the flipped status. Without this the
                        // synchronous CreateDBInstance save captures the
                        // `creating` placeholder, which the load path
                        // discards on restart, dropping the instance.
                        save_snapshot_static(
                            state_handle.clone(),
                            snapshot_store.clone(),
                            snapshot_lock.clone(),
                        )
                        .await;
                    }
                    Err(error) => {
                        tracing::error!(%error, db_instance_identifier=%id, "create_db_instance background task failed");
                        {
                            let mut accounts = state_handle.write();
                            let state = accounts.get_or_create(&account_id);
                            state.instances.remove(&id);
                        }
                        save_snapshot_static(
                            state_handle.clone(),
                            snapshot_store.clone(),
                            snapshot_lock.clone(),
                        )
                        .await;
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
            snapshot_type: "automated".to_string(),
            master_user_password: instance_for_snapshot.master_user_password.clone(),
            tags: Vec::new(),
            dump_data,
            availability_zone: instance_for_snapshot.availability_zone.clone(),
            vpc_id: None,
            instance_create_time: Some(instance_for_snapshot.created_at),
            license_model: Some(
                service_helpers::license_model_for_engine(&instance_for_snapshot.engine)
                    .to_string(),
            ),
            iops: instance_for_snapshot.iops,
            option_group_name: instance_for_snapshot.option_group_name.clone(),
            percent_progress: Some(100),
            storage_type: instance_for_snapshot.storage_type.clone(),
            encrypted: instance_for_snapshot.storage_encrypted,
            kms_key_id: instance_for_snapshot.kms_key_id.clone(),
            iam_database_authentication_enabled: instance_for_snapshot
                .iam_database_authentication_enabled,
            timezone: None,
            storage_throughput: None,
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
        let master_user_password = optional_query_param(request, "MasterUserPassword");
        let backup_retention_period =
            parse_optional_i32(optional_query_param(request, "BackupRetentionPeriod").as_deref())?;
        let preferred_backup_window = optional_query_param(request, "PreferredBackupWindow");
        let preferred_maintenance_window =
            optional_query_param(request, "PreferredMaintenanceWindow");
        let engine_version = optional_query_param(request, "EngineVersion");
        let allocated_storage =
            parse_optional_i32(optional_query_param(request, "AllocatedStorage").as_deref())?;
        let db_parameter_group_name = optional_query_param(request, "DBParameterGroupName");
        let multi_az = parse_optional_bool(optional_query_param(request, "MultiAZ").as_deref())?;
        let iops = parse_optional_i32(optional_query_param(request, "Iops").as_deref())?;
        let storage_type = optional_query_param(request, "StorageType");
        let master_user_secret_kms_key_id =
            optional_query_param(request, "MasterUserSecretKmsKeyId");
        let ca_certificate_identifier = optional_query_param(request, "CACertificateIdentifier");
        let monitoring_interval =
            parse_optional_i32(optional_query_param(request, "MonitoringInterval").as_deref())?;
        let performance_insights_enabled = parse_optional_bool(
            optional_query_param(request, "EnablePerformanceInsights").as_deref(),
        )?;

        // CloudWatch logs exports — AWS lets callers both opt-in to and
        // opt-out of specific log types in the same call. We compute the
        // resulting set per AWS semantics: start from current, remove
        // DisableLogTypes, then union with EnableLogTypes.
        let cloudwatch_enable = collect_cloudwatch_log_types(request, "EnableLogTypes");
        let cloudwatch_disable = collect_cloudwatch_log_types(request, "DisableLogTypes");
        let cloudwatch_changed = !cloudwatch_enable.is_empty() || !cloudwatch_disable.is_empty();

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

        // At-least-one-field validation: every supported mutable input.
        if db_instance_class.is_none()
            && deletion_protection.is_none()
            && vpc_security_group_ids.is_none()
            && master_user_password.is_none()
            && backup_retention_period.is_none()
            && preferred_backup_window.is_none()
            && preferred_maintenance_window.is_none()
            && engine_version.is_none()
            && allocated_storage.is_none()
            && db_parameter_group_name.is_none()
            && multi_az.is_none()
            && iops.is_none()
            && storage_type.is_none()
            && master_user_secret_kms_key_id.is_none()
            && ca_certificate_identifier.is_none()
            && monitoring_interval.is_none()
            && performance_insights_enabled.is_none()
            && !cloudwatch_changed
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

        // Fields AWS always applies immediately (per AWS RDS docs),
        // regardless of ApplyImmediately:
        //   deletion_protection, vpc_security_group_ids,
        //   ca_certificate_identifier, master_user_secret_kms_key_id,
        //   enabled_cloudwatch_logs_exports.
        if let Some(deletion_protection) = deletion_protection {
            instance.deletion_protection = deletion_protection;
        }
        if let Some(security_group_ids) = vpc_security_group_ids {
            instance.vpc_security_group_ids = security_group_ids;
        }
        if let Some(ca_id) = ca_certificate_identifier {
            instance.ca_certificate_identifier = Some(ca_id);
        }
        if let Some(kms_key) = master_user_secret_kms_key_id {
            instance.master_user_secret_kms_key_id = Some(kms_key);
        }
        if cloudwatch_changed {
            let mut current: Vec<String> = instance.enabled_cloudwatch_logs_exports.clone();
            current.retain(|t| !cloudwatch_disable.contains(t));
            for t in &cloudwatch_enable {
                if !current.contains(t) {
                    current.push(t.clone());
                }
            }
            instance.enabled_cloudwatch_logs_exports = current;
        }

        // Fields gated on ApplyImmediately. Default (None or true) is
        // immediate; false stages to pending_modified_values.
        let immediate = apply_immediately != Some(false);
        if immediate {
            if let Some(class) = db_instance_class {
                instance.db_instance_class = class;
            }
            if let Some(pwd) = master_user_password {
                instance.master_user_password = pwd;
            }
            if let Some(retention) = backup_retention_period {
                instance.backup_retention_period = retention;
            }
            if let Some(window) = preferred_backup_window {
                instance.preferred_backup_window = window;
            }
            if let Some(window) = preferred_maintenance_window {
                instance.preferred_maintenance_window = Some(window);
            }
            if let Some(version) = engine_version {
                instance.engine_version = version;
            }
            if let Some(storage) = allocated_storage {
                instance.allocated_storage = storage;
            }
            if let Some(name) = db_parameter_group_name {
                instance.db_parameter_group_name = Some(name);
            }
            if let Some(az) = multi_az {
                instance.multi_az = az;
            }
            if let Some(iops_val) = iops {
                instance.iops = Some(iops_val);
            }
            if let Some(stype) = storage_type {
                instance.storage_type = Some(stype);
            }
            if let Some(interval) = monitoring_interval {
                instance.monitoring_interval = Some(interval);
            }
            if let Some(pi) = performance_insights_enabled {
                instance.performance_insights_enabled = pi;
            }
        } else {
            // Stage only if at least one deferrable field was supplied.
            let any_deferred = db_instance_class.is_some()
                || master_user_password.is_some()
                || backup_retention_period.is_some()
                || preferred_backup_window.is_some()
                || preferred_maintenance_window.is_some()
                || engine_version.is_some()
                || allocated_storage.is_some()
                || db_parameter_group_name.is_some()
                || multi_az.is_some()
                || iops.is_some()
                || storage_type.is_some()
                || monitoring_interval.is_some()
                || performance_insights_enabled.is_some();
            if any_deferred {
                let pending = instance
                    .pending_modified_values
                    .get_or_insert(Default::default());
                if let Some(class) = db_instance_class {
                    pending.db_instance_class = Some(class);
                }
                if let Some(pwd) = master_user_password {
                    pending.master_user_password = Some(pwd);
                }
                if let Some(retention) = backup_retention_period {
                    pending.backup_retention_period = Some(retention);
                }
                if let Some(window) = preferred_backup_window {
                    pending.preferred_backup_window = Some(window);
                }
                if let Some(window) = preferred_maintenance_window {
                    pending.preferred_maintenance_window = Some(window);
                }
                if let Some(version) = engine_version {
                    pending.engine_version = Some(version);
                }
                if let Some(storage) = allocated_storage {
                    pending.allocated_storage = Some(storage);
                }
                if let Some(name) = db_parameter_group_name {
                    pending.db_parameter_group_name = Some(name);
                }
                if let Some(az) = multi_az {
                    pending.multi_az = Some(az);
                }
                if let Some(iops_val) = iops {
                    pending.iops = Some(iops_val);
                }
                if let Some(stype) = storage_type {
                    pending.storage_type = Some(stype);
                }
                if let Some(interval) = monitoring_interval {
                    pending.monitoring_interval = Some(interval);
                }
                if let Some(pi) = performance_insights_enabled {
                    pending.performance_insights_enabled = Some(pi);
                }
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
            availability_zone: instance.availability_zone.clone(),
            vpc_id: None,
            instance_create_time: Some(instance.created_at),
            license_model: Some(
                service_helpers::license_model_for_engine(&instance.engine).to_string(),
            ),
            iops: instance.iops,
            option_group_name: instance.option_group_name.clone(),
            percent_progress: Some(100),
            storage_type: instance.storage_type.clone(),
            encrypted: instance.storage_encrypted,
            kms_key_id: instance.kms_key_id.clone(),
            iam_database_authentication_enabled: instance.iam_database_authentication_enabled,
            timezone: None,
            storage_throughput: None,
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
        let tags = parse_tags(request)?;

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
            tags,
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

        // Parse Parameters.member.N.{ParameterName,ParameterValue,ApplyMethod}
        // before taking the lock so we can validate input independently.
        // ApplyMethod is accepted (immediate vs pending-reboot) but the
        // single-state model applies all changes immediately.
        let parsed_params = parse_db_parameter_members(request);

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

        for (name, value) in parsed_params {
            parameter_group.parameters.insert(name, value);
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

    fn describe_db_parameters_real(
        &self,
        request: &AwsRequest,
    ) -> Result<AwsResponse, AwsServiceError> {
        let db_parameter_group_name = required_query_param(request, "DBParameterGroupName")?;
        let source_filter = optional_query_param(request, "Source");

        let accounts = self.state.read();
        let state = match accounts.get(&request.account_id) {
            Some(s) => s,
            None => {
                return Err(AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "DBParameterGroupNotFound",
                    format!("DBParameterGroup {db_parameter_group_name} not found."),
                ));
            }
        };
        let parameter_group = state
            .parameter_groups
            .get(&db_parameter_group_name)
            .ok_or_else(|| {
                AwsServiceError::aws_error(
                    StatusCode::NOT_FOUND,
                    "DBParameterGroupNotFound",
                    format!("DBParameterGroup {db_parameter_group_name} not found."),
                )
            })?;

        // Modified params surface as Source=user; engine defaults
        // surface as Source=engine-default. We only persist user-set
        // values, so we always report `user` and skip when the caller
        // requested only `engine-default`.
        let want_user_source = source_filter.as_deref().is_none_or(|s| s == "user");
        let mut members_xml = String::new();
        if want_user_source {
            for (name, value) in &parameter_group.parameters {
                members_xml.push_str(&format!(
                    "      <Parameter>\n        <ParameterName>{}</ParameterName>\n        <ParameterValue>{}</ParameterValue>\n        <Source>user</Source>\n        <ApplyType>dynamic</ApplyType>\n        <DataType>string</DataType>\n        <IsModifiable>true</IsModifiable>\n      </Parameter>\n",
                    xml_escape(name),
                    xml_escape(value),
                ));
            }
        }
        let body = format!("    <Parameters>\n{members_xml}    </Parameters>");
        Ok(AwsResponse::xml(
            StatusCode::OK,
            query_response_xml("DescribeDBParameters", RDS_NS, &body, &request.request_id),
        ))
    }
}

/// Parse `Parameters.member.N.{ParameterName,ParameterValue,ApplyMethod}`
/// from a Query-protocol request. Skips members missing a name or value;
/// ApplyMethod is accepted but ignored (single-state model).
pub(crate) fn parse_db_parameter_members(request: &AwsRequest) -> Vec<(String, String)> {
    let mut out = Vec::new();
    for index in 1.. {
        let name_key = format!("Parameters.member.{index}.ParameterName");
        let value_key = format!("Parameters.member.{index}.ParameterValue");
        match (
            optional_query_param(request, &name_key),
            optional_query_param(request, &value_key),
        ) {
            (Some(name), Some(value)) if !name.is_empty() => {
                out.push((name, value));
            }
            (None, None) => break,
            _ => continue,
        }
    }
    out
}

pub(crate) struct PaginationResult<T> {
    items: Vec<T>,
    next_marker: Option<String>,
}

#[path = "service_helpers.rs"]
mod service_helpers;
pub(crate) use service_helpers::*;

#[cfg(test)]
#[path = "service_tests.rs"]
mod tests;
