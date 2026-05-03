use super::*;

pub(crate) fn is_mutating_action(action: &str) -> bool {
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

pub(crate) fn required_i32_param(req: &AwsRequest, name: &str) -> Result<i32, AwsServiceError> {
    let value = required_query_param(req, name)?;
    value.parse::<i32>().map_err(|_| {
        AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterValue",
            format!("Parameter {name} must be a valid integer."),
        )
    })
}

pub(crate) fn optional_i32_param(
    req: &AwsRequest,
    name: &str,
) -> Result<Option<i32>, AwsServiceError> {
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

pub(crate) fn parse_tags(req: &AwsRequest) -> Result<Vec<RdsTag>, AwsServiceError> {
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

pub(crate) fn parse_tag_keys(req: &AwsRequest) -> Result<Vec<String>, AwsServiceError> {
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

pub(crate) fn parse_subnet_ids(req: &AwsRequest) -> Result<Vec<String>, AwsServiceError> {
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

pub(crate) fn parse_vpc_security_group_ids(req: &AwsRequest) -> Vec<String> {
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

pub(crate) fn query_param_prefix_exists(req: &AwsRequest, prefix: &str) -> bool {
    req.query_params.keys().any(|key| key.starts_with(prefix))
}

/// AWS RDS encodes string lists as `{Param}.member.N` 1-indexed entries.
/// Used by `EnableCloudwatchLogsExports`, `CloudwatchLogsExportConfiguration.EnableLogTypes`,
/// `ProcessorFeatures.ProcessorFeature.N.{Name,Value}` (caller decides shape).
pub(crate) fn parse_string_member_list(req: &AwsRequest, base: &str) -> Vec<String> {
    let mut out = Vec::new();
    for i in 1.. {
        let key = format!("{base}.member.{i}");
        match optional_query_param(req, &key) {
            Some(v) => out.push(v),
            None => break,
        }
    }
    out
}

/// Convenience wrapper for the cloudwatch-log-exports list which is
/// emitted on Create/Modify/Restore paths.
pub(crate) fn parse_cloudwatch_logs_exports(req: &AwsRequest, base: &str) -> Vec<String> {
    parse_string_member_list(req, base)
}

pub(crate) fn parse_optional_i32(value: Option<&str>) -> Result<Option<i32>, AwsServiceError> {
    value
        .map(|raw| {
            raw.parse::<i32>().map_err(|_| {
                AwsServiceError::aws_error(
                    StatusCode::BAD_REQUEST,
                    "InvalidParameterValue",
                    format!("Integer parameter value '{raw}' is invalid."),
                )
            })
        })
        .transpose()
}

/// Collect the `member.N` values for a Query-protocol log-types list
/// nested under `CloudwatchLogsExportConfiguration` (e.g.
/// `CloudwatchLogsExportConfiguration.EnableLogTypes.member.1`). Returns
/// an empty vec when no values are present.
pub(crate) fn collect_cloudwatch_log_types(req: &AwsRequest, list_name: &str) -> Vec<String> {
    let base = format!("CloudwatchLogsExportConfiguration.{list_name}");
    parse_string_member_list(req, &base)
}

pub(crate) fn parse_optional_bool(value: Option<&str>) -> Result<Option<bool>, AwsServiceError> {
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

pub(crate) fn paginate<T, F>(
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

pub(crate) fn validate_create_request(
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

pub(crate) fn validate_db_instance_class(db_instance_class: &str) -> Result<(), AwsServiceError> {
    if !crate::state::SUPPORTED_INSTANCE_CLASSES.contains(&db_instance_class) {
        return Err(AwsServiceError::aws_error(
            StatusCode::BAD_REQUEST,
            "InvalidParameterValue",
            format!("DBInstanceClass '{}' is not supported.", db_instance_class),
        ));
    }
    Ok(())
}

pub(crate) fn filter_engine_versions(
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

pub(crate) fn filter_orderable_options(
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
pub(crate) fn build_restored_instance(
    db_instance_identifier: &str,
    db_instance_arn: String,
    dbi_resource_id: String,
    created_at: chrono::DateTime<Utc>,
    vpc_security_group_ids: Vec<String>,
    snapshot: &DbSnapshot,
    running: &crate::runtime::RunningDbContainer,
    tags: Vec<RdsTag>,
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
        tags,
        read_replica_source_db_instance_identifier: None,
        read_replica_db_instance_identifiers: Vec::new(),
        vpc_security_group_ids,
        db_parameter_group_name: None,
        backup_retention_period: 1,
        preferred_backup_window: "03:00-04:00".to_string(),
        preferred_maintenance_window: None,
        latest_restorable_time: Some(created_at),
        option_group_name: None,
        multi_az: false,
        pending_modified_values: None,
        availability_zone: None,
        storage_type: None,
        storage_encrypted: false,
        kms_key_id: None,
        iam_database_authentication_enabled: false,
        iops: None,
        monitoring_interval: None,
        monitoring_role_arn: None,
        performance_insights_enabled: false,
        performance_insights_kms_key_id: None,
        performance_insights_retention_period: None,
        enabled_cloudwatch_logs_exports: Vec::new(),
        ca_certificate_identifier: None,
        network_type: None,
        character_set_name: None,
        auto_minor_version_upgrade: None,
        copy_tags_to_snapshot: None,
        master_user_secret_arn: None,
        master_user_secret_kms_key_id: None,
    }
}

pub(crate) fn build_read_replica_instance(
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
        preferred_maintenance_window: source.preferred_maintenance_window.clone(),
        latest_restorable_time: if source.backup_retention_period > 0 {
            Some(created_at)
        } else {
            None
        },
        option_group_name: source.option_group_name.clone(),
        multi_az: source.multi_az,
        pending_modified_values: None,
        availability_zone: source.availability_zone.clone(),
        storage_type: source.storage_type.clone(),
        storage_encrypted: source.storage_encrypted,
        kms_key_id: source.kms_key_id.clone(),
        iam_database_authentication_enabled: source.iam_database_authentication_enabled,
        iops: source.iops,
        monitoring_interval: source.monitoring_interval,
        monitoring_role_arn: source.monitoring_role_arn.clone(),
        performance_insights_enabled: source.performance_insights_enabled,
        performance_insights_kms_key_id: source.performance_insights_kms_key_id.clone(),
        performance_insights_retention_period: source.performance_insights_retention_period,
        enabled_cloudwatch_logs_exports: source.enabled_cloudwatch_logs_exports.clone(),
        ca_certificate_identifier: source.ca_certificate_identifier.clone(),
        network_type: source.network_type.clone(),
        character_set_name: source.character_set_name.clone(),
        auto_minor_version_upgrade: source.auto_minor_version_upgrade,
        copy_tags_to_snapshot: source.copy_tags_to_snapshot,
        master_user_secret_arn: None,
        master_user_secret_kms_key_id: None,
    }
}

pub(crate) fn engine_version_xml(version: &EngineVersionInfo) -> String {
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

pub(crate) fn orderable_option_xml(option: &OrderableDbInstanceOption) -> String {
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

pub(crate) fn tag_xml(tag: &RdsTag) -> String {
    format!(
        "<Tag><Key>{}</Key><Value>{}</Value></Tag>",
        xml_escape(&tag.key),
        xml_escape(&tag.value),
    )
}

/// Free-standing version of `emit_event` so background tasks (which
/// don't have a `&self`) can publish RDS events through the same path.
///
/// When `state` and `account_id` are provided the event is also
/// recorded in the per-account events ring so DescribeEvents can serve
/// it. Background tasks that already cleared their account state pass
/// `None` for those parameters.
pub(crate) fn emit_event_static(
    delivery_bus: Option<&Arc<DeliveryBus>>,
    source_type: RdsSourceType,
    source_identifier: &str,
    source_arn: &str,
    event_id: &str,
    event_categories: &[&str],
    message: &str,
) {
    emit_event_static_with_state(
        delivery_bus,
        None,
        None,
        source_type,
        source_identifier,
        source_arn,
        event_id,
        event_categories,
        message,
    );
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn emit_event_static_with_state(
    delivery_bus: Option<&Arc<DeliveryBus>>,
    state: Option<&crate::state::SharedRdsState>,
    account_id: Option<&str>,
    source_type: RdsSourceType,
    source_identifier: &str,
    source_arn: &str,
    event_id: &str,
    event_categories: &[&str],
    message: &str,
) {
    let now = Utc::now();
    if let (Some(state), Some(account_id)) = (state, account_id) {
        let mut accounts = state.write();
        let s = accounts.get_or_create(account_id);
        s.push_event(crate::state::RdsEventRecord {
            source_identifier: source_identifier.to_string(),
            source_type: source_type.as_str().to_string(),
            source_arn: source_arn.to_string(),
            event_id: event_id.to_string(),
            event_categories: event_categories.iter().map(|s| s.to_string()).collect(),
            message: message.to_string(),
            date: now,
        });
    }
    let Some(bus) = delivery_bus else {
        return;
    };
    let detail = serde_json::json!({
        "EventCategories": event_categories,
        "SourceType": source_type.as_str(),
        "SourceArn": source_arn,
        "Date": now.to_rfc3339(),
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

pub(crate) fn db_instance_xml(instance: &DbInstance, status_override: Option<&str>) -> String {
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

    let availability_zone = instance
        .availability_zone
        .clone()
        .unwrap_or_else(|| "us-east-1a".to_string());
    let storage_type = instance
        .storage_type
        .clone()
        .unwrap_or_else(|| "gp2".to_string());
    let kms_key_id_xml = instance
        .kms_key_id
        .as_ref()
        .map(|k| format!("<KmsKeyId>{}</KmsKeyId>", xml_escape(k)))
        .unwrap_or_default();
    let iops_xml = instance
        .iops
        .map(|n| format!("<Iops>{n}</Iops>"))
        .unwrap_or_default();
    let monitoring_interval_xml = instance
        .monitoring_interval
        .map(|n| format!("<MonitoringInterval>{n}</MonitoringInterval>"))
        .unwrap_or_default();
    let monitoring_role_xml = instance
        .monitoring_role_arn
        .as_ref()
        .map(|a| {
            format!(
                "<EnhancedMonitoringResourceArn>{}</EnhancedMonitoringResourceArn>",
                xml_escape(a)
            )
        })
        .unwrap_or_default();
    let pi_kms_xml = instance
        .performance_insights_kms_key_id
        .as_ref()
        .map(|k| {
            format!(
                "<PerformanceInsightsKMSKeyId>{}</PerformanceInsightsKMSKeyId>",
                xml_escape(k)
            )
        })
        .unwrap_or_default();
    let pi_retention_xml = instance
        .performance_insights_retention_period
        .map(|n| {
            format!("<PerformanceInsightsRetentionPeriod>{n}</PerformanceInsightsRetentionPeriod>")
        })
        .unwrap_or_default();
    let cloudwatch_exports_xml = if instance.enabled_cloudwatch_logs_exports.is_empty() {
        "<EnabledCloudwatchLogsExports/>".to_string()
    } else {
        format!(
            "<EnabledCloudwatchLogsExports>{}</EnabledCloudwatchLogsExports>",
            instance
                .enabled_cloudwatch_logs_exports
                .iter()
                .map(|e| format!("<member>{}</member>", xml_escape(e)))
                .collect::<String>()
        )
    };
    let ca_cert_xml = instance
        .ca_certificate_identifier
        .as_ref()
        .map(|c| {
            format!(
                "<CACertificateIdentifier>{}</CACertificateIdentifier>",
                xml_escape(c)
            )
        })
        .unwrap_or_default();
    let network_type_xml = instance
        .network_type
        .as_ref()
        .map(|n| format!("<NetworkType>{}</NetworkType>", xml_escape(n)))
        .unwrap_or_default();
    let charset_xml = instance
        .character_set_name
        .as_ref()
        .map(|c| format!("<CharacterSetName>{}</CharacterSetName>", xml_escape(c)))
        .unwrap_or_default();
    let auto_minor_xml = format!(
        "<AutoMinorVersionUpgrade>{}</AutoMinorVersionUpgrade>",
        if instance.auto_minor_version_upgrade.unwrap_or(true) {
            "true"
        } else {
            "false"
        }
    );
    let copy_tags_xml = instance
        .copy_tags_to_snapshot
        .map(|b| {
            format!(
                "<CopyTagsToSnapshot>{}</CopyTagsToSnapshot>",
                if b { "true" } else { "false" }
            )
        })
        .unwrap_or_default();
    let master_user_secret_xml = instance
        .master_user_secret_arn
        .as_ref()
        .map(|arn| {
            let kms = instance
                .master_user_secret_kms_key_id
                .as_ref()
                .map(|k| format!("<KmsKeyId>{}</KmsKeyId>", xml_escape(k)))
                .unwrap_or_default();
            format!(
                "<MasterUserSecret><SecretArn>{}</SecretArn><SecretStatus>active</SecretStatus>{kms}</MasterUserSecret>",
                xml_escape(arn)
            )
        })
        .unwrap_or_default();

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
         <AvailabilityZone>{availability_zone}</AvailabilityZone>\
         {latest_restorable_time_xml}\
         <PreferredMaintenanceWindow>sun:00:00-sun:00:30</PreferredMaintenanceWindow>\
         <MultiAZ>{multi_az}</MultiAZ>\
         <EngineVersion>{engine_version}</EngineVersion>\
         {auto_minor_xml}\
         {read_replica_identifiers_xml}\
         {read_replica_source_xml}\
         <LicenseModel>{license_model}</LicenseModel>\
         {option_group_memberships_xml}\
         <PubliclyAccessible>{publicly_accessible}</PubliclyAccessible>\
         <StorageType>{storage_type}</StorageType>\
         <DbInstancePort>{port}</DbInstancePort>\
         <StorageEncrypted>{storage_encrypted}</StorageEncrypted>\
         {kms_key_id_xml}\
         <IAMDatabaseAuthenticationEnabled>{iam_auth}</IAMDatabaseAuthenticationEnabled>\
         {iops_xml}\
         {monitoring_interval_xml}\
         {monitoring_role_xml}\
         <PerformanceInsightsEnabled>{pi_enabled}</PerformanceInsightsEnabled>\
         {pi_kms_xml}\
         {pi_retention_xml}\
         {cloudwatch_exports_xml}\
         {ca_cert_xml}\
         {network_type_xml}\
         {charset_xml}\
         {copy_tags_xml}\
         {master_user_secret_xml}\
         <ProcessorFeatures/>\
         <ActivityStreamStatus>stopped</ActivityStreamStatus>\
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
        availability_zone = xml_escape(&availability_zone),
        storage_type = xml_escape(&storage_type),
        storage_encrypted = if instance.storage_encrypted {
            "true"
        } else {
            "false"
        },
        iam_auth = if instance.iam_database_authentication_enabled {
            "true"
        } else {
            "false"
        },
        pi_enabled = if instance.performance_insights_enabled {
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

pub(crate) fn db_snapshot_xml(snapshot: &DbSnapshot) -> String {
    let opt = |tag: &str, value: Option<&str>| -> String {
        value
            .map(|v| format!("<{tag}>{}</{tag}>", xml_escape(v)))
            .unwrap_or_default()
    };
    let opt_int = |tag: &str, value: Option<i32>| -> String {
        value
            .map(|v| format!("<{tag}>{v}</{tag}>"))
            .unwrap_or_default()
    };

    let availability_zone_xml = opt("AvailabilityZone", snapshot.availability_zone.as_deref());
    let vpc_id_xml = opt("VpcId", snapshot.vpc_id.as_deref());
    let instance_create_time_xml = snapshot
        .instance_create_time
        .map(|t| {
            format!(
                "<InstanceCreateTime>{}</InstanceCreateTime>",
                t.to_rfc3339()
            )
        })
        .unwrap_or_default();
    let license_model_xml = opt("LicenseModel", snapshot.license_model.as_deref());
    let iops_xml = opt_int("Iops", snapshot.iops);
    let option_group_xml = opt("OptionGroupName", snapshot.option_group_name.as_deref());
    let percent_progress_xml = opt_int("PercentProgress", snapshot.percent_progress);
    let storage_type_xml = opt("StorageType", snapshot.storage_type.as_deref());
    let kms_key_id_xml = opt("KmsKeyId", snapshot.kms_key_id.as_deref());
    let timezone_xml = opt("Timezone", snapshot.timezone.as_deref());
    let storage_throughput_xml = opt_int("StorageThroughput", snapshot.storage_throughput);

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
         {db_name_xml}\
         <DbiResourceId>{}</DbiResourceId>\
         <SnapshotType>{}</SnapshotType>\
         {availability_zone_xml}\
         {vpc_id_xml}\
         {instance_create_time_xml}\
         {license_model_xml}\
         {iops_xml}\
         {option_group_xml}\
         {percent_progress_xml}\
         {storage_type_xml}\
         <Encrypted>{encrypted}</Encrypted>\
         {kms_key_id_xml}\
         <IAMDatabaseAuthenticationEnabled>{iam_auth}</IAMDatabaseAuthenticationEnabled>\
         {timezone_xml}\
         {storage_throughput_xml}\
         <ProcessorFeatures/>\
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
        xml_escape(&snapshot.dbi_resource_id),
        xml_escape(&snapshot.snapshot_type),
        xml_escape(&snapshot.db_snapshot_arn),
        db_name_xml = snapshot
            .db_name
            .as_ref()
            .map(|name| format!("<DBName>{}</DBName>", xml_escape(name)))
            .unwrap_or_default(),
        encrypted = if snapshot.encrypted { "true" } else { "false" },
        iam_auth = if snapshot.iam_database_authentication_enabled {
            "true"
        } else {
            "false"
        },
    )
}

pub(crate) fn db_subnet_group_xml(subnet_group: &DbSubnetGroup) -> String {
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

pub(crate) fn db_parameter_group_xml(parameter_group: &DbParameterGroup) -> String {
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

pub(crate) fn db_instance_not_found(identifier: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::NOT_FOUND,
        "DBInstanceNotFound",
        format!("DBInstance {} not found.", identifier),
    )
}

pub(crate) fn db_snapshot_not_found(identifier: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::NOT_FOUND,
        "DBSnapshotNotFound",
        format!("DBSnapshot {} not found.", identifier),
    )
}

pub(crate) fn db_instance_not_found_by_arn(resource_name: &str) -> AwsServiceError {
    AwsServiceError::aws_error(
        StatusCode::NOT_FOUND,
        "DBInstanceNotFound",
        format!("DBInstance {resource_name} not found."),
    )
}

pub(crate) fn find_instance_by_arn<'a>(
    state: &'a crate::state::RdsState,
    resource_name: &str,
) -> Result<&'a DbInstance, AwsServiceError> {
    state
        .instances
        .values()
        .find(|instance| instance.db_instance_arn == resource_name)
        .ok_or_else(|| db_instance_not_found_by_arn(resource_name))
}

pub(crate) fn find_instance_by_arn_mut<'a>(
    state: &'a mut crate::state::RdsState,
    resource_name: &str,
) -> Result<&'a mut DbInstance, AwsServiceError> {
    state
        .instances
        .values_mut()
        .find(|instance| instance.db_instance_arn == resource_name)
        .ok_or_else(|| db_instance_not_found_by_arn(resource_name))
}

pub(crate) fn merge_tags(existing: &mut Vec<RdsTag>, incoming: &[RdsTag]) {
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

pub(crate) fn license_model_for_engine(engine: &str) -> &'static str {
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

pub(crate) fn default_db_name(engine: &str) -> &'static str {
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
pub(crate) fn default_port_for_engine(engine: &str) -> i32 {
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
pub(crate) fn default_parameter_group(engine: &str, engine_version: &str) -> String {
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

pub(crate) fn runtime_error_to_service_error(error: RuntimeError) -> AwsServiceError {
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
